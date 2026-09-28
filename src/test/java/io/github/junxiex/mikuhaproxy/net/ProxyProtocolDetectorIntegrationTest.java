package io.github.junxiex.mikuhaproxy.net;

import io.github.junxiex.mikuhaproxy.DetectorContext;
import io.github.junxiex.mikuhaproxy.config.AllowList;
import io.github.junxiex.mikuhaproxy.config.CidrBlock;
import io.github.junxiex.mikuhaproxy.config.PluginConfig;
import io.github.junxiex.mikuhaproxy.util.Counters;
import io.github.junxiex.mikuhaproxy.util.LogThrottle;
import io.netty.bootstrap.Bootstrap;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.haproxy.HAProxyMessage;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 探测器在<b>真实 NIO 管道</b>里的端到端行为：白名单通过 → 换装真解码器 → 下游拿到解析结果。
 *
 * <p>为什么不能用 {@code EmbeddedChannel}：探测器按「TCP 对端地址」查白名单，而
 * {@code EmbeddedChannel} 的对端是它自己的 {@code EmbeddedSocketAddress}——既不是
 * {@code InetSocketAddress}，也无法改成某个真实 IP，于是「白名单通过」这条路径在那里根本走不到
 * （现有 {@code ProxyProtocolDetectorTest} 用 {@code DENY_ALL} 只能覆盖拒绝路径）。
 * 这正是本插件最核心、也是历史缺陷（换装重名兜底）所在的那条路径，所以单独用一个绑定在
 * 127.0.0.1 上的真实服务端来覆盖：白名单写 127.0.0.0/8，客户端从 127.0.0.1 连进来即可命中。</p>
 */
class ProxyProtocolDetectorIntegrationTest {

    /** 一条合法的 PROXY protocol v1 头；声明的客户端地址与真实对端无关，只为验证解码结果。 */
    private static final String PROXY_V1_HEADER = "PROXY TCP4 1.2.3.4 5.6.7.8 1234 5678\r\n";

    /** 头之后跟着的正常数据；用来证明「换装没有吃掉后续字节」。 */
    private static final byte[] PAYLOAD = "hello-after-header".getBytes(StandardCharsets.US_ASCII);

    // ------------------------------------------------------------------
    // 测试用的服务端 / 客户端
    // ------------------------------------------------------------------

    /** 记录下游收到的东西。继承 SimpleChannelInboundHandler 由 Netty 自动释放引用计数对象。 */
    private static final class Recorder extends SimpleChannelInboundHandler<Object> {

        final BlockingQueue<byte[]> payloads = new LinkedBlockingQueue<>();
        final List<String> decodedHeaders = new CopyOnWriteArrayList<>();

        @Override
        protected void channelRead0(ChannelHandlerContext ctx, Object msg) {
            if (msg instanceof HAProxyMessage header) {
                decodedHeaders.add(header.sourceAddress() + ":" + header.sourcePort()
                        + " -> " + header.destinationAddress() + ":" + header.destinationPort()
                        + " version=" + header.protocolVersion());
            } else if (msg instanceof ByteBuf buf) {
                final byte[] copy = new byte[buf.readableBytes()];
                buf.getBytes(buf.readerIndex(), copy);
                payloads.add(copy);
            }
        }
    }

    /** 绑定在 127.0.0.1:随机端口上的服务端，管道与 Velocity 的形态一致：探测器在最前。 */
    private static final class ServerHarness implements AutoCloseable {

        private final EventLoopGroup boss = new NioEventLoopGroup(1);
        private final EventLoopGroup worker = new NioEventLoopGroup(1);
        private final Channel server;
        final int port;

        /**
         * @param occupiedHandlerName 若非 {@code null}，先在这个名字上占一个处理器，
         *                            模拟「别的插件已经占了 haproxy-decoder 这个名字」
         */
        ServerHarness(String occupiedHandlerName, Recorder recorder, DetectorContext context)
                throws InterruptedException {
            final ServerBootstrap bootstrap = new ServerBootstrap()
                    .group(boss, worker)
                    .channel(NioServerSocketChannel.class)
                    .childHandler(new ChannelInitializer<SocketChannel>() {
                        @Override
                        protected void initChannel(SocketChannel channel) {
                            if (occupiedHandlerName != null) {
                                channel.pipeline().addLast(occupiedHandlerName, new ChannelInboundHandlerAdapter());
                            }
                            channel.pipeline().addLast(ProxyProtocolDetector.HANDLER_NAME,
                                    new ProxyProtocolDetector(context));
                            // 单客户端场景，直接复用同一个 recorder（Netty 只禁止把非 @Sharable 处理器
                            // 加进同一条管道两次，加到不同连接上是允许的）
                            channel.pipeline().addLast(recorder);
                        }
                    });
            server = bootstrap.bind(new InetSocketAddress("127.0.0.1", 0)).sync().channel();
            port = ((InetSocketAddress) server.localAddress()).getPort();
        }

        @Override
        public void close() {
            server.close().syncUninterruptibly();
            boss.shutdownGracefully();
            worker.shutdownGracefully();
        }
    }

    /** 连到测试服务端的客户端。 */
    private static final class ClientHarness implements AutoCloseable {

        private final EventLoopGroup group = new NioEventLoopGroup(1);
        private final Channel channel;

        ClientHarness(int port) throws InterruptedException {
            channel = new Bootstrap()
                    .group(group)
                    .channel(NioSocketChannel.class)
                    .handler(new ChannelInitializer<SocketChannel>() {
                        @Override
                        protected void initChannel(SocketChannel ch) {
                            // 客户端不需要任何处理器
                        }
                    })
                    .connect(new InetSocketAddress("127.0.0.1", port)).sync().channel();
        }

        void send(String text) throws InterruptedException {
            channel.writeAndFlush(Unpooled.copiedBuffer(text, StandardCharsets.US_ASCII)).sync();
        }

        boolean isActive() {
            return channel.isActive();
        }

        @Override
        public void close() {
            channel.close().syncUninterruptibly();
            group.shutdownGracefully();
        }
    }

    // ------------------------------------------------------------------
    // 用例
    // ------------------------------------------------------------------

    @Test
    @DisplayName("白名单通过：换上真解码器，下游收到解析后的 PROXY 头与头之后的数据")
    @Timeout(30)
    void acceptedHeaderIsDecodedForDownstreamHandlers() throws Exception {
        final DetectorContext context = context();
        final Recorder recorder = new Recorder();

        try (ServerHarness server = new ServerHarness(null, recorder, context);
             ClientHarness client = new ClientHarness(server.port)) {

            client.send(PROXY_V1_HEADER + new String(PAYLOAD, StandardCharsets.US_ASCII));

            assertTrue(awaitUntil(() -> context.counters().proxied() == 1L),
                    "白名单通过后应当计入「代理」计数，实际 " + context.counters().proxied());
            assertTrue(awaitUntil(() -> !recorder.decodedHeaders.isEmpty()),
                    "下游必须收到解码后的 PROXY 头（说明换装成功）");
            assertEquals("1.2.3.4:1234 -> 5.6.7.8:5678 version=V1", recorder.decodedHeaders.get(0),
                    "解码出的地址与端口应当就是头里声明的那些");

            assertTrue(awaitUntil(() -> !recorder.payloads.isEmpty()), "头之后的正常数据也必须到达下游");
            assertArrayEquals(PAYLOAD, recorder.payloads.poll(), "后续字节不能被换装吞掉");

            assertEquals(0L, context.counters().failures(), "这条路径不应抛出任何异常");
            assertEquals(0L, context.counters().rejected(), "白名单里的来源不应被拒绝");
            assertTrue(client.isActive(), "接受之后连接必须保持打开");
        }
    }

    @Test
    @DisplayName("管道里已有同名处理器：兜底换装必须成功，不能把每一条代理连接都掐掉")
    @Timeout(30)
    void succeedsEvenWhenDecoderNameIsAlreadyTaken() throws Exception {
        final DetectorContext context = context();
        final Recorder recorder = new Recorder();

        // 占住 "haproxy-decoder" 这个名字，逼探测器走 catch 兜底分支
        try (ServerHarness server = new ServerHarness(ProxyProtocolDetector.DECODER_NAME, recorder, context);
             ClientHarness client = new ClientHarness(server.port)) {

            client.send(PROXY_V1_HEADER);

            assertTrue(awaitUntil(() -> context.counters().proxied() == 1L),
                    "重名不应影响判定，仍应计入「代理」");
            assertTrue(awaitUntil(() -> !recorder.decodedHeaders.isEmpty()),
                    "兜底分支也必须把真正的解码器装上，下游要收到解析结果");
            assertEquals(0L, context.counters().failures(),
                    "重名兜底不得抛异常（旧实现会抛 ChannelPipelineException 并关闭连接）");
            assertTrue(client.isActive(), "这条连接不能被掐掉");
        }
    }

    // ------------------------------------------------------------------
    // 辅助
    // ------------------------------------------------------------------

    private static DetectorContext context() throws UnknownHostException {
        // 允许回环，于是从 127.0.0.1 连进来的测试客户端天然命中白名单
        final List<CidrBlock> rules = new ArrayList<>();
        rules.add(CidrBlock.of(InetAddress.getByName("127.0.0.0"), 8));
        return new DetectorContext(AllowList.of(rules), PluginConfig.defaults(), new Counters(),
                new LogThrottle(60, 256), LoggerFactory.getLogger(ProxyProtocolDetectorIntegrationTest.class));
    }

    /** 轮询等待条件成立；网络往返在 CI 上可能稍慢，给 5 秒。 */
    private static boolean awaitUntil(BooleanSupplier condition) throws InterruptedException {
        final long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (System.nanoTime() < deadline) {
            if (condition.getAsBoolean()) {
                return true;
            }
            Thread.sleep(10L);
        }
        return condition.getAsBoolean();
    }
}
