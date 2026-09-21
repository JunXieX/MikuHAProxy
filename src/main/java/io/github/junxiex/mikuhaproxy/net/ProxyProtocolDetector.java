package io.github.junxiex.mikuhaproxy.net;

import io.github.junxiex.mikuhaproxy.DetectorContext;
import io.github.junxiex.mikuhaproxy.util.AddressFormat;
import io.netty.buffer.ByteBuf;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPipeline;
import io.netty.handler.codec.ByteToMessageDecoder;
import io.netty.handler.codec.ProtocolDetectionResult;
import io.netty.handler.codec.ProtocolDetectionState;
import io.netty.handler.codec.haproxy.HAProxyMessageDecoder;
import io.netty.handler.codec.haproxy.HAProxyProtocolVersion;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.List;

/**
 * 核心探测器：在连接的最前面「瞄一眼」开头几个字节，判断这条连接是否携带 PROXY protocol 头。
 *
 * <p>工作方式（在管道首位，即 Velocity 放置 {@link HAProxyMessageDecoder} 的位置）：</p>
 * <ol>
 *   <li>如果开头<b>不可能</b>是 PROXY 头 → 说明是直连，把自己从管道里摘掉，
 *       已缓冲的字节由 Netty 自动转交给后面的处理器，直连照常握手。</li>
 *   <li>如果开头确实是 PROXY 头 → 先检查 TCP 对端是不是可信代理，是则把自己替换成真正的
 *       {@link HAProxyMessageDecoder} 交还给 Velocity；不是则立即关闭连接。</li>
 * </ol>
 *
 * <p><b>为什么不等凑够 12 字节再判定</b>：那等于每条直连连接都要白等 12 个字节。本实现按
 * PROXY v2 签名首字节 {@code 0x0D} 与 v1 前缀首字母 {@code 'P'} 做<b>渐进式前缀比对</b>：
 * 只要已经收到的字节里出现失配就立刻判为直连——绝大多数直连连接只需 <b>1 个字节</b>即可得出结论，
 * 不必多等。判定结论与 Netty 的 {@code detectProtocol} 语义等价（前缀失配 ⟹ 后者必然返回
 * {@code INVALID}），只是更早收敛；字节数足够时仍然回落到官方的 {@code detectProtocol} 作为权威裁定。</p>
 */
public final class ProxyProtocolDetector extends ByteToMessageDecoder {

    /** 探测器的管道名。用社区通用的名字，方便其它插件认出管道首位的这个处理器。 */
    public static final String HANDLER_NAME = "haproxy-detector";

    /** 探测通过后装回的真解码器名，与 Netty 官方解码器对应。 */
    public static final String DECODER_NAME = "haproxy-decoder";

    /** PROXY protocol v2 的 12 字节二进制签名。 */
    private static final byte[] V2_SIGNATURE = {
            0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A};

    /** PROXY protocol v1 的文本前缀 {@code "PROXY"}。 */
    private static final byte[] V1_PREFIX = {'P', 'R', 'O', 'X', 'Y'};

    /** Netty 的 {@code detectProtocol} 需要至少 12 个可读字节才能给出权威判定。 */
    static final int MIN_PROBE_BYTES = 12;

    /** 前缀探测的结论。 */
    enum Probe {
        /** 已可确定不是 PROXY 头，按直连处理。 */
        DIRECT,
        /** 字节还不够，且仍有可能，等更多数据。 */
        INCOMPLETE,
        /** 前缀仍然吻合且字节数已足够，交由 {@code detectProtocol} 做权威裁定。 */
        CANDIDATE
    }

    private final DetectorContext context;

    /**
     * 是否已经做出终局判定。
     *
     * <p>拒绝路径上我们只是关掉连接、并不会把自己摘出管道，而 Netty 在连接关闭时会再走一遍
     * {@code channelInactive → channelInputClosed → callDecode + decodeLast}，对同一个缓冲区
     * 反复调用 {@code decode}。没有这个标记的话，一次拒绝会被计数三次、日志也可能重复。</p>
     */
    private boolean decided;

    public ProxyProtocolDetector(DetectorContext context) {
        this.context = context;
    }

    /** 只解一次：要么判定为直连，要么换上真正的解码器，不存在「继续解码后续帧」的语义。 */
    @Override
    public boolean isSingleDecode() {
        return true;
    }

    @Override
    protected void decode(ChannelHandlerContext ctx, ByteBuf in, List<Object> out) {
        if (decided) {
            return;
        }
        switch (probe(in)) {
            case DIRECT -> {
                decided = true;
                handleDirect(ctx);
            }
            case INCOMPLETE -> {
                // 等更多字节，什么都不做（不会消费任何字节）
            }
            case CANDIDATE -> {
                final ProtocolDetectionResult<HAProxyProtocolVersion> result =
                        HAProxyMessageDecoder.detectProtocol(in);
                if (result.state() == ProtocolDetectionState.DETECTED) {
                    decided = true;
                    handleProxied(ctx, result.detectedProtocol());
                } else if (result.state() == ProtocolDetectionState.INVALID) {
                    decided = true;
                    handleDirect(ctx);
                }
                // NEEDS_MORE_DATA 在可读字节 ≥ 12 时不可能出现；真出现就继续等，不做错误决定
            }
        }
    }

    /**
     * 前缀探测。
     *
     * <p>纯函数，便于单测。判定依据完全来自 PROXY protocol 规范与 Netty 的
     * {@code HAProxyMessageDecoder.detectProtocol}：v2 以 {@code \r\n\r\n\0\r\nQUIT\n} 开头，
     * v1 以 {@code "PROXY"} 开头，因此首字节不是 {@code 0x0D} 也不是 {@code 'P'} 就绝不可能是代理连接。</p>
     */
    static Probe probe(ByteBuf in) {
        final int start = in.readerIndex();
        final int readable = in.readableBytes();
        if (readable <= 0) {
            return Probe.INCOMPLETE;
        }

        final byte first = in.getByte(start);
        final boolean v2Possible = first == V2_SIGNATURE[0]
                && prefixMatches(in, start, readable, V2_SIGNATURE);
        final boolean v1Possible = first == V1_PREFIX[0]
                && prefixMatches(in, start, readable, V1_PREFIX);
        if (!v2Possible && !v1Possible) {
            return Probe.DIRECT;
        }
        return readable >= MIN_PROBE_BYTES ? Probe.CANDIDATE : Probe.INCOMPLETE;
    }

    /**
     * 只比对「当前可读范围内」的字节：只要出现失配就返回 {@code false}。
     *
     * <p>与 Netty {@code match()} 的区别仅在于遇到缓冲区末尾时提前返回 {@code true}
     * （表示「还看不出来」），这正是渐进式判定需要的行为。</p>
     */
    private static boolean prefixMatches(ByteBuf in, int start, int readable, byte[] prefix) {
        final int limit = Math.min(readable, prefix.length);
        for (int i = 0; i < limit; i++) {
            if (in.getByte(start + i) != prefix[i]) {
                return false;
            }
        }
        return true;
    }

    /** 直连：摘掉自己，让后续处理器按普通连接处理。 */
    private void handleDirect(ChannelHandlerContext ctx) {
        context.counters().direct().increment();
        // 按名字移除是 O(1)（Netty 内部维护 name -> context 的 HashMap），
        // 而 remove(ChannelHandler) 需要线性扫描整条管道。
        // 摘除发生在 decode() 内部，Netty 会把本处理器已缓冲的字节转发给后一个处理器
        // （ByteToMessageDecoder.handlerRemoved），因此直连的握手包一个字节都不会丢。
        ctx.pipeline().remove(ctx.name());
    }

    /** 代理：白名单校验通过后，把自己换成真正的 PROXY 解码器。 */
    private void handleProxied(ChannelHandlerContext ctx, HAProxyProtocolVersion version) {
        final InetAddress peer = peerAddress(ctx.channel());

        if (!context.allowList().isAllowed(peer)) {
            context.counters().rejected().increment();
            // 先关连接、再打日志：安全决策不能因为「打日志失败」而失效。
            ctx.close();
            if (context.settings().logRejectedConnections() && context.throttle().shouldLog(peer)) {
                context.logger().warn("已拒绝来自 {} 的代理连接：该地址不在白名单中。"
                        + "若这是你自己的 HAProxy，请把它加入白名单文件；否则请检查网络暴露面。", AddressFormat.format(peer));
            }
            return;
        }

        context.counters().proxied().increment();
        if (context.settings().logAcceptedConnections()) {
            context.logger().info("已接受来自 {} 的 {} 代理头。", AddressFormat.format(peer), version);
        }

        final ChannelPipeline pipeline = ctx.pipeline();
        final String self = ctx.name();
        final HAProxyMessageDecoder decoder = new HAProxyMessageDecoder();
        try {
            // 同样按名字替换：O(1)，并且沿用 "haproxy-decoder" 这个既有命名
            pipeline.replace(self, DECODER_NAME, decoder);
        } catch (IllegalArgumentException duplicateName) {
            // 管道里已经存在同名处理器（别的插件占了坑）：退回 Netty 自动命名，
            // 保证连接不会因为重名而卡住。
            pipeline.replace(self, null, decoder);
        }
    }

    /**
     * 判定过程中出现异常：计数、按原有方式关掉这条连接。
     *
     * <p>日志同样受 {@code log-rejected-connections} 与限流器约束。这一点是刻意的：
     * 关掉日志开关的人要的是「安静」，而不是「安静一半」——攻击者同样能制造异常来刷日志，
     * 只留一条漏网的日志通道等于给了它绕过限流的后门。异常数量始终能在
     * {@code /mikuproxy status} 的「异常」计数里看到，静默不等于失明。</p>
     */
    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        context.counters().failures().increment();
        final InetAddress peer = peerAddress(ctx.channel());
        if (context.settings().logRejectedConnections() && context.throttle().shouldLog(peer)) {
            context.logger().error("判定 PROXY protocol 时发生异常，已断开该连接（对端 {}）", AddressFormat.format(peer), cause);
        }
        ctx.close();
    }

    private static InetAddress peerAddress(Channel channel) {
        final SocketAddress remote = channel.remoteAddress();
        if (!(remote instanceof InetSocketAddress inet) || inet.isUnresolved()) {
            return null;
        }
        final InetAddress address = inet.getAddress();
        return address != null && address.getAddress() != null ? address : null;
    }

}
