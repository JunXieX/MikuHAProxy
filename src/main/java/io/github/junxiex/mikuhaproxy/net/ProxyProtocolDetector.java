package io.github.junxiex.mikuhaproxy.net;

import io.github.junxiex.mikuhaproxy.DetectorContext;
import io.github.junxiex.mikuhaproxy.util.AddressFormat;
import io.github.junxiex.mikuhaproxy.util.LogThrottle;
import io.netty.buffer.ByteBuf;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPipeline;
import io.netty.handler.codec.ByteToMessageDecoder;
import io.netty.handler.codec.ProtocolDetectionResult;
import io.netty.handler.codec.ProtocolDetectionState;
import io.netty.handler.codec.haproxy.HAProxyMessageDecoder;
import io.netty.handler.codec.haproxy.HAProxyProtocolException;
import io.netty.handler.codec.haproxy.HAProxyProtocolVersion;

import java.io.IOException;
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

    /**
     * 判定入口。
     *
     * <p><b>为什么不必覆写 {@code isSingleDecode()}</b>：那个开关只在本次 {@code decode} 向 {@code out}
     * 产出过消息时才会被 Netty 读到（{@code ByteToMessageDecoder.callDecode} 的字节码路径），而本探测器
     * 从不向 {@code out} 添加任何东西，覆写它等于写一段永远不会执行的代码。真正保证「只判定一次」的是：</p>
     * <ul>
     *   <li>直连：{@link #handleDirect} 把处理器自己摘出管道，Netty 随即停止调用它；</li>
     *   <li>代理：缓冲字节交给新装上的 {@link HAProxyMessageDecoder}，本处理器已不在管道里；</li>
     *   <li>字节不够：不消费、不产出，触发 Netty「{@code decode} 无进展即停止本次解码」这条规则；</li>
     *   <li>外加 {@link #decided} 标记，兜住连接关闭时 Netty 对同一缓冲区重入 {@code callDecode} 的情况。</li>
     * </ul>
     */
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
        context.counters().incrementDirect();
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
            context.counters().incrementRejected();
            // 先关连接、再打日志：安全决策不能因为「打日志失败」而失效。
            ctx.close();
            if (context.settings().logRejectedConnections() && context.throttle().shouldLog(peer)) {
                context.logger().warn("已拒绝来自 {} 的代理连接：该地址不在白名单中。"
                        + "若这是你自己的 HAProxy，请把它加入白名单文件；否则请检查网络暴露面。", AddressFormat.format(peer));
            }
            return;
        }

        context.counters().incrementProxied();
        if (context.settings().logAcceptedConnections()) {
            context.logger().info("已接受来自 {} 的 {} 代理头。", AddressFormat.format(peer), version);
        }

        final ChannelPipeline pipeline = ctx.pipeline();
        final String self = ctx.name();
        try {
            // 按名字替换：O(1)，并且沿用 "haproxy-decoder" 这个既有命名（别的插件认得它）。
            pipeline.replace(self, DECODER_NAME, new HAProxyMessageDecoder());
        } catch (RuntimeException collision) {
            // 管道里已经存在同名处理器（别的插件占了坑）。这里必须换一个**新实例**：
            // DefaultChannelPipeline.replace 是「先 checkMultiplicity(新处理器)、后 checkDuplicateName(新名字)」，
            // 所以第一次 replace 在因重名抛错之前，就已经把那个解码器实例标记成「已经加入过」；
            // HAProxyMessageDecoder 不是 @Sharable，复用同一个实例再替换一次必然抛 ChannelPipelineException。
            // 重名抛的是 IllegalArgumentException，但复用实例抛的是 ChannelPipelineException（两者都是
            // RuntimeException），所以这里按 RuntimeException 兜，才能真正保证「不会因为重名卡住这条连接」。
            pipeline.replace(self, null, new HAProxyMessageDecoder());
        }
    }

    /**
     * 判定过程中出现异常：把「连接层中断」与「判定本身失败」分开处置，再关掉这条连接。
     *
     * <p>这里收到的异常有两种来源，处置方式<b>刻意不同</b>：</p>
     * <ul>
     *   <li><b>连接层中断</b>（{@link IOException} 族，最常见的 {@code Connection reset}、
     *       {@code Broken pipe}，以及 Windows 上的 {@code An existing connection was forcibly closed}）：
     *       这类异常在 socket 读取路径上抛出（{@code implRead → doReadBytes}），{@code decode} 根本没被
     *       调用，谈不上「判定失败」。它通常是对端在发出任何数据前就 RST 掉连接——扫描器探测、客户端取消、
     *       探活——属于正常网络现象。因此<b>不计入</b>「异常」计数，日志降级为 DEBUG 且<b>不带堆栈</b>：
     *       只有真正需要关注的事件才配得上 {@code /mikuproxy status} 的「异常」计数与 ERROR 级日志。</li>
     *   <li><b>判定本身失败</b>（{@link HAProxyProtocolException}，以及 Netty 把它包起来的
     *       {@code DecoderException}）：说明有人在构造畸形的 PROXY 头，是值得警觉的安全信号，
     *       保持原有的计数与 ERROR + 堆栈。</li>
     * </ul>
     *
     * <p><b>为什么降级后仍受 {@code log-rejected-connections} 与限流器约束</b>：这是刻意的，也是底线。
     * 攻击者同样能用「异常」刷日志——若因为降级就放开限流，等于给攻击者开了一条无上限写日志的通道。
     * 降级只是把噪音从 ERROR 挪到 DEBUG，防线本身一寸都没退。默认关闭 DEBUG 时连这一行都不会产生，
     * 而「发生了多少次连接中断」对使用者没有诊断价值，故也刻意不新增计数器。</p>
     *
     * <p><b>两类日志分槽限流</b>：中断用 {@link LogThrottle#CATEGORY_INTERRUPTION}、判定失败用默认的
     * {@link LogThrottle#CATEGORY_SIGNAL}，二者是同一地址下的两个独立槽位。否则攻击者只要用自己的 IP 先发
     * 一次中断、占掉该地址的限流槽，就能在时间窗内把随后那条「伪造 PROXY 头」的 ERROR 一并挤掉——真实攻击
     * 信号被自己制造的噪音盖住。</p>
     */
    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        final InetAddress peer = peerAddress(ctx.channel());
        if (isConnectionInterruption(cause)) {
            if (context.settings().logRejectedConnections()
                    && context.throttle().shouldLog(peer, LogThrottle.CATEGORY_INTERRUPTION)) {
                context.logger().debug("连接在完成 PROXY 判定前被对端中断（对端 {}）：{}",
                        AddressFormat.format(peer), cause.toString());
            }
        } else {
            context.counters().incrementFailures();
            if (context.settings().logRejectedConnections() && context.throttle().shouldLog(peer)) {
                context.logger().error("连接初始化（PROXY 判定）阶段发生异常，已断开该连接（对端 {}）",
                        AddressFormat.format(peer), cause);
            }
        }
        // 连接中断时这条连接本就已断，这里再关一次是幂等的；仍统一关闭，保证两条路径收尾一致。
        ctx.close();
    }

    /**
     * 沿 cause 链向下遍历的最大层数。
     *
     * <p>真实的异常链不过三五层（Netty 最多再用 {@code DecoderException} 包一层），16 层已是极高余量。
     * 设上限是为了兜住「异常链被构造得极深」的意外输入：定长遍历在热路径上零分配，又不会无限往下钻。
     * （不能靠「{@code t == t.getCause()} 就停」来防环——{@code Throwable.getCause()} 对
     * {@code cause == this} 哨兵返回的是 {@code null}，而 {@code initCause(this)} 会抛
     * {@code IllegalArgumentException}，自引用链根本构造不出来，那种写法是死代码。）</p>
     */
    private static final int MAX_CAUSE_DEPTH = 16;

    /**
     * 判断一个异常是否属于「连接层中断」。
     *
     * <p>分类只依据<b>异常类型</b>，不匹配异常消息文本——消息在不同 JDK / 平台上并不稳定
     * （同样是重置，Windows 与 Linux 的措辞就不同），而类型是稳定的。{@link IOException} 及其子类
     * （{@code SocketException}、{@code ClosedChannelException} 等）在本处理器的判定逻辑里不会产生；
     * 沿入站方向能到达这里的 {@link IOException} 只可能来自 socket 读写路径，因此命中即代表「连接断了」
     * 而非「判定错了」。</p>
     *
     * <p>沿因果链遍历时优先找 {@link HAProxyProtocolException}：它在 Netty 里会被 {@code DecoderException}
     * 包一层，但只要出现就一律判为「判定失败」（宁可多报，不可漏报）。找不到它、却找到 {@link IOException}
     * 才算连接中断；两者都没有的意外异常保守地按「判定失败」处理，以免真实故障被静默吞掉。</p>
     *
     * <p>遍历最深只到 {@link #MAX_CAUSE_DEPTH} 层。若因触顶而<b>没走完整条链</b>，一律保守判为「判定失败」——
     * 方向永远是「宁可把噪音当信号，也不可把信号当噪音」：多打一条 ERROR 只是噪音，漏报一次伪造的
     * PROXY 头才是真的损失。</p>
     */
    static boolean isConnectionInterruption(Throwable cause) {
        boolean ioFailure = false;
        Throwable t = cause;
        for (int depth = 0; t != null && depth < MAX_CAUSE_DEPTH; depth++) {
            if (t instanceof HAProxyProtocolException) {
                return false;
            }
            if (t instanceof IOException) {
                ioFailure = true;
            }
            t = t.getCause();
        }
        // 到这里有两种可能：链已走完（t == null），或触及 MAX_CAUSE_DEPTH 被截断（t != null）。
        // 截断说明还有更深的层级没看，此时一律保守判为「判定失败」，不沿用中途记下的 ioFailure——
        // 否则「前 16 层是 IOException、真信号在第 17 层」这种链会被降级成噪音，恰恰抹掉了攻击证据。
        return t == null && ioFailure;
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
