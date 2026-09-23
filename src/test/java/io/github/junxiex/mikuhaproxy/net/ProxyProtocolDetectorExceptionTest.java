package io.github.junxiex.mikuhaproxy.net;

import io.github.junxiex.mikuhaproxy.DetectorContext;
import io.github.junxiex.mikuhaproxy.config.AllowList;
import io.github.junxiex.mikuhaproxy.config.PluginConfig;
import io.github.junxiex.mikuhaproxy.util.Counters;
import io.github.junxiex.mikuhaproxy.util.LogThrottle;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.DecoderException;
import io.netty.handler.codec.haproxy.HAProxyProtocolException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Marker;
import org.slf4j.event.Level;
import org.slf4j.helpers.AbstractLogger;
import org.slf4j.helpers.MessageFormatter;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link ProxyProtocolDetector#exceptionCaught} 的异常分级：把「连接层中断」与「判定本身失败」分开。
 *
 * <p>这是对历史缺陷的回归守护。旧实现对任何入站异常都无条件 {@code incrementFailures()} 并打 ERROR + 堆栈，
 * 于是「对端在发出任何数据前就把连接 RST 掉」这种正常网络现象被报成了插件异常，污染了
 * {@code /mikuproxy status} 的「异常」计数，也让服主误以为插件坏了。本测试锁定修正后的行为：</p>
 * <ul>
 *   <li>连接层中断（{@code IOException} 族）既不计数、也不打 ERROR，只留下一行不带堆栈的 DEBUG；</li>
 *   <li>判定本身失败（{@code HAProxyProtocolException}，含被 {@code DecoderException} 包裹的情形）
 *       保持计数与 ERROR + 堆栈；</li>
 *   <li>降级后的 DEBUG 仍受 {@code log-rejected-connections} 约束（防线不退）。</li>
 * </ul>
 *
 * <p><b>为什么用 {@code EmbeddedChannel} 而不是真实 NIO 服务端</b>：本类断言的是「计数」与「日志级别」，
 * 二者都不依赖 TCP 对端地址。{@code EmbeddedChannel} 自带的对端是它自己的 {@code EmbeddedSocketAddress}，
 * 探测器据此拿到 {@code null} 地址——限流器对 {@code null} 键直接放行，日志因此照常产生，正好满足断言需要。
 * 唯一需要真实对端的是「限流器仍生效」这条用例：它覆盖 {@code remoteAddress()} 提供一个非空地址来验证限流。
 * 需要真实 NIO 网络往返的用例（白名单通过路径）由 {@code ProxyProtocolDetectorIntegrationTest} 覆盖。</p>
 */
class ProxyProtocolDetectorExceptionTest {

    // ------------------------------------------------------------------
    // 记录型日志器：把每一次日志调用按级别与是否带堆栈记下来
    // ------------------------------------------------------------------

    /** 一条被记录下来的日志。{@code throwable} 为 {@code null} 即代表这行日志没有堆栈。 */
    private record Event(Level level, String message, Throwable throwable) {
    }

    /**
     * 记录型日志器。
     *
     * <p>继承 slf4j 的 {@link AbstractLogger} 只需实现两个抽象方法与 {@code isXxxEnabled} 系列：
     * 所有 {@code debug/info/warn/error} 最终都会汇入 {@link #handleNormalizedLoggingCall}，
     * 于是「打了哪个级别、带不带堆栈」都能被精确断言。这里刻意不引入任何日志实现依赖。</p>
     */
    private static final class RecordingLogger extends AbstractLogger {

        private final List<Event> events = new CopyOnWriteArrayList<>();

        RecordingLogger() {
            this.name = "recording";
        }

        @Override
        protected String getFullyQualifiedCallerName() {
            return RecordingLogger.class.getName();
        }

        @Override
        protected void handleNormalizedLoggingCall(Level level, Marker marker, String messagePattern,
                                                   Object[] arguments, Throwable throwable) {
            events.add(new Event(level, MessageFormatter.basicArrayFormat(messagePattern, arguments), throwable));
        }

        // 全部开启，保证任何级别的日志都会被记录（否则 handleNormalizedLoggingCall 根本不会被调用）。
        @Override
        public boolean isTraceEnabled() {
            return true;
        }

        @Override
        public boolean isTraceEnabled(Marker marker) {
            return true;
        }

        @Override
        public boolean isDebugEnabled() {
            return true;
        }

        @Override
        public boolean isDebugEnabled(Marker marker) {
            return true;
        }

        @Override
        public boolean isInfoEnabled() {
            return true;
        }

        @Override
        public boolean isInfoEnabled(Marker marker) {
            return true;
        }

        @Override
        public boolean isWarnEnabled() {
            return true;
        }

        @Override
        public boolean isWarnEnabled(Marker marker) {
            return true;
        }

        @Override
        public boolean isErrorEnabled() {
            return true;
        }

        @Override
        public boolean isErrorEnabled(Marker marker) {
            return true;
        }

        List<Event> events() {
            return events;
        }

        boolean hasLevel(Level level) {
            return events.stream().anyMatch(event -> event.level() == level);
        }

        /** 第一条指定级别的日志；没有则为 {@code null}。 */
        Event firstOf(Level level) {
            return events.stream().filter(event -> event.level() == level).findFirst().orElse(null);
        }
    }

    // ------------------------------------------------------------------
    // 辅助
    // ------------------------------------------------------------------

    private static DetectorContext context(RecordingLogger logger, PluginConfig settings) {
        return new DetectorContext(AllowList.ALLOW_ALL, settings, new Counters(), new LogThrottle(60, 256), logger);
    }

    /** 直接触发探测器所在管道的异常事件，等价于 Netty 把异常沿入站方向传给它。 */
    private static EmbeddedChannel fire(DetectorContext context, Throwable cause) {
        final EmbeddedChannel channel = new EmbeddedChannel();
        channel.pipeline().addLast(ProxyProtocolDetector.HANDLER_NAME, new ProxyProtocolDetector(context));
        channel.pipeline().fireExceptionCaught(cause);
        return channel;
    }

    /**
     * 同 {@link #fire}，但让管道看到一个<b>可解析的真实对端地址</b>。
     *
     * <p>{@code EmbeddedChannel} 默认的对端是它自己的 {@code EmbeddedSocketAddress}，探测器据此拿到
     * {@code null}——而限流器对 {@code null} 键直接放行。要验证「同一地址的高频中断仍被限流」，
     * 必须让对端地址非空，所以这里覆盖 {@link io.netty.channel.Channel#remoteAddress()}（它并非 final）
     * 返回一个真实地址。</p>
     */
    private static EmbeddedChannel fire(DetectorContext context, Throwable cause, SocketAddress peer) {
        final EmbeddedChannel channel = new EmbeddedChannel() {
            @Override
            public SocketAddress remoteAddress() {
                return peer;
            }
        };
        channel.pipeline().addLast(ProxyProtocolDetector.HANDLER_NAME, new ProxyProtocolDetector(context));
        channel.pipeline().fireExceptionCaught(cause);
        return channel;
    }

    // ------------------------------------------------------------------
    // 连接层中断：不计数、不打 ERROR、只留一行不带堆栈的 DEBUG
    // ------------------------------------------------------------------

    @Test
    @DisplayName("Connection reset：属于连接层中断，不计入「异常」，不打 ERROR，DEBUG 无堆栈")
    void connectionResetIsNotCountedAsFailure() {
        final RecordingLogger logger = new RecordingLogger();
        final DetectorContext context = context(logger, PluginConfig.defaults());

        final EmbeddedChannel channel = fire(context, new SocketException("Connection reset"));

        assertEquals(0L, context.counters().failures(),
                "对端在发出任何数据前 RST 掉连接属于正常网络现象，不得污染「异常」计数");
        assertFalse(logger.hasLevel(Level.ERROR), "连接中断不得打 ERROR 级日志：" + logger.events());

        final Event event = logger.firstOf(Level.DEBUG);
        assertNotNull(event, "降级后的记录应当出现在 DEBUG 级");
        assertNull(event.throwable(), "降级日志不得携带堆栈（throwable 必须为 null）");
        assertTrue(event.message().contains("Connection reset"), "日志应带上异常摘要便于排查：" + event.message());

        assertFalse(channel.isOpen(), "连接仍应被关闭（对已断开的连接是幂等操作）");
        channel.finishAndReleaseAll();
    }

    @Test
    @DisplayName("Broken pipe / 其他 IOException：同样判为连接层中断")
    void otherIoExceptionsAreTreatedAsInterruptions() {
        final RecordingLogger logger = new RecordingLogger();
        final DetectorContext context = context(logger, PluginConfig.defaults());

        final EmbeddedChannel channel = fire(context, new IOException("Broken pipe"));

        assertEquals(0L, context.counters().failures());
        assertFalse(logger.hasLevel(Level.ERROR), logger.events().toString());
        assertNotNull(logger.firstOf(Level.DEBUG));
        channel.finishAndReleaseAll();
    }

    @Test
    @DisplayName("被 DecoderException 包着的 IOException：仍是连接层中断（例如解码路径里透出的读取失败）")
    void decoderExceptionWrappingIoExceptionIsStillAnInterruption() {
        final RecordingLogger logger = new RecordingLogger();
        final DetectorContext context = context(logger, PluginConfig.defaults());

        final EmbeddedChannel channel = fire(context, new DecoderException(new IOException("Connection reset by peer")));

        assertEquals(0L, context.counters().failures(),
                "根因是 IOException 就应判为中断，不能被外层的 DecoderException 带偏");
        assertFalse(logger.hasLevel(Level.ERROR), logger.events().toString());
        // 正向断言：必须真的走到「中断」分支并留下 DEBUG。否则这条用例会因为「日志根本没触发」而假通过
        // （只断言「没有 ERROR / 计数为 0」的否定式断言，在异常被上游吞掉时同样会通过）。
        final Event event = logger.firstOf(Level.DEBUG);
        assertNotNull(event, "判为中断就必须留下 DEBUG 记录，否则是假通过：" + logger.events());
        assertNull(event.throwable(), "中断日志不得携带堆栈");
        assertTrue(event.message().contains("Connection reset"), event.message());
        channel.finishAndReleaseAll();
    }

    // ------------------------------------------------------------------
    // 判定本身失败：计数 + ERROR + 堆栈保持不变
    // ------------------------------------------------------------------

    @Test
    @DisplayName("HAProxyProtocolException：属于判定本身失败，计数并保留 ERROR + 堆栈")
    void proxyProtocolExceptionIsCountedAndLoggedAsError() {
        final RecordingLogger logger = new RecordingLogger();
        final DetectorContext context = context(logger, PluginConfig.defaults());

        final HAProxyProtocolException cause = new HAProxyProtocolException("伪造的 PROXY 头");
        final EmbeddedChannel channel = fire(context, cause);

        assertEquals(1L, context.counters().failures(), "判定本身失败必须计入「异常」");
        final Event event = logger.firstOf(Level.ERROR);
        assertNotNull(event, "判定失败必须打 ERROR 级日志");
        assertEquals(cause, event.throwable(), "ERROR 日志必须携带原始异常（含堆栈）");
        assertFalse(channel.isOpen(), "判定失败的连接必须关闭");
        channel.finishAndReleaseAll();
    }

    @Test
    @DisplayName("被 DecoderException 包着的 HAProxyProtocolException：仍判为判定失败，不能被当成中断")
    void decoderExceptionWrappingProxyProtocolExceptionIsCountedAsFailure() {
        final RecordingLogger logger = new RecordingLogger();
        final DetectorContext context = context(logger, PluginConfig.defaults());

        final DecoderException cause = new DecoderException(new HAProxyProtocolException("伪造的 PROXY 头"));
        final EmbeddedChannel channel = fire(context, cause);

        assertEquals(1L, context.counters().failures(),
                "根因是 HAProxyProtocolException 就应优先判为判定失败，即使外层是 DecoderException");
        final Event event = logger.firstOf(Level.ERROR);
        assertNotNull(event);
        assertEquals(cause, event.throwable());
        channel.finishAndReleaseAll();
    }

    @Test
    @DisplayName("无法归类的意外异常：保守地按判定失败处理，避免真实故障被静默吞掉")
    void unexpectedExceptionIsTreatedAsFailure() {
        final RecordingLogger logger = new RecordingLogger();
        final DetectorContext context = context(logger, PluginConfig.defaults());

        final EmbeddedChannel channel = fire(context, new IllegalStateException("boom"));

        assertEquals(1L, context.counters().failures(), "既不是 IO 也不是判定异常的意外情况必须冒头");
        assertNotNull(logger.firstOf(Level.ERROR), "意外异常必须打 ERROR：" + logger.events());
        channel.finishAndReleaseAll();
    }

    // ------------------------------------------------------------------
    // 分类函数本身（纯函数，直接表驱动断言）
    // ------------------------------------------------------------------

    @Test
    @DisplayName("isConnectionInterruption：只认类型、沿因果链遍历，判定失败优先")
    void classificationIsByTypeAlongTheCauseChain() {
        assertTrue(ProxyProtocolDetector.isConnectionInterruption(new SocketException("Connection reset")),
                "SocketException 是 IOException 的子类");
        assertTrue(ProxyProtocolDetector.isConnectionInterruption(new IOException("Broken pipe")));
        assertTrue(ProxyProtocolDetector.isConnectionInterruption(new DecoderException(new IOException("reset"))),
                "外层包装不应掩盖根因");
        assertTrue(ProxyProtocolDetector.isConnectionInterruption(new RuntimeException(new IOException("reset"))),
                "任意层级的 IOException 都应被识别");
        assertTrue(ProxyProtocolDetector.isConnectionInterruption(
                        new DecoderException(new DecoderException(new IOException("reset")))),
                "多层包装也应逐层遍历到根因");

        assertFalse(ProxyProtocolDetector.isConnectionInterruption(new HAProxyProtocolException("bad")),
                "HAProxyProtocolException 是判定失败，不是中断");
        assertFalse(ProxyProtocolDetector.isConnectionInterruption(
                new DecoderException(new HAProxyProtocolException("bad"))));
        assertFalse(ProxyProtocolDetector.isConnectionInterruption(
                        new IOException(new HAProxyProtocolException("bad"))),
                "两条类型都在链上时，HAProxyProtocolException 优先（宁可多报，不可漏报）");
        assertFalse(ProxyProtocolDetector.isConnectionInterruption(
                new DecoderException(new IOException(new HAProxyProtocolException("bad")))),
                "同一异常链里既有 IOException 又有 HAProxyProtocolException 时，仍判为判定失败");
        assertFalse(ProxyProtocolDetector.isConnectionInterruption(new IllegalStateException("boom")),
                "无法归类时按判定失败处理（保守）");
        assertFalse(ProxyProtocolDetector.isConnectionInterruption(null), "null 归为判定失败（保守）");
    }

    // ------------------------------------------------------------------
    // 防线不退：降级后的 DEBUG 仍受 log-rejected-connections 约束
    // ------------------------------------------------------------------

    @Test
    @DisplayName("log-rejected-connections = false：连接中断一行都不打，避免成为无上限刷屏通道")
    void disablingRejectedLogsAlsoSilencesInterruptionDebug(@TempDir Path dir) throws IOException {
        final Path file = dir.resolve(PluginConfig.FILE_NAME);
        Files.writeString(file, "log-rejected-connections = false\n", StandardCharsets.UTF_8);
        final List<String> problems = new ArrayList<>();
        final PluginConfig settings = PluginConfig.load(file, problems::add);
        assertTrue(problems.isEmpty(), problems.toString());
        assertFalse(settings.logRejectedConnections(), "前置条件：开关应为关闭");

        // 正向对照：开关打开时，同样的异常确实会产生一行 DEBUG。先用它证明「日志路径可达」，
        // 否则下面「一条都没有」也可能只是异常路径根本没走到造成的假通过。
        final RecordingLogger control = new RecordingLogger();
        fire(context(control, PluginConfig.defaults()), new SocketException("Connection reset")).finishAndReleaseAll();
        assertTrue(control.hasLevel(Level.DEBUG), "前置对照失败：开关打开时本应产生 DEBUG");

        final RecordingLogger logger = new RecordingLogger();
        final DetectorContext context = context(logger, settings);

        // 同一地址连发多次，模拟扫描器刷连接：开关关闭时不应产生任何一行日志。
        for (int i = 0; i < 5; i++) {
            final EmbeddedChannel channel = fire(context, new SocketException("Connection reset"));
            channel.finishAndReleaseAll();
        }

        assertTrue(logger.events().isEmpty(), "日志开关关闭后不得产生任何记录：" + logger.events());
        assertEquals(0L, context.counters().failures(), "连接中断始终不计入「异常」");
    }

    @Test
    @DisplayName("防线不退：同一地址的高频连接中断仍被限流器约束，只留一行 DEBUG")
    void interruptionDebugIsStillThrottledPerPeer() throws UnknownHostException {
        final RecordingLogger logger = new RecordingLogger();
        final DetectorContext context = context(logger, PluginConfig.defaults());
        // 字面量地址不会触发 DNS；用它让探测器拿到非空对端，从而真正走到限流器分支。
        final SocketAddress peer = new InetSocketAddress(InetAddress.getByName("203.0.113.7"), 50000);

        // 同一地址连发 5 次中断；限流窗口 60s，因此只应放行一次。
        for (int i = 0; i < 5; i++) {
            fire(context, new SocketException("Connection reset"), peer).finishAndReleaseAll();
        }

        final long debugCount = logger.events().stream().filter(event -> event.level() == Level.DEBUG).count();
        assertEquals(1L, debugCount, "同一地址在一个限流窗口内只应产生一行 DEBUG：" + logger.events());
        assertEquals(0L, context.counters().failures(), "连接中断始终不计入「异常」");
    }

    @Test
    @DisplayName("限流分槽：同一对端先中断、再判定失败时，那条 ERROR 仍必须打得出来")
    void interruptionDoesNotConsumeFailureThrottleSlot() throws UnknownHostException {
        final RecordingLogger logger = new RecordingLogger();
        final DetectorContext context = context(logger, PluginConfig.defaults());
        final SocketAddress peer = new InetSocketAddress(InetAddress.getByName("203.0.113.8"), 50001);

        // 先制造一次连接中断：它会占用该地址在「中断」分类下的限流槽（DEBUG 只放行一条）。
        fire(context, new SocketException("Connection reset"), peer).finishAndReleaseAll();
        assertEquals(1L, logger.events().stream().filter(event -> event.level() == Level.DEBUG).count(),
                "前置：中断应当留下 DEBUG：" + logger.events());

        // 紧接着用同一地址发一次判定失败：若两类共用限流槽，这条 ERROR 会被自己的中断噪音挤掉。
        fire(context, new HAProxyProtocolException("伪造的 PROXY 头"), peer).finishAndReleaseAll();

        final Event error = logger.firstOf(Level.ERROR);
        assertNotNull(error, "判定失败不得被同一地址此前的连接中断限流抑制：" + logger.events());
        assertEquals(1L, context.counters().failures(), "判定失败仍应计入「异常」");
    }

    @Test
    @DisplayName("因果链限深遍历：多层包装内仍能正确定类")
    void classificationWalksWrappedCauseChainWithinDepthLimit() {
        Throwable wrappedIo = new IOException("Connection reset");
        for (int i = 0; i < 10; i++) {
            wrappedIo = new DecoderException(wrappedIo);
        }
        assertTrue(ProxyProtocolDetector.isConnectionInterruption(wrappedIo),
                "10 层包装里的 IOException 仍应判为连接中断");

        Throwable wrappedProxy = new HAProxyProtocolException("伪造的 PROXY 头");
        for (int i = 0; i < 10; i++) {
            wrappedProxy = new DecoderException(wrappedProxy);
        }
        assertFalse(ProxyProtocolDetector.isConnectionInterruption(wrappedProxy),
                "10 层包装里的 HAProxyProtocolException 仍应优先判为判定失败");
    }

    @Test
    @DisplayName("限深 16 的边界：恰好 16 个节点仍可定类，第 17 个节点起不再下钻")
    void causeChainDepthLimitBoundary() {
        // 15 层包装 + 最内 1 层 = 恰好 16 个节点：最内层仍在 MAX_CAUSE_DEPTH 限内 → 识别为判定失败
        Throwable atLimit = new HAProxyProtocolException("伪造的 PROXY 头");
        for (int i = 0; i < 15; i++) {
            atLimit = new DecoderException(atLimit);
        }
        assertFalse(ProxyProtocolDetector.isConnectionInterruption(atLimit),
                "第 16 个节点上的 HAProxyProtocolException 仍在限深内，应判为判定失败");

        // 16 层包装 + 最内 1 层 = 17 个节点：最内层落在限外。此时链上没有 IOException，
        // 截断后返回 false（保守按判定失败处理）——不会把「深链末端才是判定失败」误报成连接中断。
        Throwable beyondLimit = new HAProxyProtocolException("伪造的 PROXY 头");
        for (int i = 0; i < 16; i++) {
            beyondLimit = new DecoderException(beyondLimit);
        }
        assertFalse(ProxyProtocolDetector.isConnectionInterruption(beyondLimit),
                "超出限深后按判定失败处理是保守方向，不得误判为连接中断");
    }

    @Test
    @Timeout(10)
    @DisplayName("限深兜底：异常链互为因果（成环）时必须在限深处安全终止，不得死循环")
    void cyclicCauseChainTerminates() {
        // 用成对的 initCause 造出 a → b → a → … 的环。真实 Netty/JDK 异常链不会成环，
        // 但旧实现「t == t.getCause() 才停」的写法根本防不住这种环，会死循环；限深才有兜底意义。
        final RuntimeException a = new RuntimeException("a");
        final RuntimeException b = new RuntimeException("b");
        a.initCause(b);
        b.initCause(a);

        assertFalse(ProxyProtocolDetector.isConnectionInterruption(a),
                "环链上没有 IOException / HAProxyProtocolException，应保守判为失败，且必须安全终止");
    }

    @Test
    @DisplayName("限深截断的方向：真信号落在限外时不得被降级成噪音（前 16 层有 IOException 也一样）")
    void signalBeyondDepthLimitIsNotDowngradedToNoise() {
        // 第 17 个节点才是最内层的真信号；第 16 个节点是 IOException（噪音特征）；再往外 15 层 DecoderException。
        Throwable chain = new HAProxyProtocolException("伪造的 PROXY 头");
        chain = new IOException(chain);
        for (int i = 0; i < 15; i++) {
            chain = new DecoderException(chain);
        }

        // 前 16 层里出现过 IOException，但真信号在第 17 层、已越过限深：此时必须保守判为「判定失败」，
        // 绝不能因为「前 16 层见过 IOException」就把整条链降级成连接中断、抹掉伪造 PROXY 头的证据。
        assertFalse(ProxyProtocolDetector.isConnectionInterruption(chain),
                "真信号在限深之外时，宁可把噪音当信号，也不可把信号当噪音");
    }
}
