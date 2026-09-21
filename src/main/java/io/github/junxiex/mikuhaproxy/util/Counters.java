package io.github.junxiex.mikuhaproxy.util;

import java.util.concurrent.atomic.LongAdder;

/**
 * 连接计数。
 *
 * <p>全部使用 {@link LongAdder}：这些计数器在 Netty 的 worker 线程上被高频写入，
 * {@code LongAdder} 在多线程写入下比 {@code AtomicLong} 更省（避免单点 CAS 争用），
 * 读取（{@code /mikuproxy status}）频率极低。</p>
 */
public final class Counters {

    private final LongAdder direct = new LongAdder();
    private final LongAdder proxied = new LongAdder();
    private final LongAdder rejected = new LongAdder();
    private final LongAdder notInjected = new LongAdder();
    private final LongAdder failures = new LongAdder();

    public LongAdder direct() {
        return direct;
    }

    public LongAdder proxied() {
        return proxied;
    }

    public LongAdder rejected() {
        return rejected;
    }

    /**
     * 连接初始化时没能在管道首位找到 PROXY 解码器，探测器因此根本没被注入。
     *
     * <p>这条计数发生在<b>任何判定之前</b>：该连接原样交给 Velocity 原有的处理器处理。
     * 绝大多数情况意味着 {@code velocity.toml} 没开 {@code proxy-protocol}，
     * 也可能是别的插件先占了管道首位。</p>
     */
    public LongAdder notInjected() {
        return notInjected;
    }

    public LongAdder failures() {
        return failures;
    }
}
