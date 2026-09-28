package io.github.junxiex.mikuhaproxy.util;

import java.util.concurrent.atomic.LongAdder;

/**
 * 连接计数。
 *
 * <p>内部全部使用 {@link LongAdder}：这些计数器在 Netty 的 worker 线程上被高频写入，
 * {@code LongAdder} 在多线程写入下比 {@code AtomicLong} 更省（避免单点 CAS 争用），
 * 读取（{@code /mikuproxy status}）频率极低。</p>
 *
 * <p>对外只暴露 {@code incrementXxx()} 与 {@code xxx()} 两类方法，<b>不把内部的 {@code LongAdder}
 * 交出去</b>：否则任何调用方都能对计数器 {@code reset()} / {@code decrement()}，统计也就不可信了。</p>
 */
public final class Counters {

    private final LongAdder direct = new LongAdder();
    private final LongAdder proxied = new LongAdder();
    private final LongAdder rejected = new LongAdder();
    private final LongAdder notInjected = new LongAdder();
    private final LongAdder failures = new LongAdder();

    /** 判定为直连的连接数。 */
    public void incrementDirect() {
        direct.increment();
    }

    /** 判定为代理、且白名单校验通过的连接数。 */
    public void incrementProxied() {
        proxied.increment();
    }

    /** 判定为代理、但来源不在白名单而被关闭的连接数。 */
    public void incrementRejected() {
        rejected.increment();
    }

    /**
     * 连接初始化时管道里<b>找不到</b> PROXY 解码器，探测器因此根本没被注入。
     *
     * <p>判定发生在<b>任何判定之前</b>：该连接原样交给 Velocity 原有的处理器处理。
     * 绝大多数情况意味着 {@code velocity.toml} 没开 {@code haproxy-protocol}。
     * 注意这里说的是「整条管道」，不是「管道首位」——别的插件抢先占住首位时，插件仍会退化为
     * 按类型线性查找并把探测器装上，不会走到这条计数上。</p>
     */
    public void incrementNotInjected() {
        notInjected.increment();
    }

    /**
     * 判定<b>本身</b>失败（如构造畸形的 PROXY 头被 {@code HAProxyProtocolException} 拒绝）、
     * 或探测器注入失败的连接数。
     *
     * <p>刻意<b>不含</b>「连接层中断」：对端在判定完成前 RST / 主动关闭连接（扫描器探测、客户端取消、
     * 探活）只会抛 socket 层的 {@code IOException}，判定逻辑根本还没跑，不属于需要关注的事件。
     * 把它计入只会污染「异常」计数、让真正的安全信号被淹没。</p>
     */
    public void incrementFailures() {
        failures.increment();
    }

    /** 直连连接数快照。 */
    public long direct() {
        return direct.sum();
    }

    /** 代理连接数快照。 */
    public long proxied() {
        return proxied.sum();
    }

    /** 被拒绝连接数快照。 */
    public long rejected() {
        return rejected.sum();
    }

    /** 未注入连接数快照。 */
    public long notInjected() {
        return notInjected.sum();
    }

    /** 异常计数快照。 */
    public long failures() {
        return failures.sum();
    }
}
