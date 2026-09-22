package io.github.junxiex.mikuhaproxy.util;

import java.net.InetAddress;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 按来源地址限流的日志开关。
 *
 * <p>被拒绝的代理连接来自公网，攻击者可以轻易轮换源 IP；不加约束的话，日志会被淹没、磁盘会被写满。
 * 这里用<b>有容量上限的时间窗限流</b>：同一个地址在 {@code intervalNanos} 内只放行一条日志，
 * 并且最多跟踪 {@code maxTracked} 个地址，内存占用始终有上界。</p>
 */
public final class LogThrottle {

    private final long intervalNanos;
    private final int maxTracked;
    private final Map<InetAddress, Long> lastLogged = new ConcurrentHashMap<>();

    /** 上一次全量清理的时刻，仅用于给清理限频；CAS 失败说明别的线程刚清过，跳过即可。 */
    private final AtomicLong lastPruneNanos = new AtomicLong();

    public LogThrottle(long intervalSeconds, int maxTracked) {
        this.intervalNanos = Math.max(0L, intervalSeconds) * 1_000_000_000L;
        this.maxTracked = Math.max(16, maxTracked);
    }

    /**
     * 判断这次是否应该输出日志。
     *
     * @param key 限流键，通常是来源地址；{@code null} 表示未知地址，直接放行（不做键比较）
     * @return {@code true} 表示本次应当输出日志
     */
    public boolean shouldLog(InetAddress key) {
        if (key == null || intervalNanos <= 0L) {
            return true;
        }
        final long now = System.nanoTime();
        final Long previous = lastLogged.get(key);
        if (previous != null && now - previous < intervalNanos) {
            return false;
        }
        if (previous == null && lastLogged.size() >= maxTracked) {
            prune(now);
        }
        lastLogged.put(key, now);
        return true;
    }

    /**
     * 把跟踪表拉回容量上限之内。
     *
     * <p>全量扫描（{@code removeIf}）<b>至多每个时间窗做一次</b>：攻击者轮换源 IP 时，每个新地址都会
     * 走到这里，如果每次都把 4096 项扫一遍，等于让「日志限流」自己变成了放大器。两次扫描之间若仍然
     * 超限，就直接整体清空（O(1)）——代价是那张记录暂时失效（限流在这段时间里会放宽），换来的是
     * 内存占用始终有上界、且开销不随新地址的数量线性增长。</p>
     */
    private void prune(long now) {
        final long last = lastPruneNanos.get();
        if (now - last >= intervalNanos && lastPruneNanos.compareAndSet(last, now)) {
            lastLogged.values().removeIf(seen -> now - seen >= intervalNanos);
        }
        if (lastLogged.size() >= maxTracked) {
            // 兜底：即使在两次全量清理之间，也不允许跟踪表无限增长
            lastLogged.clear();
        }
    }

    /** 当前正在跟踪的地址数量。仅供同包内的单元测试断言「内存占用有上界」这一保证。 */
    int tracked() {
        return lastLogged.size();
    }
}
