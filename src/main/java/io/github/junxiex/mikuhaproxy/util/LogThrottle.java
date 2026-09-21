package io.github.junxiex.mikuhaproxy.util;

import java.net.InetAddress;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

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

    /** 清掉已经过期的记录；如果还是满的就整体清空（比无限增长更安全）。 */
    private void prune(long now) {
        lastLogged.values().removeIf(seen -> now - seen >= intervalNanos);
        if (lastLogged.size() >= maxTracked) {
            lastLogged.clear();
        }
    }

    /** 当前正在跟踪的地址数量。仅供同包内的单元测试断言「内存占用有上界」这一保证。 */
    int tracked() {
        return lastLogged.size();
    }
}
