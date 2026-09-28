package io.github.junxiex.mikuhaproxy.util;

import java.net.InetAddress;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 按来源地址限流的日志开关。
 *
 * <p>被拒绝的代理连接来自公网，攻击者可以轻易轮换源 IP；不加约束的话，日志会被淹没、磁盘会被写满。
 * 这里用<b>有容量上限的时间窗限流</b>：同一个限流槽在 {@code intervalNanos} 内只放行一条日志，
 * 并且最多跟踪 {@code maxTracked} 个槽位，内存占用始终有上界。</p>
 *
 * <p><b>为什么限流键要带一个「分类」维度</b>：同一个对端地址可能产生两类日志——真正的安全信号
 * （代理被拒绝、判定失败）与正常网络噪音（连接在判定前被对端中断）。若二者共用一个槽位，攻击者只要
 * 用自己的 IP 先制造一次中断、把该地址的槽位占掉，就能在时间窗内把随后那条「伪造 PROXY 头」的
 * ERROR 一并挤掉——真实攻击信号被自己制造的噪音盖住。因此这里把「分类」并入限流键，让噪音与信号
 * <b>分槽</b>，互不挤占。代价只是一个键多带一个字符串维度，容量上限仍由 {@code maxTracked} 统一约束。</p>
 */
public final class LogThrottle {

    /**
     * 安全信号日志（代理被拒绝、判定失败）共用的分类。
     *
     * <p>这两类都由 {@code log-rejected-connections} 开关控制、都属于「有人在对这个端口做坏事」的线索，
     * 因此刻意共用同一槽位：同一个对端在一个时间窗内出一条信号就够了，不必区分是拒绝还是判定失败。</p>
     */
    public static final String CATEGORY_SIGNAL = "signal";

    /**
     * 连接中断日志（正常网络噪音）的独立分类。
     *
     * <p>必须与 {@link #CATEGORY_SIGNAL} 分槽：中断是本插件遇到的最高频「异常」，若它也占用信号槽位，
     * 就会把真正的判定失败日志排挤掉。</p>
     */
    public static final String CATEGORY_INTERRUPTION = "interruption";

    private final long intervalNanos;
    private final int maxTracked;

    /** 限流槽 → 上次放行时刻；槽由「分类 + 来源地址」共同决定。 */
    private final Map<Slot, Long> lastLogged = new ConcurrentHashMap<>();

    /** 上一次全量清理的时刻，仅用于给清理限频；CAS 失败说明别的线程刚清过，跳过即可。 */
    private final AtomicLong lastPruneNanos = new AtomicLong();

    /** 一个限流槽：同一地址的不同分类互不影响。 */
    private record Slot(String category, InetAddress address) {
    }

    public LogThrottle(long intervalSeconds, int maxTracked) {
        this.intervalNanos = Math.max(0L, intervalSeconds) * 1_000_000_000L;
        this.maxTracked = Math.max(16, maxTracked);
    }

    /**
     * 判断这次是否应该输出日志（使用 {@link #CATEGORY_SIGNAL} 分类）。
     *
     * @param key 限流键，通常是来源地址；{@code null} 表示未知地址，直接放行（不做键比较）
     * @return {@code true} 表示本次应当输出日志
     */
    public boolean shouldLog(InetAddress key) {
        return shouldLog(key, CATEGORY_SIGNAL);
    }

    /**
     * 判断这次是否应该输出日志，并让不同分类的日志各自独立限流。
     *
     * @param key      限流键，通常是来源地址；{@code null} 表示未知地址，直接放行（不做键比较）
     * @param category 日志分类（见 {@link #CATEGORY_SIGNAL} / {@link #CATEGORY_INTERRUPTION}）；
     *                 相同地址的不同分类互不挤占
     * @return {@code true} 表示本次应当输出日志
     */
    public boolean shouldLog(InetAddress key, String category) {
        if (key == null || intervalNanos <= 0L) {
            return true;
        }
        final Slot slot = new Slot(category, key);
        final long now = System.nanoTime();
        final Long previous = lastLogged.get(slot);
        if (previous != null && now - previous < intervalNanos) {
            return false;
        }
        if (previous == null && lastLogged.size() >= maxTracked) {
            prune(now);
        }
        lastLogged.put(slot, now);
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

    /**
     * 当前正在跟踪的槽位数量（所有分类合计）。
     *
     * <p>仅供同包内的单元测试断言「内存占用有上界」这一保证。</p>
     */
    int tracked() {
        return lastLogged.size();
    }
}
