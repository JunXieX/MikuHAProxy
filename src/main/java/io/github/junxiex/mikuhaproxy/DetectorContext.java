package io.github.junxiex.mikuhaproxy;

import io.github.junxiex.mikuhaproxy.config.AllowList;
import io.github.junxiex.mikuhaproxy.config.PluginConfig;
import io.github.junxiex.mikuhaproxy.util.Counters;
import io.github.junxiex.mikuhaproxy.util.LogThrottle;
import org.slf4j.Logger;

/**
 * 每条新连接在创建探测器时取用的一份「配置快照」。
 *
 * <p>把它做成不可变对象、由插件用 {@code volatile} 引用整体替换，好处是：重载配置时不需要碰
 * 已经建立的连接，也不需要给热路径加锁——新连接天然使用新配置。<b>反过来说，重载前已建立的连接会继续
 * 持有旧快照（连同其中的限流参数）直到连接结束</b>，这是刻意保留的行为（那批连接随时可能被关闭，为它们
 * 逐个换配置没有意义，也不安全）。<b>但两个成员的生命周期刻意不同</b>：计数器跨快照复用，保证统计不会因为重载被清零；限流器则每次重载都按新参数重建（详见 {@code @param throttle}）。</p>
 *
 * @param allowList 允许的代理来源
 * @param settings  当前配置
 * @param counters  全局计数器（跨快照复用，重载不清零）
 * @param throttle  拒绝 / 判定失败 / 连接中断三类日志的限流器（各分类独立分槽，互不挤占；
 *                  每次重载按新配置重建，因此重载后新建的连接使用新限流参数）
 * @param logger    插件日志
 */
public record DetectorContext(
        AllowList allowList,
        PluginConfig settings,
        Counters counters,
        LogThrottle throttle,
        Logger logger) {
}
