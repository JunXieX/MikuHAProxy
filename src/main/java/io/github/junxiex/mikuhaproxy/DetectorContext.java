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
 * 已经建立的连接，也不需要给热路径加锁——新连接天然使用新配置。计数器与限流器则跨快照复用，
 * 保证统计与限流不会因为重载被清零。</p>
 *
 * @param allowList 允许的代理来源
 * @param settings  当前配置
 * @param counters  全局计数器（跨快照复用，重载不清零）
 * @param throttle  拒绝 / 异常日志限流器（每次重载按新配置重建，未建立的连接不会沿用旧参数）
 * @param logger    插件日志
 */
public record DetectorContext(
        AllowList allowList,
        PluginConfig settings,
        Counters counters,
        LogThrottle throttle,
        Logger logger) {
}
