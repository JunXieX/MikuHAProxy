package io.github.junxiex.mikuhaproxy;

import io.github.junxiex.mikuhaproxy.config.AllowList;
import io.github.junxiex.mikuhaproxy.config.PluginConfig;
import io.github.junxiex.mikuhaproxy.util.Counters;
import io.github.junxiex.mikuhaproxy.util.LogThrottle;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.RecordComponent;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link DetectorContext} 的测试（此前只被间接用到）。
 *
 * <p>它虽然只是一个 record，却承担着两条容易静默出错的约定：组件<b>顺序</b>（生产代码按位置构造它）
 * 和「持有的是同一批对象而不是副本」（计数器跨快照复用就靠这个）。两者都不会在编译期报错，
 * 只会让运行时行为悄悄变样——正是最该被测试钉住的那类东西。</p>
 */
class DetectorContextTest {

    @Test
    @DisplayName("组件顺序被钉住：生产代码按位置构造，顺序一变计数与限流器会被静默对调")
    void componentOrderIsPinned() {
        final List<String> components = Arrays.stream(DetectorContext.class.getRecordComponents())
                .map(RecordComponent::getName)
                .toList();

        assertEquals(List.of("allowList", "settings", "counters", "throttle", "logger"), components,
                "DetectorContext 由 MikuHAProxy.doLoadConfiguration 按位置 new 出来："
                        + "重排组件不会报编译错，但会把计数器与限流器装反（统计丢失、限流参数失效）");
        assertTrue(DetectorContext.class.isRecord(), "快照必须是 record：不可变是「读路径无锁」的前提");
    }

    @Test
    @DisplayName("快照持有的是同一批对象（不是副本），且对外只提供读取")
    void snapshotHoldsTheSameInstancesAndIsReadOnly() {
        final AllowList allowList = AllowList.DENY_ALL;
        final PluginConfig settings = PluginConfig.defaults();
        final Counters counters = new Counters();
        final LogThrottle throttle = new LogThrottle(60, 16);
        final Logger logger = LoggerFactory.getLogger(DetectorContextTest.class);

        final DetectorContext context = new DetectorContext(allowList, settings, counters, throttle, logger);

        assertSame(allowList, context.allowList());
        assertSame(settings, context.settings());
        assertSame(counters, context.counters(),
                "计数器必须原样持有：重载时「统计不清零」就靠它跨快照存活");
        assertSame(throttle, context.throttle(),
                "限流器同样原样持有：每次重载新建一个，不能在这里被复制");
        assertSame(logger, context.logger());

        assertTrue(Arrays.stream(DetectorContext.class.getMethods())
                        .noneMatch(method -> method.getName().startsWith("set")),
                "快照只读：出现任何 set 方法，重载期间「新连接用新配置、老连接用老配置」的一致性就没了");
    }
}
