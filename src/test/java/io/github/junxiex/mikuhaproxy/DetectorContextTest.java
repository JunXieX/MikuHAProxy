package io.github.junxiex.mikuhaproxy;

import io.github.junxiex.mikuhaproxy.config.AllowList;
import io.github.junxiex.mikuhaproxy.config.PluginConfig;
import io.github.junxiex.mikuhaproxy.util.Counters;
import io.github.junxiex.mikuhaproxy.util.LogThrottle;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Method;
import java.lang.reflect.RecordComponent;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

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
                        .filter(method -> method.getDeclaringClass() == DetectorContext.class)
                        .map(Method::getName)
                        .collect(Collectors.toSet())
                        .equals(SURFACE),
                "快照的公开表面必须恰好是 5 个读取器 + equals/hashCode/toString。"
                        + "一旦多出方法（尤其是 setXxx），重载期间「新连接用新配置、老连接用老配置」的一致性就没了。"
                        + "有意扩展时更新 SURFACE 再确认一遍；实际是 " + surface());
    }

    /**
     * 本 record 允许出现的公开表面。
     *
     * <p>⚠️ 别改成「名字不以 set 开头」那种图省事的写法：record 的 {@code settings()} 访问器本身就以
     * {@code set} 开头，宽谓词会把它误判成 setter（2026-09-26 在 CI 上真的踩了一次）。</p>
     */
    private static final Set<String> SURFACE =
            Set.of("allowList", "settings", "counters", "throttle", "logger", "equals", "hashCode", "toString");

    private static Set<String> surface() {
        return Arrays.stream(DetectorContext.class.getMethods())
                .filter(method -> method.getDeclaringClass() == DetectorContext.class)
                .map(Method::getName)
                .collect(Collectors.toSet());
    }
}
