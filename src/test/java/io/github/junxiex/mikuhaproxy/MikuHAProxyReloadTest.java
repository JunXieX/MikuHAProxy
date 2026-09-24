package io.github.junxiex.mikuhaproxy;

import io.github.junxiex.mikuhaproxy.config.PluginConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 热重载的语义守护：计数器跨快照复用、限流器按新参数重建、失败时保留原快照。
 *
 * <p>这些行为此前没有任何测试守护，而 {@code DetectorContext} 的类注释曾与实际行为矛盾
 * （已订正）：没有测试的话，一次「看起来在修注释不一致」的顺手改动就可能让限流参数
 * 从此不随配置更新，CI 全绿、静默回归。</p>
 */
class MikuHAProxyReloadTest {

    @SuppressWarnings("unchecked")
    private static AtomicReference<DetectorContext> snapshotRef(MikuHAProxy plugin) throws Exception {
        final Field field = MikuHAProxy.class.getDeclaredField("context");
        field.setAccessible(true);
        return (AtomicReference<DetectorContext>) field.get(plugin);
    }

    private static MikuHAProxy plugin(Path dataDir) {
        // 构造函数在加载路径上不触碰 server：DataFolder.resolve 是纯文件系统决策，
        // new ChannelHook 只做字段赋值，writeDefaultResource 读的是 classpath 资源，
        // 所以传 null 是合法的（Velocity 不需要出现在测试 classpath 上）。
        // 若将来构造里加了 server.xxx，这里会 NPE —— 属于响亮失败，可接受。
        return new MikuHAProxy(null, LoggerFactory.getLogger(MikuHAProxyReloadTest.class), dataDir);
    }

    @Test
    @DisplayName("reload：快照整体替换，计数器跨快照复用，限流器按新参数重建")
    void reloadKeepsCountersAndRebuildsThrottle(@TempDir Path dir) throws Exception {
        final MikuHAProxy plugin = plugin(dir);
        final AtomicReference<DetectorContext> ref = snapshotRef(plugin);
        assertNull(ref.get(), "加载前不应有配置快照");

        assertTrue(plugin.loadConfiguration(true), "首次加载应当成功（默认文件从 classpath 资源写出）");
        final DetectorContext first = ref.get();
        assertNotNull(first, "加载成功后必须有快照");

        first.counters().incrementDirect();
        first.counters().incrementRejected();

        assertTrue(plugin.loadConfiguration(false), "重载应当成功");
        final DetectorContext second = ref.get();

        assertNotSame(first, second, "重载必须整体替换快照，新连接才用得上新配置");
        assertSame(first.counters(), second.counters(), "计数器跨快照复用：重载不得清零统计");
        assertNotSame(first.throttle(), second.throttle(), "限流器每次重载按新配置重建，新连接才能用上新参数");
        assertEquals(1L, second.counters().direct(), "重载后计数保持");
        assertEquals(1L, second.counters().rejected(), "重载后计数保持");
    }

    @Test
    @DisplayName("reload 失败：保留原有配置快照（before == after），插件继续用旧配置")
    void failedReloadKeepsPreviousSnapshot(@TempDir Path dir) throws Exception {
        final MikuHAProxy plugin = plugin(dir);
        final AtomicReference<DetectorContext> ref = snapshotRef(plugin);
        assertTrue(plugin.loadConfiguration(true));
        final DetectorContext before = ref.get();
        assertNotNull(before);

        // 让 reload 必然失败：把 config.toml 换成同名目录，PluginConfig.load 读取时抛 IOException。
        // 这是平台无关的构造方式（「目录不可作为文件读出」在 Linux CI 与 Windows 上行为一致）。
        final Path configFile = dir.resolve(PluginConfig.FILE_NAME);
        Files.delete(configFile);
        Files.createDirectory(configFile);

        final List<String> problems = new ArrayList<>();
        assertFalse(plugin.loadConfiguration(false, problems::add), "配置读不出来时必须报失败");
        assertSame(before, ref.get(), "失败时必须保留原有快照——线上正在用的配置不能被半新半旧的快照顶掉");
    }
}
