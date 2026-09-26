package io.github.junxiex.mikuhaproxy;

import com.velocitypowered.api.event.proxy.ProxyInitializeEvent;
import com.velocitypowered.api.event.proxy.ProxyShutdownEvent;
import com.velocitypowered.api.proxy.ProxyServer;
import io.github.junxiex.mikuhaproxy.config.DataFolder;
import io.github.junxiex.mikuhaproxy.net.ChannelHook;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 插件<b>入口的失败路径</b>测试（此前零覆盖）。
 *
 * <p>要守住的是一条顺序保证：<b>配置加载 → 注入 → 注册命令</b>，任一步失败都必须<b>短路</b>，
 * 而且都不能把异常抛给 Velocity（代理是顺序初始化所有插件的，抛出去就是在拿整个代理的启动开玩笑）。
 * 顺序错了的后果很具体：命令已注册但没接管连接，服主执行 {@code /mikuproxy status} 会看到
 * 「未安装」的同时命令还能用，于是误判成配置问题而反复重启。</p>
 *
 * <p>替身：{@code ProxyServer} 用动态代理，只记录「服务端上被调用过哪些方法」。这正好用来验证
 * 短路——例如注入失败时，{@code getCommandManager} 必须一次都没被调用过。</p>
 */
class MikuHAProxyInitializeTest {

    /** 记录服务端替身被调用了哪些方法。 */
    private static final class ServerCalls implements InvocationHandler {

        final List<String> names = new CopyOnWriteArrayList<>();

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) {
            final String name = method.getName();
            switch (name) {
                case "toString" -> {
                    return "proxy-server";
                }
                case "hashCode" -> {
                    return System.identityHashCode(proxy);
                }
                case "equals" -> {
                    return proxy == args[0];
                }
                default -> {
                    names.add(name);
                    return null;
                }
            }
        }
    }

    private static ProxyServer proxyServer(ServerCalls calls) {
        return (ProxyServer) Proxy.newProxyInstance(MikuHAProxyInitializeTest.class.getClassLoader(),
                new Class<?>[]{ProxyServer.class}, calls);
    }

    /** Velocity 注入的小写目录（不存在 ⇒ {@code DataFolder.resolve} 会落到 {@code plugins/MikuHAProxy}）。 */
    private static Path injectedDataDir(Path temp) throws IOException {
        final Path base = temp.resolve("plugins");
        Files.createDirectories(base);
        return base.resolve("mikuhaproxy");
    }

    /**
     * 目标目录位置被一个<b>同名普通文件</b>占用。
     *
     * <p>这是平台无关的失败构造：{@code Files.createDirectories} 在目录位置上遇到普通文件时必定抛
     * {@code IOException}，于是 {@code loadConfiguration} 返回 false。</p>
     */
    private static Path injectedDataDirWithOccupiedTarget(Path temp) throws IOException {
        final Path base = temp.resolve("plugins");
        Files.createDirectories(base);
        Files.createFile(base.resolve(DataFolder.NAME));
        return base.resolve("mikuhaproxy");
    }

    private static MikuHAProxy plugin(ProxyServer server, Path dataDirectory) {
        return new MikuHAProxy(server, LoggerFactory.getLogger(MikuHAProxyInitializeTest.class), dataDirectory);
    }

    @SuppressWarnings("unchecked")
    private static AtomicReference<DetectorContext> snapshot(MikuHAProxy plugin) throws Exception {
        final Field field = MikuHAProxy.class.getDeclaredField("context");
        field.setAccessible(true);
        return (AtomicReference<DetectorContext>) field.get(plugin);
    }

    private static ChannelHook hook(MikuHAProxy plugin) throws Exception {
        final Field field = MikuHAProxy.class.getDeclaredField("hook");
        field.setAccessible(true);
        return (ChannelHook) field.get(plugin);
    }

    @Test
    @DisplayName("配置加载失败：初始化短路——没有快照、没有注入、一次都不碰服务端，且不抛异常")
    void configurationFailureShortCircuitsInitialization(@TempDir Path temp) throws Exception {
        final ServerCalls calls = new ServerCalls();
        final MikuHAProxy plugin = plugin(proxyServer(calls), injectedDataDirWithOccupiedTarget(temp));

        plugin.onProxyInitialize(new ProxyInitializeEvent());

        assertNull(snapshot(plugin).get(), "配置没加载成功就不该有配置快照");
        assertFalse(hook(plugin).isInstalled(), "配置没加载成功就不该接管连接初始化流程");
        assertTrue(calls.names.isEmpty(),
                "配置失败发生在碰服务端之前，因此一次调用都不该发生：" + calls.names);
    }

    @Test
    @DisplayName("注入失败：快照照常建立，但绝不注册命令（命令必须在注入成功之后才注册）")
    void injectionFailureSkipsCommandRegistration(@TempDir Path temp) throws Exception {
        final ServerCalls calls = new ServerCalls();
        // 替身只实现 ProxyServer：ChannelHook 既找不到 getConnectionManager() 访问器，
        // 也找不到 ConnectionManager 字段 ⇒ 注入必然失败（这正是上游结构变化时的表现）
        final MikuHAProxy plugin = plugin(proxyServer(calls), injectedDataDir(temp));

        plugin.onProxyInitialize(new ProxyInitializeEvent());

        assertNotNull(snapshot(plugin).get(), "配置应当加载成功（默认文件由 classpath 资源写出）");
        assertFalse(hook(plugin).isInstalled(), "定位不到连接管理器 ⇒ 注入失败");
        assertTrue(calls.names.isEmpty(),
                "注入的第一步就是定位连接管理器，失败发生在碰服务端之前 —— "
                        + "连「软读 haproxy-protocol 开关」都走不到：" + calls.names);
        assertFalse(calls.names.contains("getCommandManager"),
                "注入失败时不能注册命令，否则服主会看到一个「能用但没生效」的命令：" + calls.names);
    }

    @Test
    @DisplayName("关机事件：不假装已安装，也不把配置快照清掉（插件进程内可能还会被再次访问）")
    void shutdownKeepsConfigurationAndReportsNotInstalled(@TempDir Path temp) throws Exception {
        final MikuHAProxy plugin = plugin(proxyServer(new ServerCalls()), injectedDataDir(temp));
        assertTrue(plugin.loadConfiguration(true), "夹具：先有一份配置快照");

        plugin.onProxyShutdown(new ProxyShutdownEvent());

        assertFalse(hook(plugin).isInstalled(), "关机不该呈现「已安装」状态");
        assertNotNull(snapshot(plugin).get(), "关机只还原管道，不清配置");
    }

    @Test
    @DisplayName("加载成功后再失败重载：快照不被清掉，插件仍可用旧配置工作")
    void failedReloadDoesNotClearSnapshot(@TempDir Path temp) throws Exception {
        final MikuHAProxy plugin = plugin(proxyServer(new ServerCalls()), injectedDataDir(temp));
        assertTrue(plugin.loadConfiguration(true));
        final DetectorContext before = snapshot(plugin).get();
        assertNotNull(before);

        // 把数据目录换成同名普通文件 ⇒ createDirectories 抛 IOException ⇒ 加载失败
        final Path dir = temp.resolve("plugins").resolve(DataFolder.NAME);
        try (var walk = Files.walk(dir)) {
            walk.sorted(java.util.Comparator.reverseOrder()).forEach(path -> {
                try {
                    Files.delete(path);
                } catch (IOException ignored) {
                    // 夹具清理失败不该掩盖主线断言
                }
            });
        }
        Files.createFile(dir);

        assertFalse(plugin.loadConfiguration(false), "数据目录被文件占用时必须报失败");
        assertTrue(before == snapshot(plugin).get(), "失败时保留原快照，线上正在用的配置不能被顶掉");
    }
}
