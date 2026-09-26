package io.github.junxiex.mikuhaproxy.command;

import com.mojang.brigadier.CommandDispatcher;
import com.mojang.brigadier.exceptions.CommandSyntaxException;
import com.mojang.brigadier.tree.CommandNode;
import com.mojang.brigadier.tree.LiteralCommandNode;
import com.velocitypowered.api.command.BrigadierCommand;
import com.velocitypowered.api.command.CommandSource;
import com.velocitypowered.api.permission.Tristate;
import io.github.junxiex.mikuhaproxy.MikuHAProxy;
import io.github.junxiex.mikuhaproxy.config.PluginConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code /mikuproxy} 命令层的测试（此前零覆盖）。
 *
 * <p>用 Brigadier 的 {@link CommandDispatcher} 真正执行命令树，而不是只断言「方法被调用了」：
 * 这样连「权限节点有没有挂上」「子命令名字有没有写错」都一起被覆盖——那两类错误都能让服主
 * 看到「未知命令」，而它们的成因完全在命令树里。回显内容用动态代理的 {@link CommandSource} 捕获。</p>
 *
 * <p>{@code MikuHAProxy} 用 {@code server = null} 构造（与 {@code MikuHAProxyReloadTest} 同理：
 * 加载路径上不触碰 server）。{@code status} 会因此把 {@code haproxy-protocol} 报成「读取失败」，
 * 这是刻意的确定性断言——那条路正是「读不到开关也要如实说读不到，不能猜」。</p>
 */
class MikuProxyCommandTest {

    /** 记录命令回显；权限判定按构造时给的布尔值回答。 */
    private static final class RecordingSource implements InvocationHandler {

        private final boolean permission;
        final List<String> messages = new CopyOnWriteArrayList<>();

        RecordingSource(boolean permission) {
            this.permission = permission;
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) {
            final String name = method.getName();
            switch (name) {
                case "sendRichMessage" -> {
                    final Object first = args == null || args.length == 0 ? null : args[0];
                    if (first instanceof String text) {
                        messages.add(text);
                    }
                    return null;
                }
                case "hasPermission" -> {
                    return permission;
                }
                case "getPermissionValue" -> {
                    return permission ? Tristate.TRUE : Tristate.FALSE;
                }
                case "toString" -> {
                    return "recording-source";
                }
                case "hashCode" -> {
                    return System.identityHashCode(proxy);
                }
                case "equals" -> {
                    return proxy == args[0];
                }
                default -> {
                    return defaultValue(method.getReturnType());
                }
            }
        }

        String joined() {
            return String.join("\n", messages);
        }
    }

    /** 未显式处理的接口方法：按返回类型给安全默认值，避免原始类型被 null 拆箱炸掉。 */
    private static Object defaultValue(Class<?> type) {
        if (!type.isPrimitive() || type == void.class) {
            return null;
        }
        if (type == boolean.class) {
            return false;
        }
        if (type == long.class) {
            return 0L;
        }
        if (type == int.class) {
            return 0;
        }
        if (type == short.class) {
            return (short) 0;
        }
        if (type == byte.class) {
            return (byte) 0;
        }
        if (type == char.class) {
            return (char) 0;
        }
        if (type == float.class) {
            return 0f;
        }
        return 0d;
    }

    private static CommandSource commandSource(RecordingSource recorder) {
        return (CommandSource) Proxy.newProxyInstance(MikuProxyCommandTest.class.getClassLoader(),
                new Class<?>[]{CommandSource.class}, recorder);
    }

    /** 把命令树挂到真实的 Brigadier 派发器上，走与代理端一致的执行路径。 */
    private static CommandDispatcher<CommandSource> dispatcher(MikuHAProxy plugin) {
        final BrigadierCommand command = MikuProxyCommand.create(plugin);
        final CommandDispatcher<CommandSource> dispatcher = new CommandDispatcher<>();
        dispatcher.getRoot().addChild(command.getNode());
        return dispatcher;
    }

    /** Velocity 注入的小写目录（不存在 ⇒ {@code DataFolder.resolve} 会落到 {@code plugins/MikuHAProxy}）。 */
    private static Path injectedDataDir(Path temp) throws IOException {
        final Path base = temp.resolve("plugins");
        Files.createDirectories(base);
        return base.resolve("mikuhaproxy");
    }

    /** 构造后实际生效的数据目录（便于提前摆好 config.toml / whitelist.conf）。 */
    private static Path effectiveDataDir(Path temp) {
        return temp.resolve("plugins").resolve("MikuHAProxy");
    }

    private static MikuHAProxy plugin(Path dataDir) {
        return new MikuHAProxy(null, LoggerFactory.getLogger(MikuProxyCommandTest.class), dataDir);
    }

    /** 已经加载过配置的插件：{@code list} / {@code status} / {@code reload} 都要求存在配置快照。 */
    private static MikuHAProxy pluginWithConfiguration(Path temp) throws IOException {
        final MikuHAProxy plugin = plugin(injectedDataDir(temp));
        assertTrue(plugin.loadConfiguration(true), "夹具：配置应当加载成功");
        return plugin;
    }

    @SuppressWarnings("unchecked")
    private static AtomicReference<?> snapshot(MikuHAProxy plugin) throws Exception {
        final Field field = MikuHAProxy.class.getDeclaredField("context");
        field.setAccessible(true);
        return (AtomicReference<?>) field.get(plugin);
    }

    // ------------------------------------------------------------------
    // 命令树形状与权限
    // ------------------------------------------------------------------

    @Test
    @DisplayName("命令树：根字面量是 mikuproxy，子命令恰好是 status / list / reload")
    void commandTreeShape(@TempDir Path temp) throws Exception {
        final LiteralCommandNode<CommandSource> node = MikuProxyCommand.create(plugin(injectedDataDir(temp))).getNode();

        assertEquals("mikuproxy", node.getName(), "根字面量名必须与命令名一致");
        assertEquals(Set.of("status", "list", "reload"),
                node.getChildren().stream().map(CommandNode::getName).collect(Collectors.toSet()),
                "子命令集合一旦变化，文档里的用法与补全都跟着错");
        assertEquals("mikuhaproxy.admin", MikuProxyCommand.PERMISSION);
    }

    @Test
    @DisplayName("权限：requires 只认 mikuhaproxy.admin")
    void requiresTheDocumentedPermission(@TempDir Path temp) throws Exception {
        final LiteralCommandNode<CommandSource> node = MikuProxyCommand.create(plugin(injectedDataDir(temp))).getNode();

        assertFalse(node.getRequirement().test(commandSource(new RecordingSource(false))),
                "没有权限的来源必须被 requires 拒绝");
        assertTrue(node.getRequirement().test(commandSource(new RecordingSource(true))));
    }

    @Test
    @DisplayName("权限：无权限时四条命令都不可用，且一行回显都不会发出去")
    void subcommandsAreBlockedWithoutPermission(@TempDir Path temp) throws Exception {
        final CommandDispatcher<CommandSource> dispatcher = dispatcher(plugin(injectedDataDir(temp)));
        final RecordingSource denied = new RecordingSource(false);
        final CommandSource source = commandSource(denied);

        for (String line : List.of("mikuproxy", "mikuproxy status", "mikuproxy list", "mikuproxy reload")) {
            assertThrows(CommandSyntaxException.class, () -> dispatcher.execute(line, source),
                    "没有权限时「" + line + "」必须不可用");
        }
        assertTrue(denied.messages.isEmpty(), "被拒的命令不得回显任何内容：" + denied.messages);
    }

    // ------------------------------------------------------------------
    // 四个子命令的回显
    // ------------------------------------------------------------------

    @Test
    @DisplayName("无参数：显示帮助，含版本与三个子命令用法")
    void showsHelp(@TempDir Path temp) throws Exception {
        final RecordingSource recorder = new RecordingSource(true);

        assertEquals(1, dispatcher(plugin(injectedDataDir(temp))).execute("mikuproxy", commandSource(recorder)),
                "Brigadier 约定：执行成功返回 1");
        assertEquals(4, recorder.messages.size(), recorder.messages.toString());
        assertTrue(recorder.messages.get(0).contains("MikuHAProxy"), recorder.messages.get(0));
        assertTrue(recorder.messages.get(0).contains(MikuHAProxy.VERSION));
        final String text = recorder.joined();
        assertTrue(text.contains("/mikuproxy status"), text);
        assertTrue(text.contains("/mikuproxy list"), text);
        assertTrue(text.contains("/mikuproxy reload"), text);
    }

    @Test
    @DisplayName("status：注入状态、haproxy-protocol、白名单概览、五项计数与运行时间都在")
    void statusReportsEverything(@TempDir Path temp) throws Exception {
        final RecordingSource recorder = new RecordingSource(true);

        dispatcher(pluginWithConfiguration(temp)).execute("mikuproxy status", commandSource(recorder));

        final String text = recorder.joined();
        assertTrue(text.contains("管道注入："), text);
        assertTrue(text.contains("未安装"), "测试里没装钩子，必须如实报未安装：" + text);
        assertTrue(text.contains("haproxy-protocol"), text);
        assertTrue(text.contains("读取失败"), "server 为 null ⇒ 读不到开关，不许猜一个值：" + text);
        assertTrue(text.contains("白名单："), text);
        assertTrue(text.contains("2 条规则"), "出厂模板含 127.0.0.0/8 与 ::1/128：" + text);
        assertTrue(text.contains("连接计数："), text);
        for (String counter : List.of("直连 0", "代理 0", "拒绝 0", "未注入 0", "异常 0")) {
            assertTrue(text.contains(counter), "计数「" + counter + "」应当出现：" + text);
        }
        assertTrue(text.contains("已运行："), text);
    }

    @Test
    @DisplayName("list：逐条列出当前生效的白名单规则")
    void listShowsRules(@TempDir Path temp) throws Exception {
        final RecordingSource recorder = new RecordingSource(true);

        dispatcher(pluginWithConfiguration(temp)).execute("mikuproxy list", commandSource(recorder));

        final String text = recorder.joined();
        assertTrue(text.contains("白名单规则（2 条）"), text);
        assertTrue(text.contains("127.0.0.0/8"), text);
        assertTrue(text.contains("::1/128"), text);
    }

    @Test
    @DisplayName("list：白名单为空时明确提示「所有代理连接都会被拒绝」")
    void listWarnsWhenWhitelistIsEmpty(@TempDir Path temp) throws Exception {
        final Path dir = effectiveDataDir(temp);
        Files.createDirectories(dir);
        Files.writeString(dir.resolve(PluginConfig.FILE_NAME), "whitelist-file = \"whitelist.conf\"\n",
                StandardCharsets.UTF_8);
        Files.writeString(dir.resolve("whitelist.conf"), "# 只有注释，一条规则都没有\n", StandardCharsets.UTF_8);

        final RecordingSource recorder = new RecordingSource(true);
        dispatcher(pluginWithConfiguration(temp)).execute("mikuproxy list", commandSource(recorder));

        assertTrue(recorder.joined().contains("白名单为空：所有代理连接都会被拒绝"),
                "空白名单是安全默认值，必须说清楚它的后果：" + recorder.joined());
    }

    @Test
    @DisplayName("reload：写错的配置项会被回显给执行者，并说明已回退默认值")
    void reloadReportsConfigProblems(@TempDir Path temp) throws Exception {
        final Path dir = effectiveDataDir(temp);
        Files.createDirectories(dir);
        Files.writeString(dir.resolve(PluginConfig.FILE_NAME), "unknown-key = 1\n", StandardCharsets.UTF_8);

        final MikuHAProxy plugin = plugin(injectedDataDir(temp));
        assertTrue(plugin.loadConfiguration(false), "夹具：先有一份快照，reload 才有「前后」可比");

        final RecordingSource recorder = new RecordingSource(true);
        dispatcher(plugin).execute("mikuproxy reload", commandSource(recorder));

        final String text = recorder.joined();
        assertTrue(text.contains("配置已重载"), text);
        assertTrue(text.contains("白名单 0 → 2 条规则"), "reload 与启动路径一致，会先写出厂模板再读：" + text);
        assertTrue(text.contains("发现 1 处配置问题"), text);
        assertTrue(text.contains("未知设置项"), "问题必须说清是哪一项：" + text);
        assertTrue(text.contains("已回退到默认值"), text);
        assertNotNull(snapshot(plugin).get(), "重载成功后必须有新快照");
    }

    @Test
    @DisplayName("reload：allow-all-proxies = true 时回显红色安全警告")
    void reloadWarnsAboutAllowAllProxies(@TempDir Path temp) throws Exception {
        final Path dir = effectiveDataDir(temp);
        Files.createDirectories(dir);
        Files.writeString(dir.resolve(PluginConfig.FILE_NAME), "allow-all-proxies = true\n", StandardCharsets.UTF_8);

        final MikuHAProxy plugin = plugin(injectedDataDir(temp));
        assertTrue(plugin.loadConfiguration(false), "夹具：先有一份快照");

        final RecordingSource recorder = new RecordingSource(true);
        dispatcher(plugin).execute("mikuproxy reload", commandSource(recorder));

        final String text = recorder.joined();
        assertTrue(text.contains("任何来源都能伪造 PROXY 头"), text);
        assertTrue(text.contains("切勿在生产环境使用"), text);
    }

    @Test
    @DisplayName("reload：配置加载失败时如实回显「已继续沿用上一份配置」")
    void reloadKeepsPreviousConfigurationOnFailure(@TempDir Path temp) throws Exception {
        final MikuHAProxy plugin = pluginWithConfiguration(temp);
        final Object before = snapshot(plugin).get();

        // 让 reload 必然失败：把整个数据目录换成一个同名普通文件（与 MikuHAProxyReloadTest 同一构造法）
        final Path dir = effectiveDataDir(temp);
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

        final RecordingSource recorder = new RecordingSource(true);
        dispatcher(plugin).execute("mikuproxy reload", commandSource(recorder));

        assertTrue(recorder.joined().contains("重载失败：配置有误，已继续沿用上一份配置"),
                recorder.joined());
        assertTrue(before == snapshot(plugin).get(), "失败时必须保留原快照，不能半新半旧");
    }
}
