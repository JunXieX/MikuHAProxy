package io.github.junxiex.mikuhaproxy.net;

import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.api.proxy.config.ProxyConfig;
import io.github.junxiex.mikuhaproxy.DetectorContext;
import io.github.junxiex.mikuhaproxy.config.AllowList;
import io.github.junxiex.mikuhaproxy.config.PluginConfig;
import io.github.junxiex.mikuhaproxy.util.Counters;
import io.github.junxiex.mikuhaproxy.util.LogThrottle;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.haproxy.HAProxyMessageDecoder;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link ChannelHook} 的注入逻辑测试。
 *
 * <p>这一层此前零覆盖，而它有一个特别的危险：它<b>全部靠反射</b>粘在上游内部结构上，
 * Velocity 一旦改了字段名或访问器，插件会<b>静默失效</b>——不会抛异常，只是再也不接管连接。
 * 这里能守住的是「我们自己的定位与包装逻辑」（三处字段选择器、持有者读写、安装/卸载、失败路径）；
 * <b>守不住</b>「上游结构是否还在」，那需要把 Velocity 实现放进测试 classpath（版本烟囱测试），
 * 本插件不做——所以别把本类读成「加了测试就不怕 Velocity 升级」。</p>
 *
 * <p>替身策略：{@code ProxyServer} / {@code ProxyConfig} 用 {@link Proxy} 动态代理（接口方法太多，
 * 手写实现既冗长又容易漏方法）；连接管理器则用
 * {@link com.velocitypowered.proxy.network.ConnectionManager 上游同名的形状替身}，
 * 因为它是被<b>按类型名</b>查找的，改名就失去意义。为了让「服务端带
 * {@code getConnectionManager()}」这一形状成立，动态代理额外实现本类的
 * {@link ConnectionManagerAccessor} 接口。</p>
 */
public class ChannelHookTest {

    /**
     * 给替身「服务端对象」补一个访问器。
     *
     * <p>必须是 public：{@link Proxy} 只在所有接口都对外可见时，才把代理类生成到动态模块里。</p>
     */
    public interface ConnectionManagerAccessor {
        com.velocitypowered.proxy.network.ConnectionManager getConnectionManager();
    }

    /**
     * 给替身「配置对象」补上 {@code isProxyProtocol()}。
     *
     * <p>这条正是「读的是<b>方法名</b>、不是字段名」那个坑的守护：{@code ProxyConfig} 接口本身
     * 没有这个开关，只有实现类才有，所以 {@code ChannelHook} 只能反射找方法。</p>
     */
    public interface ProxyProtocolFlag {
        boolean isProxyProtocol();
    }

    /** 同名但让方法返回类型对不上：用来验证「读到的不是 Boolean 就返回 null」。 */
    public interface WrongTypedFlag {
        String isProxyProtocol();
    }

    // ------------------------------------------------------------------
    // 替身基础设施
    // ------------------------------------------------------------------

    /** 记录被调用了哪些方法，并按需返回预设值；未预设时按返回类型给安全默认值。 */
    private static final class Recorder implements InvocationHandler {

        final Map<String, Object> returns = new ConcurrentHashMap<>();
        final Set<String> throwing = ConcurrentHashMap.newKeySet();
        final List<String> calls = new CopyOnWriteArrayList<>();

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            final String name = method.getName();
            // equals/hashCode/toString 也会被路由到这里，单独处理，避免污染调用记录
            if ("toString".equals(name)) {
                return "recorder";
            }
            if ("hashCode".equals(name)) {
                return System.identityHashCode(proxy);
            }
            if ("equals".equals(name)) {
                return proxy == args[0];
            }
            calls.add(name);
            if (throwing.contains(name)) {
                throw new IllegalStateException("测试构造：调用 " + name + " 时抛异常");
            }
            return returns.containsKey(name) ? returns.get(name) : defaultValue(method.getReturnType());
        }

        int count(String name) {
            return (int) calls.stream().filter(name::equals).count();
        }
    }

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

    private static ProxyServer server(Recorder recorder, boolean withConnectionManagerAccessor) {
        final Class<?>[] types = withConnectionManagerAccessor
                ? new Class<?>[]{ProxyServer.class, ConnectionManagerAccessor.class}
                : new Class<?>[]{ProxyServer.class};
        return (ProxyServer) Proxy.newProxyInstance(ChannelHookTest.class.getClassLoader(), types, recorder);
    }

    private static Object proxy(Class<?>[] types, InvocationHandler handler) {
        return Proxy.newProxyInstance(ChannelHookTest.class.getClassLoader(), types, handler);
    }

    private static DetectorContext context() {
        return new DetectorContext(AllowList.ALLOW_ALL, PluginConfig.defaults(), new Counters(),
                new LogThrottle(60, 16), LoggerFactory.getLogger(ChannelHookTest.class));
    }

    private static ChannelHook hook(ProxyServer server) {
        return new ChannelHook(server, ChannelHookTest::context, LoggerFactory.getLogger(ChannelHookTest.class));
    }

    /** {@code resolveServerInitializerHolder} 不触碰 server 字段，因此这里传 null 是合法的。 */
    private static ChannelHook hookWithoutServer() {
        return hook(null);
    }

    /** 造一个上游形状的连接管理器替身（访问器与同名字段齐全）。 */
    private static com.velocitypowered.proxy.network.ConnectionManager newConnectionManager() {
        return new com.velocitypowered.proxy.network.ConnectionManager();
    }

    /** 模仿 Velocity 的服务器初始化器：把 {@link HAProxyMessageDecoder} 放在管道首位。 */
    private static final class VelocityLikeInitializer extends ChannelInitializer<Channel> {

        final AtomicInteger calls = new AtomicInteger();

        @Override
        protected void initChannel(Channel channel) {
            calls.incrementAndGet();
            channel.pipeline().addFirst(new HAProxyMessageDecoder());
        }
    }

    /** 与上游同形的持有者替身（简单类名以 ChannelInitializerHolder 结尾，字段兜底路径认它）。 */
    static final class TestChannelInitializerHolder {

        private ChannelInitializer<Channel> initializer;

        public ChannelInitializer<Channel> get() {
            return initializer;
        }

        public void set(ChannelInitializer<Channel> value) {
            this.initializer = value;
        }
    }

    /** 只有字段、没有公共访问器的连接管理器替身。 */
    private static final class ConnectionManagerWithoutAccessor {
        @SuppressWarnings("unused")
        public final TestChannelInitializerHolder serverChannelInitializer = new TestChannelInitializerHolder();
    }

    /** 访问器存在但返回 null 的连接管理器替身：必须继续退回字段查找。 */
    private static final class ConnectionManagerWithNullAccessor {
        @SuppressWarnings("unused")
        public final TestChannelInitializerHolder serverChannelInitializer = new TestChannelInitializerHolder();

        public TestChannelInitializerHolder getServerChannelInitializer() {
            return null;
        }
    }

    // ------------------------------------------------------------------
    // 安装 / 卸载
    // ------------------------------------------------------------------

    @Test
    @DisplayName("注入成功：原初始化器被包一层，且新连接上的 PROXY 解码器会被换成探测器")
    void installWrapsInitializerAndReplacesDecoderPerConnection() throws Exception {
        final var connectionManager = newConnectionManager();
        final VelocityLikeInitializer original = new VelocityLikeInitializer();
        connectionManager.serverChannelInitializer.set(original);

        final Recorder recorder = new Recorder();
        recorder.returns.put("getConnectionManager", connectionManager);
        final ChannelHook hook = hook(server(recorder, true));

        assertTrue(hook.install(), "定位到连接管理器时注入必须成功");
        assertTrue(hook.isInstalled());

        final ChannelInitializer<Channel> wrapped = connectionManager.serverChannelInitializer.get();
        assertTrue(wrapped instanceof ChannelHook.DetectingInitializer, "必须换成本插件的包装器");
        assertSame(original, ((ChannelHook.DetectingInitializer) wrapped).delegate(),
                "被包装的必须是最初那个初始化器");

        // 端到端：像 Velocity 那样把初始化器交给管道（ChannelInitializer 会在 handlerAdded 里被执行），
        // 于是原初始化器照常放入解码器，而它必须被换成探测器
        final EmbeddedChannel channel = new EmbeddedChannel();
        channel.pipeline().addLast(wrapped);
        assertEquals(1, original.calls.get(), "原初始化器必须被原样执行，否则 Velocity 自己的初始化就没了");
        assertNotNull(channel.pipeline().context(ProxyProtocolDetector.HANDLER_NAME), "探测器必须已装进管道");
        assertNull(channel.pipeline().get(HAProxyMessageDecoder.class), "原来的 PROXY 解码器必须已被换掉");

        channel.finishAndReleaseAll();
    }

    @Test
    @DisplayName("卸载：还原最初那个初始化器，之后不再处于已安装状态")
    void uninstallRestoresOriginalInitializer() {
        final var connectionManager = newConnectionManager();
        final VelocityLikeInitializer original = new VelocityLikeInitializer();
        connectionManager.serverChannelInitializer.set(original);

        final Recorder recorder = new Recorder();
        recorder.returns.put("getConnectionManager", connectionManager);
        final ChannelHook hook = hook(server(recorder, true));
        assertTrue(hook.install());

        hook.uninstall();

        assertSame(original, connectionManager.serverChannelInitializer.get(), "卸载必须还原原始初始化器");
        assertFalse(hook.isInstalled());
    }

    @Test
    @DisplayName("同一个实例重复安装：直接返回成功，不叠加第二层包装器")
    void installIsIdempotentOnTheSameInstance() {
        final var connectionManager = newConnectionManager();
        connectionManager.serverChannelInitializer.set(new VelocityLikeInitializer());

        final Recorder recorder = new Recorder();
        recorder.returns.put("getConnectionManager", connectionManager);
        final ChannelHook hook = hook(server(recorder, true));

        assertTrue(hook.install());
        final ChannelHandler once = connectionManager.serverChannelInitializer.get();
        assertTrue(hook.install(), "已安装时重复调用应当直接返回 true");
        assertSame(once, connectionManager.serverChannelInitializer.get(), "不得再包一层");
        assertEquals(1, recorder.count("getConnectionManager"), "已安装时不应重复定位连接管理器");
    }

    @Test
    @DisplayName("换一个实例再安装：取被包装对象再包一层，绝不出现「包装器套包装器」")
    void installOnFreshInstanceRewrapsTheOriginal() {
        final var connectionManager = newConnectionManager();
        final VelocityLikeInitializer original = new VelocityLikeInitializer();
        connectionManager.serverChannelInitializer.set(original);

        final Recorder recorder = new Recorder();
        recorder.returns.put("getConnectionManager", connectionManager);
        final ProxyServer server = server(recorder, true);

        assertTrue(hook(server).install());
        final ChannelHandler first = connectionManager.serverChannelInitializer.get();

        final ChannelHook second = hook(server);
        assertTrue(second.install());
        final ChannelHandler after = connectionManager.serverChannelInitializer.get();

        assertTrue(after instanceof ChannelHook.DetectingInitializer);
        assertSame(original, ((ChannelHook.DetectingInitializer) after).delegate(),
                "第二次包装的必须仍是最初的初始化器，否则连接初始化会被执行两遍");
        assertEquals(2, recorder.count("getConnectionManager"), "两次安装各定位一次");
        assertNotSame(first, after, "应当装上一个新的包装器实例");
    }

    @Test
    @DisplayName("定位不到连接管理器：安全返回 false 且不向调用方抛异常（上游结构变化时的表现）")
    void installFailsSafelyWhenConnectionManagerCannotBeResolved() {
        final Recorder recorder = new Recorder();
        final ChannelHook hook = hook(server(recorder, false));

        assertFalse(hook.install(), "失败由日志承担，不得让异常冒到插件初始化之外");
        assertFalse(hook.isInstalled());
        assertEquals(1, recorder.count("getConfiguration"),
                "会先软读一次 haproxy-protocol 开关（读不到不影响注入结论）");
    }

    @Test
    @DisplayName("持有者里的初始化为空：返回 false，不装包装器")
    void installFailsWhenInitializerIsNull() {
        final var connectionManager = newConnectionManager();
        final Recorder recorder = new Recorder();
        recorder.returns.put("getConnectionManager", connectionManager);
        final ChannelHook hook = hook(server(recorder, true));

        assertFalse(hook.install(), "拿不到原初始化器时不能把 null 包进包装器");
        assertFalse(hook.isInstalled());
        assertNull(connectionManager.serverChannelInitializer.get());
    }

    @Test
    @DisplayName("未安装时卸载：安全 no-op，不抛异常")
    void uninstallIsNoOpWhenNotInstalled() {
        final ChannelHook hook = hook(server(new Recorder(), false));
        hook.uninstall();
        assertFalse(hook.isInstalled());
    }

    // ------------------------------------------------------------------
    // haproxy-protocol 开关：反射读的是「方法」不是字段
    // ------------------------------------------------------------------

    @Test
    @DisplayName("haproxy-protocol 开关：按 isProxyProtocol 方法名读到 true / false")
    void readsProxyProtocolFlagFromMethod() {
        assertEquals(Boolean.TRUE, hookWithFlag(boolean.class, true).readProxyProtocolFlag());
        assertEquals(Boolean.FALSE, hookWithFlag(boolean.class, false).readProxyProtocolFlag());
    }

    @Test
    @DisplayName("读不到开关时返回 null（不影响注入），而不是抛异常或猜一个值")
    void returnsNullWhenFlagCannotBeRead() {
        // ① 配置对象根本没有 isProxyProtocol 方法（ProxyConfig 接口本身就没有这个开关）
        final Object plainConfig = proxy(new Class<?>[]{ProxyConfig.class}, new Recorder());
        assertNull(hookWithConfig(plainConfig).readProxyProtocolFlag());

        // ② 方法在，但返回值不是 Boolean
        assertNull(hookWithFlag(String.class, null).readProxyProtocolFlag());

        // ③ 调用本身抛异常
        final Recorder recorder = new Recorder();
        recorder.throwing.add("isProxyProtocol");
        final Object throwingConfig = proxy(new Class<?>[]{ProxyConfig.class, ProxyProtocolFlag.class}, recorder);
        assertNull(hookWithConfig(throwingConfig).readProxyProtocolFlag());

        // ④ 连配置都拿不到（服务端为 null）
        assertNull(hook(null).readProxyProtocolFlag());
    }

    /** 造一个「配置对象带 isProxyProtocol()、返回给定值」的钩子。 */
    private static ChannelHook hookWithFlag(Class<?> flagType, Object value) {
        final Recorder configRecorder = new Recorder();
        if (value != null) {
            configRecorder.returns.put("isProxyProtocol", value);
        }
        final Class<?> flagInterface = flagType == String.class ? WrongTypedFlag.class : ProxyProtocolFlag.class;
        final Object configuration = proxy(new Class<?>[]{ProxyConfig.class, flagInterface}, configRecorder);
        return hookWithConfig(configuration);
    }

    /** 造一个「服务器返回给定配置对象」的钩子。 */
    private static ChannelHook hookWithConfig(Object configuration) {
        final Recorder serverRecorder = new Recorder();
        serverRecorder.returns.put("getConfiguration", configuration);
        return hook(server(serverRecorder, false));
    }

    // ------------------------------------------------------------------
    // 选择器与持有者读写（原来全是 lambda，只能靠端到端间接覆盖）
    // ------------------------------------------------------------------

    @Test
    @DisplayName("字段选择器：按类型全限定名定位连接管理器，上游挪包时退化按简单类名兜底")
    void connectionManagerFieldSelector() throws Exception {
        assertTrue(ChannelHook.isConnectionManagerField(
                        FqNamedHolder.class.getField("manager")),
                "类型全限定名与上游一致时必须命中");
        assertTrue(ChannelHook.isConnectionManagerField(
                        SimpleNamedHolder.class.getField("manager")),
                "包名变了（上游挪包）时必须按简单类名兜底，否则插件会静默失效");
        assertFalse(ChannelHook.isConnectionManagerField(FqNamedHolder.class.getField("other")),
                "别的类型不得被当成连接管理器");
    }

    @Test
    @DisplayName("字段选择器：只认名字以 server 开头的初始化器持有者，backend 的绝不碰")
    void serverInitializerHolderFieldSelector() throws Exception {
        assertTrue(ChannelHook.isServerInitializerHolderField(
                TwoHolders.class.getField("serverChannelInitializer")));
        assertFalse(ChannelHook.isServerInitializerHolderField(
                        TwoHolders.class.getField("backendChannelInitializer")),
                "包住 backend 的持有者会把后端连接也一起改掉");
        assertFalse(ChannelHook.isServerInitializerHolderField(TwoHolders.class.getField("serverName")),
                "名字前缀对但类型不是持有者，同样不算");
    }

    @Test
    @DisplayName("字段选择器：只认声明类型是 ChannelInitializer（含其子类）的字段")
    void initializerFieldSelector() throws Exception {
        assertTrue(ChannelHook.holdsChannelInitializer(InitializerFields.class.getField("initializer")));
        assertTrue(ChannelHook.holdsChannelInitializer(InitializerFields.class.getField("subclassed")),
                "子类字段同样要认");
        assertFalse(ChannelHook.holdsChannelInitializer(InitializerFields.class.getField("other")));
    }

    @Test
    @DisplayName("持有者定位：访问器优先；访问器缺失或返回 null 时退回同名字段")
    void resolvesServerInitializerHolder() throws Exception {
        final ChannelHook hook = hookWithoutServer();

        final var withAccessor = newConnectionManager();
        assertSame(withAccessor.serverChannelInitializer, hook.resolveServerInitializerHolder(withAccessor),
                "有公共访问器时必须用它");

        final ConnectionManagerWithoutAccessor byField = new ConnectionManagerWithoutAccessor();
        assertSame(byField.serverChannelInitializer, hook.resolveServerInitializerHolder(byField),
                "访问器缺失时必须退回按字段名前缀定位");

        final ConnectionManagerWithNullAccessor afterNull = new ConnectionManagerWithNullAccessor();
        assertSame(afterNull.serverChannelInitializer, hook.resolveServerInitializerHolder(afterNull),
                "访问器返回 null 时同样要退回字段");
    }

    @Test
    @DisplayName("持有者定位：两处都找不到时抛 NoSuchFieldException，保留「在哪个类里找不到什么」")
    void throwsWhenHolderCannotBeResolved() {
        final ChannelHook hook = hookWithoutServer();
        final NoSuchFieldException failure = assertThrows(NoSuchFieldException.class,
                () -> hook.resolveServerInitializerHolder(new Object()));
        assertTrue(failure.getMessage().contains("Object"),
                "异常里必须写明是哪个类，否则注入失败的日志只剩一句含糊的话：" + failure.getMessage());
    }

    @Test
    @DisplayName("Slot：有公共 get()/set(...) 走方法；没有时直接读写字段")
    void slotPrefersAccessorsAndFallsBackToField() throws Exception {
        final VelocityLikeInitializer original = new VelocityLikeInitializer();
        final VelocityLikeInitializer replacement = new VelocityLikeInitializer();

        final TestChannelInitializerHolder byAccessors = new TestChannelInitializerHolder();
        byAccessors.set(original);
        final ChannelHook.Slot slot = ChannelHook.Slot.of(byAccessors);
        assertSame(original, slot.get(byAccessors));
        slot.set(byAccessors, replacement);
        assertSame(replacement, byAccessors.get());

        // 兜底分支：Velocity 的 set(...) 带 @Deprecated，将来可能被删掉
        final FieldOnlyHolder byField = new FieldOnlyHolder();
        byField.initializer = original;
        final ChannelHook.Slot fallback = ChannelHook.Slot.of(byField);
        assertSame(original, fallback.get(byField), "没有访问器时必须能读到字段");
        fallback.set(byField, replacement);
        assertSame(replacement, byField.initializer, "没有访问器时必须能写回字段");
    }

    // ------------------------------------------------------------------
    // 供字段选择器断言用的替身
    // ------------------------------------------------------------------

    private static final class FqNamedHolder {
        @SuppressWarnings("unused")
        public com.velocitypowered.proxy.network.ConnectionManager manager;
        @SuppressWarnings("unused")
        public String other;
    }

    private static final class SimpleNamedHolder {
        /** 指的是本文件里的嵌套 {@link ConnectionManager}：包名与上游不同，简单类名相同。 */
        @SuppressWarnings("unused")
        public ConnectionManager manager;
    }

    /** 只用来造「包名不同、简单类名相同」这一情形。 */
    static final class ConnectionManager {
    }

    private static final class TwoHolders {
        @SuppressWarnings("unused")
        public TestChannelInitializerHolder serverChannelInitializer;
        @SuppressWarnings("unused")
        public TestChannelInitializerHolder backendChannelInitializer;
        @SuppressWarnings("unused")
        public String serverName;
    }

    private static final class InitializerFields {
        @SuppressWarnings("unused")
        public ChannelInitializer<Channel> initializer;
        @SuppressWarnings("unused")
        public VelocityLikeInitializer subclassed;
        @SuppressWarnings("unused")
        public String other;
    }

    /** 只有字段、没有 get()/set(...) 的持有者替身。 */
    private static final class FieldOnlyHolder {
        @SuppressWarnings("unused")
        private ChannelInitializer<Channel> initializer;
    }
}
