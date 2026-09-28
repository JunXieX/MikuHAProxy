package io.github.junxiex.mikuhaproxy.net;

import com.velocitypowered.api.proxy.ProxyServer;
import io.github.junxiex.mikuhaproxy.DetectorContext;
import io.github.junxiex.mikuhaproxy.util.Reflect;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.handler.codec.haproxy.HAProxyMessageDecoder;
import org.slf4j.Logger;

import java.lang.invoke.MethodHandle;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;

/**
 * 把探测器挂进 Velocity 的连接初始化流程。
 *
 * <p>Velocity 在启用 {@code haproxy-protocol} 时，会在每条新连接的管道最前面放一个
 * {@link HAProxyMessageDecoder}——它的前提是「每条连接都带 PROXY 头」，因此直连会被它直接掐掉。
 * 本插件要在不修改 Velocity 的前提下，把这个解码器换成会「先看一眼」的探测器，唯一的介入点是
 * 包一层 {@code ServerChannelInitializer}。</p>
 *
 * <p>关于反射：Velocity 4.0 已经把 {@code ConnectionManager.getServerChannelInitializer()} 与
 * {@code serverChannelInitializer} 字段开放成 public（官方注释里说明是为了支持 ViaVersion 这类要改
 * 管道的插件）。真正还是 private 的只有 {@code VelocityServer#cm} 这一个字段，所以本类只对它做一次
 * 反射取字段，其余全部走公共方法；取到之后所有调用都是编译期可检查的强类型调用。</p>
 */
public final class ChannelHook {

    /** Velocity 里持有连接管理器的实现类；只按「类型全限定名」比对，不做 Class.forName。 */
    private static final String CONNECTION_MANAGER = "com.velocitypowered.proxy.network.ConnectionManager";

    private final ProxyServer server;
    private final Supplier<DetectorContext> contexts;
    private final Logger logger;

    /** 只有当「配置说开了 haproxy-protocol、管道里却没解码器」时才告警一次，避免日志刷屏。 */
    private final AtomicBoolean missingDecoderReported = new AtomicBoolean();

    // install() 跑在代理启动线程上，isInstalled()/uninstall() 可能由命令线程调用，所以这四个字段
    // 必须是 volatile：否则命令线程可能读到 installed == false，从而把「已安装」误报成「未安装」。
    private volatile Slot initializerSlot;
    private volatile Object holder;
    private volatile ChannelInitializer<Channel> originalInitializer;
    private volatile boolean installed;

    public ChannelHook(ProxyServer server, Supplier<DetectorContext> contexts, Logger logger) {
        this.server = server;
        this.contexts = contexts;
        this.logger = logger;
    }

    /**
     * 安装钩子。
     *
     * @return 成功返回 {@code true}；失败时已经打过日志，调用方不需要再处理异常
     */
    public boolean install() {
        if (installed) {
            return true;
        }
        try {
            final Object connectionManager = resolveConnectionManager();
            final Object serverInitializerHolder = resolveServerInitializerHolder(connectionManager);
            final Slot slot = Slot.of(serverInitializerHolder);

            final ChannelInitializer<Channel> current = slot.get(serverInitializerHolder);
            if (current == null) {
                logger.error("Velocity 的连接初始化器为空，无法注入。");
                return false;
            }

            // 幂等：如果当前挂着的已经是本插件的包装器（例如重复安装），取它的被包装对象再包一层，
            // 避免包装器套包装器导致初始化被反复执行。
            final ChannelInitializer<Channel> delegate = current instanceof DetectingInitializer wrapper
                    ? wrapper.delegate()
                    : current;

            final boolean proxyProtocolEnabled = Boolean.TRUE.equals(readProxyProtocolFlag());
            final DetectingInitializer wrapper =
                    new DetectingInitializer(delegate, contexts, logger, proxyProtocolEnabled, missingDecoderReported);

            logger.info("正在替换 Velocity 的连接初始化器；Velocity 不会为此打印任何告警，也无需重启。");
            slot.set(serverInitializerHolder, wrapper);

            this.holder = serverInitializerHolder;
            this.initializerSlot = slot;
            this.originalInitializer = delegate;
            this.installed = true;
            return true;
        } catch (Throwable t) {
            // 连 Error 一起接：包装器的静态初始化失败会抛 ExceptionInInitializerError，
            // 上游内部类消失可能抛 NoClassDefFoundError，都不该让代理的插件初始化跟着失败。
            logger.error("注入失败：无法接管 Velocity 的连接初始化流程。"
                    + "请确认当前运行的是 Velocity 4.x；插件本身会保持加载但不会生效。", t);
            return false;
        }
    }

    /** 还原原始初始化器。Velocity 无法卸载插件，这里主要用于优雅关闭与自检。 */
    public void uninstall() {
        if (!installed || initializerSlot == null || holder == null) {
            return;
        }
        try {
            final ChannelInitializer<Channel> current = initializerSlot.get(holder);
            if (current instanceof DetectingInitializer) {
                initializerSlot.set(holder, originalInitializer);
            }
        } catch (ReflectiveOperationException | RuntimeException e) {
            logger.warn("还原连接初始化器失败", e);
        } finally {
            installed = false;
        }
    }

    public boolean isInstalled() {
        return installed;
    }

    /**
     * 软读取 Velocity 的 {@code haproxy-protocol} 开关。
     *
     * <p>Velocity 4.0 的 API 接口 {@code ProxyConfig} 并没有暴露它（只有实现的
     * {@code VelocityConfiguration} 有 {@code isProxyProtocol()}），所以只能反射尝试；
     * 读不到就返回 {@code null}，不影响注入。</p>
     *
     * @return {@code true}/{@code false}，读不到时为 {@code null}
     */
    public Boolean readProxyProtocolFlag() {
        try {
            final Object configuration = server.getConfiguration();
            final Method method = Reflect.findMethod(configuration.getClass(), "isProxyProtocol");
            if (method == null) {
                return null;
            }
            method.setAccessible(true);
            final Object value = method.invoke(configuration);
            return value instanceof Boolean flag ? flag : null;
        } catch (ReflectiveOperationException | RuntimeException e) {
            return null;
        }
    }

    // ------------------------------------------------------------------
    // 定位 ConnectionManager / ServerChannelInitializerHolder
    // ------------------------------------------------------------------

    /**
     * 判断一个字段是否持有连接管理器。
     *
     * <p>先按类型全限定名比对；退化时只按简单类名比对，是为了在上游把包名挪走之后仍能定位
     * （不 {@code Class.forName}，那样会直接抛 {@code NoClassDefFoundError}）。</p>
     */
    static boolean isConnectionManagerField(Field field) {
        return field.getType().getName().equals(CONNECTION_MANAGER)
                || field.getType().getSimpleName().equals("ConnectionManager");
    }

    /**
     * 判断一个字段是否持有<b>服务端</b>的连接初始化器持有者。
     *
     * <p>连接管理器里 {@code server} / {@code backend} 两个持有者同名同形，只能按字段名区分——
     * 包住后者会把后端连接也一起改掉。</p>
     */
    static boolean isServerInitializerHolderField(Field field) {
        return field.getName().startsWith("server")
                && field.getType().getSimpleName().endsWith("ChannelInitializerHolder");
    }

    /** 判断一个字段是否直接存放连接初始化器（{@link Slot#of} 的兜底路径）。 */
    static boolean holdsChannelInitializer(Field field) {
        return ChannelInitializer.class.isAssignableFrom(field.getType());
    }

    private Object resolveConnectionManager() throws ReflectiveOperationException {
        // 1) 上游若未来提供公共访问器，优先使用
        final Method accessor = Reflect.findMethod(server.getClass(), "getConnectionManager");
        if (accessor != null && accessor.getReturnType().getName().equals(CONNECTION_MANAGER)) {
            accessor.setAccessible(true);
            return accessor.invoke(server);
        }
        // 2) 否则按「类型全限定名」找字段（不 Class.forName，避免上游挪包后报 NoClassDefFoundError）
        final Field field = Reflect.findField(server.getClass(), ChannelHook::isConnectionManagerField);
        if (field == null) {
            throw new NoSuchFieldException("在 " + server.getClass().getName()
                    + " 中找不到 ConnectionManager 字段（当前 Velocity 版本可能不受支持）");
        }
        field.setAccessible(true);
        return field.get(server);
    }

    /**
     * 定位「服务端连接初始化器持有者」。
     *
     * <p>包内可见而非 private：本方法的字段兜底分支（访问器缺失或返回 {@code null}）只能靠替身对象覆盖，
     * 见 {@code ChannelHookTest}。语义与异常类型刻意保持不变——{@link NoSuchFieldException} 携带的是
     * 「在哪个类里找不到什么」，改成 RuntimeException 会让注入失败的日志从可诊断变成含糊。</p>
     */
    Object resolveServerInitializerHolder(Object connectionManager) throws ReflectiveOperationException {
        final Method accessor = Reflect.findMethod(connectionManager.getClass(), "getServerChannelInitializer");
        if (accessor != null) {
            accessor.setAccessible(true);
            final Object holder = accessor.invoke(connectionManager);
            if (holder != null) {
                return holder;
            }
        }
        // 兜底：ConnectionManager 里同时存在 server / backend 两个初始化器持有者，按名字区分开
        final Field field = Reflect.findField(connectionManager.getClass(), ChannelHook::isServerInitializerHolderField);
        if (field == null) {
            throw new NoSuchFieldException("在 " + connectionManager.getClass().getName()
                    + " 中找不到服务端连接初始化器持有者（当前 Velocity 版本可能不受支持）");
        }
        field.setAccessible(true);
        return field.get(connectionManager);
    }

    /**
     * 对「初始化器持有者」的读写抽象：优先用公共方法，方法缺失时退回字段。
     *
     * <p>包内可见而非 private：两条路径（公共 {@code get()/set(...)} 与直接读写字段）都要能被
     * {@code ChannelHookTest} 用替身对象分别覆盖。</p>
     */
    static final class Slot {

        private final Method getter;
        private final Method setter;
        private final Field field;

        private Slot(Method getter, Method setter, Field field) {
            this.getter = getter;
            this.setter = setter;
            this.field = field;
        }

        static Slot of(Object holder) throws ReflectiveOperationException {
            final Method getter = Reflect.findMethod(holder.getClass(), "get");
            final Method setter = Reflect.findMethod(holder.getClass(), "set", ChannelInitializer.class);
            if (getter != null && setter != null) {
                getter.setAccessible(true);
                setter.setAccessible(true);
                return new Slot(getter, setter, null);
            }
            // 兜底：直接读写内部字段（Velocity 的 set(...) 带 @Deprecated，未来可能消失）
            final Field field = Reflect.findField(holder.getClass(), ChannelHook::holdsChannelInitializer);
            if (field == null) {
                throw new NoSuchFieldException("无法读写 " + holder.getClass().getName() + " 里的初始化器");
            }
            field.setAccessible(true);
            return new Slot(null, null, field);
        }

        @SuppressWarnings("unchecked")
        ChannelInitializer<Channel> get(Object holder) throws ReflectiveOperationException {
            return getter != null
                    ? (ChannelInitializer<Channel>) getter.invoke(holder)
                    : (ChannelInitializer<Channel>) field.get(holder);
        }

        void set(Object holder, ChannelInitializer<Channel> value) throws ReflectiveOperationException {
            if (setter != null) {
                setter.invoke(holder, value);
            } else {
                field.set(holder, value);
            }
        }
    }

    // ------------------------------------------------------------------
    // 包装器
    // ------------------------------------------------------------------

    /**
     * 包住 Velocity 原有初始化器的包装器：先原样执行原初始化（于是 {@link HAProxyMessageDecoder}
     * 被放到管道首位），再把它换成探测器。
     */
    static final class DetectingInitializer extends ChannelInitializer<Channel> {

        /** {@code ChannelInitializer#initChannel(Channel)}，protected，只能反射获取。 */
        private static final Method INIT_CHANNEL;

        static {
            Method method = null;
            try {
                method = ChannelInitializer.class.getDeclaredMethod("initChannel", Channel.class);
                method.setAccessible(true);
            } catch (ReflectiveOperationException e) {
                throw new ExceptionInInitializerError(e);
            }
            INIT_CHANNEL = method;
        }

        private final ChannelInitializer<Channel> delegate;
        /** 已绑定 delegate 且签名固定为 {@code (Channel)void} 的句柄：热路径上是一次直接调用。 */
        private final MethodHandle delegateInit;
        private final Supplier<DetectorContext> contexts;
        private final Logger logger;
        private final boolean proxyProtocolExpected;
        private final AtomicBoolean missingDecoderReported;
        /** 注入失败只打一次完整堆栈，之后只计数（总量看 /mikuproxy status）。 */
        private final AtomicBoolean injectionFailureReported = new AtomicBoolean();

        DetectingInitializer(ChannelInitializer<Channel> delegate, Supplier<DetectorContext> contexts,
                             Logger logger, boolean proxyProtocolExpected, AtomicBoolean missingDecoderReported) {
            this.delegate = delegate;
            this.contexts = contexts;
            this.logger = logger;
            this.proxyProtocolExpected = proxyProtocolExpected;
            this.missingDecoderReported = missingDecoderReported;
            this.delegateInit = Reflect.bind(void.class, INIT_CHANNEL, delegate);
        }

        ChannelInitializer<Channel> delegate() {
            return delegate;
        }

        @Override
        protected void initChannel(Channel channel) {
            // 每个连接只读一次配置快照（AtomicReference 的 volatile 读），两条路径复用同一个引用。
            final DetectorContext context = contexts.get();
            try {
                delegateInit.invokeExact(channel);
            } catch (Throwable t) {
                Reflect.sneakyThrow(t);
            }
            try {
                installDetector(channel, context);
            } catch (Throwable t) {
                context.counters().incrementFailures();
                if (injectionFailureReported.compareAndSet(false, true)) {
                    logger.error("为连接注入 PROXY protocol 探测器失败，该连接将按 Velocity 原有方式处理；"
                            + "后续同类失败只计入 /mikuproxy status 的「异常」计数。", t);
                }
            }
        }

        private void installDetector(Channel channel, DetectorContext context) {
            if (!channel.isOpen()) {
                return;
            }
            final ChannelPipeline pipeline = channel.pipeline();
            if (pipeline.context(ProxyProtocolDetector.HANDLER_NAME) != null) {
                return;
            }

            // Velocity 用 addFirst(...) 放置解码器，因此正常情况它就在管道首位 —— O(1) 直接取。
            ChannelHandlerContext target = pipeline.firstContext();
            if (target == null || !(target.handler() instanceof HAProxyMessageDecoder)) {
                // 万一其它插件也在首位插了处理器，才退化为一次按类型线性查找。
                final ChannelHandler byType = pipeline.get(HAProxyMessageDecoder.class);
                if (byType == null) {
                    context.counters().incrementNotInjected();
                    if (proxyProtocolExpected && missingDecoderReported.compareAndSet(false, true)) {
                        logger.warn("velocity.toml 里启用了 haproxy-protocol，但整条管道里都没有 PROXY 解码器"
                                + "（探测器因此没有注入）；如果本行反复出现请反馈该问题。");
                    }
                    return;
                }
                target = pipeline.context(byType);
                if (target == null) {
                    return;
                }
            }

            pipeline.replace(target.name(), ProxyProtocolDetector.HANDLER_NAME,
                    new ProxyProtocolDetector(context));
        }
    }
}
