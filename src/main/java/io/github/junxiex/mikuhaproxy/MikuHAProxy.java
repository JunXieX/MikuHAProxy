package io.github.junxiex.mikuhaproxy;

import com.google.inject.Inject;
import com.velocitypowered.api.command.BrigadierCommand;
import com.velocitypowered.api.command.CommandSource;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.proxy.ProxyInitializeEvent;
import com.velocitypowered.api.event.proxy.ProxyShutdownEvent;
import com.velocitypowered.api.plugin.Plugin;
import com.velocitypowered.api.plugin.annotation.DataDirectory;
import com.velocitypowered.api.proxy.ProxyServer;
import io.github.junxiex.mikuhaproxy.command.MikuProxyCommand;
import io.github.junxiex.mikuhaproxy.config.AllowList;
import io.github.junxiex.mikuhaproxy.config.DataFolder;
import io.github.junxiex.mikuhaproxy.config.PluginConfig;
import io.github.junxiex.mikuhaproxy.net.ChannelHook;
import io.github.junxiex.mikuhaproxy.util.Counters;
import io.github.junxiex.mikuhaproxy.util.LogThrottle;
import org.slf4j.Logger;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

/**
 * MikuHAProxy —— 让 Velocity 同时接受代理（HAProxy PROXY protocol）与直连。
 *
 * <p>Velocity 开启 {@code haproxy-protocol} 后只认带 PROXY 头的连接，本插件在管道首位放一个
 * 「先看一眼」的探测器，据开头的字节决定这条连接该走代理路径还是直连路径。行为细节请见 README。</p>
 *
 * <p>核心安全模型（不可省略）：只允许<b>可信来源</b>发来的 PROXY 头生效。
 * 判定依据是 TCP 对端地址，而不是 PROXY 头里声明的客户端地址——后者是发头的人自己填的，可以被伪造。</p>
 *
 * @author JunXieX
 */
@Plugin(
        id = "mikuhaproxy",
        name = "MikuHAProxy",
        version = MikuHAProxy.VERSION,
        description = "让代理（PROXY protocol）连接与直连同时可用，并只放行可信来源。",
        authors = {"JunXieX"})
public final class MikuHAProxy {

    /**
     * 版本号。
     *
     * <p>它会进入 {@code @Plugin} 注解与编译期生成的 {@code velocity-plugin.json}；{@code pom.xml} 里的
     * 版本号必须与它一致，这条一致性由 {@code VersionTest} 守护。另外 {@code README.md} 的版本行与安装
     * 步骤里的 jar 名也写着版本号，那两处没有自动化守护，改版本时需要手工同步。</p>
     */
    public static final String VERSION = "1.2.0";

    /**
     * 重载时最多在聊天框里回显多少条配置问题。
     *
     * <p>白名单文件可能很长，一行一条问题时刷屏比不报还糟；超出的部分仍然会完整写进控制台日志。</p>
     */
    private static final int MAX_REPORTED_PROBLEMS = 10;

    private final ProxyServer server;
    private final Logger logger;
    private final Path dataDirectory;

    private final Counters counters = new Counters();
    private final ChannelHook hook;

    /** 当前生效的配置快照；重载时整体替换，连接在创建时取用，读路径无锁。 */
    private final AtomicReference<DetectorContext> context = new AtomicReference<>();

    private volatile Instant startedAt = Instant.now();

    @Inject
    public MikuHAProxy(ProxyServer server, Logger logger, @DataDirectory Path dataDirectory) {
        this.server = server;
        this.logger = logger;
        // @DataDirectory 只会注入 plugins/<插件 id>，而插件 id 不允许大写字母，
        // 所以这里自己解析成 plugins/MikuHAProxy，并顺手把旧目录整体重命名过去
        // （迁移失败则继续用旧目录并告警，绝不会把用户的白名单悄悄丢掉）。
        this.dataDirectory = DataFolder.resolve(dataDirectory, logger::info, logger::warn);
        this.hook = new ChannelHook(server, context::get, logger);
    }

    @Subscribe
    public void onProxyInitialize(ProxyInitializeEvent event) {
        startedAt = Instant.now();
        try {
            if (!loadConfiguration(true)) {
                logger.error("初始配置加载失败：插件不会接管连接初始化流程。修正配置后可用 /mikuproxy reload 重试。");
                return;
            }
            if (!hook.install()) {
                return;
            }
            registerCommand();
            printStartupSummary();
        } catch (Throwable t) {
            // 初始化入口必须连 Error 一起接住：包装器的静态初始化失败会抛 ExceptionInInitializerError，
            // 上游内部类消失会抛 NoClassDefFoundError。Velocity 是顺序初始化所有插件的，
            // 让这类错误漏出去就是在拿整个代理的启动开玩笑。
            logger.error("MikuHAProxy 初始化时出现意外错误，插件将保持加载但不生效。"
                    + "请把下面的堆栈反馈给插件作者。", t);
        }
    }

    @Subscribe
    public void onProxyShutdown(ProxyShutdownEvent event) {
        hook.uninstall();
    }

    // ------------------------------------------------------------------
    // 配置
    // ------------------------------------------------------------------

    /**
     * 载入（或重载）配置。
     *
     * @param writeDefaults 是否在文件缺失时写出带中文注释的默认文件
     * @return 是否成功；失败时保留原有的配置快照
     */
    public synchronized boolean loadConfiguration(boolean writeDefaults) {
        return loadConfiguration(writeDefaults, null);
    }

    /**
     * 载入（或重载）配置，并把「配置问题」额外回显给指定接收方。
     *
     * <p>为什么需要 {@code problemSink}：写错的那一项会安全地回退到默认值，插件照常工作，
     * 但问题目前只出现在控制台日志里。执行 {@code /mikuproxy reload} 的人如果只看到
     * 「配置已重载」，就不会知道自己改的那一行其实没生效——所以重载路径必须把问题回显给他。</p>
     *
     * @param writeDefaults 是否在文件缺失时写出带中文注释的默认文件
     * @param problemSink   额外的问题接收方；{@code null} 表示只写控制台日志（启动路径）
     * @return 是否成功；失败时保留原有的配置快照
     */
    public synchronized boolean loadConfiguration(boolean writeDefaults, Consumer<String> problemSink) {
        final List<String> problems = new ArrayList<>();
        final boolean success;
        try {
            success = doLoadConfiguration(writeDefaults, problems);
        } finally {
            // 放在 finally 里：失败路径上已经收集到的问题同样要报出来，
            // 否则「重载失败」只会给出一句笼统的提示，等于让人去翻日志。
            problems.forEach(problem -> logger.warn("配置问题：{}", problem));
            if (problemSink != null) {
                problems.forEach(problemSink);
            }
        }

        if (success) {
            final DetectorContext snapshot = context.get();
            if (snapshot.settings().allowAllProxies()) {
                logger.warn("!!! ==========================================================");
                logger.warn("!!! allow-all-proxies = true：任何来源都可以伪造 PROXY 头，");
                logger.warn("!!! 玩家的真实 IP / 封禁 / 风控全部失效。切勿在生产环境开启。");
                logger.warn("!!! ==========================================================");
            } else if (snapshot.allowList().size() == 0) {
                logger.warn("白名单为空：所有代理连接都会被拒绝，只有直连可以进入。");
            }
        }
        return success;
    }

    /** 真正的载入逻辑；收集到的问题统一由 {@link #loadConfiguration(boolean, Consumer)} 报告。 */
    private boolean doLoadConfiguration(boolean writeDefaults, List<String> problems) {
        try {
            Files.createDirectories(dataDirectory);
        } catch (IOException e) {
            logger.error("无法创建插件数据目录 {}", dataDirectory, e);
            return false;
        }

        final Path configFile = dataDirectory.resolve(PluginConfig.FILE_NAME);
        if (writeDefaults) {
            writeDefaultResource(PluginConfig.FILE_NAME, configFile);
        }

        final PluginConfig config;
        try {
            config = PluginConfig.load(configFile, problems::add);
        } catch (IOException e) {
            logger.error("读取 {} 失败", configFile, e);
            return false;
        }

        final Path whitelistFile = resolveWhitelistFile(config, problems);
        if (writeDefaults) {
            writeDefaultResource("whitelist.conf", whitelistFile);
        }

        final AllowList allowList;
        if (config.allowAllProxies()) {
            allowList = AllowList.ALLOW_ALL;
        } else {
            try {
                allowList = AllowList.load(whitelistFile, problems::add);
            } catch (IOException e) {
                logger.error("读取白名单 {} 失败", whitelistFile, e);
                return false;
            }
        }

        context.set(new DetectorContext(allowList, config, counters,
                new LogThrottle(config.rejectedLogIntervalSeconds(), config.rejectedLogMaxTracked()), logger));
        return true;
    }

    /**
     * 解析白名单文件路径。
     *
     * <p>{@link Path#of(String, String...)} 在 Windows 上遇到 {@code < > : " | ? *} 这类字符，
     * 或者写成保留设备名（{@code CON}、{@code NUL} 等），会抛 {@link InvalidPathException}。
     * 这是 unchecked 异常：放任它冒出去，启动时只会在日志里留下一条笼统的堆栈，reload 时则直接让命令失败——
     * 而本插件对外的承诺是「任何写法错误都能被精确报告，并且不会让插件加载失败」。所以这里自己兜住，
     * 报出问题并回退到默认文件名。</p>
     *
     * @param problems 配置问题出口
     */
    private Path resolveWhitelistFile(PluginConfig config, List<String> problems) {
        return resolveWhitelistFile(config, dataDirectory, problems, Path::of);
    }

    /**
     * 把配置里写的字符串解析成路径。
     *
     * <p>抽成可注入的接口，是为了能在 Linux CI 上覆盖「解析器抛 {@link InvalidPathException}」这一条
     * 几乎只会在 Windows 上真的发生的分支：那里遇到 {@code < > : " | ? *} 这类字符或保留设备名
     * ({@code CON}、{@code NUL}) 才会抛，而同样的字符串在 Linux 上是完全合法的路径，用真实的
     * {@link Path#of} 造不出这条分支。这与 {@code DataFolder.RealNameReader} 是同一个套路。
     * 生产路径注入 {@link Path#of}。</p>
     */
    @FunctionalInterface
    interface WhitelistPathParser {
        Path parse(String value) throws InvalidPathException;
    }

    /**
     * 解析白名单文件路径（{@code dataDirectory} 与解析器可注入，便于测试脱离 Velocity 容器覆盖判定逻辑）。
     *
     * <p>为什么值得为它写一个可注入的重载：第二个分支
     * {@code configured.isAbsolute() ? configured : dataDirectory.resolve(configured)} 走的正是
     * <b>每一个没改过 {@code whitelist-file} 这个配置项的用户</b>的路径 —— 出厂值
     * {@code whitelist.conf} 是相对路径，必须相对数据目录解析，一旦这里的行为变了，白名单会凭空
     * 「消失」（插件读不到文件 ⇒ 拒绝所有代理连接），而它此前是零覆盖。</p>
     *
     * <p>做成 static 并把 {@code dataDirectory} 变成显式入参，是因为构造 {@link MikuHAProxy}
     * 需要 Velocity 注入 {@code ProxyServer / Logger / @DataDirectory}，测试里造不出实例。</p>
     *
     * @param config        配置
     * @param dataDirectory 插件数据目录
     * @param problems      配置问题出口
     * @param parser        路径解析器；生产传入 {@link Path#of}
     */
    static Path resolveWhitelistFile(PluginConfig config, Path dataDirectory, List<String> problems,
                                     WhitelistPathParser parser) {
        final Path configured;
        try {
            configured = parser.parse(config.whitelistFile());
        } catch (InvalidPathException e) {
            final String fallback = PluginConfig.defaults().whitelistFile();
            problems.add("config.toml：whitelist-file 不是合法路径（「" + config.whitelistFile() + "」："
                    + e.getReason() + "），已改用默认值 " + fallback);
            return dataDirectory.resolve(fallback);
        }
        return configured.isAbsolute() ? configured : dataDirectory.resolve(configured);
    }

    private void writeDefaultResource(String resourceName, Path target) {
        if (Files.exists(target)) {
            return;
        }
        try (InputStream in = MikuHAProxy.class.getResourceAsStream("/" + resourceName)) {
            if (in == null) {
                logger.warn("插件资源 {} 缺失，无法生成默认文件", resourceName);
                return;
            }
            Files.copy(in, target);
            logger.info("已生成默认文件：{}", target);
        } catch (IOException e) {
            logger.warn("写出默认文件 {} 失败", target, e);
        }
    }

    // ------------------------------------------------------------------
    // 命令 / 状态
    // ------------------------------------------------------------------

    private void registerCommand() {
        final BrigadierCommand command = MikuProxyCommand.create(this);
        server.getCommandManager().register(
                server.getCommandManager().metaBuilder(command)
                        .plugin(this)
                        .aliases("mhp", "mikuhaproxy")
                        .build(),
                command);
    }

    private void printStartupSummary() {
        final DetectorContext snapshot = context.get();
        final Boolean enabled = hook.readProxyProtocolFlag();

        logger.info("MikuHAProxy {} 已启用（作者 JunXieX）。", VERSION);
        if (Boolean.FALSE.equals(enabled)) {
            logger.error("!!! ==========================================================");
            logger.error("!!! velocity.toml 里没有启用 haproxy-protocol，插件目前不会起作用。");
            logger.error("!!! 请在 velocity.toml 中设置 haproxy-protocol = true 后重启代理。");
            logger.error("!!! ==========================================================");
        } else if (enabled == null) {
            logger.info("无法读取 velocity.toml 的 haproxy-protocol 开关；若代理连接不可用请检查该配置项。");
        }
        logger.info("白名单：{}，规则 {} 条。可用 /mikuproxy status 查看详情。", snapshot.allowList(), snapshot.allowList().size());
    }

    public void sendHelp(CommandSource source) {
        source.sendRichMessage("<gradient:#7bd7ff:#a88bff><b>MikuHAProxy</b></gradient> <gray>v" + VERSION + "</gray>");
        source.sendRichMessage("<gray>/mikuproxy status <dark_gray>-</dark_gray> 查看注入状态、白名单与计数</gray>");
        source.sendRichMessage("<gray>/mikuproxy list <dark_gray>-</dark_gray> 列出当前生效的白名单规则</gray>");
        source.sendRichMessage("<gray>/mikuproxy reload <dark_gray>-</dark_gray> 重新读取 config.toml 与白名单</gray>");
    }

    public void sendStatus(CommandSource source) {
        final DetectorContext snapshot = context.get();
        final Boolean enabled = hook.readProxyProtocolFlag();

        source.sendRichMessage("<gradient:#7bd7ff:#a88bff><b>MikuHAProxy</b></gradient> <gray>v" + VERSION
                + " · 作者 JunXieX</gray>");
        source.sendRichMessage("<gray>管道注入：</gray>" + (hook.isInstalled() ? "<green>已安装</green>" : "<red>未安装</red>"));
        source.sendRichMessage("<gray>velocity.toml 的 haproxy-protocol：</gray>" + proxyProtocolState(enabled));
        source.sendRichMessage("<gray>白名单：</gray><white>" + esc(snapshot.allowList().toString())
                + "</white> <dark_gray>(" + snapshot.allowList().size() + " 条规则)</dark_gray>");
        source.sendRichMessage("<gray>拒绝日志限流：</gray><white>同地址每 "
                + snapshot.settings().rejectedLogIntervalSeconds() + " 秒最多一条</white>");
        source.sendRichMessage("<gray>连接计数：</gray><white>直连 " + counters.direct()
                + " · 代理 " + counters.proxied()
                + " · 拒绝 " + counters.rejected()
                + " · 未注入 " + counters.notInjected()
                + " · 异常 " + counters.failures() + "</white>");
        source.sendRichMessage("<gray>已运行：</gray><white>" + formatUptime() + "</white>");
    }

    public void sendWhitelist(CommandSource source) {
        final List<String> rules = context.get().allowList().describeRules();
        if (rules.isEmpty()) {
            source.sendRichMessage("<yellow>白名单为空：所有代理连接都会被拒绝。</yellow>");
            return;
        }
        source.sendRichMessage("<gray>白名单规则（" + rules.size() + " 条）：</gray>");
        for (String rule : rules) {
            source.sendRichMessage("<dark_gray> · </dark_gray><white>" + esc(rule) + "</white>");
        }
    }

    public void sendReload(CommandSource source) {
        final DetectorContext before = context.get();
        final List<String> problems = new ArrayList<>();
        // 这里刻意传 true，与启动路径（onProxyInitialize）保持一致：两条入口对「白名单文件缺失」
        // 这个**同一个条件**必须得出同一个结果。
        // 传 false 时差异是反直觉的：缺失会在 reload 时保持缺失，AllowList.load 于是返回 DENY_ALL
        // （拒绝一切代理连接）；而重启走的是 writeDefaults = true，会先写出厂模板再读 —— 那份模板里
        // 带着 127.0.0.0/8 与 ::1/128，于是回环来源被放行。同一个磁盘状态，命令里是拒绝、重启后
        // 是放行，等于留了一条「重启才生效」的暗门；想用「删掉白名单文件」表达拒绝所有的服主，
        // 重启后会发现自己其实放行了一段来源。宁可让 reload 也写出厂模板（看得见、可删），
        // 也不要让两条入口给出相反结论。
        if (!loadConfiguration(true, problems::add)) {
            source.sendRichMessage("<red>重载失败：配置有误，已继续沿用上一份配置。</red>");
        } else {
            final DetectorContext after = context.get();
            source.sendRichMessage("<green>配置已重载。</green> <gray>白名单 "
                    + before.allowList().size() + " → " + after.allowList().size() + " 条规则；"
                    + "新建立的连接立即生效。</gray>");
            if (after.settings().allowAllProxies()) {
                source.sendRichMessage("<red>警告：allow-all-proxies = true，"
                        + "任何来源都能伪造 PROXY 头，切勿在生产环境使用。</red>");
            } else if (after.allowList().size() == 0) {
                source.sendRichMessage("<yellow>注意：白名单为空，所有代理连接都会被拒绝。</yellow>");
            }
        }
        reportProblems(source, problems);
    }

    /** 写错的那一项已经回退默认值、插件照常工作，所以必须主动告诉执行者，不能只留在控制台。 */
    private static void reportProblems(CommandSource source, List<String> problems) {
        if (problems.isEmpty()) {
            return;
        }
        source.sendRichMessage("<yellow>发现 " + problems.size() + " 处配置问题"
                + "（相关设置项已回退到默认值，其余项照常生效）：</yellow>");
        final int shown = Math.min(problems.size(), MAX_REPORTED_PROBLEMS);
        for (int i = 0; i < shown; i++) {
            source.sendRichMessage("<dark_gray> · </dark_gray><white>" + esc(problems.get(i)) + "</white>");
        }
        if (problems.size() > shown) {
            source.sendRichMessage("<dark_gray> · 另有 " + (problems.size() - shown)
                    + " 条未在此处列出，详见控制台日志。</dark_gray>");
        }
    }

    private static String proxyProtocolState(Boolean enabled) {
        if (enabled == null) {
            return "<yellow>读取失败</yellow>";
        }
        return enabled ? "<green>已启用</green>" : "<red>未启用</red>";
    }

    private String formatUptime() {
        final Duration duration = Duration.between(startedAt, Instant.now());
        final long days = duration.toDays();
        final long hours = duration.toHoursPart();
        final long minutes = duration.toMinutesPart();
        final long seconds = duration.toSecondsPart();
        final StringBuilder builder = new StringBuilder();
        if (days > 0) {
            builder.append(days).append(" 天 ");
        }
        if (days > 0 || hours > 0) {
            builder.append(hours).append(" 小时 ");
        }
        builder.append(minutes).append(" 分 ").append(seconds).append(" 秒");
        return builder.toString();
    }

    /** 转义 MiniMessage 的标签起始符，避免规则文本里的特殊字符破坏格式。 */
    private static String esc(String text) {
        return text.replace("<", "\\<");
    }

}
