package io.github.junxiex.mikuhaproxy.config;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.function.Consumer;

/**
 * 插件数据目录的解析与改名。
 *
 * <p>Velocity 的 {@code @DataDirectory} 注入的永远是 {@code plugins/<插件 id>}，而插件 id 只允许
 * 「小写字母 / 数字 / 连字符 / 下划线」（{@code SerializedPluginDescription.ID_PATTERN}），
 * 拿不到 {@code plugins/MikuHAProxy} 这种带大写的目录名。**为了目录名去改插件 id 是有风险的**
 * （id 校验不过插件会完全不加载），所以这里在构造函数里自己解析。</p>
 *
 * <p>改名分两种文件系统，行为不同但目标一致（磁盘上最终都叫 {@value #NAME}）：</p>
 * <ul>
 *   <li><b>区分大小写</b>（Linux 常见）：旧名字是另一个目录，直接整体重命名——同分区下是单个
 *       原子操作，要么全部成功要么完全没动。</li>
     *   <li><b>不区分大小写</b>（Windows / macOS 默认）：两个名字<b>本来就是同一个目录</b>，直接
     *       rename 不会改变磁盘上记录的大小写，于是用「改成中间名 → 再改成目标名」两步来掰正。
     *       磁盘上已是目标名时按真实文件名判断、直接跳过，不再做无谓的 move 与日志。</li>
 * </ul>
 *
 * <p>所有失败路径都回退到「继续使用原目录」并给出告警：绝不会出现「配置已搬到新目录、插件却去读旧目录」
 * 这种半截状态——那等于把用户的白名单静默清空，代理连接会被全部拒绝。</p>
 */
public final class DataFolder {

    /** 期望的数据目录名（与插件显示名保持一致）。 */
    public static final String NAME = "MikuHAProxy";

    /** 掰正大小写时用的中间名后缀；正常跑完不会留下它。 */
    private static final String RENAMING_SUFFIX = ".renaming";

    private DataFolder() {
        throw new AssertionError();
    }

    /**
     * 解析出实际要使用的数据目录。
     *
     * @param injected Velocity 注入的目录（{@code plugins/<插件 id>}）
     * @param info     普通提示出口
     * @param warn     需要用户注意的提示出口
     * @return 实际使用的目录；解析或改名失败时返回 {@code injected}
     */
    public static Path resolve(Path injected, Consumer<String> info, Consumer<String> warn) {
        final Path parent = injected.getParent();
        if (parent == null) {
            return injected;
        }
        final Path desired = parent.resolve(NAME);
        if (isSameDirectory(injected, desired)) {
            // 走这里说明文件系统不区分大小写（Windows / macOS 默认）：两个名字是同一个目录。
            // 但磁盘上记录的大小写未必已是目标名，交给 renameCaseInPlace 按真实文件名判断（必要时才掰正）。
            renameCaseInPlace(injected, info, warn);
            return injected;
        }

        if (Files.isDirectory(desired)) {
            // 目标目录已存在：以它为准，不动任何东西（两份配置同时存在时人工合并最安全）
            if (isNonEmptyDirectory(injected)) {
                warn.accept("检测到旧数据目录 " + injected + " 仍然存在，已忽略它。"
                        + "请把里面的 whitelist.conf / config.toml 手动合并到 " + desired + " 后删除旧目录。");
            }
            return desired;
        }

        if (!Files.isDirectory(injected)) {
            // 首次运行：直接用目标名
            return desired;
        }

        try {
            Files.move(injected, desired);
            info.accept("插件数据目录已从 " + injected + " 重命名为 " + desired + "。");
            return desired;
        } catch (IOException e) {
            warn.accept("重命名数据目录到 " + desired + " 失败（" + e + "），继续使用 " + injected
                    + "；你的配置与白名单不会被丢弃。");
            return injected;
        }
    }

    /**
     * 读取目录在磁盘上的真实名字（大小写以文件系统为准）。
     *
     * <p>抽成可注入的接口，是为了能在<b>大小写敏感</b>的 CI（Linux）上模拟「注入的是小写路径、磁盘上却是
     * 目标大小写」这一 Windows / macOS 场景：那种目录在 Linux 上根本不存在，{@link Path#toRealPath()}
     * 会直接抛 {@code NoSuchFileException}，用真实文件系统测不出这条路径。生产路径注入 {@link #realNameOf}。</p>
     */
    @FunctionalInterface
    interface RealNameReader {
        String read(Path directory) throws IOException;
    }

    /** 生产用的真实名读取：{@link Path#toRealPath()} 在 Windows / macOS 上返回磁盘记录的真实大小写。 */
    private static String realNameOf(Path directory) throws IOException {
        return directory.toRealPath().getFileName().toString();
    }

    /** 目录名只有大小写不同时把它掰正；生产入口，用 {@link #realNameOf} 读真实名。 */
    private static void renameCaseInPlace(Path directory, Consumer<String> info, Consumer<String> warn) {
        renameCaseInPlace(directory, info, warn, DataFolder::realNameOf);
    }

    /**
     * 目录名只有大小写不同时，把它掰正（真实名读取器可注入，便于测试脱离平台差异覆盖判定逻辑）。
     *
     * <p>不区分大小写的文件系统上，直接 {@code rename("mikuhaproxy" → "MikuHAProxy")} 既不报错、
     * 也不会改变磁盘上记录的大小写，所以这里先改成中间名、再改成目标名。</p>
     *
     * <p><b>必须问文件系统要真实文件名</b>：{@code directory} 是 Velocity 用插件 id 拼出来的路径字符串
     * （恒为小写 {@code mikuhaproxy}），它的大小写与<b>磁盘上记录</b>的大小写无关。早先直接比对
     * {@code directory.getFileName()}，于是「磁盘上已经是 {@value #NAME}」也永远判为「不一致」，每次启动
     * 都白做一轮两次 move 并打一行日志（第二步若失败，目录还会卡在中间名上）。改读真实名后，磁盘上已经是
     * 目标名就直接返回，不打日志、不做任何 move。</p>
     */
    static void renameCaseInPlace(Path directory, Consumer<String> info, Consumer<String> warn,
                                  RealNameReader realNameReader) {
        final String actual;
        try {
            actual = realNameReader.read(directory);
        } catch (IOException e) {
            warn.accept("无法读取数据目录 " + directory + " 的真实名称（" + e + "），已跳过改名；"
                    + "配置与白名单不受影响。");
            return;
        }
        if (actual.equals(NAME)) {
            // 磁盘上已经是目标大小写：什么都不做，也不打任何日志
            return;
        }
        final Path target = directory.resolveSibling(NAME);
        final Path staging = directory.resolveSibling(actual + RENAMING_SUFFIX);
        if (Files.exists(staging)) {
            warn.accept("检测到上次改名留下的中间目录 " + staging + "，已跳过改名；"
                    + "请确认其中没有你需要的文件后手动处理。");
            return;
        }
        try {
            Files.move(directory, staging);
        } catch (IOException e) {
            warn.accept("更正数据目录名失败（" + e + "），继续使用 " + directory + "；配置与白名单不受影响。");
            return;
        }
        try {
            Files.move(staging, target);
            info.accept("插件数据目录名已由 " + actual + " 更正为 " + NAME + "。");
        } catch (IOException e) {
            try {
                // 回滚：绝不能让目录停在中间名上，否则下次启动就找不到配置了
                Files.move(staging, directory);
                warn.accept("更正数据目录名失败（" + e + "），目录已还原为 " + directory
                        + "；配置与白名单不受影响。");
            } catch (IOException rollbackFailure) {
                warn.accept("更正数据目录名失败（" + e + "），且还原也失败了（" + rollbackFailure + "）。"
                        + "你的配置目前在 " + staging + "，请手动把它改名为 " + NAME + "。");
            }
        }
    }

    /**
     * 判断两个路径是否指向同一个已存在的目录。
     *
     * <p>这里必须<b>问文件系统</b>，两种「看起来能用」的比较方式都会在某个平台上出错：</p>
     * <ul>
     *   <li>{@link Path#equals}：Windows 上按不区分大小写比较（对），但 macOS（默认 APFS 不区分大小写）
     *       上却按区分比较 —— 于是同一个目录被判成两个，接着走进「目标目录已存在」分支，把用户自己的
     *       目录当成「旧目录」提示去手动合并再删除，照做就等于删掉配置 ✗</li>
     *   <li>字符串 {@code equalsIgnoreCase}：反过来，它会把 Linux 上两个真正不同的目录判成同一个，
     *       于是该重命名的目录不会被重命名（CI 上就是这么暴露出来的）✗</li>
     * </ul>
     *
     * <p>{@link Files#isSameFile} 比的是文件本身（fileKey / inode），跨平台语义一致。两侧必须都存在；
     * 有一侧不存在时返回 {@code false}（还没建出来的目录谈不上「同一个」）。</p>
     */
    private static boolean isSameDirectory(Path a, Path b) {
        if (!Files.exists(a) || !Files.exists(b)) {
            return false;
        }
        try {
            return Files.isSameFile(a, b);
        } catch (IOException e) {
            // 判断不了就当「不是同一个」：后续分支会保守地以目标目录为准，不会动用户的文件
            return false;
        }
    }

    private static boolean isNonEmptyDirectory(Path path) {
        if (!Files.isDirectory(path)) {
            return false;
        }
        try (DirectoryStream<Path> entries = Files.newDirectoryStream(path)) {
            return entries.iterator().hasNext();
        } catch (IOException e) {
            // 读不了就当它"有东西"，宁可多提示一句也别默默忽略
            return true;
        }
    }
}
