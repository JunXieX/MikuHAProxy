package io.github.junxiex.mikuhaproxy.config;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeFalse;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * {@link DataFolder} 的测试。
 *
 * <p>关键前提：<b>Windows / macOS 的文件系统默认不区分大小写</b>，
 * 于是 {@code plugins/mikuhaproxy} 和 {@code plugins/MikuHAProxy} 是<b>同一个目录</b>。
 * 两条分支必须分开测，所以这里用运行时探针判断文件系统是否区分大小写，
 * 再用 {@code assumeTrue/assumeFalse} 只跑当前平台能表达的那条分支
 * （在 Windows 上跑断言"旧目录必须消失"永远是错的——它压根不是另一个目录）。</p>
 */
class DataFolderTest {

    /** 收集两个出口的提示，便于断言"报了没有、报了什么"。 */
    private static final class Notices {
        final List<String> info = new ArrayList<>();
        final List<String> warn = new ArrayList<>();
    }

    private static Path resolve(Path injected, Notices notices) {
        return DataFolder.resolve(injected, notices.info::add, notices.warn::add);
    }

    /** 在给定目录里探测文件系统是否区分大小写。 */
    private static boolean caseSensitive(Path dir) throws IOException {
        final Path probe = dir.resolve("case-probe");
        Files.createDirectories(probe);
        try {
            return !Files.exists(dir.resolve("CASE-PROBE"));
        } finally {
            Files.deleteIfExists(probe);
        }
    }

    /** 取目录里唯一的那个条目的名字，用来断言"磁盘上记的到底是哪种大小写"。 */
    private static String onlyEntryName(Path dir) throws IOException {
        try (var entries = Files.list(dir)) {
            final List<Path> list = entries.toList();
            assertEquals(1, list.size(), "预期目录里只有一个条目：" + list);
            return list.get(0).getFileName().toString();
        }
    }

    @Test
    @DisplayName("首次运行：返回 plugins/MikuHAProxy，且不产生任何提示")
    void freshInstallUsesDesiredFolder(@TempDir Path plugins) throws IOException {
        final Notices notices = new Notices();
        final Path result = resolve(plugins.resolve("mikuhaproxy"), notices);

        assertEquals(plugins.resolve(DataFolder.NAME), result);
        assertTrue(notices.info.isEmpty(), notices.info.toString());
        assertTrue(notices.warn.isEmpty(), notices.warn.toString());
        // 解析本身不建目录（真正创建发生在写出默认文件时）
        assertFalse(Files.exists(result));

        // 真的创建出来后，磁盘上的名字必须就是期望的大小写
        Files.createDirectories(result);
        assertEquals(DataFolder.NAME, onlyEntryName(plugins));
    }

    @Test
    @DisplayName("区分大小写的文件系统：旧目录整体重命名过去，配置与白名单都在")
    void migratesLegacyFolderWhenCaseSensitive(@TempDir Path plugins) throws IOException {
        assumeTrue(caseSensitive(plugins), "本用例需要区分大小写的文件系统（那条分支不适用）");

        final Path legacy = plugins.resolve("mikuhaproxy");
        Files.createDirectories(legacy);
        Files.writeString(legacy.resolve("config.toml"), "allow-all-proxies = false\n", StandardCharsets.UTF_8);
        Files.writeString(legacy.resolve("whitelist.conf"), "127.0.0.0/8\n", StandardCharsets.UTF_8);

        final Notices notices = new Notices();
        final Path result = resolve(legacy, notices);

        assertEquals(plugins.resolve(DataFolder.NAME), result);
        assertEquals("allow-all-proxies = false\n",
                Files.readString(result.resolve("config.toml"), StandardCharsets.UTF_8));
        assertEquals("127.0.0.0/8\n",
                Files.readString(result.resolve("whitelist.conf"), StandardCharsets.UTF_8));
        assertFalse(Files.exists(legacy), "重命名之后旧目录不应再存在");
        assertEquals(DataFolder.NAME, onlyEntryName(plugins));
        assertEquals(1, notices.info.size(), notices.info.toString());
        assertTrue(notices.warn.isEmpty(), notices.warn.toString());
    }

    @Test
    @DisplayName("不区分大小写的文件系统：原地把目录名的大小写掰正，内容一个不动")
    void rectifiesFolderNameCaseWhenCaseInsensitive(@TempDir Path plugins) throws IOException {
        assumeFalse(caseSensitive(plugins), "本用例需要不区分大小写的文件系统");

        final Path legacy = plugins.resolve("mikuhaproxy");
        Files.createDirectories(legacy);
        Files.writeString(legacy.resolve("whitelist.conf"), "127.0.0.0/8\n", StandardCharsets.UTF_8);
        assertEquals("mikuhaproxy", onlyEntryName(plugins));

        final Notices notices = new Notices();
        final Path result = resolve(legacy, notices);

        // 两个名字本来就指向同一个目录，所以返回哪个都对；重点是磁盘上的大小写变过来了
        assertEquals(DataFolder.NAME, onlyEntryName(plugins), "磁盘上的目录名应当被掰正");
        assertEquals("127.0.0.0/8\n",
                Files.readString(result.resolve("whitelist.conf"), StandardCharsets.UTF_8));
        assertFalse(Files.exists(plugins.resolve("mikuhaproxy" + ".renaming")), "不应该留下中间目录");
        assertEquals(1, notices.info.size(), notices.info.toString());
        assertTrue(notices.warn.isEmpty(), notices.warn.toString());
    }

    @Test
    @DisplayName("目录名已经是目标名：什么都不做，也不报任何提示")
    void alreadyCorrectNameIsUntouched(@TempDir Path plugins) throws IOException {
        final Path desired = plugins.resolve(DataFolder.NAME);
        Files.createDirectories(desired);
        Files.writeString(desired.resolve("whitelist.conf"), "127.0.0.0/8\n", StandardCharsets.UTF_8);

        final Notices notices = new Notices();
        final Path result = resolve(desired, notices);

        assertEquals(desired, result);
        assertTrue(notices.info.isEmpty(), notices.info.toString());
        assertTrue(notices.warn.isEmpty(), notices.warn.toString());
        // 强化为「幂等」断言：这条用例在大小写敏感与不敏感的文件系统上都会执行（不带 assume），
        // 因此在 Linux（CI）上也能覆盖 renameCaseInPlace 的早返回分支（注入 seam 的用例是另一处覆盖）。
        assertEquals(DataFolder.NAME, onlyEntryName(plugins), "名字已正确时不得做任何 move");
        assertEquals("127.0.0.0/8\n",
                Files.readString(result.resolve("whitelist.conf"), StandardCharsets.UTF_8), "内容必须原样保留");
    }

    @Test
    @DisplayName("新目录已存在时以它为准，并提醒旧目录被忽略了（绝不覆盖/合并）")
    void keepsExistingDesiredFolderAndWarnsAboutLegacy(@TempDir Path plugins) throws IOException {
        assumeTrue(caseSensitive(plugins), "本用例需要区分大小写的文件系统（否则两个名字是同一个目录）");

        final Path legacy = plugins.resolve("mikuhaproxy");
        final Path desired = plugins.resolve(DataFolder.NAME);
        Files.createDirectories(legacy);
        Files.writeString(legacy.resolve("whitelist.conf"), "10.0.0.1\n", StandardCharsets.UTF_8);
        Files.createDirectories(desired);
        Files.writeString(desired.resolve("whitelist.conf"), "127.0.0.0/8\n", StandardCharsets.UTF_8);

        final Notices notices = new Notices();
        final Path result = resolve(legacy, notices);

        assertEquals(desired, result);
        assertEquals("127.0.0.0/8\n", Files.readString(result.resolve("whitelist.conf"), StandardCharsets.UTF_8));
        assertTrue(Files.exists(legacy.resolve("whitelist.conf")), "旧目录必须原样留着让用户自己合并");
        assertEquals(1, notices.warn.size(), notices.warn.toString());
        assertTrue(notices.info.isEmpty(), notices.info.toString());
    }

    @Test
    @DisplayName("空目录改名不产生告警（提示归提示，别把正常情况报成问题）")
    void emptyFolderProducesNoWarning(@TempDir Path plugins) throws IOException {
        final Path legacy = plugins.resolve("mikuhaproxy");
        Files.createDirectories(legacy);

        final Notices notices = new Notices();
        resolve(legacy, notices);

        assertTrue(notices.warn.isEmpty(), notices.warn.toString());
    }

    @Test
    @DisplayName("改名失败时回退到原目录（配置绝不丢），并给出可读告警")
    void fallsBackToLegacyFolderWhenRenameFails(@TempDir Path plugins) throws IOException {
        assumeTrue(caseSensitive(plugins), "本用例需要区分大小写的文件系统（否则造不出同名冲突）");

        final Path legacy = plugins.resolve("mikuhaproxy");
        Files.createDirectories(legacy);
        Files.writeString(legacy.resolve("whitelist.conf"), "127.0.0.0/8\n", StandardCharsets.UTF_8);
        // 目标位置放一个同名普通文件，让目录重命名必然失败
        Files.writeString(plugins.resolve(DataFolder.NAME), "占位文件，阻止改名\n", StandardCharsets.UTF_8);

        final Notices notices = new Notices();
        final Path result = resolve(legacy, notices);

        assertEquals(legacy, result, "失败时必须继续用原目录，否则白名单会被静默清空");
        assertEquals("127.0.0.0/8\n", Files.readString(result.resolve("whitelist.conf"), StandardCharsets.UTF_8));
        assertEquals(1, notices.warn.size(), notices.warn.toString());
    }

    @Test
    @DisplayName("注入目录没有父目录时不折腾，原样返回")
    void keepsInjectedFolderWithoutParent() {
        final Notices notices = new Notices();
        final Path relative = Path.of("mikuhaproxy");   // 相对路径没有 parent
        assertEquals(relative, resolve(relative, notices));
        assertTrue(notices.info.isEmpty());
        assertTrue(notices.warn.isEmpty());
    }

    @Test
    @DisplayName("不区分大小写：磁盘上已是目标名时，即便注入路径是小写也不 rename、不打印")
    void alreadyCorrectOnDiskIsNoOpEvenWhenInjectedPathIsLowercase(@TempDir Path plugins) throws IOException {
        assumeFalse(caseSensitive(plugins), "本用例需要不区分大小写的文件系统");

        // 磁盘上已经是目标大小写（这正是上次启动掰正后的状态）
        final Path desired = plugins.resolve(DataFolder.NAME);
        Files.createDirectories(desired);
        Files.writeString(desired.resolve("whitelist.conf"), "127.0.0.0/8\n", StandardCharsets.UTF_8);
        assertEquals(DataFolder.NAME, onlyEntryName(plugins));

        final Notices notices = new Notices();
        // 模拟 Velocity 注入的小写路径 —— 恒为小写，正是「每次启动都白改名并打日志」的根因
        final Path result = resolve(plugins.resolve("mikuhaproxy"), notices);

        assertTrue(notices.info.isEmpty(), "磁盘名已正确时不得打印改名日志：" + notices.info);
        assertTrue(notices.warn.isEmpty(), notices.warn.toString());
        assertEquals(DataFolder.NAME, onlyEntryName(plugins), "不得做任何 move");
        assertEquals("127.0.0.0/8\n", Files.readString(result.resolve("whitelist.conf"), StandardCharsets.UTF_8));
    }

    @Test
    @DisplayName("注入 seam：磁盘真实名已是目标名时，无论平台/注入路径如何都不 rename、不打印（CI 全平台可跑）")
    void realNameAlreadyTargetIsNoOpWithInjectedReader(@TempDir Path plugins) throws IOException {
        final Path desired = plugins.resolve(DataFolder.NAME);
        Files.createDirectories(desired);
        Files.writeString(desired.resolve("whitelist.conf"), "127.0.0.0/8\n", StandardCharsets.UTF_8);
        assertEquals(DataFolder.NAME, onlyEntryName(plugins));

        final Notices notices = new Notices();
        // 注入 fake：无论平台、无论传入什么路径，都报告「磁盘真实名 == MikuHAProxy」。这正是 Windows/macOS
        // 上「注入小写路径、磁盘已是目标大小写」的场景 —— 在大小写敏感的 Linux CI 上，该目录根本不存在，
        // 用真实文件系统复现不出（toRealPath() 会抛 NoSuchFileException），只能靠这个 seam 覆盖。
        DataFolder.renameCaseInPlace(plugins.resolve("mikuhaproxy"), notices.info::add, notices.warn::add,
                directory -> DataFolder.NAME);

        assertTrue(notices.info.isEmpty(), "磁盘真实名已是目标名时不得打印改名日志：" + notices.info);
        assertTrue(notices.warn.isEmpty(), notices.warn.toString());
        assertEquals(DataFolder.NAME, onlyEntryName(plugins), "不得做任何 move（父目录仍只有一项且名字不变）");
        assertEquals("127.0.0.0/8\n", Files.readString(desired.resolve("whitelist.conf"), StandardCharsets.UTF_8),
                "文件内容必须原样可读");
    }

    // ------------------------------------------------------------------
    // 中间名与回滚（此前只覆盖了「第一步 move 失败」，剩下的分支真实文件系统构造不出来）
    // ------------------------------------------------------------------

    @Test
    @DisplayName("上次改名留下的 .renaming 中间目录还在：跳过改名并提示人工处理，两边内容都不动")
    void skipsWhenStagingDirectoryWasLeftBehind(@TempDir Path plugins) throws IOException {
        final Path desired = plugins.resolve(DataFolder.NAME);
        Files.createDirectories(desired);
        Files.writeString(desired.resolve("whitelist.conf"), "127.0.0.0/8\n", StandardCharsets.UTF_8);
        final Path staging = plugins.resolve("mikuhaproxy.renaming");
        Files.createDirectories(staging);
        Files.writeString(staging.resolve("whitelist.conf"), "10.0.0.1\n", StandardCharsets.UTF_8);

        final Notices notices = new Notices();
        // 注入 reader 报告「磁盘真实名仍是小写」⇒ 需要掰正，于是走到检查中间名的那一步
        DataFolder.renameCaseInPlace(desired, notices.info::add, notices.warn::add, directory -> "mikuhaproxy");

        assertEquals(1, notices.warn.size(), notices.warn.toString());
        assertTrue(notices.warn.get(0).contains(".renaming"),
                "必须点名那个中间目录，否则用户不知道该处理谁：" + notices.warn.get(0));
        assertTrue(notices.info.isEmpty(), "什么都没做成，不该有成功提示：" + notices.info);
        assertEquals("127.0.0.0/8\n", Files.readString(desired.resolve("whitelist.conf"), StandardCharsets.UTF_8),
                "目标目录的内容不得被碰");
        assertEquals("10.0.0.1\n", Files.readString(staging.resolve("whitelist.conf"), StandardCharsets.UTF_8),
                "中间目录的内容必须留着让用户自己判断——覆盖或删除都可能吃掉他的配置");
    }

    @Test
    @DisplayName("改到目标名失败但回滚成功：目录还原到原位，配置一处不丢")
    void rollsBackWhenSecondMoveFails(@TempDir Path plugins) throws IOException {
        final Path legacy = plugins.resolve("mikuhaproxy");
        Files.createDirectories(legacy);
        Files.writeString(legacy.resolve("whitelist.conf"), "10.0.0.1\n", StandardCharsets.UTF_8);

        final Notices notices = new Notices();
        // 第 1 次 move（改成中间名）真实执行；第 2 次（中间名 → 目标名）失败；第 3 次（回滚）真实执行。
        // 这条分支用真实文件系统构造不出来：第一次 move 已经把目录挪走，原路径必然空出来。
        final AtomicInteger calls = new AtomicInteger();
        final DataFolder.Mover mover = (source, target) -> {
            if (calls.incrementAndGet() == 2) {
                throw new IOException("测试构造：这一次改不到目标名");
            }
            Files.move(source, target);
        };

        DataFolder.renameCaseInPlace(legacy, notices.info::add, notices.warn::add,
                directory -> "mikuhaproxy", mover);

        assertEquals(3, calls.get(), "依次应当是：改中间名、改目标名（失败）、回滚");
        assertEquals(1, notices.warn.size(), notices.warn.toString());
        assertTrue(notices.warn.get(0).contains("已还原"), "必须告诉用户目录已经回到原位：" + notices.warn.get(0));
        assertTrue(notices.info.isEmpty(), notices.info.toString());
        assertEquals("10.0.0.1\n", Files.readString(legacy.resolve("whitelist.conf"), StandardCharsets.UTF_8),
                "回滚之后配置必须还在原路径上");
        assertFalse(Files.exists(plugins.resolve("mikuhaproxy.renaming")), "不得留下中间目录");
    }

    @Test
    @DisplayName("改到目标名与回滚都失败：必须明确告知目录停在中间名上、给出路径与要改成的名字")
    void reportsManuallyWhenRollbackAlsoFails(@TempDir Path plugins) throws IOException {
        final Path legacy = plugins.resolve("mikuhaproxy");
        Files.createDirectories(legacy);
        Files.writeString(legacy.resolve("whitelist.conf"), "10.0.0.1\n", StandardCharsets.UTF_8);

        final Notices notices = new Notices();
        final AtomicInteger calls = new AtomicInteger();
        final DataFolder.Mover mover = (source, target) -> {
            if (calls.incrementAndGet() == 1) {
                Files.move(source, target);
                return;
            }
            throw new IOException("测试构造：这次 move 失败");
        };

        DataFolder.renameCaseInPlace(legacy, notices.info::add, notices.warn::add,
                directory -> "mikuhaproxy", mover);

        assertEquals(3, calls.get(), "回滚也必须被尝试过");
        assertEquals(1, notices.warn.size(), notices.warn.toString());
        final String warning = notices.warn.get(0);
        assertTrue(warning.contains("手动"), "必须明确让用户手动处理，不能只说「失败了」：" + warning);
        assertTrue(warning.contains("mikuhaproxy.renaming"), "必须给出配置当前实际所在的位置：" + warning);
        assertTrue(warning.contains(DataFolder.NAME), "必须说明要改成的目标名字：" + warning);
        assertTrue(notices.info.isEmpty(), notices.info.toString());

        // 磁盘状态：目录确实卡在中间名上——这正是「必须显眼地报警」的条件
        assertTrue(Files.isDirectory(plugins.resolve("mikuhaproxy.renaming")), "目录应当确实停在中间名上");
        assertFalse(Files.exists(legacy), "原路径此时是空的，所以用户必须靠这条日志找回配置");
        assertEquals("10.0.0.1\n",
                Files.readString(plugins.resolve("mikuhaproxy.renaming").resolve("whitelist.conf"),
                        StandardCharsets.UTF_8),
                "配置本身没丢，只是位置变了");
    }
}
