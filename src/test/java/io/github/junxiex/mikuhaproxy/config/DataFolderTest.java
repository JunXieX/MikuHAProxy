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
}
