package io.github.junxiex.mikuhaproxy.config;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PluginConfigTest {

    private static PluginConfig load(Path dir, String content, List<String> problems) throws IOException {
        final Path file = dir.resolve("config.toml");
        Files.writeString(file, content, StandardCharsets.UTF_8);
        return PluginConfig.load(file, problems::add);
    }

    /** 模板里 `键 = 值` 的键名（只匹配小写 + 连字符，注释行不会命中）。 */
    private static final Pattern TEMPLATE_KEY = Pattern.compile("^\\s*([a-z][a-z0-9-]*)\\s*=");

    @Test
    @DisplayName("出厂模板 config.toml 与 KNOWN_KEYS 必须双向一致，且整份模板零问题解析")
    void shippedTemplateIsInSyncWithKnownKeys(@TempDir Path dir) throws IOException {
        // 方向一：模板里的每个键都必须是已知键（否则每个新用户都会看到「未知设置项」告警）
        final List<String> templateKeys = new ArrayList<>();
        try (InputStream in = PluginConfigTest.class.getResourceAsStream("/" + PluginConfig.FILE_NAME);
             BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
            assertNotNull(in, "插件资源 " + PluginConfig.FILE_NAME + " 缺失");
            String line;
            while ((line = reader.readLine()) != null) {
                final Matcher matcher = TEMPLATE_KEY.matcher(line);
                if (matcher.find()) {
                    templateKeys.add(matcher.group(1));
                }
            }
        }
        assertEquals(PluginConfig.KNOWN_KEYS.size(), templateKeys.size(),
                "模板里的键与 KNOWN_KEYS 数量不一致：模板 " + templateKeys);
        assertTrue(PluginConfig.KNOWN_KEYS.containsAll(templateKeys),
                "模板里有代码不认识的键：模板 " + templateKeys);

        // 方向二：整份模板必须零问题解析（顺便覆盖「值类型写错」这种更隐蔽的失配）
        final Path file = dir.resolve(PluginConfig.FILE_NAME);
        try (InputStream in = PluginConfigTest.class.getResourceAsStream("/" + PluginConfig.FILE_NAME)) {
            Files.copy(in, file);
        }
        final List<String> problems = new ArrayList<>();
        PluginConfig.load(file, problems::add);
        assertTrue(problems.isEmpty(), "出厂模板自身就解析出了问题：" + problems);
    }

    @Test
    @DisplayName("默认值：白名单开启、拒绝日志开启、允许日志关闭、限流 60 秒")
    void defaults() {
        final PluginConfig config = PluginConfig.defaults();
        assertFalse(config.allowAllProxies());
        assertEquals("whitelist.conf", config.whitelistFile());
        assertTrue(config.logRejectedConnections());
        assertFalse(config.logAcceptedConnections());
        assertEquals(60L, config.rejectedLogIntervalSeconds());
        assertEquals(4096, config.rejectedLogMaxTracked());
    }

    @Test
    @DisplayName("文件缺失时使用默认值，并给出提示")
    void missingFileFallsBackToDefaults(@TempDir Path dir) throws IOException {
        final List<String> problems = new ArrayList<>();
        final PluginConfig config = PluginConfig.load(dir.resolve("config.toml"), problems::add);
        assertEquals(PluginConfig.defaults().whitelistFile(), config.whitelistFile());
        assertEquals(1, problems.size());
    }

    @Test
    @DisplayName("正常解析全部设置项，支持引号与行尾注释")
    void parsesAllKeys(@TempDir Path dir) throws IOException {
        final List<String> problems = new ArrayList<>();
        final PluginConfig config = load(dir, """
                # 注释
                allow-all-proxies = true
                whitelist-file = "my-list.conf"   # 行尾注释
                log-rejected-connections = false
                log-accepted-connections = true
                rejected-log-interval-seconds = 5
                rejected-log-max-tracked = 64
                """, problems);

        assertTrue(problems.isEmpty(), "不应有问题：" + problems);
        assertTrue(config.allowAllProxies());
        assertEquals("my-list.conf", config.whitelistFile());
        assertFalse(config.logRejectedConnections());
        assertTrue(config.logAcceptedConnections());
        assertEquals(5L, config.rejectedLogIntervalSeconds());
        assertEquals(64, config.rejectedLogMaxTracked());
    }

    @Test
    @DisplayName("未知设置项：报告并忽略，其余照常生效")
    void ignoresUnknownKey(@TempDir Path dir) throws IOException {
        final List<String> problems = new ArrayList<>();
        final PluginConfig config = load(dir, """
                unknown-key = 1
                log-accepted-connections = true
                """, problems);

        assertEquals(1, problems.size());
        assertTrue(problems.get(0).contains("未知设置项"), problems.get(0));
        assertTrue(config.logAcceptedConnections());
    }

    @Test
    @DisplayName("布尔值写错：报告并回退默认值")
    void badBooleanFallsBack(@TempDir Path dir) throws IOException {
        final List<String> problems = new ArrayList<>();
        final PluginConfig config = load(dir, "allow-all-proxies = yes\n", problems);

        assertEquals(1, problems.size());
        assertTrue(problems.get(0).contains("true"), problems.get(0));
        assertFalse(config.allowAllProxies(), "应当回退到默认值 false");
    }

    @Test
    @DisplayName("整数越界或非数字：报告并回退默认值")
    void badIntegerFallsBack(@TempDir Path dir) throws IOException {
        final List<String> problems = new ArrayList<>();
        final PluginConfig config = load(dir, """
                rejected-log-interval-seconds = -1
                rejected-log-max-tracked = 不是数字
                """, problems);

        assertEquals(2, problems.size(), problems.toString());
        assertEquals(60L, config.rejectedLogIntervalSeconds());
        assertEquals(4096, config.rejectedLogMaxTracked());
    }

    @Test
    @DisplayName("缺少等号的行：报告行号并忽略")
    void reportsMissingEquals(@TempDir Path dir) throws IOException {
        final List<String> problems = new ArrayList<>();
        load(dir, """
                这是一行没有等号的内容
                log-accepted-connections = true
                """, problems);

        assertEquals(1, problems.size());
        assertTrue(problems.get(0).contains("第 1 行"), problems.get(0));
        assertTrue(problems.get(0).contains("缺少 '='"), problems.get(0));
    }

    @Test
    @DisplayName("值为空：报告并忽略该行")
    void reportsEmptyValue(@TempDir Path dir) throws IOException {
        final List<String> problems = new ArrayList<>();
        load(dir, "whitelist-file = \n", problems);
        assertEquals(1, problems.size());
        assertTrue(problems.get(0).contains("值为空"), problems.get(0));
    }

    @Test
    @DisplayName("以 # 开头或只有注释的行被完全忽略，不产生问题")
    void ignoresCommentsAndBlankLines(@TempDir Path dir) throws IOException {
        final List<String> problems = new ArrayList<>();
        final PluginConfig config = load(dir, """
                # 全是注释

                   # 前面有空格也是注释
                log-accepted-connections = true
                """, problems);

        assertTrue(problems.isEmpty(), problems.toString());
        assertTrue(config.logAcceptedConnections());
    }
}
