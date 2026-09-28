package io.github.junxiex.mikuhaproxy.config;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;

/**
 * 插件配置（{@code config.toml}）。
 *
 * <p>只使用 TOML 里「扁平的 {@code key = value}」这一子集：不引入任何第三方 TOML 解析器，
 * 也就没有「解析器版本 / 传递依赖」的风险；同时因为语法面窄，任何写法错误都能被精确定位到行号。</p>
 */
public final class PluginConfig {

    public static final String FILE_NAME = "config.toml";

    /**
     * 本插件认识的配置项。
     *
     * <p>包内可见是为了让单元测试做「模板键 ↔ 本集合」的**双向**核对：只靠人记，
     * 很容易出现「加了解析却忘了登记」或「登记了模板里却没有」这类静默不一致。</p>
     */
    static final Set<String> KNOWN_KEYS = Set.of(
            "allow-all-proxies",
            "whitelist-file",
            "log-rejected-connections",
            "log-accepted-connections",
            "rejected-log-interval-seconds",
            "rejected-log-max-tracked");

    private final boolean allowAllProxies;
    private final String whitelistFile;
    private final boolean logRejectedConnections;
    private final boolean logAcceptedConnections;
    private final long rejectedLogIntervalSeconds;
    private final int rejectedLogMaxTracked;

    private PluginConfig(boolean allowAllProxies, String whitelistFile, boolean logRejectedConnections,
                         boolean logAcceptedConnections, long rejectedLogIntervalSeconds,
                         int rejectedLogMaxTracked) {
        this.allowAllProxies = allowAllProxies;
        this.whitelistFile = whitelistFile;
        this.logRejectedConnections = logRejectedConnections;
        this.logAcceptedConnections = logAcceptedConnections;
        this.rejectedLogIntervalSeconds = rejectedLogIntervalSeconds;
        this.rejectedLogMaxTracked = rejectedLogMaxTracked;
    }

    public static PluginConfig defaults() {
        return new PluginConfig(false, "whitelist.conf", true, false, 60L, 4096);
    }

    /**
     * 读取配置。
     *
     * <p>单项写错只会回退到默认值并报告问题，不会让插件加载失败。</p>
     *
     * @param file    配置文件
     * @param problem 问题报告出口
     */
    public static PluginConfig load(Path file, Consumer<String> problem) throws IOException {
        if (!Files.isRegularFile(file)) {
            problem.accept("配置文件不存在，使用默认配置：" + file);
            return defaults();
        }

        final Map<String, String> values = new LinkedHashMap<>();
        try (BufferedReader reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
            String line;
            int lineNumber = 0;
            while ((line = reader.readLine()) != null) {
                lineNumber++;
                if (lineNumber == 1) {
                    line = stripBom(line);
                }
                final String content = stripComment(line).trim();
                if (content.isEmpty()) {
                    continue;
                }
                final int equals = content.indexOf('=');
                if (equals < 0) {
                    problem.accept("config.toml 第 " + lineNumber + " 行：缺少 '='，已忽略 → " + content);
                    continue;
                }
                final String key = content.substring(0, equals).trim();
                final String value = unquote(content.substring(equals + 1).trim());
                if (key.isEmpty()) {
                    problem.accept("config.toml 第 " + lineNumber + " 行：设置项名称为空，已忽略");
                } else if (!KNOWN_KEYS.contains(key)) {
                    problem.accept("config.toml 第 " + lineNumber + " 行：未知设置项 " + key + "，已忽略");
                } else if (value.isEmpty()) {
                    problem.accept("config.toml 第 " + lineNumber + " 行：" + key + " 的值为空，已忽略");
                } else {
                    values.put(key, value);
                }
            }
        }

        final PluginConfig defaults = defaults();
        return new PluginConfig(
                bool(values, "allow-all-proxies", defaults.allowAllProxies, problem),
                text(values, "whitelist-file", defaults.whitelistFile, problem),
                bool(values, "log-rejected-connections", defaults.logRejectedConnections, problem),
                bool(values, "log-accepted-connections", defaults.logAcceptedConnections, problem),
                integer(values, "rejected-log-interval-seconds", defaults.rejectedLogIntervalSeconds, 0L, 86_400L, problem),
                (int) integer(values, "rejected-log-max-tracked", defaults.rejectedLogMaxTracked, 16L, 1_000_000L, problem));
    }

    private static boolean bool(Map<String, String> values, String key, boolean fallback, Consumer<String> problem) {
        final String raw = values.get(key);
        if (raw == null) {
            return fallback;
        }
        if ("true".equalsIgnoreCase(raw)) {
            return true;
        }
        if ("false".equalsIgnoreCase(raw)) {
            return false;
        }
        problem.accept("config.toml：" + key + " 只能是 true 或 false，实际是「" + raw + "」，已使用默认值 " + fallback);
        return fallback;
    }

    private static long integer(Map<String, String> values, String key, long fallback, long min, long max,
                                Consumer<String> problem) {
        final String raw = values.get(key);
        if (raw == null) {
            return fallback;
        }
        try {
            final long parsed = Long.parseLong(raw);
            if (parsed < min || parsed > max) {
                problem.accept("config.toml：" + key + " 必须在 " + min + "~" + max + " 之间，实际是 " + parsed
                        + "，已使用默认值 " + fallback);
                return fallback;
            }
            return parsed;
        } catch (NumberFormatException e) {
            problem.accept("config.toml：" + key + " 不是整数，实际是「" + raw + "」，已使用默认值 " + fallback);
            return fallback;
        }
    }

    private static String text(Map<String, String> values, String key, String fallback, Consumer<String> problem) {
        final String raw = values.get(key);
        if (raw == null || raw.isBlank()) {
            if (raw != null) {
                problem.accept("config.toml：" + key + " 不能为空，已使用默认值 " + fallback);
            }
            return fallback;
        }
        return raw;
    }

    /** 去掉成对的首尾引号（单双引号都支持）。 */
    private static String unquote(String value) {
        if (value.length() >= 2) {
            final char first = value.charAt(0);
            if ((first == '"' || first == '\'') && value.charAt(value.length() - 1) == first) {
                return value.substring(1, value.length() - 1);
            }
        }
        return value;
    }

    /** 去掉 {@code #} 注释，但忽略引号内的 {@code #}。 */
    private static String stripComment(String line) {
        boolean inSingle = false;
        boolean inDouble = false;
        for (int i = 0; i < line.length(); i++) {
            final char c = line.charAt(i);
            if (c == '\\' && inDouble) {
                i++;
            } else if (c == '"' && !inSingle) {
                inDouble = !inDouble;
            } else if (c == '\'' && !inDouble) {
                inSingle = !inSingle;
            } else if (c == '#' && !inSingle && !inDouble) {
                return line.substring(0, i);
            }
        }
        return line;
    }

    private static String stripBom(String line) {
        return !line.isEmpty() && line.charAt(0) == '\uFEFF' ? line.substring(1) : line;
    }

    // ------------------------------------------------------------------

    public boolean allowAllProxies() {
        return allowAllProxies;
    }

    public String whitelistFile() {
        return whitelistFile;
    }

    public boolean logRejectedConnections() {
        return logRejectedConnections;
    }

    public boolean logAcceptedConnections() {
        return logAcceptedConnections;
    }

    public long rejectedLogIntervalSeconds() {
        return rejectedLogIntervalSeconds;
    }

    public int rejectedLogMaxTracked() {
        return rejectedLogMaxTracked;
    }
}
