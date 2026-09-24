package io.github.junxiex.mikuhaproxy;

import io.github.junxiex.mikuhaproxy.config.PluginConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link MikuHAProxy#resolveWhitelistFile} 的测试。
 *
 * <p>为什么单独为它写一个测试类：走相对路径那个分支的是<b>每一个没改过 {@code whitelist-file}
 * 这个配置项的用户</b>（出厂值 {@code whitelist.conf} 就是相对路径），而它此前是零覆盖。
 * 这里要测的不是「某个平台会不会抛异常」，而是「给定一个值，我们的决策逻辑往哪边走」——
 * 值都不用变，答案就不能变。</p>
 *
 * <p>{@code dataDirectory} 与路径解析器都从 {@link MikuHAProxy.WhitelistPathParser} 这个 seam 注入，
 * 于是两个前提同时成立：不需要 Velocity 注入的 {@link MikuHAProxy} 实例（构造它需要
 * {@code ProxyServer / Logger / @DataDirectory}），也不需要一台 Windows 才能复现
 * {@link InvalidPathException} —— 后者在 Linux 上几乎造不出来（那些字符串在 Linux 上是合法路径）。</p>
 *
 * <p>每条用例都必须有<b>正向断言</b>：只断言「没抛异常」是假通过的重灾区，这里一律断言返回值
 * 的具体形态以及 {@code problems} 的实际内容。</p>
 */
class WhitelistFileResolutionTest {

    /**
     * 转发给真实的 {@link Path#of}，并记下收到的每一个入参。
     *
     * <p>记下来是为了断言「解析的确实是配置里写的原值」：只断言返回值的话，
     * 解析器被喂了别的值也能通过。</p>
     */
    private static final class RecordingParser implements MikuHAProxy.WhitelistPathParser {
        final List<String> seen = new ArrayList<>();

        @Override
        public Path parse(String value) throws InvalidPathException {
            seen.add(value);
            return Path.of(value);
        }
    }

    /**
     * 造一份只写了 {@code whitelist-file} 的配置。
     *
     * <p>走 {@link PluginConfig#load} 而不是绕过它造假对象：这条路径顺带保证「用户手写到 config.toml
     * 里的字符串」与「插件交给解析器解析的字符串」是同一个（TOML 解析一旦改语义，这条夹具会先炸）。</p>
     */
    private static PluginConfig configWithWhitelistFile(Path dir, String rawValue) throws IOException {
        final Path configFile = dir.resolve(PluginConfig.FILE_NAME);
        Files.writeString(configFile, "whitelist-file = \"" + rawValue + "\"\n", StandardCharsets.UTF_8);

        final List<String> loadProblems = new ArrayList<>();
        final PluginConfig config = PluginConfig.load(configFile, loadProblems::add);

        assertTrue(loadProblems.isEmpty(), "夹具本身不应产生配置问题：" + loadProblems);
        assertEquals(rawValue, config.whitelistFile(), "夹具没能把原值送进 PluginConfig");
        return config;
    }

    @Test
    @DisplayName("路径非法：回退到默认文件名，并报告「原值 + 异常原因 + 默认值名」")
    void fallsBackToDefaultFileNameWhenPathIsInvalid(@TempDir Path dataDirectory) throws IOException {
        // Windows 上带 '?' 的文件名是非法的（还有 < > : " | * 以及 CON / NUL 这类保留设备名）；
        // Linux 上它完全合法 —— 所以这条分支只能靠注入 parser 来覆盖，与 DataFolder.RealNameReader 同理。
        final String configured = "bad?name.conf";
        final String reason = "测试用的原因";
        final PluginConfig config = configWithWhitelistFile(dataDirectory, configured);
        final List<String> problems = new ArrayList<>();

        final Path result = MikuHAProxy.resolveWhitelistFile(config, dataDirectory, problems,
                value -> {
                    throw new InvalidPathException(value, reason);
                });

        final String fallback = PluginConfig.defaults().whitelistFile();
        assertEquals(dataDirectory.resolve(fallback), result, "必须回退到「数据目录下的默认文件名」");

        // 正向断言：这条分支的全部价值就在于把问题说清楚，所以三者缺一不可
        assertEquals(1, problems.size(), problems.toString());
        final String problem = problems.get(0);
        assertTrue(problem.contains(configured), "报告里必须带上用户自己写的原值：" + problem);
        assertTrue(problem.contains(reason), "报告里必须带上异常给出的原因：" + problem);
        assertTrue(problem.contains(fallback), "报告里必须说明改用了哪个默认值：" + problem);
    }

    @Test
    @DisplayName("相对路径（出厂默认值）：相对数据目录解析，且不报任何配置问题")
    void relativePathIsResolvedAgainstDataDirectory(@TempDir Path dataDirectory) throws IOException {
        final String configured = "whitelist.conf";
        final PluginConfig config = configWithWhitelistFile(dataDirectory, configured);
        final RecordingParser parser = new RecordingParser();
        final List<String> problems = new ArrayList<>();

        final Path result = MikuHAProxy.resolveWhitelistFile(config, dataDirectory, problems, parser);

        assertEquals(dataDirectory.resolve(configured), result,
                "相对路径必须锚到数据目录，否则插件读不到文件 ⇒ 拒绝所有代理连接");
        assertTrue(result.isAbsolute(), "锚定之后得到的必须是绝对路径：" + result);
        assertTrue(result.startsWith(dataDirectory), "结果必须在数据目录之下：" + result);
        assertTrue(problems.isEmpty(), "合法写法不应产生任何配置问题：" + problems);
        assertEquals(List.of(configured), parser.seen, "解析的必须是配置里写的原值");
    }

    @Test
    @DisplayName("子目录形式的相对路径：完整保留目录层级，仍相对数据目录解析")
    void relativePathWithSubDirectoryKeepsItsShape(@TempDir Path dataDirectory) throws IOException {
        final String configured = "sub/my.txt";
        final PluginConfig config = configWithWhitelistFile(dataDirectory, configured);
        final RecordingParser parser = new RecordingParser();
        final List<String> problems = new ArrayList<>();

        final Path result = MikuHAProxy.resolveWhitelistFile(config, dataDirectory, problems, parser);

        assertEquals(dataDirectory.resolve("sub").resolve("my.txt"), result);
        assertEquals(dataDirectory.resolve("sub"), result.getParent(), "子目录这一层必须原样保留");
        assertTrue(problems.isEmpty(), "合法写法不应产生任何配置问题：" + problems);
        assertEquals(List.of(configured), parser.seen, "解析的必须是配置里写的原值");
    }

    @Test
    @DisplayName("绝对路径：按用户指定的位置原样使用，不再与数据目录拼接")
    void absolutePathIsUsedVerbatim(@TempDir Path dataDirectory, @TempDir Path elsewhere) throws IOException {
        final Path configured = elsewhere.resolve("external-whitelist.conf");
        assertTrue(configured.isAbsolute(), "@TempDir 给的是绝对路径，这条用例依赖这一点");
        final PluginConfig config = configWithWhitelistFile(dataDirectory, configured.toString());
        final RecordingParser parser = new RecordingParser();
        final List<String> problems = new ArrayList<>();

        final Path result = MikuHAProxy.resolveWhitelistFile(config, dataDirectory, problems, parser);

        assertEquals(configured, result, "绝对路径必须原样返回");
        assertFalse(result.startsWith(dataDirectory), "不得再被挂到数据目录下面：" + result);
        assertEquals(elsewhere, result.getParent(), "父目录必须仍是用户指定的那个：" + result);
        assertTrue(problems.isEmpty(), "合法写法不应产生任何配置问题：" + problems);
        assertEquals(List.of(configured.toString()), parser.seen, "解析的必须是配置里写的原值");
    }
}
