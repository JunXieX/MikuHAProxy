package io.github.junxiex.mikuhaproxy;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 版本号一致性。
 *
 * <p>{@code pom.xml} 与 {@link MikuHAProxy#VERSION} 必须一致：前者决定产出的 jar 名与
 * {@code velocity-plugin.json} 里的版本号，后者决定插件在日志与命令里对用户报出的版本。
 * 版本号历来是最容易漏改的地方（历史上就有四处需要手工同步），所以这里用一条测试守住最容易错、
 * 又最适合自动化的一项。</p>
 *
 * <p>{@code README.md} 里的版本行与安装步骤中的 jar 名同样是手工同步的，但那属于交付文档、
 * 每次改动都需要人工确认，因此刻意不纳入自动化断言（否则文档还没定稿就会先把构建弄红）。</p>
 *
 * <p>测试进程的工作目录就是模块根（surefire 的默认行为），所以可以直接读 {@code pom.xml}。</p>
 */
class VersionTest {

    private static final Pattern VERSION_TAG = Pattern.compile("<version>([^<]+)</version>");

    @Test
    @DisplayName("pom.xml 的版本号与 MikuHAProxy.VERSION 一致")
    void pomVersionMatchesConstant() throws IOException {
        final String pom = Files.readString(Path.of("pom.xml"), StandardCharsets.UTF_8);
        final Matcher matcher = VERSION_TAG.matcher(pom);
        assertTrue(matcher.find(), "pom.xml 里找不到 <version>");

        // 第一个 <version> 就是 project 自己的版本号：它排在所有插件与依赖的 <version> 之前
        assertEquals(MikuHAProxy.VERSION, matcher.group(1),
                "pom.xml 与 MikuHAProxy.VERSION 不一致，请同步修改");
    }

    @Test
    @DisplayName("版本号形态符合发版规则：x.y.z-Beta（测试版）或 x.y.0（正式版）")
    void versionShapeFollowsReleaseRule() {
        final Matcher matcher = Pattern.compile("^(\\d+)\\.(\\d+)\\.(\\d+)(-Beta)?$")
                .matcher(MikuHAProxy.VERSION);
        assertTrue(matcher.matches(),
                "版本号只能是 1.0.2-Beta 或 1.1.0 这种形态，实际是 " + MikuHAProxy.VERSION);

        if (matcher.group(4) == null) {
            // 正式版恒为 x.y.0：第二位 +1、第三位归零（1.4.2-Beta → 1.5.0）。
            // 少了这条，1.0.2 这种「看着像测试版直接转正」的号就会混进来，
            // 而它既不是测试版、又不是规则允许的正式版形态。
            assertEquals("0", matcher.group(3),
                    "正式版必须是 x.y.0 形态（第三位归零），实际是 " + MikuHAProxy.VERSION);
        }
    }
}
