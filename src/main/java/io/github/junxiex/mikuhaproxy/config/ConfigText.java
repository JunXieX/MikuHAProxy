package io.github.junxiex.mikuhaproxy.config;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * 配置文件（{@code config.toml} / {@code whitelist.conf}）的读取。
 *
 * <p><b>为什么不用 {@link Files#newBufferedReader(Path, java.nio.charset.Charset)}</b>：它把非法字节
 * 当成致命错误（{@code CodingErrorAction.REPORT}）。出厂模板带中文注释，而中文 Windows 上的记事本
 * 默认把文件存成 GBK / ANSI——用户只是打开白名单改了一行再保存，整份文件就会在读取时抛
 * {@code MalformedInputException}，于是插件报「读取白名单失败」、拒绝一切代理连接。这既违反
 * 「任何写法错误都不会让插件加载失败」的承诺，也让用户完全看不出问题出在文件编码上。</p>
 *
 * <p>这里改成<b>替换非法字节</b>：坏字节变成 {@code U+FFFD}，其余内容照常参与解析；调用方再用
 * {@link #hasDecodeErrors(String)} 按行报一次「文件不是 UTF-8」的提示。纯 ASCII 内容（最常见的情况）
 * 在 UTF-8 与 GBK 下字节完全一致，行为与严格解码没有任何区别。</p>
 */
final class ConfigText {

    private ConfigText() {
        throw new AssertionError();
    }

    /** 以「UTF-8 + 非法字节替换」的方式打开文件；行号语义与严格解码完全一致。 */
    static BufferedReader reader(Path file) throws IOException {
        final CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPLACE)
                .onUnmappableCharacter(CodingErrorAction.REPLACE);
        return new BufferedReader(new InputStreamReader(Files.newInputStream(file), decoder));
    }

    /** 该行是否含有解码失败留下的替换字符（{@code U+FFFD}）。 */
    static boolean hasDecodeErrors(String line) {
        return line.indexOf('\uFFFD') >= 0;
    }
}
