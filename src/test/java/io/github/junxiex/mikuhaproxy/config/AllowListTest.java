package io.github.junxiex.mikuhaproxy.config;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AllowListTest {

    private static InetAddress address(String text) throws UnknownHostException {
        return InetAddress.getByName(text);
    }

    /**
     * 构造一个真正的 16 字节 {@link Inet6Address}，内容为 IPv4-mapped 形式。
     *
     * <p>{@code InetAddress.getByName("::ffff:127.0.0.1")} 和 {@code InetAddress.getByAddress(...)}
     * 都会被 JDK 归一化成 Inet4Address，只有 {@code Inet6Address.getByAddress(...)} 会保留 16 字节，
     * 所以用它来覆盖那条兜底分支。</p>
     */
    private static InetAddress mappedIpv4Address(int a, int b, int c, int d) throws UnknownHostException {
        final byte[] raw = new byte[16];
        raw[10] = (byte) 0xFF;
        raw[11] = (byte) 0xFF;
        raw[12] = (byte) a;
        raw[13] = (byte) b;
        raw[14] = (byte) c;
        raw[15] = (byte) d;
        return Inet6Address.getByAddress(null, raw, 0);
    }

    private static AllowList listOf(String... entries) {
        final List<CidrBlock> rules = new ArrayList<>();
        for (String text : entries) {
            final List<CidrBlock> parsed = AllowList.parseEntry(text, message -> {
                throw new AssertionError("不应出现解析问题：" + message);
            });
            rules.addAll(parsed);
        }
        return AllowList.of(rules);
    }

    @Test
    @DisplayName("单机 IPv4 只放行它自己")
    void allowsSingleIpv4Host() throws Exception {
        final AllowList allow = listOf("127.0.0.1");
        assertTrue(allow.isAllowed(address("127.0.0.1")));
        assertFalse(allow.isAllowed(address("127.0.0.2")));
        assertEquals(1, allow.ipv4Count());
        assertEquals(0, allow.ipv6Count());
    }

    @Test
    @DisplayName("IPv4 网段按 CIDR 放行")
    void allowsIpv4Range() throws Exception {
        final AllowList allow = listOf("127.0.0.0/8", "10.20.0.0/16");
        assertTrue(allow.isAllowed(address("127.0.0.1")));
        assertTrue(allow.isAllowed(address("127.255.255.255")));
        assertTrue(allow.isAllowed(address("10.20.30.40")));
        assertFalse(allow.isAllowed(address("10.21.0.1")));
        assertFalse(allow.isAllowed(address("8.8.8.8")));
    }

    @Test
    @DisplayName("IPv6 单机与网段都在 IPv6 规则集里匹配")
    void allowsIpv6() throws Exception {
        final AllowList allow = listOf("::1", "fd00::/8");
        assertTrue(allow.isAllowed(address("::1")));
        assertTrue(allow.isAllowed(address("fd00::abcd")));
        assertFalse(allow.isAllowed(address("fe80::1")));
        assertEquals(0, allow.ipv4Count());
        assertEquals(2, allow.ipv6Count());
    }

    @Test
    @DisplayName("IPv4-mapped IPv6 也能命中 IPv4 规则（兜底分支）")
    void ipv4MappedAddressMatchesIpv4Rule() throws Exception {
        final AllowList allow = listOf("127.0.0.0/8");
        assertTrue(allow.isAllowed(mappedIpv4Address(127, 0, 0, 1)));
        assertFalse(allow.isAllowed(mappedIpv4Address(10, 0, 0, 1)));
    }

    @Test
    @DisplayName("空白名单拒绝一切；拿不到地址时同样拒绝（失败即关闭）")
    void emptyListDeniesEverything() throws Exception {
        assertEquals(0, AllowList.DENY_ALL.size());
        assertFalse(AllowList.DENY_ALL.isAllowed(address("127.0.0.1")));
        assertFalse(AllowList.DENY_ALL.isAllowed(null));
        assertFalse(AllowList.DENY_ALL.isAllowed(mappedIpv4Address(127, 0, 0, 1)));
    }

    @Test
    @DisplayName("allowAll 放行一切，包括拿不到地址的情况")
    void allowAllAcceptsEverything() throws Exception {
        assertTrue(AllowList.ALLOW_ALL.isAllowed(address("8.8.8.8")));
        assertTrue(AllowList.ALLOW_ALL.isAllowed(null));
    }

    @Test
    @DisplayName("读取文件：识别整行注释、行尾注释与空行")
    void loadsFileIgnoringComments(@TempDir Path dir) throws IOException {
        final Path file = dir.resolve("whitelist.conf");
        Files.writeString(file, """
                # 注释行
                127.0.0.0/8          # 行尾注释

                ::1/128
                """, StandardCharsets.UTF_8);

        final List<String> problems = new ArrayList<>();
        final AllowList allow = AllowList.load(file, problems::add);

        assertTrue(problems.isEmpty(), "不应有问题：" + problems);
        assertEquals(2, allow.size());
        assertTrue(allow.isAllowed(address("127.0.0.1")));
        assertTrue(allow.isAllowed(address("::1")));
    }

    @Test
    @DisplayName("非法行只跳过自己，并报出准确行号与原因")
    void skipsBadLinesWithLineNumbers(@TempDir Path dir) throws IOException {
        final Path file = dir.resolve("whitelist.conf");
        Files.writeString(file, """
                127.0.0.1
                not_an_address
                example.com/24
                10.0.0.0/99
                :bad::address
                ::1
                """, StandardCharsets.UTF_8);

        final List<String> problems = new ArrayList<>();
        final AllowList allow = AllowList.load(file, problems::add);

        assertEquals(2, allow.size(), "只有第 1 行与最后一行应当生效：" + problems);
        assertTrue(allow.isAllowed(address("127.0.0.1")));
        assertTrue(allow.isAllowed(address("::1")));

        assertEquals(4, problems.size(), "四行非法内容各自报告一次：" + problems);
        assertTrue(problems.get(0).contains("第 2 行"), problems.get(0));
        assertTrue(problems.get(1).contains("第 3 行"), problems.get(1));
        assertTrue(problems.get(1).contains("不支持域名"), problems.get(1));
        assertTrue(problems.get(2).contains("第 4 行"), problems.get(2));
        assertTrue(problems.get(2).contains("前缀"), problems.get(2));
        assertTrue(problems.get(3).contains("第 5 行"), problems.get(3));
        assertTrue(problems.get(3).contains("无法解析"), problems.get(3));
    }

    @Test
    @DisplayName("前缀长度与地址族不匹配时给出可执行的提示")
    void reportsPrefixMismatch() {
        final List<String> problems = new ArrayList<>();
        assertNull(AllowList.parseEntry("::ffff:127.0.0.1/128", problems::add));
        assertEquals(1, problems.size());
        assertTrue(problems.get(0).contains("IPv4-mapped"), problems.get(0));

        problems.clear();
        assertNull(AllowList.parseEntry("10.0.0.0/33", problems::add));
        assertEquals(1, problems.size());
        assertTrue(problems.get(0).contains("33"), problems.get(0));

        problems.clear();
        assertNull(AllowList.parseEntry("10.0.0.0/abc", problems::add));
        assertEquals(1, problems.size());
        assertTrue(problems.get(0).contains("不是整数"), problems.get(0));

        problems.clear();
        assertNull(AllowList.parseEntry("/24", problems::add));
        assertEquals(1, problems.size());
        assertTrue(problems.get(0).contains("缺少地址"), problems.get(0));
    }

    @Test
    @DisplayName("文件不存在时按「拒绝一切」处理，并报告问题")
    void missingFileDeniesAll(@TempDir Path dir) throws IOException {
        final List<String> problems = new ArrayList<>();
        final AllowList allow = AllowList.load(dir.resolve("nope.conf"), problems::add);
        assertEquals(0, allow.size());
        assertEquals(1, problems.size());
    }

    @Test
    @DisplayName("字面量判定：只有点分四段或含冒号的写法才当地址，其余当域名")
    void recognisesAddressLiterals() {
        assertTrue(AllowList.isAddressLiteral("127.0.0.1"));
        assertTrue(AllowList.isAddressLiteral("::1"));
        assertTrue(AllowList.isAddressLiteral("2001:DB8::1"));
        assertTrue(AllowList.isAddressLiteral("::ffff:127.0.0.1"));

        assertFalse(AllowList.isAddressLiteral("proxy.example.com"));
        assertFalse(AllowList.isAddressLiteral("localhost"));
        assertFalse(AllowList.isAddressLiteral("abc.de"));
        assertFalse(AllowList.isAddressLiteral("1.2.3"));
        assertFalse(AllowList.isAddressLiteral("1.2.3.4.5"));
        assertFalse(AllowList.isAddressLiteral(""));
    }

    @Test
    @DisplayName("域名会解析成地址（localhost 一定可解析）")
    void resolvesHostname() {
        final List<String> problems = new ArrayList<>();
        final List<CidrBlock> parsed = AllowList.parseEntry("localhost", problems::add);
        assertTrue(problems.isEmpty(), "localhost 应当可以解析：" + problems);
        assertNotNull(parsed);
        assertFalse(parsed.isEmpty(), "localhost 至少应解析出一条规则");
    }

    @Test
    @DisplayName("describeRules 输出条目文本，allowAll 时给出明确标记")
    void describesRules() {
        assertEquals(List.of("127.0.0.0/8"), listOf("127.0.0.0/8").describeRules());
        assertEquals(List.of("<全部放行>"), AllowList.ALLOW_ALL.describeRules());
        assertTrue(AllowList.DENY_ALL.describeRules().isEmpty());
    }
}
