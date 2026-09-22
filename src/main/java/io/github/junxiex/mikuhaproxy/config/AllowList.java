package io.github.junxiex.mikuhaproxy.config;

import java.io.BufferedReader;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.function.Consumer;

/**
 * 允许的代理来源白名单。
 *
 * <p>只放行「TCP 对端地址」在白名单内的连接。注意这里判断的<b>不是</b> PROXY 头里声明的客户端地址，
 * 而是真正发起 TCP 连接的那台机器的地址——后者无法伪造，是唯一有安全意义的判据。</p>
 *
 * <p>文件格式：每行一条，支持 IPv4 / IPv6 / CIDR / 域名，{@code #} 之后为注释，空行忽略。</p>
 */
public final class AllowList {

    /** 关闭白名单：放行一切代理来源（极度危险，仅调试用）。 */
    public static final AllowList ALLOW_ALL = new AllowList(true, List.of(), List.of());

    /** 空白名单：拒绝一切代理来源，只允许直连。 */
    public static final AllowList DENY_ALL = new AllowList(false, List.of(), List.of());

    private final boolean allowAll;
    private final List<CidrBlock> ipv4;
    private final List<CidrBlock> ipv6;

    private AllowList(boolean allowAll, List<CidrBlock> ipv4, List<CidrBlock> ipv6) {
        this.allowAll = allowAll;
        this.ipv4 = List.copyOf(ipv4);
        this.ipv6 = List.copyOf(ipv6);
    }

    public static AllowList of(List<CidrBlock> rules) {
        final List<CidrBlock> v4 = new ArrayList<>(rules.size());
        final List<CidrBlock> v6 = new ArrayList<>(rules.size());
        for (CidrBlock rule : rules) {
            (rule.byteLength() == 4 ? v4 : v6).add(rule);
        }
        return new AllowList(false, v4, v6);
    }

    public int size() {
        return ipv4.size() + ipv6.size();
    }

    public int ipv4Count() {
        return ipv4.size();
    }

    public int ipv6Count() {
        return ipv6.size();
    }

    /**
     * 判断某个对端地址是否被允许。
     *
     * <p>{@code null}（拿不到对端地址）按<b>拒绝</b>处理：安全功能必须「失败即关闭」，
     * 拿不准的时候不能放行。</p>
     */
    public boolean isAllowed(InetAddress address) {
        if (allowAll) {
            return true;
        }
        if (address == null) {
            return false;
        }
        final byte[] raw = address.getAddress();
        if (raw.length == 4) {
            // 同族、无偏移：直接用「整段比较」的那条重载
            return matchesWhole(ipv4, raw);
        }
        if (isIpv4Mapped(raw)) {
            // 纯兜底分支：现实中一般拿不到这种形态——JDK 与 Netty 原生传输都会把
            // ::ffff:a.b.c.d 归一化成 Inet4Address（在 JDK 25 + Netty 4.2 上实测过）。
            // 但万一从别处拿到 16 字节的 IPv4-mapped 地址，按长度比较的 IPv4 规则就会失效，
            // 所以这里额外用后 4 个字节再比一次 IPv4 规则。
            return matchesFrom(ipv4, raw, 12) || matchesWhole(ipv6, raw);
        }
        return matchesWhole(ipv6, raw);
    }

    /** 同族、无偏移的匹配：候选地址与规则长度一致，整段比较。 */
    private static boolean matchesWhole(List<CidrBlock> rules, byte[] raw) {
        for (int i = 0, n = rules.size(); i < n; i++) {
            if (rules.get(i).contains(raw)) {
                return true;
            }
        }
        return false;
    }

    /** 带偏移的匹配：用于拿 IPv4-mapped IPv6 的后 4 个字节去撞 IPv4 规则。 */
    private static boolean matchesFrom(List<CidrBlock> rules, byte[] raw, int offset) {
        for (int i = 0, n = rules.size(); i < n; i++) {
            if (rules.get(i).contains(raw, offset)) {
                return true;
            }
        }
        return false;
    }

    /** 判断是否为 IPv4-mapped IPv6 地址（{@code ::ffff:a.b.c.d}）。 */
    static boolean isIpv4Mapped(byte[] address16) {
        if (address16.length != 16) {
            return false;
        }
        for (int i = 0; i < 10; i++) {
            if (address16[i] != 0) {
                return false;
            }
        }
        return address16[10] == (byte) 0xFF && address16[11] == (byte) 0xFF;
    }

    // ------------------------------------------------------------------
    // 解析
    // ------------------------------------------------------------------

    /**
     * 读取白名单文件。
     *
     * <p>单行写错<b>不会</b>让整个插件起不来：这里逐行容错，通过 {@code problem} 报告
     * 「第几行、什么内容、什么问题」，非法行跳过，其余照常生效。</p>
     *
     * <p><b>关于域名与 DNS</b>：域名条目会调用 {@link InetAddress#getAllByName(String)}，这是<b>阻塞</b>调用。
     * 本方法在插件启动线程以及 {@code /mikuproxy reload} 的命令线程上执行，所以如果白名单里写了域名、
     * 而 DNS 又不可达，这两处会各自卡住数秒（代理本身的连接处理不受影响）。只写 IP 字面量时，
     * {@code InetAddress.getByName} 不会真正发起查询，也就没有这个开销。</p>
     *
     * @param file    白名单文件
     * @param problem 问题报告出口（通常是日志）
     * @return 解析结果；文件不存在时返回 {@link #DENY_ALL}
     */
    public static AllowList load(Path file, Consumer<String> problem) throws IOException {
        if (!Files.isRegularFile(file)) {
            problem.accept("白名单文件不存在：" + file);
            return DENY_ALL;
        }

        final List<CidrBlock> rules = new ArrayList<>();
        try (BufferedReader reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
            String line;
            int lineNumber = 0;
            while ((line = reader.readLine()) != null) {
                lineNumber++;
                if (lineNumber == 1) {
                    line = stripBom(line);
                }
                final String entry = stripComment(line).trim();
                if (entry.isEmpty()) {
                    continue;
                }
                final int currentLine = lineNumber;
                final List<CidrBlock> parsed = parseEntry(entry,
                        message -> problem.accept("whitelist.conf 第 " + currentLine + " 行：" + message));
                if (parsed != null) {
                    rules.addAll(parsed);
                }
            }
        }
        return of(rules);
    }

    /**
     * 解析单条白名单条目。
     *
     * @return 解析出的规则；失败时通过 {@code problem} 报告并返回 {@code null}
     */
    static List<CidrBlock> parseEntry(String entry, Consumer<String> problem) {
        final int slash = entry.lastIndexOf('/');
        final String addressPart = slash < 0 ? entry : entry.substring(0, slash);

        if (slash < 0) {
            final List<InetAddress> resolved = resolve(entry, true, problem);
            if (resolved == null) {
                return null;
            }
            final List<CidrBlock> rules = new ArrayList<>(resolved.size());
            for (InetAddress address : resolved) {
                rules.add(CidrBlock.ofHost(address));
            }
            return rules;
        }

        if (addressPart.isEmpty()) {
            problem.accept("'/' 前面缺少地址：「" + entry + "」");
            return null;
        }
        if (!isAddressLiteral(addressPart)) {
            problem.accept("CIDR 的地址部分必须是 IP 字面量，不支持域名：「" + entry + "」");
            return null;
        }

        final int prefixBits;
        try {
            prefixBits = Integer.parseInt(entry.substring(slash + 1).trim());
        } catch (NumberFormatException e) {
            problem.accept("CIDR 前缀不是整数：「" + entry + "」");
            return null;
        }

        final List<InetAddress> resolved = resolve(addressPart, false, problem);
        if (resolved == null) {
            return null;
        }
        final List<CidrBlock> rules = new ArrayList<>(resolved.size());
        for (InetAddress address : resolved) {
            final int maxBits = address.getAddress().length * Byte.SIZE;
            if (prefixBits < 0 || prefixBits > maxBits) {
                if (addressPart.indexOf(':') >= 0 && address.getAddress().length == 4) {
                    problem.accept("「" + addressPart + "」是 IPv4-mapped 形式，请直接写成 IPv4（例如 127.0.0.1）再配前缀");
                } else {
                    problem.accept("CIDR 前缀 " + prefixBits + " 非法，该地址最多 " + maxBits + " 位：「" + entry + "」");
                }
                return null;
            }
            rules.add(CidrBlock.of(address, prefixBits));
        }
        return rules;
    }

    /**
     * 把一段文本解析成地址列表。
     *
     * @param allowDomain 是否允许域名（{@code true} 会走 DNS；{@code false} 只接受字面量）
     * @return 解析结果；失败返回 {@code null}
     */
    private static List<InetAddress> resolve(String text, boolean allowDomain, Consumer<String> problem) {
        try {
            if (!allowDomain || isAddressLiteral(text)) {
                // 字面量：getByName 不会触发 DNS（字符串本身就是地址）
                return List.of(InetAddress.getByName(text));
            }
            // 域名：启动时解析一次，A/AAAA 记录全部纳入
            final InetAddress[] addresses = InetAddress.getAllByName(text);
            if (addresses.length == 0) {
                problem.accept("域名没有解析到任何地址：「" + text + "」");
                return null;
            }
            return List.of(addresses);
        } catch (UnknownHostException e) {
            problem.accept("无法解析地址：「" + text + "」（" + e.getMessage() + "）");
            return null;
        }
    }

    /** 判断文本是否长得像 IP 字面量（含 {@code :} 视为 IPv6，否则必须是点分四段形式）。 */
    static boolean isAddressLiteral(String text) {
        if (text.isEmpty()) {
            return false;
        }
        if (text.indexOf(':') >= 0) {
            for (int i = 0; i < text.length(); i++) {
                final char c = text.charAt(i);
                final boolean hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
                if (!hex && c != ':' && c != '.') {
                    return false;
                }
            }
            return true;
        }
        final String[] parts = text.split("\\.", -1);
        if (parts.length != 4) {
            return false;
        }
        for (String part : parts) {
            if (part.isEmpty() || part.length() > 3) {
                return false;
            }
            for (int i = 0; i < part.length(); i++) {
                final char c = part.charAt(i);
                if (c < '0' || c > '9') {
                    return false;
                }
            }
        }
        return true;
    }

    private static String stripComment(String line) {
        final int index = line.indexOf('#');
        return index < 0 ? line : line.substring(0, index);
    }

    private static String stripBom(String line) {
        return !line.isEmpty() && line.charAt(0) == '\uFEFF' ? line.substring(1) : line;
    }

    @Override
    public String toString() {
        if (allowAll) {
            return "AllowList[全部放行]";
        }
        return "AllowList[IPv4=" + ipv4Count() + ", IPv6=" + ipv6Count() + "]";
    }

    /** 导出全部规则的字符串形式，供 {@code /mikuproxy status} 展示。 */
    public List<String> describeRules() {
        if (allowAll) {
            return Collections.singletonList("<全部放行>");
        }
        final List<String> out = new ArrayList<>(size());
        for (CidrBlock rule : ipv4) {
            out.add(rule.toString());
        }
        for (CidrBlock rule : ipv6) {
            out.add(rule.toString());
        }
        return out;
    }
}
