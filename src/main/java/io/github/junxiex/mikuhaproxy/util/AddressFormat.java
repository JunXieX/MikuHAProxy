package io.github.junxiex.mikuhaproxy.util;

import java.net.InetAddress;

/**
 * 地址的文本格式化。
 *
 * <p>{@link InetAddress#getHostAddress()} 对 IPv6 会输出未压缩的 8 段形式
 * （例如 {@code ::1} 会变成 {@code 0:0:0:0:0:0:0:1}），读日志和列白名单时非常难认。
 * 这里按 RFC 5952 的推荐写法做一次压缩：小写十六进制 + 最长的一段连续 0 压缩成 {@code ::}。</p>
 */
public final class AddressFormat {

    private AddressFormat() {
        throw new AssertionError();
    }

    public static String format(InetAddress address) {
        if (address == null) {
            return "<未知地址>";
        }
        final byte[] raw = address.getAddress();
        return raw == null ? "<未知地址>" : format(raw);
    }

    public static String format(byte[] raw) {
        if (raw == null) {
            return "?";
        }
        return switch (raw.length) {
            case 4 -> ipv4(raw);
            case 16 -> ipv6(raw);
            default -> "?";
        };
    }

    private static String ipv4(byte[] raw) {
        final StringBuilder out = new StringBuilder(15);
        for (int i = 0; i < 4; i++) {
            if (i > 0) {
                out.append('.');
            }
            out.append(raw[i] & 0xFF);
        }
        return out.toString();
    }

    private static String ipv6(byte[] raw) {
        final int[] groups = new int[8];
        for (int i = 0; i < 8; i++) {
            groups[i] = ((raw[i * 2] & 0xFF) << 8) | (raw[i * 2 + 1] & 0xFF);
        }

        // 找出最长的一段连续 0（RFC 5952 要求至少 2 段才压缩，且取最靠前的一段）
        int bestStart = -1;
        int bestLength = 0;
        int runStart = -1;
        int runLength = 0;
        for (int i = 0; i < 8; i++) {
            if (groups[i] == 0) {
                if (runStart < 0) {
                    runStart = i;
                }
                runLength++;
                if (runLength > bestLength) {
                    bestLength = runLength;
                    bestStart = runStart;
                }
            } else {
                runStart = -1;
                runLength = 0;
            }
        }
        if (bestLength < 2) {
            bestStart = -1;
        }

        final StringBuilder out = new StringBuilder(39);
        for (int i = 0; i < 8; i++) {
            if (i == bestStart) {
                out.append("::");
                i += bestLength - 1;
                continue;
            }
            if (out.length() > 0 && out.charAt(out.length() - 1) != ':') {
                out.append(':');
            }
            out.append(Integer.toHexString(groups[i]));
        }
        return out.toString();
    }
}
