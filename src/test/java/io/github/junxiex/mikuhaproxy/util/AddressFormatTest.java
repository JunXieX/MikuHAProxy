package io.github.junxiex.mikuhaproxy.util;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.net.UnknownHostException;

import static org.junit.jupiter.api.Assertions.assertEquals;

class AddressFormatTest {

    /** 把 8 组 16 位数值拼成 16 字节的 IPv6 地址。 */
    private static byte[] ipv6(int... groups) {
        final byte[] raw = new byte[16];
        for (int i = 0; i < 8; i++) {
            raw[i * 2] = (byte) (groups[i] >> 8);
            raw[i * 2 + 1] = (byte) groups[i];
        }
        return raw;
    }

    @Test
    @DisplayName("IPv4 直接点分十进制输出")
    void formatsIpv4() {
        assertEquals("127.0.0.1", AddressFormat.format(new byte[]{127, 0, 0, 1}));
        assertEquals("255.255.255.255",
                AddressFormat.format(new byte[]{(byte) 255, (byte) 255, (byte) 255, (byte) 255}));
        assertEquals("0.0.0.0", AddressFormat.format(new byte[4]));
    }

    @Test
    @DisplayName("IPv6 按 RFC 5952 压缩最长的连续 0 段")
    void compressesLongestZeroRun() {
        assertEquals("2001:db8::1", AddressFormat.format(ipv6(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)));
        assertEquals("fd00::1", AddressFormat.format(ipv6(0xfd00, 0, 0, 0, 0, 0, 0, 1)));
        assertEquals("::1", AddressFormat.format(ipv6(0, 0, 0, 0, 0, 0, 0, 1)));
        assertEquals("::", AddressFormat.format(ipv6(0, 0, 0, 0, 0, 0, 0, 0)));
    }

    @Test
    @DisplayName("只有一段 0 时不压缩（RFC 5952 要求至少两段）")
    void singleZeroGroupIsNotCompressed() {
        assertEquals("1:2:3:4:5:6:0:7", AddressFormat.format(ipv6(1, 2, 3, 4, 5, 6, 0, 7)));
    }

    @Test
    @DisplayName("多段 0 时压缩最长的那一段")
    void picksLongestRun() {
        assertEquals("1:0:0:2::3", AddressFormat.format(ipv6(1, 0, 0, 2, 0, 0, 0, 3)));
    }

    @Test
    @DisplayName("十六进制输出为小写且不做前导零填充")
    void usesLowercaseHexWithoutPadding() {
        assertEquals("2001:db8:0:abcd::1", AddressFormat.format(ipv6(0x2001, 0x0db8, 0, 0xabcd, 0, 0, 0, 1)));
    }

    @Test
    @DisplayName("null 与未知长度都给出安全占位，不抛异常")
    void handlesNullAndUnknownLength() {
        assertEquals("<未知地址>", AddressFormat.format((InetAddress) null));
        assertEquals("?", AddressFormat.format((byte[]) null));
        assertEquals("?", AddressFormat.format(new byte[]{1, 2, 3}));
    }

    @Test
    @DisplayName("InetAddress 重载走同一套格式化（Java 原生会输出未压缩的 8 段形式）")
    void formatsInetAddress() throws UnknownHostException {
        assertEquals("0:0:0:0:0:0:0:1", InetAddress.getByName("::1").getHostAddress());
        assertEquals("::1", AddressFormat.format(InetAddress.getByName("::1")));
        assertEquals("127.0.0.1", AddressFormat.format(InetAddress.getByName("127.0.0.1")));
    }
}
