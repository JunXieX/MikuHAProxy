package io.github.junxiex.mikuhaproxy.config;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.net.UnknownHostException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CidrBlockTest {

    private static byte[] bytes(String address) throws UnknownHostException {
        return InetAddress.getByName(address).getAddress();
    }

    /** 构造一个 16 字节的 IPv4-mapped IPv6 地址字节（{@code InetAddress.getByName} 会把它归一化成 IPv4）。 */
    private static byte[] mappedIpv4(int a, int b, int c, int d) {
        final byte[] raw = new byte[16];
        raw[10] = (byte) 0xFF;
        raw[11] = (byte) 0xFF;
        raw[12] = (byte) a;
        raw[13] = (byte) b;
        raw[14] = (byte) c;
        raw[15] = (byte) d;
        return raw;
    }

    @Test
    @DisplayName("网络地址会按前缀做掩码，主机位被清零")
    void masksHostBits() throws Exception {
        CidrBlock block = CidrBlock.of(InetAddress.getByName("192.168.1.77"), 24);
        // toString 输出的正是「掩码后的网络地址/前缀」，用它断言主机位被清零
        assertEquals("192.168.1.0/24", block.toString());
        assertEquals(4, block.byteLength());
    }

    @Test
    @DisplayName("整字节前缀匹配")
    void matchesOnWholeByteBoundary() throws Exception {
        CidrBlock block = CidrBlock.of(InetAddress.getByName("10.0.0.0"), 8);
        assertTrue(block.contains(bytes("10.255.255.255")));
        assertTrue(block.contains(bytes("10.0.0.1")));
        assertFalse(block.contains(bytes("11.0.0.1")));
        assertFalse(block.contains(bytes("9.255.255.255")));
    }

    @Test
    @DisplayName("非整字节前缀只比较高位，192.168.0.0/20 覆盖 .0.0 ~ .15.255")
    void matchesOnPartialByteBoundary() throws Exception {
        CidrBlock block = CidrBlock.of(InetAddress.getByName("192.168.0.0"), 20);
        assertTrue(block.contains(bytes("192.168.0.1")));
        assertTrue(block.contains(bytes("192.168.15.255")));
        assertFalse(block.contains(bytes("192.168.16.0")));
        assertFalse(block.contains(bytes("192.167.255.255")));
    }

    @Test
    @DisplayName("/0 匹配同一地址族的所有地址")
    void zeroPrefixMatchesEverything() throws Exception {
        CidrBlock block = CidrBlock.of(InetAddress.getByName("0.0.0.0"), 0);
        assertTrue(block.contains(bytes("8.8.8.8")));
        assertTrue(block.contains(bytes("255.255.255.255")));
    }

    @Test
    @DisplayName("/32 与 /128 只匹配自己")
    void singleHostMatchesOnlyItself() throws Exception {
        CidrBlock v4 = CidrBlock.ofHost(InetAddress.getByName("127.0.0.1"));
        assertEquals("127.0.0.1/32", v4.toString());
        assertTrue(v4.contains(bytes("127.0.0.1")));
        assertFalse(v4.contains(bytes("127.0.0.2")));

        CidrBlock v6 = CidrBlock.ofHost(InetAddress.getByName("::1"));
        assertEquals("::1/128", v6.toString());
        assertTrue(v6.contains(bytes("::1")));
        assertFalse(v6.contains(bytes("::2")));
    }

    @Test
    @DisplayName("地址族不同时直接不匹配，不做隐式转换")
    void differentFamilyNeverMatches() throws Exception {
        CidrBlock v4 = CidrBlock.of(InetAddress.getByName("0.0.0.0"), 0);
        assertFalse(v4.contains(bytes("::1")));
        assertFalse(v4.contains(mappedIpv4(127, 0, 0, 1)));

        CidrBlock v6 = CidrBlock.of(InetAddress.getByName("::"), 0);
        assertFalse(v6.contains(bytes("127.0.0.1")));
    }

    @Test
    @DisplayName("带偏移量比较：可以直接拿 ::ffff:a.b.c.d 的后 4 字节去撞 IPv4 规则")
    void comparesWithOffset() throws Exception {
        CidrBlock block = CidrBlock.of(InetAddress.getByName("127.0.0.0"), 8);
        assertTrue(block.contains(mappedIpv4(127, 0, 0, 1), 12));
        assertFalse(block.contains(mappedIpv4(10, 0, 0, 1), 12));
        // 同族的 4 字节地址也可以带偏移（偏移 0 时等价于 contains(byte[])）
        assertTrue(block.contains(bytes("127.0.0.1"), 0));
        // 偏移越界时必须安全返回 false，而不是抛数组越界
        assertFalse(block.contains(mappedIpv4(127, 0, 0, 1), 14));
        assertFalse(block.contains(mappedIpv4(127, 0, 0, 1), -1));
        assertFalse(block.contains(null, 0));
    }

    @Test
    @DisplayName("前缀长度超出地址族范围时抛 IllegalArgumentException")
    void rejectsInvalidPrefix() throws Exception {
        InetAddress v4 = InetAddress.getByName("10.0.0.0");
        InetAddress v6 = InetAddress.getByName("::1");
        assertThrows(IllegalArgumentException.class, () -> CidrBlock.of(v4, 33));
        assertThrows(IllegalArgumentException.class, () -> CidrBlock.of(v4, -1));
        assertThrows(IllegalArgumentException.class, () -> CidrBlock.of(v6, 129));
        assertEquals("10.0.0.0/32", CidrBlock.of(v4, 32).toString());
        assertEquals("::1/128", CidrBlock.of(v6, 128).toString());
    }

    @Test
    @DisplayName("equals/hashCode 基于网络地址与前缀，随对象内容而非常量")
    void equalityIsContentBased() throws Exception {
        CidrBlock a = CidrBlock.of(InetAddress.getByName("10.0.0.5"), 8);
        CidrBlock b = CidrBlock.of(InetAddress.getByName("10.9.9.9"), 8);
        CidrBlock c = CidrBlock.of(InetAddress.getByName("10.9.9.9"), 16);
        assertEquals(a, b);
        assertEquals(a.hashCode(), b.hashCode());
        assertFalse(a.equals(c));
    }

    @Test
    @DisplayName("toString 输出 掩码后的网络地址/前缀")
    void toStringIsNetworkSlashPrefix() throws Exception {
        assertEquals("10.0.0.0/8", CidrBlock.of(InetAddress.getByName("10.1.2.3"), 8).toString());
        assertEquals("::/0", CidrBlock.of(InetAddress.getByName("::1"), 0).toString());
        assertEquals("::1/128", CidrBlock.ofHost(InetAddress.getByName("::1")).toString());
    }
}
