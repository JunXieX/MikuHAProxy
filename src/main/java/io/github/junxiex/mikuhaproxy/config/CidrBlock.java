package io.github.junxiex.mikuhaproxy.config;

import io.github.junxiex.mikuhaproxy.util.AddressFormat;

import java.net.InetAddress;
import java.util.Arrays;

/**
 * 一条 CIDR 规则（{@code 10.0.0.0/8}、{@code ::1/128} 等）。
 *
 * <p>匹配完全在 {@code byte[]} 上做：不构造 {@code BigInteger}、不产生任何临时对象。
 * 白名单有 N 条时，每个新连接的匹配开销就是 N 次纯字节比对。</p>
 */
public final class CidrBlock {

    /** 掩码之后的网络地址，长度为 4（IPv4）或 16（IPv6）。 */
    private final byte[] network;
    private final int prefixBits;

    private CidrBlock(byte[] network, int prefixBits) {
        this.network = network;
        this.prefixBits = prefixBits;
    }

    /**
     * 构造一条 CIDR 规则。
     *
     * @param address    网络地址
     * @param prefixBits 前缀长度；IPv4 取 0~32，IPv6 取 0~128
     * @throws IllegalArgumentException 前缀长度与地址族不匹配时抛出
     */
    public static CidrBlock of(InetAddress address, int prefixBits) {
        final byte[] raw = address.getAddress();
        final int maxBits = raw.length * Byte.SIZE;
        if (prefixBits < 0 || prefixBits > maxBits) {
            throw new IllegalArgumentException("前缀长度 " + prefixBits + " 非法，该地址族允许 0~" + maxBits);
        }
        return new CidrBlock(mask(raw, prefixBits), prefixBits);
    }

    /** 构造一条「精确到单机」的规则（等价于 /32 或 /128）。 */
    public static CidrBlock ofHost(InetAddress address) {
        final byte[] raw = address.getAddress();
        return new CidrBlock(raw.clone(), raw.length * Byte.SIZE);
    }

    private static byte[] mask(byte[] raw, int prefixBits) {
        final byte[] masked = raw.clone();
        for (int i = 0; i < masked.length; i++) {
            final int bitStart = i * 8;
            if (bitStart >= prefixBits) {
                masked[i] = 0;
            } else if (bitStart + 8 > prefixBits) {
                masked[i] = (byte) (masked[i] & (0xFF << (8 - (prefixBits - bitStart))));
            }
        }
        return masked;
    }

    /**
     * 判断 {@code raw} 在 {@code prefixBits} 之后是否还有置位的主机位。
     *
     * <p>供白名单解析在「用户写了 {@code 192.168.1.10/8}」这类情况下给出告警：这种写法会被
     * {@link #mask(byte[], int) 静默规范化} 成 {@code 192.0.0.0/8}，匹配范围与写作者的本意
     * 几乎必然不同——但按语法它完全合法，不该拒绝，只该提醒。</p>
     */
    static boolean hostBitsSet(byte[] raw, int prefixBits) {
        for (int i = 0; i < raw.length; i++) {
            final int bitStart = i * 8;
            if (bitStart >= prefixBits) {
                if (raw[i] != 0) {
                    return true;
                }
            } else if (bitStart + 8 > prefixBits) {
                final int networkMask = (0xFF << (8 - (prefixBits - bitStart))) & 0xFF;
                if ((raw[i] & ~networkMask & 0xFF) != 0) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * 判断候选地址是否落在本规则内（同族、无偏移的常规比较）。
     *
     * <p>要求候选地址与本规则<b>同族</b>（4 字节对 IPv4 规则、16 字节对 IPv6 规则）；
     * 长度不一致直接不匹配，不做任何隐式转换。需要跨族取后几个字节比较时用
     * {@link #contains(byte[], int)}。</p>
     *
     * @param candidate 原始地址字节
     */
    public boolean contains(byte[] candidate) {
        return candidate != null && candidate.length == network.length && contains(candidate, 0);
    }

    /**
     * 判断候选地址从 {@code offset} 开始的 {@link #byteLength()} 个字节是否落在本规则内。
     *
     * <p>要求候选地址从 {@code offset} 起至少有 {@link #byteLength()} 个字节，否则直接不匹配，
     * 不做任何隐式转换。</p>
     *
     * <p>{@code offset} 的典型用法是 IPv4-mapped IPv6（{@code ::ffff:a.b.c.d}）：直接拿后 4 个字节
     * 与 IPv4 规则比较，不需要把地址重新包装成 {@code InetAddress}，也不需要复制数组。</p>
     *
     * @param offset 起始偏移；越界时安全返回 {@code false}，不抛异常
     */
    public boolean contains(byte[] candidate, int offset) {
        final int length = network.length;
        if (candidate == null || offset < 0 || candidate.length - offset < length) {
            return false;
        }
        final int wholeBytes = prefixBits >>> 3;
        for (int i = 0; i < wholeBytes; i++) {
            if (candidate[offset + i] != network[i]) {
                return false;
            }
        }
        final int remainingBits = prefixBits & 7;
        if (remainingBits != 0) {
            final int mask = (0xFF << (8 - remainingBits)) & 0xFF;
            if ((candidate[offset + wholeBytes] & mask) != (network[wholeBytes] & mask)) {
                return false;
            }
        }
        return true;
    }

    /** 地址长度：4 表示 IPv4，16 表示 IPv6。 */
    public int byteLength() {
        return network.length;
    }

    @Override
    public String toString() {
        return AddressFormat.format(network) + "/" + prefixBits;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof CidrBlock other)) {
            return false;
        }
        return prefixBits == other.prefixBits && Arrays.equals(network, other.network);
    }

    @Override
    public int hashCode() {
        return 31 * Arrays.hashCode(network) + prefixBits;
    }
}
