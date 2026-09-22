package io.github.junxiex.mikuhaproxy.net;

import io.github.junxiex.mikuhaproxy.DetectorContext;
import io.github.junxiex.mikuhaproxy.config.AllowList;
import io.github.junxiex.mikuhaproxy.config.PluginConfig;
import io.github.junxiex.mikuhaproxy.util.Counters;
import io.github.junxiex.mikuhaproxy.util.LogThrottle;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.ProtocolDetectionResult;
import io.netty.handler.codec.ProtocolDetectionState;
import io.netty.handler.codec.haproxy.HAProxyMessageDecoder;
import io.netty.handler.codec.haproxy.HAProxyProtocolVersion;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ProxyProtocolDetectorTest {

    /** PROXY protocol v2 的 12 字节二进制签名。 */
    private static final byte[] V2_SIGNATURE = {
            0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A};

    /** 一个真实的 Minecraft 握手开头：包长 0x10、包 ID 0x00、协议号 0x47、主机名 localhost… */
    private static final byte[] HANDSHAKE = {
            0x10, 0x00, 0x47, 0x09, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't', 0x63, (byte) 0xDD, 0x01};

    private static ByteBuf buffer(int... bytes) {
        final byte[] raw = new byte[bytes.length];
        for (int i = 0; i < bytes.length; i++) {
            raw[i] = (byte) bytes[i];
        }
        return Unpooled.wrappedBuffer(raw);
    }

    private static ByteBuf buffer(byte[] raw) {
        return Unpooled.wrappedBuffer(raw.clone());
    }

    /** 直连路径不会写日志；拒绝/异常路径会，所以这里给一个真实的日志器（无 provider 时是空实现）。 */
    private static DetectorContext context(AllowList allowList) {
        return new DetectorContext(allowList, PluginConfig.defaults(), new Counters(), new LogThrottle(60, 256),
                LoggerFactory.getLogger(ProxyProtocolDetectorTest.class));
    }

    /** 按真实管道里的名字（{@value ProxyProtocolDetector#HANDLER_NAME}）挂上探测器。 */
    private static EmbeddedChannel channelWith(DetectorContext context) {
        final EmbeddedChannel channel = new EmbeddedChannel();
        channel.pipeline().addLast(ProxyProtocolDetector.HANDLER_NAME, new ProxyProtocolDetector(context));
        return channel;
    }

    @Test
    @DisplayName("直连：首字节既不是 0x0D 也不是 'P'，只需 1 个字节即可定案")
    void directConnectionDecidedFromOneByte() {
        assertEquals(ProxyProtocolDetector.Probe.DIRECT, ProxyProtocolDetector.probe(buffer(HANDSHAKE[0])));
        assertEquals(ProxyProtocolDetector.Probe.DIRECT, ProxyProtocolDetector.probe(buffer(HANDSHAKE)));
    }

    @Test
    @DisplayName("直连：握手包长恰为 0x0D（与 v2 首字节相同）时，第 2 个字节即可排除")
    void directConnectionWithLengthByteMatchingV2Signature() {
        final byte[] handshake13 = {0x0D, 0x00, 0x47, 0x09, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't'};
        assertEquals(ProxyProtocolDetector.Probe.INCOMPLETE,
                ProxyProtocolDetector.probe(buffer(0x0D)), "只有 1 个字节时确实还看不出来");
        assertEquals(ProxyProtocolDetector.Probe.DIRECT,
                ProxyProtocolDetector.probe(buffer(0x0D, 0x00)), "第 2 个字节就可以排除 v2");
        // 若非要等凑满 12 字节才判定，这种「首字节刚好撞上 0x0D」的握手包就要白等 10 个字节；
        // 本实现 2 个字节就结束了。
        assertTrue(handshake13.length >= 12);
        assertEquals(ProxyProtocolDetector.Probe.DIRECT, ProxyProtocolDetector.probe(buffer(handshake13)));
    }

    @Test
    @DisplayName("直连：握手包长恰为 'P'（0x50）时，第 2 个字节即可排除")
    void directConnectionWithLengthByteMatchingV1Prefix() {
        final byte[] handshake80 = new byte[16];
        handshake80[0] = 0x50;
        handshake80[1] = 0x00;
        assertEquals(ProxyProtocolDetector.Probe.INCOMPLETE, ProxyProtocolDetector.probe(buffer(0x50)));
        assertEquals(ProxyProtocolDetector.Probe.DIRECT, ProxyProtocolDetector.probe(buffer(0x50, 0x00)));
        assertEquals(ProxyProtocolDetector.Probe.DIRECT, ProxyProtocolDetector.probe(buffer(handshake80)));
    }

    @Test
    @DisplayName("前缀还没凑齐时保持等待，且不消费任何字节")
    void incompletePrefixesWait() {
        final ByteBuf v2Partial = buffer(V2_SIGNATURE[0], V2_SIGNATURE[1], V2_SIGNATURE[2], V2_SIGNATURE[3],
                V2_SIGNATURE[4], V2_SIGNATURE[5], V2_SIGNATURE[6], V2_SIGNATURE[7]);
        assertEquals(8, v2Partial.readableBytes());
        assertEquals(ProxyProtocolDetector.Probe.INCOMPLETE, ProxyProtocolDetector.probe(v2Partial));

        final ByteBuf v1Partial = buffer('P', 'R', 'O', 'X', 'Y');
        assertEquals(ProxyProtocolDetector.Probe.INCOMPLETE, ProxyProtocolDetector.probe(v1Partial));

        assertEquals(ProxyProtocolDetector.Probe.INCOMPLETE,
                ProxyProtocolDetector.probe(Unpooled.EMPTY_BUFFER));
    }

    @Test
    @DisplayName("前缀吻合且字节足够时交给官方 detectProtocol 裁定")
    void candidateWhenPrefixMatchesAndEnoughBytes() {
        final byte[] v2 = new byte[20];
        System.arraycopy(V2_SIGNATURE, 0, v2, 0, 12);
        v2[12] = 0x21;   // PROXY，地址族 TCP over IPv6
        v2[13] = 0x11;
        final ByteBuf v2Buffer = buffer(v2);
        assertEquals(ProxyProtocolDetector.Probe.CANDIDATE, ProxyProtocolDetector.probe(v2Buffer));
        assertEquals(HAProxyProtocolVersion.V2,
                HAProxyMessageDecoder.detectProtocol(v2Buffer).detectedProtocol());

        final ByteBuf v1Buffer = buffer("PROXY TCP4 1.2.3.4 5.6.7.8 1234 5678\r\n".getBytes(StandardCharsets.US_ASCII));
        assertEquals(ProxyProtocolDetector.Probe.CANDIDATE, ProxyProtocolDetector.probe(v1Buffer));
        assertEquals(HAProxyProtocolVersion.V1,
                HAProxyMessageDecoder.detectProtocol(v1Buffer).detectedProtocol());
    }

    @Test
    @DisplayName("probe 只读不消费（readerIndex 保持不变），否则会破坏后续解码")
    void probeNeverConsumesBytes() {
        final ByteBuf buffer = buffer(V2_SIGNATURE);
        final int before = buffer.readerIndex();
        assertEquals(ProxyProtocolDetector.Probe.CANDIDATE, ProxyProtocolDetector.probe(buffer));
        assertEquals(before, buffer.readerIndex());
        assertEquals(12, buffer.readableBytes());
    }

    @Test
    @DisplayName("可读字节 ≥ 12 时，前缀探测的 DIRECT 结论与 Netty detectProtocol 的 INVALID 完全一致")
    void probeAgreesWithNettyDetectProtocol() {
        final List<byte[]> samples = new ArrayList<>();
        samples.add(HANDSHAKE);

        final byte[] v2 = new byte[16];
        System.arraycopy(V2_SIGNATURE, 0, v2, 0, 12);
        samples.add(v2);

        samples.add("PROXY TCP4 1.2.3.4 5.6.7.8 1 2\r\n".getBytes(StandardCharsets.US_ASCII));
        samples.add("PROXYX 这一行的前缀吻合但整体不合法".getBytes(StandardCharsets.UTF_8));

        final byte[] wrongSecondByte = V2_SIGNATURE.clone();
        wrongSecondByte[1] = 0x00;
        samples.add(wrongSecondByte);

        final byte[] wrongLastByte = V2_SIGNATURE.clone();
        wrongLastByte[11] = 0x00;
        samples.add(wrongLastByte);

        samples.add(new byte[]{0x0D, 0x00, 0x47, 0x09, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't', 0x00, 0x00});

        final byte[] length80 = new byte[16];
        length80[0] = 0x50;
        samples.add(length80);

        for (byte[] sample : samples) {
            assertTrue(sample.length >= 12, "样本必须足够长才能做一致性比较");
            final boolean probeSaysDirect =
                    ProxyProtocolDetector.probe(buffer(sample)) == ProxyProtocolDetector.Probe.DIRECT;
            final ProtocolDetectionResult<HAProxyProtocolVersion> official =
                    HAProxyMessageDecoder.detectProtocol(buffer(sample));
            final boolean nettySaysInvalid = official.state() == ProtocolDetectionState.INVALID;
            assertEquals(nettySaysInvalid, probeSaysDirect,
                    "前缀探测与官方判定必须一致，样本长度 " + sample.length);
        }
    }

    @Test
    @DisplayName("直连连接：探测器摘除自己，已缓冲的字节原封不动交给后续处理器")
    void directConnectionRemovesItselfAndForwardsBytes() {
        final DetectorContext detectorContext = context(AllowList.ALLOW_ALL);
        final EmbeddedChannel channel = channelWith(detectorContext);
        assertNotNull(channel.pipeline().context(ProxyProtocolDetector.HANDLER_NAME), "探测器应当已挂上");

        assertTrue(channel.writeInbound(buffer(HANDSHAKE)));
        assertNull(channel.pipeline().context(ProxyProtocolDetector.HANDLER_NAME), "探测器应当已从管道摘除");

        final ByteBuf received = channel.readInbound();
        assertNotNull(received, "直连的握手字节必须被转发出去，不能丢");
        final byte[] actual = new byte[received.readableBytes()];
        received.readBytes(actual);
        assertArrayEquals(HANDSHAKE, actual);
        received.release();

        assertEquals(1L, detectorContext.counters().direct());
        assertEquals(0L, detectorContext.counters().rejected());
        assertEquals(0L, detectorContext.counters().failures(), "这条路径不应抛出任何异常");
        channel.finishAndReleaseAll();
    }

    @Test
    @DisplayName("前缀不完整时保持等待：字节既不消费也不转发，补全后才做决定")
    void incompletePrefixKeepsBytesBuffered() {
        // 用 DENY_ALL：EmbeddedChannel 没有对端地址，正好覆盖「拿不到地址必须拒绝」这条失败即关闭的路径
        final DetectorContext detectorContext = context(AllowList.DENY_ALL);
        final EmbeddedChannel channel = channelWith(detectorContext);

        final byte[] partial = new byte[4];
        System.arraycopy(V2_SIGNATURE, 0, partial, 0, 4);
        channel.writeInbound(buffer(partial));

        assertNotNull(channel.pipeline().context(ProxyProtocolDetector.HANDLER_NAME), "探测器应当仍在管道里");
        assertNull(channel.readInbound(), "还不能下结论，字节应当停在缓冲区里");
        assertEquals(0L, detectorContext.counters().direct());
        assertEquals(0L, detectorContext.counters().rejected());

        // 补上签名的剩余 8 个字节 → 凑齐完整的 PROXY v2 头，但 EmbeddedChannel 没有可信对端地址，于是被拒绝并关连接
        final byte[] rest = new byte[V2_SIGNATURE.length - 4];
        System.arraycopy(V2_SIGNATURE, 4, rest, 0, rest.length);
        channel.writeInbound(buffer(rest));
        assertEquals(1L, detectorContext.counters().rejected());
        assertEquals(0L, detectorContext.counters().proxied());
        assertEquals(0L, detectorContext.counters().direct(), "补全后是代理头，不应被计入直连");
        assertEquals(0L, detectorContext.counters().failures(), "这条路径不应抛出任何异常");
        assertFalse(channel.isOpen(), "被拒绝的连接必须关闭");
        channel.finishAndReleaseAll();
    }
}
