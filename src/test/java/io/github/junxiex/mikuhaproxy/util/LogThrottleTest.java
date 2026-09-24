package io.github.junxiex.mikuhaproxy.util;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LogThrottleTest {

    private static InetAddress address(String text) throws UnknownHostException {
        return InetAddress.getByName(text);
    }

    @Test
    @DisplayName("同一地址在时间窗内只放行第一条")
    void suppressesRepeatsWithinWindow() throws Exception {
        final LogThrottle throttle = new LogThrottle(3600, 256);
        final InetAddress peer = address("203.0.113.7");

        assertTrue(throttle.shouldLog(peer));
        assertFalse(throttle.shouldLog(peer));
        assertFalse(throttle.shouldLog(peer));
        assertEquals(1, throttle.tracked());
    }

    @Test
    @DisplayName("不同地址互不影响")
    void differentAddressesAreIndependent() throws Exception {
        final LogThrottle throttle = new LogThrottle(3600, 256);
        assertTrue(throttle.shouldLog(address("203.0.113.1")));
        assertTrue(throttle.shouldLog(address("203.0.113.2")));
        assertTrue(throttle.shouldLog(address("2001:db8::1")));
        assertEquals(3, throttle.tracked());
    }

    @Test
    @DisplayName("间隔设为 0 表示关闭限流：每次都放行")
    void zeroIntervalDisablesThrottling() throws Exception {
        final LogThrottle throttle = new LogThrottle(0, 256);
        final InetAddress peer = address("203.0.113.7");
        assertTrue(throttle.shouldLog(peer));
        assertTrue(throttle.shouldLog(peer));
        assertEquals(0, throttle.tracked(), "关闭限流时不应保留任何记录");
    }

    @Test
    @DisplayName("拿不到地址时直接放行（限流只针对可识别的来源）")
    void nullKeyAlwaysLogs() {
        final LogThrottle throttle = new LogThrottle(3600, 256);
        assertTrue(throttle.shouldLog(null));
        assertTrue(throttle.shouldLog(null));
        assertEquals(0, throttle.tracked());
    }

    @Test
    @DisplayName("跟踪的地址数量始终有上界，不会被轮换源 IP 撑爆内存")
    void trackedSizeIsBounded() throws Exception {
        final LogThrottle throttle = new LogThrottle(3600, 32);
        for (int i = 0; i < 5000; i++) {
            throttle.shouldLog(InetAddress.getByAddress(new byte[]{10, (byte) (i >> 8), (byte) i, 1}));
        }
        assertTrue(throttle.tracked() <= 32, "实际跟踪数量：" + throttle.tracked());
    }

    @Test
    @DisplayName("并发调用下放行次数在 1 与线程数之间（get 与 put 无原子性，刻意允许少量重复放行）")
    void concurrentCallsAllowBetweenOneAndThreadsThrough() throws Exception {
        final LogThrottle throttle = new LogThrottle(3600, 256);
        final InetAddress peer = address("203.0.113.9");
        final int threads = 8;
        final CountDownLatch start = new CountDownLatch(1);
        final CountDownLatch done = new CountDownLatch(threads);
        final AtomicInteger allowed = new AtomicInteger();
        final Set<Thread> workers = new HashSet<>();

        for (int i = 0; i < threads; i++) {
            final Thread worker = new Thread(() -> {
                try {
                    start.await();
                    if (throttle.shouldLog(peer)) {
                        allowed.incrementAndGet();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    done.countDown();
                }
            });
            workers.add(worker);
            worker.start();
        }
        start.countDown();
        assertTrue(done.await(30, TimeUnit.SECONDS), "线程未在预期时间内结束");

        assertTrue(allowed.get() >= 1, "至少要放行一次");
        assertTrue(allowed.get() <= threads, "放行次数不应超过线程数");
    }

    @Test
    @DisplayName("过了时间窗后重新放行")
    void logsAgainAfterWindowExpires() throws Exception {
        final LogThrottle throttle = new LogThrottle(1, 256);
        final InetAddress peer = address("198.51.100.1");

        assertTrue(throttle.shouldLog(peer));
        assertFalse(throttle.shouldLog(peer), "同一秒内应当被抑制");

        Thread.sleep(1_100L);

        assertTrue(throttle.shouldLog(peer), "超过窗口后应当重新放行");
    }

    @Test
    @DisplayName("分类分槽：同一地址的不同分类互不挤占（否则噪音会盖掉安全信号）")
    void categoriesHaveIndependentSlots() throws Exception {
        final LogThrottle throttle = new LogThrottle(3600, 256);
        final InetAddress peer = address("203.0.113.7");

        assertTrue(throttle.shouldLog(peer, LogThrottle.CATEGORY_INTERRUPTION));
        assertFalse(throttle.shouldLog(peer, LogThrottle.CATEGORY_INTERRUPTION), "中断分类自身仍限流");

        // 中断占满了自己的槽，但绝不能影响信号分类 —— 否则攻击者能用中断噪音把判定失败的日志挤掉
        assertTrue(throttle.shouldLog(peer), "信号分类应独立于中断分类");
        assertFalse(throttle.shouldLog(peer), "信号分类自身仍然限流");
        assertEquals(2, throttle.tracked(), "两个分类各占一个槽位");
    }
}
