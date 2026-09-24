package io.github.junxiex.mikuhaproxy.util;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

class CountersTest {

    @Test
    @DisplayName("公开表面恰好是 10 个方法：5 个 increment + 5 个读取器，不多不少")
    void publicSurfaceIsExactlyTheTenIntendedMethods() {
        // 必须用反射：无法用同包访问断言「某个方法不存在」。
        // 这条断言锁的是设计承诺——计数器只进不出，任何调用方都不能 reset / decrement。
        // 有意扩展表面时更新这里的期望集合即可；若是因为手滑多了个 set/reset，本测试会拦下。
        final Set<String> names = Stream.of(Counters.class.getMethods())
                .filter(m -> m.getDeclaringClass() == Counters.class)
                .map(Method::getName)
                .collect(Collectors.toSet());

        assertEquals(Set.of(
                        "incrementDirect", "incrementProxied", "incrementRejected",
                        "incrementNotInjected", "incrementFailures",
                        "direct", "proxied", "rejected", "notInjected", "failures"),
                names, "Counters 的公开表面变化了：更新期望集合前先确认这是有意的改动");
    }

    @Test
    @DisplayName("任何公开方法都不返回、不接受 LongAdder（内部实现不可被外部 reset）")
    void noMethodExposesLongAdder() {
        for (Method method : Counters.class.getMethods()) {
            if (method.getDeclaringClass() != Counters.class) {
                continue;
            }
            assertNotEquals(LongAdder.class, method.getReturnType(),
                    method.getName() + " 不得返回 LongAdder，否则调用方可以 reset 统计");
            for (Class<?> parameter : method.getParameterTypes()) {
                assertNotEquals(LongAdder.class, parameter,
                        method.getName() + " 不得接受 LongAdder 参数");
            }
        }
    }

    @Test
    @DisplayName("五个计数各自独立累加、独立读取")
    void countersAreIndependent() {
        final Counters counters = new Counters();
        counters.incrementDirect();
        counters.incrementDirect();
        counters.incrementProxied();
        counters.incrementRejected();
        counters.incrementNotInjected();
        counters.incrementFailures();
        counters.incrementFailures();
        counters.incrementFailures();

        assertEquals(List.of(2L, 1L, 1L, 1L, 3L),
                List.of(counters.direct(), counters.proxied(), counters.rejected(),
                        counters.notInjected(), counters.failures()),
                "五个计数互不串扰");
    }
}
