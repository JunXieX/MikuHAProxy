package io.github.junxiex.mikuhaproxy.util;

import io.netty.channel.Channel;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.embedded.EmbeddedChannel;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodType;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * {@link Reflect} 的测试（此前只被间接用到）。
 *
 * <p>本插件只对 Velocity 的<b>实现类</b>做少量反射，全部收敛在这个工具类里，所以它的行为必须被钉住：
 * 「只按名字/类型比对、不 {@code Class.forName}」是刻意的取舍（上游挪包时给出可读的
 * 「找不到某个字段」而不是 {@code NoClassDefFoundError}），而 {@link Reflect#bind} 造出的
 * {@link MethodHandle} 会被 {@code ChannelHook.DetectingInitializer} 用 <b>{@code invokeExact}</b>
 * 调用——<b>{@code invokeExact} 不做隐式类型转换</b>，签名一旦不精确匹配，就会在<b>每条新连接</b>的
 * 路径上抛 {@code WrongMethodTypeException}。这里是守住那条红线的地方。</p>
 */
class ReflectTest {

    @Test
    @DisplayName("findField：只找实例字段（静态字段一律跳过），并沿父类向上查找")
    void findFieldSkipsStaticFieldsAndWalksSuperclasses() {
        assertNotNull(Reflect.findField(Child.class, field -> "ownField".equals(field.getName())));
        assertNull(Reflect.findField(Child.class, field -> "CONSTANT".equals(field.getName())),
                "静态字段不是实例状态，被当成候选就会读到 null 甚至报错");
        assertNull(Reflect.findField(Child.class, field -> "missing".equals(field.getName())));

        final Field inherited = Reflect.findField(Child.class, field -> "parentField".equals(field.getName()));
        assertNotNull(inherited, "父类里声明的字段也要能找到");
        assertEquals(Parent.class, inherited.getDeclaringClass());
    }

    @Test
    @DisplayName("findField：private 字段取到后 setAccessible 即可读写（取值方负责打开可访问性）")
    void foundFieldIsUsableAfterSetAccessible() throws Exception {
        final Child child = new Child();
        final Field field = Reflect.findField(Child.class, candidate -> "ownField".equals(candidate.getName()));
        assertNotNull(field);

        field.setAccessible(true);
        field.set(child, "改过的值");

        assertEquals("改过的值", field.get(child));
    }

    @Test
    @DisplayName("findMethod：只认公共方法，继承来的也能找到，找不到返回 null")
    void findMethodLooksUpPublicMethodsIncludingInherited() {
        final Method own = Reflect.findMethod(Child.class, "own");
        assertNotNull(own);
        assertEquals(Child.class, own.getDeclaringClass());

        final Method inherited = Reflect.findMethod(Child.class, "inherited");
        assertNotNull(inherited, "继承来的公共方法也要能找到");
        assertEquals(Parent.class, inherited.getDeclaringClass());

        assertNull(Reflect.findMethod(Child.class, "missing"));
    }

    @Test
    @DisplayName("findMethod 只认公共方法：protected 的 ChannelInitializer#initChannel 用它是找不到的")
    void findMethodCannotSeeProtectedMethods() throws Exception {
        assertNull(Reflect.findMethod(ChannelInitializer.class, "initChannel", Channel.class),
                "这正是 ChannelHook.DetectingInitializer 必须改用 getDeclaredMethod 的原因；"
                        + "若哪天这里不再是 null，说明上游把方法改公共了，那边的反射也可以跟着简化");
        assertNotNull(ChannelInitializer.class.getDeclaredMethod("initChannel", Channel.class),
                "前提校验：这个方法确实存在，只是不公共");
    }

    @Test
    @DisplayName("unreflect：实例方法得到「接收者在前」的签名，bindTo 之后可直接调用")
    void unreflectKeepsReceiverAsFirstParameter() throws Throwable {
        final MethodHandle unbound = Reflect.unreflect(Child.class.getDeclaredMethod("own"));
        assertEquals(MethodType.methodType(String.class, Child.class), unbound.type());

        final MethodHandle bound = unbound.bindTo(new Child());
        assertEquals(MethodType.methodType(String.class), bound.type());

        // ⚠️ 必须写成 (String) bound.invokeExact()：invokeExact 是签名多态方法，调用点描述符
        // 由「显式转型」的目标类型确定 —— 直接赋给 String 变量、或塞进 assertEquals(Object, Object)
        // 的参数位，都会被推成 ()Object，与句柄的 ()String 不匹配而抛 WrongMethodTypeException
        //（2026-09-26 两种写法都在 CI/离线编译上实测踩过，正是 §7.1 ② 那条红线在测试侧的翻版）。
        final String value = (String) bound.invokeExact();
        assertEquals("own", value);
    }

    @Test
    @DisplayName("bind：把 protected 的 initChannel 钉成 (Channel)void，invokeExact 能精确调用")
    void bindFixesSignatureSoInvokeExactWorks() throws Throwable {
        final Method initChannel = ChannelInitializer.class.getDeclaredMethod("initChannel", Channel.class);
        final AtomicReference<Channel> seen = new AtomicReference<>();
        final ChannelInitializer<Channel> initializer = new ChannelInitializer<>() {
            @Override
            protected void initChannel(Channel channel) {
                seen.set(channel);
            }
        };

        final MethodHandle handle = Reflect.bind(void.class, initChannel, initializer);

        assertEquals(MethodType.methodType(void.class, Channel.class), handle.type(),
                "签名必须精确为 (Channel)void：invokeExact 不做隐式转换，差一点都不行");

        final Channel channel = new EmbeddedChannel();
        handle.invokeExact(channel);
        assertSame(channel, seen.get(), "绑定接收者之后，调用必须落到这个实例上");

        ((EmbeddedChannel) channel).finishAndReleaseAll();
    }

    @Test
    @DisplayName("sneakyThrow：受检异常原样抛出，不被包装（保证调用方看到的类型与堆栈不变）")
    void sneakyThrowPropagatesTheSameInstance() {
        final IOException original = new IOException("原样抛出");

        final IOException thrown = assertThrows(IOException.class, () -> Reflect.sneakyThrow(original));

        assertSame(original, thrown, "包一层会改变调用方看到的异常类型与堆栈，正是要避免的");
    }

    // ------------------------------------------------------------------

    @SuppressWarnings("unused")
    private static class Parent {

        public String parentField;

        public String inherited() {
            return "inherited";
        }
    }

    @SuppressWarnings("unused")
    private static class Child extends Parent {

        private static final String CONSTANT = "静态字段不参与查找";

        private String ownField;

        public String own() {
            return "own";
        }
    }
}
