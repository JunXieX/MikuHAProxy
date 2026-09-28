package io.github.junxiex.mikuhaproxy.util;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.function.Predicate;

/**
 * 反射工具。
 *
 * <p>本插件只对 Velocity 的<b>实现类</b>（{@code com.velocitypowered.proxy.*}）做极少量的反射访问，
 * 全部收敛在这里，并且刻意只按「类型名 / 方法名」比对，不做 {@code Class.forName}——这样即使上游
 * 把类挪了位置，得到的也是可读的「找不到某个字段」而不是 {@code NoClassDefFoundError}。</p>
 */
public final class Reflect {

    private Reflect() {
        throw new AssertionError();
    }

    /** 把受检异常原样抛出（配合反射调用使用，避免层层包装）。 */
    @SuppressWarnings("unchecked")
    public static <E extends Throwable> void sneakyThrow(Throwable t) throws E {
        throw (E) t;
    }

    /**
     * 在类及其父类中查找第一个满足条件的<b>实例</b>字段。
     *
     * @return 找到的字段；没有则返回 {@code null}
     */
    public static Field findField(Class<?> owner, Predicate<Field> predicate) {
        for (Class<?> c = owner; c != null && c != Object.class; c = c.getSuperclass()) {
            for (Field field : c.getDeclaredFields()) {
                if (!Modifier.isStatic(field.getModifiers()) && predicate.test(field)) {
                    return field;
                }
            }
        }
        return null;
    }

    /** 按名字 + 参数类型在类及其父类中查找公共方法；找不到返回 {@code null}。 */
    public static Method findMethod(Class<?> owner, String name, Class<?>... parameterTypes) {
        for (Class<?> c = owner; c != null && c != Object.class; c = c.getSuperclass()) {
            try {
                return c.getMethod(name, parameterTypes);
            } catch (NoSuchMethodException ignored) {
                // 继续往父类找
            }
        }
        return null;
    }

    /**
     * 为 {@code method} 生成一个「已经绑定接收者、并且把签名固定下来」的 {@link MethodHandle}。
     *
     * <p>每个新连接都要调用一次 {@code ChannelInitializer#initChannel}，绑定后的句柄在热路径上
     * 就是一次直接调用；相比每次 {@code Method.invoke}（可变参数数组 + 访问检查）更省，
     * 而且只做一次查找。</p>
     */
    public static MethodHandle bind(Class<?> returnType, Method method, Object receiver) {
        // unreflect 已经处理了访问性；bindTo / asType 的类型不匹配都是运行时异常，不必再包一层。
        return unreflect(method)
                .bindTo(receiver)
                .asType(MethodType.methodType(returnType, method.getParameterTypes()));
    }

    /**
     * 生成签名固定的 {@link MethodHandle}。
     *
     * <p>静态方法得到 {@code (params)ret}；实例方法得到 {@code (接收者, params)ret}，
     * 调用方可以再 {@code bindTo(实例)} 收敛成 {@code (params)ret}。</p>
     */
    public static MethodHandle unreflect(Method method) {
        try {
            method.setAccessible(true);
            return MethodHandles.lookup().unreflect(method);
        } catch (IllegalAccessException e) {
            throw new IllegalStateException("无法访问方法 " + method, e);
        }
    }
}
