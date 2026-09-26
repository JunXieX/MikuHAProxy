package com.velocitypowered.proxy.network;

import io.netty.channel.Channel;
import io.netty.channel.ChannelInitializer;

/**
 * Velocity 真实 {@code ConnectionManager} 的「形状替身」，<b>只用于测试</b>。
 *
 * <p>为什么要放在上游这个包名下：{@code ChannelHook} 定位连接管理器的方式之一是<b>按类型全限定名</b>
 * 比对字段/访问器返回值（刻意不 {@code Class.forName}，那样上游挪包会直接抛
 * {@code NoClassDefFoundError}），而 {@code velocity-api} 只提供 API、<b>不含</b>
 * {@code com.velocitypowered.proxy.*} 实现类，测试 classpath 上拿不到真货。于是这里复刻上游的
 * <b>形状</b>（公共访问器 + 同名字段 + 同形持有者），让「定位 → 包装 → 还原」整条链路能被端到端覆盖。</p>
 *
 * <p><b>它锁不住什么（别误读）</b>：这只证明<b>本插件自己的定位与包装逻辑</b>没被改坏，
 * <b>不能</b>证明上游 Velocity 的字段与访问器还在——那需要把 Velocity 的实现放进测试 classpath，
 * 属于版本烟囱测试，本插件不做。上游真改了结构时，插件的行为是「注入失败并打日志」，
 * 而 {@code ChannelHookTest} 正好也覆盖了这条失败路径。</p>
 */
public class ConnectionManager {

    /** 与上游同名同形的字段：{@code ChannelHook} 的字段兜底路径认「名字以 server 开头 + 类型名以 ChannelInitializerHolder 结尾」。 */
    public final ServerChannelInitializerHolder serverChannelInitializer = new ServerChannelInitializerHolder();

    /** 与上游同形的公共访问器（优先级高于字段）。 */
    public ServerChannelInitializerHolder getServerChannelInitializer() {
        return serverChannelInitializer;
    }

    /** 与上游同形的初始化器持有者：公共 {@code get()} / {@code set(...)}。 */
    public static final class ServerChannelInitializerHolder {

        private ChannelInitializer<Channel> initializer;

        public ChannelInitializer<Channel> get() {
            return initializer;
        }

        public void set(ChannelInitializer<Channel> initializer) {
            this.initializer = initializer;
        }
    }
}
