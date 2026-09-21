package io.github.junxiex.mikuhaproxy.command;

import com.mojang.brigadier.builder.LiteralArgumentBuilder;
import com.velocitypowered.api.command.BrigadierCommand;
import com.velocitypowered.api.command.CommandSource;
import io.github.junxiex.mikuhaproxy.MikuHAProxy;

/**
 * {@code /mikuproxy} 命令。
 *
 * <p>使用 Velocity 4.0 推荐的 Brigadier 命令（{@link BrigadierCommand}），子命令自带补全，
 * 权限统一由 {@link #PERMISSION} 控制。</p>
 */
public final class MikuProxyCommand {

    public static final String PERMISSION = "mikuhaproxy.admin";

    private MikuProxyCommand() {
        throw new AssertionError();
    }

    public static BrigadierCommand create(MikuHAProxy plugin) {
        final LiteralArgumentBuilder<CommandSource> root = BrigadierCommand.literalArgumentBuilder("mikuproxy")
                .requires(source -> source.hasPermission(PERMISSION))
                .executes(context -> {
                    plugin.sendHelp(context.getSource());
                    return 1;
                })
                .then(BrigadierCommand.literalArgumentBuilder("status")
                        .executes(context -> {
                            plugin.sendStatus(context.getSource());
                            return 1;
                        }))
                .then(BrigadierCommand.literalArgumentBuilder("list")
                        .executes(context -> {
                            plugin.sendWhitelist(context.getSource());
                            return 1;
                        }))
                .then(BrigadierCommand.literalArgumentBuilder("reload")
                        .executes(context -> {
                            plugin.sendReload(context.getSource());
                            return 1;
                        }));

        return new BrigadierCommand(root);
    }
}
