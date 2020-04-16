package org.mineid.authserver;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import okhttp3.OkHttpClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetSocketAddress;

public final class AuthServer {
    private static final ServerBootstrap bootstrap = new ServerBootstrap();

    public static void main(String[] args) {
        long stopwatch = System.currentTimeMillis();

        Logger logger = LoggerFactory.getILoggerFactory().getLogger("AuthServer");
        logger.info("MineID AuthServer v1 Starting up...");

        OkHttpClient client = new OkHttpClient.Builder().build();

        EventLoopGroup bossGroup = new NioEventLoopGroup();
        EventLoopGroup workerGroup = new NioEventLoopGroup();

        bootstrap.group(bossGroup, workerGroup);
        bootstrap.channel(NioServerSocketChannel.class);
        bootstrap.option(ChannelOption.SO_BACKLOG, 128);
        bootstrap.childOption(ChannelOption.SO_KEEPALIVE, true);

        bootstrap.childHandler(new ChannelInitializer<SocketChannel>() {
            @Override
            protected void initChannel(SocketChannel ch) {
                logger.debug("Opened handler on " + ch.remoteAddress());
                ch.pipeline().addLast("mc", new ServerHandler(client));
            }
        });

        InetSocketAddress address = new InetSocketAddress(25565);

        logger.info("Binding to [" + address.toString() + "]");
        try {
            logger.info("Server started in {}ms!", System.currentTimeMillis() - stopwatch);
            bootstrap.bind(address).sync().channel().closeFuture().sync();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }
}
