package org.mineid.authserver;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelOutboundHandlerAdapter;
import io.netty.channel.ChannelPromise;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;

public final class EncryptHandler extends ChannelOutboundHandlerAdapter {
    
    private static final Logger logger = LoggerFactory.getILoggerFactory().getLogger("EncryptHandler");
    
    private final Cipher encrypt;
    private byte[] pre;
    private byte[] post;

    EncryptHandler(Cipher encrypt) {
        this.encrypt = encrypt;
    }

    private byte[] filter(@NotNull ByteBuf in) {
        int readable = in.readableBytes();
        if (pre == null || pre.length < readable) {
            pre = new byte[readable];
        }

        in.readBytes(pre, 0, readable);
        return pre;
    }

    @Override
    public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise) {
        try {
            if (msg instanceof ByteBuf) {
                ByteBuf in = (ByteBuf) msg;
                int readable = in.readableBytes();
                int outputSize = encrypt.getOutputSize(readable);
                byte[] filtered = filter(in);

                if (post == null || post.length < outputSize) {
                    post = new byte[outputSize];
                }

                final ByteBuf buffer = ctx.channel().alloc().buffer(outputSize);
                buffer.writeBytes(post, 0, encrypt.update(filtered, 0, readable, post));
                in.release();
                msg = buffer;
            }
            super.write(ctx, msg, promise);
        } catch (Exception e) {
            logger.debug("EncryptionHandler exception");
            e.printStackTrace();
        }
    }
}
