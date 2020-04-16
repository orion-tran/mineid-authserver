package org.mineid.authserver;

import io.netty.buffer.ByteBuf;
import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

public final class PacketUtil {
    public static int readVarInt(@NotNull ByteBuf input) throws IllegalArgumentException {
        int value = 0;
        int i = 0;
        int b;
        while (((b = input.readByte()) & 0x80) != 0) {
            value |= (b & 0x7F) << i;
            i += 7;
            if (i > 35) {
                throw new IllegalArgumentException("Variable length quantity is too long");
            }
        }
        return value | (b << i);
    }

    public static void writeVarInt(int value, ByteBuf output) {
        while ((value & 0xFFFFFF80) != 0L) {
            output.writeByte((value & 0x7F) | 0x80);
            value >>>= 7;
        }
        output.writeByte(value & 0x7F);
    }

    public static void writeUTF8(@NotNull String value, ByteBuf buf) throws IOException {
        final byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        if (bytes.length >= Short.MAX_VALUE) {
            throw new IOException("String length longer than Short.MAX_VALUE");
        }
        writeVarInt(bytes.length, buf);
        buf.writeBytes(bytes);
    }

    @Contract("_ -> new")
    public static @NotNull String readUTF8(ByteBuf buf) throws IllegalArgumentException {
        final int len = readVarInt(buf);
        final byte[] bytes = new byte[len];
        buf.readBytes(bytes);
        return new String(bytes, StandardCharsets.UTF_8);
    }
}