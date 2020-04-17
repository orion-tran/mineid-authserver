package org.mineid.authserver;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.ByteToMessageDecoder;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.List;

public final class ServerHandler extends ByteToMessageDecoder {

    private static final SecureRandom random = new SecureRandom();
    private static final Logger logger = LoggerFactory.getILoggerFactory().getLogger("ServerHandler");

    private int version = 47;
    private ProtocolState protocolState = ProtocolState.HANDSHAKE;

    private boolean hasEncrypted = false;
    private KeyPair keys;
    private byte[] verify;
    private String username;
    private final OkHttpClient httpClient;

    ServerHandler(OkHttpClient client) {
        logger.debug("New ServerHandler instance");
        httpClient = client;
    }

    private static void close(String reason, @NotNull ChannelHandlerContext context) {
        try {
            ByteBuf out = Unpooled.buffer();
            ByteBuf data = Unpooled.buffer();
            PacketUtil.writeVarInt(0x00, data);
            PacketUtil.writeUTF8(reason, data);
            PacketUtil.writeVarInt(data.readableBytes(), out);
            out.writeBytes(data);
            context.writeAndFlush(out);
        } catch (Exception e) {
            context.close();
            logger.debug("failure in close message");
        }
    }

    @Override
    public void channelUnregistered(ChannelHandlerContext ctx) throws Exception {
        super.channelUnregistered(ctx);
        logger.debug("Closed channel!");
    }

    @Override
    protected void decode(@NotNull ChannelHandlerContext ctx, ByteBuf in, List<Object> o) {
        try {
            if (!ctx.channel().isOpen()) return; // if the context isn't open, then don't do anything

            if (in.readableBytes() > 32767) {
                logger.debug("Huge packet incoming (bad packet)! Disconnecting...");
                ctx.close();
                return;
            }

            int length;
            int id;

            try {
                length = PacketUtil.readVarInt(in); // read the length and id of packet
                id = PacketUtil.readVarInt(in);     // https://wiki.vg/Protocol#Packet_format
                logger.debug("{} ID: {} (0x{}) Length: {}", protocolState, id, Integer.toHexString(id), length);
            } catch (Exception e) {
                logger.debug("Bad packet (invalid length/id)! Disconnecting...");
                ctx.close();
                return;
            }

            if (id > 0x01 || length == 0) { // detect malicious packets
                logger.debug("Bad packet! Disconnecting...");
                logger.debug("BAD {} ID: {} (0x{}) Length: {}", protocolState, id, Integer.toHexString(id), length);
                ctx.close(); // close connection, possible overflow attack possible
                return;
            }

            // handshake / status code
            if (protocolState == ProtocolState.HANDSHAKE || protocolState == ProtocolState.STATUS) {
                if (id == 0x00) {
                    // status request
                    if (length != 1) {
                        try {
                            version = PacketUtil.readVarInt(in);
                            String address = PacketUtil.readUTF8(in);
                            int port = in.readUnsignedShort();
                            int state = PacketUtil.readVarInt(in);
                            logger.debug("Client: version: {}, @{}, :{}", version, address, port);
                            if (state == 1) {
                                logger.debug("Client wants status");
                                protocolState = ProtocolState.STATUS;
                                return;
                            }
                            if (state == 2) {
                                if (version < 47) {
                                    close("{\"text\":\"Please join with a 1.8+ Minecraft client (>47)\"}", ctx);
                                    return;
                                }
                                protocolState = ProtocolState.LOGIN;
                                logger.debug("Client wants to login");
                                // logging in boys, let's authenticate them with the committee
                                return;
                            }
                        } catch (Exception ignored) {
                            // *shrugs*
                        }
                    } else {
                        logger.debug("Sending Ping!");
                        // status response
                        String response;
                        if (version >= 47) {
                            response = Messages.getStatus(version);
                        } else {
                            response = Messages.getStatusOutdated(version);
                        }
                        ByteBuf out = Unpooled.buffer();
                        ByteBuf data = Unpooled.buffer();
                        PacketUtil.writeVarInt(0, data);
                        PacketUtil.writeUTF8(response, data);
                        PacketUtil.writeVarInt(data.readableBytes(), out);
                        out.writeBytes(data);
                        ctx.writeAndFlush(out);
                        protocolState = ProtocolState.HANDSHAKE;
                        return;
                    }
                } else if (id == 0x01) {
                    // ping request
                    long time = in.readLong();
                    logger.debug("Received ping packet: {}, {}, {}", length, id, time);
                    // ping response
                    ByteBuf out = Unpooled.buffer();
                    ByteBuf data = Unpooled.buffer();
                    PacketUtil.writeVarInt(0x01, data);
                    data.writeLong(time);

                    PacketUtil.writeVarInt(data.readableBytes(), out);
                    out.writeBytes(data);

                    ctx.writeAndFlush(out);
                }
            }

            if (protocolState == ProtocolState.LOGIN) {
                if (id == 0x00) {
                    // username packet
                    try {
                        // read username and remove control characters
                        username = PacketUtil.readUTF8(in).replaceAll("\\p{Cc}", "");
                    } catch (Exception e) {
                        logger.debug("Invalid Username");
                        close("{\"text\":\"Your username was invalid, try joining again!\"}", ctx);
                        ctx.close();
                        return;
                    }

                    logger.debug("Username of player: {}", username);

                    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
                    generator.initialize(1024);

                    keys = generator.generateKeyPair();

                    X509EncodedKeySpec encodedKeySpec = new X509EncodedKeySpec(keys.getPublic().getEncoded());
                    KeyFactory keyFactory = KeyFactory.getInstance("RSA");

                    byte[] publicKey = keyFactory.generatePublic(encodedKeySpec).getEncoded();
                    verify = new byte[4];
                    random.nextBytes(verify);

                    ByteBuf out = Unpooled.buffer();
                    ByteBuf data = Unpooled.buffer();

                    PacketUtil.writeVarInt(0x01, data);
                    PacketUtil.writeUTF8("", data);
                    PacketUtil.writeVarInt(publicKey.length, data);
                    data.writeBytes(publicKey);
                    PacketUtil.writeVarInt(verify.length, data);
                    data.writeBytes(verify);

                    PacketUtil.writeVarInt(data.readableBytes(), out);
                    out.writeBytes(data);
                    ctx.writeAndFlush(out);

                    logger.debug("Sent encryption request!");
                    hasEncrypted = true;
                } else if (id == 0x01 && hasEncrypted) {
                    int secretLength = PacketUtil.readVarInt(in);
                    byte[] secret = in.readBytes(secretLength).array();
                    int verifyTokenLength = PacketUtil.readVarInt(in);
                    byte[] verifyToken = in.readBytes(verifyTokenLength).array();

                    PrivateKey key = keys.getPrivate();
                    Cipher rsaCipher = Cipher.getInstance("RSA");

                    rsaCipher.init(Cipher.DECRYPT_MODE, key);
                    SecretKey sharedSecret = new SecretKeySpec(rsaCipher.doFinal(secret), "AES");

                    rsaCipher.init(Cipher.DECRYPT_MODE, key);
                    byte[] finalVerifyToken = rsaCipher.doFinal(verifyToken);

                    if (!Arrays.equals(verify, finalVerifyToken)) {
                        logger.debug("Verification arrays don't match! (kick!)");
                        close("{\"text\":\"Encryption failed! (Rejoin)\"}", ctx);
                        ctx.close();
                        return;
                    } else {
                        logger.debug("Verification arrays successfully match");
                    }

                    MessageDigest digest = MessageDigest.getInstance("SHA-1");
                    digest.update("".getBytes());
                    digest.update(sharedSecret.getEncoded());
                    digest.update(keys.getPublic().getEncoded());

                    String hash = new BigInteger(digest.digest()).toString(16);

                    String url = "https://sessionserver.mojang.com/session/minecraft/hasJoined?username="
                            + username + "&serverId=" + hash + "&ip=" + ctx.channel().remoteAddress();

                    logger.debug("url: {}", url);

                    Request request = new Request.Builder()
                            .url(url).addHeader("User-Agent", "MineAuth/1.0").build();
                    Response response = httpClient.newCall(request).execute();

                    if (!ctx.channel().isOpen()) return;

                    boolean good = response.code() == 200;

                    response.close();

                    Cipher encrypt = Cipher.getInstance("AES/CFB8/NoPadding");
                    encrypt.init(Cipher.ENCRYPT_MODE, sharedSecret, new IvParameterSpec(sharedSecret.getEncoded()));

                    ctx.channel().pipeline().addFirst("encrypt", new EncryptHandler(encrypt));

                    if (good) {
                        logger.info("Authenticated player: {}", username);
                        close(Messages.getVerificationMessage("yourmom123"), ctx);
                        // TODO: Implement actual token retrieval/generation
                    } else {
                        logger.info("Invalid session {}", username);
                        close("{\"text\":\"Invalid Login (Try restarting your game!)\"}", ctx);
                    }

                    ctx.close();
                }
            }
        } catch (Exception e) {
            logger.error("Forcibly closed client! Exception occurred!");
            close("{\"text\":\"An error has occurred, please reconnect!\"}", ctx);
            logger.error(e.getMessage());
            e.printStackTrace();
            ctx.close();
        }
    }

    enum ProtocolState {
        HANDSHAKE, STATUS, LOGIN
    }
}