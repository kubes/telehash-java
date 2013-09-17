package com.denniskubes.telehash;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.DatagramPacket;
import io.netty.channel.socket.nio.NioDatagramChannel;

import java.io.File;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.Signature;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.provider.JCERSAPublicKey;
import org.bouncycastle.util.encoders.Base64;

public class TelehashClient {

  private int port;

  public TelehashClient(int port) {
    this.port = port;
  }

  private byte[] getRandomBytes(int size) {
    byte[] randomBytes = new byte[size];
    Random rand = new Random();
    rand.nextBytes(randomBytes);
    return randomBytes;
  }

  private byte[] getOpenPacketBytes()
    throws Exception {

    String hashname = "8f83606d57ab52161aec9868725d53f2054d9ae16a91274ffcb20a68a15c0855";
    File pubKeyFile = new File(
      "/home/dennis/Projects/telehash/keys/sender-pub.key");
    File privKeyFile = new File(
      "/home/dennis/Projects/telehash/keys/sender-priv.key");
    RSAKeyPairManager manager = new RSAKeyPairManager(pubKeyFile, privKeyFile);

    File seedFile = new File("/home/dennis/Projects/telehash/keys/seeds.json");
    SeedReader seedReader = new SeedReader(seedFile);
    Seed receiverSeed = seedReader.getSeed(hashname);
    JCERSAPublicKey receiverPubKey = TelehashUtils.getRSAPublicKeyFromPemString(receiverSeed.getPublicKeyPem());

    SubjectPublicKeyInfo subjectPublicKeyInfo = new SubjectPublicKeyInfo(
      (ASN1Sequence)ASN1Object.fromByteArray(receiverPubKey.getEncoded()));

    AsymmetricKeyParameter param = PublicKeyFactory.createKey(subjectPublicKeyInfo);
    AsymmetricBlockCipher cipher = new OAEPEncoding(new RSAEngine(),
      new SHA1Digest());
    cipher.init(true, param);

    ElipticKeyPairManager eccKpMan = new ElipticKeyPairManager();
    byte[] eccPubKey = eccKpMan.getUncompressedPublicKey();
    byte[] encrypted = cipher.processBlock(eccPubKey, 0, eccPubKey.length);

    Hex hex = new Hex();
    String line = new String(hex.encode(getRandomBytes(16)));

    Map<String, Object> innerPacketVals = new LinkedHashMap<String, Object>();
    innerPacketVals.put("to", hashname);
    innerPacketVals.put("at", System.currentTimeMillis());
    innerPacketVals.put("line", line);
    String packetJson = JSON.serializeToJson(innerPacketVals);
    byte[] jsonBytes = packetJson.getBytes();

    byte[] senderPubBytes = TelehashUtils.getPublicKeyDER(manager.getPublicKeyPem());
    int innerNumBytes = 2 + jsonBytes.length + senderPubBytes.length;
    byte[] innerPacketBytes = new byte[innerNumBytes];

    byte[] jsonLengthBytes = ByteBuffer.allocate(2).putShort(
      (short)jsonBytes.length).array();
    System.arraycopy(jsonLengthBytes, 0, innerPacketBytes, 0,
      jsonLengthBytes.length);
    System.arraycopy(jsonBytes, 0, innerPacketBytes, jsonLengthBytes.length,
      jsonBytes.length);
    System.arraycopy(senderPubBytes, 0, innerPacketBytes,
      jsonLengthBytes.length + jsonBytes.length, senderPubBytes.length);

    Cipher aesCipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
    byte[] eccSha256 = DigestUtils.sha256(eccPubKey);
    Key key = new SecretKeySpec(eccSha256, "AES");
    byte[] N = getRandomBytes(16);
    aesCipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(N));
    byte[] aesEncrypted = aesCipher.doFinal(innerPacketBytes);

    Signature signer = Signature.getInstance("SHA256withRSA", "BC");
    signer.initSign(manager.getPrivateKey());
    signer.update(aesEncrypted);
    byte[] sigBytes = signer.sign();

    Map<String, Object> openPacket = new LinkedHashMap<String, Object>();
    openPacket.put("open", new String(Base64.encode(encrypted)));
    openPacket.put("iv", new String(hex.encode(N)));
    openPacket.put("sig", new String(Base64.encode(sigBytes)));
    openPacket.put("type", "open");
    String openPacketJson = JSON.serializeToJson(openPacket);
    byte[] openJsonBytes = openPacketJson.getBytes();

    int openNumBytes = 2 + openJsonBytes.length + aesEncrypted.length;
    byte[] openPacketBytes = new byte[openNumBytes];
    byte[] openJsonLengthBytes = ByteBuffer.allocate(2).putShort(
      (short)openJsonBytes.length).array();
    System.arraycopy(openJsonLengthBytes, 0, openPacketBytes, 0,
      openJsonLengthBytes.length);
    System.arraycopy(openJsonBytes, 0, openPacketBytes,
      openJsonLengthBytes.length, openJsonBytes.length);
    System.arraycopy(aesEncrypted, 0, openPacketBytes,
      openJsonLengthBytes.length + openJsonBytes.length, aesEncrypted.length);

    System.out.println(new String(hex.encode(openPacketBytes)));
    return openPacketBytes;
  }

  public void run()
    throws Exception {

    EventLoopGroup group = new NioEventLoopGroup();
    try {

      Bootstrap bootstrap = new Bootstrap();
      bootstrap.group(group);
      bootstrap.channel(NioDatagramChannel.class);
      bootstrap.option(ChannelOption.SO_BROADCAST, true);
      bootstrap.handler(new TelehashClientHandler());

      Channel ch = bootstrap.bind(0).sync().channel();

      ByteBuf data = Unpooled.buffer(1000);
      data.writeBytes(getOpenPacketBytes());

      DatagramPacket packet = new DatagramPacket(data, new InetSocketAddress(
        "255.255.255.255", port));

      ch.writeAndFlush(packet).sync();

      if (!ch.closeFuture().await(150000)) {
        System.err.println("Telehash request timed out.");
      }
    }
    finally {
      group.shutdownGracefully();
    }
  }

  public static void main(String[] args)
    throws Exception {
    int port;
    if (args.length > 0) {
      port = Integer.parseInt(args[0]);
    }
    else {
      port = 4222;
    }
    new TelehashClient(port).run();
  }

}
