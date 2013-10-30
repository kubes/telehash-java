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

    // get the sender's RSA public and private key
    File pubKeyFile = new File(
      "/home/dennis/Projects/telehash/keys/sender-pub.key");
    File privKeyFile = new File(
      "/home/dennis/Projects/telehash/keys/sender-priv.key");
    RSAKeyPairManager senderRSA = new RSAKeyPairManager(pubKeyFile, privKeyFile);

    // get the recipient's RSA public from the seeds file
    String recipentHashname = "8f83606d57ab52161aec9868725d53f2054d9ae16a91274ffcb20a68a15c0855";
    File seedFile = new File("/home/dennis/Projects/telehash/keys/seeds.json");
    SeedReader seedReader = new SeedReader(seedFile);
    Seed receiverSeed = seedReader.getSeed(recipentHashname);
    JCERSAPublicKey receiverPubKey = TelehashUtils.getRSAPublicKeyFromPemString(receiverSeed.getPublicKeyPem());
    SubjectPublicKeyInfo subjectPublicKeyInfo = new SubjectPublicKeyInfo(
      (ASN1Sequence)ASN1Object.fromByteArray(receiverPubKey.getEncoded()));

    // create an ecc key on the fly through the ecc key pair manager and then
    // encrypt it using rsa
    AsymmetricKeyParameter param = PublicKeyFactory.createKey(subjectPublicKeyInfo);
    AsymmetricBlockCipher cipher = new OAEPEncoding(new RSAEngine(),
      new SHA1Digest());
    cipher.init(true, param);
    ElipticKeyPairManager eccKpMan = new ElipticKeyPairManager();
    byte[] eccPubKey = eccKpMan.getUncompressedPublicKey();
    byte[] eccRSAEncrypted = cipher.processBlock(eccPubKey, 0, eccPubKey.length);

    // create the line, similar to a session cookie, from random 16 bytes
    Hex hex = new Hex();
    byte[] lineBytes = getRandomBytes(16);
    String line = new String(hex.encode(lineBytes));

    // create the inner packet, who I am sending to, the timestamp, and the
    // line session cookie
    Map<String, Object> innerPacketVals = new LinkedHashMap<String, Object>();
    innerPacketVals.put("to", recipentHashname);
    innerPacketVals.put("at", System.currentTimeMillis());
    innerPacketVals.put("line", line);
    String innerPacketJson = JSON.serializeToJson(innerPacketVals);
    byte[] innerPacketJsonBytes = innerPacketJson.getBytes();

    // get the bytes for the senders public RSA key
    byte[] senderPubBytes = TelehashUtils.getPublicKeyDER(senderRSA.getPublicKeyPem());

    // get total bytes which is inner packet json and senders RSA public key
    // in unencrypted form
    int innerNumBytes = 2 + innerPacketJsonBytes.length + senderPubBytes.length;

    // create array to hold inner packet
    byte[] innerPacketBytes = new byte[innerNumBytes];

    // copy the inner packet json length, then inner json unencrypted, and then
    // the unencrypted senders RSA public key
    byte[] innerJsonLengthBytes = ByteBuffer.allocate(2).putShort(
      (short)innerPacketJsonBytes.length).array();
    System.arraycopy(innerJsonLengthBytes, 0, innerPacketBytes, 0,
      innerJsonLengthBytes.length);
    System.arraycopy(innerPacketJsonBytes, 0, innerPacketBytes,
      innerJsonLengthBytes.length, innerPacketJsonBytes.length);
    System.arraycopy(senderPubBytes, 0, innerPacketBytes,
      innerJsonLengthBytes.length + innerPacketJsonBytes.length,
      senderPubBytes.length);

    // use AES256 with ecc key to encrypt inner packet bytes
    Cipher aesInnerCipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
    byte[] eccInnerSha256 = DigestUtils.sha256(eccPubKey);
    Key aesInnerKey = new SecretKeySpec(eccInnerSha256, "AES");
    byte[] salt = getRandomBytes(16);
    aesInnerCipher.init(Cipher.ENCRYPT_MODE, aesInnerKey, new IvParameterSpec(
      salt));
    byte[] aesEncryptedInnerPacket = aesInnerCipher.doFinal(innerPacketBytes);

    // sign the AES256 encrypted inner packet
    Signature signer = Signature.getInstance("SHA256withRSA", "BC");
    signer.initSign(senderRSA.getPrivateKey());
    signer.update(aesEncryptedInnerPacket);
    byte[] aesEncryptedInnerSig = signer.sign();

    // create the key used for the sha256 of the sig
    byte[] sigKeyBytes = new byte[eccPubKey.length + lineBytes.length];
    System.arraycopy(lineBytes, 0, sigKeyBytes, 0, lineBytes.length);
    System.arraycopy(eccPubKey, 0, sigKeyBytes, lineBytes.length,
      eccPubKey.length);

    // encrypt the signature using and aes with sha256
    Cipher aesSigCipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
    byte[] sigSha256 = DigestUtils.sha256(sigKeyBytes);
    Key sigKey = new SecretKeySpec(sigSha256, "AES");
    aesSigCipher.init(Cipher.ENCRYPT_MODE, sigKey, new IvParameterSpec(salt));
    byte[] aesEncryptedSig = aesSigCipher.doFinal(aesEncryptedInnerSig);

    // create an open packet to wrap the inner packet. Will contain the on the
    // fly encrypted ecc public key for the session, the salt for AES, the
    // signature, and the packet type which is open
    Map<String, Object> openPacket = new LinkedHashMap<String, Object>();
    openPacket.put("open", new String(Base64.encode(eccRSAEncrypted)));
    openPacket.put("iv", new String(hex.encode(salt)));
    openPacket.put("sig", new String(Base64.encode(aesEncryptedSig)));
    openPacket.put("type", "open");
    String openPacketJson = JSON.serializeToJson(openPacket);
    byte[] openJsonBytes = openPacketJson.getBytes();

    // get the total number of bytes for the open packet and create array
    int openNumBytes = 2 + openJsonBytes.length
      + aesEncryptedInnerPacket.length;
    byte[] openPacketBytes = new byte[openNumBytes];

    // copy the open packet json length, the open packet in unencrypted form,
    // and the body which is the encrypted inner packet
    byte[] openJsonLengthBytes = ByteBuffer.allocate(2).putShort(
      (short)openJsonBytes.length).array();
    System.arraycopy(openJsonLengthBytes, 0, openPacketBytes, 0,
      openJsonLengthBytes.length);
    System.arraycopy(openJsonBytes, 0, openPacketBytes,
      openJsonLengthBytes.length, openJsonBytes.length);
    System.arraycopy(aesEncryptedInnerPacket, 0, openPacketBytes,
      openJsonLengthBytes.length + openJsonBytes.length,
      aesEncryptedInnerPacket.length);

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
