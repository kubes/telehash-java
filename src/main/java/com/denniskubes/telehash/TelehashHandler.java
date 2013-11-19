package com.denniskubes.telehash;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.socket.DatagramPacket;

import java.io.File;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.PrivateKey;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang.StringUtils;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.util.encoders.Base64;
import org.codehaus.jackson.JsonNode;

public class TelehashHandler
  extends SimpleChannelInboundHandler<DatagramPacket> {

  @Override
  public void channelRead0(ChannelHandlerContext ctx, DatagramPacket packet)
    throws Exception {

    // get the seed's RSA public and private key
    File pubKeyFile = new File(
      "/home/dennis/Projects/telehash/keys/seed-public.key");
    File privKeyFile = new File(
      "/home/dennis/Projects/telehash/keys/seed-private.key");
    RSAKeyPairManager seedRSA = new RSAKeyPairManager(pubKeyFile, privKeyFile);

    ByteBuf buff = packet.content();
    if (!buff.isReadable()) {
      return;
    }

    // get the json bytes
    int jsonLength = (int)buff.readShort();
    byte[] jsonBytes = new byte[jsonLength];
    buff.readBytes(jsonBytes);

    // get the reset of the bytes which is the body
    byte[] bodyBytes = new byte[buff.readableBytes()];
    buff.readBytes(bodyBytes);

    String json = new String(jsonBytes);
    JsonNode root = JSON.parse(json);

    String type = JSON.getString(root, "type");
    if (StringUtils.equalsIgnoreCase(type, "open")) {

      String iv = JSON.getString(root, "iv");
      String open = JSON.getString(root, "open");
      String sig = JSON.getString(root, "sig");
      Hex hex = new Hex();

      // base64 decode the open value
      byte[] openBase64 = Base64.decode(open);     

      // decrypt the open value which is the senders ecc public key
      String seedPrivatePEM = FileUtils.readFileToString(privKeyFile);
      PrivateKey seedPrivateKey = TelehashUtils.getRSAPrivateKeyFromPemString(seedPrivatePEM);
      AsymmetricKeyParameter param = PrivateKeyFactory.createKey(seedPrivateKey.getEncoded());
      AsymmetricBlockCipher cipher = new OAEPEncoding(new RSAEngine(),
        new SHA1Digest());
      cipher.init(false, param);      
      byte[] rsaDecrypted = cipher.processBlock(openBase64, 0, openBase64.length);
      
      // create the inner packet AES decryption key
      Cipher aesInnerCipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
      byte[] eccInnerSha256 = DigestUtils.sha256(rsaDecrypted);
      Key aesInnerKey = new SecretKeySpec(eccInnerSha256, "AES");
      byte[] salt = hex.decode(iv.getBytes());
      aesInnerCipher.init(Cipher.DECRYPT_MODE, aesInnerKey, new IvParameterSpec(
        salt));
      byte[] aesEncryptedInnerPacket = aesInnerCipher.doFinal(bodyBytes);
      
      ByteBuffer packetBuffer = ByteBuffer.wrap(aesEncryptedInnerPacket);
      short openJsonLength = packetBuffer.getShort();
      byte[] openJson = new byte[openJsonLength];
      packetBuffer.get(openJson);
      System.out.println(new String(openJson));

    }

  }

  @Override
  public void channelReadComplete(ChannelHandlerContext ctx)
    throws Exception {
    ctx.flush();
  }

  @Override
  public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause)
    throws Exception {
    cause.printStackTrace();
    // We don't close the channel because we can keep serving requests.
  }
}
