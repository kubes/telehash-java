package com.denniskubes.telehash;

import java.io.File;
import java.nio.ByteBuffer;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Random;

import org.apache.commons.codec.binary.Hex;
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

public class OpenPacketSender {

  public static void main(String[] args)
    throws Exception {

    String hashname = "5fa6f146d784c9ae6f6d762fbc56761d472f3d097dfba3915c890eec9b79a088";
    File pubKeyFile = new File("/home/dennis/Projects/telehash/keys/sender-pub.key");
    File privKeyFile = new File("/home/dennis/Projects/telehash/keys/sender-priv.key");
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
    
    byte[] lineBytes = new byte[16];
    Random rand = new Random();
    rand.nextBytes(lineBytes);
    Hex hex = new Hex();
    String line = new String(hex.encode(lineBytes));
    
    Map<String, Object> packetValues = new LinkedHashMap<String, Object>();
    packetValues.put("to", hashname);
    packetValues.put("at", System.currentTimeMillis());
    packetValues.put("line", line);
    String packetJson = JSON.serializeToJson(packetValues);
    byte[] jsonBytes = packetJson.getBytes();
    
    byte[] senderPubBytes = TelehashUtils.getPublicKeyDER(manager.getPublicKeyPem());
    int totalBytes = 2 + jsonBytes.length + senderPubBytes.length;
    byte[] packetBytes = new byte[totalBytes];   
    
    byte[] jsonLengthBytes = ByteBuffer.allocate(2).putShort((short)jsonBytes.length).array();
    System.arraycopy(jsonLengthBytes, 0, packetBytes, 0, packetBytes.length);
    System.arraycopy(jsonBytes, 0, packetBytes, packetBytes.length, jsonBytes.length);
    System.arraycopy(senderPubBytes, 0, packetBytes, packetBytes.length + jsonBytes.length, senderPubBytes.length);
    
    
    
    
  }
}
