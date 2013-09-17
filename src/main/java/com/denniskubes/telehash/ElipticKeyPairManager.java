package com.denniskubes.telehash;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.JCEECPublicKey;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;

public class ElipticKeyPairManager {

  private KeyPair eccKeyPair = null;
  
  private byte[] formatKey(BigInteger x, BigInteger y) {
    
    byte[] xBytes = BigIntegers.asUnsignedByteArray(x);
    byte[] yBytes = BigIntegers.asUnsignedByteArray(y);
    
    byte[] pubKeyBytes = new byte[65];
    pubKeyBytes[0] = 0x04;
    System.arraycopy(xBytes, 0, pubKeyBytes, 1, xBytes.length);
    System.arraycopy(yBytes, 0, pubKeyBytes, 1 + xBytes.length, yBytes.length);
    
    return pubKeyBytes;
  }

  public ElipticKeyPairManager()
    throws Exception {

    Security.addProvider(new BouncyCastleProvider());
    ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("secp256r1");
    KeyPairGenerator generator = KeyPairGenerator.getInstance("ECDH", "BC");
    generator.initialize(ecGenSpec, new SecureRandom());
    eccKeyPair = generator.generateKeyPair();
  }

  public byte[] getUncompressedPublicKey() {
    
    JCEECPublicKey pubKey = (JCEECPublicKey)eccKeyPair.getPublic();
    pubKey.setPointFormat("UNCOMPRESSED");
    ECPoint qPoint = pubKey.getQ();
    return formatKey(qPoint.getX().toBigInteger(), qPoint.getY().toBigInteger());
  }
  
  public KeyPair getEccKeyPair() {
    return eccKeyPair;
  }
  

  public static void main(String[] args)
    throws Exception {
    
    ElipticKeyPairManager kpMan = new ElipticKeyPairManager();
    byte[] ucPubKey = kpMan.getUncompressedPublicKey();

    Hex hex = new Hex();
    System.out.println(ucPubKey.length);
    System.out.println(new String(hex.encode(ucPubKey)));

  }

}
