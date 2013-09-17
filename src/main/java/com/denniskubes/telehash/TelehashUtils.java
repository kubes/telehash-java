package com.denniskubes.telehash;

import java.io.IOException;
import java.io.StringReader;

import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.jce.provider.JCERSAPublicKey;
import org.bouncycastle.openssl.PEMReader;

public class TelehashUtils {

  public static JCERSAPublicKey getRSAPublicKeyFromPemString(String publicKeyPEM)
    throws IOException {
    PEMReader pemReader = new PEMReader(new StringReader(publicKeyPEM));
    return (JCERSAPublicKey)pemReader.readObject();
  }

  public static String getHashname(String publicKeyPEM)
    throws IOException {
    return DigestUtils.sha256Hex(getPublicKeyDER(publicKeyPEM));
  }

  public static byte[] getPublicKeyDER(String publicKeyPEM)
    throws IOException {
    JCERSAPublicKey publicKey = TelehashUtils.getRSAPublicKeyFromPemString(publicKeyPEM);
    return publicKey.getEncoded();
  }
}
