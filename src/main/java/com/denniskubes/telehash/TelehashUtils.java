package com.denniskubes.telehash;

import java.io.IOException;
import java.io.StringReader;

import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.jce.provider.JCERSAPublicKey;
import org.bouncycastle.openssl.PEMReader;

public class TelehashUtils {

  public static String getHashname(String publicKeyPem)
    throws IOException {
    PEMReader pemReader = new PEMReader(new StringReader(publicKeyPem));
    JCERSAPublicKey publicKey = (JCERSAPublicKey)pemReader.readObject();
    byte[] publicKeyBytes = publicKey.getEncoded();
    return DigestUtils.sha256Hex(publicKeyBytes);
  }
}
