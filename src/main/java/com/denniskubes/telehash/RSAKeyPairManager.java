package com.denniskubes.telehash;

import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.JCERSAPublicKey;
import org.bouncycastle.jce.provider.JDKKeyPairGenerator;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.openssl.PEMWriter;

public class RSAKeyPairManager {

  private File publicKeyFile = null;
  private File privateKeyFile = null;
  private String publicKeyPem = null;
  private String privateKeyPem = null;

  private void generateAndSaveKeys()
    throws IOException {

    // generate a 2048 bit key pair
    JDKKeyPairGenerator.RSA keyPairGen = new JDKKeyPairGenerator.RSA();
    keyPairGen.initialize(2048);
    KeyPair keyPair = keyPairGen.generateKeyPair();

    // write the public key to a file
    StringWriter publicKeyWriter = new StringWriter();
    PEMWriter publicPemWriter = new PEMWriter(publicKeyWriter);
    publicPemWriter.writeObject(keyPair.getPublic());
    publicPemWriter.close();
    publicKeyPem = publicKeyWriter.toString();
    publicKeyWriter.close();
    FileUtils.writeStringToFile(publicKeyFile, publicKeyPem);

    // write the private key to a file
    StringWriter privateKeyWriter = new StringWriter();
    PEMWriter privatePemWriter = new PEMWriter(privateKeyWriter);
    privatePemWriter.writeObject(keyPair.getPrivate());
    privatePemWriter.close();
    privateKeyPem = privateKeyWriter.toString();
    privateKeyWriter.close();
    FileUtils.writeStringToFile(privateKeyFile, privateKeyPem);
  }

  public RSAKeyPairManager(File publicKeyFile, File privateKeyFile)
    throws IOException {

    Security.addProvider(new BouncyCastleProvider());
    this.publicKeyFile = publicKeyFile;
    this.privateKeyFile = privateKeyFile;

    if (publicKeyFile.exists() && privateKeyFile.exists()) {
      publicKeyPem = FileUtils.readFileToString(publicKeyFile);
      privateKeyPem = FileUtils.readFileToString(privateKeyFile);
    }
    else {
      generateAndSaveKeys();
    }
  }

  public PublicKey getPublicKey()
    throws IOException {
    PEMReader pemReader = new PEMReader(new StringReader(publicKeyPem));
    return (PublicKey)pemReader.readObject();
  }

  public PrivateKey getPrivateKey()
    throws IOException {
    PEMReader pemReader = new PEMReader(new StringReader(privateKeyPem));
    return ((KeyPair)pemReader.readObject()).getPrivate();
  }

  public String getPublicKeyPem() {
    return publicKeyPem;
  }

  public String getPrivateKeyPem() {
    return privateKeyPem;
  }

}
