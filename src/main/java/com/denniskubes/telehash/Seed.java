package com.denniskubes.telehash;

import java.io.Serializable;

import org.apache.commons.lang.builder.EqualsBuilder;
import org.apache.commons.lang.builder.HashCodeBuilder;
import org.apache.commons.lang.builder.ToStringBuilder;

public class Seed
  implements Serializable, Cloneable {

  private String publicKeyPem;
  private String host;
  private int port;

  public Seed(String host, int port, String publicKeyPem) {
    this.host = host;
    this.port = port;
    this.publicKeyPem = publicKeyPem;
  }

  public String getPublicKeyPem() {
    return publicKeyPem;
  }

  public String getHost() {
    return host;
  }

  public int getPort() {
    return port;
  }

  public Object clone()
      throws CloneNotSupportedException {
      return super.clone();
    }

    public String toString() {
      return ToStringBuilder.reflectionToString(this);
    }

    public boolean equals(Object obj) {
      return EqualsBuilder.reflectionEquals(this, obj);
    }

    public int hashCode() {
      return HashCodeBuilder.reflectionHashCode(this);
    }
    
}
