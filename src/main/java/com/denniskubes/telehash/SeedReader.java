package com.denniskubes.telehash;

import java.io.File;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

import org.apache.commons.io.FileUtils;
import org.codehaus.jackson.JsonNode;
import org.codehaus.jackson.node.ArrayNode;

public class SeedReader {

  private Map<String, Seed> seeds = new LinkedHashMap<String, Seed>();

  public SeedReader(File seedsFile)
    throws IOException {

    JsonNode root = JSON.parse(FileUtils.readFileToString(seedsFile));
    if (root != null && !root.isNull() && root instanceof ArrayNode) {
      for (JsonNode curNode : (ArrayNode)root) {
        String host = JSON.getString(curNode, "ip");
        int port = JSON.getInt(curNode, "port");
        String publicKey = JSON.getString(curNode, "pubkey");
        Seed seed = new Seed(host, port, publicKey);
        seeds.put(TelehashUtils.getHashname(publicKey), seed);
      }
    }
  }

  public Seed getSeed(String hashname) {
    return seeds.get(hashname);
  }
}
