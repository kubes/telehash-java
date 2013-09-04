package com.denniskubes.telehash;

import java.io.StringReader;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang.StringUtils;
import org.codehaus.jackson.JsonGenerator;
import org.codehaus.jackson.JsonNode;
import org.codehaus.jackson.JsonParser;
import org.codehaus.jackson.map.MappingJsonFactory;
import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.node.ArrayNode;
import org.codehaus.jackson.node.BooleanNode;
import org.codehaus.jackson.node.DoubleNode;
import org.codehaus.jackson.node.NumericNode;
import org.codehaus.jackson.node.TextNode;

/**
 * Utility methods for parsing JSON strings and getting values.
 */
public class JSON {

  /**
   * Returns true if the string look like a valid JSON string, starting and
   * ending with either squiggly or square brackets.
   * 
   * @param content The JSON string to check.
   * 
   * @return True if the string looks like a valid JSON string.
   */
  public static boolean looksLikeJson(String content) {

    String trimmed = content.trim();
    boolean squiggs = trimmed.startsWith("{") && trimmed.endsWith("}");
    boolean square = trimmed.startsWith("[") && trimmed.endsWith("]");

    return squiggs || square;
  }

  /**
   * Parses the JSON string into a tree of JsonNode objects.
   * 
   * @param json The JSON string to parse.
   * 
   * @return The root of a tree of JsonNode objects.
   */
  public static JsonNode parse(String json) {

    ObjectMapper mapper = new ObjectMapper();
    JsonNode root = null;
    try {
      root = mapper.readValue(new StringReader(json), JsonNode.class);
      return root;
    }
    catch (Exception e) {
      return null;
    }
  }

  /**
   * Parses the JSON string into a Map.  The Jackson JSON parser will parse
   * value into common types.
   * 
   * @param json The JSON string to parse.
   * 
   * @return The root of a tree of objects.
   */
  public static Map<String, Object> parseToMap(String json) {

    ObjectMapper mapper = new ObjectMapper();
    Map root = null;
    try {
      root = mapper.readValue(new StringReader(json), Map.class);
    }
    catch (Exception e) {
      return null;
    }
    return root;
  }

  public static String serializeToJson(Object object) {

    try {

      StringWriter sw = new StringWriter();
      ObjectMapper mapper = new ObjectMapper();
      MappingJsonFactory jsonFactory = new MappingJsonFactory();
      JsonGenerator jsonGenerator = jsonFactory.createJsonGenerator(sw);
      mapper.writeValue(jsonGenerator, object);
      sw.close();

      return sw.toString();
    }
    catch (Exception e) {
      return null;
    }
  }

  public static Object deserializeFromJson(String json, Class valueType) {

    try {
      ObjectMapper mapper = new ObjectMapper();
      MappingJsonFactory jsonFactory = new MappingJsonFactory();
      JsonParser jsonParser = jsonFactory.createJsonParser(json);
      return mapper.readValue(jsonParser, valueType);
    }
    catch (Exception e) {
      return null;
    }
  }

  public static JsonNode getJsonNode(JsonNode parent, String field) {

    boolean parentNull = parent != null && !parent.isNull();
    return parentNull ? parent.get(field) : null;
  }

  public static List<JsonNode> getJsonNodes(JsonNode parent, String field) {

    JsonNode node = getJsonNode(parent, field);
    List<JsonNode> values = new ArrayList<JsonNode>();
    if (node != null && !node.isNull() && node instanceof ArrayNode) {
      for (JsonNode curNode : (ArrayNode)node) {
        values.add(curNode);
      }
    }
    return values;

  }

  public static String getString(JsonNode parent, String field) {
    return getString(parent, field, null);
  }

  public static String getString(JsonNode parent, String field,
    String defaultValue) {

    JsonNode node = getJsonNode(parent, field);
    if (node != null && !node.isNull() && node instanceof TextNode) {
      return node.asText();
    }
    return defaultValue;
  }

  public static List<String> getStrings(JsonNode parent, String field) {
    return getStrings(getJsonNode(parent, field));
  }

  public static List<String> getStrings(JsonNode node) {

    List<String> strVals = new ArrayList<String>();
    if (node != null && !node.isNull()) {
      if (node instanceof TextNode) {
        String val = ((TextNode)node).asText();
        if (StringUtils.isNotBlank(val)) {
          strVals.add(val);
        }
      }
      else if (node instanceof ArrayNode) {
        for (JsonNode curNode : (ArrayNode)node) {
          if (curNode instanceof TextNode) {
            String val = ((TextNode)curNode).asText();
            if (StringUtils.isNotBlank(val)) {
              strVals.add(val);
            }
          }
        }
      }
    }
    return strVals;
  }

  public static boolean getBoolean(JsonNode parent, String field) {
    return getBoolean(parent, field, false);
  }

  public static boolean getBoolean(JsonNode parent, String field,
    boolean defaultValue) {

    JsonNode node = getJsonNode(parent, field);
    if (node != null && !node.isNull() && node instanceof BooleanNode) {
      return node.getBooleanValue();
    }
    return defaultValue;
  }

  public static List<Boolean> getBooleans(JsonNode parent, String field) {
    return getBooleans(getJsonNode(parent, field));
  }

  public static List<Boolean> getBooleans(JsonNode node) {

    List<Boolean> boolVals = new ArrayList<Boolean>();
    if (node != null && !node.isNull()) {
      if (node instanceof BooleanNode) {
        boolVals.add(node.getBooleanValue());
      }
      else if (node instanceof ArrayNode) {
        for (JsonNode curNode : (ArrayNode)node) {
          if (curNode instanceof BooleanNode) {
            boolean val = ((BooleanNode)curNode).getBooleanValue();
            boolVals.add(val);
          }
        }
      }
    }
    return boolVals;
  }

  public static int getInt(JsonNode parent, String field) {
    return getInt(parent, field, 0);
  }

  public static int getInt(JsonNode parent, String field, int defaultValue) {

    JsonNode node = getJsonNode(parent, field);
    if (node != null && !node.isNull() && node instanceof NumericNode) {
      return node.getIntValue();
    }
    return defaultValue;
  }

  public static List<Integer> getInts(JsonNode parent, String field) {
    return getInts(getJsonNode(parent, field));
  }

  public static List<Integer> getInts(JsonNode node) {

    List<Integer> intVals = new ArrayList<Integer>();
    if (node != null && !node.isNull()) {
      if (node instanceof NumericNode) {
        intVals.add(node.getIntValue());
      }
      else if (node instanceof ArrayNode) {
        for (JsonNode curNode : (ArrayNode)node) {
          if (curNode instanceof NumericNode) {
            int val = ((NumericNode)curNode).getIntValue();
            intVals.add(val);
          }
        }
      }
    }
    return intVals;
  }

  public static long getLong(JsonNode parent, String field) {
    return getLong(parent, field, 0L);
  }

  public static long getLong(JsonNode parent, String field, long defaultValue) {

    JsonNode node = getJsonNode(parent, field);
    if (node != null && !node.isNull() && node instanceof NumericNode) {
      return node.getLongValue();
    }
    return defaultValue;
  }

  public static List<Long> getLongs(JsonNode parent, String field) {
    return getLongs(getJsonNode(parent, field));
  }
  
  public static List<Long> getLongs(JsonNode node) {

    List<Long> longVals = new ArrayList<Long>();
    if (node != null && !node.isNull()) {
      if (node instanceof NumericNode) {
        longVals.add(node.getLongValue());
      }
      else if (node instanceof ArrayNode) {
        for (JsonNode curNode : (ArrayNode)node) {
          if (curNode instanceof NumericNode) {
            long val = ((NumericNode)curNode).getLongValue();
            longVals.add(val);
          }
        }
      }
    }
    return longVals;
  }

  public static double getDouble(JsonNode parent, String field) {
    return getDouble(parent, field, 0.0d);
  }

  public static double getDouble(JsonNode parent, String field,
    double defaultValue) {

    JsonNode node = getJsonNode(parent, field);
    if (node != null && !node.isNull() && node instanceof DoubleNode) {
      return node.getDoubleValue();
    }
    return defaultValue;
  }

  public static List<Double> getDoubles(JsonNode parent, String field) {
    return getDoubles(getJsonNode(parent, field));
  }
  
  public static List<Double> getDoubles(JsonNode node) {

    List<Double> doubleVals = new ArrayList<Double>();
    if (node != null && !node.isNull()) {
      if (node instanceof DoubleNode) {
        doubleVals.add(node.getDoubleValue());
      }
      else if (node instanceof ArrayNode) {
        for (JsonNode curNode : (ArrayNode)node) {
          if (curNode instanceof DoubleNode) {
            double val = ((DoubleNode)curNode).getDoubleValue();
            doubleVals.add(val);
          }
        }
      }
    }
    return doubleVals;
  }

  public static List<String> getFieldnames(JsonNode parent) {

    List<String> fieldnames = new ArrayList<String>();
    if (parent != null && !parent.isNull()) {
      Iterator<String> fieldnameIt = parent.getFieldNames();
      while (fieldnameIt.hasNext()) {
        String fieldName = fieldnameIt.next();
        fieldnames.add(fieldName);
      }
    }
    return fieldnames;
  }

  public static Map<String, JsonNode> getFields(JsonNode parent) {

    Map<String, JsonNode> fields = new LinkedHashMap<String, JsonNode>();
    if (parent != null && !parent.isNull()) {
      Iterator<String> fieldnameIt = parent.getFieldNames();
      while (fieldnameIt.hasNext()) {
        String fieldname = fieldnameIt.next();
        fields.put(fieldname, parent.get(fieldname));
      }
    }
    return fields;
  }

}