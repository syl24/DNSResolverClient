package ca.ubc.cs.cs317.dnslookup;
import java.util.*;


public class Bytehelper {
    private final static char[] hexArray = "0123456789ABCDEF".toCharArray();
    private static final int MAX_SEND_SIZE = 512; // max number of bytes to send


    public  Bytehelper() {
    }
     // https://www.tutorialspoint.com/convert-hex-string-to-byte-array-in-java
 public static byte[] hexStringToByteArray(String str) {
   String query_message = str.replace(" ", "").replace("\n", ""); // guard
  byte[] val = new byte[query_message.length() / 2];
  for (int i = 0; i < val.length && i < MAX_SEND_SIZE; i++) {
   int index = i * 2;
   int j = Integer.parseInt(query_message.substring(index, index + 2), 16);
   val[i] = (byte) j;
  }
  return val;
 }

 public static String bytesToHex(byte[] bytes) {
    char[] hexChars = new char[bytes.length * 2];
    for ( int j = 0; j < bytes.length; j++ ) {
        int v = bytes[j] & 0xFF;
        hexChars[j * 2] = hexArray[v >>> 4];
        hexChars[j * 2 + 1] = hexArray[v & 0x0F];
    }
    return new String(hexChars);
}

// eliminate trailing 0s of  byte array
// https://stackoverflow.com/questions/17003164/byte-array-with-padding-of-null-bytes-at-the-end-how-to-efficiently-copy-to-sma
public static byte[] byteTrim(byte[] bytes)
{
    int i = bytes.length - 1;
    while (i >= 0 && bytes[i] == 0)
    {
        --i;
    }
    // keep last 0 byte ??? // TODO make + 2
    return Arrays.copyOf(bytes, i + 1);
}
}