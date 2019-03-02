package ca.ubc.cs.cs317.dnslookup;
import java.util.*;


/**
  * @return
* A Bytehelper object with helper functions dealing with byte to string conversion and vice-versa

*/
public class Bytehelper {
 private final static char[] hexArray = "0123456789ABCDEF".toCharArray();
 private static final int MAX_SEND_SIZE = 512; // max number of bytes to send


 public Bytehelper() {}
 /**
  * @return
  * Convert a hex string to byte[]
  * @param str A hex string without a leading 0x (E.g 03CEAB05)
  */
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
 /**
  * @return
  * Convert a byte[] to a hex string without a leading 0x
  * @param bytes A byte[]
  */
 public static String bytesToHex(byte[] bytes) {
  char[] hexChars = new char[bytes.length * 2];
  for (int j = 0; j < bytes.length; j++) {
   int v = bytes[j] & 0xFF;
   hexChars[j * 2] = hexArray[v >>> 4];
   hexChars[j * 2 + 1] = hexArray[v & 0x0F];
  }
  return new String(hexChars);
 }

 /**
  * @return return a byte[] of the num bytes read from input bytes parameter
  *
  * @param start an int representing the offset from where in the bytes (byte[]) you want to start reading from
  * @param num the number of bytes you want to read
  * @param bytes The source byte[] you want to read bytes from
  */
 public static byte[] readBytes(int start, int num, byte[] bytes) {
  int i = 0;
  byte[] resBytes = new byte[num];
  while (i < num && start < bytes.length) {
   resBytes[i] = bytes[start];
   i++;
   start++;
  }
  return resBytes;
 }

 // eliminate trailing 0s of  byte array
 // https://stackoverflow.com/questions/17003164/byte-array-with-padding-of-null-bytes-at-the-end-how-to-efficiently-copy-to-sma
 /**
  * @return
  *    returns a byte[] with trailing null (0 bytes) removed
  * @param bytes A byte[]
  */
 public static byte[] byteTrim(byte[] bytes) {
  int i = bytes.length - 1;
  while (i >= 0 && bytes[i] == 0) {
   --i;
  }
  // keep last 0 byte ??? // TODO make + 2
  return Arrays.copyOf(bytes, i + 1);
 }
}