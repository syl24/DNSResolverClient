package ca.ubc.cs.cs317.dnslookup;
import java.util.regex.Pattern;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.Buffer.*;
import java.nio.ByteBuffer;
import java.util.*;


/**
    * @return
  * A DNSQuery object with the following attributes <p>
  * queryString (String): The raw hex string format of the encoded message to send to the DNS server. The queryString DOES NOT begin with 0x <p>
  * DNSIA (InetAddress): The inetaddress of the DNS server the message is being sent to <p>
  * lookupName (String):  The domain name being queried <p>
  * type (String): The Question type in the string form of decimal number <p>
    * transID (String): The transaction ID <p>

  * @param node  a DNSNode
  */
public class DNSQuery {
 String queryString;
 InetAddress DNSIA; // ip address of DNS the message being sent to
 String lookupName;
 String type; // QType
 String transID;


 public DNSQuery(DNSNode node) {
  ByteArrayOutputStream queryStream = new ByteArrayOutputStream();
  RecordType type = node.getType();
  int code = type.getCode();
  String hostString = node.getHostName();
  headerFormat header = new headerFormat();
  QuestionFormat questionHeader = new QuestionFormat(hostString, code);
  try {
   queryStream.write(header.headerBytes);
   queryStream.write(questionHeader.QuestionBytes);
  } catch (IOException er) {
   // TODO
  }
  byte[] dnsQueryBytes = queryStream.toByteArray();
  this.type = Integer.toString(code);
  this.lookupName = hostString;
  this.transID = header.id;
  this.queryString = Bytehelper.bytesToHex(dnsQueryBytes);
 };

 /**
  * @return
  * A Class to create header object with the following attributes <p>
  * headerBytes (byte[]): A byte[] of all the bytes corresponding to the header <p>
  * id (String): The transaction id in hex String format <p>
  * @param node  a DNSNode
  */
 private static class headerFormat {
  byte[] headerBytes;
  private static int HEADER_SIZE = 12;
  String id;
  public headerFormat() {
   createRequestHeader();
  }
  private void createRequestHeader() {
   ByteBuffer header = ByteBuffer.allocate(HEADER_SIZE);
   byte[] randomID = new byte[2];
   new Random().nextBytes(randomID);
   this.id = Bytehelper.bytesToHex(randomID);
   header.put(randomID);
   header.put((byte) 0x00); // 1st half of flags (0000 0000) (norecursion chnge right most bit to 1 if you want) HARDCODED FLAGS
   header.put((byte) 0x00); // 2nd half of flags (0000 0000) HARDCODED FLAGS
   header.put((byte) 0x00); // HARDCODED
   header.put((byte) 0x01); // numbe of questions HARDCODED
   // lines 3, 4, and 5 will be all 0s, which is what we want (ANCount, ARCOunt, NSCount)
   this.headerBytes = header.array();
  }
 }
 /**
  * Class to create Question Header
  * @return
  * A QuestionFormat object with the following attributes <p>
  *  QuestionBytes (byte[]): the bytes corresponding to the Question Header
  * @param lookupString the domain name (string) you are trying to query.
  * @param type     Record type for search.
  */
 private static class QuestionFormat {
  private ByteArrayOutputStream questionOutputStream = new ByteArrayOutputStream();
  private byte[] qname;
  private byte[] qtype; // q type 
  private int QName_Size = 0; // TODO?
  private static final byte[] qclass = Bytehelper.hexStringToByteArray("0001"); //internet class HARDCODED
  byte[] QuestionBytes;

  public QuestionFormat(String lookupString, int typeCode) {
   String qString = formatQName(lookupString);
   this.qname = Bytehelper.hexStringToByteArray(qString);
   try {
    questionOutputStream.write(this.qname);
    this.qtype = getQTypeBytes(typeCode);
    questionOutputStream.write(this.qtype);
    // System.out.println("Qtype string: " + Bytehelper.bytesToHex(this.qtype));
    questionOutputStream.write(this.qclass);
    // System.out.println("QClss string: " + Bytehelper.bytesToHex(this.qclass));
    this.QuestionBytes = questionOutputStream.toByteArray();
    // System.out.println(Bytehelper.bytesToHex(this.QuestionBytes));
   } catch (IOException err) {
    // TODO
   }
  }

  /**
   *  @return return a byte[] corresponding to the QType of interest (E.g typeCode of 1 produces a byte[] with byte[0] = 0x0 byte[1] = 0x1)
   *
   * @param typeCode the QType you want
   */
  private byte[] getQTypeBytes(int typeCode) {
   byte[] qTypeBytes = new byte[2];
   switch (typeCode) {
    // A record
    case 1:
     qTypeBytes[0] = 0x0;
     qTypeBytes[1] = 0x1;
     break;
     // NS Record
    case 2:
     qTypeBytes[0] = 0x0;
     qTypeBytes[1] = 0x2;
     break;
     // CNAME record
    case 5:
     qTypeBytes[0] = 0x0;
     qTypeBytes[1] = 0x5;
     break;
     // AAAA record
    case 28:
     qTypeBytes[0] = 0x0;
     qTypeBytes[1] = 0x1C;
     break;

    default:
     // TODO shouldnt reach here unless typeCode specified is not A, AAAA, CNAME, NS
     throw new RuntimeException("Type code not supported " + typeCode);
   }
   return qTypeBytes;
  }

  /**
   * @return 
   * format the domain name string to QName format. (E.g www.apple.com will be translated to the string 03 77 77 77  05 61 70 70 6C 65 03 63 6F 6D )
   * without the spaces (spaces are shown for readability)
   *
   * @param lookupString  domain name being searched.
   */
  private String formatQName(String lookupString) {
   String qString = "";
   String[] strArr = lookupString.split(Pattern.quote("."));
   for (String str: strArr) {
    int len = str.length();
    String hexLen = String.format("%02X", ((int) len));
    qString += hexLen;
    this.QName_Size++;
    for (int j = 0; j < len; j++) {
     char character = str.charAt(j);
     String hexChar = String.format("%02X", (int) character);
     qString += hexChar;
     this.QName_Size++;
    }
   }
   qString += "00"; // terminating byte
   this.QName_Size++;
   return qString;
  }
 }

 /**
  * @return 
  * The string translation of decimal type code (E.g 1  returns "A")
  *
  * @param i  The decimal form of the type code of interest (E.g 1 is an A record)
  */
 public String convertType(int i) {
  switch (i) {
   case 1:
    return "A";
   case 2:
    return "NS";
   case 5:
    return "CNAME";
   case 6:
    return "SOA";
   case 11:
    return "WKS";
   case 12:
    return "PTR";
   case 15:
    return "MX";
   case 33:
    return "SRV";
   case 28:
    return "AAAA";
   default:
    System.out.println("Unsupported type supplied, default to A");
    return "A"; // unsupported type supplied
  }
 }
}