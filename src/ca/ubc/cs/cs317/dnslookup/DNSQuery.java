package ca.ubc.cs.cs317.dnslookup;
import java.util.regex.Pattern;
import java.net.InetAddress;
import java.util.*;

public class DNSQuery {
 String queryString;
 InetAddress DNSIA;  // ip address of DNS the message being sent to
 String lookupName;
 String type; // QType
 String transID;


 public DNSQuery(DNSNode node) {
  headerFormat header = new headerFormat();
  RecordType type = node.getType();
  int code = type.getCode();
  String hostString = node.getHostName();
  QuestionFormat question = new QuestionFormat(hostString, code);
  this.type = Integer.toString(code);
  this.lookupName = hostString;
  this.transID = Integer.toHexString(header.id);
  this.queryString = header.headerString + question.questionHeader;
 };
 private static class headerFormat {
  private static int ID_MAX = 65535;
  private static int ID_MIN = 0;
  int id;
  byte rd;
  byte tc;
  byte aa;
  byte qr;
  byte opcode;
  byte rcode;
  byte z;
  byte ra;
  short qdcount;
  short ancount;
  short nscount;
  short arcount;
  String headerString;
  public headerFormat() {
   this.id = idGenerator();
   this.rd = 1; // TODO should be 0 but for now make 1
   this.opcode = 0;
   this.qr = 0;
   this.ra = 0;
   this.z = 0;
   this.rcode = 0;
   this.qdcount = 1; //TODO ? only ever sending one question
   this.ancount = 0;
   this.nscount = 0;
   this.arcount = 0;
   this.headerString = headerToHex();
  }

  private int idGenerator() {
   Random r = new Random();
   return r.nextInt((ID_MAX - ID_MIN) + 1) + ID_MIN;
  }

  private String headerToHex() {
   String headerString = String.format("%02X", this.id);
   int queryParams1 = this.qr + this.opcode + this.aa + this.tc + this.rd;
   int queryParams2 = this.ra + this.z + this.rcode;
   headerString += Integer.toHexString(queryParams1);
   headerString += Integer.toHexString(queryParams2);
   headerString += String.format("%04X", qdcount); // qdcount two bytes
   headerString += String.format("%04X", ancount); // two bytes
   headerString += String.format("%04X", nscount); //two bytes
   headerString += String.format("%04X", arcount);
   return headerString;
  }
 }

 private static class QuestionFormat {
  String qname;
  int qtype;
  short qclass;
  String questionHeader;

  public QuestionFormat(String lookupString, int typeCode) {
   String qString = formatQName(lookupString);
   this.qname = qString;
   this.qtype = typeCode;
   this.qclass = 1; // TODO // internet class
   this.questionHeader = qString + String.format("%04X", this.qtype) + String.format("%04X", this.qclass);
  }

  private String formatQName(String lookupString) {
   String qString = "";
   String[] strArr = lookupString.split(Pattern.quote("."));
   for (String str: strArr) {
    int len = str.length();
    String hexLen = String.format("%02X", ((int) len));
    qString += hexLen;
    for (int j = 0; j < len; j++) {
     char character = str.charAt(j);
     String hexChar = String.format("%02X", (int) character);
     qString += hexChar;
    }
   }
   qString += "00";
   return qString;
  }
 }
}