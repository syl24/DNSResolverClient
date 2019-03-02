package ca.ubc.cs.cs317.dnslookup;
import java.util.regex.Pattern;
import java.util.stream.*;

import javax.management.RuntimeErrorException;
import java.nio.ByteBuffer;

import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.*;


/**
  *  @return A DNSResponse Object contains the following attributes <p>
  * responseID (String): The id of the response as a hex String <p>
  * lookupName (String): The domain name being searched <p>
  * Rcode (int): The decimal value of RCode <p>
  * serversToQueryArr (String): A list of servers to query (A records) <p>
  * authFlag (String): Easier for output in DNSLookupservice. The value is true or false if Authoritative <p>
  * isPacketDrooped (boolean): Flag to determine if the packet has been dropped when max reattempts reached. Look at send_udp_message <p>
  * isAuth (boolean):  boolean for Authoritative <p>
    * queryNSFlag (String): flag to determine whether or not to query nameservers as dead end reached <p>
  * validAuthFlag (String): determine if the authorative response is valid <p>
  * numAnswers (String): number of records in Nameserver section <p>
  * numNameServers (String): number of records in Nameserver section <p>
  * numAddInfo (String): number of records in Additional Info section <p>
  * numARecords (String): Number of A records in response <p>
  * numNSRecords (String): Number of NS records in response <p>
  * <type>Records are a List of HashMaps, which represents a list of records in the <type> section, 
  where each record is in the format of HashMap<String, String> with keys rdata, name, ttl, class, rtype <p>
  * answerRecords (List<Map<String, String>>):  <p>
  * nameRecords (List<Map<String, String>>): <p>
    * addRecords (List<Map<String, String>>):  <p>
  * aRecords (List<Map<String, String>>): <p>
  * nsRecords (List<Map<String, String>>): <p>
  * 
  * @param responseBuffer the response buffer received from the datagram
  */
public class DNSResponse {
 private final static int HEADER_SIZE = 12; // header size in number of bytes
 private byte[] responseBuffer;
 String responseID;
 String lookupName;
 // String queryType;
 int RCode;
 boolean isPacketDropped; // flag to determine if max number of tries of resends reached (for send_udp_message)
 List < String > serversToQueryArr = new ArrayList < String > (); // listof servers to query based on name servers with corresponding ip addresses from additional info
 String authFlag; // for outputting in DNSLookupService
 boolean isAuth; // boolean for simplicity
 boolean queryNSFlag; // flag to determine whether or not to query nameservers as dead end reached
 boolean validAuthFlag; // determine if the authorative response is valid
 int numAnswers; // number of records in answer section
 int numNameservers; // number of records in Nameserver section
 int numAddInfo; // number of records in Additional Info section
 int numARecords; // number of A records in response
 int numNSRecords; // number of NS records in response
 List < Map < String, String >> answerRecords = new ArrayList < Map < String, String >> ();
 List < Map < String, String >> nameRecords = new ArrayList < Map < String, String >> ();
 List < Map < String, String >> addRecords = new ArrayList < Map < String, String >> ();
 List < Map < String, String >> aRecords = new ArrayList < > ();
 List < Map < String, String >> nsRecords = new ArrayList < > ();

 private final HashMap < Integer, Boolean > typesSupported = new HashMap();
 private int currAddr = 0; // starting offset
 public DNSResponse(byte[] responseBuffer) {
  if (responseBuffer.length < 1) {
   this.isPacketDropped = true;
   // if empty buffer passed in return
   return;
  }
  this.isPacketDropped = false;
  this.responseBuffer = responseBuffer;
  populateTypesSupported();
  // System.out.println("Response buffer length: " + this.responseBuffer.length);
  byte[] headerArr = extractHeaderBytes();
  parseHeader parsedHeader = new parseHeader(headerArr);
  this.RCode = parsedHeader.RCode;
  this.responseID = parsedHeader.transID;
  this.numAnswers = parsedHeader.ANCount;
  this.numNameservers = parsedHeader.NSCount;
  this.numAddInfo = parsedHeader.ARCount;

  // ("responseID: " + parsedHeader.transID);
  // System.out.println("authBool: " + parsedHeader.authBool);
  // System.out.println("RCode: " + parsedHeader.RCode);
  // System.out.println("QDCount: " + parsedHeader.QDCount);
  // System.out.println("ANCount: " + this.numAnswers);
  // System.out.println("NSCount: " + this.numNameservers);
  // System.out.println("ARCount: " + this.numAddInfo);
  parseQuestion parsedQuestion = new parseQuestion();
  this.answerRecords = getResourceRecordsInfo("answer");
  this.nameRecords = getResourceRecordsInfo("nameserver");
  this.addRecords = getResourceRecordsInfo("additional");
  this.isAuth = isAuthResponse();
  if (this.isAuth) {
   validateAuthResponse();
  } else {
   // if not authoratative answer get servers to query
   // guard against when no servers left to query (no addRecords) terminate
   setQueryNSFlag();
   getServersToQuery();
   // printServerArr();
  }
  getAandNSRecords(1);
  getAandNSRecords(2);
  getAandNSRecords(3);
  // printRecordListVals(this.nameRecords);
  // printRecordListVals(this.addRecords);
  // System.out.println("answer record size: " + this.answerRecords.size());
  // System.out.println("name record size: " + this.nameRecords.size());
  // System.out.println("add record size: " + this.addRecords.size());
 };

 /**
  * @return A parseHeader has the following attributes <p>
  * headerArr (byte[]) : An byte[] of the extracted bytes corresponding to the header section <p>
  * transID (String) : The transaction ID as a hex String <p>
  * authBool (int) : Flag if response is from Auth server <p>
  * ANCount (byte[]) : Number of records in answer section in response <p>
  * NSCount (byte[]) : Number of records in Nameserver section in response <p>
  * ARCount (byte[]) : Number of records in Additional Info section in response <p>
  * QDCount (byte[]) : Number of records in Question section in response <p>
  * RCode (byte[]) : RCode as decimal
  */
 private class parseHeader {
  private final static int FLAGS_SIZE = 2; // two bytes
  private final static int ID_SIZE = 2;
  private final static int QD_SIZE = 2;
  private final static int AN_SIZE = 2;
  private final static int NS_SIZE = 2;
  private final static int AR_SIZE = 2;

  byte[] headerArr;
  String transID;
  int authBool; // flag if response is from Authoritative server
  int ANCount;
  int NSCount;
  int ARCount;
  int QDCount;
  private int headerOffset; // current pointer of header byte array
  int RCode; // if RCode is not 0, there is an error from the DNS Response. Catch in Lookupservice

  public parseHeader(byte[] headerBytes) {
   this.headerOffset = 0;
   this.headerArr = headerBytes; // TODO not needed?
   extractTransID();
   extractFlags();
   extractQDCount();
   extractANCount();
   extractNSCount();
   extractARCount();
   authFlag = authBool == 1 ? "true" : "false";
  }

  private void extractTransID() {
   byte[] IDBytes = Bytehelper.readBytes(this.headerOffset, ID_SIZE, this.headerArr); // starting offset of 0
   this.headerOffset += ID_SIZE;
   this.transID = Bytehelper.bytesToHex(IDBytes);
  }
  private void extractFlags() {
   byte[] flagBytes = Bytehelper.readBytes(this.headerOffset, FLAGS_SIZE, this.headerArr);
   // System.out.println("Flags: " + Bytehelper.bytesToHex(flagBytes));
   this.headerOffset += FLAGS_SIZE;
   this.authBool = getBit(flagBytes[0], 2); // get the AA bit from the 1st byte of flagbytes
   this.RCode = flagBytes[1] & 0x0F; // get the last 4 bits of the 2nd byte for RCode
   checkRCode();
  }

  // TODO catch Rcode Errors at the begining
  // if SOA response don't throw an Error, otherwise DO
  /**
   * @throws RuntimeException <p> if RCode will break the program. Cases that potentially will break are responses that do not termiante, do not terminate with SOA (response), or something else I don't know...
   * I have not guarded against these cases as they are hard to test <p>
   * If error from DNS server will not break code such as Name Error, proceed as it most likely terminates with SOA.
   * Error will be caught in DNSLookupService
   */
  private void checkRCode() throws RuntimeException {
   switch (this.RCode) {
    case 0:
     break; // no error
    case 1:
     System.err.println("Format error - The name server was unable to interpret the query.");
     throw new RuntimeException("Format error - The name server was unable to interpret the query.");
    case 2:
     System.err.println("Server Failure.");
     throw new RuntimeException("Server Failure");
    case 3:
     //System.err.println("Name error");
     // should be SOA response
     break;
     // throw new RuntimeException("Name error");
    case 4:
     System.err.println("Not implemented");
     throw new RuntimeException("Not implemented");
     // break;
    case 5:
     System.err.println("Refused");
     break;
     // throw new RuntimeException("Refused");
    default:
     System.err.println("Unknown RCode val received - Hard Fail");
     throw new RuntimeException("Unknown RCode val received");
   }
  }

  private void extractQDCount() {
   byte[] QDCountBytes = Bytehelper.readBytes(this.headerOffset, QD_SIZE, this.headerArr);
   this.QDCount = Integer.parseInt(Bytehelper.bytesToHex(QDCountBytes), 16);
   this.headerOffset += QD_SIZE;
  }

  private void extractANCount() {
   byte[] ANBytes = Bytehelper.readBytes(this.headerOffset, AN_SIZE, this.headerArr);
   this.ANCount = Integer.parseInt(Bytehelper.bytesToHex(ANBytes), 16);
   this.headerOffset += AN_SIZE;
  }

  private void extractNSCount() {
   byte[] NSBytes = Bytehelper.readBytes(this.headerOffset, NS_SIZE, this.headerArr);
   this.NSCount = Integer.parseInt(Bytehelper.bytesToHex(NSBytes), 16);
   this.headerOffset += NS_SIZE;
  }
  private void extractARCount() {
   byte[] ARBytes = Bytehelper.readBytes(this.headerOffset, AR_SIZE, this.headerArr);
   this.ARCount = Integer.parseInt(Bytehelper.bytesToHex(ARBytes), 16);
   this.headerOffset += NS_SIZE;
  }
 }
 /**
  *  parseQuestion Object contains the following attributes <p>
  * QName (String): The domain name being queried
  * QType (String): The Question tyoe
  * QClass (String): The Question Class
  */
 private class parseQuestion {
  private static final int QTYPE_SIZE = 2;
  private static final int QCLASS_SIZE = 2;
  private static final int POINTER_SIZE = 2;
  String QName = "";
  String QType;
  String QClass;
  private final static int OFFSET_POS = 1; // posistion from RHS where offset is
  private final static int OFFSET_SIZE = 14; // number of bits of the offset
  private int domainOffset;
  public parseQuestion() {
   extractQName();
   extractQType();
   extractQClass();
   // System.out.println("QNAME: " + QName);
   // System.out.println("QType: " + QType);
   // System.out.println("QClass: " + QClass);
  }

  /*
  private void extractQName() {
    parseResourceRecord.
    // TODO can Question be of the pointer
   int curByte = responseBuffer[currAddr] & 0xFF; // cast to int
   while (curByte != 0) {
    int label_length = curByte;
    byte[] label_bytes = Bytehelper.readBytes(currAddr + 1, label_length, responseBuffer);
    currAddr += label_length + 1;
    try {
     String labelString = new String(label_bytes, "US-ASCII");
     this.QName += labelString + ".";
     curByte = responseBuffer[currAddr] & 0xFF; // cast to int
    } catch (UnsupportedEncodingException err) {
     System.err.println("Error in extract QName");
     throw new RuntimeException(err);
    }
   }
   this.QName = removeLastChar(this.QName); // remove last "." character
   currAddr += 1; // set offset after terminating byte
  }
  */

  private void extractQName() {
   // resoure name is never a literal (non label)
   getDomainOffset(currAddr);
   // System.out.println("Current offset resource name: " + currAddr);
   // System.out.println("Domain offset resource name: " + this.domainOffset);
   // resource name is label
   if (this.domainOffset == currAddr) {
    // if resource name is not using a pointer format  set the curaddrr to the number of bytes read for label
    HashMap < String, String > nameMap = extractLabel(currAddr);
    this.QName = removeLastChar(nameMap.get("name")); // remove last "." character
    currAddr = Integer.parseInt(nameMap.get("offset")); // set the new offset
   } else {
    // resource name is using pointer only read two bytes
    currAddr += POINTER_SIZE;
    HashMap < String, String > nameMap = extractLabel(this.domainOffset);
    this.QName = removeLastChar(nameMap.get("name")); // remove last "." character
   }
   // System.out.println("Current offset after parse Name: " + currAddr);  
  }

  private int extractOffset(int message) {
   int offset = bitExtracted(message, OFFSET_SIZE, OFFSET_POS);
   return offset;
  }

  /**
  *  get the domain offset. Usually used when a pointer has been encountered
  @param offset The offset where you are currently at
  */
  public void getDomainOffset(int offset) {
   try {
    int curByte = responseBuffer[offset] & 0xFF;
    boolean isPointer = isPointer(curByte);
    if (!isPointer) {
     // if the initial offset is not a pointer pass back current address
     this.domainOffset = offset == currAddr ? currAddr : offset; // decimal representation
     //   System.out.println("domain offset is: " + this.domainOffset);
     return;
    } else {
     byte[] messageBytes = new byte[2];
     messageBytes[0] = responseBuffer[offset];
     messageBytes[1] = responseBuffer[offset + 1];
     int convertedMessageInt = Integer.parseInt(Bytehelper.bytesToHex(messageBytes), 16);
     int extractedOffset = extractOffset(convertedMessageInt);
     getDomainOffset(extractedOffset);
    }
   } catch (ArrayIndexOutOfBoundsException err) {
    System.err.println("Error occured in getDomainOffset");
    System.err.println("Illegal array access based on offset");
    throw new RuntimeException(err);
   } catch (NumberFormatException err1) {
    System.err.println("Error occured in getDomainOffset");
    throw new RuntimeException(err1);
   }
  }

  // label is defined as a non-string literal (E.g has pointer or label or combination of both)
  /**
   * Extract A Label, which is defined as a non-string literal (E.g is of the form pointer, label or a combination of both)
   *  This is usually the case for NS and CNAME recrods, where their RData are not string-literals (unline A and AAAA records)
   * @param offset The offset of current address
   */
  public HashMap < String, String > extractLabel(int offset) {
   int curByte = responseBuffer[offset] & 0xFF; // cast to int
   HashMap < String, String > labelMap = new HashMap < String, String > ();
   String pointerName = "";
   boolean pointerFlag = isPointer(curByte);
   while (curByte != 0 && !pointerFlag) {
    int label_length = curByte;
    byte[] label_bytes = Bytehelper.readBytes(offset + 1, label_length, responseBuffer);
    offset += label_length + 1;
    try {
     String labelString = new String(label_bytes, "US-ASCII");
     pointerName += labelString + ".";
     // System.out.println(labelString);
     curByte = responseBuffer[offset] & 0xFF; // cast to int
     pointerFlag = isPointer(curByte);
     // System.out.println("pointer flag: " + pointerFlag);
     //   System.out.println("cur byte: " + curByte);
    } catch (UnsupportedEncodingException err) {
     System.err.println("Error pccured in extractLabel");
     throw new RuntimeException(err);
    } catch (ArrayIndexOutOfBoundsException err1) {
     System.err.println("Error occured in extractLabel");
     System.err.println("Ileggal offset access of responseBuffer: Should not occur: " + offset);
     throw new RuntimeException(err1);
    }
   }
   if (pointerFlag == true) {
    // Name with terminating pointer
    getDomainOffset(offset);
    //System.out.println("the domain offset at terminating pointer: " + this.domainOffset);
    HashMap < String, String > labelInfo = extractLabel(this.domainOffset);
    pointerName += labelInfo.get("name");
    labelMap.put("name", pointerName);
    offset += POINTER_SIZE;
    labelMap.put("offset", Integer.toString(offset));
    return labelMap;
   }
   // label with terminating 0 byte
   // System.out.println("Reached label with terminating byte");
   offset += 1;
   String formatString = removeLastChar(pointerName);
   labelMap.put("name", formatString); /// remove last "." character
   labelMap.put("offset", Integer.toString(offset));
   return labelMap;
  }

  // determine if answer name is using compressed format (left most bits are 1 1)
  private boolean isPointer(int firstByte) {
   int two_left_bits = bitExtracted(firstByte, 2, 7); // if first byte is a pointer, left most 2 bits are 1 1, which is value 3
   return two_left_bits == 3;
  }

  private void extractQType() {
   String hexQType = Bytehelper.bytesToHex(Bytehelper.readBytes(currAddr, QTYPE_SIZE, responseBuffer));
   // System.out.println("QType hex: " + hexQType);
   this.QType = convertTypeCode(Integer.parseInt(hexQType, 16));
   currAddr += QTYPE_SIZE;
  }
  private void extractQClass() {
   this.QClass = Bytehelper.bytesToHex(Bytehelper.readBytes(currAddr, QCLASS_SIZE, responseBuffer));
   currAddr += QCLASS_SIZE;
  }
 }

 /**
  *  parseResourceRecord Object contains the following attributes <p>
  * resourceName (String): The name of the resource
  * resourceType (String): The resource type in decimal representation (E.g A is 1)
  * resourceClass (String): The resouceClass 
  * TTL (String): The TTL of the resource expressed as a hex string to have 0x infront for easier long decoding
  * RDLength (String): The Question Class 
  * RData (String): The Question Class
  */
 private class parseResourceRecord {
  String resourceName;
  String resourceType;
  String resourceClass;
  String TTL;
  int RDLength; // number of bytes(octets) to read for RDData
  String RData;
  // private Boolean pointerFlag;
  private int domainOffset;
  // this works for any number of elements:
  public final static int POINTER_SIZE = 2;
  private final static int VARY_SIZE = 9999; // number of bytes to read for a variable length
  private final static int TYPE_SIZE = 2;
  private final static int CLASS_SIZE = 2;
  private final static int TTL_SIZE = 4;
  private final static int RDLENGTH_SIZE = 2;
  private final static int LEFT_BITS_POS = 7; // the init posistion of  the two  left bits of answer name
  private final static int OFFSET_POS = 1; // posistion from RHS where offset is
  private final static int OFFSET_SIZE = 14; // number of bits of the offset

  public parseResourceRecord() {
   extractResourceName();
   extractResourceType();
   extractResourceClass();
   extractTTL();
   extractRDLength();
   extractRDData();
   // System.out.println("Resource Name: " + this.resourceName);
   // System.out.println("Resource type: " + this.resourceType);
   // System.out.println("Resource class: " + this.resourceClass);
   // System.out.println("Resource TTL: " + this.TTL);
   // System.out.println("RD Length: " + this.RDLength);
   // System.out.println("RD Data: " + this.RData);
  }

  private void extractResourceName() {
   // resoure name is never a literal (non label)
   getDomainOffset(currAddr);
   // System.out.println("Current offset resource name: " + currAddr);
   // System.out.println("Domain offset resource name: " + this.domainOffset);
   // resource name is label
   if (this.domainOffset == currAddr) {
    // if resource name is not using a pointer format  set the curaddrr to the number of bytes read for label
    HashMap < String, String > nameMap = extractLabel(currAddr);
    this.resourceName = nameMap.get("name");
    currAddr = Integer.parseInt(nameMap.get("offset")); // set the new offset
   } else {
    // resource name is using pointer only read two bytes
    currAddr += POINTER_SIZE;
    HashMap < String, String > nameMap = extractLabel(this.domainOffset);
    this.resourceName = nameMap.get("name");
   }
   // System.out.println("Current offset after parse Name: " + currAddr);  
  }



  private void extractRDData() {
   int typeCode = Integer.parseInt(this.resourceType);
   if (!typesSupported.containsKey(typeCode)) {
    // skip record (RData as type not supported) TODO
    currAddr += this.RDLength;
    return;
   }
   boolean isRDataLabel = typesSupported.get(typeCode);
   if (isRDataLabel) {
    // if rdata is a label handle label case
    getDomainOffset(currAddr);
    // System.out.println("Current offset RData: " + currAddr);
    // System.out.println("Domain offset RData: " + this.domainOffset);    // if resource name is not using a pointer format  set the curaddrr to the number of bytes read for label
    HashMap < String, String > nameMap = extractLabel(this.domainOffset);
    this.RData = nameMap.get("name");
    // currAddr += this.RDLength;
    //currAddr = Integer.parseInt(nameMap.get("offset")); // set the new offset
    // System.out.println("Domain offset AFTER RData: " + currAddr);
   } else {
    // TODO SET THE OFFSET OF RDDATA
    // resource name is a literal treat as real string (non -label case)
    extractNonLabel(currAddr, this.RDLength);
   }
   currAddr += this.RDLength;

   // System.out.println("Current offset after parse Record RData: " + this.RData + " | " + currAddr);
  }

  /**
  *  get the domain offset. Usually used when a pointer has been encountered
  @param offset The offset where you are currently at
  */
  private void getDomainOffset(int offset) {
   try {
    int curByte = responseBuffer[offset] & 0xFF;
    boolean isPointer = isPointer(curByte);
    if (!isPointer) {
     // if the initial offset is not a pointer pass back current address
     this.domainOffset = offset == currAddr ? currAddr : offset; // decimal representation
     //   System.out.println("domain offset is: " + this.domainOffset);
     return;
    } else {
     byte[] messageBytes = new byte[2];
     messageBytes[0] = responseBuffer[offset];
     messageBytes[1] = responseBuffer[offset + 1];
     int convertedMessageInt = Integer.parseInt(Bytehelper.bytesToHex(messageBytes), 16);
     int extractedOffset = extractOffset(convertedMessageInt);
     getDomainOffset(extractedOffset);
    }
   } catch (ArrayIndexOutOfBoundsException err) {
    System.err.println("Error occured in getDomainOffset");
    System.err.println("Illegal array access based on offset");
    throw new RuntimeException(err);
   } catch (NumberFormatException err1) {
    System.err.println("Error occured in getDomainOffset");
    throw new RuntimeException(err1);
   }
  }

  private int extractOffset(int message) {
   int offset = bitExtracted(message, OFFSET_SIZE, OFFSET_POS);
   return offset;
  }
  // label is defined as a non-string literal (E.g has pointer or label or combination of both)
  /**
   * Extract A Label, which is defined as a non-string literal (E.g is of the form pointer, label or a combination of both)
   *  This is usually the case for NS and CNAME recrods, where their RData are not string-literals (unline A and AAAA records)
   * @param offset The offset of current address
   */
  private HashMap < String, String > extractLabel(int offset) {
   int curByte = responseBuffer[offset] & 0xFF; // cast to int
   HashMap < String, String > labelMap = new HashMap < String, String > ();
   String pointerName = "";
   boolean pointerFlag = isPointer(curByte);
   while (curByte != 0 && !pointerFlag) {
    int label_length = curByte;
    byte[] label_bytes = Bytehelper.readBytes(offset + 1, label_length, responseBuffer);
    offset += label_length + 1;
    try {
     String labelString = new String(label_bytes, "US-ASCII");
     pointerName += labelString + ".";
     // System.out.println(labelString);
     curByte = responseBuffer[offset] & 0xFF; // cast to int
     pointerFlag = isPointer(curByte);
     // System.out.println("pointer flag: " + pointerFlag);
     //   System.out.println("cur byte: " + curByte);
    } catch (UnsupportedEncodingException err) {
     System.err.println("Error pccured in extractLabel");
     throw new RuntimeException(err);
    } catch (ArrayIndexOutOfBoundsException err1) {
     System.err.println("Error occured in extractLabel");
     System.err.println("Ileggal offset access of responseBuffer: Should not occur: " + offset);
     throw new RuntimeException(err1);
    }
   }
   if (pointerFlag == true) {
    // Name with terminating pointer
    getDomainOffset(offset);
    //System.out.println("the domain offset at terminating pointer: " + this.domainOffset);
    HashMap < String, String > labelInfo = extractLabel(this.domainOffset);
    pointerName += labelInfo.get("name");
    labelMap.put("name", pointerName);
    offset += POINTER_SIZE;
    labelMap.put("offset", Integer.toString(offset));
    return labelMap;
   }
   // label with terminating 0 byte
   // System.out.println("Reached label with terminating byte");
   offset += 1;
   String formatString = removeLastChar(pointerName);
   labelMap.put("name", formatString); /// remove last "." character
   labelMap.put("offset", Integer.toString(offset));
   return labelMap;
  }

  // (E.g string literal, Should never encounter a pointer never terminates with null byte)
  // string literal represents ip address
  /**
* Extract a Non label, which is defined as a string-literal (Format is treated as a string literal). This is usually the case for A and AAAA records, where
* their RData 32-bit or 64 bit unsigned integer representing IP address
@param offset The offset
@param num The number of bytes to read. This is usually RDLength
  */
  private void extractNonLabel(int offset, int num) {
   try {
    byte[] ipBytes = Bytehelper.readBytes(offset, num, responseBuffer);
    InetAddress convertedAddress = InetAddress.getByAddress(ipBytes);
    this.RData = convertedAddress.getHostAddress();
    // currAddr += num;
   } catch (UnknownHostException err) {
    System.err.println("Error occured in extractNonLabel");
    throw new RuntimeException(err);
   }
  }

  private void extractResourceType() {
   String typeString = Bytehelper.bytesToHex(Bytehelper.readBytes(currAddr, TYPE_SIZE, responseBuffer));
   currAddr += TYPE_SIZE;
   this.resourceType = Integer.toString(Integer.parseInt(typeString, 16)); // decimal representation
   // System.out.println("Resouce type is: " + convertTypeCode(Integer.parseInt(this.resourceType)));
  }

  private void extractResourceClass() {
   String classString = Bytehelper.bytesToHex(Bytehelper.readBytes(currAddr, CLASS_SIZE, responseBuffer));
   currAddr += CLASS_SIZE;
   this.resourceClass = Integer.toString(Integer.parseInt(classString, 16)); // decimal representation
  }

  private void extractTTL() {
   String ttlString = Bytehelper.bytesToHex(Bytehelper.readBytes(currAddr, TTL_SIZE, responseBuffer));
   currAddr += TTL_SIZE;
   this.TTL = "0x" + ttlString; // format ttl hex string to have 0x infront, easier for long decoding
  }

  private void extractRDLength() {
   String rdString = Bytehelper.bytesToHex(Bytehelper.readBytes(currAddr, RDLENGTH_SIZE, responseBuffer));
   currAddr += RDLENGTH_SIZE;
   this.RDLength = Integer.parseInt(rdString, 16);
  }
  // determine if answer name is using compressed format (left most bits are 1 1)
  private boolean isPointer(int firstByte) {
   int two_left_bits = bitExtracted(firstByte, 2, 7); // if first byte is a pointer, left most 2 bits are 1 1, which is value 3
   return two_left_bits == 3;
  }

  private int extractPointerOffset(int pointerByte) {
   return bitExtracted(pointerByte, OFFSET_SIZE, OFFSET_POS);
  }
 }
 /**
* Converts a raw type string to its decimal representation. (E.g A will return 1)
@return An int representing the type converted (E.g A is 1)
@param typeString The raw type string (E.g "A") to be converted
  */
 private int convertTypeString(String typeString) {
  switch (typeString) {
   case "A":
    return 1;
   case "NS":
    return 2;
   case "CNAME":
    return 5;
   case "SOA":
    return 6;
   case "WKS":
    return 11;
   case "PTR":
    return 12;
   case "MX":
    return 15;
   case "SRV":
    return 33;
   case "AAAA":
    return 28;
   default:
    return 0; // error occured malformed/unknown typeString
  }
 }

 /**
* Converts an int to its string Type representation. (E.g 1 returns A)
@return A String representing the type converted (E.g 1 is A)
@param code The decimal representation of the type (E.g A is 1)
  */

 private String convertTypeCode(int code) {
  switch (code) {
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
   case 255:
    return "ANY"; // any record
   default:
    return "No code found"; // if no type found
  }
 }

 // the key are the field names and the coressponding value is the response value 
 /**
* get all the resource records in the section {@code type}
@return A List of all the records  in the section {@code type}. Each element in the List is a HashMap<String, String> with keys
* rdata, name, ttl, class, rtype
@param type The section to extract records from
  */
 private List < Map < String, String >> getResourceRecordsInfo(String type) {
  List < Map < String, String >> recordList = new ArrayList < Map < String, String >> ();
  int i = 0;
  int n;
  switch (type) {
   case "answer":
    n = this.numAnswers;
    break;
   case "nameserver":
    n = this.numNameservers;
    break;
   case "additional":
    n = this.numAddInfo;
    break;
   default:
    n = 0; // something went wrong
    System.err.println("Opps: Should never reach here as custom code");
  }
  // System.out.println("Number of " + type + " " + n);
  while (i < n && currAddr < responseBuffer.length) {
   HashMap < String, String > recordInfo = new HashMap();
   parseResourceRecord resource = new parseResourceRecord();
   recordInfo.put("rdata", resource.RData);
   recordInfo.put("name", resource.resourceName);
   recordInfo.put("ttl", resource.TTL);
   recordInfo.put("class", resource.resourceClass);
   recordInfo.put("rtype", resource.resourceType);
   // System.out.println("Inserting into rdata into map: " + resource.RData);
   // System.out.println("Inserting into name into map: " + resource.resourceName);
   // System.out.println("Inserting into ttl into map: " + resource.TTL);
   //  System.out.println("Inserting into class into map: " + resource.resourceClass);
   //System.out.println("Inserting into rtype into map: " + resource.resourceType);
   recordList.add(recordInfo);
   //System.out.println("Current offset after parse record resource: " + currAddr);
   i++;
  }
  // System.out.println("Current offset after parse all resources for type: " + type + " " + currAddr);
  if (n != 0) printRecordListVals(recordList);
  return recordList;
 }

 private void printRecordListVals(List < Map < String, String >> recordList) {
  for (int i = 0; i < recordList.size(); i++) {
   // System.out.println("rdata val : " + recordList.get(i).get("rdata"));
   // System.out.println("ttl val: " + recordList.get(i).get("ttl"));
   // System.out.println("name val: " + recordList.get(i).get("name"));
   // System.out.println("class val: " + recordList.get(i).get("class"));
   // System.out.println("rtype val: " + recordList.get(i).get("rtype"));
  }
 }

 // get the A and NS records in the supplied section type
 /**
*  Get the A and NS records in section {@code sectionType}
@param sectionType The sectionType of interest
  */
 private void getAandNSRecords(int sectionType) {
  int num;
  List < Map < String, String >> resourceList;
  switch (sectionType) {
   case 1:
    num = this.numAnswers;
    resourceList = this.answerRecords;
    break;
   case 2:
    num = this.numNameservers;
    resourceList = this.nameRecords;
    break;
   case 3:
    num = this.numAddInfo;
    resourceList = this.addRecords;
    break;
   default:
    throw new RuntimeException("Should not reach here, error with section type code");
  }
  for (int i = 0; i < num; i++) {
   Map < String, String > resourceMap = resourceList.get(i);
   String rType = resourceMap.get("rtype");
   int convertRTypecode = Integer.parseInt(rType);
   // a record
   if (convertRTypecode == 1) {
    this.numARecords++;
    this.aRecords.add(resourceMap);
   } else {
    // ns record
    if (convertRTypecode == 2) {
     this.numNSRecords++;
     this.nsRecords.add(resourceMap);
    }
   }
  }
 }

 /**
  * Get a list of servers to query (based on NS and corresponding A records) <p>
  * Adds servers to serversToQueryArr
  */

 private void getServersToQuery() {
  boolean hasNameRecords = this.numNameservers > 0;
  boolean hasAddrecords = this.numAddInfo > 0;
  // if not a valid authoratiative answer and has name + additional records
  if (!this.isAuth && hasNameRecords && hasAddrecords) {
   for (int i = 0; i < this.numAddInfo; i++) {
    String rType = addRecords.get(i).get("rtype");
    int convertRTypecode = Integer.parseInt(rType);
    // if is an A record get the name and RData (Ip address)
    if (convertRTypecode == 1) {
     String ipAddress = addRecords.get(i).get("rdata");
     this.serversToQueryArr.add(ipAddress);
    }
   }
  }
 }

 //-------------------------------------------------Flag and boolean check functions -----------------------------------------------------//
 //------------------------------------------------- -----------------------------------------------------------------------------------------------------//

 /**
  * @return
  * return a boolean if authFlag  (String) is true or false
  */
 private boolean isAuthResponse() {
  boolean authBool = this.authFlag == "true" ? true : false;
  return authBool;
 }

 /**
  * set queryNSFlag if a dead-end is reached, meaning there is no further information available to query (A records) <p>
  * A dead-end is determined when there are 0 records in the answer and additional section AND there is at least one Name Server (NS record)
  */
 // determine if a "dead-end "is reached. This means no A/AAAA records are present, No answers, only name servers are provided
 private void setQueryNSFlag() {
  // TODO better guard with the presence of AA records???
  this.queryNSFlag = (numAddInfo == 0) && (numAnswers == 0) && (numNameservers > 0);
 }

 // if AA bit is 1 and  RCode is 0 (no error) check if an answer field exists
 /**
  * set the validAuthFlag which determines if the authoritative response is valid. (AA bit is 1, at least one record in Answer section, and No error code (Rcode  is 0)) 
  */
 private void validateAuthResponse() {
  boolean authBool = this.authFlag == "true" ? true : false;
  boolean RCodeBool = this.RCode == 0;
  boolean numAnswerBool = this.numAnswers > 0;
  this.validAuthFlag = authBool && RCodeBool && numAnswerBool;
 }

 //-----------------------------------------------------------------------------------------------------//
 //------------------------------------------------- -----------------------------------------------------------------------------------------------------//

 //-------------------------------------------------Bit Helpers -----------------------------------------------------//
 //------------------------------------------------- --------------------------------------------------------------------//

 // https://stackoverflow.com/questions/9354860/how-to-get-the-value-of-a-bit-at-a-certain-position-from-a-byte
 /**
 * get the bit from a byte at a particular posistion
 * *@return the bit extracted from byte casted to an int
 * @param b The byte you want to check
 * @param posistion posistion of the bit you want to extract

  */
 private int getBit(byte b, int position) {
  return (b >> position) & 1;
 }

 // https://www.geeksforgeeks.org/extract-k-bits-given-position-number/
 // extract n bits from position pos inclusive, pos initial starts at RHS
 /**
 * extract n bits from position pos inclusive, pos initial starts at RHS
 * @param number The int number you want to extract from (can only be four bytes)
 * @param n number of bits you want to extract starting from pos and proceed to LHS
 * @param pos The starting posistion from where you want to start extracting

  */
 private int bitExtracted(int number, int n, int pos) {
  return (((1 << n) - 1) & (number >> (pos - 1)));
 }

 //------------------------------------------------------------------------------------------------------//
 //------------------------------------------------- --------------------------------------------------------------------//

 //-------------------------------------------------Helper functions -----------------------------------------------------//
 //------------------------------------------------- --------------------------------------------------------------------//

 /**
  * remove the last character of string
  * @param str The string that you want foramt
  */

 private static String removeLastChar(String str) {
  // blank str;
  if (str.length() < 1) return str;
  return str.substring(0, str.length() - 1);
 }

 /**
  * extract Header Bytes from response buffer
  * @param buffer The response buffer
  */
 private byte[] extractHeaderBytes() {
  byte[] headerBytes = Bytehelper.readBytes(currAddr, HEADER_SIZE, responseBuffer);
  currAddr += HEADER_SIZE;
  String hexResString = Bytehelper.bytesToHex(headerBytes);
  // System.out.println("Response header HEXstring: " + hexResString);
  return headerBytes;
 }

 /**
  *  Populate typesSupported hash which is an hashset containing resource records supported along with a boolean determining if their RData is a label or literal string
  */
 private void populateTypesSupported() {
  this.typesSupported.put(1, false); // A record not a label
  this.typesSupported.put(2, true); // NS record is label
  this.typesSupported.put(5, true); // CNAME is label
  this.typesSupported.put(28, false); // AAAA not label
  this.typesSupported.put(6, true); // SOA is label
 }

 /**
  *  Print the list of servers to query from serversToQueryArr
  */
 public void printServerArr() {
  for (int i = 0; i < serversToQueryArr.size(); i++) {
   // System.out.println("ipAddress val: " + serversToQueryArr.get(i));
  }
 }
 //------------------------------------------------- -----------------------------------------------------//
 //------------------------------------------------- --------------------------------------------------------------------//

}