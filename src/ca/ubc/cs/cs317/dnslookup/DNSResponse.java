package ca.ubc.cs.cs317.dnslookup;
import java.util.regex.Pattern;
import java.util.stream.*;

import javax.management.RuntimeErrorException;

import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.*;

public class DNSResponse {
private final static int HEADER_SIZE = 12; // header size in number of bytes
private byte[] responseBuffer;
 String responseID;
 String lookupName;
 String queryType;
int RCode;
List<String> serversToQueryArr = new ArrayList<String>(); // listof servers to query based on name servers with corresponding ip addresses from additional info
String authFlag; // for outputting in DNSLookupService
boolean isAuth; // boolean for simplicity
boolean validAuthFlag; // determine if the authorative response is valid
int numAnswers; // number of answers
int numNameservers; // number of NS
int numAddInfo; // number of AR
List<Map<String, String>> answerRecords = new ArrayList<Map<String, String>>();
List<Map<String, String>> nameRecords = new ArrayList<Map<String, String>>();
List<Map<String, String>> addRecords = new ArrayList<Map<String, String>>();
 private int currAddr =0; // starting offset
 public DNSResponse(byte[] responseBuffer) {
     this.responseBuffer = responseBuffer;
     byte[] headerArr = extractHeaderBytes(this.responseBuffer);
     parseHeader parsedHeader = new parseHeader(headerArr);
     this.RCode = parsedHeader.RCode;
     this.responseID = parsedHeader.transID;
     this.numAnswers = parsedHeader.ANCount;
     this.numNameservers = parsedHeader.NSCount;
     this.numAddInfo = parsedHeader.ARCount;

     System.out.println("responseID: " + parsedHeader.transID);
     System.out.println("authBool: " + parsedHeader.authBool);
     System.out.println("RCode: " + parsedHeader.RCode);
     System.out.println("QDCount: " + parsedHeader.QDCount);
     System.out.println("ANCount: " + this.numAnswers);
     System.out.println("NSCount: " + this.numNameservers);
     System.out.println("ARCount: " + this.numAddInfo);
     parseQuestion parsedQuestion = new parseQuestion();
     this.answerRecords = getResourceRecordsInfo("answer");
     this.nameRecords = getResourceRecordsInfo("nameserver");
     this.addRecords = getResourceRecordsInfo("additional");
     this.isAuth = isAuthResponse();
     if (this.isAuth) {
        validateAuthResponse();
     } else {
         // if not authoratative answer get servers to query
         getServersToQuery();
         printServerArr();
     }
    // printRecordListVals(this.nameRecords);
    // printRecordListVals(this.addRecords);
     System.out.println("answer record size: " + this.answerRecords.size());
     System.out.println("name record size: " + this.nameRecords.size());
     System.out.println("add record size: " + this.addRecords.size());
 };
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
     int headerOffset; // current pointer of header byte array
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
         authFlag = authBool == 1? "true" : "false";
     }

     private void extractTransID() {
         byte[] IDBytes = readBytes(this.headerOffset, ID_SIZE, this.headerArr); // starting offset of 0
         this.headerOffset += ID_SIZE;
         this.transID = Bytehelper.bytesToHex(IDBytes);
     }
     private void extractFlags() {
         byte[] flagBytes = readBytes(this.headerOffset, FLAGS_SIZE, this.headerArr);
         System.out.println("Flags: " + Bytehelper.bytesToHex(flagBytes));
         this.headerOffset += FLAGS_SIZE;
         this.authBool = getBit(flagBytes[0], 2); // get the AA bit from the 1st byte of flagbytes
         this.RCode = flagBytes[1] & 0x0F; // get the last 4 bits of the 2nd byte for RCode
         checkRCode();
     }

     // TODO catch Rcode Errors at the begining
     private void checkRCode() throws RuntimeException {
         switch(this.RCode) {
             case 0:
             break; // no error
             case 1:
             throw new RuntimeException("Format error - The name server was unable to interpret the query.");
             case 2:
             throw new RuntimeException("Server Failure");
             case 3:
             throw new RuntimeException("Name error");
             case 4:
             throw new RuntimeException("Not implemented");
             case 5:
             throw new RuntimeException("Refused");
             default:
             throw new RuntimeException("Unknown RCode val received");
         }
     }

     private void extractQDCount() {
         byte[] QDCountBytes = readBytes(this.headerOffset, QD_SIZE, this.headerArr);
         this.QDCount = Integer.parseInt(Bytehelper.bytesToHex(QDCountBytes), 16);
         this.headerOffset += QD_SIZE;
     }

     private void extractANCount() {
        byte[] ANBytes = readBytes(this.headerOffset, AN_SIZE, this.headerArr);
        this.ANCount = Integer.parseInt(Bytehelper.bytesToHex(ANBytes), 16);
        this.headerOffset += AN_SIZE;
    }

    private void extractNSCount() {
        byte[] NSBytes = readBytes(this.headerOffset, NS_SIZE, this.headerArr);
        this.NSCount = Integer.parseInt(Bytehelper.bytesToHex(NSBytes), 16);
        this.headerOffset += NS_SIZE;
    }
    private void extractARCount() {
        byte[] ARBytes = readBytes(this.headerOffset, AR_SIZE, this.headerArr);
        this.ARCount = Integer.parseInt(Bytehelper.bytesToHex(ARBytes), 16);
        this.headerOffset += NS_SIZE;
    }
 }

 private class parseQuestion {
     private static final int QTYPE_SIZE = 2;
     private static final int QCLASS_SIZE = 2;
     String QName = "";
     String QType;
     String QClass;
     public parseQuestion () {
         extractQName();
         extractQType();
         extractQClass();
         System.out.println("QNAME: " + QName);
         System.out.println("QType: " + QType);
         System.out.println("QClass: " + QClass);
     }

     private void extractQName() {
         int curByte = responseBuffer[currAddr] & 0xFF; // cast to int
         while (curByte != 0) {
             int label_length = curByte;
             byte[] label_bytes = readBytes(currAddr + 1, label_length, responseBuffer);
             currAddr += label_length + 1;
             try {
                String labelString = new String(label_bytes, "US-ASCII");
                this.QName += labelString + ".";
                curByte = responseBuffer[currAddr] & 0xFF; // cast to int
             }
             catch (UnsupportedEncodingException err) {
                 // TODO
             }
         }
         this.QName = removeLastChar(this.QName); // remove last "." character
         currAddr += 1; // set offset after terminating byte
     }

     private void extractQType() {
         String hexQType = Bytehelper.bytesToHex(readBytes(currAddr, QTYPE_SIZE, responseBuffer));
         System.out.println("QType hex: " + hexQType);
         this.QType = convertTypeCode(Integer.parseInt(hexQType, 16));
         currAddr += QTYPE_SIZE;
     }
     private void extractQClass() {
         this.QClass = Bytehelper.bytesToHex(readBytes(currAddr, QCLASS_SIZE, responseBuffer));
         currAddr += QCLASS_SIZE;
     }
 }

 private class parseResourceRecord{
     String resourceName;
     String resourceType;
     String resourceClass;
     String TTL;
     int RDLength; // number of bytes(octets) to read for RDData
     String RData;
     Boolean pointerFlag;
     private int domainOffset;
// this works for any number of elements:
private final HashMap<Integer, Boolean> typesSupported = new HashMap();     
    private final static int POINTER_SIZE = 2;
     private final static int VARY_SIZE = 9999; // number of bytes to read for a variable length
     private final static int TYPE_SIZE = 2;
     private final static int CLASS_SIZE = 2;
     private final static int TTL_SIZE = 4;
     private final static int RDLENGTH_SIZE= 2;
     private final static int LEFT_BITS_POS = 7; // the init posistion of  the two  left bits of answer name
     private final static int OFFSET_POS = 14;
     private final static int OFFSET_SIZE = 14; // number of bits of the offset

     public parseResourceRecord() {
         populateTypesSupported();
         extractResourceName();
         extractResourceType();
         extractResourceClass();
         extractTTL();
         extractRDLength();
         extractRDData();
         System.out.println("Resource Name: " + this.resourceName);
         System.out.println("Resource type: " + this.resourceType);
         System.out.println("Resource class: " + this.resourceClass);
         System.out.println("Resource TTL: " + this.TTL);
         System.out.println("RD Length: " + this.RDLength);
         System.out.println("RD Data: " + this.RData);
     }

     private void extractResourceName() {
         // resoure name is never a literal (non label)
     getDomainOffset(currAddr);
     System.out.println("Current offset resource name: " + currAddr);
     System.out.println("Domain offset resource name: " + this.domainOffset);
     // resource name is label
     if (this.domainOffset == currAddr) {
         // if resource name is not using a pointer format  set the curaddrr to the number of bytes read for label
         HashMap<String, String> nameMap = extractALabel(this.domainOffset);
         this.resourceName = nameMap.get("name");
         currAddr = Integer.parseInt(nameMap.get("offset")); // set the new offset
     } else {
         // resource name is using pointer only read two bytes
         currAddr += POINTER_SIZE;
         HashMap<String, String> nameMap = extractALabel(this.domainOffset);
         this.resourceName = nameMap.get("name");  
        }
        System.out.println("Current offset after parse Name: " + currAddr);  
       }

     private void extractRDData() {
     // exactly the same as parsing the resoucename and RData 

     int typeCode = Integer.parseInt(this.resourceType);
     if (!this.typesSupported.containsKey(typeCode)) {
         // skip record (RData as type not supported)
         currAddr += RDLENGTH_SIZE;
         return;
     }
     boolean isRDataLabel = this.typesSupported.get(typeCode);
     if (isRDataLabel) {
         // if rdata is a label handle label case
        getDomainOffset(currAddr);
        System.out.println("Current offset RData: " + currAddr);
        System.out.println("Domain offset RData: " + this.domainOffset);    // if resource name is not using a pointer format  set the curaddrr to the number of bytes read for label
         HashMap<String, String> nameMap = extractALabel(this.domainOffset);
         this.RData = nameMap.get("name");
         currAddr = Integer.parseInt(nameMap.get("offset")); // set the new offset
         System.out.println("Domain offset AFTER RData: " + currAddr);
     }
 else {
         // resource name is a literal treat as real string (non -label case)
         extractANonLabel(currAddr, this.RDLength);
        }
        System.out.println("Current offset after parse Record: " + this.RData + " | " + currAddr);    
     }

     private void getDomainOffset(int offset) {
            int curByte = responseBuffer[offset] & 0xFF;
            boolean isPointer = isPointer(curByte);
            if (!isPointer) {
                // if the initial offset is not a pointer pass back current address
                this.domainOffset = offset == currAddr? currAddr : offset; // decimal representation
                System.out.println("domain offset is: " + this.domainOffset);
               return ;
           } else {
               offset += 1;
               int hexExtractOffset = responseBuffer[offset] & 0xFF;
               getDomainOffset(hexExtractOffset);
           }
     }
     
     /*
     private void extractAName(String field) {
         // exactly the same as parsing the resoucename and RData 
         field = field == "name"? this.resourceName : this.RData;
         getDomainOffset(currAddr);
         System.out.println("Current offset: " + currAddr);
         System.out.println("Domain offset: " + this.domainOffset);
         // resource name is label
         if (this.domainOffset == currAddr) {
             // if resource name is not using a pointer format  set the curaddrr to the number of bytes read for label
             HashMap<String, String> nameMap = extractALabel(this.domainOffset);
             field = nameMap.get("name");
             currAddr = Integer.parseInt(nameMap.get("offset")); // set the new offset
         } else {
             // resource name is using pointer only read two bytes
             currAddr += POINTER_SIZE;
             HashMap<String, String> nameMap = extractALabel(this.domainOffset);
             field = nameMap.get("name");  
            }
            System.out.println("Current offset after parse Name: " + currAddr);
     }
     */

     private void populateTypesSupported() {
         this.typesSupported.put(1, false); // A record not a label
         this.typesSupported.put(2, true); // NS record is label
         this.typesSupported.put(5, true); // CNAME is label
         this.typesSupported.put(28, false); // AAAA not label
     }

     // label is defined as a non-string literal (E.g has pointer or label or combination of both)
     private HashMap<String,  String> extractALabel(int offset) {
        int curByte = responseBuffer[offset] & 0xFF; // cast to int
        HashMap<String, String> labelMap = new HashMap();
        String pointerName = "";
        boolean pointerFlag = isPointer(curByte);
        while (curByte != 0 && !pointerFlag) {
            int label_length = curByte;
            byte[] label_bytes = readBytes(offset + 1, label_length, responseBuffer);
            offset += label_length + 1;
            try {
               String labelString = new String(label_bytes, "US-ASCII");
               pointerName += labelString + ".";
               curByte = responseBuffer[offset] & 0xFF; // cast to int
               pointerFlag = isPointer(curByte);
            }
            catch (UnsupportedEncodingException err) {
                // TODO
            }
        }
        if (pointerFlag == true) {
            // Name with terminating pointer
            getDomainOffset(offset);
            System.out.println("the domain offset at terminating pointer: " + this.domainOffset);
            HashMap<String, String> labelInfo = extractALabel(this.domainOffset);
            pointerName += labelInfo.get("name");
            labelMap.put("name", pointerName);
            offset += POINTER_SIZE;
            labelMap.put("offset", Integer.toString(offset));
            return labelMap;
        }
        // label with terminating 0 byte
        offset += 1; // set offset after terminating byte
        String formatString = removeLastChar(pointerName);
        labelMap.put("name", formatString); /// remove last "." character
        labelMap.put("offset", Integer.toString(offset));
        return labelMap;
    }

    // (E.g string literal, Should never encounter a pointer never terminates with null byte)
    // string literal represents ip address
    private void extractANonLabel(int offset, int num) {
        try {
            byte[] ipBytes = readBytes(offset, num, responseBuffer);
            InetAddress convertedAddress = InetAddress.getByAddress(ipBytes);
            this.RData = convertedAddress.getHostAddress();
            currAddr += num;
        }
        catch(UnknownHostException err) {
            // TODO
        }
    }

    private void extractResourceType() {
        String typeString = Bytehelper.bytesToHex(readBytes(currAddr, TYPE_SIZE, responseBuffer));
        currAddr += TYPE_SIZE;
        this.resourceType = Integer.toString(Integer.parseInt(typeString, 16)); // decimal representation
        System.out.println("Resouce type is: " + convertTypeCode(Integer.parseInt(this.resourceType)));
    }

    private void extractResourceClass() {
        String classString = Bytehelper.bytesToHex(readBytes(currAddr, CLASS_SIZE, responseBuffer));
        currAddr += CLASS_SIZE;
        this.resourceClass = Integer.toString(Integer.parseInt(classString, 16)); // decimal representation
    }

    private void extractTTL() {
        String ttlString = Bytehelper.bytesToHex(readBytes(currAddr, TTL_SIZE, responseBuffer));
        currAddr += TTL_SIZE;
        this.TTL =  "0x" + ttlString; // format ttl hex string to have 0x infront, easier for long decoding
    }

    private void extractRDLength() {
        String rdString = Bytehelper.bytesToHex(readBytes(currAddr, RDLENGTH_SIZE, responseBuffer));
        currAddr += RDLENGTH_SIZE;
        this.RDLength = Integer.parseInt(rdString, 16);
    }
     // determine if answer name is using compressed format (left most bits are 1 1)
     private boolean isPointer (int firstByte) {
         int two_left_bits = bitExtracted(firstByte, 2, 7); // if first byte is a pointer, left most 2 bits are 1 1, which is value 3
         return two_left_bits == 3;
     } 

     private int extractPointerOffset(int pointerByte) {
        return bitExtracted(pointerByte, OFFSET_SIZE, OFFSET_POS);
    }
 }

 private int convertTypeString(String typeString) {
     switch(typeString) {
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

 private String convertTypeCode(int code) {
    switch(code) {
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
 private List<Map<String, String>> getResourceRecordsInfo (String type) {
    List<Map<String, String>> recordList = new ArrayList<Map<String, String>>();
     int i =0;
     int n;
     switch(type) {
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
     }
     System.out.println("Number of " + type + " " + n);
     while (i < n && currAddr < responseBuffer.length) {
        HashMap<String, String> recordInfo = new HashMap();
        parseResourceRecord resource = new parseResourceRecord();
        recordInfo.put("rdata", resource.RData);
        recordInfo.put("name", resource.resourceName);
        recordInfo.put("ttl", resource.TTL);
        recordInfo.put("class", resource.resourceClass);
        recordInfo.put("rtype", resource.resourceType);
        System.out.println("Inserting into rdata into map: " + resource.RData);
        System.out.println("Inserting into name into map: " + resource.resourceName);
        System.out.println("Inserting into ttl into map: " + resource.TTL);
        System.out.println("Inserting into class into map: " + resource.resourceClass);
        System.out.println("Inserting into rtype into map: " + resource.resourceType);
        recordList.add(recordInfo);
        System.out.println("Current offset after parse resource: " + currAddr);
        i++;
     }
     System.out.println("Current offset after parse all resources for type: " + type + " " + currAddr);
     if (n != 0) printRecordListVals(recordList);
     return recordList;
 }

 private void printRecordListVals(List<Map<String, String>> recordList) {
     for (int i=0; i < recordList.size(); i++) {
        System.out.println("rdata val : " + recordList.get(i).get("rdata"));
        System.out.println("ttl val: " + recordList.get(i).get("ttl"));
        System.out.println("name val: " + recordList.get(i).get("name"));
        System.out.println("class val: " + recordList.get(i).get("class"));
        System.out.println("rtype val: " + recordList.get(i).get("rtype"));
     }
 }

 private void printServerArr () {
    for (int i=0; i < serversToQueryArr.size(); i++) {
       System.out.println("ipAddress val: " + serversToQueryArr.get(i));
    }
}

 // if AA bit is 1 and  RCode is 0 (no error) check if an answer field exists
 private void validateAuthResponse() {
     boolean authBool = this.authFlag == "true"? true: false;
     boolean RCodeBool = this.RCode == 0;
     boolean numAnswerBool = this.numAnswers > 0;
     this.validAuthFlag = authBool && RCodeBool && numAnswerBool;
 }

 private void getServersToQuery() {
     boolean hasNameRecords = this.numNameservers > 0;
    boolean hasAddrecords = this.numAddInfo > 0;
    // if not a valid authoratiative answer and has name + additional records
     if (!this.isAuth && hasNameRecords && hasAddrecords)  {
        for (int i=0; i < this.numAddInfo; i++) {
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

 private boolean isAuthResponse() {
     boolean authBool = this.authFlag == "true" ? true : false;
     return authBool;
 }

 private byte[] extractHeaderBytes(byte[] buffer) {
     byte[] headerBytes = readResponseBuff(HEADER_SIZE, buffer);
     String hexResString = Bytehelper.bytesToHex(headerBytes);
     System.out.println("Response header HEXstring: " + hexResString);
     return headerBytes;
 }


private byte[] readBytes(int start, int num, byte[] bytes) {
    int i = 0;
    byte[] resBytes = new byte[num];
    while (i < num && start< bytes.length) {
        resBytes[i] = bytes[start];
        i++;
        start++;
    }
    return resBytes;
}

// https://stackoverflow.com/questions/9354860/how-to-get-the-value-of-a-bit-at-a-certain-position-from-a-byte
private int getBit (byte b, int position) {
    return (b >> position) & 1;
}

// https://www.geeksforgeeks.org/extract-k-bits-given-position-number/
// extract n bits from position pos inclusive
private int bitExtracted(int number, int n, int pos) 
    { 
        return (((1 << n) - 1) & (number >> (pos - 1))); 
    } 

private static String removeLastChar(String str) {
    return str.substring(0, str.length() - 1);
}
 // read the given num bytes of response buffer
 private byte[] readResponseBuff(int num, byte[] bytes) {
     int i =0;
     byte[] resArr = new byte[num];
     while (i < num && currAddr < bytes.length) {
         resArr[i] = bytes[currAddr];
         currAddr++;
         i++;
     }
     return resArr;
 }

}