package ca.ubc.cs.cs317.dnslookup;
import java.io.Console;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.net.DatagramPacket;
import java.math.BigInteger;
import java.lang.*;
import java.util.*;

public class DNSLookupService {

 private static final int DEFAULT_DNS_PORT = 53;
 private static final int MAX_INDIRECTION_LEVEL = 10;
 private static final int TIMEOUT = 5000;
 private static final int MAX_RESPONSE_SIZE = 1024; // Max number of bytes of response buffer 
 private static final int MAX_SEND_SIZE = 512; // max number of bytes to send


 private static InetAddress rootServer;
 private static boolean verboseTracing = false;
 private static DatagramSocket socket;
 private static String lookupString;
 private static RecordType qType;
 private final static char[] hexArray = "0123456789ABCDEF".toCharArray();


 private static DNSCache cache = DNSCache.getInstance();

 private static Random random = new Random();

 /**
  * Main function, called when program is first invoked.
  *
  * @param args list of arguments specified in the command line.
  */
 public static void main(String[] args) {

  if (args.length != 1) {
   System.err.println("Invalid call. Usage:");
   System.err.println("\tjava -jar DNSLookupService.jar rootServer");
   System.err.println("where rootServer is the IP address (in dotted form) of the root DNS server to start the search at.");
   System.exit(1);
  }

  try {
   rootServer = InetAddress.getByName(args[0]);
   System.out.println("Root DNS server is: " + rootServer.getHostAddress());
  } catch (UnknownHostException e) {
   System.err.println("Invalid root server (" + e.getMessage() + ").");
   System.exit(1);
  }

  try {
   socket = new DatagramSocket();
   socket.setSoTimeout(5000);
  } catch (SocketException ex) {
   ex.printStackTrace();
   System.exit(1);
  }

  Scanner in = new Scanner(System.in);
  Console console = System.console();
  do {
   // Use console if one is available, or standard input if not.
   String commandLine;
   if (console != null) {
    System.out.print("DNSLOOKUP> ");
    commandLine = console.readLine();
   } else
    try {
     commandLine = in .nextLine();
    } catch (NoSuchElementException ex) {
     break;
    }
   // If reached end-of-file, leave
   if (commandLine == null) break;

   // Ignore leading/trailing spaces and anything beyond a comment character
   commandLine = commandLine.trim().split("#", 2)[0];

   // If no command shown, skip to next command
   if (commandLine.trim().isEmpty()) continue;

   String[] commandArgs = commandLine.split(" ");

   if (commandArgs[0].equalsIgnoreCase("quit") ||
    commandArgs[0].equalsIgnoreCase("exit"))
    break;
   else if (commandArgs[0].equalsIgnoreCase("server")) {
    // SERVER: Change root nameserver
    if (commandArgs.length == 2) {
     try {
      rootServer = InetAddress.getByName(commandArgs[1]);
      System.out.println("Root DNS server is now: " + rootServer.getHostAddress());
     } catch (UnknownHostException e) {
      System.out.println("Invalid root server (" + e.getMessage() + ").");
      continue;
     }
    } else {
     System.out.println("Invalid call. Format:\n\tserver IP");
     continue;
    }
   } else if (commandArgs[0].equalsIgnoreCase("trace")) {
    // TRACE: Turn trace setting on or off
    if (commandArgs.length == 2) {
     if (commandArgs[1].equalsIgnoreCase("on"))
      verboseTracing = true;
     else if (commandArgs[1].equalsIgnoreCase("off"))
      verboseTracing = false;
     else {
      System.err.println("Invalid call. Format:\n\ttrace on|off");
      continue;
     }
     System.out.println("Verbose tracing is now: " + (verboseTracing ? "ON" : "OFF"));
    } else {
     System.err.println("Invalid call. Format:\n\ttrace on|off");
     continue;
    }
   } else if (commandArgs[0].equalsIgnoreCase("lookup") ||
    commandArgs[0].equalsIgnoreCase("l")) {
    // LOOKUP: Find and print all results associated to a name.
    RecordType type;
    if (commandArgs.length == 2) {
     type = RecordType.A;
     qType = type;
     lookupString = commandArgs[1];
    } else if (commandArgs.length == 3)
     try {
      type = RecordType.valueOf(commandArgs[2].toUpperCase());
      qType = type;
      lookupString = commandArgs[1];
     } catch (IllegalArgumentException ex) {
      System.err.println("Invalid query type. Must be one of:\n\tA, AAAA, NS, MX, CNAME");
      continue;
     }
    else {
     System.err.println("Invalid call. Format:\n\tlookup hostName [type]");
     continue;
    }
    findAndPrintResults(commandArgs[1], type);
   } else if (commandArgs[0].equalsIgnoreCase("dump")) {
    // DUMP: Print all results still cached
    cache.forEachNode(DNSLookupService::printResults);
   } else {
    System.err.println("Invalid command. Valid commands are:");
    System.err.println("\tlookup fqdn [type]");
    System.err.println("\ttrace on|off");
    System.err.println("\tserver IP");
    System.err.println("\tdump");
    System.err.println("\tquit");
    continue;
   }

  } while (true);

  socket.close();
  System.out.println("Goodbye!");
 }

 /**
  * Finds all results for a host name and type and prints them on the standard output.
  *
  * @param hostName Fully qualified domain name of the host being searched.
  * @param type     Record type for search.
  */
 private static void findAndPrintResults(String hostName, RecordType type) {

  DNSNode node = new DNSNode(hostName, type);
  //  is initial call always with 0 even if recordType is CNAME
  printResults(node, getResults(node, 0));
 }

 /**
  * Finds all the result for a specific node.
  *
  * @param node             Host and record type to be used for search.
  * @param indirectionLevel Control to limit the number of recursive calls due to CNAME redirection.
  *                         The initial call should be made with 0 (zero), while recursive calls for
  *                         regarding CNAME results should increment this value by 1. Once this value
  *                         reaches MAX_INDIRECTION_LEVEL, the function prints an error message and
  *                         returns an empty set.
  * @return A set of resource records corresponding to the specific query requested.
  */
 private static Set < ResourceRecord > getResults(DNSNode node, int indirectionLevel) {
  DNSQuery qf = new DNSQuery(node);
  qf.DNSIA = rootServer;
  Set<ResourceRecord> cacheResults = cache.getCachedResults(node);
  if (!cacheResults.isEmpty()) {
    return cacheResults;
  } 
  DNSResponse qr = send_udp_message(qf);
  if (qr.isAuth) {
    // if DNS response is authorartive and is valid authoratative 
    if (qr.validAuthFlag) {
      return cache.getCachedResults(node);
    } else {
      // TODO handle this case 
      throw new RuntimeException("Auth error: response is authoroatative and Rcode is 0: no error but no answers");
    }
    // TODO CATCH CASE WHERE VALIDAUTHRESPONSE IS FALSE AND AA BIT (1) + RCODE (0) *TERMINATE THERE ERROR
    // terminate as reached valid auth response
  } else {
    // keep querying
    if (indirectionLevel > MAX_INDIRECTION_LEVEL) {
      System.err.println("Maximum number of indirection levels reached.");
      return Collections.emptySet();
     }
     List<String> serverArr = qr.serversToQueryArr;
     System.out.println("Servers to query");
     qr.printServerArr();
     System.out.println(serverArr.size());
     makeAdditionalQueries(serverArr, node);
  }
  // TODO To be completed by the student
  return cache.getCachedResults(node);
 }

 private static boolean makeAdditionalQueries(List<String> serversArr, DNSNode serverNode) {
   for (int i=0; i < serversArr.size(); i++) {
     String ipAddress = serversArr.get(i);
     DNSQuery qf = new DNSQuery(serverNode);
     try {
      qf.DNSIA = InetAddress.getByName(ipAddress);
      System.out.println("Querying Ip address: " + ipAddress);
      DNSResponse qr = send_udp_message(qf);
      if (qr.isAuth) {
        // terminate 
        System.out.println("Response is Authoratative - Terminate");
        // TODO need to check if qr is validAuth as well?
        return true;
      } else {
        if (qr.queryNSFlag) {
          // INFINIT recursion case ???
          List<Map<String, String>> nsMap = qr.nameRecords;
          String nameServerIP = queryNameRecords(nsMap);
          DNSNode newNode = new DNSNode(nameServerIP, qType);
          getResults(newNode, 0);
          return true;
        }
        List<String> responseQuerries = qr.serversToQueryArr;
        boolean isAuthFound = makeAdditionalQueries(responseQuerries, serverNode);
        if (isAuthFound != false) {
          return true;
        }
      }
     }
     catch(UnknownHostException err) {
       throw new RuntimeException("shoouldn't reach here");
     }
   }
   return false; 
 }

 private static String queryNameRecords(List<Map<String, String>> nameRecords) {
   for (int i=0; i < nameRecords.size(); i++) {
    String hostString = nameRecords.get(i).get("rdata");
    DNSNode nsNode = new DNSNode(hostString, qType);
    boolean nameServerFound = findNameServerIP(nsNode, rootServer, MAX_INDIRECTION_LEVEL);
    // if name server is found consult the cache associated with the node
    if (nameServerFound) {
      Object[] nsRecordsArr = cache.getCachedResults(nsNode).toArray();
      for (Object recordObj : nsRecordsArr) {
        ResourceRecord record = (ResourceRecord)recordObj;
        if (record.getTextResult() == nsNode.getHostName()) {
          System.out.println("CACHE CONTAINS THE NAME SERVER IP");
          return record.getTextResult();
        }
      }
    }
   }
   throw new RuntimeException("Name servers query finished, could not find ip address");
  }

  // return true if name server IP is found otherwise false
  private static boolean findNameServerIP (DNSNode node, InetAddress queryIA, int indirectionLevel) {
  DNSQuery qf = new DNSQuery(node);
  qf.DNSIA = queryIA;
  Set<ResourceRecord> cacheResults = cache.getCachedResults(node);
  if (!cacheResults.isEmpty()) {
    return true; //
  } 
  DNSResponse qr = send_udp_message(qf);
    // if DNS response is authorartive and is valid authoratative 
    if (qr.numARecords > 0 && qr.numNSRecords > 0) {
      if (qr.numARecords != qr.numNSRecords) throw new RuntimeException("number of name records and add records should be the same");
      // both name servers and add info length should be the same
      for (int i =0; i< qr.numARecords && i < qr.numNSRecords; i++) {
        String nsRData = qr.nsRecords.get(i).get("rdata");
        String addName = qr.aRecords.get(i).get("name");
        if (nsRData == addName) {
          System.out.println("Name server found");
          // name server found
          return true;
        } else {
          if (indirectionLevel > MAX_INDIRECTION_LEVEL) {
            System.err.println("Maximum number of indirection levels reached FOR RESOLVING NAME SERVER.");
            return true;
           }
           List<String> serverArr = qr.serversToQueryArr;
           System.out.println("Resolving name servers: Servers to query");
           qr.printServerArr();
           System.out.println(serverArr.size());
           for (int j =0; j  < serverArr.size(); j++) {
             try {
             InetAddress serverIA = InetAddress.getByName(serverArr.get(j));
            boolean isFound = findNameServerIP(node, serverIA, indirectionLevel + 1);
            if (isFound != false) {
              return true;
            }
          }
          catch(UnknownHostException err) {
            throw new RuntimeException(err);
            // TODO
          }
           }
           return false;
        }
      }
      return false;
  }
  return false; // not found
}

private void queryNameServerIP() {

}

 // udp in java send https://www.baeldung.com/udp-in-java
 // return true if response is a valid authoratative answer response, else false (keep querying)
 private static DNSResponse send_udp_message (DNSQuery qf) throws RuntimeException {
   String message = qf.queryString;
   String hostName = qf.lookupName;
   String typeInt = qf.type;
   int typeCode = Integer.parseInt(typeInt);
  String query_message = message.replace(" ", "").replace("\n", ""); // guard
  System.out.println("TO SEND: "+ query_message);
  byte[] data = Bytehelper.hexStringToByteArray(message);
  DatagramPacket pack = new DatagramPacket(data, data.length, qf.DNSIA, DEFAULT_DNS_PORT);
  try {
   DatagramSocket ds = new DatagramSocket();
   byte[] receiveBuf = new byte[1024];
   DatagramPacket rPack = new DatagramPacket(receiveBuf, receiveBuf.length);
   ds.setSoTimeout(TIMEOUT);
   ds.send(pack);
   ds.receive(rPack);
   // byte[] trimResBuffer = Bytehelper.byteTrim(rPack.getData()); // trim trailing 0s
   String receiveStr = Bytehelper.bytesToHex(rPack.getData());
   // System.out.println("Receive hexString: "+ receiveStr);
   try {
    DNSResponse extractedResponse = new DNSResponse(rPack.getData());
    cacheDNSResponse(extractedResponse);
    FormatOutputTrace(qf, extractedResponse);
    return extractedResponse;
   }
   catch(RuntimeException err) {
     System.out.println("Caught error here: " + err);
   }
  } catch (SocketException err) {
   System.out.println(err);
  } catch (SocketTimeoutException err2) {
   // TODO resend packet if not received output -1
  } catch (IOException e1) {
   System.out.println(e1);
  }
  System.out.println("Shouldn't reach here send_udp");
  throw new RuntimeException("Shouldn't reach here");
 }

 private static void FormatOutputTrace(DNSQuery qs, DNSResponse qr) {
     System.out.print("\n\n"); // begin with two blank lines
     System.out.println("Query Id     " + qs.transID + " " + qs.lookupName + "  " + qs.type + "--> " + qs.DNSIA.getHostAddress()); // TODO???
     System.out.println("Response ID: " + qr.responseID + " " + "Authoritative " + "= " + qr.authFlag);
     resourceRecordFormat("Answers", qr);
     resourceRecordFormat("Nameservers", qr);
     resourceRecordFormat("Additional Information", qr);
 }

 private static void cacheDNSResponse(DNSResponse qr) {
  int numAnswers = qr.numAnswers; // 
  int numNameservers = qr.numNameservers;
  int numAddInfo = qr.numAddInfo;
  List<Map<String, String>> answerMap = qr.answerRecords;
  List<Map<String, String>> nsMap = qr.nameRecords;
  List<Map<String, String>> addMap = qr.addRecords;
  cacheRecords(numAnswers, answerMap);
  cacheRecords(numNameservers, nsMap);
  cacheRecords(numAddInfo, addMap);
 }

 private static void cacheRecords(int numRecords, List<Map<String, String>> recordList) {
  for (int i =0; i < numRecords; i++) {
    String recordName = recordList.get(i).get("name");
    long recordTTL = Long.decode(recordList.get(i).get("ttl"));
    int recordType = Integer.parseInt(recordList.get(i).get("rtype"));
    String recordRData = recordList.get(i).get("rdata");
    // if resource type is A or AAAA make  RData an InetAddress based on the raw IP address string
    if (recordType == 1 || recordType == 28) {
      try {
      InetAddress InetRData = InetAddress.getByName(recordRData);
      ResourceRecord newRecord = new ResourceRecord(recordName, RecordType.getByCode(recordType), recordTTL, InetRData);
      cache.addResult(newRecord);
      } 
      catch (UnknownHostException err) {
        // TODO
      }
    } else {
      ResourceRecord newRecord = new ResourceRecord(recordName, RecordType.getByCode(recordType), recordTTL,  recordRData);
      cache.addResult(newRecord);
    }
  }
 }

 private static void resourceRecordFormat(String type, DNSResponse qr) {
   int numRecords;
   String recordName;
   long recordTTL;
   int recordType;
   String recordRData;
   List<Map<String, String>> recordList = new ArrayList<Map<String, String>>();
   switch(type) {
     case "Answers":
     numRecords = qr.numAnswers;
     recordList = qr.answerRecords;
     break;
     case "Nameservers":
     numRecords = qr.numNameservers;
     recordList = qr.nameRecords;
     break;
     case "Additional Information":
     numRecords = qr.numAddInfo;
     recordList = qr.addRecords;
     break;
     default:
     numRecords = 9999; // something went wrong, should never reach here
     break;
   }
   if (numRecords == 9999) throw new RuntimeException("Something went wrong in record Formatter"); // should never throw
   System.out.println(String.format("  %s (%d)", type, numRecords));
   for (int i =0; i < numRecords; i++) {
   recordName = recordList.get(i).get("name");
   recordTTL = Long.decode(recordList.get(i).get("ttl"));
   recordType = Integer.parseInt(recordList.get(i).get("rtype"));
   recordRData = recordList.get(i).get("rdata");
   ResourceRecord newRecord = new ResourceRecord(recordName, RecordType.getByCode(recordType), recordTTL, recordRData);
   verbosePrintResourceRecord(newRecord, recordType);
   }
 }

 /*
 // https://www.tutorialspoint.com/convert-hex-string-to-byte-array-in-java
 private static byte[] hexStringToByteArray(String str) {
  byte[] val = new byte[str.length() / 2];
  for (int i = 0; i < val.length && i < MAX_SEND_SIZE; i++) {
   int index = i * 2;
   int j = Integer.parseInt(str.substring(index, index + 2), 16);
   val[i] = (byte) j;
  }
  return val;
 }

 private static String bytesToHex(byte[] bytes) {
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
private static byte[] byteTrim(byte[] bytes)
{
    int i = bytes.length - 1;
    while (i >= 0 && bytes[i] == 0)
    {
        --i;
    }
    return Arrays.copyOf(bytes, i + 1);
}
*/

 /**
  * Retrieves DNS results from a specified DNS server. Queries are sent in iterative mode,
  * and the query is repeated with a new server if the provided one is non-authoritative.
  * Results are stored in the cache.
  *
  * @param node   Host name and record type to be used for the query.
  * @param server Address of the server to be used for the query.
  */
 private static void retrieveResultsFromServer(DNSNode node, InetAddress server) {

  // TODO To be completed by the student
 }

 private static void verbosePrintResourceRecord(ResourceRecord record, int rtype) {
  if (verboseTracing)
   System.out.format("       %-30s %-10d %-4s %s\n", record.getHostName(),
    record.getTTL(),
    record.getType() == RecordType.OTHER ? rtype : record.getType(),
    record.getTextResult());
 }

 /**
  * Prints the result of a DNS query.
  *
  * @param node    Host name and record type used for the query.
  * @param results Set of results to be printed for the node.
  */
 private static void printResults(DNSNode node, Set < ResourceRecord > results) {
  if (results.isEmpty())
   System.out.printf("%-30s %-5s %-8d %s\n", node.getHostName(),
    node.getType(), -1, "0.0.0.0");
  for (ResourceRecord record: results) {
   System.out.printf("%-30s %-5s %-8d %s\n", node.getHostName(),
    node.getType(), record.getTTL(), record.getTextResult());
  }
 }
}