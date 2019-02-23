package ca.ubc.cs.cs317.dnslookup;
import java.io.Console;
import java.io.IOException;
import ca.ubc.cs.cs317.dnslookup.QueryFormat;
import java.io.UnsupportedEncodingException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.net.DatagramPacket;
import java.math.BigInteger;
import java.util.*;

public class DNSLookupService {

 private static final int DEFAULT_DNS_PORT = 53;
 private static final int MAX_INDIRECTION_LEVEL = 10;
 private static final int TIMEOUT = 5000;

 private static InetAddress rootServer;
 private static boolean verboseTracing = false;
 private static DatagramSocket socket;
 private static String lookupString;
 private static RecordType qType;

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
  QueryFormat qf = new QueryFormat(lookupString);
  send_udp_message(qf.queryString);

  if (indirectionLevel > MAX_INDIRECTION_LEVEL) {
   System.err.println("Maximum number of indirection levels reached.");
   return Collections.emptySet();
  }

  // TODO To be completed by the student

  return cache.getCachedResults(node);
 }

 private static String send_udp_message(String message) {
  String query_message = message.replace(" ", "").replace("\n", ""); // guard
  System.out.println(query_message);
  byte[] data = hexStringToByteArray(query_message);
  DatagramPacket pack = new DatagramPacket(data, data.length, rootServer, DEFAULT_DNS_PORT);
  try {
   DatagramSocket ds = new DatagramSocket();
   byte[] receiveBuf = new byte[data.length];
   DatagramPacket rPack = new DatagramPacket(receiveBuf, data.length);
   ds.setSoTimeout(TIMEOUT);
   ds.send(pack);
   ds.receive(rPack);
   String rString = new String(rPack.getData(), 0, rPack.getLength());
   System.out.println(rString);
  } catch (SocketException err) {
   System.out.println(err);
  } catch (SocketTimeoutException err2) {
   // TODO resend packet if not received output -1
  } catch (IOException e1) {
   System.out.println(e1);
  }
  return "";
 }

 private static byte[] hexStringToByteArray(String s) {
  int len = s.length();
  byte[] data = new byte[len / 2];
  for (int i = 0; i < len; i += 2) {
   data[i / 2] = (byte)((Character.digit(s.charAt(i), 16) << 4) +
    Character.digit(s.charAt(i + 1), 16));
  }
  return data;
 }

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