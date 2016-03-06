//
// ChatServer.java
// Created by Ting on 2/18/2003
// Modified : Priyank K. Patel <pkpatel@cs.stanford.edu>
//
package cs470_chat;

// Java General
import java.util.*;
import java.math.BigInteger;

// socket
import java.net.*;
import java.io.*;

// Crypto
import java.security.*;
import java.security.cert.*;
import java.security.spec.*;
import java.security.interfaces.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;
import javax.security.auth.x500.*;
//import sun.security.x509.*;

public class ChatServer {
    private String roomName;
    private Hashtable _clients;
//      private Hashtable _clientsRoomA;
//      private Hashtable _clientsRoomB;
    private int _clientID = 0;
    private int _port;
    private String _hostName = null;
    // Some hints: security related fields.
    private String SERVER_KEYSTORE = "cskeystore";
    private char[] SERVER_KEYSTORE_PASSWORD = "cspass".toCharArray();
    private char[] SERVER_KEY_PASSWORD = "cspass".toCharArray();
    private ServerSocket _serverSocket = null;
    private SecureRandom secureRandom;
    private KeyStore serverKeyStore;
    private ArrayList<ObjectOutputStream> outStreams;
    private int cur = 0;
//    private KeyManagerFactory keyManagerFactory;
//    private TrustManagerFactory trustManagerFactory;
  
    public ChatServer(int port, String roomname) {
        roomName = roomname;
        outStreams = new ArrayList<ObjectOutputStream>();
        try {

            serverKeyStore = KeyStore.getInstance("jceks");
            serverKeyStore.load( new FileInputStream(SERVER_KEYSTORE), SERVER_KEYSTORE_PASSWORD);
            try {
                
                _clients = new Hashtable();
                _serverSocket = null;
                _clientID = -1;
                _port = port;
                InetAddress serverAddr = InetAddress.getByName(null);
                _hostName = serverAddr.getHostName();
                
            } catch (UnknownHostException e) {
                
                _hostName = "0.0.0.0";
                
            }

        } catch (FileNotFoundException ex) {

            ex.printStackTrace();

        } catch (KeyStoreException ex) {
            ex.printStackTrace();
        } catch (IOException ex) {
            ex.printStackTrace();
        } catch (NoSuchAlgorithmException ex) {
            ex.printStackTrace();
        } catch (CertificateException ex) {
            ex.printStackTrace();
        }
    }

    public static void main(String args[]) {

        try {

            if (args.length < 1) {

                //  Might need more arguments if extending for extra credit
                System.out.println("Usage: java ChatServer portNum");
                return;

            } else {
                int roomNo = 1;
                if ( args.length > 1) {
                    roomNo = Integer.parseInt(args[1]);
                }
                int port = Integer.parseInt(args[0]);
                String name = "room";
                name = name + roomNo;
                System.out.println(name);
                ChatServer server = new ChatServer(port, name);
                server.run();
                port++;
            }

        } catch (NumberFormatException e) {

            System.out.println("Useage: java ChatServer host portNum");
            e.printStackTrace();
            return;

        } catch (Exception e) {

            System.out.println("ChatServer error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /***
     *
     * Your methods for setting up secure connection
     *
     */
    public void run() {

        try {

            _serverSocket = new ServerSocket(_port);
            System.out.println("ChatServer is running on "
                    + _hostName + " port " + _port);

            while (true) {

                Socket socket = _serverSocket.accept();
                ClientRecord clientRecord = new ClientRecord(socket);
                _clients.put(new Integer(_clientID++), clientRecord);
                outStreams.add(new ObjectOutputStream( socket.getOutputStream()));
                ChatServerThread thread = new ChatServerThread(this, socket, roomName, cur);
                cur++;
                thread.start();
            }

            //_serverSocket.close();

        } catch (IOException e) {

            System.err.println("Could not listen on port: " + _port);
            System.exit(-1);

        } catch (Exception e) {

            e.printStackTrace();
            System.exit(1);

        }
    }

    public Hashtable getClientRecords() {

        return _clients;
    }
    
    public ArrayList<ObjectOutputStream> getOutStreams() {
        return outStreams;
    }
}
