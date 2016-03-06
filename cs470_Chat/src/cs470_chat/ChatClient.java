//  ChatClient.java
//
//  Modified 1/30/2000 by Alan Frindell
//  Last modified 2/18/2003 by Ting Zhang 
//  Last modified : Priyank Patel <pkpatel@cs.stanford.edu>
//
//  Chat Client starter application.
package cs470_chat;

//  AWT/Swing
import java.awt.*;
import java.awt.event.*;
import javax.swing.*;

//  Java
import java.io.*;
import java.math.BigInteger;

// socket
import java.net.*;
import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;



//  Crypto
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

public class ChatClient {

    public static final int SUCCESS = 0;
    public static final int CONNECTION_REFUSED = 1;
    public static final int BAD_HOST = 2;
    public static final int ERROR = 3;
    String _loginName;
    ChatServer _server;
    ChatClientThread _thread;
    ChatLoginPanel _loginPanel;
    ChatRoomPanel _chatPanel;
    CardLayout _layout;
    JFrame _appFrame;
    SecretKey sessionKey;
    SecretKey roomkey;
    SecretKey mackey;
    byte[] TGT;
    ObjectOutputStream _out;
    ObjectInputStream _in;

    Socket _socket = null;
    SecureRandom secureRandom;
    KeyStore clientKeyStore;
//    KeyManagerFactory keyManagerFactory;
//    TrustManagerFactory trustManagerFactory;
  
    //  ChatClient Constructor
    //
    //  empty, as you can see.
    public ChatClient() {
        _loginName = null;
        _server = null;

        try {
            initComponents();
        } catch (Exception e) {
            System.out.println("ChatClient error: " + e.getMessage());
            e.printStackTrace();
        }

        _layout.show(_appFrame.getContentPane(), "Login");

    }

    public void run() {
        _appFrame.pack();
        _appFrame.setVisible(true);

    }

    //  main
    //
    //  Construct the app inside a frame, in the center of the screen
    public static void main(String[] args) {
        
        ChatClient app = new ChatClient();

        app.run();
    }

    //  initComponents
    //
    //  Component initialization
    private void initComponents() throws Exception {

        _appFrame = new JFrame("CS255 Chat");
        _appFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        _layout = new CardLayout();
        _appFrame.getContentPane().setLayout(_layout);
        _loginPanel = new ChatLoginPanel(this);
        _chatPanel = new ChatRoomPanel(this);
        _appFrame.getContentPane().add(_loginPanel, "Login");
        _appFrame.getContentPane().add(_chatPanel, "ChatRoom");
        _appFrame.addWindowListener(new WindowAdapter() {

            public void windowClosing(WindowEvent e) {
                quit();
            }
        });
    }

    //  quit
    //
    //  Called when the application is about to quit.
    public void quit() {

        try {
            _socket.shutdownOutput();
            //_thread.join();
            _socket.close();

        } catch (Exception err) {
            System.out.println("ChatClient error: " + err.getMessage());
            err.printStackTrace();
        } finally {
            System.exit(0);
        }
    }

    //
    //  connect
    //
    //  Called from the login panel when the user clicks the "connect"
    //  button. You will need to modify this method to add certificate
    //  authentication.  
    //  There are two passwords : the keystorepassword is the password
    //  to access your private key on the file system
    //  The other is your authentication password on the CA.
    //
    public int connect(String loginName, char[] password,
            String keyStoreName, char[] keypass,
            String caHost, int caPort,
            String serverHost, int serverPort) {

        try {

            _loginName = loginName;
            clientKeyStore = KeyStore.getInstance("jceks");
            clientKeyStore.load(new FileInputStream(keyStoreName), keypass);
            _socket = new Socket(serverHost, serverPort);
            _in = new ObjectInputStream( _socket.getInputStream());
            _out = new ObjectOutputStream( _socket.getOutputStream());
            authenticate(loginName, password, keyStoreName, keypass, caHost);

            _layout.show(_appFrame.getContentPane(), "ChatRoom");

            _thread = new ChatClientThread(this);
            _thread.start();
            return SUCCESS;

        } catch (UnknownHostException e) {

            System.err.println("Don't know about the serverHost: " + serverHost);
            System.exit(1);

        } catch (IOException e) {

            System.err.println("Couldn't get I/O for "
                    + "the connection to the serverHost: " + serverHost);
            System.out.println("ChatClient error: " + e.getMessage());
            e.printStackTrace();

            System.exit(1);

        } catch (AccessControlException e) {

            return BAD_HOST;

        } catch (Exception e) {

            System.out.println("ChatClient err: " + e.getMessage());
            e.printStackTrace();
        }

        return ERROR;

    }

    //  sendMessage
    //
    //  Called from the ChatPanel when the user types a carrige return.
    public void sendMessage(String msg) {
        
        try {
            System.out.println("1");
            msg = _loginName + "> " + msg;
            System.out.println("2");
            byte[] response = msg.getBytes();
            System.out.println("3");
            Cipher c = Cipher.getInstance(roomkey.getAlgorithm());
            System.out.println("4");
            Mac mac = Mac.getInstance("HmacSHA256");
            System.out.println("5");
            c.init(Cipher.ENCRYPT_MODE, roomkey);
            System.out.println("6");
            mac.init(mackey);
            System.out.println("7");
            response = c.doFinal(response);
            System.out.println("8");
            _out.writeObject(new ByteWrapper(response));
            System.out.println("9");
            response = mac.doFinal(response);
            System.out.println("10");
            _out.writeObject(new ByteWrapper(response));
            System.out.println("11");

        } catch (Exception e) {

            System.out.println("ChatClient err: " + e.getMessage());
            e.printStackTrace();
        }

    }

    public Socket getSocket() {

        return _socket;
    }

    public JTextArea getOutputArea() {

        return _chatPanel.getOutputArea();
    }
    
    public void authenticate(String name, char[] pass, String keyStoreName, char[] keypass, String rname) {
        try {
            System.out.println("Client in authenticate.");
            Socket authSocket = null;
            ObjectInputStream authInput = null;
            ObjectOutputStream authOutput = null;
            try {
                authSocket = new Socket("localhost", 7777);
                authOutput = new ObjectOutputStream( authSocket.getOutputStream());
                authInput = new ObjectInputStream( authSocket.getInputStream());
            } catch (IOException ex) {
                Logger.getLogger(ChatClientThread.class.getName()).log(Level.SEVERE, null, ex);
            }
            System.out.println("Connected to authenticate.");
            authOutput.writeObject("TGT");
            System.out.println("Sent TGT request.");
            authOutput.writeObject(name);
            System.out.println("Sent name: " + name);
            System.out.println("At keystore");
            clientKeyStore = KeyStore.getInstance("jceks");
            clientKeyStore.load(new FileInputStream(keyStoreName), pass);
            byte[] nonce = null;
            try {
                nonce = ((ByteWrapper) authInput.readObject()).data;
                java.security.cert.Certificate cert = (java.security.cert.Certificate) authInput.readObject();
                PublicKey askey = clientKeyStore.getCertificate("business").getPublicKey();
                cert.verify(askey);
            } catch (IOException ex) {
                ex.printStackTrace();
            } catch (ClassNotFoundException ex) {
                ex.printStackTrace();
            } catch (NoSuchProviderException ex) {
                ex.printStackTrace();
                System.exit(ERROR);
            } catch (SignatureException ex) {
                ex.printStackTrace();
                System.exit(ERROR);
            }
            Key key = clientKeyStore.getKey(name, keypass);
            ByteBuffer buffer = ByteBuffer.wrap(nonce);
            int nonceInt = buffer.getInt();
            System.out.println("nonce: " + nonceInt);
            nonceInt++;
            Cipher c = Cipher.getInstance(key.getAlgorithm());
            c.init(Cipher.ENCRYPT_MODE, key);
            byte[] response = c.doFinal(ByteBuffer.allocate(4).putInt(nonceInt).array());
            authOutput.writeObject(new ByteWrapper(response));
            byte[] input = null;
            input = ((ByteWrapper) authInput.readObject()).data;
            c.init(Cipher.DECRYPT_MODE, key);
            byte[] temp = c.doFinal(input);
            sessionKey = new SecretKeySpec( temp, "DES");
            input = ((ByteWrapper) authInput.readObject()).data;
            c.init(Cipher.DECRYPT_MODE, key);
            TGT = c.doFinal(input);
            authInput.close();
            authOutput.close();
            authSocket.close();
            System.out.println("TGS start.");
            Socket tgsSocket = new Socket("localhost", 7778);
            ObjectInputStream tgsInput = new ObjectInputStream( tgsSocket.getInputStream());
            ObjectOutputStream tgsOutput = new ObjectOutputStream( tgsSocket.getOutputStream());
            tgsOutput.writeObject(name);
            tgsOutput.writeObject(rname);
            tgsOutput.writeObject(new ByteWrapper(TGT));
            input = ((ByteWrapper)tgsInput.readObject()).data;
            c = Cipher.getInstance(sessionKey.getAlgorithm());
            c.init(Cipher.DECRYPT_MODE, sessionKey);
            roomkey = new SecretKeySpec( c.doFinal(input), "DES");
            input = ((ByteWrapper)tgsInput.readObject()).data;
            c = Cipher.getInstance(sessionKey.getAlgorithm());
            c.init(Cipher.DECRYPT_MODE, sessionKey);
            mackey = new SecretKeySpec( c.doFinal(input), "DES");
            tgsOutput.close();
            tgsInput.close();
            tgsSocket.close();
            System.out.println("Starting Connection.");
            SecureRandom secureGenerator = new SecureRandom();
            nonce = new byte[4];
            secureGenerator.nextBytes(nonce);
            c = Cipher.getInstance(roomkey.getAlgorithm());
            c.init(Cipher.ENCRYPT_MODE, roomkey);
            _out.writeObject(new ByteWrapper(c.doFinal(nonce)));
            buffer = ByteBuffer.wrap(nonce);
            nonceInt = buffer.getInt();
            nonceInt++;
            input = ((ByteWrapper) _in.readObject()).data;
            c.init(Cipher.DECRYPT_MODE, roomkey);
            byte[] decrypted = c.doFinal(input);
            int decryptedInt = ByteBuffer.wrap(decrypted).getInt();
            if ( nonceInt != decryptedInt) {
                System.out.println("Authentication with Room Failed. " + nonceInt + " != " + decryptedInt);
                System.exit(ERROR);
            }
            System.out.println("Connection Successful.");
        } catch (FileNotFoundException ex) {
            ex.printStackTrace();
        } catch (IOException ex) {
            ex.printStackTrace();
        } catch (NoSuchAlgorithmException ex) {
            ex.printStackTrace();
        } catch (CertificateException ex) {
            ex.printStackTrace();
        } catch (KeyStoreException ex) {
            ex.printStackTrace();
        } catch (UnrecoverableKeyException ex) {
            ex.printStackTrace();
        } catch (NoSuchPaddingException ex) {
            ex.printStackTrace();
        } catch (InvalidKeyException ex) {
            ex.printStackTrace();
        } catch (IllegalBlockSizeException ex) {
            ex.printStackTrace();
        } catch (BadPaddingException ex) {
            ex.printStackTrace();
        } catch (ClassNotFoundException ex) {
            ex.printStackTrace();
        }
    }
    
    public ObjectInputStream getInStream() {
        return _in;
    }
}
