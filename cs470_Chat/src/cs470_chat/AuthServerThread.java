//
//  AuthServerThread.java
//
//  Written by : Priyank Patel <pkpatel@cs.stanford.edu>
//
//  Accepts connection requests and processes them
package cs470_chat;

// socket
import java.net.*;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.MappedByteBuffer;

// Swing
import javax.swing.JTextArea;

//  Crypto
import java.security.*;
import java.security.spec.*;
import java.security.interfaces.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;

public class AuthServerThread extends Thread {

    private AuthServer _as;
    private ServerSocket _serverSocket = null;
    private int _portNum;
    private String _hostName;
    private JTextArea _outputArea;

    public AuthServerThread(AuthServer as) {

        super("AuthServerThread");
        _as = as;
        _portNum = as.getPortNumber();
        _outputArea = as.getOutputArea();
        _serverSocket = null;

        try {

            InetAddress serverAddr = InetAddress.getByName(null);
            _hostName = serverAddr.getHostName();

        } catch (UnknownHostException e) {
            _hostName = "0.0.0.0";
        }
    }
    
    //  Accept connections and service them one at a time
    public void run() {
        try {
            _serverSocket = new ServerSocket(_portNum);
            _outputArea.append("AS waiting on " + _hostName + " port " + _portNum);
            while (true) {
                Socket socket = _serverSocket.accept();
                ObjectOutputStream socketOutput = new ObjectOutputStream( socket.getOutputStream());
                ObjectInputStream socketInput = new ObjectInputStream( socket.getInputStream());
                String input = (String)socketInput.readObject();
                System.out.println("TGT :=: " + input);
                if ( input.equals("TGT")) {
                    input = (String)socketInput.readObject();
                    String cname = input;
                    System.out.println("client1 :=: " + input);
                    KeyStore ks = _as.getKeyStore();
                    Key key = ks.getKey( input, _as.getPass());
                    SecureRandom secureGenerator = new SecureRandom();
                    byte[] nonce = new byte[4];
                    secureGenerator.nextBytes(nonce);
                    java.security.cert.Certificate cert = ks.getCertificate("business");
                    socketOutput.writeObject(new ByteWrapper(nonce));
                    socketOutput.writeObject(cert);
                    ByteBuffer buffer = ByteBuffer.wrap(nonce);
                    int nonceInt = buffer.getInt();
                    System.out.println("nonce :" + nonceInt);
                    nonceInt++;
                    byte[] encrypted = ((ByteWrapper) socketInput.readObject()).data;
                    Cipher c = Cipher.getInstance(key.getAlgorithm());
                    c.init(Cipher.DECRYPT_MODE, key);
                    byte[] decrypted = c.doFinal(encrypted);
                    buffer = ByteBuffer.wrap(decrypted);
                    int decryptedInt = buffer.getInt();
                    System.out.println("nonce+1 :" + decryptedInt);
                    if ( nonceInt == decryptedInt) {
                        KeyGenerator generator = KeyGenerator.getInstance("DES");
                        generator.init(secureGenerator);
                        SecretKey sessionKey = generator.generateKey();
                        Key tgsKey = ks.getKey("tgs", "authserver".toCharArray());
                        c = Cipher.getInstance(tgsKey.getAlgorithm());
                        c.init(Cipher.ENCRYPT_MODE, tgsKey);
                        byte[] TGT = c.doFinal(sessionKey.getEncoded());
                        c = Cipher.getInstance(key.getAlgorithm());
                        c.init(Cipher.ENCRYPT_MODE, key);
                        byte[] response = c.doFinal(sessionKey.getEncoded());
                        socketOutput.writeObject(new ByteWrapper(response));
                        c.init(Cipher.ENCRYPT_MODE, key);
                        response = c.doFinal(TGT);
                        socketOutput.writeObject(new ByteWrapper(response));
                    } else {
                        System.out.println("Authentication with Server Failed. " + nonceInt + " != " + decryptedInt);
                        System.exit(5);
                    }
                }
                socketOutput.close();
                socketInput.close();
                socket.close();
            }
        } catch (Exception e) {
            System.out.println("AS thread error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
