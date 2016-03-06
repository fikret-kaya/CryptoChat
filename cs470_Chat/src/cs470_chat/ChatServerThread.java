//
// ChatServerThread.java
// created 02/18/03 by Ting Zhang
// Modified : Priyank K. Patel <pkpatel@cs.stanford.edu>
//
package cs470_chat;

// Java
import java.util.*;
import java.math.BigInteger;

// socket
import java.net.*;
import java.io.*;
import java.nio.ByteBuffer;


// Crypto
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.*;
import java.security.interfaces.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;

public class ChatServerThread extends Thread {


    private Socket _socket = null;
    private ChatServer _server = null;
    private Hashtable _records = null;
    private String name;
    private int no;

    public ChatServerThread(ChatServer server, Socket socket, String name, int no) {
        super("ChatServerThread");
        this.no = no;
        this.name = name;
        _server = server;
        _socket = socket;
        _records = server.getClientRecords();
    }

    public void run() {

        try {
            ObjectOutputStream clientOutput = _server.getOutStreams().get(no);
            ObjectInputStream clientInput = new ObjectInputStream( _socket.getInputStream());
            byte[] input = ((ByteWrapper)clientInput.readObject()).data;
            KeyStore ks = KeyStore.getInstance("jceks");
            ks.load(new FileInputStream(name+"keystore"), (name + "pass").toCharArray());
            Key key = ks.getKey(name, (name + "pass").toCharArray());
            Cipher cp = Cipher.getInstance(key.getAlgorithm());
            cp.init(Cipher.DECRYPT_MODE, key);
            byte[] nonce = cp.doFinal(input);
            int nonceInt = ByteBuffer.wrap(nonce).getInt();
            nonceInt++;
            System.out.println("nonce :=: " + nonceInt);
            nonce = ByteBuffer.allocate(4).putInt(nonceInt).array();
            cp.init(Cipher.ENCRYPT_MODE, key);
            byte[] response = cp.doFinal(nonce);
            clientOutput.writeObject(new ByteWrapper(response));
            Key mac = ks.getKey("mac" + name.substring(name.length()-1), (name + "pass").toCharArray());
            System.out.println("Connection Successful.");
            
            Object receivedMsg;
            Object receivedMac;

            while ((receivedMsg = clientInput.readObject()) != null) {
                receivedMac = clientInput.readObject();
                Enumeration theClients = _records.elements();

                int i = 0;
                ArrayList<ObjectOutputStream> clientOutputs = _server.getOutStreams();
                while (theClients.hasMoreElements()) {

                    ClientRecord c = (ClientRecord) theClients.nextElement();

                    clientOutputs.get(i).writeObject(receivedMsg);
                    clientOutputs.get(i).writeObject(receivedMac);
                    i++;

                }
            }

            _socket.shutdownInput();
            _socket.shutdownOutput();
            _socket.close();

        } catch (IOException e) {

            e.printStackTrace();
        } catch (ClassNotFoundException ex) {
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
        }

    }
}
