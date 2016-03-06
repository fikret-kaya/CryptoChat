//
//  TGServerThread.java
//
//  Written by : Priyank Patel <pkpatel@cs.stanford.edu>
//
//  Accepts connection requests and processes them
package cs470_chat;

// socket
import java.net.*;
import java.io.*;

// Swing
import javax.swing.JTextArea;

//  Crypto
import java.security.*;
import java.security.spec.*;
import java.security.interfaces.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;

public class TGServerThread extends Thread {

    private TGServer _tgs;
    private ServerSocket _serverSocket = null;
    private int _portNum;
    private String _hostName;
    private JTextArea _outputArea;

    public TGServerThread(TGServer tgs) {

        super("AuthServerThread");
        _tgs = tgs;
        _portNum = tgs.getPortNumber();
        _outputArea = tgs.getOutputArea();
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
                System.out.println("TGS start.");
                ObjectOutputStream socketOutput = new ObjectOutputStream( socket.getOutputStream());
                ObjectInputStream socketInput = new ObjectInputStream( socket.getInputStream());
                String cname = (String) socketInput.readObject();
                String rname = (String) socketInput.readObject();
                byte[] TGT = ((ByteWrapper)socketInput.readObject()).data;
                KeyStore ks = _tgs.getKeyStore();
                char[] pass = _tgs.getPass();
                Key tgskey = ks.getKey("tgs", pass);
                Cipher c = Cipher.getInstance(tgskey.getAlgorithm());
                c.init(Cipher.DECRYPT_MODE, tgskey);
                Key sessionKey = new SecretKeySpec(c.doFinal(TGT), "DES");
                Key roomkey = ks.getKey(rname, _tgs.getPass());
                Key mackey = ks.getKey("mac" + rname.substring(rname.length()-1), _tgs.getPass());
                c = Cipher.getInstance(sessionKey.getAlgorithm());
                c.init(Cipher.ENCRYPT_MODE, sessionKey);
                byte[] response = c.doFinal(roomkey.getEncoded());
                socketOutput.writeObject(new ByteWrapper(response));
                c.init(Cipher.ENCRYPT_MODE, sessionKey);
                response = c.doFinal(mackey.getEncoded());
                socketOutput.writeObject(new ByteWrapper(response));
                socketInput.close();
                socketOutput.close();
                socket.close();
            }
        } catch (Exception e) {
            System.out.println("AS thread error: " + e.getMessage());
            e.printStackTrace();
        }

    }
}
