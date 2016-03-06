/**
 *  Created 2/16/2003 by Ting Zhang 
 *  Part of implementation of the ChatClient to receive
 *  all the messages posted to the chat room.
 */
package cs470_chat;

// socket
import java.net.*;
import java.io.*;
import java.nio.ByteBuffer;

//  Swing
import javax.swing.JTextArea;

//  Crypto
import java.security.*;
import java.security.spec.*;
import java.security.interfaces.*;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;

public class ChatClientThread extends Thread {

    private ChatClient _client;
    private JTextArea _outputArea;
    private Socket _socket = null;
    ObjectInputStream in;

    public ChatClientThread(ChatClient client) {

        super("ChatClientThread");
        _client = client;
        _socket = client.getSocket();
        _outputArea = client.getOutputArea();
        in = client.getInStream();
    }

    public void run() {
        try {

            Key roomkey = _client.roomkey;
            Key mackey = _client.mackey;
            Mac mac = Mac.getInstance("HmacSHA256");
            Cipher c = Cipher.getInstance(roomkey.getAlgorithm());
            mac.init(mackey);
            c.init(Cipher.DECRYPT_MODE, roomkey);
            
            byte[] msg;
            byte[] ac;

            System.out.println("1");
            while ((msg = ((ByteWrapper)in.readObject()).data) != null) {
                System.out.println("2");
                ac = ((ByteWrapper)in.readObject()).data;
                System.out.println("3");
                if (!Arrays.equals(ac, mac.doFinal(msg))) {
                    System.out.println("Incorrect mac.");
                }
                System.out.println("4");
                mac.init(mackey);
                System.out.println("5");
                msg = c.doFinal(msg);
                System.out.println("6");
                c.init(Cipher.DECRYPT_MODE, roomkey);
                System.out.println("7");
                consumeMessage(new String(msg) + " \n");
                System.out.println("8");
            }

            _socket.close();

        } catch (IOException e) {

            e.printStackTrace();
        } catch (NoSuchAlgorithmException ex) {
            ex.printStackTrace();
        } catch (NoSuchPaddingException ex) {
            ex.printStackTrace();
        } catch (InvalidKeyException ex) {
            ex.printStackTrace();
        } catch (ClassNotFoundException ex) {
            ex.printStackTrace();
        } catch (IllegalBlockSizeException ex) {
            ex.printStackTrace();
        } catch (BadPaddingException ex) {
            ex.printStackTrace();
        }

    }

    public void consumeMessage(String msg) {


        if (msg != null) {
            _outputArea.append(msg);
        }

    }
}
