/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cs470_chat;

import java.io.Serializable;

/**
 *
 * @author fkrt_kya
 */
public class ByteWrapper implements Serializable {
    static final long serialVersionUID = 7526472295622776147L;
    public byte[] data;
    
    public ByteWrapper( byte[] data) {
        this.data = data;
    }
}
