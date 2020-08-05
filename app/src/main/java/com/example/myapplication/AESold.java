package com.example.myapplication;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

import static javax.crypto.Cipher.ENCRYPT_MODE;




/*
public class AESold {

    private String AESEncryptionMethod(String string){

        byte[] stringByte = string.getBytes();
        byte[] encryptedByte = new byte[stringByte.length];
        try {
        //    cipher.init(ENCRYPT_MODE,secretKeySpec);
            encryptedByte = cipher.doFinal(stringByte);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        String returnString = null;
        try {
            returnString = new String(encryptedByte,"ISO-8859-1");//specifying what character set to use
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return returnString;
    }
    private String AESDecryptionMethod(String string) {
        String decryptedString = null;
        try {
            byte[] EncryptedByte = string.getBytes("ISO-8859-1"); //specifying what character set to use
            decryptedString = string;
            byte[] decryption;
            Cipher decipher;
          //  decipher.init(cipher.DECRYPT_MODE, secretKeySpec); // init decrypt mode with key
            //decryption = decipher.doFinal(EncryptedByte); // pass encrypted msg to algorithm
            //decryptedString = new String(decryption); //Plaintext

        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return decryptedString;
    }
}

*/

