package com.example.encryptme;

import android.content.Context;
import android.util.Log;

import java.io.BufferedReader;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.concurrent.ExecutionException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class RSA {

    public PrivateKey llavePrivada = null;
    public PublicKey llavePublica = null;

    public Context context;

    public RSA(){

    }

    public Context getContext(){
        return context;
    }

    public void setContext(Context context){
        this.context = context;
    }

    public void setLlavePrivadaString(String key) throws NoSuchAlgorithmException, InvalidKeyException{

        byte[] llavePrivadaCodificada = stringToBytes(key);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec llavePrivadaSpec = new PKCS8EncodedKeySpec(llavePrivadaCodificada);

        try {
            PrivateKey privateKey = keyFactory.generatePrivate(llavePrivadaSpec);
            this.llavePrivada = privateKey;
        } catch (Exception e){
            Log.e("ExceptionPrivate","Exception error generating the private key");
        }

    }

    public void setLlavePublicaString(String key) throws NoSuchAlgorithmException, InvalidKeyException{

        byte[] llavePublicaCodificada = stringToBytes(key);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec llavePublicaSpec = new X509EncodedKeySpec(llavePublicaCodificada);

        try {
            PublicKey publicKey = keyFactory.generatePublic(llavePublicaSpec);
            this.llavePublica = publicKey;
        } catch (Exception e){
            Log.e("ExceptionPublic", "Exception error generating the public key");
        }

    }

    public String getLlavePrivadaKeyString(){

        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(this.llavePrivada.getEncoded());

        return bytesToString(pkcs8EncodedKeySpec.getEncoded());

    }

    public String getLlavePublicaKeyString(){

        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(this.llavePublica.getEncoded());

        return bytesToString(x509EncodedKeySpec.getEncoded());

    }

    public void generarParejaLLaves(int size) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(size);
        KeyPair kp = kpg.genKeyPair();

        PublicKey llavePublica = kp.getPublic();
        PrivateKey llavePrivada = kp.getPrivate();

        this.llavePublica = llavePublica;
        this.llavePrivada = llavePrivada;

    }

    public String Encriptar(String plain) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{

        byte[] encryptedBytes;

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, this.llavePublica);
        encryptedBytes = cipher.doFinal(plain.getBytes());

        return bytesToString(encryptedBytes);

    }

    public String Desencriptar(String result) throws NoSuchAlgorithmException,NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
        byte[] decryptedBytes;

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE,this.llavePrivada);
        decryptedBytes = cipher.doFinal(stringToBytes(result));

        return new String(decryptedBytes);

    }

    public String bytesToString(byte[] b) {
        byte[] b2 = new byte[b.length + 1];
        b2[0] = 1;
        System.arraycopy(b, 0, b2, 1, b.length);
        return new BigInteger(b2).toString(36);
    }

    public byte[] stringToBytes(String s) {
        byte[] b2 = new BigInteger(s, 36).toByteArray();
        return Arrays.copyOfRange(b2, 1, b2.length);
    }

    public void guardarLlavePrivadaEnDisco(String path){
        try {
            FileOutputStream outputStream = null;
            outputStream =  this.context.openFileOutput(path, Context.MODE_PRIVATE);
            outputStream.write(this.getLlavePrivadaKeyString().getBytes());
            outputStream.close();
        } catch (Exception e) {
            Log.d("RSA:","Error write PrivateKey");
        }
    }

    public void guardarLlavePublicaEnDisco(String path) {
        try {
            FileOutputStream outputStream = null;
            outputStream =  this.context.openFileOutput(path, Context.MODE_PRIVATE);
            outputStream.write(this.getLlavePublicaKeyString().getBytes());
            outputStream.close();
        } catch (Exception e) {
            Log.d("RSA:","Error write Public");
        }
    }

    public void abrirLlavePublicaEnDisco(String path) throws InvalidKeySpecException, NoSuchAlgorithmException, IOException, InvalidKeyException {
        String content = this.readFileAsString(path);
        this.setLlavePublicaString(content);
    }

    public void abrirLlavePrivadaEnDisco(String path) throws InvalidKeySpecException, NoSuchAlgorithmException, IOException, InvalidKeyException {
        String content = this.readFileAsString(path);
        this.setLlavePrivadaString(content);
    }


    private String readFileAsString(String filePath) throws IOException {

        BufferedReader fin = new BufferedReader(new InputStreamReader(context.openFileInput(filePath)));
        String txt = fin.readLine();
        fin.close();
        return txt;

    }

}
