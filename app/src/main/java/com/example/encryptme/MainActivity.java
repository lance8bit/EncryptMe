package com.example.encryptme;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Context;
import android.os.Bundle;
import android.text.format.DateFormat;
import android.util.Log;
import android.util.Xml;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;

import org.xmlpull.v1.XmlSerializer;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class MainActivity extends AppCompatActivity {

    private EditText mensajeOriginal, mensajeCifrado, mensajeDescifrado;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        mensajeOriginal = (EditText) findViewById(R.id.texto_inserted);
        mensajeCifrado = (EditText) findViewById(R.id.texto_cifrado);
        mensajeDescifrado = (EditText) findViewById(R.id.texto_descifrado);

    }

    public void cifrar_guardar(View view) throws InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, IOException {

        String texto_original = mensajeOriginal.getText().toString();

        /**
         * CIFRADO DEL TEXTO
         */

        RSA rsa = new RSA();

        rsa.setContext(getBaseContext());

        rsa.generarParejaLLaves(1024);

        rsa.guardarLlavePrivadaEnDisco("rsa.pri");
        rsa.guardarLlavePublicaEnDisco("rsa.pub");

        String encode_text = rsa.Encriptar(texto_original);
        mensajeCifrado.setText(encode_text);

        RSA rsa2 = new RSA();

        rsa2.setContext(getBaseContext());

        rsa2.abrirLlavePrivadaEnDisco("rsa.pri");
        rsa2.abrirLlavePublicaEnDisco("rsa.pub");

        String decode_text = rsa2.Desencriptar(encode_text);

        mensajeDescifrado.setText(decode_text);

        /**
         * GUARDAR LAS VARIABLES EN UN FICHERO XML QUE NO ESTA CREADO
         */

        String archivo = "encrpytme.xml";

        Long timestamp = System.currentTimeMillis();
        String ts = DateFormat.format("dd-MM-yyyy H:mm:ss", timestamp).toString();;

        File cfile = new File(getApplicationContext().getFilesDir(),"encryptme.xml");
        try {
            if (!cfile.exists()){
                cfile.createNewFile();
            }
        } catch (IOException e){
            Log.e("IOException", "Exception in create new File(");
        }

        FileOutputStream fileos = null;
        try {
            fileos = new FileOutputStream(cfile);
        } catch (FileNotFoundException e){
            Log.e("FileNotFoundException",e.toString());
        }

        XmlSerializer serializer = Xml.newSerializer();
        try {
            serializer.setFeature("http://xmlpull.org/v1/doc/features.html#indent-output", true);
            serializer.setOutput(fileos, "UTF-8");
            serializer.startDocument(null, Boolean.valueOf(true));

            serializer.startTag(null, "cifrados");

            serializer.startTag(null, "usuario");

            serializer.startTag(null, "textOriginal");
            serializer.text(texto_original);
            serializer.endTag(null,"textOriginal");

            serializer.startTag(null, "textoCifrado");
            serializer.text(encode_text);
            serializer.endTag(null, "textoCifrado");

            serializer.startTag(null, "fechaCifrado");
            serializer.text(ts);
            serializer.endTag(null, "fechaCifrado");

            serializer.endTag(null, "usuario");

            serializer.endTag(null, "cifrados");

            serializer.endDocument();

            serializer.flush();
            fileos.close();

        }catch (Exception e){
            Log.e("Exception","Exception occured in wroting");
        }

    }
}
