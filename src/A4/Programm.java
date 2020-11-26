package A4;

import javax.crypto.BadPaddingException;
import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;
import java.util.Scanner;

import static A4.Xifrar.*;

public class Programm {
    public static void main(String[] args) throws IOException {

        //Xifrar i desxifrar un text en clar amb una clau generada amb el codi 1.1.1
        String msg1 = "hola, bon dia";
        SecretKey seck1 = keygenKeyGeneration(128);
        byte[] msg1xifrat = encryptData(msg1.getBytes(), seck1);
        byte[] msg1desxifrat = decryptData(msg1xifrat, seck1);

        String s = new String(msg1desxifrat);
        System.out.println(s);


        //Xifrar i desxifrar un text en clar amb una clau (codi 1.1.2) generada a partir de la paraula de pas.
        String msg2 = "hola, bon dia";
        String pss = "dani";
        SecretKey seck2 = passwordKeyGeneration(pss,256);

        byte[] msg2xifrat = encryptData(msg2.getBytes(), seck2);
        byte[] msg2desxifrat = decryptData(msg2xifrat, seck2);

        String l = new String(msg2desxifrat);
        System.out.println(l);

        System.out.println("-----------");
        System.out.println("-----------");
        System.out.println("-----------");

        //Prova alguns dels mètodes que proporciona la classe SecretKey
        System.out.println(seck1.getEncoded());
        System.out.println(seck1.getAlgorithm());
        System.out.println(seck1.getFormat());

        System.out.println("-----------");
        System.out.println("-----------");
        System.out.println("-----------");

        //Desxifra el text del punt 6 i comprova que donant una paraula de pas incorrecte salta l'excepció BadPaddingException
        String msg3 = "hola,bon dia";
        String passwd = "adeu bona tarda";
        SecretKey seck3 = passwordKeyGeneration(passwd, 128);

        byte[] msgxifrat3 = encryptData(msg3.getBytes(), seck2);
        //byte[] msgdesxifrat3 = decryptData(msgxifrat3, seck3);

        //String m = new String(msgdesxifrat3);
        //System.out.println(m);


        //Donat un text xifrat (textamagat) amb algoritme estàndard AES i
        //clau simètrica generada amb el mètode SHA-256 a partir d’una contrasenya,
        //i donat un fitxer (clausA4.txt) on hi ha possibles contrasenyes correctes,
        //fes un programa per trobar la bona i desxifrar el missatge.

        //paths
        Path textocifrado = Paths.get("textamagat");
        Path claves = Paths.get("clausA4.txt");

        //llegir i fer un arraylist
        byte[] textoenbytes = Files.readAllBytes(textocifrado);
        List<String> claus = Files.readAllLines(claves);

        int i = 0;
        boolean correct = false;

        while (!correct){
            try {
                SecretKey cp = passwordKeyGeneration(claus.get(i), 128);
                byte[] result = decryptData(textoenbytes, cp);
                System.out.println(result.toString());

                System.out.println(claus.get(i));
                System.out.println(new String(decryptData(textoenbytes, cp)));
                correct = true;

            }catch (Exception e){
                i++;
                System.out.println("contrasenya erronea");
            }
        }
    }
}
