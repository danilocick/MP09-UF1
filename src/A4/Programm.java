package A4;

import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileNotFoundException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Scanner;

import static A4.Xifrar.*;

public class Programm {
    public static void main(String[] args) {

        //Xifrar i desxifrar un text en clar amb una clau generada amb el codi 1.1.1
        String msg1 = "hola, bon dia";
        SecretKey seck1 = keygenKeyGeneration(128);
        byte[] msg1xifrat = encryptData(msg1.getBytes(), seck1);
        byte[] msg1desxifrat = decryptData(msg1xifrat, seck1);

        String s = new String(msg1desxifrat);
        System.out.println(s);

/*
        //Xifrar i desxifrar un text en clar amb una clau (codi 1.1.2) generada a partir de la paraula de pas.
        String msg2 = "hola, bon dia";
        SecretKey seck2 = passwordKeyGeneration("daniel hernandez",128);
        byte[] msg2xifrat = decryptData(msg2.getBytes(), seck2);
        byte[] msg2desxifrat = decryptData(msg2xifrat, seck2);

        String l = new String(msg2desxifrat);
        System.out.println(l);

*/
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
        try {
            File myObj = new File("clausA4.txt");
            File myHide = new File("textamagat");
            Scanner myReader = new Scanner(myObj);

            while (myHide.hasNextLine()) {
                String textAmagat = myHide.nextLine();
            }

            while (myReader.hasNextLine()) {
                String tryPasswd = myReader.nextLine();
                System.out.println(tryPasswd);
                SecretKey sk = passwordKeyGeneration(tryPasswd,128);
                byte[] result = decryptData(textAmagat.getBytes(),sk);

            /*    if (result.equals(textAmagat.getBytes())){
                    System.out.println("la resposta es: "+textAmagat);
                    System.exit(0);
                }
            */

            }
            myReader.close();
        } catch (FileNotFoundException e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
        }

    }

}
