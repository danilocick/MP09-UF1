package A4;

import javax.crypto.SecretKey;

import java.security.PrivateKey;
import java.security.PublicKey;

import static A4.Xifrar.*;

public class Programm {
    public static void main(String[] args) {

        //Xifrar i desxifrar un text en clar amb una clau generada amb el codi 1.1.1
        SecretKey hola=keygenKeyGeneration(128);

        decryptData(hola.getEncoded(),);

        //Xifrar i desxifrar un text en clar amb una clau (codi 1.1.2) generada a partir de la paraula de pas.
        SecretKey text = passwordKeyGeneration("hola.txt",128);
        decryptData(text.getEncoded(),);

        //Prova alguns dels mètodes que proporciona la classe SecretKey

        //Desxifra el text del punt 6 i comprova que donant una paraula de pas incorrecte salta l'excepció BadPaddingException

    }

}
