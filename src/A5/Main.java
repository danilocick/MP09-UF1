package A5;

import javax.crypto.SecretKey;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Collection;
import java.util.Iterator;
import java.util.Scanner;
import static A5.Xifrar.*;

public class Main {

    //loadKeyStore --> jks
    public static void main(String[] args) throws Exception {
        Scanner sc = new Scanner(System.in);

        //Afegeix a la classe d’utilitats de criptografia de l’activitat
        // A4 el mètode 1.2.1 randomGenerate del apunts.
        //Genera un parell de claus (KeyPair) de 1024bits,
        // i utilitza-les per xifrar i desxifrar un missatge.
        KeyPair pair = randomGenerate(1024);

        //Fes que el missatge a xifrar s’entri pel teclat.
        System.out.println("missage to encrypt");
        String text = sc.nextLine();
        //
        byte [] textBytes = text.getBytes();

        byte[] xifrat = encryptData(textBytes, pair.getPublic());
        byte[] desxifrat = decryptData(xifrat, pair.getPrivate());


        System.out.println("xifrat: "+xifrat);
        System.out.println("desxifrat: "+new String(desxifrat));
        System.out.println("---------------");
        System.out.println("Private Key: "+pair.getPrivate());
        System.out.println("Public Key: "+pair.getPublic());

        System.out.println("---------------");
        System.out.println("1.2.1");
        System.out.println("---------------");

        //Fés la lectura d’un dels keystore que tinguis al teu sistema i extreu-ne la següent informació:
        //Tipus de keystore que és (JKS, JCEKS, PKCS12, ...)
        //Mida del magatzem (quantes claus hi ha?)
        //Àlies de totes les claus emmagatzemades
        //El certificat d’una de les claus
        //L'algorisme de xifrat d’alguna de les claus
        KeyStore ks = loadKeyStore("keystore_danielh.ks","usuari");

        System.out.println("Tipo del keystore: " + ks.getType());
        System.out.println("Tamaño del keystore: " + ks.size());
        System.out.println(ks.aliases());


        System.out.println("Certificado de una clave del keystore: " + ks.getCertificate("lamevaclaum9"));
        System.out.println("Algoritmo de una clave del keystore : " + ks.getKey("lamevaclaum9", "usuari".toCharArray()).getAlgorithm());


        System.out.println("---------------");
        System.out.println("1.2.2");
        System.out.println("---------------");

        String pswd = "passwd";
        SecretKey secretKey = keygenKeyGeneration(256);

        KeyStore.SecretKeyEntry skEntry = new KeyStore.SecretKeyEntry(secretKey);
        KeyStore.ProtectionParameter protectionParameter = new KeyStore.PasswordProtection(pswd.toCharArray());

        ks.setEntry("secretKeyAlias", skEntry, protectionParameter);
            try (FileOutputStream fileOutputStream = new FileOutputStream("keystore_danielh.jks")){
                ks.store(fileOutputStream, "passwd".toCharArray());
            }
        System.out.println(ks.getEntry("secretKeyAlias", protectionParameter));

        System.out.println("---------------");
        System.out.println("1.3");
        System.out.println("---------------");

        FileInputStream fileInputStream = new FileInputStream("cerdanielh.cer");
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        Collection c = certificateFactory.generateCertificates(fileInputStream);
        Iterator i = c.iterator();
        while (i.hasNext()) {
            Certificate cert = (Certificate)i.next();
            System.out.println(cert);
        }

        System.out.println("---------------");
        System.out.println("1.4");
        System.out.println("---------------");

        String psswd = "usuari";
        String alias = "lamevaclauM9";

        FileInputStream is = new FileInputStream("keystore_danielh.ks");
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(is, psswd.toCharArray());
        Key key = keystore.getKey(alias, psswd.toCharArray());

        if (key instanceof PrivateKey) {
            Certificate cert = keystore.getCertificate(alias);
            PublicKey publicKey = cert.getPublicKey();
            System.out.println(publicKey.toString());
        }

        System.out.println("---------------");
        System.out.println("1.5");
        System.out.println("---------------");

        byte[] manubrio = "manubrio".getBytes();
        PrivateKey privKey = pair.getPrivate();
        byte[] firma = signData(manubrio,privKey);
        System.out.println(new String(firma));

        System.out.println("---------------");
        System.out.println("1.6");
        System.out.println("---------------");

        PublicKey publicKey = pair.getPublic();
        boolean verificado = validateSignature(manubrio,firma,publicKey);
        if(verificado == true) {
            System.out.println("esta verificada");
        }else System.out.println("No verificada");;

        System.out.println("---------------");
        System.out.println("2.1");
        System.out.println("---------------");



        System.out.println("---------------");
        System.out.println("2.2");
        System.out.println("---------------");

        KeyPair claves = randomGenerate(1024);

        PublicKey pubKey = claves.getPublic();
        PrivateKey privateKey = claves.getPrivate();

        byte[][] wrappedKeyEncrypt = encryptWrappedData(manubrio,pubKey);
        byte[]  wrappedKeyDecrypt = decryptWrappedData(wrappedKeyEncrypt,privateKey);

        System.out.println(new String);
        System.out.println(new String(wrappedKeyDecrypt));

    }
}
