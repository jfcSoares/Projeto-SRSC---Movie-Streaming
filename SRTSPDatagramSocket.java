import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketAddress;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.KeyStore.PasswordProtection;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

public class SRTSPDatagramSocket extends DatagramSocket {

    private static final String keyStoreFile = "CipherMovies.config";
    private static final String cipherInstance = "AES/GCM/NoPadding";
    private static final int IV_LENGTH_BYTE = 12;
    private static final int TAG_LENGTH_BITS = 128;

    private KeyStore keystore;
    private final SecureRandom secureRandom;

    public SRTSPDatagramSocket() throws Exception {
        super();
        this.keystore = createKeyStore(keyStoreFile, "123");
        secureRandom = new SecureRandom();
    }

    public SRTSPDatagramSocket(SocketAddress bindaddr) throws Exception {
        super(bindaddr);
        this.keystore = createKeyStore(keyStoreFile, "123");
        secureRandom = new SecureRandom();
    }

    public void sendEncrypted(DatagramPacket p) throws Exception {
        byte[] encryptedData = encryptPayload(p.getData());
        send(new DatagramPacket(encryptedData, encryptedData.length, p.getSocketAddress()));
    }

    /**
     * Encrypts a clear movie frame
     * 
     * @param frame: the movie frame to be encrypted
     * @return the encrypted data: the IV plus the ciphered frame
     */
    public byte[] encryptPayload(byte[] frame) {
        byte[] iv = generateIV();
        byte[] encryptedData = null;

        try {
            Cipher cipher = Cipher.getInstance(cipherInstance, "BC");
            SecretKey encryptionKey = getPrivateKey();

            cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, new GCMParameterSpec(TAG_LENGTH_BITS, iv));

            // Encryption
            byte[] cipherText = cipher.doFinal(frame);
            int ctLength = cipherText.length;

            // Prepend iv to cipherText to help decryption
            encryptedData = new byte[iv.length + ctLength];
            System.arraycopy(iv, 0, encryptedData, 0, iv.length);
            System.arraycopy(cipherText, 0, encryptedData, iv.length, ctLength);
            return encryptedData;
        } catch (Exception e) {
            e.printStackTrace();
        }

        return encryptedData;
    }

    public byte[] decryptPayload(byte[] encryptedData) {
        byte[] plainText = null;
        try {
            Cipher cipher = Cipher.getInstance(cipherInstance, "BC");
            SecretKey decryptionKey = getPrivateKey();

            // Separate the received data
            byte[] iv = new byte[IV_LENGTH_BYTE];
            iv = Arrays.copyOfRange(encryptedData, 0, IV_LENGTH_BYTE);

            byte[] cipherText = new byte[encryptedData.length - IV_LENGTH_BYTE];
            System.arraycopy(encryptedData, iv.length, cipherText, 0, cipherText.length);

            // decryption
            cipher.init(Cipher.DECRYPT_MODE, decryptionKey, new GCMParameterSpec(TAG_LENGTH_BITS, iv));
            plainText = cipher.doFinal(cipherText);

            System.out.println(plainText);
            return plainText;

        } catch (Exception e) {
            e.printStackTrace();
        }
        return plainText;
    }

    // *** METODOS AUXILIARES ***/

    private static KeyStore createKeyStore(String fileName, String pw) throws Exception {
        File file = new File(fileName);

        // PKCS12 OR JCEKS?
        final KeyStore keyStore = KeyStore.getInstance("PKCS12");
        if (file.exists() && file != null) {
            // .keystore file already exists => load it
            keyStore.load(new FileInputStream(file), pw.toCharArray());
        } else {
            // .keystore file not created yet => create it
            keyStore.load(null, null);
            keyStore.store(new FileOutputStream(fileName), pw.toCharArray());
        }

        return keyStore;
    }

    /**
     * Generates and stores a secret encryption key
     * 
     * @throws Exception
     */
    public void generateKey() throws Exception {
        // generate a secret key for AES encryption
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256); // Defines the size for the AES Key
        SecretKey secretKey = keyGen.generateKey();
        System.out.println("Stored Key: " + Base64.getEncoder().encodeToString(secretKey.getEncoded()));

        // store the secret key
        KeyStore.SecretKeyEntry keyStoreEntry = new KeyStore.SecretKeyEntry(secretKey);
        PasswordProtection keyPassword = new PasswordProtection("pw-secret".toCharArray());
        keystore.setEntry("mySecretKey", keyStoreEntry, keyPassword);
        keystore.store(new FileOutputStream(keyStoreFile), "123".toCharArray());

    }

    /**
     * Obtains an existing secret key from the keystore
     * 
     * @return
     * @throws Exception
     */
    private SecretKey getPrivateKey() throws Exception {
        // retrieve the stored key back

        PasswordProtection keyPassword = new PasswordProtection("pw-secret".toCharArray());
        KeyStore.Entry entry = keystore.getEntry("mySecretKey", keyPassword);
        SecretKey keyFound = ((KeyStore.SecretKeyEntry) entry).getSecretKey();
        return keyFound;
    }

    private byte[] generateIV() {
        // IV generation
        byte[] ivBytes = new byte[IV_LENGTH_BYTE];
        secureRandom.nextBytes(ivBytes);

        return ivBytes;
    }

}
