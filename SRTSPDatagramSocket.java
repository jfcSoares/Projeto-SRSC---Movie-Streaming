import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.KeyStore.PasswordProtection;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

import utils.Utils;

public class SRTSPDatagramSocket extends DatagramSocket {

    private static final String keyStoreFile = "CipherMovies.config";
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final int IV_LENGTH_BYTE = 16;

    byte[] ivBytes = new byte[] { 
	    0x00, 0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x01,
	    0x00, 0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x01
	};

    private AlgorithmParameterSpec iv;
    private KeyStore keystore;
    private SecureRandom random;
    private Mac hmac;
    private Integer bufSize;

    public SRTSPDatagramSocket() throws Exception {
        super();
        this.keystore = createKeyStore(keyStoreFile, "123");
        // generateKey();
        random = new SecureRandom();
    }

    public SRTSPDatagramSocket(SocketAddress bindaddr) throws Exception {
        super(bindaddr);
        this.keystore = createKeyStore(keyStoreFile, "123");
        // generateKey();
        random = new SecureRandom();
    }

    /**
     * Implements AES (Advanced Encryption Standard) with Cipher Block Chaining
     * (CBC), which is a mode of operation for symmetric key cryptographic block
     * ciphers. For integrity it uses HMAC with SHA-256, using the encrypt-then-mac
     * schema.
     * 
     * @param Arrays
     * 
     * @param packet: the original Packet carrying the data
     * @throws Exception
     */
    public void sendEncrypted(DatagramPacket packet) throws Exception {
        byte[] input = packet.getData();
        System.out.println("plain: " + Utils.toHex(input, input.length) + " bytes: " + input.length);
        System.out.println("---------------------------------------------------------------------");
        
        try {

            byte[] iv = new byte[IV_LENGTH_BYTE];
            random.nextBytes(iv);
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            SecretKey encryptionKey = getPrivateKey();


            // Encrypts the packet data
            cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, new GCMParameterSpec(128, iv));
            byte[] cipherText = new byte[cipher.getOutputSize(input.length)];
            int ctLength = cipher.update(input, 0, input.length, cipherText, 0);
            ctLength += cipher.doFinal(cipherText, ctLength);
            int cypherLenLen = ctLength - input.length;
            //System.out.println("plain: " + Utils.toHex(input, input.length) + " bytes: " + input.length + " " + cypherLenLen);
            //System.out.println("---------------------------------------------------------------------");
            //System.out.println("cipher: " + Utils.toHex(cipherText, ctLength) + " bytes: " + ctLength + " " + cypherLenLen);
            //System.out.println("---------------------------------------------------------------------");
            
            ByteBuffer byteBuffer = ByteBuffer.allocate(1 + iv.length + cipherText.length + 1);           
            byteBuffer.put((byte) cypherLenLen);  //tamanho do tamanho da cifra
            byteBuffer.put((byte) iv.length); //tamanho do iv
            byteBuffer.put(iv); //iv
            byteBuffer.put(cipherText); //cifra + tamanho da cifra
            byte[] cipherMessage = byteBuffer.array();
            bufSize = cipherMessage.length;

            //System.out.println("iv: " + Utils.toHex(iv, iv.length) + " bytes: " + iv.length + " " + (byte) 16);
            //System.out.println("CIFRA FINAL (SERVER): " + Utils.toHex(cipherMessage, bufSize) + " bytes: " + bufSize + " cypherLenLen " + cypherLenLen);
            //System.out.println("---------------------------------------------------------------------");
            

            // sends a new packet with the encrypted and authenticated data
            DatagramPacket p = new DatagramPacket(cipherMessage, bufSize, packet.getSocketAddress());
            send(p);
        } catch (Exception e) {
            throw new AuthenticatedEncryptionException("Could not encrypt", e);
        } finally {
           
        }
    }

    public byte[] decryptData(byte[] encryptedData) throws Exception {

        //System.out.println("CIFRA ENCRIPTADA (PROXY) : " + Utils.toHex(encryptedData, encryptedData.length) + " bytes: " + encryptedData.length);

        // Separate the received data
        byte[] ivLength = new byte[1];
        System.arraycopy(encryptedData, 0, ivLength, 0, ivLength.length);
        //System.out.println("DECRYPTION ivLength: " + Integer.parseInt(Utils.toHex(ivLength, ivLength.length),16) + " bytes: " + ivLength.length);

        // Separate the received data
        byte[] cypherLenLen = new byte[1];
        System.arraycopy(encryptedData, 1, cypherLenLen, 0, cypherLenLen.length);
        //System.out.println("DECRYPTION cypherLengthLenght: " + Utils.toHex(cypherLenLen, cypherLenLen.length)  + " bytes: " + cypherLenLen.length);
          
        byte[] iv = new byte[Integer.parseInt(Utils.toHex(ivLength, ivLength.length),16)];
        System.arraycopy(encryptedData, 2, iv, 0, iv.length);
        //System.out.println("DECRYPTION iv: " + Utils.toHex(iv, iv.length) + " bytes: " + iv.length);

        byte[] cipherText = new byte[encryptedData.length - ivLength.length - iv.length - cypherLenLen.length];
        System.arraycopy(encryptedData, ivLength.length + iv.length + cypherLenLen.length, cipherText, 0, cipherText.length);
        //System.out.println("DECRYPTION cipherText: " + Utils.toHex(cipherText, cipherText.length) + " bytes: " + cipherText.length);


        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKey encryptionKey = getPrivateKey();
        cipher.init(Cipher.DECRYPT_MODE, encryptionKey, new GCMParameterSpec(128, iv));

        byte[] plainText1 = new byte[cipher.getOutputSize(cipherText.length)];
        int ptLength = cipher.update(cipherText, 0, cipherText.length, plainText1, 0);
        ptLength += cipher.doFinal(plainText1, ptLength);
        System.out.println("DESENCRIPTADA (PROXY) : " + Utils.toHex(plainText1, ptLength) + " bytes: " + ptLength);

        
        System.out.println("---------------------------------------------------------------------");
        return plainText1;
    }

    // Returns the required buffer size to receive the encrypted and MAC'ed packet
    // data
    public Integer getBufSize() {
        return bufSize;
    }

    // *** AUXILIARY METHODS ***/

    public KeyStore createKeyStore(String fileName, String pw) throws Exception {
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
     * Generates and stores a secret encryption and HMAC key
     * 
     * @throws Exception
     */
    public void generateKeys() throws Exception {
        // generate a secret key for AES encryption
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey secretKey = keyGen.generateKey();
        System.out.println("Stored Key: " + Base64.getEncoder().encodeToString(secretKey.getEncoded()));

        // store the secret key
        KeyStore.SecretKeyEntry keyStoreEntry = new KeyStore.SecretKeyEntry(secretKey);
        PasswordProtection keyPassword = new PasswordProtection("pw-secret".toCharArray());
        keystore.setEntry("mySecretKey", keyStoreEntry, keyPassword);
        keystore.store(new FileOutputStream(keyStoreFile), "123".toCharArray());

        // generate a secret Mac key
        KeyGenerator keyG = KeyGenerator.getInstance("HmacSHA256");
        keyG.init(256);
        SecretKey hMacKey = keyG.generateKey();

        // store the secret Mac key
        KeyStore.SecretKeyEntry macKeyStoreEntry = new KeyStore.SecretKeyEntry(hMacKey);
        PasswordProtection macPassword = new PasswordProtection("mac-secret".toCharArray());
        keystore.setEntry("mySecretMacKey", macKeyStoreEntry, macPassword);
        keystore.store(new FileOutputStream(keyStoreFile), "123".toCharArray());
    }

    /**
     * Obtains an existing secret key from the keystore
     * 
     * @return
     * @throws Exception
     */
    private SecretKey getPrivateKey() throws Exception {
        // retrieve the stored key

        PasswordProtection keyPassword = new PasswordProtection("pw-secret".toCharArray());
        KeyStore.Entry entry = keystore.getEntry("mySecretKey", keyPassword);
        SecretKey keyFound = ((KeyStore.SecretKeyEntry) entry).getSecretKey();
        return keyFound;
    }

    private SecretKey getMacKey() throws Exception {
        // retrieve the stored Mac key

        PasswordProtection keyPassword = new PasswordProtection("mac-secret".toCharArray());
        KeyStore.Entry entry = keystore.getEntry("mySecretMacKey", keyPassword);
        SecretKey keyFound = ((KeyStore.SecretKeyEntry) entry).getSecretKey();
        return keyFound;
    }

    private byte[] macCipherText(SecretKey macKey, byte[] cipherText, byte[] iv) {

        try {
            createHmacInstance();
            hmac.init(macKey);
            hmac.update(iv);
            hmac.update(cipherText);
        } catch (InvalidKeyException e) {
            throw new IllegalStateException("error during HMAC calculation");
        }

        return hmac.doFinal();
    }

    private Mac createHmacInstance() {
        if (hmac == null) {
            try {
                hmac = Mac.getInstance(HMAC_ALGORITHM);
            } catch (Exception e) {
                throw new IllegalStateException("could not get cipher instance", e);
            }
        }
        return hmac;
    }

    private void verifyMac(SecretKey macKey, byte[] iv, byte[] mac, byte[] cipherText)
            throws AuthenticatedEncryptionException {
        byte[] actualMac = macCipherText(macKey, cipherText, iv);

        // if MACs do not match
        if (!MessageDigest.isEqual(mac, actualMac)) {
            throw new AuthenticatedEncryptionException("Encryption integrity exception: mac does not match");
        }
    }
}