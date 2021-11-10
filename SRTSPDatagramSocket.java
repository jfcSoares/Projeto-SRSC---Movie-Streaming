
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
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class SRTSPDatagramSocket extends DatagramSocket {

    private static final String keyStoreFile = "CipherMovies.config";
    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final int IV_LENGTH_BYTE = 16;

    private KeyStore keystore;
    private SecureRandom random;
    private Mac hmac;

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
     * @throws AuthenticatedEncryptionException
     */
    public void sendEncrypted(DatagramPacket packet) throws AuthenticatedEncryptionException {
        byte[] input = packet.getData();
        byte[] cipherText = null;
        byte[] mac = null;
        byte[] iv = new byte[IV_LENGTH_BYTE];
        random.nextBytes(iv);

        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM, "BC");
            SecretKey encryptionKey = getPrivateKey();
            SecretKey hMacKey = getMacKey();

            // Encrypts the packet data
            cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, new IvParameterSpec(iv));
            cipherText = cipher.doFinal(input);

            // Authenticates the data
            mac = macCipherText(hMacKey, cipherText, iv);

            ByteBuffer byteBuffer = ByteBuffer.allocate(1 + iv.length + 1 + mac.length + cipherText.length);
            byteBuffer.put((byte) iv.length);
            byteBuffer.put(iv);
            byteBuffer.put((byte) mac.length);
            byteBuffer.put(mac);
            byteBuffer.put(cipherText);

            // collect the full cipherText
            byte[] cipherMessage = byteBuffer.array();

            // sends a new packet with the encrypted and authenticated data
            DatagramPacket p = new DatagramPacket(cipherMessage, cipherMessage.length, packet.getSocketAddress());
            this.send(p);
        } catch (Exception e) {
            throw new AuthenticatedEncryptionException("Could not encrypt", e);
        } finally {
            // Release auxiliary vectors memory
            java.util.Arrays.fill(iv, (byte) 0);
            java.util.Arrays.fill(cipherText, (byte) 0);
            java.util.Arrays.fill(mac, (byte) 0);
        }
    }

    public byte[] decryptData(byte[] encryptedData) throws Exception {
        /** Separates the data received into all the algorithm parameters **/

        ByteBuffer byteBuffer = ByteBuffer.wrap(encryptedData);

        int ivLength = (byteBuffer.get());

        if (ivLength != 16) { // check input parameter
            throw new IllegalArgumentException("invalid iv length");
        }
        byte[] iv = new byte[ivLength];
        byteBuffer.get(iv);

        int macLength = (byteBuffer.get());
        if (macLength != 32) { // check input parameter
            throw new IllegalArgumentException("invalid mac length");
        }
        byte[] mac = new byte[macLength];
        byteBuffer.get(mac);

        byte[] cipherText = new byte[byteBuffer.remaining()];
        byteBuffer.get(cipherText);

        /** Separates the data received into all the algorithm parameters **/

        // Checks MAC integrity
        SecretKey macKey = getMacKey();
        verifyMac(macKey, iv, mac, cipherText);

        // Decrypts data
        final Cipher cipherDec = Cipher.getInstance(ALGORITHM, "BC");
        SecretKey decryptKey = getPrivateKey();
        cipherDec.init(Cipher.DECRYPT_MODE, decryptKey, new IvParameterSpec(iv));
        byte[] plainText = cipherDec.doFinal(cipherText);
        return plainText;

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
