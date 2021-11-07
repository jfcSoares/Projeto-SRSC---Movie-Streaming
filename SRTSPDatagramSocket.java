import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;

import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.KeyStore.PasswordProtection;

import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class SRTSPDatagramSocket extends DatagramSocket {

    private static final String keyStoreFile = "CipherMovies.config";
    private static final String cipherInstance = "AES/GCM/NoPadding";

    private InetSocketAddress address;
    private KeyStore keystore;
    private byte[] ivBytes;

    public SRTSPDatagramSocket() throws Exception {
        super();
        this.keystore = createKeyStore(keyStoreFile, "123");
        generateKey();
        ivBytes = new byte[] { 0x00, 0x00, 0x00, 0x01, 0x04, 0x05, 0x06, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x01 };
    }

    public SRTSPDatagramSocket(InetSocketAddress bindaddr) throws Exception {
        super(bindaddr);
        this.address = bindaddr;
        this.keystore = createKeyStore(keyStoreFile, "123");
        generateKey();
        ivBytes = new byte[] { 0x00, 0x00, 0x00, 0x01, 0x04, 0x05, 0x06, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x01 };
    }

    /**
     * Either sends, encryting the received data
     * 
     * @param packet: the original Packet carrying the data
     */
    public void sendEncrypted(DatagramPacket packet) {
        byte[] input = packet.getData();

        try {
            Cipher cipher = Cipher.getInstance(cipherInstance, "BC");
            SecretKey encryptionKey = getPrivateKey();
            SecretKey hMacKey = getMacKey();
            Mac hMac = Mac.getInstance("HmacSHA512");

            // Encrypts the packet data
            cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, new IvParameterSpec(ivBytes));
            byte[] cipherText = new byte[cipher.getOutputSize(input.length) + 1000];
            int ctLength = cipher.update(input, 0, input.length, cipherText, 0);

            hMac.init(hMacKey);
            hMac.update(input);
            ctLength += cipher.doFinal(hMac.doFinal(), 0, hMac.getMacLength(), cipherText, ctLength);

            // Send a new packet with an encrypted frame of the movie
            DatagramPacket p = new DatagramPacket(cipherText, cipherText.length, packet.getSocketAddress());
            this.send(p);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void receiveEncrypted(DatagramPacket packet) {
        byte[] input = packet.getData();

        try {
            Cipher cipher = Cipher.getInstance(cipherInstance, "BC");
            SecretKey encryptionKey = getPrivateKey();
            SecretKey hMacKey = getMacKey();
            Mac hMac = Mac.getInstance("HmacSHA512");

            // Decrypts the packet data
            cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, new IvParameterSpec(ivBytes));
            byte[] plainText = cipher.doFinal(input);
            int messageLength = plainText.length - hMac.getMacLength();

            hMac.init(hMacKey);
            hMac.update(plainText, 0, messageLength);

            byte[] messageHash = new byte[hMac.getMacLength()];
            System.arraycopy(plainText, messageLength, messageHash, 0, messageHash.length);

            // Verifies message integrity
            if (MessageDigest.isEqual(hMac.doFinal(), messageHash)) {
                // Receives a new packet with an encrypted frame of the movie
                DatagramPacket p = new DatagramPacket(plainText, plainText.length, address);
                this.receive(p);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
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
    private void generateKey() throws Exception {
        // generate a secret key for AES encryption
        SecretKey secretKey = KeyGenerator.getInstance("AES").generateKey();
        System.out.println("Stored Key: " + Base64.getEncoder().encodeToString(secretKey.getEncoded()));

        // store the secret key
        KeyStore.SecretKeyEntry keyStoreEntry = new KeyStore.SecretKeyEntry(secretKey);
        PasswordProtection keyPassword = new PasswordProtection("pw-secret".toCharArray());
        keystore.setEntry("mySecretKey", keyStoreEntry, keyPassword);
        keystore.store(new FileOutputStream(keyStoreFile), "123".toCharArray());

        // generate a secret Mac key
        SecretKey hMacKey = KeyGenerator.getInstance("HmacSHA512").generateKey();

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
        // retrieve the stored key back

        PasswordProtection keyPassword = new PasswordProtection("pw-secret".toCharArray());
        KeyStore.Entry entry = keystore.getEntry("mySecretKey", keyPassword);
        SecretKey keyFound = ((KeyStore.SecretKeyEntry) entry).getSecretKey();
        return keyFound;
    }

    private SecretKey getMacKey() throws Exception {
        // retrieve the stored Mac key back

        PasswordProtection keyPassword = new PasswordProtection("mac-secret".toCharArray());
        KeyStore.Entry entry = keystore.getEntry("mySecretMacKey", keyPassword);
        SecretKey keyFound = ((KeyStore.SecretKeyEntry) entry).getSecretKey();
        return keyFound;
    }
}
