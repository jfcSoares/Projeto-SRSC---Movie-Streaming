import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.SocketException;
import java.security.Key;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import utils.CryptoUtils;

public class SRTSPDatagramSocket extends DatagramSocket {

    private InetSocketAddress address;
    private Cipher cipher;
    private SecureRandom random;
    private IvParameterSpec ivSpec;
    private Key key;
    private Mac hMac;
    private Key hMacKey;
    private int ctLength;

    public SRTSPDatagramSocket(InetSocketAddress bindaddr) throws SocketException {
        super(bindaddr);
        address = bindaddr;
        try {
            cipher = Cipher.getInstance("AES/ECB/NoPadding", "SunJCE");
            random = new SecureRandom();
            ivSpec = CryptoUtils.createCtrIvForAES(1, random);
            key = CryptoUtils.createKeyForAES(256, random);
            hMac = Mac.getInstance("HmacSHA512");
            hMacKey = new SecretKeySpec(key.getEncoded(), "HmacSHA512");
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    public void sendEncrypted(DatagramPacket packet) {
        // SecretKeySpec key = new SecretKeySpec(packet.getData(), "AES");
        byte[] encrypted = new byte[4096];
        try {

            // **** Initiates encryption ****//
            cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            byte[] input = packet.getData();
            byte[] cypherText = new byte[input.length + hMac.getMacLength()];

            ctLength = cipher.update(input, 0, input.length, cypherText, 0);
            hMac.init(hMacKey);
            hMac.update(input);

            ctLength += cipher.doFinal(hMac.doFinal(), 0, hMac.getMacLength(), cypherText, ctLength);
            encrypted = hMac.doFinal(); // Not sure se e assim

            // Sends a refurbished packet with encrypted data
            DatagramPacket p = new DatagramPacket(encrypted, encrypted.length, address);
            this.send(p);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void receive(DatagramPacket packet) {

        try {
            // **** Initiates decryption ****//
            cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

            byte[] originalData = cipher.doFinal(packet.getData(), 0, ctLength);
            int messageLength = originalData.length - hMac.getMacLength();

            hMac.init(hMacKey);
            hMac.update(originalData, 0, messageLength);

            DatagramPacket p = new DatagramPacket(originalData, originalData.length, packet.getSocketAddress());
            this.receive(p);
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

}