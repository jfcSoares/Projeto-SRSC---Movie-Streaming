/* hjUDPproxy, 20/Mar/18
 *
 * This is a very simple (transparent) UDP proxy
 * The proxy can listening on a remote source (server) UDP sender
 * and transparently forward received datagram packets in the
 * delivering endpoint
 *
 * Possible Remote listening endpoints:
 *    Unicast IP address and port: configurable in the file config.properties
 *    Multicast IP address and port: configurable in the code
 *  
 * Possible local listening endpoints:
 *    Unicast IP address and port
 *    Multicast IP address and port
 *       Both configurable in the file config.properties
 */

import java.io.FileInputStream;
import java.io.InputStream;

import java.net.DatagramPacket;
import java.net.InetSocketAddress;
import java.net.SocketAddress;

import java.util.Arrays;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;

class ProxyBox {
    public static void main(String[] args) throws Exception {
        InputStream inputStream = new FileInputStream("config.properties");
        Properties properties = new Properties();
        properties.load(inputStream);
        String remote = properties.getProperty("remote");
        String destinations = properties.getProperty("localdelivery");

        SocketAddress inSocketAddress = parseSocketAddress(remote);
        Set<SocketAddress> outSocketAddressSet = Arrays.stream(destinations.split(",")).map(s -> parseSocketAddress(s))
                .collect(Collectors.toSet());

        SRTSPDatagramSocket inSocket = new SRTSPDatagramSocket(inSocketAddress);
        SRTSPDatagramSocket outSocket = new SRTSPDatagramSocket();
        byte[] buffer = new byte[64000];

        inSocket.generateKey();
        while (true) {
            DatagramPacket inPacket = new DatagramPacket(buffer, buffer.length);
            inSocket.receive(inPacket); // if remote is unicast
            byte[] newBuf = new byte[inPacket.getLength()];
            System.arraycopy(buffer, 0, newBuf, 0, newBuf.length);
            newBuf = inSocket.decryptPayload(newBuf);

            System.out.print("*");
            for (SocketAddress outSocketAddress : outSocketAddressSet) {
                outSocket.send(new DatagramPacket(newBuf, newBuf.length, outSocketAddress));
            }
        }
    }

    private static InetSocketAddress parseSocketAddress(String socketAddress) {
        String[] split = socketAddress.split(":");
        String host = split[0];
        int port = Integer.parseInt(split[1]);
        return new InetSocketAddress(host, port);
    }
}
