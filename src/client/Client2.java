package client;

import utils.CryptoUtils;

import javax.crypto.SecretKey;
import java.net.*;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

public class Client2 {
    private static final int SERVER_PORT = 5000; // Puerto fijo del servidor
    private static final Map<String, PublicKey> publicKeys = new HashMap<>();
    private static final Map<String, String> userIps = new HashMap<>();

    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);

        // Solicitar puerto local al usuario
        System.out.print("Ingresa el puerto local (ejemplo: 6001): ");
        int localPort = scanner.nextInt();
        scanner.nextLine(); // Consumir el salto de línea

        // Crear socket con el puerto local
        DatagramSocket socket = new DatagramSocket(localPort);

        // Generar claves RSA únicas para este cliente
        KeyPair keyPair = CryptoUtils.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        System.out.println("Puerto local: " + localPort);
        System.out.println("Clave Pública (Base64): " + Base64.getEncoder().encodeToString(publicKey.getEncoded()));

        System.out.print("Tu nombre de usuario: ");
        String username = scanner.nextLine();

        InetAddress serverAddress = InetAddress.getByName("127.0.0.1");

        // Registrar usuario
        String registerMessage = "REGISTER:" + username + ":" + Base64.getEncoder().encodeToString(publicKey.getEncoded());
        socket.send(new DatagramPacket(registerMessage.getBytes(), registerMessage.length(), serverAddress, SERVER_PORT));

        // Hilo para recibir mensajes
        new Thread(() -> {
            try {
                byte[] buffer = new byte[2048];
                while (true) {
                    DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                    socket.receive(packet);

                    String message = new String(packet.getData(), 0, packet.getLength()).trim();
                    System.out.println("Mensaje recibido (RAW): " + message);

                    if (message.startsWith("PUBLIC_KEY:")) {
                        String[] parts = message.split(":");
                        if (parts.length == 4) {
                            String recipient = parts[1];
                            String publicKeyBase64 = parts[2];
                            String recipientIp = parts[3];

                            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyBase64);
                            PublicKey recipientPublicKey = CryptoUtils.getPublicKey(publicKeyBytes);

                            publicKeys.put(recipient, recipientPublicKey);
                            userIps.put(recipient, recipientIp);

                            System.out.println("[Servidor] Clave pública de " + recipient + " almacenada.");
                        }
                    } else if (message.startsWith("ENCRYPTED:")) {
                        String[] parts = message.split(":");
                        if (parts.length == 3) {
                            String encryptedAESKeyBase64 = parts[1];
                            String encryptedMessageBase64 = parts[2];

                            try {
                                System.out.println("Clave AES recibida (Base64): " + encryptedAESKeyBase64);
                                System.out.println("Mensaje cifrado recibido (Base64): " + encryptedMessageBase64);

                                byte[] encryptedAESKey = Base64.getDecoder().decode(encryptedAESKeyBase64);
                                byte[] aesKeyBytes = CryptoUtils.decryptWithRSA(encryptedAESKey, privateKey);
                                SecretKey aesKey = CryptoUtils.secretKeyFromBase64(Base64.getEncoder().encodeToString(aesKeyBytes));

                                byte[] encryptedMessage = Base64.getDecoder().decode(encryptedMessageBase64);
                                String decryptedMessage = CryptoUtils.decryptWithAES(encryptedMessage, aesKey);

                                System.out.println("[Mensaje descifrado]: " + decryptedMessage);
                            } catch (Exception e) {
                                System.out.println("❌ Error al descifrar: " + e.getMessage());
                                e.printStackTrace();
                            }
                        }
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }).start();

        // Enviar mensajes
        while (true) {
            System.out.print("Nombre del destinatario: ");
            String recipient = scanner.nextLine();

            if (!publicKeys.containsKey(recipient)) {
                String request = "GET_PUBLIC_KEY:" + recipient;
                socket.send(new DatagramPacket(request.getBytes(), request.length(), serverAddress, SERVER_PORT));
                Thread.sleep(2000);
            }

            if (!publicKeys.containsKey(recipient)) {
                System.out.println("Error: No se pudo obtener la clave pública del destinatario.");
                continue;
            }

            PublicKey recipientKey = publicKeys.get(recipient);
            String recipientIp = userIps.get(recipient);

            System.out.print("Mensaje: ");
            String message = scanner.nextLine();

            String[] encryptedData = CryptoUtils.encrypt(message, recipientKey);
            String encryptedAESKeyBase64 = encryptedData[0];
            String encryptedMessageBase64 = encryptedData[1];

            String finalMessage = "ENCRYPTED:" + encryptedAESKeyBase64 + ":" + encryptedMessageBase64;
            InetAddress targetAddress = InetAddress.getByName(recipientIp);
            socket.send(new DatagramPacket(finalMessage.getBytes(), finalMessage.length(), targetAddress, localPort));
            System.out.println("Mensaje enviado a " + recipient + " (" + recipientIp + ")");
        }
    }
}
