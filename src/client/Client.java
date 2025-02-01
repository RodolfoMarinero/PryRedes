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

public class Client {
    private static final int SERVER_PORT = 5000;
    private static final Map<String, PublicKey> publicKeys = new HashMap<>();
    private static final Map<String, String> userIps = new HashMap<>();

    public static void main(String[] args) throws Exception {
        // Obtener variables de entorno
        int localPort = Integer.parseInt(System.getenv("LOCAL_PORT"));
        String serverIp = System.getenv("SERVER_IP");
        String username = System.getenv("USERNAME");

        if (username == null || username.isEmpty()) {
            System.out.println("❌ Error: No se ha definido un nombre de usuario.");
            return;
        }

        // Crear socket UDP
        DatagramSocket socket = new DatagramSocket(localPort);

        // Generar claves RSA
        KeyPair keyPair = CryptoUtils.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        System.out.println("✅ Cliente iniciado en el puerto " + localPort);
        System.out.println("📡 Servidor IP: " + serverIp);
        System.out.println("👤 Nombre de usuario: " + username);
        System.out.println("🔑 Clave Pública (Base64): " + Base64.getEncoder().encodeToString(publicKey.getEncoded()));

        InetAddress serverAddress = InetAddress.getByName(serverIp);

        // Registrar usuario en el servidor ESP8266
        String registerMessage = "REGISTER:" + username + ":" + Base64.getEncoder().encodeToString(publicKey.getEncoded());
        socket.send(new DatagramPacket(registerMessage.getBytes(), registerMessage.length(), serverAddress, SERVER_PORT));
        System.out.println("📩 Registro enviado al servidor.");

        // Hilo para recibir mensajes
        new Thread(() -> {
            try {
                byte[] buffer = new byte[2048];
                while (true) {
                    DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                    socket.receive(packet);

                    String message = new String(packet.getData(), 0, packet.getLength()).trim();
                    System.out.println("📩 Mensaje recibido (RAW): " + message);

                    if (message.startsWith("PUBLIC_KEY:")) {
                        handlePublicKeyResponse(message);
                    } else if (message.startsWith("ENCRYPTED:")) {
                        handleEncryptedMessage(message, privateKey);
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }).start();

        // Enviar mensajes
        while (true) {
            try {
                System.out.print("Nombre del destinatario: ");
                String recipient = System.console().readLine();

                if (!publicKeys.containsKey(recipient)) {
                    requestPublicKey(socket, serverAddress, recipient);
                    Thread.sleep(2000); // Esperar respuesta del servidor
                }

                if (!publicKeys.containsKey(recipient)) {
                    System.out.println("❌ Error: No se pudo obtener la clave pública del destinatario.");
                    continue;
                }

                PublicKey recipientKey = publicKeys.get(recipient);
                System.out.print("Mensaje: ");
                String message = System.console().readLine();

                byte[] encryptedMessage = CryptoUtils.encryptWithRSA(message.getBytes(), recipientKey);
                String encryptedMessageBase64 = Base64.getEncoder().encodeToString(encryptedMessage);

                System.out.println("📤 Mensaje cifrado (Base64): " + encryptedMessageBase64);
                sendMessage(socket, serverAddress, encryptedMessageBase64);

                System.out.println("✅ Mensaje enviado a " + recipient);
            } catch (Exception e) {
                System.out.println("❌ Error al enviar el mensaje: " + e.getMessage());
            }
        }
    }

    private static void handlePublicKeyResponse(String message) {
        String[] parts = message.split(":");
        if (parts.length >= 4) {
            String recipient = parts[1];
            try {
                byte[] publicKeyBytes = Base64.getDecoder().decode(parts[2]);
                PublicKey recipientKey = CryptoUtils.getPublicKey(publicKeyBytes);
                publicKeys.put(recipient, recipientKey);
                userIps.put(recipient, parts[3]);
                System.out.println("🔑 Clave pública de " + recipient + " almacenada.");
            } catch (Exception e) {
                System.out.println("❌ Error al procesar la clave pública de " + recipient);
            }
        }
    }

    private static void handleEncryptedMessage(String message, PrivateKey privateKey) {
        try {
            String encryptedData = message.substring(10).trim();
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedData);
            byte[] decryptedBytes = CryptoUtils.decryptWithRSA(encryptedBytes, privateKey);
            String decryptedMessage = new String(decryptedBytes);

            System.out.println("🔓 Mensaje recibido: " + decryptedMessage);
        } catch (Exception e) {
            System.out.println("❌ Error al desencriptar el mensaje.");
        }
    }

    private static void requestPublicKey(DatagramSocket socket, InetAddress serverAddress, String recipient) throws Exception {
        String request = "GET_PUBLIC_KEY:" + recipient;
        DatagramPacket packet = new DatagramPacket(request.getBytes(), request.length(), serverAddress, SERVER_PORT);
        socket.send(packet);
        System.out.println("📡 Solicitando clave pública de " + recipient);
    }

    private static void sendMessage(DatagramSocket socket, InetAddress serverAddress, String encryptedMessageBase64) throws Exception {
        String encryptedMessagePacket = "ENCRYPTED:" + encryptedMessageBase64;
        DatagramPacket packet = new DatagramPacket(encryptedMessagePacket.getBytes(), encryptedMessagePacket.length(), serverAddress, SERVER_PORT);
        socket.send(packet);
    }
}
