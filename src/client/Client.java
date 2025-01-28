package client;

import utils.CryptoUtils;

import java.net.*;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

public class Client {
    private static final int SERVER_PORT = 5000;
    private static final int LOCAL_PORT = 6001;

    private static final Map<String, PublicKey> publicKeys = new HashMap<>();
    private static final Map<String, String> userIps = new HashMap<>();

    public static void main(String[] args) throws Exception {
        DatagramSocket socket = new DatagramSocket(LOCAL_PORT);
        Scanner scanner = new Scanner(System.in);

        // Generar claves RSA
        KeyPair keyPair = CryptoUtils.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        System.out.println("Clave Pública (Base64): " + Base64.getEncoder().encodeToString(publicKey.getEncoded()));

        System.out.print("Tu nombre de usuario: ");
        String username = scanner.nextLine();

        InetAddress serverAddress = InetAddress.getByName("192.168.0.19");

        // Registrar usuario
        String registerMessage = "REGISTER:" + username + ":" + Base64.getEncoder().encodeToString(publicKey.getEncoded());
        socket.send(new DatagramPacket(registerMessage.getBytes(), registerMessage.length(), serverAddress, SERVER_PORT));

        // Hilo para escuchar mensajes
        new Thread(() -> {
            try {
                byte[] buffer = new byte[2048];
                while (true) {
                    DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                    socket.receive(packet);

                    String message = new String(packet.getData(), 0, packet.getLength()).trim();
                    System.out.println("Mensaje recibido (RAW): " + message);

                    if (message.startsWith("Usuarios registrados:")) {
                        // Mensajes informativos
                        System.out.println("[Servidor] " + message);
                    } else if (message.startsWith("PUBLIC_KEY:")) {
                        // Procesar clave pública
                        String[] parts = message.split(":");
                        String recipient = parts[1];
                        String recipientIp = parts[3];
                        byte[] publicKeyBytes = Base64.getDecoder().decode(parts[2]);
                        PublicKey recipientKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKeyBytes));
                        publicKeys.put(recipient, recipientKey);
                        userIps.put(recipient, recipientIp);
                        System.out.println("[Servidor] Clave pública e IP de " + recipient + " recibidas y almacenadas.");
                    } else if (isValidBase64(message)) {
                        // Procesar mensajes cifrados
                        try {
                            byte[] encryptedMessage = Base64.getDecoder().decode(message);
                            String decryptedMessage = CryptoUtils.decrypt(encryptedMessage, privateKey);
                            System.out.println("[Mensaje recibido descifrado]: " + decryptedMessage);
                        } catch (Exception e) {
                            System.out.println("Error al descifrar el mensaje: " + e.getMessage());
                        }
                    } else {
                        System.out.println("Mensaje desconocido recibido: " + message);
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

                System.out.println("Clave Pública del destinatario (Base64): " + Base64.getEncoder().encodeToString(recipientKey.getEncoded()));

                byte[] encryptedMessage = CryptoUtils.encrypt(message, recipientKey);
                String encryptedMessageBase64 = Base64.getEncoder().encodeToString(encryptedMessage);
                System.out.println("Mensaje cifrado (Base64): " + encryptedMessageBase64);

                InetAddress targetAddress = InetAddress.getByName(recipientIp);
                socket.send(new DatagramPacket(encryptedMessageBase64.getBytes(), encryptedMessageBase64.length(), targetAddress, LOCAL_PORT));
                System.out.println("Mensaje enviado a " + recipient + " (" + recipientIp + ")");
            } catch (Exception e) {
                System.out.println("Error al enviar el mensaje: " + e.getMessage());
            }
        }
    }

    // Verificar si una cadena es válida en Base64
    public static boolean isValidBase64(String message) {
        try {
            Base64.getDecoder().decode(message);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}
