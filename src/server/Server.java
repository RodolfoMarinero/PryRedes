package server;


import java.net.*;
import java.util.HashMap;
import java.util.Map;

public class Server {
    private static final int PORT = 5000;
    private static final Map<String, String> users = new HashMap<>();
    private static final Map<String, String> publicKeys = new HashMap<>();

    public static void main(String[] args) {
        try (DatagramSocket socket = new DatagramSocket(PORT, InetAddress.getByName("0.0.0.0"))) {
            byte[] buffer = new byte[2048];
            System.out.println("Servidor escuchando en el puerto " + PORT);

            while (true) {
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                socket.receive(packet);

                String request = new String(packet.getData(), 0, packet.getLength()).trim();
                processRequest(request, packet, socket);
            }
        } catch (Exception e) {
            System.err.println("❌ Error en el servidor: " + e.getMessage());
        }
    }

    private static void processRequest(String request, DatagramPacket packet, DatagramSocket socket) {
        try {
            if (request.isEmpty()) {
                log("⚠️ Solicitud vacía ignorada.");
                return;
            }

            String[] parts = request.split(":");
            if (parts.length < 2) {
                log("⚠️ Comando malformado: " + request);
                return;
            }

            String command = parts[0].toUpperCase();
            switch (command) {
                case "REGISTER":
                    handleRegister(parts, packet, socket);
                    break;
                case "GET_PUBLIC_KEY":
                    handleGetPublicKey(parts, packet, socket);
                    break;
                default:
                    log("⚠️ Comando no reconocido: " + command);
            }
        } catch (Exception e) {
            log("❌ Error al procesar solicitud: " + e.getMessage());
        }
    }

    private static void handleRegister(String[] parts, DatagramPacket packet, DatagramSocket socket) {
        try {
            if (parts.length < 3) {
                log("⚠️ Registro malformado: " + String.join(":", parts));
                return;
            }

            String username = parts[1];
            String publicKey = parts[2];
            String ip = packet.getAddress().getHostAddress();

            // Registrar usuario y clave pública
            users.put(username, ip);
            publicKeys.put(username, publicKey);

            log("✅ Usuario registrado: " + username + " | IP: " + ip);
            log("🔑 Clave pública (Base64): " + publicKey);

            // Enviar lista de usuarios
            String response = "Usuarios registrados: " + users.keySet();
            sendResponse(response, packet, socket);
        } catch (Exception e) {
            log("❌ Error al registrar usuario: " + e.getMessage());
        }
    }

    private static void handleGetPublicKey(String[] parts, DatagramPacket packet, DatagramSocket socket) {
        try {
            if (parts.length < 2) {
                log("⚠️ Solicitud de clave pública malformada: " + String.join(":", parts));
                return;
            }

            String username = parts[1];
            String response;

            if (publicKeys.containsKey(username)) {
                String publicKey = publicKeys.get(username);
                String userIp = users.get(username);
                response = "PUBLIC_KEY:" + username + ":" + publicKey + ":" + userIp;
                log("🔑 Clave pública enviada para " + username + " | IP: " + userIp);
            } else {
                response = "ERROR: Usuario no encontrado.";
                log("⚠️ Clave pública no encontrada para " + username);
            }

            sendResponse(response, packet, socket);
        } catch (Exception e) {
            log("❌ Error al obtener clave pública: " + e.getMessage());
        }
    }

    private static void sendResponse(String response, DatagramPacket packet, DatagramSocket socket) {
        try {
            byte[] responseData = response.getBytes();
            DatagramPacket responsePacket = new DatagramPacket(responseData, responseData.length, packet.getAddress(), packet.getPort());
            socket.send(responsePacket);
        } catch (Exception e) {
            log("❌ Error al enviar respuesta: " + e.getMessage());
        }
    }

    private static void log(String message) {
        System.out.println(message);
    }
}
