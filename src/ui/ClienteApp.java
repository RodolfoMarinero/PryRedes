/*package ui;

import javafx.application.Application;
import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.GridPane;
import javafx.stage.Stage;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import utils.CryptoUtils;

public class ClienteApp extends Application {

    private static final int SERVER_PORT = 5000;
    private static final int LOCAL_PORT = 6000;
    private static final String SERVER_IP = "127.0.0.1";

    private DatagramSocket socket;
    private String username;
    private PublicKey publicKey;
    private PrivateKey privateKey;
    private final Map<String, PublicKey> publicKeys = new HashMap<>();

    public static void main(String[] args) {
        launch(args);
    }

    @Override
    public void start(Stage primaryStage) throws Exception {
        KeyPair keyPair = CryptoUtils.generateKeyPair();
        publicKey = keyPair.getPublic();
        privateKey = keyPair.getPrivate();
        socket = new DatagramSocket(LOCAL_PORT);

        primaryStage.setTitle("Cliente Chat");

        GridPane grid = new GridPane();
        grid.setPadding(new Insets(10));
        grid.setHgap(10);
        grid.setVgap(10);

        Label usernameLabel = new Label("Usuario:");
        TextField usernameField = new TextField();
        Button connectButton = new Button("Conectar");

        Label recipientLabel = new Label("Destinatario:");
        TextField recipientField = new TextField();

        Label messageLabel = new Label("Mensaje:");
        TextField messageField = new TextField();

        Button sendButton = new Button("Enviar");
        TextArea chatArea = new TextArea();
        chatArea.setEditable(false);

        grid.add(usernameLabel, 0, 0);
        grid.add(usernameField, 1, 0);
        grid.add(connectButton, 2, 0);
        grid.add(recipientLabel, 0, 1);
        grid.add(recipientField, 1, 1);
        grid.add(messageLabel, 0, 2);
        grid.add(messageField, 1, 2);
        grid.add(sendButton, 2, 2);
        grid.add(chatArea, 0, 3, 3, 1);

        connectButton.setOnAction(event -> {
            username = usernameField.getText().trim();
            if (username.isEmpty()) {
                chatArea.appendText("⚠️ Ingresa un nombre de usuario.\n");
                return;
            }

            try {
                String registerMessage = "REGISTER:" + username + ":" + Base64.getEncoder().encodeToString(publicKey.getEncoded());
                sendToServer(registerMessage);
                chatArea.appendText("✅ Conectado como: " + username + "\n");
                startListening(chatArea);
            } catch (Exception e) {
                chatArea.appendText("❌ Error al conectar: " + e.getMessage() + "\n");
            }
        });

        sendButton.setOnAction(event -> {
            String recipient = recipientField.getText().trim();
            String message = messageField.getText().trim();

            if (recipient.isEmpty() || message.isEmpty()) {
                chatArea.appendText("⚠️ Completa los campos de destinatario y mensaje.\n");
                return;
            }

            try {
                if (!publicKeys.containsKey(recipient)) {
                    String request = "GET_PUBLIC_KEY:" + recipient;
                    sendToServer(request);
                    Thread.sleep(1000);
                }

                PublicKey recipientKey = publicKeys.get(recipient);
                if (recipientKey == null) {
                    chatArea.appendText("❌ No se pudo obtener la clave pública de " + recipient + ".\n");
                    return;
                }

                byte[] encryptedMessage = CryptoUtils.encrypt(message, recipientKey);
                String encryptedBase64 = "MESSAGE:" + username + ":" + recipient + ":" + Base64.getEncoder().encodeToString(encryptedMessage);
                sendToServer(encryptedBase64);
                chatArea.appendText("📤 Tú -> " + recipient + ": " + message + "\n");
            } catch (Exception e) {
                chatArea.appendText("❌ Error al enviar mensaje: " + e.getMessage() + "\n");
            }
        });

        primaryStage.setScene(new Scene(grid, 500, 400));
        primaryStage.show();
    }

    private void sendToServer(String message) throws Exception {
        byte[] data = message.getBytes();
        DatagramPacket packet = new DatagramPacket(data, data.length, InetAddress.getByName(SERVER_IP), SERVER_PORT);
        socket.send(packet);
    }

    private void startListening(TextArea chatArea) {
        Thread listenerThread = new Thread(() -> {
            try {
                byte[] buffer = new byte[2048];
                while (true) {
                    DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                    socket.receive(packet);

                    String response = new String(packet.getData(), 0, packet.getLength()).trim();
                    Platform.runLater(() -> processServerResponse(response, chatArea));
                }
            } catch (Exception e) {
                Platform.runLater(() -> chatArea.appendText("❌ Error al recibir datos: " + e.getMessage() + "\n"));
            }
        });
        listenerThread.setDaemon(true);
        listenerThread.start();
    }

    private void processServerResponse(String response, TextArea chatArea) {
        if (response.startsWith("PUBLIC_KEY:")) {
            String[] parts = response.split(":");
            String sender = parts[1];
            String keyBase64 = parts[2];
            try {
                byte[] keyBytes = Base64.getDecoder().decode(keyBase64);
                PublicKey key = CryptoUtils.getPublicKey(keyBytes);
                publicKeys.put(sender, key);
                chatArea.appendText("[🔑 Servidor] Clave pública de " + sender + " almacenada.\n");
            } catch (Exception e) {
                chatArea.appendText("❌ Error al procesar clave pública: " + e.getMessage() + "\n");
            }
        } else if (response.startsWith("MESSAGE:")) {
            String[] parts = response.split(":", 4);
            String sender = parts[1];
            String encryptedMessage = parts[3];
            try {
                byte[] decodedMessage = Base64.getDecoder().decode(encryptedMessage);
                String decryptedMessage = CryptoUtils.decrypt(decodedMessage, privateKey);
                chatArea.appendText("[📥 " + sender + "] " + decryptedMessage + "\n");
            } catch (Exception e) {
                chatArea.appendText("[📥 " + sender + "] ❌ Error al descifrar mensaje.\n");
            }
        } else {
            chatArea.appendText("⚠️ Respuesta desconocida: " + response + "\n");
        }
    }
}
*/