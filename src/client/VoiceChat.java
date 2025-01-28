package client;

import javax.sound.sampled.*;
import java.net.*;

public class VoiceChat {
    public static void captureAndSend(DatagramSocket socket, InetAddress targetAddress, int port) throws Exception {
        AudioFormat format = new AudioFormat(44100, 16, 1, true, true);
        DataLine.Info info = new DataLine.Info(TargetDataLine.class, format);
        TargetDataLine microphone = (TargetDataLine) AudioSystem.getLine(info);
        microphone.open(format);
        microphone.start();

        byte[] buffer = new byte[1024];
        while (true) {
            int bytesRead = microphone.read(buffer, 0, buffer.length);
            socket.send(new DatagramPacket(buffer, bytesRead, targetAddress, port));
        }
    }

    public static void receiveAndPlay(DatagramSocket socket) throws Exception {
        AudioFormat format = new AudioFormat(44100, 16, 1, true, true);
        DataLine.Info info = new DataLine.Info(SourceDataLine.class, format);
        SourceDataLine speakers = (SourceDataLine) AudioSystem.getLine(info);
        speakers.open(format);
        speakers.start();

        byte[] buffer = new byte[1024];
        while (true) {
            DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
            socket.receive(packet);
            speakers.write(packet.getData(), 0, packet.getLength());
        }
    }
}
