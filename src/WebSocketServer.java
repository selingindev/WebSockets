import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class WebSocketServer {
    public static void main(String[] args) throws Exception {
        ServerSocket serverSocket = new ServerSocket(8000);
        System.out.println("Servidor WebSocket rodando na porta 8000...");

        while (true) {
            Socket socket = serverSocket.accept();
            System.out.println("Cliente conectado: " + socket.getInetAddress());

            InputStream iS = socket.getInputStream();
            OutputStream oS = socket.getOutputStream();

            // Realizar handshake
            BufferedReader reader = new BufferedReader(new InputStreamReader(iS));
            StringBuilder request = new StringBuilder();
            String line;
            while (!(line = reader.readLine()).isEmpty()) {
                request.append(line).append("\r\n");
            }

            String data = request.toString();
            System.out.println("Handshake recebido:\n" + data);

            Matcher get = Pattern.compile("^GET").matcher(data);
            if (get.find()) {
                Matcher match = Pattern.compile("Sec-WebSocket-Key: (.*)").matcher(data);
                if (match.find()) {
                    String key = match.group(1).trim();
                    String acceptKey = Base64.getEncoder()
                            .encodeToString(MessageDigest.getInstance("SHA-1")
                                    .digest((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").getBytes("UTF-8")));

                    String response = "HTTP/1.1 101 Switching Protocols\r\n"
                            + "Connection: Upgrade\r\n"
                            + "Upgrade: websocket\r\n"
                            + "Sec-WebSocket-Accept: " + acceptKey + "\r\n\r\n";

                    oS.write(response.getBytes("UTF-8"));
                    oS.flush();
                    System.out.println("Handshake enviado com sucesso!");
                }
            }

            // Agora, receber mensagens WebSocket
            while (true) {
                int b1 = iS.read();
                int b2 = iS.read();

                if (b1 == -1 || b2 == -1) {
                    System.out.println("Cliente desconectado.");
                    break;
                }

                boolean fin = (b1 & 0x80) != 0;
                int opcode = b1 & 0x0F;
                boolean masked = (b2 & 0x80) != 0;
                int payloadLength = b2 & 0x7F;

                if (!masked) {
                    System.out.println("Frame não mascarado! (cliente deve sempre mascarar)");
                    break;
                }

                if (payloadLength == 126) {
                    payloadLength = (iS.read() << 8) | iS.read();
                } else if (payloadLength == 127) {
                    System.out.println("Payload muito grande (não tratado aqui).");
                    break;
                }

                byte[] maskingKey = new byte[4];
                iS.read(maskingKey, 0, 4);

                byte[] encodedData = new byte[payloadLength];
                iS.read(encodedData, 0, payloadLength);

                byte[] decodedData = new byte[payloadLength];
                for (int i = 0; i < payloadLength; i++) {
                    decodedData[i] = (byte) (encodedData[i] ^ maskingKey[i % 4]);
                }

                String mensagem = new String(decodedData, "UTF-8");
                System.out.println("Mensagem recebida: " + mensagem);

                if (opcode == 8) { // 8 = Close
                    System.out.println("Cliente pediu para fechar a conexão.");
                    socket.close();
                    break;
                }
            }
        }
    }
}
