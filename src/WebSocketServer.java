import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class WebSocketServer {
        private static List<Socket> clients = new CopyOnWriteArrayList<>();

    public static void main(String[] args) throws Exception {
        ServerSocket serverSocket = new ServerSocket(8000);
        System.out.println("Servidor WebSocket rodando na porta 8000...");
        List<Socket> clients = new ArrayList<>();

        while (true) {
            Socket socket = serverSocket.accept();
            clients.add(socket);
            System.out.println("Cliente conectado: " + socket.getInetAddress());


            new Thread(() -> clientNotifier(socket)).start();

            
           
        }
    }
        
        private static void clientNotifier(Socket socket) {
            try {
                InputStream iS = socket.getInputStream();
                OutputStream oS = socket.getOutputStream();
    
                // Handshake
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
    
                // Receber mensagens WebSocket
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
    
                    if (opcode == 8) { // Close frame
                        System.out.println("Cliente pediu para fechar a conexão.");
                        break;
                    }
    
                    // Broadcast da mensagem para todos os clientes
                    broadcast(mensagem, socket);
                }
            } catch (Exception e) {
                System.out.println("Erro com cliente: " + e.getMessage());
            } finally {
                try {
                    clients.remove(socket);
                    socket.close();
                    System.out.println("Cliente desconectado e removido.");
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }




    
        private static void broadcast(String mensagem, Socket sender) {
            for (Socket client : clients) {
                if (client.isClosed()) continue;
                if (client == sender) continue; // se não quiser enviar para quem mandou, deixe essa linha. Se quiser, remova.
    
                try {
                    OutputStream oS = client.getOutputStream();
                    sendWebSocketMessage(oS, mensagem);
                } catch (IOException e) {
                    System.out.println("Erro ao enviar para cliente: " + e.getMessage());
                }
            }
        }
    
        private static void sendWebSocketMessage(OutputStream oS, String mensagem) throws IOException {
            byte[] data = mensagem.getBytes("UTF-8");
    
            int frameCount = 0;
            byte[] frame = new byte[10];
    
            frame[0] = (byte) 129; // 1000 0001 -> FIN + texto
    
            if (data.length <= 125) {
                frame[1] = (byte) data.length;
                frameCount = 2;
            } else if (data.length >= 126 && data.length <= 65535) {
                frame[1] = 126;
                frame[2] = (byte) ((data.length >> 8) & (byte) 255);
                frame[3] = (byte) (data.length & (byte) 255);
                frameCount = 4;
            } else {
                frame[1] = 127;
                frame[2] = frame[3] = frame[4] = frame[5] = 0;
                frame[6] = (byte) ((data.length >> 24) & (byte) 255);
                frame[7] = (byte) ((data.length >> 16) & (byte) 255);
                frame[8] = (byte) ((data.length >> 8) & (byte) 255);
                frame[9] = (byte) (data.length & (byte) 255);
                frameCount = 10;
            }
    
            oS.write(frame, 0, frameCount);
            oS.write(data);
            oS.flush();
        }
    }