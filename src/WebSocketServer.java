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

            // passando uma requisição http especial para mudar de http para ws
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

                // recebendo os byte com bit reservados e custmizações e tipo de dados
                int b1 = iS.read();

                // pegando o length em byte
                int b2 = iS.read();

                if (b1 == -1 || b2 == -1) {
                    System.out.println("Cliente desconectado.");
                    break;
                }

                // final frame bit, 1 = ultimo bit para descobrir o ultimo valor
                boolean fin = (b1 & 0x80) != 0;

                // peganado o tipo de dados = 129 então texto, 0x07 apenas pega os 4 primeiro
                // bits da direita, exlcuindo da esquerda
                int opcode = b1 & 0x0F;

                // mascara obrigatoria do cliente, 1bit
                boolean masked = (b2 & 0x80) != 0;

                // pegando o tamanho de bytes presentes
                int payloadLength = b2 & 0x7F;
                if (!masked) {
                    System.out.println("Frame não mascarado! (cliente deve sempre mascarar)");
                    break;
                }

                // se o payload igual 126 espera receber mais dois bytes para pegar o tamanho
                // real
                if (payloadLength == 126) {
                    payloadLength = (iS.read() << 8) | iS.read();
                } else if (payloadLength == 127) {
                    System.out.println("Payload muito grande (não tratado aqui).");
                    break;
                }

                // preparando para receber os quatro bytes de maskingkey do cliente
                byte[] maskingKey = new byte[4];
                iS.read(maskingKey, 0, 4);

                // recebendo unicamente os 11bytes(pegando pelo payloadLentgh) do b2
                byte[] encodedData = new byte[payloadLength];
                iS.read(encodedData, 0, payloadLength);

                // criando array de bytes para destribuir a masking de quatro em quatro
                byte[] decodedData = new byte[payloadLength];
                for (int i = 0; i < payloadLength; i++) {
                    decodedData[i] = (byte) (encodedData[i] ^ maskingKey[i % 4]);
                }

                // Retorna uma string com cada byte correspondente de cada letra formando a
                // palavra
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
