import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class App {
    public static void main(String[] args) throws Exception {
        ServerSocket serverSocket = new ServerSocket(8000);
        try {
            System.out.println("Servidor sincronizando no endereço 127.0.0.1:8000.\r\nEspere pela conexão...");
            Socket client = serverSocket.accept();

            InputStream iS = client.getInputStream();
            OutputStream oS = client.getOutputStream();

            
            System.out.println("Conectado");
            Scanner scanner = new Scanner(iS, "UTF-8");
            try {
                String data = scanner.useDelimiter("\\r\\n\\r\\n").next();
                Matcher get = Pattern.compile("^GET").matcher(data);
                if (get.find()) {
                    Matcher match = Pattern.compile("Sec-WebSocket-Key: (.*)").matcher(data);
                    match.find();
                    byte[] response = ("HTTP/1.1 101 Switching Protocols\r\n"
                            + "Connection: Upgrade\r\n"
                            + "Upgrade: websocket\r\n"
                            + "Sec-WebSocket-Accept: "
                            + Base64.getEncoder()
                                    .encodeToString(MessageDigest.getInstance("SHA-1")
                                            .digest((match.group(1) + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
                                                    .getBytes("UTF-8")))
                            + "\r\n\r\n").getBytes("UTF-8");
                    oS.write(response, 0, response.length);

                    byte[] decoded = new byte[6];
                    byte[] encoded = new byte[] { (byte) 198, (byte) 131, (byte) 130, (byte) 182, (byte) 194, (byte) 135 };
                    byte[] key = new byte[] { (byte) 167, (byte) 225, (byte) 225, (byte) 210 };

                    for (int i = 0; i < encoded.length; i++) {
                        decoded[i] = (byte) (encoded[i] ^ key[i & 0x3]);

                    }
                    System.out.println(oS);
                }
            } finally {
                scanner.close();
            }
        } finally {
            serverSocket.close();
        }

    }

}
