import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ServidorWebSocket {
    // Lista de clientes conectados (usando estrutura thread-safe)
    private static List<Socket> clientes = new CopyOnWriteArrayList<>();

    public static void main(String[] args) throws Exception {
        // Cria o servidor socket escutando na porta 8000
        ServerSocket servidorSocket = new ServerSocket(8000);
        System.out.println("Servidor WebSocket rodando na porta 8000...");

        //laços para esperar novos clientes
        while (true) {
            Socket clienteSocket = servidorSocket.accept(); // Aceita nova conexão e deixa bloqueado enquanto n aceita
            clientes.add(clienteSocket); // Adiciona cliente na lista
            System.out.println("Cliente " + clientes.size() + " conectado na porta: " + clienteSocket.getPort());

            // Cria uma nova thread para lidar com esse novo cliente enquanto ha outros
            new Thread(() -> requisicaoCliente(clienteSocket)).start(); 
        }
    }

    // Método que trata a comunicação com o cliente
    private static void requisicaoCliente(Socket clienteSocket) {
        try {
            InputStream entrada = clienteSocket.getInputStream();
            OutputStream saida = clienteSocket.getOutputStream();

            // Realiza o handshake (aperto de mão) do protocolo WebSocket
            BufferedReader leitor = new BufferedReader(new InputStreamReader(entrada));
            StringBuilder requisicao = new StringBuilder();

            //construindo texto partindo do cabecalho da requisição do socket
            String linha;
            while (!(linha = leitor.readLine()).isEmpty()) {
                requisicao.append(linha).append("\r\n");
            }

            String dadosRequisicao = requisicao.toString();
            System.out.println("Handshake recebido:\n" + dadosRequisicao);


            // verifica se a requisição começa com GET (sinal do handshake WebSocket).
            Matcher get = Pattern.compile("^GET").matcher(dadosRequisicao);

            //se for do tipo get procura a chave do WEBSOCKET passado pelo cliente  
                if (get.find()) {
                Matcher match = Pattern.compile("Sec-WebSocket-Key: (.*)").matcher(dadosRequisicao);
                if (match.find()) {
                    //extraindo a chave
                    String chave = match.group(1).trim();

                    //gera a chave da resposta, usando SHA-1 e Base64. Padrão do WS
                    String chaveAceita = 
                    // converte o hash do SHA-1 em uma string Base64, que é o que o protocolo espera como resposta.
                    Base64.getEncoder().encodeToString(
                        //aplica o algoritmo SHA-1 nesses bytes. (um hash com resumo criptográfico de 20 bytes)
                            MessageDigest.getInstance("SHA-1")  
                                    .digest((chave + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
                                    //converte a resposta em um array de bytes para usar para o SHA-1
                                    .getBytes("UTF-8")));     
                                    

                    String resposta = "HTTP/1.1 101 Switching Protocols\r\n"
                            + "Connection: Upgrade\r\n"
                            + "Upgrade: websocket\r\n"
                            + "Sec-WebSocket-Accept: " + chaveAceita + "\r\n\r\n";

                    //envia devolta para o cliente(navegador) avisando que o websocket funciona de fato
                    saida.write(resposta.getBytes("UTF-8"));
                    saida.flush();
                    System.out.println("Handshake enviado com sucesso!");
                }
            }

            // Laço para ler mensagens do cliente
            while (true) {
                //ws manda dois byts importantes

                //FIN(1) RSV OPCODE(4)
                int b1 = entrada.read();
                //MASK DO USER E O PAYLOAD DA msg
                int b2 = entrada.read();

                if (b1 == -1 || b2 == -1) {
                    System.out.println("Cliente desconectado.");
                    break;
                }

                //verfica se a mensagem termina neste frame se nao necessario criar outro(possivel manipular)
                boolean fin = (b1 & 0x80) != 0;
                //tipo da mensagem, texto, binario, ping pong,closse connection ...
                int opcode = b1 & 0x0F;
                //mascara obrigatoria que o cliente passa;
                boolean mascarado = (b2 & 0x80) != 0;
                //ignora o digito a esquerda e extrai o tamanho da mensagem
                int tamanhoPayload = b2 & 0x7F;

                if (!mascarado) {
                    System.out.println("Frame não mascarado! (cliente deve sempre mascarar)");
                    break;
                }
                //caso a mensagem seja mt grande avisa que o dado esta no proximos 8 bytes
                if (tamanhoPayload == 126) {
                    tamanhoPayload = (entrada.read() << 8) | entrada.read();
                } else if (tamanhoPayload == 127) {
                    System.out.println("Payload muito grande (não tratado aqui).");
                    break;
                }

                //cliente envia 4 chave de mscara 
                byte[] chaveMascara = new byte[4];
                entrada.read(chaveMascara, 0, 4);

                //byte do estilo UTF8 representando cada letra
                byte[] dadosCodificados = new byte[tamanhoPayload];
                entrada.read(dadosCodificados, 0, tamanhoPayload);

                byte[] dadosDecodificados = new byte[tamanhoPayload];
                for (int i = 0; i < tamanhoPayload; i++) {
                    //mascara tem o papel de dedodificar o dado do paylaod
                    //a cada 4 bytes ele volta para o primeiro byte da mascara do cliente
                    dadosDecodificados[i] = (byte) (dadosCodificados[i] ^ chaveMascara[i % 4]);
                }

                //retorna a mensagem
                String mensagem = new String(dadosDecodificados, "UTF-8");
                System.out.println("Mensagem recebida: " + mensagem);

                if (opcode == 8) { // Close frame
                    System.out.println("Cliente pediu para fechar a conexão.");
                    break;
                }

                // Envia a mensagem para todos os clientes conectados
                enviarParaTodos(mensagem, clienteSocket);
            }
        } catch (Exception e) {
            System.out.println("Erro com cliente: " + e.getMessage());
        } finally {
            try {
                clientes.remove(clienteSocket);
                clienteSocket.close();
                System.out.println("Cliente desconectado e removido.");
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    // Envia uma mensagem para todos os clientes (broadcast)
    //pega o cliente atual e a mensagem q nosos servidor procesosu
    private static void enviarParaTodos(String mensagem, Socket remetente) {
        for (Socket cliente : clientes) {
            if (cliente.isClosed()) continue;
            try {
                OutputStream saida = cliente.getOutputStream();
                enviarMensagemWebSocket(saida, mensagem);
            } catch (IOException e) {
                System.out.println("Erro ao enviar para cliente: " + e.getMessage());
            }
        }
    }

    // Envia uma mensagem WebSocket formatada corretamente
    private static void enviarMensagemWebSocket(OutputStream saida, String mensagem) throws IOException {
        //converte a string para um array de bytes
        byte[] dados = mensagem.getBytes("UTF-8");
        int contadorFrame = 0;
        byte[] frame = new byte[4];
        frame[0] = (byte) 129; // FIN + codigo texto byte 10000001
        if (dados.length <= 125) {
            frame[1] = (byte) dados.length;
            contadorFrame = 2;
        } else if (dados.length >= 126 && dados.length <= 65535) {
            frame[1] = 126;
            frame[2] = (byte) ((dados.length >> 8) & (byte) 255);
            frame[3] = (byte) (dados.length & (byte) 255);
            contadorFrame = 4;
        } 
        saida.write(frame, 0, contadorFrame);
        saida.write(dados);
        saida.flush();
    }
}
