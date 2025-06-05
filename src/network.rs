use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt, AsyncBufReadExt, BufReader as TokioBufReader};
use tokio::net::TcpStream;
use std::net::SocketAddr;
use bincode::{serialize as bincode_serialize, deserialize as bincode_deserialize};
use crate::rsa::{self, PublicKey, encrypt_string, PrivateKey};
use crate::sha::sha256;
use std::io::Write;

/// Inicia o servidor TCP, escutando por conexões de clientes.
///
/// Ouve em todas as interfaces de rede (0.0.0.0) na porta especificada.
/// Para cada conexão aceita, ele cria uma nova tarefa Tokio para lidar com a comunicação.
pub async fn start_server(port: u16) {
    // Vincula o TcpListener à porta especificada em todas as interfaces de rede.
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await.unwrap();
    println!("Servidor escutando na porta: {}", port);

    // Loop infinito para aceitar novas conexões.
    loop {
        // Aceita uma nova conexão de entrada. Isso bloqueará até que um cliente se conecte.
        let (socket, addr) = listener.accept().await.unwrap();
        // Cria uma nova tarefa assíncrona para lidar com a conexão do cliente.
        // Isso permite que o servidor lide com múltiplos clientes simultaneamente.
        tokio::spawn(async move {
            let mut mutable_socket = socket; // Cria uma cópia mutável do socket
            // Gera o par de chaves RSA para o servidor. Essas chaves serão usadas para criptografia/descriptografia
            // e para o processo de handshake.
            let (local_server_pub, local_server_priv) = rsa::generate_keypair(); // Chaves do servidor
            // Realiza um handshake com o cliente para trocar chaves públicas.
            let client_pub_key = perform_handshake(&mut mutable_socket, &local_server_pub).await;
            // Lida com a comunicação contínua com o cliente após o handshake.
            handle_connection(mutable_socket, addr, local_server_priv, client_pub_key).await;
        });
    }
}

/// Lida com a comunicação com um único cliente conectado.
///
/// Esta função gerencia tanto o envio quanto o recebimento de mensagens, incluindo
/// a descriptografia usando a chave privada do servidor e a verificação da integridade da mensagem
/// usando hash SHA-256.
async fn handle_connection(
    socket: TcpStream,
    addr: SocketAddr,
    my_server_priv_key: rsa::PrivateKey,
    peer_client_pub_key: rsa::PublicKey,
) {
    // Divide o fluxo TCP em uma metade legível e uma metade gravável.
    let (mut reader_half, mut writer_half) = tokio::io::split(socket);
    // Clona a chave privada do servidor para ser usada na tarefa de leitura.
    let server_priv_key_clone_for_read = my_server_priv_key.clone();

    // Cria uma nova tarefa assíncrona para lidar com a leitura de mensagens do cliente.
    tokio::spawn(async move {
        let mut client_msg_payload_buf = [0; 4096]; // Buffer para o payload da mensagem criptografada
        let mut received_hash_buf = [0u8; 32]; // Buffer para o hash SHA-256 recebido (32 bytes)

        loop {
            // Primeiro, lê o hash SHA-256 de 32 bytes.
            reader_half.read_exact(&mut received_hash_buf).await.unwrap();
            // Lê o payload da mensagem criptografada. `read` retorna o número de bytes lidos.
            let bytes_read = reader_half.read(&mut client_msg_payload_buf).await.unwrap();

            // Desserializa os bytes recebidos em um vetor de u64, que representa a
            // mensagem criptografada RSA.
            let encrypted_msg: Vec<u64> =
                bincode_deserialize(&client_msg_payload_buf[..bytes_read]).unwrap();

            // NOVO: Imprime a mensagem criptografada recebida no servidor
            println!("\n[Servidor - Recebido] Mensagem criptografada (Vec<u64>): {:?}", encrypted_msg);

            // Descriptografa a mensagem usando a chave privada do servidor.
            let decrypted_text = rsa::decrypt_string(
                &encrypted_msg,
                server_priv_key_clone_for_read.d,
                server_priv_key_clone_for_read.n,
            );

            // Calcula o hash SHA-256 da mensagem descriptografada.
            let calculated_hash = sha256(decrypted_text.as_bytes());

            // Compara o hash calculado com o hash recebido para verificar a integridade da mensagem.
            if calculated_hash == received_hash_buf {
                println!("[CLIENTE {} Assinatura VÁLIDA]: {}", addr, decrypted_text);
            } else {
                println!("[CLIENTE {} Assinatura INVÁLIDA!]: {}", addr, decrypted_text);
            }
            // Solicita uma resposta do servidor.
            print!("Servidor, sua resposta para {}: ", addr);
            let _ = std::io::stdout().flush(); // Libera o stdout para garantir que o prompt seja exibido imediatamente.
        }
    });

    // Lida com o envio de mensagens do servidor para o cliente.
    let mut server_stdin_reader = TokioBufReader::new(tokio::io::stdin()); // Cria um leitor bufferizado para stdin.
    let mut server_response_line = String::new(); // Buffer para a entrada do servidor.

    // Prompt inicial para o servidor.
    print!("Servidor, sua resposta para {}: ", addr);
    let _ = std::io::stdout().flush();

    loop {
        server_response_line.clear(); // Limpa o buffer para a próxima entrada.

        // Lê uma linha do stdin. Se 0 bytes forem lidos, significa que o stdin foi fechado.
        if server_stdin_reader.read_line(&mut server_response_line).await.unwrap() == 0 {
            break; // Sai do loop se o stdin for fechado.
        }

        let response_text_from_server = server_response_line.trim(); // Remove espaços em branco da entrada.

        // Calcula o hash SHA-256 da resposta do servidor.
        let message_hash = sha256(response_text_from_server.as_bytes());

        // Criptografa a resposta do servidor usando a chave pública do cliente.
        let mut encrypted_response_to_client = rsa::encrypt_string(
            response_text_from_server,
            peer_client_pub_key.e,
            peer_client_pub_key.n,
        );

        // --- TESTE DE ALTERAÇÃO (Simulação de adulteração) ---
        // Se o servidor digitar "testar", altera intencionalmente o primeiro bloco
        // da mensagem criptografada para simular adulteração.
        if response_text_from_server == "testar" {
            if let Some(first) = encrypted_response_to_client.get_mut(0) {
                *first = first.wrapping_add(1); // Incrementa o primeiro valor u64.
            }
        }

        // Serializa a mensagem criptografada em bytes usando bincode.
        let serialized_response = bincode_serialize(&encrypted_response_to_client).unwrap();

        writer_half.write_all(&message_hash).await.unwrap();
        writer_half.write_all(&serialized_response).await.unwrap();
        writer_half.flush().await.unwrap(); // Garante que todos os dados em buffer sejam enviados.

        // Solicita novamente a próxima resposta.
        print!("Servidor, sua resposta para {}: ", addr);
        let _ = std::io::stdout().flush();
    }
}

/// Realiza um handshake para trocar chaves públicas entre o servidor e um cliente.
///
/// O servidor envia sua chave pública e, em seguida, recebe a chave pública do cliente.
async fn perform_handshake(stream: &mut TcpStream, my_pub_key: &PublicKey) -> PublicKey {
    // Serializa a chave pública do servidor em bytes.
    let pub_key_bytes = my_pub_key.to_bytes();
    // Envia a chave pública do servidor para o cliente.
    stream.write_all(&pub_key_bytes).await.unwrap();
    stream.flush().await.unwrap(); // Garante que a chave seja enviada.

    let mut buf = [0; 512]; // Buffer para receber a chave pública do cliente.
    // Lê a chave pública do cliente do fluxo.
    let bytes_read = stream.read(&mut buf).await.unwrap();

    // Desserializa os bytes recebidos de volta em uma estrutura PublicKey.
    let peer_pub_key = PublicKey::from_bytes(&buf[..bytes_read]);
    peer_pub_key
}

/// Inicia o cliente TCP e conecta-se ao endereço do servidor especificado.
///
/// Após a conexão, ele realiza um handshake para trocar chaves públicas e
/// então lida com o envio e recebimento de mensagens criptografadas e assinadas.
pub async fn start_client(server_addr: &str) {
    // Analisa a string do endereço do servidor em um SocketAddr.
    let server_socket_addr = server_addr
        .parse::<SocketAddr>()
        .expect("Endereço do servidor inválido");
    // Conecta-se ao servidor. Isso bloqueará até que uma conexão seja estabelecida.
    let mut stream = TcpStream::connect(server_socket_addr).await.unwrap();
    println!("Conectado ao servidor {}", server_addr);

    // Gera o par de chaves RSA para o cliente.
    let (my_pub_key, my_priv_key) = rsa::generate_keypair();
    // Realiza o handshake com o servidor para trocar chaves públicas.
    let server_pub_key = perform_handshake(&mut stream, &my_pub_key).await;
    println!("Handshake com servidor OK.\n");

    // Divide o fluxo TCP para leitura e escrita concorrentes.
    let (mut reader_half, mut writer_half) = tokio::io::split(stream);
    // Clona a chave privada do cliente para a tarefa de leitura.
    let priv_key_for_read_task = my_priv_key.clone();

    // Cria uma nova tarefa assíncrona para lidar com a leitura de mensagens do servidor.
    tokio::spawn(async move {
        let mut server_msg_payload_buf = [0; 4096]; // Buffer para o payload da mensagem criptografada.
        let mut received_hash_buf = [0u8; 32]; // Buffer para o hash SHA-256 recebido.

        loop {
            // Primeiro, lê o hash SHA-256 de 32 bytes.
            reader_half.read_exact(&mut received_hash_buf).await.unwrap();
            // Lê o payload da mensagem criptografada.
            let bytes_read = reader_half.read(&mut server_msg_payload_buf).await.unwrap();

            // Desserializa os bytes recebidos no formato de mensagem criptografada (Vec<u64>).
            let encrypted_msg =
                bincode_deserialize::<Vec<u64>>(&server_msg_payload_buf[..bytes_read]).unwrap();

            // NOVO: Imprime a mensagem criptografada recebida no cliente
            println!("\n[Cliente - Recebido] Mensagem criptografada (Vec<u64>): {:?}", encrypted_msg);

            // Descriptografa a mensagem usando a chave privada do cliente.
            let decrypted_text = rsa::decrypt_string(
                &encrypted_msg,
                priv_key_for_read_task.d,
                priv_key_for_read_task.n,
            );

            // Calcula o hash SHA-256 da mensagem descriptografada.
            let calculated_hash = sha256(decrypted_text.as_bytes());

            // Verifica a integridade da mensagem comparando os hashes.
            if calculated_hash == received_hash_buf {
                println!("[SERVIDOR Assinatura VÁLIDA]: {}", decrypted_text);
            } else {
                println!("[SERVIDOR Assinatura INVÁLIDA!]: {}", decrypted_text);
            }
            // Solicita uma resposta do cliente.
            print!("Cliente, sua resposta para o servidor: ");
            let _ = std::io::stdout().flush();
        }
    });

    // Lida com o envio de mensagens do cliente para o servidor.
    let stdin = tokio::io::stdin();
    let mut stdin_reader = TokioBufReader::new(stdin);
    let mut input_line = String::new();

    // Prompt inicial para o cliente.
    print!("Cliente, sua resposta para o servidor: ");
    let _ = std::io::stdout().flush();

    loop {
        input_line.clear(); // Limpa o buffer.
        // Lê uma linha do stdin.
        let stdin_bytes_read = stdin_reader.read_line(&mut input_line).await.unwrap();
        if stdin_bytes_read == 0 {
            break; // Sai se o stdin for fechado.
        }

        let trimmed_input = input_line.trim(); // Remove espaços em branco.
        if trimmed_input.is_empty() {
            // Não envia mensagens vazias.
            print!("Cliente, sua resposta para o servidor (não pode ser vazia): ");
            let _ = std::io::stdout().flush();
            continue;
        }

        // Calcula o hash SHA-256 da mensagem do cliente.
        let message_hash = sha256(trimmed_input.as_bytes());

        // Criptografa a mensagem do cliente usando a chave pública do servidor.
        let encrypted_to_server = encrypt_string(
            trimmed_input,
            server_pub_key.e,
            server_pub_key.n,
        );
        
        // Serializa a mensagem criptografada.
        let serialized_msg = bincode_serialize(&encrypted_to_server).unwrap();

        writer_half.write_all(&message_hash).await.unwrap();
        writer_half.write_all(&serialized_msg).await.unwrap();
        writer_half.flush().await.unwrap(); // Garante que os dados sejam enviados.

        // Solicita a próxima mensagem.
        print!("Cliente, sua resposta para o servidor: ");
        let _ = std::io::stdout().flush();
    }
}