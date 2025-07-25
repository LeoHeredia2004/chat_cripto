# Crypto Chat
Uma aplicação de chat cliente-servidor simples e segura construída com Rust, com criptografia de ponta a ponta RSA e SHA-256 para integridade das mensagens.
Ele simula um chat entre dois terminais, onde as mensagens serão protegidas por criptografia. O RSA e o SHA-256 também foram feitos por mim.

## Funcionalidades
Comunicação Cliente-Servidor: Estabelece uma conexão TCP entre um servidor e múltiplos clientes.

Criptografia de Ponta a Ponta: Todas as mensagens são criptografadas usando o algoritmo RSA.

Verificação de Integridade: Cada mensagem é assinada com um hash SHA-256 para garantir que não foi adulterada.

Handshake Seguro: Um processo de handshake é realizado para trocar chaves públicas de forma segura antes que qualquer mensagem seja enviada.

## Pré-requisitos
Você precisa ter a toolchain do Rust instalada. Você pode instalá-la através do rustup.

## Compilando e Executando
Clone o repositório.

### Inicie o Servidor:
Em um terminal, execute o seguinte comando para iniciar o servidor, que ficará escutando na porta 8080:

cargo run -- --server

### Inicie o Cliente:
Em um terminal separado, execute o seguinte comando para se conectar ao servidor:

cargo run

----------------------------------------------------------------------------------------------------------------------------------

# Crypto Chat

A simple and secure client-server chat application built with Rust, featuring RSA end-to-end encryption and SHA-256 for message integrity.
It simulates a chat between two terminals, where the messages will be secured via cryptography, the rsa and SHA-256 were also made by me. 

## Features
Client-Server Communication: Establishes a TCP connection between a server and multiple clients.

End-to-End Encryption: All messages are encrypted using the RSA algorithm.

Integrity Check: Each message is signed with a SHA-256 hash to ensure it has not been tampered with.

Secure Handshake: A handshake process is performed to securely exchange public keys before any messages are sent.

## Prerequisites
You must have the Rust toolchain installed. You can install it via rustup.

## Compiling and Running
Clone the repository.

### Start the Server:
In a terminal, run the following command to start the server, which will listen on port 8080:

cargo run -- --server

### Start the Client:
In a separate terminal, run the following command to connect to the server:

cargo run
