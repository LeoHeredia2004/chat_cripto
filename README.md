#Crypto Chat
A simple and secure client-server chat application built with Rust, featuring RSA end-to-end encryption and SHA-256 for message integrity.

🚀 Features
Client-Server Communication: Establishes a TCP connection between a server and multiple clients.

End-to-End Encryption: All messages are encrypted using the RSA algorithm.

Integrity Check: Each message is signed with a SHA-256 hash to ensure it has not been tampered with.

Secure Handshake: A handshake process is performed to securely exchange public keys before any messages are sent.

🛠️ How to Run
The project can be run in two modes: server or client.

Prerequisites
You must have the Rust toolchain installed. You can install it via rustup.

Compiling and Running
Clone the repository:

Bash

git clone <your-repository-url>
cd chat_cripto
Build the project:

Bash

cargo build
Start the Server:
In a terminal, run the following command to start the server, which will listen on port 8080:

Bash

cargo run -- --server
Start the Client:
In a separate terminal, run the following command to connect to the server:

Bash

cargo run
