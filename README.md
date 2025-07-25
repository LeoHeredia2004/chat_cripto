##Crypto Chat##
This project is a simple and secure client-server chat application developed in Rust. It uses RSA encryption to ensure the confidentiality of messages and SHA-256 to verify their integrity. Communication is established via TCP sockets.

#Features:#
Client-Server Communication: Establishes a TCP connection between a server and multiple clients.

End-to-End Encryption: Messages are encrypted using the RSA algorithm. Each client and the server generate their own key pairs (public and private) and exchange them during an initial handshake.

Integrity Check: Each message is accompanied by a SHA-256 hash of its original content, ensuring that the message was not altered in transit.

Secure Handshake: Before message exchange begins, a handshake process is performed to securely exchange public keys between the client and the server.

#How to Run:#
The project can be run in two modes: as a server or as a client.

#Prerequisites:#
You must have Rust installed. You can install it via rustup.

Compiling and Running
In one terminal:
cargo run -- --server

Start the Client:
In another terminal, simply run:
cargo run
