mod rsa;
mod network;
mod sha;

// Se o codigo for passado com --server como argumento, o terminal servirá
//como servidor, sem, será cliente

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() > 1 && args[1] == "--server" {
        network::start_server(8080).await;
    } else {
        network::start_client("127.0.0.1:8080").await;
    }

    Ok(())
}