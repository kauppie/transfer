use anyhow::anyhow;
use clap::Parser;
use tokio::io::AsyncWriteExt;
use tonic::transport::{Certificate, Channel, ClientTlsConfig};

use transfer::transfer_client::TransferClient;
use transfer::{FileName, Path};

pub mod transfer {
    tonic::include_proto!("transfer"); // The string specified here must match the proto package name
}

#[derive(clap::Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(subcommand)]
    command: Command,
}

#[derive(clap::Subcommand, Debug)]
enum Command {
    List(ListArgs),
    Get(GetArgs),
}

#[derive(clap::Args, Debug)]
struct ListArgs {
    path: String,
}

#[derive(clap::Args, Debug)]
struct GetArgs {
    name: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse command line arguments.
    let args = Args::parse();

    // Build a runtime for asynchronous requests.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("couldn't create tokio runtime");

    // Run asynchronous runtime.
    runtime.block_on(async move {
        let pem = tokio::fs::read("dev/ca.pem").await?;
        let ca = Certificate::from_pem(pem);

        let tls = ClientTlsConfig::new()
            .ca_certificate(ca)
            .domain_name("example.com");

        let channel = Channel::from_static("http://[::1]:50051")
            .tls_config(tls)?
            .connect()
            .await?;

        // Build and connect a client for gRPC communication.
        let mut client = TransferClient::new(channel);

        match args.command {
            Command::List(args) => {
                // Create a file list request.
                let request = tonic::Request::new(Path { path: args.path });
                // Make a request to the server with request and get response.
                let response = client.list_files(request).await?;

                // Print result file names.
                for file_name in response.into_inner().names {
                    println!("{}", file_name);
                }
            }
            Command::Get(args) => {
                // Make a request to the server with file name request and get file response.
                let response = client
                    .get_file(tonic::Request::new(FileName { name: args.name }))
                    .await?
                    .into_inner();

                let mut file = tokio::fs::File::create("output").await?;
                file.write_all(&response.content).await?;
            }
        }

        Ok(())
    })
}
