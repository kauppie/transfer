mod common;

use clap::Parser;
use tokio::io::AsyncWriteExt;
use tonic::metadata::MetadataValue;
use tonic::transport::{Certificate, Channel, ClientTlsConfig};
use tonic::Request;

use transfer::login_client::LoginClient;
use transfer::transfer_client::TransferClient;
use transfer::{GetFileRequest, ListFilesRequest};

use crate::transfer::LoginRequest;

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
    Login(LoginArgs),
}

#[derive(clap::Args, Debug)]
struct ListArgs {
    path: String,
}

#[derive(clap::Args, Debug)]
struct GetArgs {
    name: String,
}

#[derive(clap::Args, Debug)]
struct LoginArgs {
    username: String,
    password: String,
}

type StdError = Box<dyn std::error::Error + Send + Sync + 'static>;

#[tokio::main]
async fn main() -> Result<(), StdError> {
    // Parse command line arguments.
    let args = Args::parse();

    // Read server's CA certificate.
    let pem = tokio::fs::read("dev/ca.pem").await?;
    let ca = Certificate::from_pem(pem);

    // Configure TLS client with server settings.
    let tls = ClientTlsConfig::new()
        .ca_certificate(ca)
        .domain_name("example.com");

    // Create and connect a TLS channel to the server.
    let channel = Channel::from_static("http://[::1]:50051")
        .tls_config(tls)?
        .connect()
        .await?;

    let token: MetadataValue<_> = "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJoZWxsbyIsImV4cCI6MTY1NjYyODExN30.av9hf8fDRSzPzZtU6nUTpo8081UgUiWFHj-lKBefaiWQpVWVVVrzdUHqseNsNL-E-zi2q1nOFJg6plRad3Y6ngiGbH08Hye1T5HrgaBzS5QBhBVYfoFDPdkSojX5KLHnwApi9B1G2mN3UI_SWScPJBxhOfCxjin1RL7u1XLqBI7kGMYRFUiK7jSERE7ktFvGyKFsjJWrln9gLQQ6vh4cyGHE2bZeisPtqaSll1rd3iu7mG6Wy0MUCXYCJllv1YwcZl-PuaAP9woDSKXpnSNmhlQ2nbZxPhQjRXQO69DJ-oPheWkBP1dHWmZbUgzqFk5sZWM2_PwtNLdTnNoRL8Wsvg".parse()?;

    // Create a client using the created channel.
    let mut client =
        TransferClient::with_interceptor(channel.clone(), move |mut req: Request<()>| {
            req.metadata_mut().insert("authorization", token.clone());
            Ok(req)
        });

    let mut login_client = LoginClient::new(channel);

    match args.command {
        Command::List(args) => {
            // Create a file list request.
            let request = tonic::Request::new(ListFilesRequest { path: args.path });
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
                .get_file(tonic::Request::new(GetFileRequest { name: args.name }))
                .await?
                .into_inner();

            let mut file = tokio::fs::File::create("output").await?;
            file.write_all(&response.content).await?;
        }
        Command::Login(args) => {
            let request = tonic::Request::new(LoginRequest {
                username: args.username,
                password: args.password,
            });
            let response = login_client.login(request).await?;
            println!("{:?}", response);
        }
    }

    Ok(())
}
