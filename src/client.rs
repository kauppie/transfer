mod common;

use clap::Parser;
use tokio::io::AsyncWriteExt;
use tonic::metadata::MetadataValue;
use tonic::transport::{Certificate, Channel, ClientTlsConfig};
use tonic::Request;

use login::login_client::LoginClient;
use login::{CreateAccountRequest, LoginRequest};
use transfer::transfer_client::TransferClient;
use transfer::{GetFileRequest, ListFilesRequest};

pub mod transfer {
    // The string specified here must match the proto package name
    tonic::include_proto!("transfer");
}
pub mod login {
    tonic::include_proto!("login");
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
    CreateAccount(CreateAccountArgs),
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

#[derive(clap::Args, Debug)]
struct CreateAccountArgs {
    username: String,
    password: String,
}

type StdError = Box<dyn std::error::Error + Send + Sync + 'static>;

async fn load_token(path: &str) -> Result<String, StdError> {
    let token_str = tokio::fs::read_to_string(path).await?;
    Ok(token_str)
}

const TOKEN_PATH: &str = "token.txt";

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

    if let Command::Login(args) = &args.command {
        let mut login_client = LoginClient::new(channel.clone());

        // Create the login request.
        let request = tonic::Request::new(LoginRequest {
            username: args.username.clone(),
            password: args.password.clone(),
        });
        // Get response by calling the server.
        let response = login_client.login(request).await?;

        // Save the token got via response to file.
        let token = response.into_inner().token;
        tokio::fs::write(TOKEN_PATH, "Bearer ".to_owned() + &token).await?;
    } else if let Command::CreateAccount(args) = &args.command {
        let mut login_client = LoginClient::new(channel.clone());

        // Create the login request.
        let request = tonic::Request::new(CreateAccountRequest {
            username: args.username.clone(),
            password: args.password.clone(),
        });
        // Get response by calling the server.
        let _response = login_client.create_account(request).await?;
    } else {
        let token: MetadataValue<_> = load_token(TOKEN_PATH).await?.parse()?;

        // Create a client requiring authorization.
        let mut transfer_client =
            TransferClient::with_interceptor(channel.clone(), move |mut req: Request<()>| {
                req.metadata_mut().insert("authorization", token.clone());
                Ok(req)
            });

        match args.command {
            Command::List(args) => {
                // Create a file list request.
                let request = tonic::Request::new(ListFilesRequest { path: args.path });
                // Make a request to the server with request and get response.
                let response = transfer_client.list_files(request).await?;

                // Print result file names.
                for file_name in response.into_inner().names {
                    println!("{}", file_name);
                }
            }
            Command::Get(args) => {
                // Make a request to the server with file name request and get file response.
                let response = transfer_client
                    .get_file(tonic::Request::new(GetFileRequest { name: args.name }))
                    .await?
                    .into_inner();

                let mut file = tokio::fs::File::create("output").await?;
                file.write_all(&response.content).await?;
            }
            _ => unreachable!(),
        }
    }

    Ok(())
}
