mod common;

use std::path::Path;

use clap::Parser;
use tokio::io::AsyncWriteExt;
use tonic::metadata::MetadataValue;
use tonic::transport::{Certificate, Channel, ClientTlsConfig};
use tonic::Request;

use auth::auth_client::AuthClient;
use auth::{CreateAccountRequest, LoginRequest};
use transfer::transfer_client::TransferClient;
use transfer::{DownloadRequest, UploadRequest};
use user::user_client::UserClient;
use user::ChangePasswordRequest;

pub mod transfer {
    // The string specified here must match the proto package name
    tonic::include_proto!("transfer");
}
pub mod auth {
    tonic::include_proto!("auth");
}
pub mod user {
    tonic::include_proto!("user");
}

#[derive(clap::Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(subcommand)]
    command: Command,
}

#[derive(clap::Subcommand, Debug)]
enum Command {
    /// Upload file to the target server.
    Upload(UploadArgs),
    /// Download file from the target server.
    Download(DownloadArgs),
    /// Login to the target server.
    Login(LoginArgs),
    /// Create account.
    CreateAccount(CreateAccountArgs),
    /// Change password of the account.
    ChangePassword(ChangePasswordArgs),
}

#[derive(clap::Args, Debug)]
struct UploadArgs {
    name: String,
    data: Vec<u8>,
}

#[derive(clap::Args, Debug)]
struct DownloadArgs {
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

#[derive(clap::Args, Debug)]
struct ChangePasswordArgs {
    old_password: String,
    new_password: String,
}

type StdError = Box<dyn std::error::Error + Send + Sync + 'static>;

async fn load_token(path: impl AsRef<Path>) -> Result<String, StdError> {
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
        let mut login_client = AuthClient::new(channel.clone());

        // Create the login request.
        let request = tonic::Request::new(LoginRequest {
            username: args.username.clone(),
            password: args.password.clone(),
        });
        // Get response by calling the server.
        let response = login_client.login(request).await?;

        // Save the token got via response to file.
        let token = response.into_inner().token;
        tokio::fs::write(TOKEN_PATH, format!("Bearer {}", token)).await?;
    } else if let Command::CreateAccount(args) = &args.command {
        let mut login_client = AuthClient::new(channel.clone());

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
        let mut transfer_client = TransferClient::with_interceptor(channel.clone(), {
            let token = token.clone();
            move |mut req: Request<()>| {
                req.metadata_mut().insert("authorization", token.clone());
                Ok(req)
            }
        });

        match args.command {
            Command::Upload(args) => {
                let data = tokio::fs::read(&args.name).await?;

                let request = tonic::Request::new(UploadRequest {
                    name: args.name,
                    data,
                });

                let response = transfer_client.upload(request).await?.into_inner();

                println!("file uuid: {}", response.uuid);
            }
            Command::Download(args) => {
                // Make a request to the server with file name request and get file response.
                let response = transfer_client
                    .download(tonic::Request::new(DownloadRequest {
                        name: args.name.clone(),
                    }))
                    .await?
                    .into_inner();

                let mut file = tokio::fs::File::create(format!("{}.copy", args.name)).await?;
                file.write_all(&response.data).await?;
            }
            Command::ChangePassword(args) => {
                // Create client ad-hoc.
                let mut user_client =
                    UserClient::with_interceptor(channel.clone(), move |mut req: Request<()>| {
                        req.metadata_mut().insert("authorization", token.clone());
                        Ok(req)
                    });

                // Create a change password request.
                let request = tonic::Request::new(ChangePasswordRequest {
                    old_password: args.old_password,
                    new_password: args.new_password,
                });
                // Get response by calling the server.
                let _response = user_client.change_password(request).await?;
            }
            _ => unreachable!(),
        }
    }

    Ok(())
}
