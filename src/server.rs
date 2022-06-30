mod common;

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use tonic::{
    transport::{Identity, Server, ServerTlsConfig},
    Request, Response, Status,
};

use transfer::{
    login_server::{Login, LoginServer},
    transfer_server::{Transfer, TransferServer},
    GetFileRequest, GetFileResponse, ListFilesRequest, LoginRequest, LoginResponse,
};

use crate::transfer::ListFilesResponse;

pub mod transfer {
    tonic::include_proto!("transfer"); // The string specified here must match the proto package name
}

type ResponseResult<T> = Result<Response<T>, Status>;

#[derive(Debug, Default)]
pub struct MyTransfer {}

impl MyTransfer {
    pub fn new() -> Self {
        Self {}
    }
}

#[tonic::async_trait]
impl Transfer for MyTransfer {
    #[tracing::instrument]
    async fn list_files(
        &self,
        request: Request<ListFilesRequest>,
    ) -> ResponseResult<ListFilesResponse> {
        tracing::info!("got a file listing request");

        let mut names = Vec::new();

        let mut entries = tokio::fs::read_dir(&request.into_inner().path).await?;
        while let Some(entry) = entries.next_entry().await? {
            names.push(
                entry
                    .file_name()
                    .into_string()
                    .map_err(|_| Status::internal("list item conversion failed"))?,
            );
        }

        let reply = ListFilesResponse { names };

        Ok(Response::new(reply))
    }

    #[tracing::instrument]
    async fn get_file(&self, request: Request<GetFileRequest>) -> ResponseResult<GetFileResponse> {
        tracing::info!("got a file download request");

        let file_name = request.into_inner().name;

        let bytes = tokio::fs::read(&file_name)
            .await
            .map_err(|_| Status::failed_precondition("file does not exist"))?;

        let reply = GetFileResponse {
            name: file_name,
            content: bytes,
        };

        Ok(Response::new(reply))
    }
}

#[derive(Debug, Default)]
pub struct MyLogin {
    logins: Arc<Mutex<HashMap<String, String>>>,
}

impl MyLogin {
    const NAME: &'static str = "hello";
    const PASSWORD: &'static str = "world";

    pub fn new(logins: Arc<Mutex<HashMap<String, String>>>) -> Self {
        Self { logins }
    }
}

#[tonic::async_trait]
impl Login for MyLogin {
    #[tracing::instrument]
    async fn login(&self, request: Request<LoginRequest>) -> ResponseResult<LoginResponse> {
        tracing::info!("got a login request");

        let request = request.into_inner();
        if request.username == Self::NAME && request.password == Self::PASSWORD {
            let claims = common::Claims {
                sub: request.username.clone(),
                exp: jsonwebtoken::get_current_timestamp() + 3600, // One hour validity.
            };

            let token = jsonwebtoken::encode(
                &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256),
                &claims,
                &jsonwebtoken::EncodingKey::from_rsa_pem(include_bytes!("../dev/private.pem"))
                    .map_err(|_| Status::internal("private key is invalid"))?,
            )
            .map_err(|_| Status::internal("token encoding failed"))?;

            // Add username and corresponding token.
            self.logins
                .lock()
                .unwrap()
                .insert(token.clone(), request.username);

            Ok(Response::new(LoginResponse { token }))
        } else {
            Err(Status::permission_denied("invalid credentials"))
        }
    }
}

type StdError = Box<dyn std::error::Error + Send + Sync + 'static>;

fn setup_tracing() {
    let subscriber = tracing_subscriber::FmtSubscriber::builder()
        .with_max_level(tracing::Level::INFO)
        .with_file(true)
        .with_line_number(true)
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .expect("failed to set global tracing subscriber");
}

#[tokio::main]
#[tracing::instrument]
async fn main() -> Result<(), StdError> {
    setup_tracing();

    let cert = tokio::fs::read("dev/cert.pem").await?;
    let key = tokio::fs::read("dev/cert.key").await?;
    let identity = Identity::from_pem(&cert, &key);

    let jwt_pub_key = tokio::fs::read("dev/public.pem").await?;
    let decoding_key = jsonwebtoken::DecodingKey::from_rsa_pem(&jwt_pub_key)
        .map_err(|_| Status::internal("decoding error"))?;

    lazy_static::lazy_static! {
        static ref BEAR_REGEX: regex::Regex = regex::Regex::new(r"Bearer (?P<bearer>.*)").unwrap();
    }

    let addr = "[::1]:50051".parse()?;

    // Map to store username and password combos. Just for testing.
    let pass_storage = Arc::new(Mutex::new(HashMap::<String, String>::new()));

    let my_login = MyLogin::new(pass_storage.clone());
    let login_service = LoginServer::new(my_login);

    let my_transfer = MyTransfer::default();
    let transfer_service = TransferServer::with_interceptor(my_transfer, move |req: Request<()>| {
        let bearer = req
            .metadata()
            .get("authorization")
            .unwrap()
            .to_str()
            .unwrap();

        let token_str = &BEAR_REGEX.captures_iter(bearer).next().unwrap()["bearer"];
        tracing::info!("{}", token_str);

        let header = jsonwebtoken::decode_header(&token_str);
        tracing::info!("{:?}", header);

        let _token_data = jsonwebtoken::decode::<common::Claims>(
            token_str,
            &decoding_key,
            &jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256),
        )
        .map_err(|e| Status::permission_denied(format!("{}", e)))?;

        Ok(Request::new(()))
    });

    Server::builder()
        .tls_config(ServerTlsConfig::new().identity(identity))?
        .add_service(login_service)
        .add_service(transfer_service)
        .serve(addr)
        .await?;

    Ok(())
}
