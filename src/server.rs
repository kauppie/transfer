mod common;
mod entities;

use std::sync::Arc;

use sea_orm::{ColumnTrait, Database, EntityTrait, IntoActiveModel, QueryFilter};
use tonic::{
    transport::{Identity, Server, ServerTlsConfig},
    Request, Response, Status,
};

use login::{
    login_server::{Login, LoginServer},
    CreateAccountRequest, CreateAccountResponse, LoginRequest, LoginResponse,
};
use transfer::{
    transfer_server::{Transfer, TransferServer},
    GetFileRequest, GetFileResponse, ListFilesRequest, ListFilesResponse,
};

use entities::prelude::Objects as TableObjects;

pub mod transfer {
    // The string specified here must match the proto package name
    tonic::include_proto!("transfer");
}
pub mod login {
    tonic::include_proto!("login");
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
    db_connection: sea_orm::DatabaseConnection,
}

impl MyLogin {
    pub fn new(db_connection: sea_orm::DatabaseConnection) -> Self {
        Self { db_connection }
    }
}

#[tonic::async_trait]
impl Login for MyLogin {
    #[tracing::instrument]
    async fn login(&self, request: Request<LoginRequest>) -> ResponseResult<LoginResponse> {
        tracing::info!("got a login request");
        let request = request.into_inner();
        let credential_error = || Status::unauthenticated("invalid credentials");

        // Query user from database using with username.
        let user = TableObjects::find()
            .filter(entities::users::Column::Username.eq(request.username.clone()))
            .one(&self.db_connection)
            .await
            .map_err(|_| Status::internal("database query failed"))?
            .ok_or_else(credential_error)?;

        // Validate username and password.
        if request.username == user.username && request.password == user.password {
            let claims = common::Claims {
                sub: request.username,
                exp: jsonwebtoken::get_current_timestamp() + 3600, // One hour validity.
            };

            let token = jsonwebtoken::encode(
                &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256),
                &claims,
                &jsonwebtoken::EncodingKey::from_rsa_pem(include_bytes!("../dev/private.pem"))
                    .map_err(|_| Status::internal("private key is invalid"))?,
            )
            .map_err(|_| Status::internal("token encoding failed"))?;

            Ok(Response::new(LoginResponse { token }))
        } else {
            Err(credential_error())
        }
    }

    #[tracing::instrument]
    async fn create_account(
        self: &Self,
        request: Request<CreateAccountRequest>,
    ) -> ResponseResult<CreateAccountResponse> {
        tracing::info!("got a create account request");

        let request = request.into_inner();
        let model = entities::users::Model {
            id: sea_orm::prelude::Uuid::new_v4(), // Fix this to the actual crate, not re-export when 0.9.0 is released.
            username: request.username,
            password: request.password,
        };

        // Model needs to be active to be able to mutate the database via insertion.
        let active_model = model.into_active_model();
        let _res = TableObjects::insert(active_model)
            .exec(&self.db_connection)
            .await
            .map_err(|_| Status::failed_precondition("creating account failed"))?;

        Ok(Response::new(CreateAccountResponse {}))
    }
}

#[derive(Clone)]
struct AuthInterceptor {
    // Avoid cloning large decoding key by using a reference.
    decoding_key: Arc<jsonwebtoken::DecodingKey>,
}

impl AuthInterceptor {
    pub fn new(decoding_key: jsonwebtoken::DecodingKey) -> Self {
        Self {
            decoding_key: Arc::new(decoding_key),
        }
    }
}

impl tonic::service::Interceptor for AuthInterceptor {
    fn call(&mut self, request: tonic::Request<()>) -> Result<tonic::Request<()>, Status> {
        // Get the authorization header. This string should be in format "Bearer <token>".
        let bearer = request
            .metadata()
            .get("authorization")
            .ok_or_else(|| Status::unauthenticated("missing authorization header"))?
            .to_str()
            .map_err(|_| {
                Status::invalid_argument("authorization header is not valid ASCII string")
            })?;

        // Strip the string prefix to get the token.
        let token_str = bearer
            .strip_prefix("Bearer ")
            .ok_or_else(|| Status::invalid_argument("bearer is missing"))?;

        let header = jsonwebtoken::decode_header(token_str)
            .map_err(|_| Status::invalid_argument("token header cannot be parsed"))?;

        // Validation is done using the algorithm reported by the header. Is this safe?
        let validation = jsonwebtoken::Validation::new(header.alg);

        // Validate token. Token claims are not used at least yet.
        let _token_data =
            jsonwebtoken::decode::<common::Claims>(token_str, &self.decoding_key, &validation)
                .map_err(|e| Status::unauthenticated(e.to_string()))?;

        Ok(Request::new(()))
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
    let identity = Identity::from_pem(cert, key);

    let jwt_pub_key = tokio::fs::read("dev/public.pem").await?;
    let decoding_key = jsonwebtoken::DecodingKey::from_rsa_pem(&jwt_pub_key)
        .expect("failed to load public decoding key");

    let db_connection = Database::connect("postgres://root:root@localhost:5432/database").await?;
    let my_login = MyLogin::new(db_connection);
    let login_service = LoginServer::new(my_login);

    let my_transfer = MyTransfer::default();
    let transfer_service =
        TransferServer::with_interceptor(my_transfer, AuthInterceptor::new(decoding_key));

    let addr = "[::1]:50051".parse()?;

    Server::builder()
        .tls_config(ServerTlsConfig::new().identity(identity))?
        .add_service(login_service)
        .add_service(transfer_service)
        .serve(addr)
        .await?;

    Ok(())
}
