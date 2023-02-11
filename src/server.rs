mod common;
mod tables;

use std::{path::Path, sync::Arc, time::Duration};

use jsonwebtoken as jwt;

use pbkdf2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Pbkdf2,
};
use rand_core::OsRng;
use sea_orm::{
    ActiveModelTrait, ActiveValue, ColumnTrait, ConnectOptions, Database, EntityTrait,
    IntoActiveModel, QueryFilter,
};
use tonic::{
    transport::{Identity, Server, ServerTlsConfig},
    Request, Response, Status,
};

use auth::{
    auth_server::{Auth, AuthServer},
    CreateAccountRequest, CreateAccountResponse, LoginRequest, LoginResponse,
};
use transfer::{
    transfer_server::{Transfer, TransferServer},
    DownloadRequest, DownloadResponse, UploadRequest, UploadResponse,
};
use user::{
    user_server::{User, UserServer},
    ChangePasswordRequest, ChangePasswordResponse,
};

use tables::prelude::Things as TableThings;
use tables::prelude::Users as TableUsers;

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

type ResponseResult<T> = Result<Response<T>, Status>;
type StdError = Box<dyn std::error::Error + Send + Sync + 'static>;

#[derive(Debug)]
pub struct MyTransfer {
    db_connection: sea_orm::DatabaseConnection,
}

impl MyTransfer {
    pub fn new(db_connection: sea_orm::DatabaseConnection) -> Self {
        Self { db_connection }
    }
}

#[tonic::async_trait]
impl Transfer for MyTransfer {
    #[tracing::instrument(skip(self, request))]
    async fn upload(&self, request: Request<UploadRequest>) -> ResponseResult<UploadResponse> {
        tracing::info!("upload request");

        let request = request.into_inner();

        let uuid = uuid::Uuid::new_v4();
        let version = 1;
        let uuid_ver = format!("{uuid}.{version}");

        let active_model = tables::things::ActiveModel {
            uuid_ver: ActiveValue::set(uuid_ver),
            uuid: ActiveValue::set(uuid.clone()),
            name: ActiveValue::set(request.name),
            version: ActiveValue::set(version),
            data: ActiveValue::set(request.data),
        };

        active_model
            .insert(&self.db_connection)
            .await
            .map_err(|_| Status::internal("failed to insert"))?;

        Ok(Response::new(UploadResponse {
            uuid: uuid.to_string(),
        }))
    }

    #[tracing::instrument(skip(self, request))]
    async fn download(
        &self,
        request: Request<DownloadRequest>,
    ) -> ResponseResult<DownloadResponse> {
        tracing::info!("download request");

        let request = request.into_inner();

        let user = TableThings::find()
            .filter(tables::things::Column::Name.eq(request.name))
            .one(&self.db_connection)
            .await
            .map_err(|_| Status::internal("database query failed"))?
            .ok_or_else(|| Status::failed_precondition("not found"))?;

        Ok(Response::new(DownloadResponse { data: user.data }))
    }
}

fn verify_password(password: &str, password_salted_hashed: &str) -> bool {
    let password_hash = PasswordHash::new(password_salted_hashed);
    password_hash
        .and_then(|password_hash| Pbkdf2.verify_password(password.as_bytes(), &password_hash))
        .is_ok()
}

pub struct MyLogin {
    db_connection: sea_orm::DatabaseConnection,
    priv_key: jwt::EncodingKey,
}

impl MyLogin {
    // Authenticated token expires in 1 hour.
    const AUTH_PERIOD_SECS: u64 = 60 * 60;

    pub async fn new(
        db_connection: sea_orm::DatabaseConnection,
        priv_key_path: impl AsRef<Path>,
    ) -> Result<Self, StdError> {
        let key_bytes = tokio::fs::read(priv_key_path).await?;
        let priv_key =
            jwt::EncodingKey::from_rsa_pem(&key_bytes).map_err(|_| "invalid key".to_owned())?;

        Ok(Self {
            db_connection,
            priv_key,
        })
    }
}

impl std::fmt::Debug for MyLogin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MyLogin")
            .field("db_connection", &self.db_connection)
            .finish_non_exhaustive()
    }
}

#[tonic::async_trait]
impl Auth for MyLogin {
    #[tracing::instrument]
    async fn login(&self, request: Request<LoginRequest>) -> ResponseResult<LoginResponse> {
        tracing::info!("got a login request");
        let request = request.into_inner();
        let credential_error = || Status::unauthenticated("invalid credentials");

        // Query user from database using their username.
        let user = TableUsers::find()
            .filter(tables::users::Column::Username.eq(request.username.clone()))
            .one(&self.db_connection)
            .await
            .map_err(|_| Status::internal("database query failed"))?
            .ok_or_else(credential_error)?;

        // Verify password.
        let valid_password =
            verify_password(request.password.as_str(), &user.password_salted_hashed);

        // Validate password.
        if valid_password {
            let claims = common::Claims {
                sub: request.username,
                exp: jwt::get_current_timestamp() + MyLogin::AUTH_PERIOD_SECS,
            };

            let token = jwt::encode(
                &jwt::Header::new(jwt::Algorithm::RS256),
                &claims,
                &self.priv_key,
            )
            .map_err(|_| Status::internal("token encoding failed"))?;

            Ok(Response::new(LoginResponse { token }))
        } else {
            Err(credential_error())
        }
    }

    #[tracing::instrument]
    async fn create_account(
        &self,
        request: Request<CreateAccountRequest>,
    ) -> ResponseResult<CreateAccountResponse> {
        tracing::info!("got a create account request");
        let request = request.into_inner();

        // Generate random salt for password hashing.
        let salt = SaltString::generate(&mut OsRng);
        // Use default hashing strategy and salt to generate password hash.
        let password_salted_hashed = Pbkdf2
            .hash_password(request.password.as_bytes(), &salt)
            .map_err(|_| Status::internal("creating account failed"))?
            .to_string();

        // Create the user model to be stored.
        let model = tables::users::Model {
            id: uuid::Uuid::new_v4(),
            username: request.username,
            password_salted_hashed,
        };

        // Model needs to be active to be able to mutate the database via insertion.
        let active_model = model.into_active_model();
        // Execute the insertion.
        let _res = TableUsers::insert(active_model)
            .exec(&self.db_connection)
            .await
            .map_err(|e| Status::failed_precondition(format!("creating account failed: {e}")))?;

        Ok(Response::new(CreateAccountResponse {}))
    }
}

pub struct MyUser {
    db_connection: sea_orm::DatabaseConnection,
    // Avoid cloning large decoding key by using a reference.
    decoding_key: Arc<jwt::DecodingKey>,
}

impl MyUser {
    pub fn new(
        db_connection: sea_orm::DatabaseConnection,
        decoding_key: Arc<jwt::DecodingKey>,
    ) -> Self {
        Self {
            db_connection,
            decoding_key,
        }
    }
}

#[tonic::async_trait]
impl User for MyUser {
    #[tracing::instrument(skip(self, request))]
    async fn change_password(
        &self,
        request: Request<ChangePasswordRequest>,
    ) -> ResponseResult<ChangePasswordResponse> {
        tracing::info!("got a change password request");

        let token_data = get_request_token_claims(&request, &self.decoding_key)?;
        let username = token_data.claims.sub;

        // Query user from database using their username.
        let user = TableUsers::find()
            .filter(tables::users::Column::Username.eq(username.clone()))
            .one(&self.db_connection)
            .await
            .map_err(|_| Status::internal("database query failed"))?
            .ok_or_else(|| Status::unauthenticated("invalid credentials"))?;

        let request = request.into_inner();
        // Verify the old password with the stored hash.
        if verify_password(&request.old_password, &user.password_salted_hashed) {
            // Password is valid. Generate new salt and hash the new password.

            // Generate random salt for password hashing.
            let salt = SaltString::generate(&mut OsRng);
            // Use default hashing strategy and salt to generate password hash.
            let password_salted_hashed = Pbkdf2
                .hash_password(request.new_password.as_bytes(), &salt)
                .map_err(|_| Status::internal("changing password failed"))?
                .to_string();

            // Create active model where the password is updated.
            let active_model = tables::users::ActiveModel {
                id: ActiveValue::unchanged(user.id),
                username: ActiveValue::unchanged(user.username),
                password_salted_hashed: ActiveValue::set(password_salted_hashed),
            };

            // Execute database update.
            active_model
                .update(&self.db_connection)
                .await
                .map_err(|e| Status::internal(format!("changing password failed: {e}")))?;

            Ok(Response::new(ChangePasswordResponse {}))
        } else {
            // Given old password is invalid.
            Err(Status::unauthenticated("invalid credentials"))
        }
    }
}

#[derive(Clone)]
struct AuthInterceptor {
    // Avoid cloning large decoding key by using a reference.
    decoding_key: Arc<jwt::DecodingKey>,
}

impl AuthInterceptor {
    pub fn new(decoding_key: Arc<jwt::DecodingKey>) -> Self {
        Self { decoding_key }
    }
}

impl tonic::service::Interceptor for AuthInterceptor {
    fn call(&mut self, request: tonic::Request<()>) -> Result<tonic::Request<()>, Status> {
        // Validate token.
        validate_request_token(&request, &self.decoding_key)?;
        // Forward request to the service with the original header, etc.
        Ok(request)
    }
}

fn validate_request_token<T>(
    request: &Request<T>,
    decoding_key: &jwt::DecodingKey,
) -> Result<(), Status> {
    // Get token data from request. This fails if the token is invalid.
    let _token_data = get_request_token_claims(request, decoding_key)?;
    Ok(())
}

fn get_request_token_claims<T>(
    request: &tonic::Request<T>,
    decoding_key: &jwt::DecodingKey,
) -> Result<jwt::TokenData<common::Claims>, Status> {
    // Get the authorization header. This string should be in format "Bearer <token>".
    let bearer = request
        .metadata()
        .get("authorization")
        .ok_or_else(|| Status::unauthenticated("missing authorization header"))?
        .to_str()
        .map_err(|_| Status::invalid_argument("authorization header is not valid ASCII string"))?;

    // Strip the string prefix to get the token.
    let token_str = bearer
        .strip_prefix("Bearer ")
        .ok_or_else(|| Status::invalid_argument("bearer is missing"))?;

    let header = jwt::decode_header(token_str)
        .map_err(|_| Status::invalid_argument("token header cannot be parsed"))?;

    // Validation is done using the algorithm reported by the header. Is this safe?
    let validation = jwt::Validation::new(header.alg);

    // Validate token. Token claims are not used at least yet.
    let token_data = jwt::decode::<common::Claims>(token_str, &decoding_key, &validation)
        .map_err(|e| Status::unauthenticated(e.to_string()))?;

    Ok(token_data)
}

fn setup_tracing() -> Result<(), StdError> {
    let subscriber = tracing_subscriber::FmtSubscriber::builder()
        .with_max_level(tracing::Level::INFO)
        .with_file(true)
        .with_line_number(true)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    Ok(())
}

/// Creates a new database connection with shorter than default timeout. Timeout is set to 10 seconds.
async fn connect_to_database(
    url: impl Into<String>,
) -> Result<sea_orm::DatabaseConnection, sea_orm::DbErr> {
    let mut opt = ConnectOptions::new(url.into());
    opt.connect_timeout(Duration::from_secs(10));

    Database::connect(opt).await
}

#[tokio::main]
#[tracing::instrument]
async fn main() -> Result<(), StdError> {
    setup_tracing()?;

    let cert = tokio::fs::read("dev/cert.pem").await?;
    let key = tokio::fs::read("dev/cert.key").await?;
    let identity = Identity::from_pem(cert, key);

    let jwt_pub_key = tokio::fs::read("dev/public.pem").await?;
    let decoding_key = Arc::new(
        jwt::DecodingKey::from_rsa_pem(&jwt_pub_key).expect("failed to load public decoding key"),
    );

    // Create database connection.
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let db_connection = connect_to_database(database_url).await?;

    // Create login service.
    let my_login = MyLogin::new(db_connection.clone(), "dev/private.pem").await?;
    let login_service = AuthServer::new(my_login);

    // Create transfer service. This service has authentication middleware.
    let my_transfer = MyTransfer::new(db_connection.clone());
    let transfer_service = TransferServer::with_interceptor(
        my_transfer,
        AuthInterceptor::new(Arc::clone(&decoding_key)),
    );

    // Create user service. This service has authentication middleware.
    let my_user = MyUser::new(db_connection, Arc::clone(&decoding_key));
    let user_service = UserServer::with_interceptor(my_user, AuthInterceptor::new(decoding_key));

    // Create service address.
    let addr = "[::1]:50051".parse().expect("failed to parse address");

    // Create and start server.
    Server::builder()
        .tls_config(ServerTlsConfig::new().identity(identity))?
        .add_service(login_service)
        .add_service(transfer_service)
        .add_service(user_service)
        .serve(addr)
        .await?;

    Ok(())
}
