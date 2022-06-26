use tonic::{
    transport::{Identity, Server, ServerTlsConfig},
    Request, Response, Status,
};

use transfer::transfer_server::{Transfer, TransferServer};
use transfer::{FileName, FileNames, FileResponse, Path};

pub mod transfer {
    tonic::include_proto!("transfer"); // The string specified here must match the proto package name
}

type ResponseResult<T> = Result<Response<T>, Status>;

#[derive(Debug, Default)]
pub struct MyTransfer {}

#[tonic::async_trait]
impl Transfer for MyTransfer {
    #[tracing::instrument]
    async fn list_files(&self, request: Request<Path>) -> ResponseResult<FileNames> {
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

        let reply = FileNames { names };

        Ok(Response::new(reply))
    }

    #[tracing::instrument]
    async fn get_file(&self, request: Request<FileName>) -> ResponseResult<FileResponse> {
        tracing::info!("got a file download request");

        let file_name = request.into_inner().name;

        let bytes = tokio::fs::read(&file_name)
            .await
            .map_err(|_| Status::failed_precondition("file does not exist"))?;

        let reply = FileResponse {
            name: file_name,
            content: bytes,
        };

        Ok(Response::new(reply))
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

fn main() -> Result<(), StdError> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("couldn't create tokio runtime");

    runtime.block_on(async move {
        setup_tracing();

        let cert = tokio::fs::read("dev/cert.pem").await?;
        let key = tokio::fs::read("dev/cert.key").await?;

        let identity = Identity::from_pem(cert, key);

        let addr = "[::1]:50051".parse()?;
        let greeter = MyTransfer::default();

        Server::builder()
            .tls_config(ServerTlsConfig::new().identity(identity))?
            .add_service(TransferServer::new(greeter))
            .serve(addr)
            .await?;

        Ok(())
    })
}
