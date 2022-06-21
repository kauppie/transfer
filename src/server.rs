use tonic::{transport::Server, Request, Response, Status};

use transfer::transfer_server::{Transfer, TransferServer};
use transfer::{FileListRequest, FileName, FileNames, FileResponse};

pub mod transfer {
    tonic::include_proto!("transfer"); // The string specified here must match the proto package name
}

#[derive(Debug, Default)]
pub struct MyTransfer {}

#[tonic::async_trait]
impl Transfer for MyTransfer {
    async fn list_files(
        &self,
        request: Request<FileListRequest>,
    ) -> Result<Response<FileNames>, Status> {
        println!("Got a file listing request: {:?}", request);

        let mut names = Vec::new();

        let mut entries = tokio::fs::read_dir(".").await?;
        while let Some(entry) = entries.next_entry().await? {
            names.push(format!(
                "{}",
                entry
                    .file_name()
                    .into_string()
                    .map_err(|_| Status::internal("list item conversion failed"))?
            ));
        }

        let reply = FileNames { names };

        Ok(Response::new(reply))
    }

    async fn get_file(&self, request: Request<FileName>) -> Result<Response<FileResponse>, Status> {
        println!("Got a file download request: {:?}", request);

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

#[tokio::main]
async fn main() -> Result<(), StdError> {
    let addr = "[::1]:50051".parse()?;
    let greeter = MyTransfer::default();

    Server::builder()
        .add_service(TransferServer::new(greeter))
        .serve(addr)
        .await?;

    Ok(())
}
