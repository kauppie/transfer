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

        let reply = FileNames {
            names: vec![FileName {
                name: "my file name".to_string(),
            }],
        };

        Ok(Response::new(reply)) // Send back our formatted greeting
    }

    async fn get_file(&self, request: Request<FileName>) -> Result<Response<FileResponse>, Status> {
        println!("Got a file download request: {:?}", request);

        let reply = FileResponse {
            name: Some(FileName {
                name: "my file".to_string(),
            }),
            content: vec![],
        };

        Ok(Response::new(reply)) // Send back our formatted greeting
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