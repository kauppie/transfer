use transfer::transfer_client::TransferClient;
use transfer::FileListRequest;

pub mod transfer {
    tonic::include_proto!("transfer"); // The string specified here must match the proto package name
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = TransferClient::connect("http://[::1]:50051").await?;

    let request = tonic::Request::new(FileListRequest {});

    let response = client.list_files(request).await?;

    for file_name in response.into_inner().names {
        println!("{}", file_name.name);
    }

    Ok(())
}
