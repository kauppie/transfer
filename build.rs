fn main() -> Result<(), Box<dyn std::error::Error>> {
    // TODO: configure to automatically include all proto files.
    tonic_build::configure().compile(&["proto/transfer.proto", "proto/login.proto"], &["proto"])?;
    Ok(())
}
