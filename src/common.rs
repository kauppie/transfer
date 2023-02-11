use serde::{Deserialize, Serialize};

/// This represents the claims made by the client as
/// part of the JWT token.
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: u64,
}
