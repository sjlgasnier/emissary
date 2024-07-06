#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error: `{0:?}`")]
    IoError(#[from] std::io::Error),

    #[error("Invalid data")]
    InvalidData,

    #[error("Custom error: `{0}`")]
    Custom(String),
}
