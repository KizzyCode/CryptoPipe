pub const KDF_KEY_SIZE: usize = 32;
pub const CIPHER_KEY_SIZE: usize = 32;
pub const MAC_KEY_SIZE: usize = 32;

pub const PBKDF_NONCE_SIZE: usize = 32;
pub const MAC_SIZE: usize = 16;

pub const CHUNK_DATA_SIZE: usize = (1 * 1024 * 1024);

pub const STREAM_HEADER_SIZE: usize = 3 + 1 + 1 + 1 + PBKDF_NONCE_SIZE + 4 + 4 + 4;
pub const STREAM_VERSION: (u8, u8, u8) = (0, 2, 0);

pub const PBKDF_ALGO_ID: u8 = 0;
pub const KDF_ALGO_ID: u8 = 0;
pub const AEAD_ALGO_ID: u8 = 0;