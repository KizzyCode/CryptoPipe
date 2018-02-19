use super::super::{ Error, ErrorType };
use super::super::asn1_der;
use super::super::asn1_der::FromDer;
use super::libsodium;

pub trait AuthEnc {
	/// Seals the data using the specified key and returns `Ok(encrypted_data_length)` on success or
	/// an error on error
	fn seal(&self, data_buffer: &mut[u8], data_length: usize, key: libsodium::Key) -> Result<usize, Error>;
	/// Opens some sealed data using the specified key and returns `Ok(encrypted_data_length)` on
	/// success or an error on error
	fn open(&self, data_buffer: &mut[u8], data_length: usize, key: libsodium::Key) -> Result<usize, Error>;
	
	/// Returns the byte-overhead when encrypting (usually the MAC)
	fn overhead(&self) -> usize;
	
	/// Returns a string specifying the algorithm-instance
	fn algorithm(&self) -> &'static str;
	
	/// Serializes the algorithm-instance
	fn serialize(&self) -> asn1_der::DerObject {
		let sequence: Vec<asn1_der::DerObject> = vec![self.algorithm().to_string().into()];
		sequence.into()
	}
}

pub fn from_serialized(serialized: asn1_der::DerObject) -> Result<Box<AuthEnc>, Error> {
	// Try to parse info
	let info: Vec<asn1_der::DerObject> = try_err!(Vec::<asn1_der::DerObject>::from_der(serialized));
	if info.len() < 1 { throw_err!(ErrorType::InvalidData) }
	
	// Parse and select algorithm
	match (try_err!(String::from_der(info[0].clone())) as String).as_str() {
		CHACHA20_POLY1305_ID => Ok(ChaCha20Poly1305::new()),
		_ => throw_err!(ErrorType::Unsupported)
	}
}



pub const CHACHA20_POLY1305_ID: &str = "ChaCha20+Poly1305@de.KizzyCode.CryptoPipe.v1";
/// A ChaCha20-Poly1305 authenticated-encryption-scheme
///
/// This scheme works like this:
///  1. Initialize a ChaCha20-keystream with the given key and nonce (note that we use a 64-bit
///     nonce and not the IETF-96-bit nonce)
///  2. Compute 64-keystream bytes (beginning by keystream-byte-offset 0) and use the first 32-bytes
///     as Poly1305-key
///  3. Encrypt the data with the next ChaCha20-keystream-bytes (beginning by keystream-byte-offset
///     64)
///  4. Compute the Poly1305-MAC (using the key from step 2) over the encrypted data and append it
///     to the encrypted data
pub struct ChaCha20Poly1305;
impl ChaCha20Poly1305 {
	pub fn new() -> Box<Self> {
		Box::new(ChaCha20Poly1305)
	}
}
impl ChaCha20Poly1305 {
	/// Validates `key` and `nonce` and computes the Poly1305-one-time-key
	///
	/// Returns either `Ok((chacha20_key, chacha20_nonce, poly1305_key))` or an error if a parameter
	/// is invalid
	fn prepare(&self, key: libsodium::Key) -> Result<(libsodium::Key, libsodium::Key), Error> {
		// Validate input
		if key.len() != 32 { throw_err!(ErrorType::InvalidParameter) }
		
		// Compute Poly1305-key
		let mut poly1305_key = libsodium::Key::new(32);
		for byte in poly1305_key.as_mut_slice().iter_mut() { *byte = 0x00 }
		libsodium::chacha20_xor(poly1305_key.as_mut_slice(), 0, &key, &[0u8; 8])?;
		
		Ok((key, poly1305_key))
	}
}
impl AuthEnc for ChaCha20Poly1305 {
	fn seal(&self, data_buffer: &mut[u8], data_length: usize, key: libsodium::Key) -> Result<usize, Error> {
		// Validate and get keys and nonce
		let (chacha20_key, poly1305_key) = self.prepare(key)?;
		
		// Validate buffer-size
		if data_length > data_buffer.len() || data_buffer.len() - data_length < 16 { throw_err!(ErrorType::InvalidParameter) }
		
		// Encrypt data
		libsodium::chacha20_xor(&mut data_buffer[.. data_length], 64, &chacha20_key, &[0u8; 8])?;
		
		// Compute and copy MAC
		let mut mac = [0u8; 16];
		libsodium::poly1305(&mut mac, &data_buffer[.. data_length], &poly1305_key)?;
		data_buffer[data_length .. data_length + 16].copy_from_slice(&mac);
		
		Ok(data_length + 16)
	}
	
	fn open(&self, data_buffer: &mut[u8], data_length: usize, key: libsodium::Key) -> Result<usize, Error> {
		// Validate and get keys and nonce
		let (chacha20_key, poly1305_key) = self.prepare(key)?;
		
		// Validate if the data is large enough to contain at least a MAC
		if data_length > data_buffer.len() { throw_err!(ErrorType::InvalidParameter) }
		if data_length < 16 { throw_err!(ErrorType::InvalidData, "Invalid authentication-tag".to_string()) }
		
		// Validate MAC
		let mut mac = [0u8; 16];
		libsodium::poly1305(&mut mac, &data_buffer[.. data_length - 16], &poly1305_key)?;
		if !libsodium::compare_constant_time(&mac, &data_buffer[data_length - 16 .. data_length]) { throw_err!(ErrorType::InvalidData, "Invalid authentication-tag".to_string()) }
		
		// Decrypt data
		libsodium::chacha20_xor(&mut data_buffer[.. data_length - 16], 64, &chacha20_key, &[0u8; 8])?;
		Ok(data_length - 16)
	}
	
	fn overhead(&self) -> usize {
		16
	}
	
	fn algorithm(&self) -> &'static str {
		CHACHA20_POLY1305_ID
	}
}