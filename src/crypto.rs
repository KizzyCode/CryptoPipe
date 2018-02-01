use super::error::{ Error, ErrorType };
use super::libsodium;
use super::constants;

pub struct Pbkdf;
impl Pbkdf {
	pub fn compute(algo_id: u8, mut password: String, pbkdf_nonce: &[u8], pbkdf_iterations: u32, pbkdf_memory_requirements: u32, pbkdf_parallelism: u32) -> Result<libsodium::Key, Error> {
		// Validate algorithm
		if algo_id != constants::PBKDF_ALGO_ID { throw_err!(ErrorType::Unsupported, "Unsupported PBKDF-algorithm".to_owned()) }
		if pbkdf_nonce.len() != constants::PBKDF_NONCE_SIZE { throw_err!(ErrorType::InvalidParameter) }
		
		// Compute master-key
		let mut key = libsodium::Key::new(constants::KDF_KEY_SIZE);
		libsodium::argon2i_v13(&mut key, &password, pbkdf_nonce, pbkdf_iterations, pbkdf_memory_requirements, pbkdf_parallelism)?;
		libsodium::erase(unsafe{ password.as_bytes_mut() });
		
		Ok(key)
	}
}



pub struct Kdf {
	key: Option<libsodium::Key>,
	state: u64
}
impl Kdf {
	pub fn new(algo_id: u8, master_key: libsodium::Key) -> Result<Self, Error> {
		// Validate algorithms
		if algo_id != constants::KDF_ALGO_ID { throw_err!(ErrorType::Unsupported, "Unsupported KDF-algorithm".to_owned()) }
		
		// Validate key-length
		if master_key.len() != constants::KDF_KEY_SIZE { throw_err!(ErrorType::InvalidParameter) }
		
		Ok(Kdf{ key: Some(master_key), state: 0 })
	}
	
	pub fn next(&mut self, cipher_key: &mut libsodium::Key, mac_key: &mut libsodium::Key, end_of_stream: bool) -> Result<(), Error> {
		// Set end-of-stream-counter
		if end_of_stream { self.state = self.state.checked_add(0x8000000000000000).unwrap() }
		
		// Compute key-bytes
		let mut keys = libsodium::Key::new(cipher_key.len() + mac_key.len());
		libsodium::chacha20_xor(keys.as_mut_slice(), self.state, self.key.as_ref().expect("KDF used after end-of-stream"), &[0u8; 8])?;
		
		// Increment state or release key
		if end_of_stream { self.key = None }
			else { self.state += keys.len() as u64 }
		
		// Copy key-bytes
		let (cipher_key_range, mac_key_range) = (.. cipher_key.len(), cipher_key.len() ..);
		cipher_key.as_mut_slice().copy_from_slice(&keys.as_slice()[cipher_key_range]);
		mac_key.as_mut_slice().copy_from_slice(&keys.as_slice()[mac_key_range]);
		
		Ok(())
	}
}



pub struct Aead {
	kdf: Kdf
}
impl Aead {
	pub fn new(algo_id: u8, kdf: Kdf) -> Result<Self, Error> {
		// Validate algorithm
		if algo_id != constants::AEAD_ALGO_ID { throw_err!(ErrorType::Unsupported, "Unsupported AEAD-algorithm".to_owned()) }
		
		Ok(Aead{ kdf })
	}
	
	pub fn encrypt_chunk<'a>(&mut self, chunk_buffer: &'a mut[u8], chunk_len: usize, is_last: bool) -> Result<&'a[u8], Error> {
		// Validate input
		if chunk_buffer.len() - chunk_len < constants::MAC_SIZE { throw_err!(ErrorType::InvalidParameter) }
		
		// Generate keys
		let (mut cipher_key, mut mac_key) = (libsodium::Key::new(constants::CIPHER_KEY_SIZE), libsodium::Key::new(constants::MAC_KEY_SIZE));
		self.kdf.next(&mut cipher_key, &mut mac_key, is_last)?;
		
		// Compute chunk-ranges: `chunk_data || chunk_mac`
		let chunk_data_range = 0 .. chunk_len;
		let chunk_mac_range = chunk_data_range.end .. chunk_data_range.end + constants::MAC_SIZE;
		
		// Encrypt chunk
		libsodium::chacha20_xor(&mut chunk_buffer[chunk_data_range.start .. chunk_data_range.end], 0, &cipher_key, &[0u8; 8])?;
		
		// Compute MAC
		let mut mac = [0u8; constants::MAC_SIZE];
		libsodium::poly1305(&mut mac, &chunk_buffer[chunk_data_range.start .. chunk_data_range.end], &mac_key)?;
		chunk_buffer[chunk_mac_range.start .. chunk_mac_range.end].copy_from_slice(&mac);
		
		// Finalize
		Ok(&chunk_buffer[chunk_data_range.start .. chunk_mac_range.end])
	}
	
	pub fn decrypt_chunk<'a>(&mut self, chunk_buffer: &'a mut[u8], chunk_len: usize, is_last: bool) -> Result<&'a[u8], Error> {
		// Validate data
		if chunk_len < constants::MAC_SIZE { throw_err!(ErrorType::InvalidData, "Unexpected end-of-stream".to_owned()) }
		
		// Generate keys
		let (mut cipher_key, mut mac_key) = (libsodium::Key::new(constants::CIPHER_KEY_SIZE), libsodium::Key::new(constants::MAC_KEY_SIZE));
		self.kdf.next(&mut cipher_key, &mut mac_key, is_last)?;
		
		// Compute chunk-ranges: `chunk_data || chunk_mac`
		let chunk_data_range = 0 .. chunk_len - constants::MAC_SIZE;
		let chunk_mac_range = chunk_data_range.end .. chunk_data_range.end + constants::MAC_SIZE;
		
		// Compute and validate MAC
		let mut mac = [0u8; constants::MAC_SIZE];
		libsodium::poly1305(&mut mac, &chunk_buffer[chunk_data_range.start .. chunk_data_range.end], &mac_key)?;
		if !libsodium::compare_constant_time(&mac, &chunk_buffer[chunk_mac_range.start .. chunk_mac_range.end]) { throw_err!(ErrorType::InvalidData, "Invalid MAC/unexpected end-of-stream".to_owned()) }
		
		// Decrypt chunk and finalize
		libsodium::chacha20_xor(&mut chunk_buffer[chunk_data_range.start .. chunk_data_range.end], 0, &cipher_key, &[0u8; 8])?;
		
		Ok(&chunk_buffer[chunk_data_range.start .. chunk_data_range.end])
	}
}