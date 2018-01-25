use super::error::{ Error, ErrorType };
use super::libsodium;

pub const PBKDF_NONCE_SIZE: usize = 32;
pub const PBKDF_INFO_SIZE: usize = PBKDF_NONCE_SIZE + 4 + 4 + 4;

#[derive(Default, Debug, Clone)]
pub struct PbkdfInfo {
	pub nonce: [u8; PBKDF_NONCE_SIZE],
	pub iterations: u32,
	pub memory_requirements: u32,
	pub parallelism: u32,
}
impl PbkdfInfo {
	pub fn new(iterations: u32, memory_requirements: u32, parallelism: u32) -> Self {
		// Create random nonce
		let mut nonce = [0u8; PBKDF_NONCE_SIZE];
		libsodium::random(&mut nonce);
		
		PbkdfInfo{ nonce, iterations, memory_requirements, parallelism }
	}
	
	pub fn parse(data: &[u8]) -> Result<Self, Error> {
		// Validate input
		if data.len() < PBKDF_INFO_SIZE { throw_err!(ErrorType::InvalidParameter) }
		
		let mut pbkdf_info = PbkdfInfo::default();
		pbkdf_info.nonce.copy_from_slice(&data[.. PBKDF_NONCE_SIZE]);
		pbkdf_info.iterations = PbkdfInfo::read_u32_be(&data[PBKDF_NONCE_SIZE ..]);
		pbkdf_info.memory_requirements = PbkdfInfo::read_u32_be(&data[PBKDF_NONCE_SIZE + 4 ..]);
		pbkdf_info.parallelism = PbkdfInfo::read_u32_be(&data[PBKDF_NONCE_SIZE + 4 + 4 ..]);
		Ok(pbkdf_info)
	}
	
	pub fn serialize(&self, buffer: &mut[u8]) -> Result<(), Error> {
		// Validate input
		if buffer.len() < PBKDF_INFO_SIZE { throw_err!(ErrorType::InvalidParameter) }
		
		buffer[.. PBKDF_NONCE_SIZE].copy_from_slice(&self.nonce);
		PbkdfInfo::write_u32_be(&mut buffer[PBKDF_NONCE_SIZE ..], self.iterations);
		PbkdfInfo::write_u32_be(&mut buffer[PBKDF_NONCE_SIZE + 4 ..], self.memory_requirements);
		PbkdfInfo::write_u32_be(&mut buffer[PBKDF_NONCE_SIZE + 4 + 4 ..], self.parallelism);
		Ok(())
	}
	
	fn read_u32_be(bytes: &[u8]) -> u32 {
		bytes[0 .. 4].iter().fold(0u32, |num, byte| (num << 8) | *byte as u32)
	}
	
	fn write_u32_be(buffer: &mut[u8], mut num: u32) {
		for i in (0..4).rev() { buffer[i] = num as u8; num >>= 8; }
	}
}



pub struct Kdf {
	key: libsodium::Key,
	state: u64
}
impl Kdf {
	pub fn new(key: libsodium::Key) -> Self {
		Kdf{ key, state: 0 }
	}
	
	pub fn next(&mut self, cipher_key: &mut libsodium::Key, mac_key: &mut libsodium::Key, end_of_stream: bool) -> Result<(), Error> {
		// Set end-of-stream-counter
		if end_of_stream { self.state = self.state.checked_add(0x8000000000000000).unwrap() }
		
		// Compute key-bytes
		let mut keys = libsodium::Key::new(cipher_key.len() + mac_key.len());
		libsodium::chacha20_xor(keys.as_mut_slice(), self.state, &self.key, &[0u8; 8])?;
		
		// Increment state or release key
		if end_of_stream { self.key = libsodium::Key::new(0) }
			else { self.state += keys.len() as u64 }
		
		// Copy key-bytes
		let (cipher_key_range, mac_key_range) = (.. cipher_key.len(), cipher_key.len() ..);
		cipher_key.as_mut_slice().copy_from_slice(&keys.as_slice()[cipher_key_range]);
		mac_key.as_mut_slice().copy_from_slice(&keys.as_slice()[mac_key_range]);
		
		Ok(())
	}
}
impl Default for Kdf {
	fn default() -> Self {
		Kdf{ key: libsodium::Key::new(0), state: 0 }
	}
}