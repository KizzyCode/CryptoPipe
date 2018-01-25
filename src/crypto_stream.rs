use super::error::{ Error, ErrorType };
use super::io::IO;
use super::libsodium;
use super::kdf::{ PBKDF_INFO_SIZE, PbkdfInfo, Kdf };

const KEY_SIZE: usize = 32;
pub const MAC_SIZE: usize = 16;

pub const CHUNK_DATA_SIZE: usize = (1 * 1024 * 1024);

pub struct Encryptor<'a> {
	io: &'a mut IO,
	buffer: Vec<u8>,
	kdf: Kdf
}
impl<'a> Encryptor<'a> {
	pub fn new(io: &'a mut IO) -> Self {
		Encryptor{ io, buffer: vec![0u8; CHUNK_DATA_SIZE + MAC_SIZE], kdf: Kdf::default() }
	}
	
	pub fn runloop(&mut self, mut password: String, pbkdf_info: PbkdfInfo) -> Result<(), Error> {
		// Init KDF and erase password
		self.kdf = {
			let mut kdf_key = libsodium::Key::new(KEY_SIZE);
			libsodium::argon2i_v13(&mut kdf_key, &password, &pbkdf_info.nonce, pbkdf_info.iterations, pbkdf_info.memory_requirements, pbkdf_info.parallelism)?;
			libsodium::erase(unsafe{ password.as_bytes_mut() });
			Kdf::new(kdf_key)
		};
		
		// Write PBKDF-info
		{
			let mut pbkdf_info_serialized = [0u8; PBKDF_INFO_SIZE];
			pbkdf_info.serialize(&mut pbkdf_info_serialized)?;
			self.io.write_exact(&pbkdf_info_serialized)?;
		}
		
		// Encrypt chunks
		while !self.encrypt_chunk()? {}
		Ok(())
	}
	
	fn encrypt_chunk(&mut self) -> Result<bool, Error> {
		// Get chunk
		let (chunk_data_size, is_last) = self.io.read_chunk(&mut self.buffer)?;
		
		// Generate keys and chunk-slices
		let (mut cipher_key, mut mac_key) = (libsodium::Key::new(KEY_SIZE), libsodium::Key::new(KEY_SIZE));
		self.kdf.next(&mut cipher_key, &mut mac_key, is_last)?;
		
		// Compute chunk-ranges: `chunk_data || chunk_mac`
		let chunk_data_range = 0 .. chunk_data_size;
		let chunk_mac_range = chunk_data_range.end .. chunk_data_range.end + MAC_SIZE;
		
		// Encrypt chunk
		libsodium::chacha20_xor(&mut self.buffer[chunk_data_range.start .. chunk_data_range.end], 0, &cipher_key, &[0u8; 8])?;
		
		// Compute MAC
		let mut mac = [0u8; MAC_SIZE];
		libsodium::poly1305(&mut mac, &self.buffer[chunk_data_range.start .. chunk_data_range.end], &mac_key)?;
		self.buffer[chunk_mac_range.start .. chunk_mac_range.end].copy_from_slice(&mac);
		
		// Write chunk
		self.io.write_chunk(&self.buffer[chunk_data_range.start .. chunk_mac_range.end])?;
		Ok(is_last)
	}
}



pub struct Decryptor<'a> {
	io: &'a mut IO,
	buffer: Vec<u8>,
	kdf: Kdf
}
impl<'a> Decryptor<'a> {
	pub fn new(io: &'a mut IO) -> Self {
		Decryptor{ io, buffer: vec![0u8; CHUNK_DATA_SIZE + MAC_SIZE], kdf: Kdf::default() }
	}
	
	pub fn runloop(&mut self, mut password: String) -> Result<(), Error> {
		// Create PBKDF-info-buffer, read the info and parse it
		let pbkdf_info = {
			let mut pbkdf_info_buffer = [0u8; PBKDF_INFO_SIZE];
			self.io.read_exact(&mut pbkdf_info_buffer)?;
			PbkdfInfo::parse(&pbkdf_info_buffer)?
		};
		
		// Compute KDF-key, overwrite password and init KDF
		self.kdf = {
			let mut kdf_key = libsodium::Key::new(KEY_SIZE);
			libsodium::argon2i_v13(&mut kdf_key, &password, &pbkdf_info.nonce, pbkdf_info.iterations, pbkdf_info.memory_requirements, pbkdf_info.parallelism)?;
			libsodium::erase(unsafe{ password.as_bytes_mut() });
			Kdf::new(kdf_key)
		};
		
		// Decrypt chunks
		while !self.decrypt_chunk()? {}
		Ok(())
	}
	
	fn decrypt_chunk(&mut self) -> Result<bool, Error> {
		// Get chunk
		let (chunk_data_mac_size, is_last) = self.io.read_chunk(&mut self.buffer)?;
		
		// Generate keys and chunk-slices
		let (mut cipher_key, mut mac_key) = (libsodium::Key::new(KEY_SIZE), libsodium::Key::new(KEY_SIZE));
		self.kdf.next(&mut cipher_key, &mut mac_key, is_last)?;
		
		// Compute chunk-ranges: `chunk_data || chunk_mac`
		let chunk_data_range = 0 .. chunk_data_mac_size - MAC_SIZE;
		let chunk_mac_range = chunk_data_range.end .. chunk_data_range.end + MAC_SIZE;
		
		// Compute and validate MAC
		let mut mac = [0u8; MAC_SIZE];
		libsodium::poly1305(&mut mac, &self.buffer[chunk_data_range.start .. chunk_data_range.end], &mac_key)?;
		if !libsodium::compare_constant_time(&mac, &self.buffer[chunk_mac_range.start .. chunk_mac_range.end]) { throw_err!(ErrorType::InvalidData, "Invalid MAC/unexpected end-of-stream".to_owned()) }
		
		// Decrypt and write chunk
		libsodium::chacha20_xor(&mut self.buffer[chunk_data_range.start .. chunk_data_range.end], 0, &cipher_key, &[0u8; 8])?;
		self.io.write_chunk(&self.buffer[chunk_data_range.start .. chunk_data_range.end])?;
		
		Ok(is_last)
	}
}