use super::error::{ Error, ErrorType };
use super::crypto::{ Pbkdf, Kdf, Aead };
use super::libsodium;
use super::constants;


struct StreamHeader {
	pub version: (u8, u8, u8),
	
	pub pbkdf_algo_id: u8,
	pub kdf_algo_id: u8,
	pub aead_algo_id: u8,
	
	pub pbkdf_nonce: [u8; constants::PBKDF_NONCE_SIZE],
	pub pbkdf_iterations: u32,
	pub pbkdf_memory_requirements: u32,
	pub pbkdf_parallelism: u32
}
impl StreamHeader {
	pub fn new(pbkdf_nonce: &[u8], pbkdf_iterations: u32, pbkdf_memory_requirements: u32, pbkdf_parallelism: u32) -> Result<Self, Error> {
		// Validate input
		if pbkdf_nonce.len() != constants::PBKDF_NONCE_SIZE { throw_err!(ErrorType::Unsupported) }
		
		// Copy nonce
		let mut pbkdf_nonce_array = [0u8; constants::PBKDF_NONCE_SIZE];
		pbkdf_nonce_array.copy_from_slice(pbkdf_nonce);
		
		Ok(StreamHeader {
			version: constants::STREAM_VERSION,
			pbkdf_algo_id: constants::PBKDF_ALGO_ID, kdf_algo_id: constants::KDF_ALGO_ID, aead_algo_id: constants::AEAD_ALGO_ID,
			pbkdf_nonce: pbkdf_nonce_array, pbkdf_iterations, pbkdf_memory_requirements, pbkdf_parallelism
		})
	}
	
	pub fn parse(data: &[u8]) -> Result<Self, Error> {
		fn read_u32_be(bytes: &[u8]) -> u32 {
			bytes[0 .. 4].iter().fold(0u32, |num, byte| (num << 8) | *byte as u32)
		}
		
		// Validate input
		if data.len() < constants::STREAM_HEADER_SIZE { throw_err!(ErrorType::InvalidParameter) }
		
		// Read nonce
		let mut pbkdf_nonce = [0u8; constants::PBKDF_NONCE_SIZE];
		pbkdf_nonce.copy_from_slice(&data[6 .. 6 + constants::PBKDF_NONCE_SIZE]);
		
		// Parse header
		Ok(StreamHeader {
			version: (data[0], data[1], data[2]),
			pbkdf_algo_id: data[3], kdf_algo_id: data[4], aead_algo_id: data[5],
			pbkdf_nonce,
			pbkdf_iterations: read_u32_be(&data[6 + constants::PBKDF_NONCE_SIZE ..]),
			pbkdf_memory_requirements: read_u32_be(&data[6 + constants::PBKDF_NONCE_SIZE + 4 ..]),
			pbkdf_parallelism: read_u32_be(&data[6 + constants::PBKDF_NONCE_SIZE + 8 ..]),
		})
	}
	
	pub fn serialize(&self, buffer: &mut[u8]) -> Result<(), Error> {
		fn write_u32_be(buffer: &mut[u8], mut num: u32) {
			for i in (0..4).rev() { buffer[i] = num as u8; num >>= 8; }
		}
		
		// Validate input
		if buffer.len() < constants::STREAM_HEADER_SIZE { throw_err!(ErrorType::InvalidParameter) }
		
		// Serialize version
		buffer[0] = self.version.0; buffer[1] = self.version.1; buffer[2] = self.version.2;
		// Serialize algorithm-IDs
		buffer[3] = self.pbkdf_algo_id; buffer[4] = self.kdf_algo_id; buffer[5] = self.aead_algo_id;
		// Copy nonce
		buffer[6 .. 6 + constants::PBKDF_NONCE_SIZE].copy_from_slice(&self.pbkdf_nonce);
		// Serialize PBKDF-parameters
		write_u32_be(&mut buffer[6 + constants::PBKDF_NONCE_SIZE ..], self.pbkdf_iterations);
		write_u32_be(&mut buffer[6 + constants::PBKDF_NONCE_SIZE + 4 ..], self.pbkdf_memory_requirements);
		write_u32_be(&mut buffer[6 + constants::PBKDF_NONCE_SIZE + 8 ..], self.pbkdf_parallelism);
		
		Ok(())
	}
}



pub trait IoProcessor {
	fn header_buffer_and_in_sizes(&self) -> (usize, usize);
	fn chunk_buffer_and_in_sizes(&self) -> (usize, usize);
	fn process_header<'a>(&mut self, data: &'a mut[u8]) -> Result<&'a[u8], Error>;
	fn process_chunk<'a>(&mut self, data: &'a mut[u8], data_len: usize, is_last: bool) -> Result<&'a[u8], Error>;
}

pub struct IoEncryptor {
	aead: Aead,
	stream_header: StreamHeader
}
impl IoEncryptor {
	pub fn new(password: String, pbkdf_iterations: u32, pbkdf_memory_requirements: u32, pbkdf_parallelism: u32) -> Result<Self, Error> {
		// Generate random nonce
		let mut pbkdf_nonce = [0u8; constants::PBKDF_NONCE_SIZE];
		libsodium::random(&mut pbkdf_nonce);
		
		IoEncryptor::with_nonce(password, &pbkdf_nonce, pbkdf_iterations, pbkdf_memory_requirements, pbkdf_parallelism)
	}
	pub fn with_nonce(password: String, pbkdf_nonce: &[u8], pbkdf_iterations: u32, pbkdf_memory_requirements: u32, pbkdf_parallelism: u32) -> Result<Self, Error> {
		// Generate stream-header and compute master-key
		let stream_header = StreamHeader::new(pbkdf_nonce, pbkdf_iterations, pbkdf_memory_requirements, pbkdf_parallelism)?;
		
		// Compute master-key, init KDF and AEAD
		let aead = {
			let master_key = Pbkdf::compute(stream_header.pbkdf_algo_id, password, pbkdf_nonce, pbkdf_iterations, pbkdf_memory_requirements, pbkdf_parallelism)?;
			let kdf = Kdf::new(stream_header.kdf_algo_id, master_key)?;
			Aead::new(stream_header.aead_algo_id, kdf)?
		};
		
		Ok(IoEncryptor{ aead, stream_header })
	}
}
impl IoProcessor for IoEncryptor {
	fn header_buffer_and_in_sizes(&self) -> (usize, usize) {
		(constants::STREAM_HEADER_SIZE, 0)
	}
	fn chunk_buffer_and_in_sizes(&self) -> (usize, usize) {
		(constants::CHUNK_DATA_SIZE + constants::MAC_SIZE, constants::CHUNK_DATA_SIZE)
	}
	
	fn process_header<'a>(&mut self, buffer: &'a mut[u8]) -> Result<&'a[u8], Error> {
		// Validate input
		if buffer.len() < constants::STREAM_HEADER_SIZE { throw_err!(ErrorType::InvalidParameter) }
		
		// Serialize header and finalize
		self.stream_header.serialize(buffer)?;
		Ok(&buffer[.. constants::STREAM_HEADER_SIZE])
	}
	
	fn process_chunk<'a>(&mut self, data: &'a mut[u8], data_len: usize, is_last: bool) -> Result<&'a[u8], Error> {
		self.aead.encrypt_chunk(data, data_len, is_last)
	}
}

pub struct IoDecryptor {
	password: Option<String>,
	aead: Option<Aead>
}
impl IoDecryptor {
	pub fn new(password: String) -> Self {
		IoDecryptor{ password: Some(password), aead: None }
	}
}
impl IoProcessor for IoDecryptor {
	fn header_buffer_and_in_sizes(&self) -> (usize, usize) {
		(constants::STREAM_HEADER_SIZE, constants::STREAM_HEADER_SIZE)
	}
	fn chunk_buffer_and_in_sizes(&self) -> (usize, usize) {
		(constants::CHUNK_DATA_SIZE + constants::MAC_SIZE, constants::CHUNK_DATA_SIZE + constants::MAC_SIZE)
	}
	
	fn process_header<'a>(&mut self, buffer: &'a mut[u8]) -> Result<&'a[u8], Error> {
		// Parse header
		let stream_header = StreamHeader::parse(&buffer)?;
		
		// Compute master-key, init KDF and AEAD
		self.aead = Some({
			let master_key = Pbkdf::compute(
				stream_header.pbkdf_algo_id, self.password.take().expect("Decryptor must not be initialized twice"),
				&stream_header.pbkdf_nonce, stream_header.pbkdf_iterations, stream_header.pbkdf_memory_requirements, stream_header.pbkdf_parallelism
			)?;
			let kdf = Kdf::new(stream_header.kdf_algo_id, master_key)?;
			Aead::new(stream_header.aead_algo_id, kdf)?
		});
		
		// Finalize
		Ok(&buffer[0 .. 0])
	}
	
	fn process_chunk<'a>(&mut self, data: &'a mut[u8], data_len: usize, is_last: bool) -> Result<&'a[u8], Error> {
		self.aead.as_mut().expect("Decryptor is not initialized").decrypt_chunk(data, data_len, is_last)
	}
}