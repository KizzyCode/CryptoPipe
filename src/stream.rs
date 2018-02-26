use super::{ Error, CpError };
use super::crypto;
use super::io;


pub const CHUNK_DATA_SIZE: usize = (1 * 1024 * 1024);


pub fn kdf_info<'a>(buffer: &'a mut[u8], mut counter: u64, info: &str) -> Result<&'a [u8], Error<CpError>> {
	// Validate info-length
	if info.len() > buffer.len() - 8 { throw_err!(CpError::InvalidParameter) }
	
	// Serialize counter as 64-bit big-endian-integer
	for i in (0..8).rev() { buffer[i] = counter as u8; counter >>= 8; }
	
	// Append info and return slice over `serialized_counter || info`
	buffer[8 .. 8 + info.len()].copy_from_slice(info.as_bytes());
	Ok(&buffer[.. 8 + info.len()])
}



pub struct Encryptor<'a> {
	io: &'a mut io::Io,
	key: crypto::Key,
	stream_instance: crypto::StreamInstance
}
impl<'a> Encryptor<'a> {
	pub fn new(password: String, io: &'a mut io::Io, stream_instance: crypto::StreamInstance) -> Result<Self, Error<CpError>> {
		// Generate key from password
		let key = try_err!(stream_instance.pbkdf.derive(password));
		Ok(Encryptor{ io, key, stream_instance })
	}
	
	pub fn runloop(&mut self) -> Result<(), Error<CpError>> {
		// Serialize stream-instance and write it as header
		try_err!(self.io.write_exact(&self.stream_instance.as_serialized().into_encoded()));
		
		// Initialize KDF-counter and -buffer and chunk-buffer
		let mut counter = 0u64;
		let (mut kdf_buffer, mut chunk_buffer) = ([0u8; 32], vec![0u8; CHUNK_DATA_SIZE + self.stream_instance.auth_enc.overhead()]);
		
		// Process chunks
		loop {
			// Read chunk
			let (chunk_length, is_last) = try_err!(self.io.read_chunk(&mut chunk_buffer[.. CHUNK_DATA_SIZE]));
			
			// Compute KDF-info and key
			let chunk_info = if is_last { "#Last Chunk" } else { "" };
			let key = try_err!(self.stream_instance.kdf.derive(&self.key, try_err!(kdf_info(&mut kdf_buffer, counter, chunk_info))));
			counter += 1;
			
			// Seal and print chunk
			let sealed_length = try_err!(self.stream_instance.auth_enc.seal(&mut chunk_buffer, chunk_length, key));
			try_err!(self.io.write_chunk(&chunk_buffer[.. sealed_length]));
			
			// Return after last chunk
			if is_last { return Ok(()) }
		}
	}
}



pub struct Decryptor<'a> {
	io: &'a mut io::Io,
	password: Option<String>
}
impl<'a> Decryptor<'a> {
	pub fn new(password: String, io: &'a mut io::Io) -> Result<Self, Error<CpError>> {
		Ok(Decryptor{ io, password: Some(password) })
	}
	
	pub fn runloop(&mut self) -> Result<(), Error<CpError>> {
		// Create stream-instance
		let stream_instance = {
			// Determine stream-header-length
			let (mut header_data, mut header_pos) = (vec![0u8; 0], 0);
			let header_length = 'read_header_loop: loop {
				if let Some(length) = try_err!(crypto::StreamInstance::try_parse_length(&header_data)) {
					break 'read_header_loop length
				} else {
					header_data.resize(header_pos + 1, 0x00);
					try_err!(self.io.read_exact(&mut header_data[header_pos .. header_pos + 1]));
					header_pos += 1;
				}
			};
			
			// Read remaining header-data
			header_data.resize(header_length, 0x00);
			try_err!(self.io.read_exact(&mut header_data[header_pos ..]));
			
			try_err!(crypto::StreamInstance::from_serialized(header_data))
		};
		
		// Compute base-key and initialize KDF-counter and -buffer and chunk-buffer
		let password = if let Some(password) = self.password.take() { password }
			else { throw_err!(CpError::Unsupported, "`runloop()` cannot be invoked twice on the same instance") };
		let base_key = try_err!(stream_instance.pbkdf.derive(password));
		
		let mut counter = 0u64;
		let (mut kdf_buffer, mut chunk_buffer) = ([0u8; 32], vec![0u8; CHUNK_DATA_SIZE + stream_instance.auth_enc.overhead()]);
		
		// Process chunks
		loop {
			// Read chunk
			let (chunk_length, is_last) = try_err!(self.io.read_chunk(&mut chunk_buffer));
			
			// Compute KDF-info and key
			let chunk_info = if is_last { "#Last Chunk" } else { "" };
			let key = try_err!(stream_instance.kdf.derive(&base_key, try_err!(kdf_info(&mut kdf_buffer, counter, chunk_info))));
			counter += 1;
			
			// Seal and print chunk
			let data_length = try_err!(stream_instance.auth_enc.open(&mut chunk_buffer, chunk_length, key));
			try_err!(self.io.write_chunk(&chunk_buffer[.. data_length]));
			
			// Return after last chunk
			if is_last { return Ok(()) }
		}
	}
}