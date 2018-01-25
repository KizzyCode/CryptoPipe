use std;
use super::error::{ Error, ErrorType };
use super::io::IO;
use super::libsodium;
use super::kdf::{ PBKDF_INFO_SIZE, PbkdfInfo };
use super::crypto_stream::{ MAC_SIZE, CHUNK_DATA_SIZE, Encryptor, Decryptor };


const CRYPTO_STREAM_PREDEFINED_PASSWORD: &'static str = "Predefined password";
const CRYPTO_STREAM_RANDOM_PASSWORD: &'static str = "Random password";

const PREDEFINED_STREAM_PLAIN: &'static[u8] = include_bytes!("predefined_stream.plain");
const PREDEFINED_STREAM_PBKDF_INFO: &'static[u8] = include_bytes!("predefined_stream.pbkdf_info");
const PREDEFINED_STREAM_SEALED: &'static[u8] = include_bytes!("predefined_stream.sealed");


/// A StdIO-replacement that works with memory-buffers instead of the StdIO-streams
struct VectorIO<'a> {
	stdin: (&'a[u8], usize),
	stdout: (Vec<u8>, usize),
	chunk_size: usize
}
impl<'a> VectorIO<'a> {
	pub fn new(chunk_size: usize, stdin: &'a[u8], expected_output_len: usize) -> Self {
		VectorIO{ chunk_size, stdin: (stdin, 0), stdout: (vec![0u8; expected_output_len], 0) }
	}
	
	pub fn stdout(&self) -> &[u8] {
		&self.stdout.0[.. self.stdout.1]
	}
}
impl<'a> IO for VectorIO<'a> {
	fn read_chunk(&mut self, chunk_buffer: &mut[u8]) -> Result<(usize, bool), Error> {
		let to_copy = std::cmp::min(self.chunk_size, self.stdin.0[self.stdin.1 ..].len());
		chunk_buffer[.. to_copy].copy_from_slice(&self.stdin.0[self.stdin.1 .. self.stdin.1 + to_copy]);
		self.stdin.1 += to_copy;
		
		Ok((to_copy, self.stdin.0.len() <= self.stdin.1))
	}
	fn write_chunk(&mut self, data: &[u8]) -> Result<(), Error> {
		self.write_exact(data)
	}
	
	fn read_exact(&mut self, buffer: &mut[u8]) -> Result<(), Error> {
		let to_copy = if self.stdin.0[self.stdin.1 ..].len() >= buffer.len() { buffer.len() }
			else { throw_err!(ErrorType::IOError(std::io::ErrorKind::UnexpectedEof.into()), "Failed to read from stdin".to_owned()) };
		buffer.copy_from_slice(&self.stdin.0[self.stdin.1 .. self.stdin.1 + to_copy]);
		self.stdin.1 += to_copy;
		
		Ok(())
	}
	fn write_exact(&mut self, data: &[u8]) -> Result<(), Error> {
		if self.stdout.0[self.stdout.1 ..].len() < data.len() { throw_err!(ErrorType::IOError(std::io::ErrorKind::UnexpectedEof.into()), "Failed to write to stdout".to_owned()) }
		self.stdout.0[self.stdout.1 .. self.stdout.1 + data.len()].copy_from_slice(data);
		self.stdout.1 += data.len();
		
		Ok(())
	}
}

fn estimate_sealed_size(plain_size: usize) -> usize {
	let block_count = (plain_size / CHUNK_DATA_SIZE) + 1;
	PBKDF_INFO_SIZE + (CHUNK_DATA_SIZE * block_count) + (MAC_SIZE * block_count)
}



#[test]
fn test_predefined_encryption() {
	// Create IO-buffer and PBKDF-info
	let mut io = VectorIO::new(CHUNK_DATA_SIZE, PREDEFINED_STREAM_PLAIN, estimate_sealed_size(PREDEFINED_STREAM_PLAIN.len()));
	let pbkdf_info = PbkdfInfo::parse(PREDEFINED_STREAM_PBKDF_INFO).unwrap();
	
	// Encrypt stream
	{
		let mut encryptor = Encryptor::new(&mut io);
		encryptor.runloop(CRYPTO_STREAM_PREDEFINED_PASSWORD.to_owned(), pbkdf_info).unwrap();
	}
	
	assert_eq!(PREDEFINED_STREAM_SEALED, io.stdout())
}
#[test]
fn test_predefined_decryption() {
	// Create IO-buffer and PBKDF-info
	let mut io = VectorIO::new(CHUNK_DATA_SIZE + MAC_SIZE, PREDEFINED_STREAM_SEALED, estimate_sealed_size(PREDEFINED_STREAM_SEALED.len()));
	
	// Encrypt stream
	{
		let mut decryptor = Decryptor::new(&mut io);
		decryptor.runloop(CRYPTO_STREAM_PREDEFINED_PASSWORD.to_owned()).unwrap();
	}
	
	assert_eq!(PREDEFINED_STREAM_PLAIN, io.stdout())
}



#[test]
fn test_encryption_decryption_random() {
	let sizes = [
		0,
		7789,
		1 * 1024 * 1024, 2 * 1024 * 1024, 3 * 1024 * 1024, 4 * 1024 * 1024,
		5 * 1024 * 1024, 6 * 1024 * 1024, 7 * 1024 * 1024, 8 * 1024 * 1024,
		8396411
	];
	let pbkdf_infos = [
		PbkdfInfo::new(8, 256 * 1024, 4),
		PbkdfInfo::new(4, 512 * 1024, 8)
	];
	
	// Test for params
	for size in sizes.iter() {
		for pbkdf_info in pbkdf_infos.iter() { encryption_decryption_random(*size, pbkdf_info.clone()) }
	}
}
fn encryption_decryption_random(size: usize, pbkdf_info: PbkdfInfo) {
	// Create random plain-text-stream
	let mut random_plain = vec![0u8; size];
	libsodium::random(&mut random_plain);
	
	// Create encryptor-IO-buffer
	let mut encryptor_io = VectorIO::new(CHUNK_DATA_SIZE, &random_plain, estimate_sealed_size(random_plain.len()));
	
	// Encrypt stream
	{
		let mut encryptor = Encryptor::new(&mut encryptor_io);
		encryptor.runloop(CRYPTO_STREAM_RANDOM_PASSWORD.to_owned(), pbkdf_info).unwrap();
	}
	let encrypted = encryptor_io.stdout();
	
	
	// Create decryptor-IO-buffer
	let mut decryptor_io = VectorIO::new(CHUNK_DATA_SIZE + MAC_SIZE, encrypted, estimate_sealed_size(encrypted.len()));
	
	// Decrypt stream
	{
		let mut decryptor = Decryptor::new(&mut decryptor_io);
		decryptor.runloop(CRYPTO_STREAM_RANDOM_PASSWORD.to_owned()).unwrap();
	}
	let decrypted = decryptor_io.stdout();
	
	assert_eq!(random_plain.as_slice(), decrypted)
}