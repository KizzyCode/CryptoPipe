use std::io::ErrorKind;
use super::super::error::ErrorType;
use super::super::io_runloop::IoRunloop;
use super::super::io_processor::{ IoEncryptor, IoDecryptor };
use super::super::libsodium;
use super::super::constants;
use super::memory_io::MemoryIo;
use super::{ estimate_sealed_size, RANDOM_STREAM_PASSWORD };

struct Test<'a> {
	random_size: usize,
	modificator: &'a Fn(&mut Vec<u8>),
	error_type_description: (ErrorType, String)
}
impl<'a> Test<'a> {
	pub fn run(&self, pbkdf_parameters: (u32, u32, u32)) {
		// Create random plain-text-stream
		let mut random_plain = vec![0u8; self.random_size];
		libsodium::random(&mut random_plain);
		
		// Encrypt data
		let mut encrypted = {
			// Create IO-handle
			let io_handle = MemoryIo::new(random_plain.clone(), estimate_sealed_size(random_plain.len()));
			
			// Create encryptor with given PBKDF-parameters and a random nonce
			let io_encryptor = Box::new(IoEncryptor::new(
				RANDOM_STREAM_PASSWORD.to_owned(),
				pbkdf_parameters.0, pbkdf_parameters.1, pbkdf_parameters.2
			).unwrap());
			
			// Start runloop and return encrypted data
			IoRunloop::new(io_encryptor, Box::new(io_handle.duplicate())).start().unwrap();
			io_handle.stdout().to_vec()
		};
		
		// Introduce error
		(self.modificator)(&mut encrypted);
		
		// Decrypt data
		let error = {
			// Create IO-handle
			let io_handle_decryption = MemoryIo::new(encrypted.clone(), encrypted.len());
			
			// Create decryptor
			let io_decryptor = Box::new(IoDecryptor::new(RANDOM_STREAM_PASSWORD.to_owned()));
			
			// Start runloop and return error
			IoRunloop::new(io_decryptor, Box::new(io_handle_decryption.duplicate())).start().unwrap_err()
		};
		
		// Compare errors
		assert_eq!(error.error_type, self.error_type_description.0);
		assert_eq!(error.description, self.error_type_description.1);
	}
}

#[test]
fn batch() {
	let tests = [
		// Pass empty input
		Test {
			random_size: 0,
			modificator: &|x: &mut Vec<u8>| x.truncate(0),
			error_type_description: (ErrorType::IOError(ErrorKind::UnexpectedEof.into()), "Failed to read from stdin".to_owned())
		},
		// Modify data
		Test {
			random_size: 7798,
			modificator: &|x: &mut Vec<u8>| x[714] = 0x40,
			error_type_description: (ErrorType::InvalidData, "Invalid MAC/unexpected end-of-stream".to_owned())
		},
		// Truncate MAC
		Test {
			random_size: 1 * 1024 * 1024,
			modificator: &|x: &mut Vec<u8>| { let len = x.len(); x.truncate(len - 1); },
			error_type_description: (ErrorType::InvalidData, "Invalid MAC/unexpected end-of-stream".to_owned())
		},
		// Truncate chunk
		Test {
			random_size: 2 * 1024 * 1024,
			modificator: &|x: &mut Vec<u8>| x.truncate(constants::STREAM_HEADER_SIZE + constants::MAC_SIZE),
			error_type_description: (ErrorType::InvalidData, "Invalid MAC/unexpected end-of-stream".to_owned())
		},
		// Remove last chunk
		Test {
			random_size: 3 * 1024 * 1024,
			modificator: &|x: &mut Vec<u8>| { let len = x.len(); x.truncate(len - (constants::CHUNK_DATA_SIZE + constants::MAC_SIZE)); },
			error_type_description: (ErrorType::InvalidData, "Invalid MAC/unexpected end-of-stream".to_owned())
		},
		// Damage MAC
		Test {
			random_size: 7 * 1024 * 1024,
			modificator: &|x: &mut Vec<u8>| { let len = x.len(); x[len - 1] ^= 0x40 },
			error_type_description: (ErrorType::InvalidData, "Invalid MAC/unexpected end-of-stream".to_owned())
		},
		// Remove everything except the stream-header
		Test {
			random_size: 8 * 1024 * 1024,
			modificator: &|x: &mut Vec<u8>| x.truncate(constants::STREAM_HEADER_SIZE),
			error_type_description: (ErrorType::InvalidData, "Unexpected end-of-stream".to_owned())
		},
		// Truncate the stream-header
		Test {
			random_size: 8396411,
			modificator: &|x: &mut Vec<u8>| x.truncate(7),
			error_type_description: (ErrorType::IOError(ErrorKind::UnexpectedEof.into()), "Failed to read from stdin".to_owned())
		},
	];
	
	// Run tests with two different PBKDF-parameters
	for test in tests.iter() {
		test.run((8, 256 * 1024, 4));
		test.run((4, 512 * 1024, 5));
	}
}