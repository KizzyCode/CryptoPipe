use std::io::ErrorKind;
use super::super::error::ErrorType;
use super::super::crypto;
use super::super::stream;
use super::memory_io::MemoryIo;

const INVALID_STREAM_PASSWORD: &str = "Invalid password";



struct Test<'a> {
	random_size: usize,
	modificator: &'a Fn(&mut Vec<u8>),
	error_type_description: (ErrorType, String)
}
impl<'a> Test<'a> {
	pub fn argon2i_hmacsha512_chachapoly(&self, pbkdf_parameters: (u32, u32, u32)) {
		// Create random plain-text-stream
		let mut random_plain = vec![0u8; self.random_size];
		crypto::random(&mut random_plain);
		
		// Encrypt data
		let mut encrypted = {
			// Create stream-instance
			let stream_instance = crypto::StreamInstance::new(
				crypto::pbkdf::Argon2i::new(pbkdf_parameters.0, pbkdf_parameters.1, pbkdf_parameters.2),
				crypto::kdf::HmacSha2512::new(),
				crypto::auth_enc::ChaCha20Poly1305::new()
			);
			
			// Start runloop
			let mut io = MemoryIo::new(
				random_plain.clone(),
				super::estimate_sealed_size(random_plain.len(), stream_instance.auth_enc.overhead())
			);
			{
				let mut encryptor = stream::Encryptor::new(INVALID_STREAM_PASSWORD.to_string(), &mut io, stream_instance).unwrap();
				encryptor.runloop().unwrap();
			}
			io.stdout()
		};
		
		// Introduce error
		(self.modificator)(&mut encrypted);
		
		// Decrypt data
		let error = {
			// Start runloop
			let mut io = MemoryIo::new(encrypted.clone(), encrypted.len());
			let mut decryptor = stream::Decryptor::new(INVALID_STREAM_PASSWORD.to_string(), &mut io).unwrap();
			decryptor.runloop().unwrap_err()
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
			error_type_description: (ErrorType::InvalidData, "Invalid authentication-tag".to_owned())
		},
		// Truncate MAC
		Test {
			random_size: 1 * 1024 * 1024,
			modificator: &|x: &mut Vec<u8>| { let len = x.len(); x.truncate(len - 1); },
			error_type_description: (ErrorType::InvalidData, "Invalid authentication-tag".to_owned())
		},
		// Truncate chunk
		Test {
			random_size: 2 * 1024 * 1024,
			modificator: &|x: &mut Vec<u8>| x.truncate(158 + 16),
			error_type_description: (ErrorType::InvalidData, "Invalid authentication-tag".to_owned())
		},
		// Remove last chunk
		Test {
			random_size: 3 * 1024 * 1024,
			modificator: &|x: &mut Vec<u8>| { let len = x.len(); x.truncate(len - (stream::CHUNK_DATA_SIZE + 16)); },
			error_type_description: (ErrorType::InvalidData, "Invalid authentication-tag".to_owned())
		},
		// Damage MAC
		Test {
			random_size: 7 * 1024 * 1024,
			modificator: &|x: &mut Vec<u8>| { let len = x.len(); x[len - 1] ^= 0x40 },
			error_type_description: (ErrorType::InvalidData, "Invalid authentication-tag".to_owned())
		},
		// Remove everything except the stream-header
		Test {
			random_size: 8 * 1024 * 1024,
			modificator: &|x: &mut Vec<u8>| x.truncate(158),
			error_type_description: (ErrorType::InvalidData, "Invalid authentication-tag".to_owned())
		},
		// Truncate the stream-header
		Test {
			random_size: 8396411,
			modificator: &|x: &mut Vec<u8>| x.truncate(7),
			error_type_description: (ErrorType::IOError(ErrorKind::UnexpectedEof.into()), "Failed to read from stdin".to_owned())
		}
	];
	
	// Run tests with two different PBKDF-parameters
	for test in tests.iter() {
		test.argon2i_hmacsha512_chachapoly((8, 256, 4));
		test.argon2i_hmacsha512_chachapoly((4, 512, 5));
	}
}