use super::super::crypto;
use super::super::stream;
use super::memory_io::MemoryIo;

const RANDOM_STREAM_PASSWORD: &str = "Random password";



struct Test {
	random_size: usize
}
impl Test {
	pub fn argon2i_hmacsha512_chachapoly(&self, pbkdf_parameters: (u32, u32, u32)) {
		// Create random plain-text-stream
		let mut random_plain = vec![0u8; self.random_size];
		crypto::random(&mut random_plain);
		
		// Encrypt data
		let encrypted = {
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
				let mut encryptor = stream::Encryptor::new(RANDOM_STREAM_PASSWORD.to_string(), &mut io, stream_instance).unwrap();
				encryptor.runloop().unwrap();
			}
			io.stdout()
		};
		
		// Decrypt data
		let decrypted = {
			// Start runloop
			let mut io = MemoryIo::new(encrypted.clone(), encrypted.len());
			{
				let mut decryptor = stream::Decryptor::new(RANDOM_STREAM_PASSWORD.to_string(), &mut io).unwrap();
				decryptor.runloop().unwrap();
			}
			io.stdout()
		};
		
		// Test result
		assert_eq!(random_plain.as_slice(), decrypted.as_slice())
	}
}

#[test]
fn batch() {
	let tests = [
		Test{ random_size: 0 },
		Test{ random_size: 7789 },
		Test{ random_size: 1 * 1024 * 1024 },
		Test{ random_size: 2 * 1024 * 1024 },
		Test{ random_size: 3 * 1024 * 1024 },
		Test{ random_size: 4 * 1024 * 1024 },
		Test{ random_size: 5 * 1024 * 1024 },
		Test{ random_size: 6 * 1024 * 1024 },
		Test{ random_size: 7 * 1024 * 1024 },
		Test{ random_size: 8 * 1024 * 1024 },
		Test{ random_size: 8396411 },
	];
	
	// Run tests with two different PBKDF-parameters
	for test in tests.iter() {
		test.argon2i_hmacsha512_chachapoly((8, 256, 4));
		test.argon2i_hmacsha512_chachapoly((4, 512, 8));
	}
}