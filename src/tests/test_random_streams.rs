use super::super::io_runloop::IoRunloop;
use super::super::io_processor::{ IoEncryptor, IoDecryptor };
use super::super::libsodium;
use super::memory_io::MemoryIo;
use super::{ estimate_sealed_size, RANDOM_STREAM_PASSWORD };

struct Test {
	random_size: usize
}
impl Test {
	pub fn run(&self, pbkdf_parameters: (u32, u32, u32)) {
		// Create random plain-text-stream
		let mut random_plain = vec![0u8; self.random_size];
		libsodium::random(&mut random_plain);
		
		// Encrypt data
		let encrypted = {
			// Create IO-handle
			let io_handle = MemoryIo::new(random_plain.clone(), estimate_sealed_size(random_plain.len()));
			
			// Create encryptor with random nonce
			let io_encryptor = Box::new(IoEncryptor::new(
				RANDOM_STREAM_PASSWORD.to_owned(),
				pbkdf_parameters.0, pbkdf_parameters.1, pbkdf_parameters.2
			).unwrap());
			
			// Start runloop
			IoRunloop::new(io_encryptor, Box::new(io_handle.duplicate())).start().unwrap();
			io_handle.stdout().to_vec()
		};
		
		// Decrypt data
		let decrypted = {
			// Create IO-handle
			let io_handle = MemoryIo::new(encrypted.clone(), encrypted.len());
			
			// Create decryptor
			let io_decryptor = Box::new(IoDecryptor::new(RANDOM_STREAM_PASSWORD.to_owned()));
			
			// Start runloop
			IoRunloop::new(io_decryptor, Box::new(io_handle.duplicate())).start().unwrap();
			io_handle.stdout().to_vec()
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
		test.run((8, 256 * 1024, 4));
		test.run((4, 512 * 1024, 8));
	}
}