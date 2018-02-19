use super::super::crypto;
use super::super::stream;
use super::memory_io::MemoryIo;

const PASSWORD: &str = "Predefined password";
const PBKDF: (&'static[u8], u32, u32, u32) = (b"This is an 32-byte nonce-text :P", 8, 256, 4);
const PLAIN: &'static[u8] = include_bytes!("predefined_stream.plain");
const SEALED_ARGON2I_HMACSHA512_CHACHAPOLY: &'static[u8] = include_bytes!("predefined_stream.sealed");



#[test]
fn test_encryption_argon2i_hmacsha512_chachapoly() {
	// Encrypt data
	let encrypted = {
		// Create stream-instance
		let stream_instance = crypto::StreamInstance::new(
			crypto::pbkdf::Argon2i::with_nonce(PBKDF.0.to_vec(), PBKDF.1, PBKDF.2, PBKDF.3),
			crypto::kdf::HmacSha2512::new(),
			crypto::auth_enc::ChaCha20Poly1305::new()
		);
		
		// Start runloop
		let mut io = MemoryIo::new(
			PLAIN.to_vec(),
			super::estimate_sealed_size(PLAIN.len(), stream_instance.auth_enc.overhead())
		);
		{
			let mut encryptor = stream::Encryptor::new(PASSWORD.to_string(), &mut io, stream_instance).unwrap();
			encryptor.runloop().unwrap();
		}
		io.stdout()
	};
	
	// Compare data
	assert_eq!(SEALED_ARGON2I_HMACSHA512_CHACHAPOLY, encrypted.as_slice())
}

#[test]
fn test_decryption_argon2i_hmacsha512_chachapoly() {
	// Decrypt data
	let decrypted = {
		// Start runloop
		let mut io = MemoryIo::new(SEALED_ARGON2I_HMACSHA512_CHACHAPOLY.to_vec(), SEALED_ARGON2I_HMACSHA512_CHACHAPOLY.len());
		{
			let mut decryptor = stream::Decryptor::new(PASSWORD.to_string(), &mut io).unwrap();
			decryptor.runloop().unwrap();
		}
		io.stdout()
	};
	
	// Compare data
	assert_eq!(PLAIN, decrypted.as_slice())
}