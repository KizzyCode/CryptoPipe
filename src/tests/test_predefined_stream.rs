use super::super::io_runloop::IoRunloop;
use super::super::io_processor::{ IoEncryptor, IoDecryptor };
use super::memory_io::MemoryIo;
use super::{ estimate_sealed_size, PREDEFINED_STREAM_SEALED, PREDEFINED_STREAM_PLAIN, PREDEFINED_STREAM_PASSWORD, PREDEFINED_STREAM_PBKDF };

#[test]
fn test_encryption() {
	// Create IO-handle
	let io_handle = MemoryIo::new(PREDEFINED_STREAM_PLAIN.to_vec(), estimate_sealed_size(PREDEFINED_STREAM_PLAIN.len()));
	
	// Create encryptor with preedefined nonce
	let io_encryptor = Box::new(IoEncryptor::with_nonce(
		PREDEFINED_STREAM_PASSWORD.to_owned(), PREDEFINED_STREAM_PBKDF.0,
		PREDEFINED_STREAM_PBKDF.1, PREDEFINED_STREAM_PBKDF.2, PREDEFINED_STREAM_PBKDF.3
	).unwrap());
	
	// Start runloop
	IoRunloop::new(io_encryptor, Box::new(io_handle.duplicate())).start().unwrap();
	
	// Compare data
	assert_eq!(PREDEFINED_STREAM_SEALED, io_handle.stdout().as_slice())
}

#[test]
fn test_decryption() {
	// Create IO-handle
	let io_handle = MemoryIo::new(PREDEFINED_STREAM_SEALED.to_vec(), PREDEFINED_STREAM_SEALED.len());
	
	// Create decryptor
	let io_decryptor = Box::new(IoDecryptor::new(PREDEFINED_STREAM_PASSWORD.to_owned()));
	
	// Start runloop
	IoRunloop::new(io_decryptor, Box::new(io_handle.duplicate())).start().unwrap();
	
	// Test data
	assert_eq!(PREDEFINED_STREAM_PLAIN, io_handle.stdout().as_slice())
}