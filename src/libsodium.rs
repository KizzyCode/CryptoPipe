use std;
use std::os::raw::{c_uchar, c_int, c_ulonglong, c_void};
use super::error::{ Error, ErrorType };



/// A key-object to hold keys with various length. The memory will be initialized with random
/// data and overwritten with random-data if it is dropped.
#[derive(Default, Clone)]
pub struct Key(Vec<u8>);
impl Key {
	/// Initializes a new key filled with random data
	pub fn new(size: usize) -> Self {
		let mut key = Key(vec![0u8; size]);
		erase(key.as_mut_slice());
		key
	}
	/// Returns the key-bytes as slice
	pub fn as_slice(&self) -> &[u8] {
		&self.0
	}
	/// Returns the key-bytes as mutable slice
	pub fn as_mut_slice(&mut self) -> &mut[u8] {
		&mut self.0
	}
	/// Returns the key-length
	pub fn len(&self) -> usize {
		self.0.len()
	}
	/// Returns a pointer to the key-bytes of type `T`
	pub fn as_ptr<T>(&self) -> *const T {
		self.0.as_ptr() as *const T
	}
}
impl Drop for Key {
	fn drop(&mut self) {
		erase(self.as_mut_slice())
	}
}



extern {
	// Argon2i-PBKDF
	fn argon2i_hash_raw(
		iterations: u32, memory_cost_kb: u32, parallelism: u32,
		pwd: *const c_void, pwd_len: isize,
		salt: *const c_void, salt_len: isize,
		hash: *mut c_void, hash_len: isize
	) -> c_int;
	
	// Cipher and MAC
	fn crypto_stream_chacha20_xor_ic(buffer: *mut c_uchar, data: *const c_uchar, data_len: c_ulonglong, nonce: *const c_uchar, block: u64, key: *const c_uchar) -> c_int;
	fn crypto_onetimeauth_poly1305(mac: *mut c_uchar, data: *const c_uchar, data_len: c_ulonglong,  key: *const c_uchar) -> c_int;
	
	// Helpers
	fn sodium_init() -> c_int;
	fn randombytes_buf(buffer: *mut c_void, buffer_len: isize);
	fn sodium_memcmp(a: *const c_uchar, b: *const c_uchar, len: isize) -> c_int;
}



pub fn argon2i_v13(buffer: &mut Key, password: &str, salt: &[u8], iterations: u32, memory_cost_kb: u32, parallelism: u32) -> Result<(), Error> {
	if unsafe{ sodium_init() } == -1 { panic!("Failed to init libsodium") }
	
	// Derive key
	let result = unsafe{ argon2i_hash_raw(
		iterations, memory_cost_kb, parallelism,
		password.as_ptr() as *const c_void, password.len() as isize,
		salt.as_ptr() as *const c_void, salt.len() as isize,
		buffer.as_mut_slice().as_mut_ptr() as *mut c_void, buffer.len() as isize
	) };
	
	// Check for error
	match result {
		0 => Ok(()),
		-22 | -23 | -24 => throw_err!(ErrorType::ResourceError, format!("argon2i_hash_raw returned {}", result)),
		-35 => throw_err!(ErrorType::InvalidParameter, format!("argon2i_hash_raw returned {}", result)),
		-1 | -2 | -3 | -4 | -5 | -6 | -7 | -8 | -9 | -10 | -11 | -12 | -13 | -14 | -15 | -16 | -17 | -18 | -19 | -20 | -21 | -25 | -26 | -27 | -28 | -29 | -30 =>
			throw_err!(ErrorType::Unsupported, format!("argon2i_hash_raw returned {}", result)),
		_ => throw_err!(ErrorType::Other(format!("argon2i_hash_raw returned {}", result)))
	}
}



pub fn chacha20_xor(to_xor: &mut[u8], state_byte_offset: u64, key: &Key, nonce: &[u8]) -> Result<(), Error> {
	if unsafe{ sodium_init() } == -1 { panic!("Failed to init libsodium") }
	
	// Validate input
	if key.len() != 32 { throw_err!(ErrorType::InvalidParameter, format!("The key-length is invalid ({} bytes instead of 32)", key.len())) }
	if nonce.len() != 8 { throw_err!(ErrorType::InvalidParameter, format!("The nonce-length is invalid ({} bytes instead of 8)", nonce.len())) }
	
	// Compute the aligned boundaries and initialize position-indicator
	let (skip_left, mut current_block, mut to_xor_pos) = {
		let aligned_offset = (state_byte_offset / 64u64) * 64u64;
		((state_byte_offset - aligned_offset) as usize, aligned_offset / 64u64, 0)
	};
	
	// Process first partial block
	{
		let to_process = std::cmp::min(64 - skip_left, to_xor.len());
		unsafe{ crypto_stream_chacha20_xor_ic(
			to_xor.as_mut_ptr() as *mut c_uchar, to_xor.as_ptr() as *const c_uchar,
			to_process as c_ulonglong, nonce.as_ptr() as *const c_uchar, current_block, key.as_ptr()
		) };
		to_xor_pos += to_process;
		current_block += 1;
	}
	
	// Process the remaining blocks
	while to_xor_pos < to_xor.len() {
		let to_process = std::cmp::min(64, to_xor.len() - to_xor_pos);
		unsafe{ crypto_stream_chacha20_xor_ic(
			to_xor[to_xor_pos ..].as_mut_ptr() as *mut c_uchar, to_xor[to_xor_pos ..].as_ptr() as *const c_uchar,
			to_process as c_ulonglong, nonce.as_ptr() as *const c_uchar, current_block, key.as_ptr()
		)};
		to_xor_pos += to_process;
		current_block += 1;
	}
	
	Ok(())
}



pub fn poly1305(buffer: &mut[u8], data: &[u8], key: &Key) -> Result<(), Error> {
	if unsafe{ sodium_init() } == -1 { panic!("Failed to init libsodium") }
	
	// Validate input
	if buffer.len() < 16 { throw_err!(ErrorType::InvalidParameter, format!("The target-buffer is too small ({} bytes instead of 16)", buffer.len())) }
	if key.len() != 32 { throw_err!(ErrorType::InvalidParameter, format!("The key-length is invalid ({} bytes instead of 32)", buffer.len())) }
	
	// Compute MAC
	unsafe{ crypto_onetimeauth_poly1305(buffer.as_mut_ptr() as *mut c_uchar, data.as_ptr() as *const c_uchar, data.len() as c_ulonglong, key.as_ptr()); }
	Ok(())
}



pub fn random(buffer: &mut[u8]) {
	if unsafe{ sodium_init() } == -1 { panic!("Failed to init libsodium") }
	
	unsafe{ randombytes_buf(buffer.as_mut_ptr() as *mut c_void, buffer.len() as isize); }
}



pub fn compare_constant_time(data0: &[u8], data1: &[u8]) -> bool {
	if unsafe{ sodium_init() } == -1 { panic!("Failed to init libsodium") }
	
	if data0.len() != data1.len() { return false }
	(unsafe{ sodium_memcmp(data0.as_ptr() as *const c_uchar, data1.as_ptr() as *const c_uchar, data0.len() as isize) } == 0)
}



pub fn erase(buffer: &mut[u8]) {
	for i in 0..buffer.len() {
		unsafe{ std::ptr::write_volatile(&mut buffer[i], 0x58) } // Will not be optimized away
	}
}