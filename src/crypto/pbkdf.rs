use std;
use super::super::{ Error, CpError };
use super::libsodium;
use super::super::asn1_der;
use super::super::asn1_der::FromDer;

pub trait Pbkdf {
	/// Derives a key from the provided password and erases the password afterwards
	fn derive(&self, password: String) -> Result<libsodium::Key, Error<CpError>>;
	
	/// Returns the algorithm-ID
	fn algorithm(&self) -> &str;
	
	/// Serializes the algorithm-instance
	fn serialize(&self) -> asn1_der::DerObject;
}

pub fn from_serialized(serialized: asn1_der::DerObject) -> Result<Box<Pbkdf>, Error<CpError>> {
	// Try to parse info
	let info: Vec<asn1_der::DerObject> = try_convert_err!(Vec::<asn1_der::DerObject>::from_der(serialized));
	if info.len() < 2 { throw_err!(CpError::InvalidData) }
	
	// Parse and select algorithm
	match try_convert_err!(String::from_der(info[0].clone())).as_str() {
		ARGON2I_ID => Argon2i::from_serialized(info[1].clone()),
		_ => throw_err!(CpError::Unsupported)
	}
}



pub const ARGON2I_ID: &str = "Argon2i@v1.3";
pub struct Argon2i {
	nonce: Vec<u8>,
	time_cost: u32,
	memory_cost_mib: u32,
	parallelism: u32
}
impl Argon2i {
	/// Creates a new Argon2i-PBKDF-instance with a pregenerated nonce
	pub fn with_nonce(nonce: Vec<u8>, time_cost: u32, memory_cost_mib: u32, parallelism: u32) -> Box<Pbkdf> {
		Box::new(Argon2i{ nonce, time_cost, memory_cost_mib, parallelism })
	}
	
	/// Creates a new Argon2i-PBKDF-instance with a random 256-bit-nonce
	pub fn new(time_cost: u32, memory_cost_mib: u32, parallelism: u32) -> Box<Pbkdf> {
		// Create random nonce
		let mut nonce = vec![0u8; 32];
		libsodium::random(&mut nonce);
		
		Argon2i::with_nonce(nonce, time_cost, memory_cost_mib, parallelism)
	}
	
	/// Creates a new Argon2i-PBKDF-instance from a serialized representation of the nonce and
	/// parameters
	pub fn from_serialized(parameters: asn1_der::DerObject) -> Result<Box<Pbkdf>, Error<CpError>> {
		// Try to parse parameters
		let parameters: Vec<asn1_der::DerObject> = try_convert_err!(Vec::<asn1_der::DerObject>::from_der(parameters));
		if parameters.len() < 4 { throw_err!(CpError::InvalidData) }
		
		let nonce: Vec<u8> = try_convert_err!(Vec::<u8>::from_der(parameters[0].clone()));
		let time_cost = try_err!(u64_to_u32(try_convert_err!(u64::from_der(parameters[1].clone()))));
		let memory_cost_mib = try_err!(u64_to_u32(try_convert_err!(u64::from_der(parameters[2].clone()))));
		let parallelism = try_err!(u64_to_u32(try_convert_err!(u64::from_der(parameters[3].clone()))));
		
		Ok(Argon2i::with_nonce(nonce, time_cost, memory_cost_mib, parallelism))
	}
}
impl Pbkdf for Argon2i {
	fn derive(&self, mut password: String) -> Result<libsodium::Key, Error<CpError>> {
		// Compute memory-cost in kiB
		let memory_cost_kib = try_err!(u64_to_u32((self.memory_cost_mib as u64) * 1024));
		
		// Compute master-key
		let mut key = libsodium::Key::new(32);
		try_err!(libsodium::argon2i_v13(&mut key, &password, &self.nonce, self.time_cost, memory_cost_kib, self.parallelism));
		libsodium::erase(unsafe{ password.as_bytes_mut() });
		
		Ok(key)
	}
	
	fn algorithm(&self) -> &'static str {
		ARGON2I_ID
	}
	
	fn serialize(&self) -> asn1_der::DerObject {
		// Serialize parameters
		let parameters: Vec<asn1_der::DerObject> = vec![
			self.nonce.clone().into(),
			(self.time_cost as u64).into(),
			(self.memory_cost_mib as u64).into(),
			(self.parallelism as u64).into()
		];
		
		// Create ASN.1-DER-Sequence
		let sequence: Vec<asn1_der::DerObject> = vec![
			self.algorithm().to_string().into(),
			parameters.into()
		];
		sequence.into()
	}
}



/// Helper for safe u64->u32-conversion
fn u64_to_u32(input: u64) -> Result<u32, Error<CpError>> {
	if input > std::u32::MAX as u64 { throw_err!(CpError::Unsupported) }
	Ok(input as u32)
}