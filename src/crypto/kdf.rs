use super::super::{ Error, CpError };
use super::libsodium;
use super::super::asn1_der;
use super::super::asn1_der::{ FromDerObject, IntoDerObject };

pub trait Kdf {
	/// Derives a key from a base-key
	fn derive(&self, base_key: &libsodium::Key, info: &[u8]) -> Result<libsodium::Key, Error<CpError>>;
	
	/// Returns a string specifying the algorithm-instance
	fn algorithm(&self) -> &'static str;
	
	/// Serializes the algorithm-instance
	fn serialize(&self) -> asn1_der::DerObject {
		let sequence: Vec<asn1_der::DerObject> = vec![self.algorithm().to_string().into_der_object()];
		sequence.into_der_object()
	}
}

pub fn from_serialized(serialized: asn1_der::DerObject) -> Result<Box<Kdf>, Error<CpError>> {
	// Try to parse info
	let info: Vec<asn1_der::DerObject> = try_err!(Vec::<asn1_der::DerObject>::from_der_object(serialized), CpError::InvalidData);
	if info.len() < 1 { throw_err!(CpError::InvalidData) }
	
	// Parse and select algorithm
	match (try_err!(String::from_der_object(info[0].clone()), CpError::InvalidData) as String).as_str() {
		HMAC_SHA2_512_ID => Ok(HmacSha2512::new()),
		_ => throw_err!(CpError::Unsupported)
	}
}



pub const HMAC_SHA2_512_ID: &str = "HMAC-SHA2-512";
pub struct HmacSha2512;
impl HmacSha2512 {
	pub fn new() -> Box<Self> {
		Box::new(HmacSha2512)
	}
}
impl Kdf for HmacSha2512 {
	fn derive(&self, base_key: &libsodium::Key, info: &[u8]) -> Result<libsodium::Key, Error<CpError>> {
		let mut derived_key = libsodium::Key::new(64);
		for byte in derived_key.as_mut_slice().iter_mut() { *byte = 0x00; }
		
		try_err!(libsodium::hmac_sha2_512(derived_key.as_mut_slice(), &info, base_key));
		try_err!(derived_key.truncate(32));
		Ok(derived_key)
	}
	
	fn algorithm(&self) -> &'static str {
		HMAC_SHA2_512_ID
	}
}