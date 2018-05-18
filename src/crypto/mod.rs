pub mod libsodium;
pub mod pbkdf;
pub mod kdf;
pub mod auth_enc;

use super::asn1_der;
use super::asn1_der::{ FromDerEncoded, FromDerObject, IntoDerObject };
use super::{ Error, CpError };

pub use self::libsodium::{ Key, random };
pub use self::pbkdf::Pbkdf;
pub use self::kdf::Kdf;
pub use self::auth_enc::AuthEnc;



static VERSIONS: [&str; 1] = ["de.KizzyCode.CryptoPipe.v1"]; // The current-version needs to be at index 0
pub struct StreamInstance {
	pub pbkdf: Box<Pbkdf>,
	pub kdf: Box<Kdf>,
	pub auth_enc: Box<AuthEnc>
}
impl StreamInstance {
	/// Initializes the stream-info with the given algorithm and parameters
	pub fn new(pbkdf: Box<Pbkdf>, kdf: Box<Kdf>, auth_enc: Box<AuthEnc>) -> Self {
		StreamInstance{ pbkdf, kdf, auth_enc }
	}
	
	/// Returns `Ok(Some(header_length))` if the length was decoded successfully or
	/// `Ok(None)` if there are not enough bytes to decode the length or
	/// `Err(error)` on error
	pub fn try_parse_length(data: &[u8]) -> Result<Option<usize>, Error<CpError>> {
		if let Some((length, _)) = try_err!(asn1_der::der::try_decode_length(data), CpError::InvalidData) { Ok(Some(length)) }
			else { Ok(None) }
	}
	
	/// Parses the stream-info from a serialized representation
	pub fn from_serialized(serialized: Vec<u8>) -> Result<Self, Error<CpError>> {
		// DER-decode data
		let der_object: asn1_der::DerObject = try_err!(asn1_der::DerObject::from_der_encoded(serialized), CpError::InvalidData);
		
		// Parse sequence
		let sequence: Vec<asn1_der::DerObject> = try_err!(Vec::<asn1_der::DerObject>::from_der_object(der_object), CpError::InvalidData);
		if sequence.len() < 4 { throw_err!(CpError::InvalidData) }
		
		// Validate version
		let version: String = try_err!(String::from_der_object(sequence[0].clone()), CpError::InvalidData);
		if !VERSIONS.contains(&version.as_str()) { throw_err!(CpError::Unsupported, format!("Unsupported CryptoPipe-stream-version ({})", version)) }
		
		// Load instances
		Ok(StreamInstance {
			pbkdf: try_err!(pbkdf::from_serialized(sequence[1].clone())),
			kdf: try_err!(kdf::from_serialized(sequence[2].clone())),
			auth_enc: try_err!(auth_enc::from_serialized(sequence[3].clone()))
		})
	}
	
	/// Serializes this stream-info
	pub fn as_serialized(&self) -> asn1_der::DerObject {
		let sequence: Vec<asn1_der::DerObject> = vec![
			VERSIONS[0].to_string().into_der_object(),
			self.pbkdf.serialize(),
			self.kdf.serialize(),
			self.auth_enc.serialize()
		];
		sequence.into_der_object()
	}
}