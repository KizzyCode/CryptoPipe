use std;
use super::asn1_der;

#[derive(Debug, Clone, Eq, PartialEq)]
/// The error-type
pub enum CpError {
	/// Invalid data (invalid encoding, integrity error etc.)
	InvalidData,
	/// Not enough resources to process data
	ResourceError,
	
	/// Other IO-error
	IOError(std::io::ErrorKind, String),
	
	/// Invalid parameter (not in range, does not make sense etc.)
	InvalidParameter,
	/// The parameter might be valid but us unsupported
	Unsupported,
	
	/// CLI-error
	CliError,
	
	Other(String)
}
impl From<std::io::Error> for CpError {
	fn from(error: std::io::Error) -> Self {
		use std::error::Error;
		CpError::IOError(error.kind(), format!("{}", error.description()))
	}
}
impl From<std::io::ErrorKind> for CpError {
	fn from(kind: std::io::ErrorKind) -> Self {
		CpError::IOError(kind, format!("{:?}", kind))
	}
}
impl From<std::str::Utf8Error> for CpError {
	fn from(_: std::str::Utf8Error) -> Self {
		CpError::InvalidData
	}
}
impl From<std::num::ParseIntError> for CpError {
	fn from(_: std::num::ParseIntError) -> Self {
		CpError::InvalidData
	}
}
impl From<asn1_der::Error> for CpError {
	fn from(_: asn1_der::Error) -> CpError {
		CpError::InvalidData
	}
}