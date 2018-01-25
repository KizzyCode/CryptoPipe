use std;

#[derive(Debug)]
/// The error-type
pub enum ErrorType {
	/// Invalid data (invalid encoding, integrity error etc.)
	InvalidData,
	/// Not enough resources to process data
	ResourceError,
	
	/// Other IO-error
	IOError(std::io::Error),
	
	/// Invalid parameter (not in range, does not make sense etc.)
	InvalidParameter,
	/// The parameter might be valid but us unsupported
	Unsupported,
	
	/// CLI-error
	CliError,
	
	/// Another error
	Other(String)
}
impl From<std::io::Error> for ErrorType {
	fn from(error: std::io::Error) -> Self {
		ErrorType::IOError(error)
	}
}
impl From<std::str::Utf8Error> for ErrorType {
	fn from(_: std::str::Utf8Error) -> Self {
		ErrorType::InvalidData
	}
}
impl From<std::num::ParseIntError> for ErrorType {
	fn from(_: std::num::ParseIntError) -> Self {
		ErrorType::InvalidData
	}
}
impl PartialEq for ErrorType {
	fn eq(&self, other: &Self) -> bool {
		let self_string = format!("{:?}", self);
		let other_string = format!("{:?}", other);
		self_string == other_string
	}
}
impl Eq for ErrorType {}


#[derive(Debug)]
/// An error-describing structure containing the error and it's file/line
pub struct Error {
	/// The error-type
	pub error_type: ErrorType,
	/// Description
	pub description: String,
	/// The file in which the error occurred
	pub file: &'static str,
	/// The line on which the error occurred
	pub line: u32
}
impl Error {
	pub fn as_string(&self) -> String {
		if !self.description.is_empty() { self.description.clone() }
			else { format!("{:?}", self) }
	}
}


#[macro_export]
/// Create an error from an `ErrorType`
macro_rules! new_err {
	($error_type:expr, $description:expr) => (Err($crate::error::Error {
		error_type: $error_type,
		description: $description,
		file: file!(),
		line: line!()
	}));
	($error_type:expr) => (new_err!($error_type, "".to_owned()));
}

#[macro_export]
/// Create an error from an `ErrorType`
macro_rules! throw_err {
	($error_type:expr, $description:expr) => (return new_err!($error_type, $description));
	($error_type:expr) => (throw_err!($error_type, "".to_owned()));
}

#[macro_export]
/// Tries an expression and propagates an eventual error
macro_rules! try_err {
	($code:expr, $description:expr) => (match $code {
		Ok(result) => result,
		Err(error) => throw_err!($crate::error::ErrorType::from(error), $description)
	});
	($code:expr) => (try_err!($code, "".to_owned()))
}