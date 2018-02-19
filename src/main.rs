extern crate asn1_der;

#[macro_use] mod error;
#[cfg(test)] mod tests;
mod cli;
mod crypto;
mod io;
mod stream;

use std::env::var;
use error::{ Error, ErrorType };


/// Prints `message` to stderr and terminates with `code`
fn die(text: &str, code: i32) -> ! {
	eprintln!("*** CryptoPipe {} ***\n", env!("CARGO_PKG_VERSION"));
	eprint!("{}\n", text.trim());
	std::process::exit(code)
}

/// Prints the license-information to stderr and terminates with `0`
fn die_licenses() -> ! {
	die(include_str!("texts/licenses.txt"), 0)
}

/// Prints `error` and the help-text to stderr and terminates with `1`
fn die_error_help(error: &str) -> ! {
	// Replace `%PROGRAM_NAME%` and build message
	let program_name = std::env::args().next().unwrap_or("<program_name>".to_owned());
	let text = format!("{}\n\n{}", error, include_str!("texts/help.txt").replace("%PROGRAM_NAME%", &program_name));
	die(&text, 1)
}

/// Prints the help-text to stderr and terminates with `0`
fn die_help() -> ! {
	// Replace `%PROGRAM_NAME%`
	let program_name = std::env::args().next().unwrap_or("<program_name>".to_owned());
	let text = include_str!("texts/help.txt").replace("%PROGRAM_NAME%", &program_name);
	die(&text, 0)
}



/// Parses the CLI-verb and it's switches
fn parse_cli() -> Result<cli::Verb, Error> {
	// CLI-parse-helpers
	fn parse_string(raw: &str) -> Result<String, Error> {
		Ok(raw.to_string())
	}
	fn parse_u32(raw: &str) -> Result<u32, Error> {
		if let Ok(value) = raw.parse::<u32>() { Ok(value) }
			else { throw_err!(ErrorType::CliError, format!("Invalid parameter \"{}\" (must be a positive integer)", raw)) }
	}
	
	// CLI-verbs
	let verbs = vec![
		cli::Verb::new("help", vec![]),
		cli::Verb::new("licenses", vec![]),
		cli::Verb::new("encrypt", vec![
			Box::new(cli::TypedSwitch::new("--password=", Some(String::new()), &parse_string)),
			
			Box::new(cli::TypedSwitch::new("--pbkdf-time-cost=", Some(8u32), &parse_u32)),
			Box::new(cli::TypedSwitch::new("--pbkdf-memory-cost=", Some(256u32), &parse_u32)),
			Box::new(cli::TypedSwitch::new("--pbkdf-parallelism=", Some(4u32), &parse_u32)),
			
			Box::new(cli::TypedSwitch::new("--pbkdf-algo=", Some("Argon2i".to_string()), &parse_string)),
			Box::new(cli::TypedSwitch::new("--kdf-algo=", Some("HMAC-SHA512".to_string()), &parse_string)),
			Box::new(cli::TypedSwitch::new("--auth-enc-algo=", Some("ChaChaPoly".to_string()), &parse_string)),
		]),
		cli::Verb::new("decrypt", vec![
			Box::new(cli::TypedSwitch::new("--password=", Some(String::new()), &parse_string))
		])
	];
	cli::parse(verbs)
}

/// Get the password either from the "--password="-CLI-switch or from the "CRYPTO_PIPE_PASSWORD"-
/// environment-variable
fn get_password(verb: &cli::Verb) -> Result<String, Error> {
	// Check if CLI-switch is set
	let password = verb.get_switch::<String>("--password=")?;
	if !password.is_empty() { return Ok(password) }
	
	// Try to read environment-var
	if let Ok(password) = var("CRYPTO_PIPE_PASSWORD") { return Ok(password) }
	throw_err!(ErrorType::CliError, "You either need to set the \"--password=\"-switch or the \"CRYPTO_PIPE_PASSWORD\"-environment-variable".to_string())
}

/// Reads and executes the verb
fn run() -> Result<(), Error> {
	// Read and process verb
	let verb = parse_cli()?;
	
	match verb.name() {
		"help" => die_help(),
		"licenses" => die_licenses(),
		"seal" => {
			// Read PBKDF-params
			let pbkdf_params = (
				verb.get_switch::<u32>("--pbkdf-time-cost=")?,
				verb.get_switch::<u32>("--pbkdf-memory-cost=")?,
				verb.get_switch::<u32>("--pbkdf-parallelism=")?
			);
			
			// Create stream-instance
			let stream_instance = {
				// Create algorithm-instances
				let pbkdf = match verb.get_switch::<String>("--pbkdf-algo=")?.as_str() {
					"Argon2i" => crypto::pbkdf::Argon2i::new(pbkdf_params.0, pbkdf_params.1, pbkdf_params.2),
					algo => throw_err!(ErrorType::CliError, format!("Unsupported PBKDF-algorithm \"{}\"", algo))
				};
				let kdf = match verb.get_switch::<String>("--kdf-algo=")?.as_str() {
					"HMAC-SHA512" => crypto::kdf::HmacSha2512::new(),
					algo => throw_err!(ErrorType::CliError, format!("Unsupported KDF-algorithm \"{}\"", algo))
				};
				let auth_enc = match verb.get_switch::<String>("--auth-enc-algo=")?.as_str() {
					"ChaChaPoly" => crypto::auth_enc::ChaCha20Poly1305::new(),
					algo => throw_err!(ErrorType::CliError, format!("Unsupported authenticated-encryption-algorithm \"{}\"", algo))
				};
				crypto::StreamInstance::new(pbkdf, kdf, auth_enc)
			};
			
			// Start runloop
			stream::Encryptor::new(get_password(&verb)?, &mut io::Stdio::new(), stream_instance)?.runloop()
		},
		"open" => {
			// Start runloop
			stream::Decryptor::new(get_password(&verb)?, &mut io::Stdio::new())?.runloop()
		},
		_ => panic!("Should never happen")
	}
}


fn main() {
	// "Catch" all errors to print them readable
	match run() {
		Ok(result) => result,
		Err(error) => if error.error_type == ErrorType::CliError { die_error_help(&error.as_string()) }
			else { die(&error.as_string(), 2) }
	}
}