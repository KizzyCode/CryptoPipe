#[macro_use] extern crate etrace;
extern crate asn1_der;
extern crate cli;

mod error;
#[cfg(test)] mod tests;
mod crypto;
mod io;
mod stream;

use std::env::var;
use std::collections::HashMap;
use error::CpError;
use etrace::Error;



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
fn parse_cli() -> Result<cli::CliResult, Error<CpError>> {
	let verbs = vec![
		("help", cli::VerbParser::new()),
		("licenses", cli::VerbParser::new()),
		("seal", cli::VerbParser::with_switches(vec![
			("--password=", cli::SwitchParser::with_default(String::new(), &cli::parsers::parse_from_str::<String>)),
			
			("--pbkdf-time-cost=", cli::SwitchParser::with_default(12u32, &cli::parsers::parse_from_str::<u32>)),
			("--pbkdf-memory-cost=", cli::SwitchParser::with_default(512u32, &cli::parsers::parse_from_str::<u32>)),
			("--pbkdf-parallelism=", cli::SwitchParser::with_default(4u32, &cli::parsers::parse_from_str::<u32>)),
			
			("--pbkdf-algo=", cli::SwitchParser::with_default("Argon2i".to_string(), &cli::parsers::parse_from_str::<String>)),
			("--kdf-algo=", cli::SwitchParser::with_default("HMAC-SHA512".to_string(), &cli::parsers::parse_from_str::<String>)),
			("--auth-enc-algo=", cli::SwitchParser::with_default("ChaChaPoly".to_string(), &cli::parsers::parse_from_str::<String>))
		])),
		("open", cli::VerbParser::with_switches(vec![
			("--password=", cli::SwitchParser::with_default(String::new(), &cli::parsers::parse_from_str::<String>))
		]))
	];
	Ok(try_err!(cli::parse_verbs(verbs), CpError::CliError, "Failed to parse CLI-arguments"))
}

/// Get the password either from the "--password="-CLI-switch or from the "CRYPTO_PIPE_PASSWORD"-
/// environment-variable
fn get_password(switches: &mut HashMap<String, cli::SwitchParser>) -> Result<String, Error<CpError>> {
	// Get switch-value
	let password = try_err!(switches.remove("--password=").unwrap().into_value::<String>(), CpError::CliError, "Failed to parse \"--password=\"");
	if !password.is_empty() { return Ok(password) }
	
	// Try to read environment-var
	if let Ok(password) = var("CRYPTO_PIPE_PASSWORD") { return Ok(password) }
	throw_err!(CpError::CliError, "You either need to set the \"--password=\"-switch or the \"CRYPTO_PIPE_PASSWORD\"-environment-variable")
}

/// Reads and executes the verb
fn run() -> Result<(), Error<CpError>> {
	// Read and process CLI-input
	let (verb, mut switches): (String, HashMap<String, cli::SwitchParser>) = try_err!(parse_cli());
	
	match verb.as_str() {
		"help" => die_help(),
		"licenses" => die_licenses(),
		"seal" => {
			// Read PBKDF-params
			let pbkdf_params: (u32, u32, u32) = (
				*try_err!(switches["--pbkdf-time-cost="].get::<u32>(), CpError::CliError, "Failed to parse \"--pbkdf-time-cost=\""),
				*try_err!(switches["--pbkdf-memory-cost="].get::<u32>(), CpError::CliError, "Failed to parse \"--pbkdf-memory-cost=\""),
				*try_err!(switches["--pbkdf-parallelism="].get::<u32>(), CpError::CliError, "Failed to parse \"--pbkdf-parallelism=\"")
			);
			
			// Create stream-instance
			let stream_instance = {
				// Create algorithm-instances
				let pbkdf = match try_err!(switches["--pbkdf-algo="].get::<String>(), CpError::CliError, "Failed to parse \"--pbkdf-algo=\"").as_str() {
					"Argon2i" => crypto::pbkdf::Argon2i::new(pbkdf_params.0, pbkdf_params.1, pbkdf_params.2),
					algo => throw_err!(CpError::CliError, format!("Unsupported PBKDF-algorithm \"{}\"", algo))
				};
				let kdf = match try_err!(switches["--kdf-algo="].get::<String>(), CpError::CliError, "Failed to parse \"--kdf-algo=\"").as_str() {
					"HMAC-SHA512" => crypto::kdf::HmacSha2512::new(),
					algo => throw_err!(CpError::CliError, format!("Unsupported KDF-algorithm \"{}\"", algo))
				};
				let auth_enc = match try_err!(switches["--auth-enc-algo="].get::<String>(), CpError::CliError, "Failed to parse \"--auth-enc-algo=\"").as_str() {
					"ChaChaPoly" => crypto::auth_enc::ChaCha20Poly1305::new(),
					algo => throw_err!(CpError::CliError, format!("Unsupported authenticated-encryption-algorithm \"{}\"", algo))
				};
				crypto::StreamInstance::new(pbkdf, kdf, auth_enc)
			};
			
			// Start runloop
			try_err!(stream::Encryptor::new(try_err!(get_password(&mut switches)), &mut io::Stdio::new(), stream_instance)).runloop()
		},
		"open" => {
			// Start runloop
			try_err!(stream::Decryptor::new(try_err!(get_password(&mut switches)), &mut io::Stdio::new())).runloop()
		},
		_ => unreachable!()
	}
}

fn main() {
	// "Catch" all errors to print them readable
	match run() {
		Ok(result) => result,
		Err(error) => die_error_help(&error.to_string())
	}
}