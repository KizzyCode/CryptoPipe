#[macro_use] mod error;
mod cli;
mod io;
mod libsodium;
mod kdf;
mod crypto_stream;
#[cfg(test)] mod tests;

use std::env::var;
use kdf::PbkdfInfo;
use crypto_stream::{ Encryptor, Decryptor };
use error::{ Error, ErrorType };



fn die(message: &str, code: i32) -> ! {
	eprintln!("*** CryptoPipe {} ***\n", include_str!("version.txt"));
	eprint!("{}\n", message.trim());
	std::process::exit(code)
}


fn licenses() -> ! {
	die(include_str!("licenses.txt"), 0)
}

fn help(msg: &str) -> ! {
	// Build message
	let mut message = msg.to_owned() + "\n\n";
	message += include_str!("help.txt");
	
	// Replace `%PROGRAM_NAME%`
	let program_name = std::env::args().next().unwrap_or("<program_name>".to_owned());
	message = message.replace("%PROGRAM_NAME%", &program_name);
	
	die(&message, if msg != "" { 1 } else { 0 })
}


fn unwrap_or_die<T>(result: Result<T, Error>) -> T {
	match result {
		Ok(result) => result,
		Err(error) => if error.error_type == ErrorType::CliError { help(&error.as_string()) }
			else { die(&error.as_string(), 2) }
	}
}

fn expect_environment_password() -> Result<String, Error> {
	if let Ok(password) = var("CRYPTO_STREAM_PASSWORD") { return Ok(password) }
	throw_err!(ErrorType::CliError, "You either need to set the \"--password=\"-switch or the \"CRYPTO_STREAM_PASSWORD\"-environment-variable".to_owned())
}



fn main() {
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
			Box::new(cli::TypedSwitch::new("--pbkdf-iterations=", Some(8u32), &parse_u32)),
			Box::new(cli::TypedSwitch::new("--pbkdf-memory-requirements=", Some(256u32 * 1024), &parse_u32)),
			Box::new(cli::TypedSwitch::new("--pbkdf-parallelism=", Some(4u32), &parse_u32)),
		]),
		cli::Verb::new("decrypt", vec![
			Box::new(cli::TypedSwitch::new("--password=", Some(String::new()), &parse_string)),
			Box::new(cli::TypedSwitch::new("--pbkdf-iterations=", Some(8u32), &parse_u32)),
			Box::new(cli::TypedSwitch::new("--pbkdf-memory-requirements=", Some(256u32 * 1024), &parse_u32)),
			Box::new(cli::TypedSwitch::new("--pbkdf-parallelism=", Some(4u32), &parse_u32)),
		])
	];
	let verb = unwrap_or_die(cli::parse(verbs));
	
	// Switch based on verb
	match verb.name() {
		"help" => help(""),
		"licenses" => licenses(),
		"encrypt" => {
			// Get password
			let mut password = unwrap_or_die(verb.get_switch::<String>("--password="));
			if password.is_empty() { password = unwrap_or_die(expect_environment_password()) }
			
			// Build PBKDF-info
			let pbkdf_info = PbkdfInfo::new(
				unwrap_or_die(verb.get_switch::<u32>("--pbkdf-iterations=")),
				unwrap_or_die(verb.get_switch::<u32>("--pbkdf-memory-requirements=")),
				unwrap_or_die(verb.get_switch::<u32>("--pbkdf-parallelism="))
			);
			
			// Create STDIO-handle an run encryptor
			let mut stdio = io::StdIO::new(crypto_stream::CHUNK_DATA_SIZE);
			unwrap_or_die(Encryptor::new(&mut stdio).runloop(password, pbkdf_info));
		},
		"decrypt" => {
			// Get password
			let mut password = unwrap_or_die(verb.get_switch::<String>("--password="));
			if password.is_empty() { password = unwrap_or_die(expect_environment_password()) }
			
			// Create STDIO-handle an run decryptor
			let mut stdio = io::StdIO::new(crypto_stream::CHUNK_DATA_SIZE + crypto_stream::MAC_SIZE);
			unwrap_or_die(Decryptor::new(&mut stdio).runloop(password));
		},
		_ => panic!("Should never happen")
	}
}