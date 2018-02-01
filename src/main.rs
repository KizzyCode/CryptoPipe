#[macro_use] mod error;
mod cli;
mod libsodium;
mod crypto;
mod constants;
mod io_runloop;
mod io_processor;

#[cfg(test)] mod tests;

use std::env::var;
use error::{ Error, ErrorType };



fn die(message: &str, code: i32) -> ! {
	eprintln!("*** CryptoPipe {} ***\n", env!("CARGO_PKG_VERSION"));
	eprint!("{}\n", message.trim());
	std::process::exit(code)
}

fn licenses() -> ! {
	die(include_str!("texts/licenses.txt"), 0)
}

fn help(msg: &str) -> ! {
	// Build message
	let mut message = msg.to_owned() + "\n\n";
	message += include_str!("texts/help.txt");
	
	// Replace `%PROGRAM_NAME%`
	let program_name = std::env::args().next().unwrap_or("<program_name>".to_owned());
	message = message.replace("%PROGRAM_NAME%", &program_name);
	
	die(&message, if msg != "" { 1 } else { 0 })
}



fn get_environment_password() -> Result<String, Error> {
	if let Ok(password) = var("CRYPTO_PIPE_PASSWORD") { return Ok(password) }
	throw_err!(ErrorType::CliError, "You either need to set the \"--password=\"-switch or the \"CRYPTO_PIPE_PASSWORD\"-environment-variable".to_owned())
}

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
	cli::parse(verbs)
}

fn main() {
	// "Catch" all errors to print them readable
	fn safe() -> Result<(), Error> {
		// Read and process verb
		let verb = parse_cli()?;
		
		match verb.name() {
			"help" => help(""),
			"licenses" => licenses(),
			"encrypt" => {
				// Get password
				let mut password = verb.get_switch::<String>("--password=")?;
				if password.is_empty() { password = get_environment_password()? }
				
				// Parse PBKDF-parameters
				let pbkdf_iterations = verb.get_switch::<u32>("--pbkdf-iterations=")?;
				let pbkdf_memory_requirements = verb.get_switch::<u32>("--pbkdf-memory-requirements=")?;
				let pbkdf_parallelism = verb.get_switch::<u32>("--pbkdf-parallelism=")?;
				
				// Start runloop
				let io_processor = Box::new(io_processor::IoEncryptor::new(password, pbkdf_iterations, pbkdf_memory_requirements, pbkdf_parallelism)?);
				io_runloop::IoRunloop::new(io_processor, Box::new(io_runloop::Stdio::new())).start()
			},
			"decrypt" => {
				// Get password
				let mut password = verb.get_switch::<String>("--password=")?;
				if password.is_empty() { password = get_environment_password()? }
				
				// Start runloop
				let io_processor = Box::new(io_processor::IoDecryptor::new(password));
				io_runloop::IoRunloop::new(io_processor, Box::new(io_runloop::Stdio::new())).start()
			},
			_ => panic!("Should never happen")
		}
	}
	match safe() {
		Ok(result) => result,
		Err(error) => if error.error_type == ErrorType::CliError { help(&error.as_string()) }
			else { die(&error.as_string(), 2) }
	}
}