use std::fmt::{ Debug, Formatter, Error as FmtError };
use std::env::args;
use std::any::Any;
use super::error::{ Error, ErrorType };

pub trait Switch: Debug {
	fn parse(&mut self, arguments: &mut Vec<String>) -> Result<(), Error>;
	fn name(&self) -> &str;
	fn value(&self) -> &Any;
}

pub struct TypedSwitch<'a, T: 'static + Clone + Debug> {
	switch: String,
	value: Option<T>,
	parser: &'a Fn(&str) -> Result<T, Error>
}
impl<'a, T: Clone + Debug> TypedSwitch<'a, T> {
	pub fn new<S: ToString>(name: S, default: Option<T>, parser: &'a Fn(&str) -> Result<T, Error>) -> Self {
		TypedSwitch{ switch: name.to_string(), value: default, parser }
	}
}
impl<'a, T: Clone + Debug> Switch for TypedSwitch<'a, T> {
	fn parse(&mut self, arguments: &mut Vec<String>) -> Result<(), Error> {
		// Iterate over arguments
		for i in 0..arguments.len() {
			if arguments[i].starts_with(&self.switch) {
				// Extract value after switch name and parse the raw string-value
				{
					let raw = arguments[i].split_at(self.switch.len()).1;
					self.value = Some((self.parser)(raw)?);
				}
				
				// Remove parsed argument and break
				arguments.remove(i);
				break
			}
		}
		
		// Check if we parsed an argument (or had a default argument)
		if self.value.is_none() { throw_err!(ErrorType::CliError, format!("Required switch \"{}\" is missing", self.name())) }
		Ok(())
	}
	fn name(&self) -> &str {
		&self.switch
	}
	fn value(&self) -> &Any {
		self.value.as_ref().unwrap()
	}
}
impl<'a, T: Clone + Debug> Debug for TypedSwitch<'a, T> {
	fn fmt(&self, formatter: &mut Formatter) -> Result<(), FmtError> {
		write!(formatter, "TypedSwitch {{ switch: {:?}, value: {:?} }}", &self.switch, &self.value)
	}
}

#[derive(Debug)]
pub struct Verb {
	verb: String,
	switches: Vec<Box<Switch>>
}
impl Verb {
	pub fn new<S: ToString>(verb: S, switches: Vec<Box<Switch>>) -> Self {
		Verb{ verb: verb.to_string(), switches }
	}
	
	pub fn parse(&mut self, arguments: &mut Vec<String>) -> Result<(), Error> {
		for switch in self.switches.iter_mut() { switch.parse(arguments)? }
		Ok(())
	}
	
	pub fn name(&self) -> &str {
		&self.verb
	}
	
	pub fn get_switch<T: 'static + Clone>(&self, name: &str) -> Result<T, Error> {
		for switch in self.switches.iter() {
			if switch.name() == name {
				if let Some(casted_value) = switch.value().downcast_ref::<T>() { return Ok(casted_value.clone()) }
					else { throw_err!(ErrorType::Unsupported) }
			}
		}
		throw_err!(ErrorType::CliError)
	}
}

pub fn parse(verbs: Vec<Verb>) -> Result<Verb, Error> {
	// Gather all arguments and convert them to strings
	let mut arguments: Vec<String> = args().collect();
	if arguments.len() < 2 { throw_err!(ErrorType::CliError, "No verb specified".to_string()) }
	
	// Determine verb
	for mut verb in verbs {
		if &arguments[1] == verb.name() {
			// Parse verb
			verb.parse(&mut arguments)?;
			if arguments.len() > 2 { throw_err!(ErrorType::CliError, format!("Invalid switch \"{}\"", &arguments[2])) }
			return Ok(verb)
		}
	}
	throw_err!(ErrorType::CliError, format!("Unknown verb \"{}\"", arguments[1]))
}