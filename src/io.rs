use std;
use super::error::{ Error, ErrorType };

pub trait Io {
	fn read_chunk(&mut self, chunk_buffer: &mut[u8]) -> Result<(usize, bool), Error>;
	fn write_chunk(&mut self, data: &[u8]) -> Result<(), Error>;
	fn read_exact(&mut self, buffer: &mut[u8]) -> Result<(), Error>;
	fn write_exact(&mut self, data: &[u8]) -> Result<(), Error>;
}



pub struct Stdio {
	stdin: std::io::Stdin,
	stdout: std::io::Stdout,
	next_chunk: (Vec<u8>, usize)
}
impl Stdio {
	pub fn new() -> Self {
		Stdio{ stdin: std::io::stdin(), stdout: std::io::stdout(), next_chunk: (vec![0u8; 0], std::usize::MAX) }
	}
	
	fn read_next_chunk(&mut self, chunk_size: usize) -> Result<(), Error> {
		use std::io::Read;
		
		// Reset chunk
		self.next_chunk.0.resize(chunk_size, 0x00);
		self.next_chunk.1 = 0;
		
		// Read until EOF or any error other than `ErrorKind::Interrupted`
		'read_loop: loop {
			let bytes_read = match self.stdin.read(&mut self.next_chunk.0[self.next_chunk.1 ..]) {
				Ok(bytes_read) => bytes_read,
				Err(ref error) if error.kind() == std::io::ErrorKind::Interrupted => continue 'read_loop,
				Err(error) => throw_err!(ErrorType::from(error), "Failed to read from stdin".to_string())
			};
			if bytes_read > 0 { self.next_chunk.1 += bytes_read }
				else { return Ok(()) }
		}
	}
}
impl Io for Stdio {
	fn read_chunk(&mut self, chunk_buffer: &mut[u8]) -> Result<(usize, bool), Error> {
		// Prefetch chunk
		if self.next_chunk.1 == std::usize::MAX { self.read_next_chunk(chunk_buffer.len())? }
		
		// Copy the data of the prefetched chunk to `buffer`
		let to_copy = self.next_chunk.1;
		chunk_buffer[.. to_copy].copy_from_slice(&self.next_chunk.0[.. to_copy]);
		
		// Prefetch next chunk and return `true` if there are no data left (=> the current chunk was the last chunk)
		self.read_next_chunk(chunk_buffer.len())?;
		Ok((to_copy, self.next_chunk.1 == 0))
	}
	fn write_chunk(&mut self, data: &[u8]) -> Result<(), Error> {
		self.write_exact(data)
	}
	
	fn read_exact(&mut self, buffer: &mut[u8]) -> Result<(), Error> {
		use std::io::Read;
		try_err!(self.stdin.read_exact(buffer), "Failed to read from stdin".to_owned());
		Ok(())
	}
	fn write_exact(&mut self, data: &[u8]) -> Result<(), Error> {
		use std::io::Write;
		try_err!(self.stdout.write_all(data), "Failed to write to stdout".to_owned());
		try_err!(self.stdout.flush());
		Ok(())
	}
}