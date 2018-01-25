use std::usize;
use std::io::{ stdin, stdout, Stdin, Stdout, Read, Write, ErrorKind };
use super::error::{ Error, ErrorType };

pub trait IO {
	fn read_chunk(&mut self, chunk_buffer: &mut[u8]) -> Result<(usize, bool), Error>;
	fn write_chunk(&mut self, data: &[u8]) -> Result<(), Error>;
	fn read_exact(&mut self, buffer: &mut[u8]) -> Result<(), Error>;
	fn write_exact(&mut self, data: &[u8]) -> Result<(), Error>;
}

pub struct StdIO {
	stdin: Stdin,
	stdout: Stdout,
	prefetched_chunk: (Vec<u8>, usize)
}
impl StdIO {
	pub fn new(chunk_size: usize) -> Self {
		StdIO{ stdin: stdin(), stdout: stdout(), prefetched_chunk: (vec![0u8; chunk_size], usize::MAX) }
	}
	
	fn read_next_chunk(&mut self) -> Result<(), Error> {
		// Reset chunk
		self.prefetched_chunk.1 = 0;
		
		// Read until EOF or any error other than `ErrorKind::Interrupted`
		'read_loop: loop {
			let bytes_read = match self.stdin.read(&mut self.prefetched_chunk.0[self.prefetched_chunk.1 ..]) {
				Ok(bytes_read) => bytes_read,
				Err(ref error) if error.kind() == ErrorKind::Interrupted => continue 'read_loop,
				Err(error) => throw_err!(ErrorType::from(error), "Failed to read from stdin".to_owned())
			};
			if bytes_read > 0 { self.prefetched_chunk.1 += bytes_read }
				else { return Ok(()) }
		}
	}
}
impl IO for StdIO {
	fn read_chunk(&mut self, chunk_buffer: &mut[u8]) -> Result<(usize, bool), Error> {
		// Prefetch chunk
		if self.prefetched_chunk.1 == usize::MAX { self.read_next_chunk()? }
		
		// Copy the data of the prefetched chunk to `buffer`
		let to_copy = self.prefetched_chunk.1;
		chunk_buffer[.. to_copy].copy_from_slice(&self.prefetched_chunk.0[.. to_copy]);
		
		// Prefetch next chunk and return `true` if there are no data left (=> the current chunk was the last chunk)
		self.read_next_chunk()?;
		Ok((to_copy, self.prefetched_chunk.1 == 0))
	}
	fn write_chunk(&mut self, data: &[u8]) -> Result<(), Error> {
		self.write_exact(data)
	}
	
	fn read_exact(&mut self, buffer: &mut[u8]) -> Result<(), Error> {
		try_err!(self.stdin.read_exact(buffer), "Failed to read from stdin".to_owned());
		Ok(())
	}
	fn write_exact(&mut self, data: &[u8]) -> Result<(), Error> {
		try_err!(self.stdout.write_all(data), "Failed to write to stdout".to_owned());
		try_err!(self.stdout.flush());
		Ok(())
	}
}