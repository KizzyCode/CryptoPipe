use std;
use super::super::error::{ Error, ErrorType };
use super::super::io_runloop;

/// A StdIO-replacement that works with memory-buffers instead of the StdIO-streams
pub struct MemoryIo {
	stdin: std::sync::Arc<std::sync::Mutex<(Vec<u8>, usize)>>,
	stdout: std::sync::Arc<std::sync::Mutex<(Vec<u8>, usize)>>
}
impl MemoryIo {
	pub fn new(stdin: Vec<u8>, expected_output_size: usize) -> Self {
		MemoryIo {
			stdin: std::sync::Arc::new(std::sync::Mutex::new((stdin, 0))),
			stdout: std::sync::Arc::new(std::sync::Mutex::new((vec![0u8; expected_output_size], 0)))
		}
	}
	
	pub fn stdout(&self) -> Vec<u8> {
		// Copy the data in StdOut
		let stdout = self.stdout.lock().unwrap();
		stdout.0[.. stdout.1].to_vec()
	}
	
	pub fn duplicate(&self) -> Self {
		// Clone references to the underlying buffer
		MemoryIo{ stdin: self.stdin.clone(), stdout: self.stdout.clone() }
	}
}
impl io_runloop::Io for MemoryIo {
	fn read_chunk(&mut self, chunk_buffer: &mut[u8]) -> Result<(usize, bool), Error> {
		// Lock StdIn-buffer
		let mut stdin = self.stdin.lock().unwrap();
		let (stdin_buf, stdin_pos) = (stdin.0.clone(), stdin.1);
		
		// Copy the data into `chunk_buffer`
		let to_copy = std::cmp::min(chunk_buffer.len(), stdin_buf[stdin_pos ..].len());
		chunk_buffer[.. to_copy].copy_from_slice(&stdin_buf[stdin_pos .. stdin_pos + to_copy]);
		
		// Update StdIn-buffer and return `(chunk_length, is_last)`
		*stdin = (stdin_buf, stdin_pos + to_copy);
		Ok((to_copy, stdin.0.len() <= stdin.1))
	}
	
	fn write_chunk(&mut self, data: &[u8]) -> Result<(), Error> {
		self.write_exact(data)
	}
	
	fn read_exact(&mut self, buffer: &mut[u8]) -> Result<(), Error> {
		// Lock StdIn-buffer
		let mut stdin = self.stdin.lock().unwrap();
		let (stdin_buf, stdin_pos) = (stdin.0.clone(), stdin.1);
		
		// Copy the data into `buffer`
		let to_copy = if stdin_buf[stdin_pos ..].len() >= buffer.len() { buffer.len() }
			else { throw_err!(ErrorType::IOError(std::io::ErrorKind::UnexpectedEof.into()), "Failed to read from stdin".to_owned()) };
		buffer.copy_from_slice(&stdin_buf[stdin_pos .. stdin_pos + to_copy]);
		
		// Update StdIn-buffer
		*stdin = (stdin_buf, stdin_pos + to_copy);
		Ok(())
	}
	
	fn write_exact(&mut self, data: &[u8]) -> Result<(), Error> {
		// Lock StdOut-buffer
		let mut stdout = self.stdout.lock().unwrap();
		let (mut stdout_buf, stdout_len) = (stdout.0.clone(), stdout.1);
		
		// Copy the data into the StdOut-buffer
		if stdout_buf[stdout_len ..].len() < data.len() { throw_err!(ErrorType::IOError(std::io::ErrorKind::UnexpectedEof.into()), "Failed to write to stdout".to_owned()) }
		stdout_buf[stdout_len .. stdout_len + data.len()].copy_from_slice(data);
		
		// Update StdOut-buffer
		*stdout = (stdout_buf, stdout_len + data.len());
		Ok(())
	}
}