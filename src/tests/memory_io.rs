use std;
use super::super::{ Error, CpError };
use super::super::io;

/// A StdIO-replacement that works with memory-buffers instead of the StdIO-streams
pub struct MemoryIo {
	stdin: (Vec<u8>, usize),
	stdout: (Vec<u8>, usize)
}
impl MemoryIo {
	pub fn new(stdin: Vec<u8>, expected_output_size: usize) -> Self {
		MemoryIo{ stdin: (stdin, 0), stdout: (vec![0u8; expected_output_size], 0) }
	}
	
	pub fn stdout(&self) -> Vec<u8> {
		// Copy the data in StdOut
		self.stdout.0[.. self.stdout.1].to_vec()
	}
}
impl io::Io for MemoryIo {
	fn read_chunk(&mut self, chunk_buffer: &mut[u8]) -> Result<(usize, bool), Error<CpError>> {
		// Copy the data into `chunk_buffer`
		let to_copy = std::cmp::min(chunk_buffer.len(), self.stdin.0[self.stdin.1 ..].len());
		chunk_buffer[.. to_copy].copy_from_slice(&self.stdin.0[self.stdin.1 .. self.stdin.1 + to_copy]);
		
		// Update StdIn-buffer and return `(chunk_length, is_last)`
		self.stdin.1 += to_copy;
		Ok((to_copy, self.stdin.0.len() <= self.stdin.1))
	}
	
	fn write_chunk(&mut self, data: &[u8]) -> Result<(), Error<CpError>> {
		self.write_exact(data)
	}
	
	fn read_exact(&mut self, buffer: &mut[u8]) -> Result<(), Error<CpError>> {
		// Copy the data into `buffer`
		let to_copy = if self.stdin.0[self.stdin.1 ..].len() >= buffer.len() { buffer.len() }
			else { throw_err!(std::io::ErrorKind::UnexpectedEof.into(), "Failed to read from stdin") };
		buffer.copy_from_slice(&self.stdin.0[self.stdin.1 .. self.stdin.1 + to_copy]);
		
		// Update StdIn-buffer
		self.stdin.1 += to_copy;
		Ok(())
	}
	
	fn write_exact(&mut self, data: &[u8]) -> Result<(), Error<CpError>> {
		// Copy the data into the StdOut-buffer
		if self.stdout.0[self.stdout.1 ..].len() < data.len() { throw_err!(std::io::ErrorKind::UnexpectedEof.into(), "Failed to write to stdout") }
		self.stdout.0[self.stdout.1 .. self.stdout.1 + data.len()].copy_from_slice(data);
		
		// Update StdOut-buffer
		self.stdout.1 += data.len();
		Ok(())
	}
}