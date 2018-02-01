mod memory_io;
mod test_predefined_stream;
mod test_random_streams;
mod test_invalid_streams;

use super::constants;



const RANDOM_STREAM_PASSWORD: &'static str = "Random password";

const PREDEFINED_STREAM_PASSWORD: &'static str = "Predefined password";
const PREDEFINED_STREAM_PBKDF: (&'static[u8], u32, u32, u32) = (b"This is an 32-byte nonce-text :P", 8, 256 * 1024, 4);
const PREDEFINED_STREAM_PLAIN: &'static[u8] = include_bytes!("predefined_stream.plain");
const PREDEFINED_STREAM_SEALED: &'static[u8] = include_bytes!("predefined_stream.sealed");



fn estimate_sealed_size(plain_size: usize) -> usize {
	let block_count = (plain_size / constants::CHUNK_DATA_SIZE) + 1;
	constants::STREAM_HEADER_SIZE + (constants::CHUNK_DATA_SIZE * block_count) + (constants::MAC_SIZE * block_count)
}