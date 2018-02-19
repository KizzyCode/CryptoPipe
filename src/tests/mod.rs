mod memory_io;
mod test_predefined_stream;
mod test_random_streams;
mod test_invalid_streams;

fn estimate_sealed_size(plain_size: usize, overhead: usize) -> usize {
	let block_count = (plain_size / super::stream::CHUNK_DATA_SIZE) + 1;
	256 + (super::stream::CHUNK_DATA_SIZE * block_count) + (overhead * block_count)
}