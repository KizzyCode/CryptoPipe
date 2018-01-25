# Chunk format
The stream is processed in 1-MiB chunks (the last chunk may be smaller).

Each chunk has this structure:
```c
struct Chunk {
	uint8_t* chunk_data; // Usually 1 MiB
	uint8_t chunk_mac[16];
} chunk; // => Raw-serialized (without memory-alignment-padding)
```


# Stream Format
The stream has the following format:
```c
struct {
	uint8_t kdf_salt[32]; // Random KDF-salt
	
	uint32_t kdf_iterations; // => Serialized as Big-Endian number
	uint32_t kdf_memory_requirements; // => Serialized as Big-Endian number
	uint32_t kdf_parallelism; // => Serialized as Big-Endian number
	
	Chunk* chunks;
} stream; // => Raw-serialized (without memory-alignment-padding)
```


# Cryptography
## Key Generation
The KDF is initialized with the PBKDF-derived key. For each __non-last__ chunk, we derive 64 bytes from the KDF and use
them as cipher-key (first 32-bytes) and MAC-key (second 32-bytes). Then we increment the KDF-position by 64.

For the __last__ chunk, we first _increment_ the KDF-position by 2^63 and then derive 64 bytes from the KDF and use them
as cipher-key (first 32-bytes) and MAC-key (second 32-bytes).


# Threat-model
 1. Our stream-cipher ChaCha20 is vulnerable to key+nonce-reuse. To mitigate this, we use a KDF to compute unique keys
    per chunk. The odds of a key+nonce-collision are 1/2^128 and thus negligible.
 
 2. Our MAC Poly1305 is vulnerable to key-reuse. To mitigate this, we use a KDF to compute unique keys per chunk. The
    odds of a key+nonce-collision are 1/2^128 and thus negligible.
   
 3. Our model is vulnerable to a master-key-reuse because this would lead to the same KDF-output and thus result in a
    chunk-key-reuse (see 1. and 2.). To mitigate this, we use a random 256-bit nonce in our PBKDF. The odds for a 
    master-key-collision are 1/2^128 and thus negligible.
    
 4. Our chunk-model is vulnerable against chunk-reordering/omitting/duplication. This is mitigated by the KDF because
    our KDF is position-dependent, a different MAC-key is used for each chunk and thus the MAC-verification can only
    succeed if the chunk is at the correct position.
    
 5. Our chunk-model is vulnerable to stream-truncation. This is mitigated by using a higher KDF-position for the last
    chunk. The KDF-position is incremented by 2^63 so that we still preserve the relative position to protect against
    reordering etc. (see 4.) but also have a unique last-chunk-indicator.