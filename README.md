CryptoPipe
==========

CryptoPipe a fast and secure stream-encryption-utility.

Features:
 - Uses [Argon2i v1.3](https://www.cryptolux.org/images/0/0d/Argon2.pdf) as PBKDF (instead of the outdated PBKDF2)
 - Authenticated encryption using [ChaCha20+Poly1305](#chacha20+poly1305@de.kizzycode.cryptopipe.v1) (which is pretty
   fast even on platforms without AES-acceleration)
 - The encrypted-stream-format also allows random access opening/sealing (the data is splitted into ordered 1MiB-chunks
   which can be processed independently)
 - Protects against tampering, data-reordering and -truncation
 - Flexible stream-header-format that can be easily extended in the future
 - Written in safe Rust (except the bindings to [libsodium](https://libsodium.org))

## Table Of Contents
 0. [Introduction](#cryptopipe)
 1. [Table Of Contents](#table-of-contents)
 2. [Build Instructions](#build-instructions)
 3. [Cryptography](#cryptography)
     1. [Master-Key-Generation](#master-key-generation)
     2. [Per-Chunk Key-Derivation](#per-chunk-key-derivation)
     3. [Chunk-Encryption](#chunk-encryption)
 
 4. [Overall Stream-Format](#overall-stream-format)
     1. [Stream-Header-Format](#stream-header-format)
         1. [Magic-Numbers](#magic-numbers)
     
     2. [Chunk-Format](#chunk-format)
 
 5. [Appendix A](#appendix-a)
     1. [PBKDFs](#pbkdfs)
         1. [Argon2i v1,3](#argon2i-v1.3)
     
     2. [KDFs](#kdfs)
         1. [HMAC-SHA2-512](#hmac-sha2-512)
     
     3. [AuthEncs](#authencs)
         1. [ChaCha20+Poly1305@de.KizzyCode.CryptoPipe.v1](#chacha20+poly1305@de.kizzycode.cryptopipe.v1)


## Build-Instructions
Make sure, you have a working and up-to-date Rust-toolchain installed 😉

To build the documentation go into the project's root-directory and run `cargo doc --release`; to open the documentation
in your web-browser run `cargo doc --open`.

To build the application, go into the project's root-directory and run `cargo build --release`; you can find the build
in target/release.


## Cryptography
_(A note on terminology: instead of "encrypt"/"decrypt" we use the terms "seal"/"open" because this also implies
auth-tag-generation/-validation)_

There are three kinds of cryptographic algorithms required:
 - A PBKDF to derive a master-key from a password: `pbkdf(key: String) -> Key`
 - A KDF to derive individual, position-dependent keys for each chunk: `kdf(master_key: Key, info: Bytes) -> Key`
 - An AuthEnc-scheme (authenticated-encryption-scheme) used to seal each chunk: 
    - `auth_enc_seal(key: Key, data: Bytes) -> Bytes`
    - `auth_enc_open(key: Key, data: Bytes) -> Result<Bytes, Error>`

### Master-Key-Generation
The master-key-generation is pretty straight forward: we just throw the user's password into the PBKDF to derive
`master_key`. For specified PBKDF-algorithms and their parameters see [Appendix A](#appendix-a).

### Per-Chunk Key-Derivation
It is important that each chunk has a unique key because key-reuse might lead to catastrophic failures (including but
not limited to the complete loss of secrecy and/or authenticity).

To achieve this property, we use the chunk's index and it's stream-position (read: is the chunk the last one or not):
```c++
struct {
	u64 chunk_index; // (=> Raw-serialized as 64-bit-big-endian-integer)
	char* stream_position; // Either "#Last Chunk" if the chunk is the last one or "" if the chunk is a normal chunk (=> raw-serialized as US-ASCII-string)
} kdf_info; // (=> Raw-serialized without memory-alignment-padding)
```

Using the chunk-index as KDF-info has two advantages:
 1. It avoids the need for a unique random per-chunk-nonce (which we would need to save along with the chunk)
 2. It protects against chunk-reordering: If you swap `chunk_0` and `chunk_1`, the chunk-key for the 0th chunk (now
    `chunk_1`) is still derived with chunk-index 0 and thus cannot open `chunk_1`.

For the same reason as in 2nd, we also append the US-ASCII-string `#Last Chunk` if the chunk is the last-one so that an
attacker cannot strip it from the file – the key derived for the last-chunk cannot open a normal chunk (and because the
last-chunk's key also depends on it's chunk-index, it cannot be reordered).

### Chunk-Encryption
The chunk-encryption is also pretty straight forward:
 1. The user-data is splitted into 1MiB-large chunks (the __last__ chunk may be smaller)
 2. The chunks are sealed with their unique key (see [Per-Chunk Key-Derivation](#per-chunk-key-derivation))


## Overall Stream-Format
The stream consists of two parts:
 1. The stream-header
 2. One or more sealed data-chunks

The stream-header and each data-chunk are simply concatenated together (`stream_header || chunk_0 || ... || chunk_n`).

### Stream-Header-Format
The stream-header is consists of an ASN.1-DER-serialized structure which looks like this
```c++
struct {
	char* magic_number; // This must ALWAYS be the first field to allow testing for compatibility (=> ASN.1-DER-UTF8String)
	
	struct {
		char* algorithm;      // The PBKDF-algorithm (=> ASN.1-DER-UTF8String)
		void* parameters;     // Additional algorithm-parameters; see appendix A (=> ASN.1-DER-Struct) 
	} pbkdf; // (=> ASN.1-DER-Struct)
	
	struct {
		char* algorithm;      // The KDF-algorithm (=> ASN.1-DER-UTF8String)
		void* parameters;     // Additional algorithm-parameters; see appendix A (=> ASN.1-DER-Struct)
	} kdf; // (=> ASN.1-DER-Struct)

	struct {
		char* algorithm;      // The authenticated-encryption-algorithm (=> ASN.1-DER-UTF8String)
		void* parameters;     // Additional algorithm-parameters; see appendix A (=> ASN.1-DER-Struct)
	} auth_enc; // (=> ASN.1-DER-Struct)
	
} header_v1; // (=> ASN.1-DER-Struct)
```

#### Magic-Numbers
 - current: `de.KizzyCode.CryptoPipe.v1`


### Chunk-Format 
A chunk is simply the authenticated ciphertext (see [Chunk-Encryption](#chunk-encryption))

   

Appendix A
==========

## PBKDFs
These PBKDFs are currently specified:

### Argon2i v1.3
The standard [Argon2i v1.3](https://www.cryptolux.org/images/0/0d/Argon2.pdf)-algorithm.

 - algorithm: `Argon2i@v1.3`
 - parameters:
   ```c++
   struct {
       u8* nonce;           // The PBKDF-nonce (=> ASN.1-DER-OctetString)
       u32 time_cost;       // The PBKDF-time-cost in MiB (=> ASN.1-DER-Integer)
       u32 memory_cost_mib; // The PBKDF-memory-cost (=> ASN.1-DER-Integer)
       u32 parallelism;     // The PBKDF-parallelism-degree (=> ASN.1-DER-Integer)
   } parameters; // (=> ASN.1-DER-Struct)
   ```


## KDFs
These KDFs are currently specified:

### HMAC-SHA2-512
 - algorithm: `HMAC-SHA2-512`
 - parameters:
   ```c++
   NULL; // (=> ASN.1-DER-NULL)
   ```


## AuthEncs
These authenticated-encryption-schemes are currently supported:

### ChaCha20+Poly1305@de.KizzyCode.CryptoPipe.v1
A ChaCha20-Poly1305 authenticated-encryption-scheme:
 1. Initialize a ChaCha20-keystream with the given key and a zero-byte-nonce
 2. Compute 64-keystream bytes (beginning by keystream-byte-offset 0) and use the first 32-bytes as Poly1305-key
 3. Encrypt the data with the next ChaCha20-keystream-bytes (beginning by keystream-byte-offset 64)
 4. Compute the Poly1305-MAC (using the key from step 2) over the encrypted data and append it to the encrypted data

__Note: In this case, a zero-byte-nonce is not a security-issue because each key has to be unique and thus
key-nonce-collisions cannot happen__

 - algorithm: `ChaCha20+Poly1305@de.KizzyCode.CryptoPipe.v1`
 - parameters:
   ```c++
   NULL; // (=> ASN.1-DER-NULL)
   ```