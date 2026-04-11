# Secure Hash Algorithm 2 (SHA-2)

An implementation of the family of cryptographic hash functions Secure Hash Standard (SHS) in C.

The standard specifies seven approved hash algorithms:
- SHA‑1 
- SHA‑224
- SHA‑256
- SHA‑384
- SHA‑512
- SHA‑512/224
- SHA‑512/256

The publication FIPS 180-4 can be found [here](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf) for additional information on the standard.

## Repository Structure

- `src`: contains all the source files, Makefile, and bash script required to build the `libSHA2.so` file.
- `testing`: test driver program to validate operation of the SHA-2 library.

## Requirements and Dependencies

- C
- Make

## Build

1. Navigate into `src`.
2. Issue the command `sh Initialize.sh` to prepare the environment before creating the library file.
3. Issue the command `make`. This will generate the shared object file in `res/libSHA2.so`.
4. You can now copy the shared object file `res/libSHA2.so` to a desired location for your project.

## Usage and Integration

Add the flags `-L$<path> -libSHA2 -Wl,-rpath,<path>` to the linker `gcc` command of your project, where `<path>` the the absolute path to the directory where `libSHA2.so` has been moved in the `Build` section `Step 4`.

The file `testing/SHA2Example.c` is an integration example on how the `SHA2` library can be used within a C program.

### SHA-224

#### `sha224* sha224_init()`

- **Input arguments**: None.
- **Output**: Returns a pointer to an allocated `sha224` instance on success. Returns `NULL` on allocation failure.
- Allocates a zero-initialized `sha224` structure with `calloc`.
- Initializes the internal `hash` to `SHA224_INIT_HASH` via `memcpy`.
- Prints an error message and returns `NULL` if allocation fails.

#### `int sha224_chain(sha224* s, uint8_t* input_data, uint64_t input_bytelen)`

- **Input arguments**:
  - `s`: pointer to an initialized `sha224` instance.
  - `input_data`: pointer to input byte array (must be non-NULL).
  - `input_bytelen`: number of bytes in `input_data`.
- **Output**: Returns `0` on success. Returns `-1` on error (e.g., `s` or `input_data` is `NULL`) plus error message is posted.
- Appends `input_data` into the internal buffer. When the internal buffer reaches the chunk size (`SHA224_CHUNK_BYTESIZE`), calls `sha224_process()` to compress the chunk and resets the buffer.
- Processes input in a loop until all input bytes are consumed.

#### `int sha224_end(sha224* s)`

- **Input arguments**:
  - `s`: pointer to a `sha224` instance.
- **Output**: Returns `0` on success. Returns `-1` on error (e.g., `s` is `NULL`) plus error message is posted.
- Finalizes the message:
  - Appends the `0x80` byte, pads with zeros as required to reach the correct position for the 64-bit big-endian bit-length.
  - Appends the message bit-length (big-endian) into the last 8 bytes of the final chunk.
  - Calls `sha224_process(s)` to process the last chunk.
- If running on a little-endian system, converts the final `s->hash` words to big-endian before returning.
- Sets `s->hash[SHA224_HASH_U32WORDS - 1] = 0x0` (trims last 32-bit word for SHA-224) and marks `s->done = true`.

#### `int sha224_delete(sha224* s)`

- **Input arguments**:
  - `s`: pointer to a `sha224` instance.
- **Output**: Returns `0` on success. Returns `-1` if `s` is `NULL` plus error message is posted.
- Frees the `sha224` instance memory.

#### `int sha224_get_hash(sha224* s, uint8_t* out_buffer)`

- **Input arguments**:
  - `s`: pointer to a `sha224` instance.
  - `out_buffer`: pointer to a caller-provided byte buffer to receive the raw hash bytes.
- **Output**: Returns `0` on success. Returns `-1` on error (e.g., `s` is `NULL`, `s->done` is false, or `out_buffer` is `NULL`) plus error message is posted.
- Copies the internal hash words (all but the last 32-bit word) into `out_buffer` as bytes.

#### `int sha224_get_stringified_hash(sha224* s, char* out_buffer)`

- **Input arguments**:
  - `s`: pointer to a `sha224` instance.
  - `out_buffer`: pointer to a caller-provided character buffer to receive the hex string.
- **Output**: Returns `0` on success. Returns `-1` on error (e.g., `s` is `NULL`, `s->done` is false, or `out_buffer` is `NULL`) plus error message is posted.
- Writes the hash into `out_buffer` as a lowercase hex string by iterating over the internal hash bytes.

## Changelog

### v1.0

- Initial release.
