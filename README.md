# Secure Hash Algorithm 2 (SHA-2)

An implementation of the family of cryptographic hash functions Secure Hash Standard (SHS) in C.

The standard specifies seven approved hash algorithms:
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

For the descriptions detailed below, the `XYZ` substring is a placeholder that can be interpreted as `224`, `256`, `384`, or `512`.

### `shaXYZ* shaXYZ_init()`

- **Input arguments**: None.
- **Output**: Returns a pointer to an allocated `sha` instance on success. Returns `NULL` on allocation failure.
- Allocates a zero-initialized `sha` structure.
- Initializes the internal `hash` to its corresponding initial hash value.
- Prints an error message and returns `NULL` if allocation fails.

### `int shaXYZ_chain(shaXYZ* s, uint8_t* input_data, uint64_t input_bytelen)`

- **Input arguments**:
  - `s`: pointer to an initialized `shaXYZ` instance.
  - `input_data`: pointer to input byte array (must be non-NULL).
  - `input_bytelen`: number of bytes in `input_data`.
- **Output**: Returns `0` on success. Returns `-1` on error (e.g., `s` or `input_data` is `NULL`) plus error message is posted.
- Appends `input_data` into the internal buffer. When the internal buffer reaches the maximum chunk size (based on the algorithm), calls `shaXYZ_process()` to compress the chunk and resets the buffer.
- Processes input in a loop until all input bytes are consumed.

### `int shaXYZ_end(shaXYZ* s)`

- **Input arguments**:
  - `s`: pointer to a `shaXYZ` instance.
- **Output**: Returns `0` on success. Returns `-1` on error (e.g., `s` is `NULL`) plus error message is posted.
- Finalizes the message:
  - Appends the `0x80` byte, pads with zeros as required to reach the correct position for the bit-length value in big-endian notation.
  - Appends the message bit-length into the last bytes of the final chunk.
  - Calls `shaXYZ_process(s)` to process the last chunk.
- If running on a little-endian system, converts the final `s->hash` words to big-endian before returning.
- Sets `s->done` to `true`.

### `int shaXYZ_delete(shaXYZ* s)`

- **Input arguments**:
  - `s`: pointer to a `shaXYZ` instance.
- **Output**: Returns `0` on success. Returns `-1` if `s` is `NULL` plus error message is posted.
- Frees the `shaXYZ` instance memory.

### `int shaXYZ_get_hash(shaXYZ* s, uint8_t* out_buffer)`

- **Input arguments**:
  - `s`: pointer to a `shaXYZ` instance.
  - `out_buffer`: pointer to a caller-provided byte buffer to receive the raw hash bytes.
- **Output**: Returns `0` on success. Returns `-1` on error (e.g., `s` is `NULL`, `s->done` is false, or `out_buffer` is `NULL`) plus error message is posted.
- Copies the internal hash up to the size  of `XYZ` in bytes into `out_buffer` as bytes.

### `int shaXYZ_get_stringified_hash(shaXYZ* s, char* out_buffer)`

- **Input arguments**:
  - `s`: pointer to a `shaXYZ` instance.
  - `out_buffer`: pointer to a caller-provided character buffer to receive the hex string.
- **Output**: Returns `0` on success. Returns `-1` on error (e.g., `s` is `NULL`, `s->done` is false, or `out_buffer` is `NULL`) plus error message is posted.
- Writes the hash into `out_buffer` as a lowercase hex string by iterating over the internal hash bytes.


## Changelog

### v1.0

- Initial release.
