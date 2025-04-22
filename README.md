# **FHE-AES Implementation**

A Fully Homomorphic Encryption (FHE) implementation of the Advanced Encryption Standard (AES) using the TFHE-rs library.

## **Project Overview**

This project implements AES encryption in multiple modes (ECB, CBC, OFB, CTR) within a fully homomorphic encryption context. The implementation focuses on optimizing performance, particularly for the computationally expensive "SubBytes" operation.

### **Key Features**

- Implements AES-128 encryption and decryption
- Supports multiple encryption modes (ECB, CBC, OFB, CTR)
- Utilizes the TFHE-rs boolean API for improved performance
- Custom optimized implementation of the SubBytes operation
- Parallelized computation where possible

### **Technical Approach**

The implementation was designed with several performance optimizations:

1. **Transposed State Matrix**: Working with transposed state matrices for improved performance in 32-bit systems
2. **Boolean-Based Implementation**: Using the `tfhe::boolean` API instead of standard `FHEUint` types
3. **Optimized SubBytes**: Implementing the S-box as an 8-bit multiplexer using a boolean tree
4. **Staged Evaluation**: Processing boolean expressions in a staged manner for increased parallelism
5. **Expression Caching**: Using hashmap-based caching to avoid redundant computations

## **Implementation Details**

### **FHEByte**

We implemented a custom `FHEByte` type, which is a wrapper around `[tfhe::boolean; 8]`. This type supports logical operations like `xor`, `and`, `not`, and bit-shifting, as well as conversions between clear and encrypted values.

### **Boolean Tree and Multiplexer**

The SubBytes operation is implemented using an 8-bit multiplexer for each output bit. This approach represents the S-box substitution as a recursive `BooleanExpr` object. The expressions are simplified using a `reduce_mux` method that eliminates redundancies and optimizes the evaluation process.

### **Staged Evaluation**

To optimize the evaluation of boolean expressions, we implemented a staging system that:
1. Identifies common subexpressions
2. Maintains a hashmap of already evaluated expressions
3. Uses thread pools for parallel evaluation

This approach significantly reduces computation time for SubByte operations.

## **Performance**

On a 16-thread machine, the implementation achieves:
- SubByte operation: ~1.6s per byte
- One block encryption/decryption in ECB mode: ~300 seconds

Performance is primarily limited by the complexity of homomorphically evaluating the AES SubBytes operation.

## **Getting Started**

### **Prerequisites**

- Rust (latest stable version)
- Cargo (included with Rust)

Verify your installation:
```sh
rustc --version
cargo --version
```

### **Building the Project**

```sh
cargo build --release
```

### **Running the Program**

```sh
cargo run --release -- [OPTIONS]
```

Or after building:
```sh
./target/release/tfhe_aes [OPTIONS]
```

### **Command-Line Arguments**

| Argument                     | Short | Description |
|------------------------------|:-----:|-------------|
| `--number-of-outputs <u8>`   | `-n`  | Number of random test blocks to generate (default: `1`). |
| `--iv <hex-string>`          | `-i`  | 16-byte Initialization Vector (IV) in hexadecimal format. |
| `--key <hex-string>`         | `-k`  | 16-byte encryption key in hexadecimal format. |
| `--key-expansion-offline`    | `-x`  | Enable offline key expansion (default: `false`). |
| `--mode <ECB\|CBC\|CTR\|OFB>` | `-m`  | Encryption mode (default: `ECB`). |

### **Example Usage**

```sh
cargo run --release -- -i "00112233445566778899AABBCCDDEEFF" -k "0F1571C947D9E8590CB7ADD6AF7F6798"
```

```sh
cargo run --release -- -n 5 -i "00112233445566778899AABBCCDDEEFF" -k "0F1571C947D9E8590CB7ADD6AF7F6798" -m CTR
```

## **Configuration**

### **Rust Configuration**
```toml
[profile.release]
debug = true
opt-level = 2
```

### **TFHE-rs Dependency**
```toml
tfhe = { git = "https://github.com/zama-ai/tfhe-rs.git", rev = "4e2db92", features = ["integer", "nightly-avx512", "noise-asserts", "boolean"]}
```

## **Testing**

It is recommended to run tests for each module separately, as some modules take significantly longer to test:

```sh
cd base && cargo test
cd ../modes && cargo test
cd ../tfhe-aes && cargo test
```

## **References**

This implementation draws inspiration from various academic works on efficient AES implementation and FHE:

- Standard specifications from NIST for AES (FIPS 197) and Block Cipher Modes of Operation (SP 800-38A)
- Research on efficient AES implementation in 32-bit systems
- Literature on optimizing homomorphic evaluation of cryptographic functions
