# Homomorphic Encryption Analysis

Simple Rust project for comparing selected properties of RSA and Paillier.

## Tests

The project currently includes three main test groups.

### 1. RSA ciphertext size test

Unit tests in `src/rsa_pure.rs` verify:

- a short message,
- a message close to the maximum allowed size,
- an oversized message (`m >= n`).

Assumption:

- for a `2048`-bit key, an RSA ciphertext should take `256` bytes.

### 2. Paillier ciphertext size test

Unit tests in `src/paillier_pure.rs` verify:

- a small value,
- a value close to `n`,
- an invalid value (`m >= n`).

Assumption:

- for a `2048`-bit key, a Paillier ciphertext should take about `512` bytes.

### 3. Memory overhead test

The integration test in `tests/memory_overhead.rs` compares:

- input data size,
- ciphertext size.

Checked input sizes:

- `1 KB`,
- `10 KB`,
- `100 KB`,
- `1 MB`.

## How to run the tests

Run all library tests:

```powershell
cargo test --lib
```

Run only the memory overhead test:

```powershell
cargo test --test memory_overhead
```

Run all tests:

```powershell
cargo test
```

## Memory overhead report

The report generator is located in `src/bin/memory_overhead.rs`.

Run it with:

```powershell
cargo run --bin memory_overhead
```

The program:

- prints a table in the terminal,
- saves CSV data to `results/memory_overhead.csv`.

## Benchmark

The time benchmark is located in `benches/rsa_bench.rs`.

Run it with:

```powershell
cargo bench
```
