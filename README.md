# Merkle Tree Implementation in Rust

This is a simple implementation of a Merkle Tree data structure in Rust. Merkle Trees are hash trees that are widely used in blockchain and distributed systems for efficient and secure verification of large datasets.

## Features

- Constructs a Merkle Tree from a list of data blocks
- Verifies the integrity of the Merkle Tree by recalculating the root hash and comparing it to the expected root hash
- Written in Rust for efficiency and safety

## Usage

1. Install Rust and Cargo if you haven't already. You can find installation instructions [here](https://www.rust-lang.org/tools/install).

2. Clone this repository:

   ```bash
   git clone https://github.com/isoprophlex/rusty-merkle-tree/

3. Move to the right directory
    ```bash
   cd rusty-merkle-tree
    
4. Commands:
   
   a. Build
   ```bash
      make build
   
   b. Run
      ```bash
      make run
      
   c. Tests
      ```bash
      make test
      
   d. Format & clippy
      ```bash
      make format

   
3. Run:
    ```bash
   cargo run
4. Test:
    ```bash
   cargo test
   
