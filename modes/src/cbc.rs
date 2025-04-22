// Copyright (c) 2023 Amit Pandey
// FHE-AES: Cipher Block Chaining Mode Implementation
// Licensed under the Apache License, Version 2.0

use crate::ecb::ECB;
use base::*;
use tfhe::boolean::prelude::*;

/// CBC (Cipher Block Chaining) mode implementation for AES-128
///
/// In CBC mode, each plaintext block is XORed with the previous ciphertext block
/// before being encrypted, adding diffusion across blocks.
pub struct CBC {
    cipher: ECB,               // Base ECB cipher for block encryption
    initialization_vector: State,  // Initialization vector for the first block
    block_count: u8,           // Number of blocks to process
}

impl CBC {
    /// Creates a new CBC mode cipher
    ///
    /// # Arguments
    /// * `round_keys` - The AES round keys for encryption/decryption
    /// * `initialization_vector` - The initialization vector (IV)
    /// * `block_count` - Number of blocks to process
    pub fn new(round_keys: &[Key], initialization_vector: &State, block_count: u8) -> Self {
        CBC {
            cipher: ECB::new(round_keys),
            initialization_vector: initialization_vector.clone(),
            block_count,
        }
    }

    /// Encrypts multiple blocks in-place using CBC mode
    ///
    /// # Arguments
    /// * `blocks` - The plaintext blocks to encrypt
    /// * `server_key` - The TFHE server key for FHE operations
    pub fn encrypt(&self, blocks: &mut [State], server_key: &ServerKey) {
        // First block: XOR with IV then encrypt
        blocks[0].xor_state(&self.initialization_vector, server_key);
        self.cipher.encrypt(&mut blocks[0], server_key);

        // Subsequent blocks: XOR with previous ciphertext then encrypt
        for block_index in 1..self.block_count as usize {
            // Split array to borrow previous and current blocks separately
            let (previous_blocks, current_blocks) = blocks.split_at_mut(block_index);
            
            // XOR current block with previous ciphertext
            current_blocks[0].xor_state(&previous_blocks[block_index - 1], server_key);
            
            // Encrypt the current block
            self.cipher.encrypt(&mut current_blocks[0], server_key);
        }
    }

    /// Decrypts multiple blocks in-place using CBC mode
    ///
    /// # Arguments
    /// * `blocks` - The ciphertext blocks to decrypt
    /// * `server_key` - The TFHE server key for FHE operations
    pub fn decrypt(&self, blocks: &mut [State], server_key: &ServerKey) {
        // Process blocks in reverse order (except the first one)
        for block_index in (1..self.block_count as usize).rev() {
            // Split array to borrow previous and current blocks separately
            let (previous_blocks, current_blocks) = blocks.split_at_mut(block_index);
            
            // Decrypt the current block
            self.cipher.decrypt(&mut current_blocks[0], server_key);
            
            // XOR with previous ciphertext to get plaintext
            current_blocks[0].xor_state(&previous_blocks[block_index - 1], server_key);
        }

        // First block: Decrypt then XOR with IV
        self.cipher.decrypt(&mut blocks[0], server_key);
        blocks[0].xor_state(&self.initialization_vector, server_key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;
    use tfhe::boolean::gen_keys;

    #[test]
    fn test_cbc_encryption_decryption() {
        let (client_key, server_key) = gen_keys();

        // Test vectors
        let encryption_key = Key::from_u128_enc(0x2b7e1516_28aed2a6a_bf71588_09cf4f3c, &client_key);
        let round_keys = encryption_key.generate_round_keys(&server_key);
        let init_vector = State::from_u128_enc(0x3243f6a8_885a308d_313198a2_e0312122, &client_key);
        
        // Create CBC cipher with 2 blocks
        let cbc_cipher = CBC::new(&round_keys, &init_vector, 2);

        // Create test plaintext blocks
        let plaintext_block_0 =
            State::from_u128_enc(0x3243f6a8_885a308d_313198a2_e0370734, &client_key);
        let plaintext_block_1 =
            State::from_u128_enc(0x3243f6a8_885a308d_313198a2_e0372324, &client_key);
        let mut blocks = vec![plaintext_block_0, plaintext_block_1];

        // Encrypt blocks
        let start_time = Instant::now();
        cbc_cipher.encrypt(&mut blocks, &server_key);
        println!("CBC ENCRYPTION TIME: {:?}", start_time.elapsed());

        // Print encrypted results
        blocks
            .iter()
            .enumerate()
            .for_each(|(i, block)| println!("Ciphertext block {}: {:#x?}", i, block.decrypt_to_u128(&client_key)));

        // Decrypt blocks
        let start_time = Instant::now();
        cbc_cipher.decrypt(&mut blocks, &server_key);
        println!("CBC DECRYPTION TIME: {:?}", start_time.elapsed());

        // Verify results match original plaintext
        assert_eq!(
            blocks[0].decrypt_to_u128(&client_key),
            0x3243f6a8_885a308d_313198a2_e0370734,
            "First block decryption failed"
        );
        assert_eq!(
            blocks[1].decrypt_to_u128(&client_key),
            0x3243f6a8_885a308d_313198a2_e0372324,
            "Second block decryption failed"
        );
    }
}
