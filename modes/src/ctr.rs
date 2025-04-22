// Copyright (c) 2023 Amit Pandey
// FHE-AES: Counter Mode Implementation
// Licensed under the Apache License, Version 2.0

use crate::ecb::ECB;
use base::*;
use rayon::prelude::*;
use tfhe::boolean::prelude::*;

/// CTR (Counter) mode implementation for AES-128
/// 
/// Counter mode turns a block cipher into a stream cipher by encrypting
/// sequential counter values and XORing them with plaintext.
///
/// Implementation Notes:
/// - Counter generation can't be done directly in the FHE context
/// - Pre-generated encrypted counters must be provided
/// - In a client/server scenario, the client would generate counters,
///   encrypt them in the FHE context, and send them to the server
pub struct CounterMode {
    cipher: ECB,                 // Base ECB cipher for block encryption
    counter_blocks: Vec<State>,  // Pre-encrypted counter blocks
}

impl CounterMode {
    /// Creates a new Counter mode cipher
    ///
    /// # Arguments
    /// * `round_keys` - The AES round keys for encryption
    /// * `counters` - Pre-generated counter blocks (already encrypted with FHE)
    /// * `block_count` - Number of blocks to process (must match counters.len())
    ///
    /// # Panics
    /// Panics if the number of counter blocks doesn't match block_count
    pub fn new(round_keys: &[Key], counters: &[State], block_count: u8) -> Self {
        assert!(
            counters.len() == block_count as usize,
            "Number of counter blocks must match the specified block count"
        );
        
        CounterMode {
            cipher: ECB::new(round_keys),
            counter_blocks: counters.to_vec(),
        }
    }

    /// Encrypts multiple blocks using CTR mode
    ///
    /// # Arguments
    /// * `blocks` - The plaintext blocks to encrypt
    /// * `server_key` - The TFHE server key for FHE operations
    ///
    /// # Process
    /// 1. Encrypt all counter blocks with AES
    /// 2. XOR each plaintext block with the corresponding encrypted counter
    pub fn encrypt(&self, blocks: &mut [State], server_key: &ServerKey) {
        // Clone the counters so we can encrypt them without modifying the originals
        let mut encrypted_counters = self.counter_blocks.to_vec();
        
        // Encrypt all counters in parallel
        encrypted_counters
            .par_iter_mut()
            .for_each(|counter| self.cipher.encrypt(counter, server_key));
        
        // XOR each plaintext block with its corresponding encrypted counter (in parallel)
        blocks
            .par_iter_mut()
            .zip(encrypted_counters.par_iter())
            .for_each_with(server_key, |server_key, (block, counter)| 
                block.xor_state(counter, server_key)
            );
    }

    /// Decrypts multiple blocks using CTR mode
    ///
    /// # Arguments
    /// * `blocks` - The ciphertext blocks to decrypt
    /// * `server_key` - The TFHE server key for FHE operations
    ///
    /// # Note
    /// Counter mode is symmetric - encryption and decryption are 
    /// performed in exactly the same way
    pub fn decrypt(&self, blocks: &mut [State], server_key: &ServerKey) {
        // CTR mode decryption is identical to encryption
        self.encrypt(blocks, server_key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;
    use tfhe::boolean::gen_keys;

    #[test]
    fn test_counter_mode_encryption_decryption() {
        let (client_key, server_key) = gen_keys();

        // Initialize test encryption key
        let encryption_key = Key::from_u128_enc(0x2b7e1516_28aed2a6a_bf71588_09cf4f3c, &client_key);
        let round_keys = encryption_key.generate_round_keys(&server_key);
        
        // Create two counter blocks with sequential values
        let counter_blocks = vec![
            State::from_u128_enc(0x3243f6a8_885a308d_00000000_00000000, &client_key),
            State::from_u128_enc(0x3243f6a8_885a308d_00000000_00000001, &client_key),
        ];
        
        // Create CTR cipher with 2 blocks
        let counter_cipher = CounterMode::new(&round_keys, &counter_blocks, 2);

        // Create test plaintext blocks
        let plaintext_block_0 =
            State::from_u128_enc(0x3243f6a8_885a308d_313198a2_e0370734, &client_key);
        let plaintext_block_1 =
            State::from_u128_enc(0x3243f6a8_885a308d_313198a2_e0372324, &client_key);
        let mut blocks = vec![plaintext_block_0, plaintext_block_1];

        // Encrypt blocks and measure time
        let start_time = Instant::now();
        counter_cipher.encrypt(&mut blocks, &server_key);
        println!("CTR ENCRYPTION TIME: {:?}", start_time.elapsed());

        // Print encrypted results
        blocks
            .iter()
            .enumerate()
            .for_each(|(i, block)| println!("Ciphertext block {}: {:#x?}", i, block.decrypt_to_u128(&client_key)));

        // Decrypt blocks and measure time
        let start_time = Instant::now();
        counter_cipher.decrypt(&mut blocks, &server_key);
        println!("CTR DECRYPTION TIME: {:?}", start_time.elapsed());

        // Verify decryption succeeded
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
