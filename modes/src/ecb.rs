// Copyright (c) 2023 Amit Pandey
// FHE-AES: Electronic Codebook Mode Implementation
// Licensed under the Apache License, Version 2.0

use base::*;
use tfhe::boolean::prelude::*;

/// ECB (Electronic Codebook) mode implementation for AES-128
/// This is the simplest encryption mode where each block is encrypted independently
pub struct ECB {
    round_keys: Vec<Key>,
}

impl ECB {
    /// Creates a new ECB mode cipher with the given round keys
    pub fn new(round_keys: &[Key]) -> Self {
        ECB {
            round_keys: round_keys.to_vec(),
        }
    }

    /// Encrypts a state in-place using the ECB mode
    /// 
    /// # Arguments
    /// * `block` - The state to encrypt
    /// * `server_key` - The TFHE server key for FHE operations
    pub fn encrypt(&self, block: &mut State, server_key: &ServerKey) {
        // Add the initial round key
        block.xor_key_enc(&self.round_keys[0], server_key);

        // Perform the main encryption rounds (1-9)
        for round_num in 1..10 {
            // SubBytes transformation - substitute each byte using the S-box
            block.sub_bytes(server_key);
            
            // ShiftRows transformation - cyclically shift the rows
            block.shift_rows();
            
            // MixColumns transformation - mix data within each column
            block.mix_columns(server_key);
            
            // AddRoundKey transformation - XOR the state with the round key
            block.xor_key_enc(&self.round_keys[round_num], server_key);
        }

        // Final round (doesn't include MixColumns)
        block.sub_bytes(server_key);
        block.shift_rows();
        block.xor_key_enc(&self.round_keys[10], server_key);
    }

    /// Decrypts a state in-place using the ECB mode
    /// 
    /// # Arguments
    /// * `block` - The state to decrypt
    /// * `server_key` - The TFHE server key for FHE operations
    pub fn decrypt(&self, block: &mut State, server_key: &ServerKey) {
        // Add the final round key (in reverse)
        block.xor_key_enc(&self.round_keys[10], server_key);

        // Perform the main decryption rounds in reverse order
        for round_num in 1..10 {
            // Inverse ShiftRows transformation
            block.inv_shift_rows();
            
            // Inverse SubBytes transformation
            block.inv_sub_bytes(server_key);
            
            // Inverse AddRoundKey transformation
            block.xor_key_enc(&self.round_keys[10 - round_num], server_key);
            
            // Inverse MixColumns transformation
            block.inv_mix_columns(server_key);
        }

        // Final round (in reverse)
        block.inv_shift_rows();
        block.inv_sub_bytes(server_key);
        block.xor_key_enc(&self.round_keys[0], server_key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base::primitive::*;
    use std::time::Instant;
    use tfhe::boolean::gen_keys;

    /// Test a single block encryption and decryption
    #[test]
    fn test_ecb_single_block() {
        let (client_key, server_key) = gen_keys();

        // Initialize with test vectors
        let cipher_key = Key::from_u128_enc(0x2b7e1516_28aed2a6a_bf71588_09cf4f3c, &client_key);
        let round_keys: Vec<_> = cipher_key.generate_round_keys(&server_key).to_vec();
        let mut plaintext_block = State::from_u128_enc(0x3243f6a8_885a308d_313198a2_e0370734, &client_key);

        // Create ECB mode cipher
        let ecb_cipher = ECB::new(&round_keys);

        // Encrypt the block
        let start_time = Instant::now();
        ecb_cipher.encrypt(&mut plaintext_block, &server_key);
        println!("ENCRYPTION TIME: {:?}", start_time.elapsed());

        // Verify encrypted result
        assert_eq!(
            plaintext_block.decrypt_to_u128(&client_key),
            0x3925841d_02dc09fb_dc118597_196a0b32
        );

        // Decrypt the block
        let start_time = Instant::now();
        ecb_cipher.decrypt(&mut plaintext_block, &server_key);
        println!("DECRYPTION TIME: {:?}", start_time.elapsed());

        // Verify decrypted result matches original plaintext
        assert_eq!(
            plaintext_block.decrypt_to_u128(&client_key),
            0x3243f6a8_885a308d_313198a2_e0370734
        )
    }

    /// Test that encrypting the same block twice produces the same result
    #[test]
    fn test_ecb_deterministic() {
        let (client_key, server_key) = gen_keys();

        // Initialize with test vectors
        let cipher_key = Key::from_u128_enc(0x2b7e1516_28aed2a6a_bf71588_09cf4f3c, &client_key);
        let round_keys: Vec<_> = cipher_key.generate_round_keys(&server_key).to_vec();
        let mut block1 = State::from_u128_enc(0x3243f6a8_885a308d_313198a2_e0370734, &client_key);
        let mut block2 = block1.clone();

        // Create ECB mode cipher
        let ecb_cipher = ECB::new(&round_keys);

        // Encrypt both blocks
        with_server_key(|server_key| {
            ecb_cipher.encrypt(&mut block1, &server_key);
        });

        with_server_key(|server_key| {
            ecb_cipher.encrypt(&mut block2, &server_key);
        });

        // Verify both produce the same ciphertext
        assert_eq!(
            block1.decrypt_to_u128(&client_key),
            block2.decrypt_to_u128(&client_key)
        )
    }
}
