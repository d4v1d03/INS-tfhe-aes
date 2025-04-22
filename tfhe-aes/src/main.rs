// Copyright (c) 2023 Amit Pandey
// FHE-AES: A Fully Homomorphic Encryption implementation of the Advanced Encryption Standard
// Licensed under the Apache License, Version 2.0

use std::array;
use std::time::Instant;

use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::Aes128;
use base::key_schedule::key_expansion_clear;
use base::{Key, State};
use clap::Parser;
use hex;
use modes::{cbc::CBC, ctr::CTR, ecb::ECB, ofb::OFB};
use rand::Rng;
use tfhe::boolean::gen_keys;
use tfhe::boolean::prelude::*;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct CipherArgs {
    #[arg(short = 'n', long = "number-of-outputs", default_value_t = 1)]
    output_count: u8,

    #[arg(short, long)]
    initialization_vector: String,

    #[arg(short, long)]
    encryption_key: String,

    #[arg(short = 'x', long = "key-expansion-offline", default_value_t = false)]
    offline_key_expansion: bool,

    #[arg(short, long, default_value = "ECB")]
    cipher_mode: String,
}

enum CipherMode {
    ECB,
    CBC,
    CTR,
    OFB,
}

fn main() {
    let args = CipherArgs::parse();

    println!("Number of Outputs: {}", args.output_count);
    println!("IV: {}", args.initialization_vector);
    println!("Key: {}", args.encryption_key);
    println!("Key Expansion Offline: {}", args.offline_key_expansion);
    println!("Mode: {}", args.cipher_mode);

    let encryption_key = decode_hex_to_bytes(&args.encryption_key).expect("Invalid key format");
    let init_vector = decode_hex_to_bytes(&args.initialization_vector).expect("Invalid IV format");
    let mode = parse_cipher_mode(&args.cipher_mode).expect("Invalid Mode format");
    let offline_key_expansion = args.offline_key_expansion;
    let output_count = args.output_count;

    let mut rng = rand::rng();
    let mut input_blocks = Vec::with_capacity(args.output_count as usize);
    for _ in 0..args.output_count {
        let mut block = [0u8; 16];
        rng.fill(&mut block);
        input_blocks.push(block);
    }

    let (client_key, server_key) = gen_keys();

    match mode {
        CipherMode::ECB => execute_ecb_mode(
            &encryption_key,
            &input_blocks,
            offline_key_expansion,
            &server_key,
            &client_key,
        ),
        CipherMode::CBC => execute_cbc_mode(
            &encryption_key,
            &init_vector,
            &input_blocks,
            offline_key_expansion,
            output_count,
            &server_key,
            &client_key,
        ),
        CipherMode::CTR => execute_ctr_mode(
            &encryption_key,
            &init_vector,
            &input_blocks,
            offline_key_expansion,
            output_count,
            &server_key,
            &client_key,
        ),
        CipherMode::OFB => execute_ofb_mode(
            &encryption_key,
            &init_vector,
            &input_blocks,
            offline_key_expansion,
            output_count,
            &server_key,
            &client_key,
        ),
    }
}

fn parse_cipher_mode(input: &str) -> Result<CipherMode, String> {
    match input {
        "ECB" => Ok(CipherMode::ECB),
        "CBC" => Ok(CipherMode::CBC),
        "CTR" => Ok(CipherMode::CTR),
        "OFB" => Ok(CipherMode::OFB),
        _ => Err(format!("Unsupported cipher mode: {}", input)),
    }
}

fn decode_hex_to_bytes(hex_str: &str) -> Result<[u8; 16], String> {
    if hex_str.len() != 32 {
        return Err(format!(
            "Hex string must be 32 characters (16 bytes), found {} characters.",
            hex_str.len()
        ));
    }
    let bytes = hex::decode(hex_str).map_err(|_| "Failed to decode hex string")?;
    let mut result = [0u8; 16];
    result.copy_from_slice(&bytes[..16]);
    Ok(result)
}

fn execute_ecb_mode(
    encryption_key: &[u8; 16],
    input_blocks: &[[u8; 16]],
    offline_key_expansion: bool,
    server_key: &ServerKey,
    client_key: &ClientKey,
) {
    println!("---Testing ECB mode---");

    let aes_clear = Aes128::new(GenericArray::from_slice(encryption_key));
    let mut expected_result = input_blocks.to_vec();

    for block in expected_result.iter_mut() {
        aes_clear.encrypt_block(GenericArray::from_mut_slice(block));
    }

    let round_keys = prepare_key_schedule(encryption_key, offline_key_expansion, server_key, client_key);

    // ENCRYPTION
    println!("---Begin Encryption---");
    let ecb = ECB::new(&round_keys);

    let mut encrypted_blocks = input_blocks
        .iter()
        .map(|x| State::from_u8_enc(x, client_key))
        .collect::<Vec<_>>(); // Convert into State Matrixes and encrypt with FHE

    let start = Instant::now();
    encrypted_blocks
        .iter_mut()
        .for_each(|x| ecb.encrypt(x, server_key)); // Encrypt with AES

    println!(
        "AES of #{:?} outputs computed in: {:?}",
        input_blocks.len(),
        start.elapsed()
    );

    assert_eq!(
        encrypted_blocks
            .iter()
            .map(|x| x.decrypt_to_u8(client_key))
            .collect::<Vec<_>>(),
        expected_result
    );

    // DECRYPTION
    println!("---Decryption---");

    let start = Instant::now();
    encrypted_blocks
        .iter_mut()
        .for_each(|x| ecb.decrypt(x, server_key)); // Decrypt with AES
    println!(
        "AES of #{:?} outputs decrypted in: {:?}",
        input_blocks.len(),
        start.elapsed()
    );

    assert_eq!(
        encrypted_blocks
            .iter()
            .map(|x| x.decrypt_to_u8(client_key))
            .collect::<Vec<_>>(),
        input_blocks.to_vec()
    );

    println!("ECB mode test passed");
}

fn execute_cbc_mode(
    encryption_key: &[u8; 16],
    init_vector: &[u8; 16],
    input_blocks: &[[u8; 16]],
    offline_key_expansion: bool,
    output_count: u8,
    server_key: &ServerKey,
    client_key: &ClientKey,
) {
    println!("Testing CBC mode");

    let expected_result = simulate_cbc_encryption(input_blocks, encryption_key, init_vector);

    let round_keys = prepare_key_schedule(encryption_key, offline_key_expansion, server_key, client_key);
    let iv_state = State::from_u8_enc(init_vector, client_key);
    
    // ENCRYPTION
    println!("---Begin Encryption---");
    let cbc: CBC = CBC::new(&round_keys, &iv_state, output_count);

    let start = Instant::now();
    let mut encrypted_blocks = input_blocks
        .iter()
        .map(|x| State::from_u8_enc(x, client_key))
        .collect::<Vec<_>>(); // Convert into State Matrixes and encrypt with FHE
    println!("Conversion to FHE Time Taken: {:?}", start.elapsed());

    let start = Instant::now();
    cbc.encrypt(&mut encrypted_blocks, server_key); // Encrypt with AES
    println!(
        "AES of #{:?} outputs computed in: {:?}",
        input_blocks.len(),
        start.elapsed()
    );

    assert_eq!(
        encrypted_blocks
            .iter()
            .map(|x| x.decrypt_to_u8(client_key))
            .collect::<Vec<_>>(),
        expected_result
    );

    // DECRYPTION
    println!("---Decryption---");

    let start = Instant::now();
    cbc.decrypt(&mut encrypted_blocks, server_key); // Decrypt with AES
    println!(
        "AES of #{:?} outputs decrypted in: {:?}",
        input_blocks.len(),
        start.elapsed()
    );

    assert_eq!(
        encrypted_blocks
            .iter()
            .map(|x| x.decrypt_to_u8(client_key))
            .collect::<Vec<_>>(),
        input_blocks.to_vec()
    );

    println!("CBC mode test passed");
}

fn execute_ctr_mode(
    encryption_key: &[u8; 16],
    init_vector: &[u8; 16],
    input_blocks: &[[u8; 16]],
    offline_key_expansion: bool,
    output_count: u8,
    server_key: &ServerKey,
    client_key: &ClientKey,
) {
    println!("Testing CTR mode");
    let counters = create_counter_blocks(init_vector, output_count);
    let expected_result = simulate_ctr_encryption(input_blocks, encryption_key, &counters);

    let round_keys = prepare_key_schedule(encryption_key, offline_key_expansion, server_key, client_key);

    // ENCRYPTION
    println!("---Begin Encryption---");
    let encrypted_counters = counters
        .iter()
        .map(|x| State::from_u8_enc(x, client_key))
        .collect::<Vec<_>>(); // Convert into State Matrixes and encrypt with FHE
    let ctr = CTR::new(&round_keys, &encrypted_counters, output_count);

    let mut encrypted_blocks = input_blocks
        .iter()
        .map(|x| State::from_u8_enc(x, client_key))
        .collect::<Vec<_>>(); // Convert into State Matrixes and encrypt with FHE

    let start = Instant::now();
    ctr.encrypt(&mut encrypted_blocks, server_key); // Encrypt with AES
    println!(
        "AES of #{:?} outputs computed in: {:?}",
        input_blocks.len(),
        start.elapsed()
    );

    assert_eq!(
        encrypted_blocks
            .iter()
            .map(|x| x.decrypt_to_u8(client_key))
            .collect::<Vec<_>>(),
        expected_result
    );

    // DECRYPTION
    println!("---Decryption---");

    let start = Instant::now();
    ctr.decrypt(&mut encrypted_blocks, server_key); // Decrypt with AES
    println!(
        "AES of #{:?} outputs decrypted in: {:?}",
        input_blocks.len(),
        start.elapsed()
    );

    assert_eq!(
        encrypted_blocks
            .iter()
            .map(|x| x.decrypt_to_u8(client_key))
            .collect::<Vec<_>>(),
        input_blocks.to_vec()
    );

    println!("CTR mode test passed");
}

fn execute_ofb_mode(
    encryption_key: &[u8; 16],
    init_vector: &[u8; 16],
    input_blocks: &[[u8; 16]],
    offline_key_expansion: bool,
    output_count: u8,
    server_key: &ServerKey,
    client_key: &ClientKey,
) {
    println!("Testing OFB mode");

    let expected_result = simulate_ofb_encryption(input_blocks, encryption_key, init_vector);

    let round_keys = prepare_key_schedule(encryption_key, offline_key_expansion, server_key, client_key);
    let iv_state = State::from_u8_enc(init_vector, client_key);

    // ENCRYPTION
    println!("---Begin Encryption---");
    let ofb = OFB::new(&round_keys, &iv_state, output_count);

    let mut encrypted_blocks = input_blocks
        .iter()
        .map(|x| State::from_u8_enc(x, client_key))
        .collect::<Vec<_>>(); // Convert into State Matrixes and encrypt with FHE

    let start = Instant::now();
    ofb.encrypt(&mut encrypted_blocks, server_key); // Encrypt with AES
    println!(
        "AES of #{:?} outputs computed in: {:?}",
        input_blocks.len(),
        start.elapsed()
    );

    assert_eq!(
        encrypted_blocks
            .iter()
            .map(|x| x.decrypt_to_u8(client_key))
            .collect::<Vec<_>>(),
        expected_result
    );

    // DECRYPTION
    println!("---Decryption---");

    let start = Instant::now();
    ofb.decrypt(&mut encrypted_blocks, server_key); // Decrypt with AES
    println!(
        "AES of #{:?} outputs decrypted in: {:?}",
        input_blocks.len(),
        start.elapsed()
    );

    assert_eq!(
        encrypted_blocks
            .iter()
            .map(|x| x.decrypt_to_u8(client_key))
            .collect::<Vec<_>>(),
        input_blocks.to_vec()
    );

    println!("OFB mode test passed");
}

fn prepare_key_schedule(
    encryption_key: &[u8; 16],
    offline_key_expansion: bool,
    server_key: &ServerKey,
    client_key: &ClientKey,
) -> [Key; 11] {
    // KEY EXPANSION
    println!(
        "---Key Expansion ({:})---",
        if offline_key_expansion {
            "offline"
        } else {
            "online"
        }
    );

    let start = Instant::now();
    let round_keys: [Key; 11] = if offline_key_expansion {
        let clear_keys = key_expansion_clear(encryption_key);
        array::from_fn(|i| Key::from_u8_enc(&clear_keys[i], client_key))
    } else {
        let curr_key = Key::from_u8_enc(encryption_key, client_key);
        curr_key.generate_round_keys(server_key)
    };

    println!("AES key expansion took: {:?}", start.elapsed());

    round_keys
}

fn simulate_cbc_encryption(blocks: &[[u8; 16]], key: &[u8; 16], iv: &[u8; 16]) -> Vec<[u8; 16]> {
    let aes = Aes128::new(GenericArray::from_slice(key));
    let mut prev_cipher = *iv; // Start with IV
    let mut ciphertext = Vec::with_capacity(blocks.len());
    let mut blocks = blocks.to_vec();

    for block in blocks.iter_mut() {
        // XOR block with previous ciphertext (or IV for first block)
        for i in 0..16 {
            block[i] ^= prev_cipher[i];
        }

        // Encrypt block
        let mut block_arr = GenericArray::from_mut_slice(block);
        aes.encrypt_block(&mut block_arr);

        // Store ciphertext and update previous block
        ciphertext.push(*block);
        prev_cipher = *block;
    }

    ciphertext
}

fn create_counter_blocks(iv: &[u8; 16], output_count: u8) -> Vec<[u8; 16]> {
    let mut counters = Vec::with_capacity(output_count as usize);
    let mut counter = iv.clone();
    counter[8..16].fill(0); // Clear the counter part of the IV

    for _ in 0..output_count {
        counters.push(counter);
        counter = increment_counter_value(counter);
    }
    counters
}

fn increment_counter_value(mut counter: [u8; 16]) -> [u8; 16] {
    for i in (8..16).rev() {
        if counter[i] == 255 {
            counter[i] = 0;
        } else {
            counter[i] += 1;
            break;
        }
    }
    counter
}

fn simulate_ctr_encryption(blocks: &[[u8; 16]], key: &[u8; 16], counters: &[[u8; 16]]) -> Vec<[u8; 16]> {
    let mut result = counters.to_vec();
    let aes = Aes128::new(GenericArray::from_slice(key));

    for i in 0..result.len() {
        let mut counter_arr = GenericArray::from_mut_slice(&mut result[i]);
        aes.encrypt_block(&mut counter_arr);

        for j in 0..16 {
            result[i][j] ^= blocks[i][j];
        }
    }

    result
}

fn simulate_ofb_encryption(blocks: &[[u8; 16]], key: &[u8; 16], iv: &[u8; 16]) -> Vec<[u8; 16]> {
    let mut result = blocks.to_vec();
    let aes = Aes128::new(GenericArray::from_slice(key));

    let mut curr_cipher = iv.clone();
    let mut curr_cipher = GenericArray::from_mut_slice(&mut curr_cipher);
    aes.encrypt_block(&mut curr_cipher);

    for i in 0..result.len() {
        for j in 0..16 {
            result[i][j] ^= curr_cipher[j];
        }
        aes.encrypt_block(&mut curr_cipher);
    }

    result
}
