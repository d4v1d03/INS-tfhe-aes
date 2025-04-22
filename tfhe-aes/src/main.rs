// Copyright (c) 2023 Your Name
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
struct Args {
    #[arg(short = 'n', long = "number-of-outputs", default_value_t = 1)]
    number_of_outputs: u8,

    #[arg(short, long)]
    iv: String,

    #[arg(short, long)]
    key: String,

    #[arg(short = 'x', long = "key-expansion-offline", default_value_t = false)]
    key_expansion_offline: bool,

    #[arg(short, long, default_value = "ECB")]
    mode: String,
}

enum Mode {
    ECB,
    CBC,
    CTR,
    OFB,
}

fn main() {
    let args = Args::parse();

    println!("Number of Outputs: {}", args.number_of_outputs);
    println!("IV: {}", args.iv);
    println!("Key: {}", args.key);
    println!("Key Expansion Offline: {}", args.key_expansion_offline);
    println!("Mode: {}", args.mode);

    let key = parse_hex_16(&args.key).expect("Invalid key format");
    let iv = parse_hex_16(&args.iv).expect("Invalid IV format");
    let mode = parse_mode(&args.mode).expect("Invalid Mode format");
    let key_expansion_offline = args.key_expansion_offline;
    let number_of_outputs = args.number_of_outputs;

    let mut rng = rand::rng();
    let mut random_test_blocks = Vec::with_capacity(args.number_of_outputs as usize);
    for _ in 0..args.number_of_outputs {
        let mut block = [0u8; 16];
        rng.fill(&mut block);
        random_test_blocks.push(block);
    }

    let (client_key, server_key) = gen_keys();

    match mode {
        Mode::ECB => test_ecb(
            &key,
            &random_test_blocks,
            key_expansion_offline,
            &server_key,
            &client_key,
        ),
        Mode::CBC => test_cbc(
            &key,
            &iv,
            &random_test_blocks,
            key_expansion_offline,
            number_of_outputs,
            &server_key,
            &client_key,
        ),
        Mode::CTR => test_ctr(
            &key,
            &iv,
            &random_test_blocks,
            key_expansion_offline,
            number_of_outputs,
            &server_key,
            &client_key,
        ),
        Mode::OFB => test_ofb(
            &key,
            &iv,
            &random_test_blocks,
            key_expansion_offline,
            number_of_outputs,
            &server_key,
            &client_key,
        ),
    }
}

fn parse_mode(input: &str) -> Result<Mode, String> {
    match input {
        "ECB" => Ok(Mode::ECB),
        "CBC" => Ok(Mode::CBC),
        "CTR" => Ok(Mode::CTR),
        "OFB" => Ok(Mode::OFB),
        _ => Err(format!("Invalid mode: {}", input)),
    }
}

fn parse_hex_16(hex_str: &str) -> Result<[u8; 16], String> {
    if hex_str.len() != 32 {
        return Err(format!(
            "Must be 32 hex characters (16 bytes), it is currently {} characters.",
            hex_str.len()
        ));
    }
    let bytes = hex::decode(hex_str).map_err(|_| "Failed to decode hex")?;
    let mut array = [0u8; 16];
    array.copy_from_slice(&bytes[..16]);
    Ok(array)
}

fn test_ecb(
    key: &[u8; 16],
    blocks: &[[u8; 16]],
    key_expansion_offline: bool,
    server_key: &ServerKey,
    client_key: &ClientKey,
) {
    println!("---Testing ECB mode---");

    let aes_clear = Aes128::new(GenericArray::from_slice(key));
    let mut expected_result = blocks.to_vec();

    for block in expected_result.iter_mut() {
        aes_clear.encrypt_block(GenericArray::from_mut_slice(block));
    }

    let keys = key_expansion(key, key_expansion_offline, server_key, client_key);

    // ENCRYPTION
    println!("---Begin Encryption---");
    let ecb = ECB::new(&keys);

    let mut encrypted_blocks = blocks
        .iter()
        .map(|x| State::from_u8_enc(x, client_key))
        .collect::<Vec<_>>(); // Convert into State Matrixes and encrypt with FHE

    let start = Instant::now();
    encrypted_blocks
        .iter_mut()
        .for_each(|x| ecb.encrypt(x, server_key)); // Encrypt with AES

    println!(
        "AES of #{:?} outputs computed in: {:?}",
        blocks.len(),
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
        blocks.len(),
        start.elapsed()
    );

    assert_eq!(
        encrypted_blocks
            .iter()
            .map(|x| x.decrypt_to_u8(client_key))
            .collect::<Vec<_>>(),
        blocks.to_vec()
    );

    println!("ECB mode test passed");
}

fn test_cbc(
    key: &[u8; 16],
    iv: &[u8; 16],
    blocks: &[[u8; 16]],
    key_expansion_offline: bool,
    number_of_outputs: u8,
    server_key: &ServerKey,
    client_key: &ClientKey,
) {
    println!("Testing CBC mode");

    let expected_result = cbc_encrypt_clear(blocks, key, iv);

    let keys = key_expansion(key, key_expansion_offline, server_key, client_key);
    let iv = State::from_u8_enc(iv, client_key);
    // ENCRYPTION
    println!("---Begin Encryption---");
    let cbc: CBC = CBC::new(&keys, &iv, number_of_outputs);

    let start = Instant::now();
    let mut encrypted_blocks = blocks
        .iter()
        .map(|x| State::from_u8_enc(x, client_key))
        .collect::<Vec<_>>(); // Convert into State Matrixes and encrypt with FHE
    println!("Conversion to FHE Time Taken: {:?}", start.elapsed());

    let start = Instant::now();
    cbc.encrypt(&mut encrypted_blocks, server_key); // Encrypt with AES
    println!(
        "AES of #{:?} outputs computed in: {:?}",
        blocks.len(),
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
        blocks.len(),
        start.elapsed()
    );

    assert_eq!(
        encrypted_blocks
            .iter()
            .map(|x| x.decrypt_to_u8(client_key))
            .collect::<Vec<_>>(),
        blocks.to_vec()
    );

    println!("CBC mode test passed");
}

fn test_ctr(
    key: &[u8; 16],
    iv: &[u8; 16],
    blocks: &[[u8; 16]],
    key_expansion_offline: bool,
    number_of_outputs: u8,
    server_key: &ServerKey,
    client_key: &ClientKey,
) {
    println!("Testing CTR mode");
    let counters = generate_counters(iv, number_of_outputs);
    let expected_result = ctr_encrypt_clear(blocks, key, &counters);

    let keys = key_expansion(key, key_expansion_offline, server_key, client_key);

    // ENCRYPTION
    println!("---Begin Encryption---");
    let encrypted_counters = counters
        .iter()
        .map(|x| State::from_u8_enc(x, client_key))
        .collect::<Vec<_>>(); // Convert into State Matrixes and encrypt with FHE
    let ctr = CTR::new(&keys, &encrypted_counters, number_of_outputs);

    let mut encrypted_blocks = blocks
        .iter()
        .map(|x| State::from_u8_enc(x, client_key))
        .collect::<Vec<_>>(); // Convert into State Matrixes and encrypt with FHE

    let start = Instant::now();
    ctr.encrypt(&mut encrypted_blocks, server_key); // Encrypt with AES
    println!(
        "AES of #{:?} outputs computed in: {:?}",
        blocks.len(),
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
        blocks.len(),
        start.elapsed()
    );

    assert_eq!(
        encrypted_blocks
            .iter()
            .map(|x| x.decrypt_to_u8(client_key))
            .collect::<Vec<_>>(),
        blocks.to_vec()
    );

    println!("CTR mode test passed");
}

fn test_ofb(
    key: &[u8; 16],
    iv: &[u8; 16],
    blocks: &[[u8; 16]],
    key_expansion_offline: bool,
    number_of_outputs: u8,
    server_key: &ServerKey,
    client_key: &ClientKey,
) {
    println!("Testing OFB mode");

    let expected_result = ofb_encrypt_clear(blocks, key, iv);

    let keys = key_expansion(key, key_expansion_offline, server_key, client_key);
    let iv = State::from_u8_enc(iv, client_key);

    // ENCRYPTION
    println!("---Begin Encryption---");
    let ofb = OFB::new(&keys, &iv, number_of_outputs);

    let mut encrypted_blocks = blocks
        .iter()
        .map(|x| State::from_u8_enc(x, client_key))
        .collect::<Vec<_>>(); // Convert into State Matrixes and encrypt with FHE

    let start = Instant::now();
    ofb.encrypt(&mut encrypted_blocks, server_key); // Encrypt with AES
    println!(
        "AES of #{:?} outputs computed in: {:?}",
        blocks.len(),
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
        blocks.len(),
        start.elapsed()
    );

    assert_eq!(
        encrypted_blocks
            .iter()
            .map(|x| x.decrypt_to_u8(client_key))
            .collect::<Vec<_>>(),
        blocks.to_vec()
    );

    println!("OFB mode test passed");
}

fn key_expansion(
    key: &[u8; 16],
    key_expansion_offline: bool,
    server_key: &ServerKey,
    client_key: &ClientKey,
) -> [Key; 11] {
    // KEY EXPANSION
    println!(
        "---Key Expansion ({:})---",
        if key_expansion_offline {
            "offline"
        } else {
            "online"
        }
    );

    let start = Instant::now();
    let keys: [Key; 11] = if key_expansion_offline {
        let clear_keys = key_expansion_clear(key);
        array::from_fn(|i| Key::from_u8_enc(&clear_keys[i], client_key))
    } else {
        let curr_key = Key::from_u8_enc(key, client_key);
        curr_key.generate_round_keys(server_key)
    };

    println!("AES key expansion took: {:?}", start.elapsed());

    keys
}

fn cbc_encrypt_clear(blocks: &[[u8; 16]], key: &[u8; 16], iv: &[u8; 16]) -> Vec<[u8; 16]> {
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

fn generate_counters(iv: &[u8; 16], number_of_outputs: u8) -> Vec<[u8; 16]> {
    let mut counters = Vec::with_capacity(number_of_outputs as usize);
    let mut counter = iv.clone();
    counter[8..16].fill(0); // Clear the counter part of the IV

    for _ in 0..number_of_outputs {
        counters.push(counter);
        counter = increment_counter(counter);
    }
    counters
}

fn increment_counter(mut counter: [u8; 16]) -> [u8; 16] {
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

fn ctr_encrypt_clear(blocks: &[[u8; 16]], key: &[u8; 16], counters: &[[u8; 16]]) -> Vec<[u8; 16]> {
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

fn ofb_encrypt_clear(blocks: &[[u8; 16]], key: &[u8; 16], iv: &[u8; 16]) -> Vec<[u8; 16]> {
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
