// Copyright (c) 2023 Amit Pandey
// FHE-AES: Core primitive operations for homomorphic byte operations
// Licensed under the Apache License, Version 2.0

use rayon::prelude::*;

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{LazyLock, RwLock};
use tfhe::boolean::prelude::*;
use tfhe::boolean::server_key::*;

use crate::boolean_tree::{BooleanExpr, Operand, Runnable};
use crate::sbox::*;

/// Global server key for convenience operations
pub static GLOBAL_SERVER_KEY: RwLock<Option<ServerKey>> = const { RwLock::new(None) };

// Pre-computed boolean expression trees for S-box and inverse S-box operations
pub static S_BOX_EXPR: RwLock<LazyLock<Vec<BooleanExpr>>> =
    RwLock::new(LazyLock::new(|| create_boolean_expressions(S_BOX_DATA)));
pub static INV_S_BOX_EXPR: RwLock<LazyLock<Vec<BooleanExpr>>> =
    RwLock::new(LazyLock::new(|| create_boolean_expressions(INV_S_BOX_DATA)));

/// Sets the global server key for convenience functions
pub fn register_server_key(key: &ServerKey) {
    let mut guard = GLOBAL_SERVER_KEY.write().unwrap();
    *guard = Some(key.clone());
}

/// Clears the global server key
pub fn clear_server_key() {
    let mut guard = GLOBAL_SERVER_KEY.write().unwrap();
    *guard = None;
}

/// Executes a function with the global server key
///
/// This convenience function allows operating with the globally registered server key
/// without having to pass it explicitly through function calls.
///
/// # Parameters
/// * `operation` - The function to execute with the server key
///
/// # Returns
/// The result of the function execution
#[inline(always)]
pub fn with_server_key<F, T>(operation: F) -> T
where
    F: FnOnce(&ServerKey) -> T + std::marker::Send,
    T: std::marker::Send,
{
    let guard = GLOBAL_SERVER_KEY.read().unwrap();
    let server_key = &guard
        .as_ref()
        .expect("Server key must be registered before calling this function");
    operation(server_key)
}

/// FHEByte represents an encrypted byte in the FHE context
///
/// This struct is a wrapper around a VecDeque of boolean Ciphertexts,
/// providing bit-level operations on encrypted bytes. The byte is stored
/// in big-endian format (most significant bit first).
///
/// Key features:
/// - Basic bitwise operations: XOR, AND, OR, NOT
/// - Substitution operations (S-box and inverse S-box)
/// - Field operations in GF(2^8) for AES mix columns
/// - Bit manipulation (shifts, rotations)
#[derive(Clone, Debug)]
pub struct FHEByte {
    bits: VecDeque<Ciphertext>,
}

impl FHEByte {
    /// Creates a new FHEByte from an array of boolean values
    ///
    /// # Parameters
    /// * `bit_values` - Array of 8 boolean values
    /// * `client_key` - Client key for encryption
    ///
    /// # Returns
    /// A new FHEByte instance
    pub fn new(bit_values: &[bool], client_key: &ClientKey) -> Self {
        assert!(
            bit_values.len() == 8,
            "FHEByte must be initialized with exactly 8 boolean values"
        );
        let bits = bit_values
            .into_iter()
            .map(|bit| client_key.encrypt(*bit).into())
            .collect();
        Self { bits }
    }

    /// Creates a new FHEByte from a plaintext byte value
    ///
    /// # Parameters
    /// * `value` - The plaintext byte value to encrypt
    /// * `client_key` - Client key for encryption
    ///
    /// # Returns
    /// A new FHEByte instance with encrypted bits
    pub fn from_u8_enc(value: &u8, client_key: &ClientKey) -> Self {
        let bits: VecDeque<Ciphertext> = (0..8)
            .rev()
            .map(|bit_pos| client_key.encrypt(value & (1 << bit_pos) != 0))
            .collect();
        Self { bits }
    }

    /// Creates a new FHEByte with trivial encryption (no security)
    ///
    /// # Parameters
    /// * `value` - The plaintext byte value
    /// * `server_key` - Server key for trivial encryption
    ///
    /// # Returns
    /// A new FHEByte instance with trivially encrypted bits
    pub fn from_u8_clear(value: &u8, server_key: &ServerKey) -> Self {
        let bits: VecDeque<Ciphertext> = (0..8)
            .rev()
            .map(|bit_pos| server_key.trivial_encrypt(value & (1 << bit_pos) != 0))
            .collect();
        Self { bits }
    }

    /// Decrypts the FHEByte to a vector of boolean values
    ///
    /// # Parameters
    /// * `client_key` - Client key for decryption
    ///
    /// # Returns
    /// Vector of 8 decrypted boolean values
    pub fn decrypt(&self, client_key: &ClientKey) -> Vec<bool> {
        self.bits.iter().map(|bit| client_key.decrypt(bit)).collect()
    }

    /// Decrypts the FHEByte to a plaintext byte value
    ///
    /// # Parameters
    /// * `client_key` - Client key for decryption
    ///
    /// # Returns
    /// The decrypted byte value
    pub fn decrypt_to_u8(&self, client_key: &ClientKey) -> u8 {
        self.decrypt(client_key)
            .iter()
            .enumerate()
            .filter_map(|(i, &bit)| bit.then(|| 2_u8.pow(8 - (i + 1) as u32)))
            .sum()
    }

    /// Performs bitwise XOR operation in-place
    ///
    /// # Parameters
    /// * `other` - The other FHEByte to XOR with
    /// * `server_key` - Server key for homomorphic operations
    pub fn xor_in_place(&mut self, other: &Self, server_key: &ServerKey) {
        self.bits
            .par_iter_mut()
            .zip(other.bits.par_iter())
            .for_each_with(server_key, |server_key, (bit, other_bit)| 
                server_key.xor_assign(bit, other_bit)
            )
    }

    /// Performs bitwise XOR operation
    ///
    /// # Parameters
    /// * `other` - The other FHEByte to XOR with
    /// * `server_key` - Server key for homomorphic operations
    ///
    /// # Returns
    /// A new FHEByte with the result of the XOR operation
    pub fn xor(&self, other: &Self, server_key: &ServerKey) -> Self {
        let mut result = self.clone();
        result.xor_in_place(other, server_key);
        result
    }

    /// Performs bitwise AND operation in-place
    ///
    /// # Parameters
    /// * `other` - The other FHEByte to AND with
    /// * `server_key` - Server key for homomorphic operations
    pub fn and_in_place(&mut self, other: &Self, server_key: &ServerKey) {
        self.bits
            .par_iter_mut()
            .zip(other.bits.par_iter())
            .for_each_with(server_key, |server_key, (bit, other_bit)| 
                server_key.and_assign(bit, other_bit)
            )
    }

    /// Performs bitwise AND operation
    ///
    /// # Parameters
    /// * `other` - The other FHEByte to AND with
    /// * `server_key` - Server key for homomorphic operations
    ///
    /// # Returns
    /// A new FHEByte with the result of the AND operation
    pub fn and(&self, other: &Self, server_key: &ServerKey) -> Self {
        let mut result = self.clone();
        result.and_in_place(other, server_key);
        result
    }

    /// Performs bitwise OR operation in-place
    ///
    /// # Parameters
    /// * `other` - The other FHEByte to OR with
    /// * `server_key` - Server key for homomorphic operations
    pub fn or_in_place(&mut self, other: &Self, server_key: &ServerKey) {
        self.bits
            .par_iter_mut()
            .zip(other.bits.par_iter())
            .for_each_with(server_key, |server_key, (bit, other_bit)| 
                server_key.or_assign(bit, other_bit)
            )
    }

    /// Performs bitwise OR operation
    ///
    /// # Parameters
    /// * `other` - The other FHEByte to OR with
    /// * `server_key` - Server key for homomorphic operations
    ///
    /// # Returns
    /// A new FHEByte with the result of the OR operation
    pub fn or(&self, other: &Self, server_key: &ServerKey) -> Self {
        let mut result = self.clone();
        result.or_in_place(other, server_key);
        result
    }

    /// Performs bitwise NOT operation in-place
    ///
    /// # Parameters
    /// * `server_key` - Server key for homomorphic operations
    pub fn not_in_place(&mut self, server_key: &ServerKey) {
        self.bits
            .par_iter_mut()
            .for_each_with(server_key, |server_key, bit| 
                server_key.not_assign(bit)
            )
    }

    /// Performs bitwise NOT operation
    ///
    /// # Parameters
    /// * `server_key` - Server key for homomorphic operations
    ///
    /// # Returns
    /// A new FHEByte with the result of the NOT operation
    pub fn not(&self, server_key: &ServerKey) -> Self {
        let mut result = self.clone();
        result.not_in_place(server_key);
        result
    }

    /// Rotates bits to the right in-place
    ///
    /// # Parameters
    /// * `shift` - Number of positions to rotate
    fn rotate_right_in_place(&mut self, shift: usize) -> () {
        self.bits.rotate_right(shift);
    }

    /// Rotates bits to the left in-place
    ///
    /// # Parameters
    /// * `shift` - Number of positions to rotate
    fn rotate_left_in_place(&mut self, shift: usize) -> () {
        self.bits.rotate_left(shift);
    }

    /// Rotates bits to the left
    ///
    /// # Parameters
    /// * `shift` - Number of positions to rotate
    ///
    /// # Returns
    /// A new FHEByte with rotated bits
    fn rotate_left(&self, shift: usize) -> Self {
        let mut result = self.clone();
        result.rotate_left_in_place(shift);
        result
    }

    /// Rotates bits to the right
    ///
    /// # Parameters
    /// * `shift` - Number of positions to rotate
    ///
    /// # Returns
    /// A new FHEByte with rotated bits
    fn rotate_right(&self, shift: usize) -> Self {
        let mut result = self.clone();
        result.rotate_right_in_place(shift);
        result
    }

    /// Shifts bits to the right in-place, filling with zeros
    ///
    /// # Parameters
    /// * `shift` - Number of positions to shift
    /// * `server_key` - Server key for creating trivial encryptions
    fn shift_right_in_place(&mut self, shift: usize, server_key: &ServerKey) -> () {
        let shift = shift.clamp(0, 8);
        for _ in 0..shift {
            self.bits.push_front(server_key.trivial_encrypt(false));
            self.bits.pop_back();
        }
    }

    /// Shifts bits to the left in-place, filling with zeros
    ///
    /// # Parameters
    /// * `shift` - Number of positions to shift
    /// * `server_key` - Server key for creating trivial encryptions
    fn shift_left_in_place(&mut self, shift: usize, server_key: &ServerKey) -> () {
        let shift = shift.clamp(0, 8);

        for _ in 0..shift {
            self.bits.push_back(server_key.trivial_encrypt(false));
            self.bits.pop_front();
        }
    }

    /// Shifts bits to the left, filling with zeros
    ///
    /// # Parameters
    /// * `shift` - Number of positions to shift
    /// * `server_key` - Server key for creating trivial encryptions
    ///
    /// # Returns
    /// A new FHEByte with shifted bits
    fn shift_left(&self, shift: usize, server_key: &ServerKey) -> Self {
        let mut result = self.clone();
        result.shift_left_in_place(shift, server_key);
        result
    }

    /// Shifts bits to the right, filling with zeros
    ///
    /// # Parameters
    /// * `shift` - Number of positions to shift
    /// * `server_key` - Server key for creating trivial encryptions
    ///
    /// # Returns
    /// A new FHEByte with shifted bits
    fn shift_right(&self, shift: usize, server_key: &ServerKey) -> Self {
        let mut result = self.clone();
        result.shift_right_in_place(shift, server_key);
        result
    }

    /// Creates a new FHEByte with a trivially encrypted value
    ///
    /// # Parameters
    /// * `clear_value` - The plaintext byte value
    /// * `server_key` - Server key for trivial encryption
    ///
    /// # Returns
    /// A new FHEByte with trivially encrypted bits
    pub fn trivial_clear(clear_value: u8, server_key: &ServerKey) -> Self {
        let bits = (0..8)
            .rev()
            .into_iter()
            .map(|shift| server_key.trivial_encrypt(clear_value & (1 << shift) != 0))
            .collect();
        Self { bits }
    }

    pub fn trivial_false(server_key: &ServerKey) -> Self {
        Self::trivial_clear(0, server_key)
    }

    pub fn sub_byte(&self, server_key: &ServerKey) -> Self {
        let curr_data = self.bits.iter().rev().cloned().collect::<Vec<_>>();

        let lazy_lock_sbox = S_BOX_EXPR.read().unwrap();
        let s_box_exprs: &Vec<BooleanExpr> = lazy_lock_sbox.as_ref();
        let mut hashset: HashSet<BooleanExpr> = HashSet::new();
        for expr in s_box_exprs.iter() {
            expr.to_hashset(&mut hashset);
        }

        let mut grouped_by_stage: Vec<Vec<BooleanExpr>> = vec![Vec::new(); 8];

        // Iterate over each BooleanExpr and insert them into the appropriate HashSet based on their stage
        for expr in hashset {
            let stage = expr.stage() as usize;
            grouped_by_stage[stage].push(expr);
        }

        // Initialize HashMap with all the operands that are required for the computation
        let mut operands: HashMap<Operand, Ciphertext> = HashMap::new();
        operands.insert(Operand::Bit0, curr_data[0].clone());
        operands.insert(Operand::Bit1, curr_data[1].clone());
        operands.insert(Operand::Bit2, curr_data[2].clone());
        operands.insert(Operand::Bit3, curr_data[3].clone());
        operands.insert(Operand::Bit4, curr_data[4].clone());
        operands.insert(Operand::Bit5, curr_data[5].clone());
        operands.insert(Operand::Bit6, curr_data[6].clone());
        operands.insert(Operand::Bit7, curr_data[7].clone());

        operands.insert(Operand::NotBit0, server_key.not(&curr_data[0]));
        operands.insert(Operand::NotBit1, server_key.not(&curr_data[1]));
        operands.insert(Operand::NotBit2, server_key.not(&curr_data[2]));
        operands.insert(Operand::NotBit3, server_key.not(&curr_data[3]));
        operands.insert(Operand::NotBit4, server_key.not(&curr_data[4]));
        operands.insert(Operand::NotBit5, server_key.not(&curr_data[5]));
        operands.insert(Operand::NotBit6, server_key.not(&curr_data[6]));
        operands.insert(Operand::NotBit7, server_key.not(&curr_data[7]));

        operands.insert(Operand::True, server_key.trivial_encrypt(true));
        operands.insert(Operand::False, server_key.trivial_encrypt(false));

        let mut hash_map: HashMap<BooleanExpr, Ciphertext> = HashMap::new();
        for i in 0..8 {
            hash_map.extend(
                grouped_by_stage[i]
                    .clone()
                    .into_iter()
                    .map(|expr| (expr.clone(), Runnable::new(&operands, &hash_map, expr)))
                    .collect::<Vec<_>>()
                    .into_par_iter()
                    .map_with(server_key, |server_key, (expr, runnable)| {
                        (expr, runnable.run(server_key))
                    })
                    .collect::<HashMap<_, _>>()
                    .into_iter(),
            );
        }

        // Once all BooleanExpr are evaluated, we retrieve the relevant Ciphertexts and store them into the FHEByte.
        let data = s_box_exprs
            .iter()
            .map(|expr| hash_map.get(expr).unwrap().clone())
            .collect();

        FHEByte { data }
    }

    pub fn inv_sub_byte(&self, server_key: &ServerKey) -> Self {
        let curr_data = self.bits.iter().rev().cloned().collect::<Vec<_>>();

        let lazy_lock_inv_sbox = INV_S_BOX_EXPR.read().unwrap();
        let inv_s_box_exprs: &Vec<BooleanExpr> = lazy_lock_inv_sbox.as_ref();

        let mut hashset: HashSet<BooleanExpr> = HashSet::new();
        for expr in inv_s_box_exprs.iter() {
            expr.to_hashset(&mut hashset);
        }

        let mut grouped_by_stage: Vec<Vec<BooleanExpr>> = vec![Vec::new(); 8];

        // Iterate over each BooleanExpr and insert them into the appropriate HashSet based on their stage
        for expr in hashset {
            let stage = expr.stage() as usize;
            grouped_by_stage[stage].push(expr);
        }

        // Initialize HashMap with all the operands that are required for the computation
        let mut operands: HashMap<Operand, Ciphertext> = HashMap::new();
        operands.insert(Operand::Bit0, curr_data[0].clone());
        operands.insert(Operand::Bit1, curr_data[1].clone());
        operands.insert(Operand::Bit2, curr_data[2].clone());
        operands.insert(Operand::Bit3, curr_data[3].clone());
        operands.insert(Operand::Bit4, curr_data[4].clone());
        operands.insert(Operand::Bit5, curr_data[5].clone());
        operands.insert(Operand::Bit6, curr_data[6].clone());
        operands.insert(Operand::Bit7, curr_data[7].clone());

        operands.insert(Operand::NotBit0, server_key.not(&curr_data[0]));
        operands.insert(Operand::NotBit1, server_key.not(&curr_data[1]));
        operands.insert(Operand::NotBit2, server_key.not(&curr_data[2]));
        operands.insert(Operand::NotBit3, server_key.not(&curr_data[3]));
        operands.insert(Operand::NotBit4, server_key.not(&curr_data[4]));
        operands.insert(Operand::NotBit5, server_key.not(&curr_data[5]));
        operands.insert(Operand::NotBit6, server_key.not(&curr_data[6]));
        operands.insert(Operand::NotBit7, server_key.not(&curr_data[7]));

        operands.insert(Operand::True, server_key.trivial_encrypt(true));
        operands.insert(Operand::False, server_key.trivial_encrypt(false));

        let mut hash_map: HashMap<BooleanExpr, Ciphertext> = HashMap::new();
        for i in 0..8 {
            hash_map.extend(
                grouped_by_stage[i]
                    .clone()
                    .into_iter()
                    .map(|expr| (expr.clone(), Runnable::new(&operands, &hash_map, expr)))
                    .collect::<Vec<_>>()
                    .into_par_iter()
                    .map_with(server_key, |server_key, (expr, runnable)| {
                        (expr, runnable.run(server_key))
                    })
                    .collect::<HashMap<_, _>>()
                    .into_iter(),
            );
        }

        // Once all BooleanExpr are evaluated, we retrieve the relevant Ciphertexts and store them into the FHEByte.
        let data = inv_s_box_exprs
            .iter()
            .map(|expr| hash_map.get(expr).unwrap().clone())
            .collect();

        FHEByte { data }
    }

    /// This function multiplies the byte by x in GF(2^8) and returns the result.
    ///
    /// This is achieved by first checking if the most significant bit is set.
    /// If it is, then the byte is shifted left by 1 and then XORed with the irreducible polynomial 0x1b.
    /// Otherwise, the byte is just shifted left by 1.
    pub fn mul_x_gf2_in_place(&mut self, server_key: &ServerKey) {
        let conditional_bit = self.bits[0].clone();
        self.shift_left_in_place(1, server_key);
        let irr_poly = FHEByte::trivial_clear(0x1b, server_key);

        self.bits = self
            .bits
            .par_iter()
            .zip(irr_poly.bits.par_iter())
            .map_with(server_key, |server_key, (x, y)| {
                server_key.mux(&conditional_bit, &server_key.xor(x, y), x)
            })
            .collect();
    }

    pub fn mul_x_gf2(&self, server_key: &ServerKey) -> Self {
        let mut result = self.clone();
        result.mul_x_gf2_in_place(server_key);
        result
    }
}

#[cfg(test)]

mod tests {
    use super::*;
    use tfhe::boolean::gen_keys;

    fn clear_mul_x_gf2(x: &u8) -> u8 {
        let mut res = x.clone();
        res <<= 1;
        if x & 0x80 != 0 {
            res ^= 0x1b;
        }

        res
    }

    #[test]
    fn test_xor() {
        let (client_key, server_key) = gen_keys();

        let x = FHEByte::new(
            &vec![true, true, true, true, true, true, true, true],
            &client_key,
        );
        let y = FHEByte::new(
            &vec![true, false, true, false, true, true, true, true],
            &client_key,
        );

        let mut test_data: Vec<_> = (0..200).into_iter().map(|_| x.clone()).collect();

        test_data
            .par_iter_mut()
            .for_each_with(server_key, |server_key, x| x.xor_in_place(&y, server_key));

        assert!(
            test_data[0].decrypt(&client_key)
                == vec![false, true, false, true, false, false, false, false]
        );
    }

    #[test]
    fn test_and() {
        let (client_key, server_key) = gen_keys();

        let x = FHEByte::new(
            &vec![true, true, true, true, true, true, true, true],
            &client_key,
        );

        let y = FHEByte::new(
            &vec![true, false, true, false, true, true, true, true],
            &client_key,
        );

        let mut test_data: Vec<_> = (0..200).into_iter().map(|_| x.clone()).collect();

        test_data
            .par_iter_mut()
            .for_each(|x| x.and_in_place(&y, &server_key));

        assert!(
            test_data[0].decrypt(&client_key)
                == vec![true, false, true, false, true, true, true, true]
        );
    }

    #[test]
    fn test_sub_byte() {
        let (client_key, server_key) = gen_keys();

        let x = FHEByte::from_u8_enc(&0x01, &client_key);

        let y = x.sub_byte(&server_key);

        assert_eq!(
            y.decrypt_to_u8(&client_key),
            0x7c,
            "{:#x?}",
            y.decrypt_to_u8(&client_key)
        );
    }

    #[test]
    fn test_mul_gf_2() {
        let (client_key, server_key) = gen_keys();

        for clear_value in 0..=255 {
            let x = FHEByte::from_u8_enc(&clear_value, &client_key);

            let y: Vec<_> = (0..1)
                .into_par_iter()
                .map(|_| x.mul_x_gf2(&server_key))
                .collect();

            assert_eq!(
                y[0].decrypt_to_u8(&client_key),
                clear_mul_x_gf2(&clear_value)
            )
        }
    }
}
