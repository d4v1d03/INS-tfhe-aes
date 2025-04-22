use rayon::prelude::*;
use tfhe::boolean::prelude::*;

use crate::primitive::*;
use crate::sbox::*;

const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];

/// This represents a key in AES-128. The key is represented in a transposed manner, and all algorithms are implemented as such.
/// For more details for each algorithm, refer to the [Efficient Implementation of AES in 32 bit systems](https://link.springer.com/content/pdf/10.1007/3-540-36400-5_13.pdf) paper.

#[derive(Clone, Debug)]
pub struct Key {
    pub data: [FHEByte; 16],
}

impl Key {
    pub fn from_u128_enc(value: u128, client_key: &ClientKey) -> Self {
        let mut data: [FHEByte; 16] = (0..16)
            .rev()
            .map(|i| FHEByte::from_u8_enc(&{ ((value >> 8 * i) & 0xFF) as u8 }, client_key))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        // TRANSPOSE INPUT DATA
        data.swap(1, 4);
        data.swap(2, 8);
        data.swap(3, 12);

        data.swap(6, 9);
        data.swap(7, 13);

        data.swap(11, 14);

        Self { data }
    }

    pub fn from_u128_clear(value: u128, server_key: &ServerKey) -> Self {
        let mut data: [FHEByte; 16] = (0..16)
            .rev()
            .map(|i| FHEByte::from_u8_clear(&{ ((value >> 8 * i) & 0xFF) as u8 }, server_key))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        // TRANSPOSE INPUT DATA
        data.swap(1, 4);
        data.swap(2, 8);
        data.swap(3, 12);

        data.swap(6, 9);
        data.swap(7, 13);

        data.swap(11, 14);

        Self { data }
    }

    pub fn from_u8_enc(data: &[u8; 16], client_key: &ClientKey) -> Self {
        let mut data = data.map(|value| FHEByte::from_u8_enc(&value, client_key));

        // TRANSPOSE INPUT DATA
        data.swap(1, 4);
        data.swap(2, 8);
        data.swap(3, 12);

        data.swap(6, 9);
        data.swap(7, 13);

        data.swap(11, 14);
        Self { data }
    }

    pub fn from_u8_clear(data: &[u8; 16], server_key: &ServerKey) -> Self {
        let mut data = data.map(|value| FHEByte::from_u8_clear(&value, server_key));

        // TRANSPOSE INPUT DATA
        data.swap(1, 4);
        data.swap(2, 8);
        data.swap(3, 12);

        data.swap(6, 9);
        data.swap(7, 13);

        data.swap(11, 14);
        Self { data }
    }

    pub fn generate_next_key_in_place(&mut self, rcon: &u8, server_key: &ServerKey) {
        let mut temp: Vec<_> = [7, 11, 15, 3]
            .into_par_iter()
            .map(|i| self.data[i].sub_byte(server_key))
            .collect();
        temp[0].xor_in_place(&FHEByte::from_u8_clear(rcon, server_key), server_key);

        self.data
            .par_iter_mut()
            .enumerate()
            .filter(|(i, _)| i % 4 == 0)
            .for_each_with(server_key, |server_key, (i, x)| {
                x.xor_in_place(&temp[i / 4], server_key)
            });

        self.data
            .par_chunks_mut(2)
            .enumerate()
            .filter(|(i, _)| i % 2 == 0)
            .for_each_with(server_key, |server_key, (_, x)| {
                let (a, b) = x.split_at_mut(1);
                b[0].xor_in_place(&a[0], server_key)
            });

        self.data[1..]
            .par_chunks_mut(2)
            .enumerate()
            .filter(|(i, _)| i % 2 == 0)
            .for_each_with(server_key, |server_key, (_, x)| {
                let (a, b) = x.split_at_mut(1);
                b[0].xor_in_place(&a[0], server_key)
            });

        self.data
            .par_chunks_mut(2)
            .enumerate()
            .filter(|(i, _)| i % 2 == 1)
            .for_each_with(server_key, |server_key, (_, x)| {
                let (a, b) = x.split_at_mut(1);
                b[0].xor_in_place(&a[0], server_key)
            });
    }

    pub fn decrypt_to_u8(&self, client_key: &ClientKey) -> [u8; 16] {
        let mut decrypted_data: [u8; 16] = self
            .data
            .iter()
            .map(|x| {
                (&x.decrypt(client_key))
                    .iter()
                    .enumerate()
                    .filter_map(|(i, &x)| x.then(|| 2_u8.pow(8 - (i + 1) as u32)))
                    .sum()
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        // TRANSPOSE OUTPUT DATA
        decrypted_data.swap(1, 4);
        decrypted_data.swap(2, 8);
        decrypted_data.swap(3, 12);

        decrypted_data.swap(6, 9);
        decrypted_data.swap(7, 13);

        decrypted_data.swap(11, 14);

        decrypted_data
    }

    /// This method performs the key expansion for the given key in the FHE context, and returns all keys as an array of 11 keys.
    pub fn generate_round_keys(&self, server_key: &ServerKey) -> [Key; 11] {
        let mut keys = vec![self.clone()];
        for i in 0..10 {
            let mut key = keys[i].clone();
            key.generate_next_key_in_place(&RCON[i], &server_key);
            keys.push(key);
        }

        keys.try_into().expect("There should be 11 Keys")
    }
}

fn sub_word(word: &[u8; 4]) -> [u8; 4] {
    word.map(|x| S_BOX_DATA[x as usize])
}

fn rot_word(word: &[u8; 4]) -> [u8; 4] {
    [word[1], word[2], word[3], word[0]]
}

/// This method performs the key expansion for the given key in the clear, and returns all keys as an array of 11 keys.
pub fn key_expansion_clear(key: &[u8; 16]) -> [[u8; 16]; 11] {
    let mut round_keys = [[0u8; 16]; 11];

    // Round 0 Key (original key)
    round_keys[0] = *key;

    for round in 1..=10 {
        let mut temp = [
            round_keys[round - 1][12],
            round_keys[round - 1][13],
            round_keys[round - 1][14],
            round_keys[round - 1][15],
        ];

        temp = sub_word(&rot_word(&temp));
        temp[0] ^= RCON[round - 1];

        for i in 0..4 {
            round_keys[round][i] = round_keys[round - 1][i] ^ temp[i];
        }

        for i in 4..16 {
            round_keys[round][i] = round_keys[round - 1][i] ^ round_keys[round][i - 4];
        }
    }

    round_keys
}

#[cfg(test)]

mod tests {
    use std::time::Instant;

    use super::*;
    use tfhe::boolean::gen_keys;

    #[test]
    fn test_key_schedule() {
        let (client_key, server_key) = gen_keys();
        let key = Key::from_u128_enc(0x2b7e151628aed2a6abf7158809cf4f3c, &client_key);

        let start = Instant::now();

        let keys = key.generate_round_keys(&server_key);
        for key in keys.iter() {
            println!("{:#x?}", key.decrypt_to_u8(&client_key));
        }

        println!("TIME TAKEN {:?}", start.elapsed() / 1);
    }

    #[test]
    fn test_key_expansion() {
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let round_keys = key_expansion_clear(&key);

        for key in round_keys.iter() {
            println!("{:#x?}", key);
        }
    }

    #[test]
    fn test_conversion_u8_u128() {
        let (client_key, _) = gen_keys();
        let key_data = [
            0x04, 0xe0, 0x48, 0x28, 0x66, 0xcb, 0xf8, 0x06, 0x81, 0x19, 0xd3, 0x26, 0xe5, 0x9a,
            0x7a, 0x4c,
        ];
        let key = Key::from_u8_enc(&key_data, &client_key);

        assert_eq!(
            key.decrypt_to_u8(&client_key),
            key_data,
            "{:#?}",
            key.decrypt_to_u8(&client_key)
        );

        let key = Key::from_u128_enc(0x04e04828_66cbf806_8119d326_e59a7a4c, &client_key);

        assert_eq!(
            key.decrypt_to_u8(&client_key),
            key_data,
            "{:#?}",
            key.decrypt_to_u8(&client_key)
        );
    }
}
