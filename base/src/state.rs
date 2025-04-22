use crate::Key;
use crate::primitive::*;
use rayon::prelude::*;
use tfhe::boolean::prelude::*;

/// This represents the state of a 128-bit block in AES-128. The matrix is represented in a transposed manner, and all algorithms are implemented as such.
/// For more details for each algorithm, refer to the [Efficient Implementation of AES in 32 bit systems](https://link.springer.com/content/pdf/10.1007/3-540-36400-5_13.pdf) paper.
#[derive(Clone)]
pub struct State {
    // This matrix is the transposed state matrix.
    data: [FHEByte; 16],
}

impl State {
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

        State { data }
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

        State { data }
    }

    pub fn sub_bytes(&mut self, server_key: &ServerKey) {
        self.data = self
            .data
            .par_iter()
            .map_with(server_key, |server_key, byte| byte.sub_byte(server_key))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
    }

    pub fn inv_sub_bytes(&mut self, server_key: &ServerKey) {
        self.data = self
            .data
            .par_iter()
            .map_with(server_key, |server_key, byte| byte.inv_sub_byte(server_key))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
    }

    pub fn mix_columns(&mut self, server_key: &ServerKey) {
        let data_order: [usize; 16] = [8, 9, 10, 11, 8, 9, 10, 11, 0, 1, 2, 3, 0, 1, 2, 3];

        let mut y: [FHEByte; 16] = data_order
            .into_par_iter()
            .map_with(server_key, |server_key, i| {
                self.data[i].xor(&self.data[4 + i], server_key)
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let data_chained = self.data[4..8]
            .par_iter()
            .chain(self.data[..4].par_iter())
            .chain(self.data[12..].par_iter())
            .chain(self.data[8..12].par_iter());
        y.par_iter_mut()
            .zip(data_chained)
            .for_each_with(server_key, |server_key, (x, y)| {
                x.xor_in_place(y, server_key)
            });

        self.data
            .par_iter_mut()
            .for_each_with(server_key, |server_key, x| x.mul_x_gf2_in_place(server_key));

        y.par_iter_mut()
            .zip(self.data.par_iter())
            .for_each_with(server_key, |server_key, (x, y)| {
                x.xor_in_place(y, server_key)
            });

        let data_chained = self.data[4..8]
            .par_iter()
            .chain(self.data[8..12].par_iter())
            .chain(self.data[12..].par_iter())
            .chain(self.data[..4].par_iter());

        y.par_iter_mut()
            .zip(data_chained)
            .for_each_with(server_key, |server_key, (x, y)| {
                x.xor_in_place(y, server_key)
            });

        self.data = y
    }

    pub fn inv_mix_columns(&mut self, server_key: &ServerKey) {
        let mut y: [FHEByte; 16] = (0..16_usize)
            .into_par_iter()
            .map_with(server_key, |server_key, i| {
                self.data[i].xor(&self.data[(i + 4) % 16], server_key)
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        // y_i = (x_i ^ x_(i + 1) % 4)

        let mut temp_0: [FHEByte; 8] = (0..8)
            .into_par_iter()
            .map_with(server_key, |server_key, i| {
                self.data[i].xor(&self.data[i + 8], server_key)
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(); // (X_i XOR X_(i + 2))

        temp_0
            .par_iter_mut()
            .for_each_with(server_key, |server_key, x| x.mul_x_gf2_in_place(server_key)); // 02 * (X_i XOR X_(i + 2))

        temp_0
            .par_iter_mut()
            .for_each_with(server_key, |server_key, x| x.mul_x_gf2_in_place(server_key)); // 04 * (X_i XOR X_(i + 2))

        let mut temp_1: [FHEByte; 4] = y[..4]
            .par_iter()
            .zip(y[8..12].par_iter())
            .map_with(server_key, |server_key, (x, y)| x.xor(y, server_key))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(); // (X_0 ^ X_1 ^ X_2 ^ X_3)

        let temp_0_iter = temp_0[..4]
            .par_iter()
            .chain(temp_0[4..].par_iter())
            .chain(temp_0[..4].par_iter())
            .chain(temp_0[4..].par_iter());

        y.par_iter_mut()
            .for_each_with(server_key, |server_key, x| x.mul_x_gf2_in_place(server_key));

        y.par_iter_mut()
            .zip(temp_0_iter)
            .for_each_with(server_key, |server_key, (x, y)| {
                x.xor_in_place(y, server_key)
            });

        let temp_1_iter = temp_1
            .par_iter()
            .chain(temp_1.par_iter())
            .chain(temp_1.par_iter())
            .chain(temp_1.par_iter());

        self.data
            .par_iter_mut()
            .zip(y.par_iter())
            .for_each_with(server_key, |server_key, (x, y)| {
                x.xor_in_place(y, server_key)
            });

        self.data
            .par_iter_mut()
            .zip(temp_1_iter)
            .for_each_with(server_key, |server_key, (x, y)| {
                x.xor_in_place(y, server_key)
            });

        temp_1
            .par_iter_mut()
            .for_each_with(server_key, |server_key, x| x.mul_x_gf2_in_place(server_key));

        temp_1
            .par_iter_mut()
            .for_each_with(server_key, |server_key, x| x.mul_x_gf2_in_place(server_key));

        temp_1
            .par_iter_mut()
            .for_each_with(server_key, |server_key, x| x.mul_x_gf2_in_place(server_key)); //08 * (X_0 ^ X_1 ^ X_2 ^ X_3)

        let temp_1_iter = temp_1
            .par_iter()
            .chain(temp_1.par_iter())
            .chain(temp_1.par_iter())
            .chain(temp_1.par_iter());

        self.data
            .par_iter_mut()
            .zip(temp_1_iter)
            .for_each_with(server_key, |server_key, (x, y)| {
                x.xor_in_place(y, server_key)
            });
    }

    pub fn xor_key_enc(&mut self, key: &Key, server_key: &ServerKey) {
        self.data
            .par_iter_mut()
            .zip(key.data.par_iter())
            .for_each_with(server_key, |server_key, (x, y)| {
                x.xor_in_place(y, server_key)
            });
    }

    pub fn xor_key_clear(&mut self, key: &[u8; 16], server_key: &ServerKey) {
        let mut key_data = key.clone();

        // TRANSPOSE INPUT DATA
        key_data.swap(1, 4);
        key_data.swap(2, 8);
        key_data.swap(3, 12);

        key_data.swap(6, 9);
        key_data.swap(7, 13);

        key_data.swap(11, 14);

        self.data
            .par_iter_mut()
            .zip(key_data.into_par_iter())
            .for_each_with(server_key, |server_key, (x, y)| {
                x.xor_in_place(&FHEByte::trivial_clear(y, server_key), server_key)
            });
    }

    pub fn xor_state(&mut self, state: &State, server_key: &ServerKey) {
        self.data
            .par_iter_mut()
            .zip(state.data.par_iter())
            .for_each_with(server_key, |server_key, (x, y)| {
                x.xor_in_place(y, server_key)
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

    pub fn decrypt_to_u128(&self, client_key: &ClientKey) -> u128 {
        let u8_data = self.decrypt_to_u8(client_key);
        let mut res: u128 = 0;
        for i in 0..15 {
            res ^= u8_data[i] as u128;
            res <<= 8;
        }

        res ^= u8_data[15] as u128;
        res
    }

    pub fn shift_rows(&mut self) {
        let mut slice = &mut self.data[4..8];
        slice.rotate_left(1);
        slice = &mut self.data[8..12];
        slice.rotate_left(2);
        slice = &mut self.data[12..];
        slice.rotate_left(3);
    }

    pub fn inv_shift_rows(&mut self) {
        let mut slice = &mut self.data[4..8];
        slice.rotate_right(1);
        slice = &mut self.data[8..12];
        slice.rotate_right(2);
        slice = &mut self.data[12..];
        slice.rotate_right(3);
    }
}

#[cfg(test)]

mod tests {
    use super::*;
    use tfhe::boolean::gen_keys;

    #[test]
    fn test_mix_columns() {
        // This test follows the test case on page 34 of the FIPS-197 standard
        let (client_key, server_key) = gen_keys();
        let state = State::from_u128_enc(0xd4bf5d30_e0b452ae_b84111f1_1e2798e5, &client_key);
        let mut test_data: Vec<_> = (0..1).into_iter().map(|_| state.clone()).collect();

        test_data
            .par_iter_mut()
            .for_each(|state| state.mix_columns(&server_key));

        assert_eq!(
            test_data[0].decrypt_to_u128(&client_key),
            0x046681e5_e0cb199a_48f8d37a_2806264c,
            "{:#x?}",
            test_data[0].decrypt_to_u128(&client_key)
        );
    }

    #[test]
    fn test_sub_bytes() {
        // This test follows the test case on page 34 of the FIPS-197 standard
        let (client_key, server_key) = gen_keys();
        let state = State::from_u128_enc(0x193de3be_a0f4e22b_9ac68d2a_e9f84808, &client_key);
        let mut test_data: Vec<_> = (0..1).into_iter().map(|_| state.clone()).collect();

        test_data
            .par_iter_mut()
            .map(|state| state.sub_bytes(&server_key))
            .collect::<Vec<_>>();

        assert_eq!(
            test_data[0].decrypt_to_u128(&client_key),
            0xd42711ae_e0bf98f1_b8b45de5_1e415230,
            "{:#x?}",
            test_data[0].decrypt_to_u128(&client_key)
        );
    }

    #[test]
    fn test_inv_sub_bytes() {
        // This test follows the test case on page 34 of the FIPS-197 standard
        let (client_key, server_key) = gen_keys();
        let state = State::from_u128_enc(0xd42711ae_e0bf98f1_b8b45de5_1e415230, &client_key);
        let mut test_data: Vec<_> = (0..1).into_iter().map(|_| state.clone()).collect();

        test_data
            .par_iter_mut()
            .map(|state| state.inv_sub_bytes(&server_key))
            .collect::<Vec<_>>();

        assert_eq!(
            test_data[0].decrypt_to_u128(&client_key),
            0x193de3be_a0f4e22b_9ac68d2a_e9f84808,
            "{:#x?}",
            test_data[0].decrypt_to_u128(&client_key)
        );
    }

    #[test]
    fn test_shift_rows() {
        // This test follows the test case on page 34 of the FIPS-197 standard
        let (client_key, _) = gen_keys();
        let state = State::from_u128_enc(0xd42711ae_e0bf98f1_b8b45de5_1e415230, &client_key);
        let mut test_data: Vec<_> = (0..1).into_iter().map(|_| state.clone()).collect();

        test_data
            .par_iter_mut()
            .map(|state| state.shift_rows())
            .collect::<Vec<_>>();

        assert_eq!(
            test_data[0].decrypt_to_u128(&client_key),
            0xd4bf5d30_e0b452ae_b84111f1_1e2798e5,
            "{:#x?}",
            test_data[0].decrypt_to_u128(&client_key)
        );
    }

    #[test]
    fn test_inv_shift_rows() {
        // This test follows the test case on page 34 of the FIPS-197 standard
        let (client_key, _) = gen_keys();
        let state = State::from_u128_enc(0xd4bf5d30_e0b452ae_b84111f1_1e2798e5, &client_key);
        let mut test_data: Vec<_> = (0..1).into_iter().map(|_| state.clone()).collect();

        test_data
            .par_iter_mut()
            .map(|state| state.inv_shift_rows())
            .collect::<Vec<_>>();

        assert_eq!(
            test_data[0].decrypt_to_u128(&client_key),
            0xd42711ae_e0bf98f1_b8b45de5_1e415230,
            "{:#x?}",
            test_data[0].decrypt_to_u128(&client_key)
        );
    }

    #[test]
    fn test_inv_mix_columns() {
        // This test follows the test case on page 34 of the FIPS-197 standard
        let (client_key, server_key) = gen_keys();
        let state = State::from_u128_enc(0x046681e5_e0cb199a_48f8d37a_2806264c, &client_key);
        let mut test_data: Vec<_> = (0..1).into_iter().map(|_| state.clone()).collect();

        test_data
            .par_iter_mut()
            .map(|state| state.inv_mix_columns(&server_key))
            .collect::<Vec<_>>();

        assert_eq!(
            test_data[0].decrypt_to_u128(&client_key),
            0xd4bf5d30_e0b452ae_b84111f1_1e2798e5,
            "{:#x?}",
            test_data[0].decrypt_to_u128(&client_key)
        );
    }

    #[test]
    fn test_decrypt_u128() {
        let (client_key, _) = gen_keys();
        let state = State::from_u128_enc(0x04e04828_66cbf806_8119d326_e59a7a4c, &client_key);

        assert_eq!(
            state.decrypt_to_u128(&client_key),
            0x04e04828_66cbf806_8119d326_e59a7a4c,
            "{:#x?}",
            state.decrypt_to_u128(&client_key)
        );
    }

    #[test]
    fn test_conversion_u8_u128() {
        let (client_key, _) = gen_keys();
        let state_data = [
            0x04, 0xe0, 0x48, 0x28, 0x66, 0xcb, 0xf8, 0x06, 0x81, 0x19, 0xd3, 0x26, 0xe5, 0x9a,
            0x7a, 0x4c,
        ];
        let state = State::from_u8_enc(&state_data, &client_key);

        assert_eq!(
            state.decrypt_to_u128(&client_key),
            0x04e04828_66cbf806_8119d326_e59a7a4c,
            "{:#x?}",
            state.decrypt_to_u128(&client_key)
        );

        let state = State::from_u128_enc(0x04e04828_66cbf806_8119d326_e59a7a4c, &client_key);

        assert_eq!(
            state.decrypt_to_u8(&client_key),
            state_data,
            "{:#x?}",
            state.decrypt_to_u128(&client_key)
        );
    }
}
