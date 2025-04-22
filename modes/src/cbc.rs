use crate::ecb::ECB;
use base::*;
use tfhe::boolean::prelude::*;

/// CBC mode is the Cipher Block Chaining mode for AES-128

pub struct CBC {
    ecb: ECB,
    iv: State,
    n: u8,
}

impl CBC {
    pub fn new(keys: &[Key], iv: &State, n: u8) -> Self {
        CBC {
            ecb: ECB::new(keys),
            iv: iv.clone(),
            n,
        }
    }

    pub fn encrypt(&self, plaintext: &mut [State], server_key: &ServerKey) {
        plaintext[0].xor_state(&self.iv, server_key);
        self.ecb.encrypt(&mut plaintext[0], server_key);

        for i in 1..self.n as usize {
            let (prev, curr) = plaintext.split_at_mut(i);
            curr[0].xor_state(&prev[i - 1], server_key);
            self.ecb.encrypt(&mut curr[0], server_key);
        }
    }

    pub fn decrypt(&self, ciphertexts: &mut [State], server_key: &ServerKey) {
        for i in (1..self.n as usize).rev() {
            let (prev, curr) = ciphertexts.split_at_mut(i);
            self.ecb.decrypt(&mut curr[0], server_key);
            curr[0].xor_state(&prev[i - 1], server_key);
        }

        self.ecb.decrypt(&mut ciphertexts[0], server_key);
        ciphertexts[0].xor_state(&self.iv, server_key);
    }
}

#[cfg(test)]

mod tests {

    use super::*;
    use std::time::Instant;
    use tfhe::boolean::gen_keys;

    #[test]
    fn test_cbc() {
        let (client_key, server_key) = gen_keys();

        let curr_key = Key::from_u128_enc(0x2b7e1516_28aed2a6a_bf71588_09cf4f3c, &client_key);
        let keys = curr_key.generate_round_keys(&server_key);
        let iv = State::from_u128_enc(0x3243f6a8_885a308d_313198a2_e0312122, &client_key);
        let cbc = CBC::new(&keys, &iv, 2);

        let plaintext_block_0 =
            State::from_u128_enc(0x3243f6a8_885a308d_313198a2_e0370734, &client_key);
        let plaintext_block_1 =
            State::from_u128_enc(0x3243f6a8_885a308d_313198a2_e0372324, &client_key);
        let mut plaintext = vec![plaintext_block_0, plaintext_block_1];

        let start = Instant::now();
        cbc.encrypt(&mut plaintext, &server_key);
        println!("ENCRYPT TIME TAKEN {:?}", start.elapsed());

        plaintext
            .iter()
            .for_each(|x| println!("{:#x?}", x.decrypt_to_u128(&client_key)));

        let start = Instant::now();
        cbc.decrypt(&mut plaintext, &server_key);
        println!("DECRYPT TIME TAKEN {:?}", start.elapsed());

        assert_eq!(
            plaintext[0].decrypt_to_u128(&client_key),
            0x3243f6a8_885a308d_313198a2_e0370734
        );
        assert_eq!(
            plaintext[1].decrypt_to_u128(&client_key),
            0x3243f6a8_885a308d_313198a2_e0372324
        );
    }
}
