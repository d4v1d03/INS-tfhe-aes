use crate::ecb::ECB;
use base::*;
use tfhe::boolean::prelude::*;

/// OFB is the Output Feedback mode for AES-128

pub struct OFB {
    ecb: ECB,
    iv: State,
    n: u8,
}

impl OFB {
    pub fn new(keys: &[Key], iv: &State, n: u8) -> Self {
        OFB {
            ecb: ECB::new(keys),
            iv: iv.clone(),
            n,
        }
    }

    pub fn encrypt(&self, plaintext: &mut [State], server_key: &ServerKey) {
        let mut curr_state = self.iv.clone();

        for i in 0..self.n {
            self.ecb.encrypt(&mut curr_state, server_key);
            plaintext[i as usize].xor_state(&curr_state, server_key);
        }
    }

    pub fn decrypt(&self, ciphertexts: &mut [State], server_key: &ServerKey) {
        let mut curr_state = self.iv.clone();

        for i in 0..self.n {
            self.ecb.encrypt(&mut curr_state, server_key);
            ciphertexts[i as usize].xor_state(&curr_state, server_key);
        }
    }
}

#[cfg(test)]

mod tests {

    use super::*;
    use base::primitive::*;
    use std::time::Instant;
    use tfhe::boolean::gen_keys;

    #[test]
    fn test_ofb() {
        let (client_key, server_key) = gen_keys();

        let curr_key = Key::from_u128_enc(0x2b7e1516_28aed2a6a_bf71588_09cf4f3c, &client_key);
        let keys = curr_key.generate_round_keys(&server_key);
        let iv = State::from_u128_enc(0x3243f6a8_885a308d_313198a2_e0312122, &client_key);
        let ofb = OFB::new(&keys, &iv, 2);

        let plaintext_block_0 =
            State::from_u128_enc(0x3243f6a8_885a308d_313198a2_e0370734, &client_key);
        let plaintext_block_1 =
            State::from_u128_enc(0x3243f6a8_885a308d_313198a2_e0372324, &client_key);
        let mut plaintext = vec![plaintext_block_0, plaintext_block_1];

        let start = Instant::now();

        ofb.encrypt(&mut plaintext, &server_key);
        println!("ENCRYPT TIME TAKEN {:?}", start.elapsed());

        let start = Instant::now();
        ofb.decrypt(&mut plaintext, &server_key);
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
