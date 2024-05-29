use bitcoin::{Error, TxOut};
use bitcoin::{
    blockdata::{opcodes, script::ScriptBuf, transaction::Transaction},
    key::PrivateKey,
    key::{KeyPair, TapTweak, TweakedKeyPair, TweakedPublicKey, UntweakedKeyPair},
    policy::MAX_STANDARD_TX_WEIGHT,
    secp256k1::{self, constants::SCHNORR_SIGNATURE_SIZE, Secp256k1, schnorr::Signature,XOnlyPublicKey},
    sighash::{TapSighash,Prevouts, SighashCache, TapSighashType},
    taproot::{ControlBlock, LeafVersion, TapLeafHash, TaprootBuilder},
};

pub struct SigTool {
    pub key_pair: KeyPair,
}

impl SigTool {
    pub fn new() -> Result<Self, Error> {
        let secp256k1 = Secp256k1::new();
        let key_pair = UntweakedKeyPair::new(&secp256k1, &mut rand::thread_rng());
        Ok(SigTool { key_pair })
    }

    pub fn from_key_pair(key_pair: KeyPair) -> Result<Self, Error> {
        Ok(SigTool{key_pair})
    }

    // 1. reveal_tx
    // 2. commit_input
    // 3. prevouts
    // 4. reveal_script
    pub fn sig(&self, mut reveal_tx: Transaction, commit_input: usize, prevouts: Vec<TxOut>, reveal_script: ScriptBuf) -> Signature {
        let mut sighash_cache = SighashCache::new(&mut reveal_tx);
        let sighash = sighash_cache.taproot_script_spend_signature_hash(
            commit_input,
            &Prevouts::All(&prevouts),
            TapLeafHash::from_script(&reveal_script, LeafVersion::TapScript),
            TapSighashType::Default,
        ).expect("signature hash should compute");

        let secp256k1 = Secp256k1::new();
        let key_pair = self.key_pair.clone();
        secp256k1.sign_schnorr(
            &secp256k1::Message::from_slice(sighash.as_ref())
                .expect("should be cryptographically secure hash"),
            &key_pair,
        )
    }

    pub fn sig_ex(&self, sighash: TapSighash) -> Signature {
        let secp256k1 = Secp256k1::new();
        let key_pair = self.key_pair.clone();
        secp256k1.sign_schnorr(
            &secp256k1::Message::from_slice(sighash.as_ref())
                .expect("should be cryptographically secure hash"),
            &key_pair,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // #[test]
    // fn it_works() {
    //     let result = add(2, 2);
    //     assert_eq!(result, 4);
    // }
}
