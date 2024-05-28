use {
    bitcoin::{
        blockdata::{opcodes, script},
        key::PrivateKey,
        key::{TapTweak, TweakedKeyPair, KeyPair,TweakedPublicKey, UntweakedKeyPair},
        policy::MAX_STANDARD_TX_WEIGHT,
        secp256k1::{self, constants::SCHNORR_SIGNATURE_SIZE, Secp256k1, XOnlyPublicKey},
        sighash::{Prevouts, SighashCache, TapSighashType},
        taproot::Signature,
        taproot::{ControlBlock, LeafVersion, TapLeafHash, TaprootBuilder},
    },
};
pub struct SigTool {
    pub key_pair: KeyPair
}

impl SigTool {
    pub fn new() {
        let secp256k1 = Secp256k1::new();
        let key_pair = UntweakedKeyPair::new(&secp256k1, &mut rand::thread_rng());
    }

    // 请求签名时传入的参数
    // 1. TapSighash
    // 2. reveal_script
    // 3. data
    // pub fn sig(reveal_tx: transaction, commit_input: usize, prevouts: Vec<TxOut>, reveal_script: ScriptBuf) -> Signature {
    //     // todo
    //     Signature::from_slice(&[1]).expect("")
    // }
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
