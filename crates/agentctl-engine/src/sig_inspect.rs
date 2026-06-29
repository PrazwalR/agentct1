//! EIP-712 digest construction + signer recovery for EIP-3009 (USDC) and Permit2
//! witness authorizations. This is the hot-path "what does this signature
//! actually authorize, and who signed it" check, in native code.

use alloy_primitives::{keccak256, U256};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

pub struct Eip712Domain {
    pub name: String,
    /// None for Permit2 (its domain has no version field).
    pub version: Option<String>,
    pub chain_id: u64,
    pub verifying_contract: [u8; 20],
}

pub struct Eip3009Auth {
    pub from: [u8; 20],
    pub to: [u8; 20],
    pub value: U256,
    pub valid_after: U256,
    pub valid_before: U256,
    pub nonce: [u8; 32],
}

pub struct Permit2Auth {
    pub token: [u8; 20],
    pub amount: U256,
    pub spender: [u8; 20],
    pub nonce: U256,
    pub deadline: U256,
    pub witness_to: [u8; 20],
    pub witness_valid_after: U256,
}

fn addr_word(a: &[u8; 20]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(a);
    w
}

fn u256_word(v: &U256) -> [u8; 32] {
    v.to_be_bytes::<32>()
}

/// keccak256(0x1901 || domainSeparator || structHash)
fn eip712_digest(domain_separator: [u8; 32], struct_hash: [u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(66);
    buf.push(0x19);
    buf.push(0x01);
    buf.extend_from_slice(&domain_separator);
    buf.extend_from_slice(&struct_hash);
    keccak256(&buf).0
}

fn domain_separator(d: &Eip712Domain) -> [u8; 32] {
    let mut buf = Vec::new();
    match &d.version {
        Some(version) => {
            buf.extend_from_slice(
                keccak256(
                    b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
                )
                .as_slice(),
            );
            buf.extend_from_slice(keccak256(d.name.as_bytes()).as_slice());
            buf.extend_from_slice(keccak256(version.as_bytes()).as_slice());
        }
        None => {
            buf.extend_from_slice(
                keccak256(b"EIP712Domain(string name,uint256 chainId,address verifyingContract)")
                    .as_slice(),
            );
            buf.extend_from_slice(keccak256(d.name.as_bytes()).as_slice());
        }
    }
    buf.extend_from_slice(&u256_word(&U256::from(d.chain_id)));
    buf.extend_from_slice(&addr_word(&d.verifying_contract));
    keccak256(&buf).0
}

fn struct_hash_eip3009(a: &Eip3009Auth) -> [u8; 32] {
    let type_hash = keccak256(
        b"TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)",
    );
    let mut buf = Vec::new();
    buf.extend_from_slice(type_hash.as_slice());
    buf.extend_from_slice(&addr_word(&a.from));
    buf.extend_from_slice(&addr_word(&a.to));
    buf.extend_from_slice(&u256_word(&a.value));
    buf.extend_from_slice(&u256_word(&a.valid_after));
    buf.extend_from_slice(&u256_word(&a.valid_before));
    buf.extend_from_slice(&a.nonce);
    keccak256(&buf).0
}

fn struct_hash_permit2(a: &Permit2Auth) -> [u8; 32] {
    let type_hash = keccak256(
        b"PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,Witness witness)TokenPermissions(address token,uint256 amount)Witness(address to,uint256 validAfter)",
    );

    let token_permissions = {
        let th = keccak256(b"TokenPermissions(address token,uint256 amount)");
        let mut buf = Vec::new();
        buf.extend_from_slice(th.as_slice());
        buf.extend_from_slice(&addr_word(&a.token));
        buf.extend_from_slice(&u256_word(&a.amount));
        keccak256(&buf).0
    };
    let witness = {
        let th = keccak256(b"Witness(address to,uint256 validAfter)");
        let mut buf = Vec::new();
        buf.extend_from_slice(th.as_slice());
        buf.extend_from_slice(&addr_word(&a.witness_to));
        buf.extend_from_slice(&u256_word(&a.witness_valid_after));
        keccak256(&buf).0
    };

    let mut buf = Vec::new();
    buf.extend_from_slice(type_hash.as_slice());
    buf.extend_from_slice(&token_permissions);
    buf.extend_from_slice(&addr_word(&a.spender));
    buf.extend_from_slice(&u256_word(&a.nonce));
    buf.extend_from_slice(&u256_word(&a.deadline));
    buf.extend_from_slice(&witness);
    keccak256(&buf).0
}

/// Recover the Ethereum address that produced a 65-byte secp256k1 signature
/// over a 32-byte EIP-712 digest.
pub fn ecrecover(digest: &[u8; 32], sig: &[u8; 65]) -> Option<[u8; 20]> {
    let v = sig[64];
    let recid = RecoveryId::from_byte(if v >= 27 { v - 27 } else { v })?;
    let signature = Signature::from_slice(&sig[..64]).ok()?;
    let vk = VerifyingKey::recover_from_prehash(digest, &signature, recid).ok()?;
    let encoded = vk.to_encoded_point(false);
    let bytes = encoded.as_bytes(); // 0x04 || X(32) || Y(32)
    let hash = keccak256(&bytes[1..]).0;
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    Some(addr)
}

pub fn digest_eip3009(domain: &Eip712Domain, auth: &Eip3009Auth) -> [u8; 32] {
    eip712_digest(domain_separator(domain), struct_hash_eip3009(auth))
}

pub fn digest_permit2(domain: &Eip712Domain, auth: &Permit2Auth) -> [u8; 32] {
    eip712_digest(domain_separator(domain), struct_hash_permit2(auth))
}

pub fn recover_eip3009(
    domain: &Eip712Domain,
    auth: &Eip3009Auth,
    sig: &[u8; 65],
) -> Option<[u8; 20]> {
    ecrecover(&digest_eip3009(domain, auth), sig)
}

pub fn recover_permit2(
    domain: &Eip712Domain,
    auth: &Permit2Auth,
    sig: &[u8; 65],
) -> Option<[u8; 20]> {
    ecrecover(&digest_permit2(domain, auth), sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a20(hexstr: &str) -> [u8; 20] {
        let mut a = [0u8; 20];
        a.copy_from_slice(&hex::decode(hexstr.trim_start_matches("0x")).unwrap());
        a
    }
    fn b32(hexstr: &str) -> [u8; 32] {
        let mut a = [0u8; 32];
        a.copy_from_slice(&hex::decode(hexstr.trim_start_matches("0x")).unwrap());
        a
    }
    fn s65(hexstr: &str) -> [u8; 65] {
        let mut a = [0u8; 65];
        a.copy_from_slice(&hex::decode(hexstr.trim_start_matches("0x")).unwrap());
        a
    }

    const SIGNER: &str = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";

    // ─── EIP-3009 vector generated by viem (hashTypedData + signTypedData) ──────
    #[test]
    fn eip3009_digest_and_recovery_match_viem() {
        let domain = Eip712Domain {
            name: "USDC".into(),
            version: Some("2".into()),
            chain_id: 84532,
            verifying_contract: a20("0x036CbD53842c5426634e7929541eC2318f3dCF7e"),
        };
        let auth = Eip3009Auth {
            from: a20(SIGNER),
            to: a20("0x000000000000000000000000000000000000dEaD"),
            value: U256::from(100000u64),
            valid_after: U256::ZERO,
            valid_before: U256::from(1924992000u64),
            nonce: b32(&"11".repeat(32)),
        };

        let digest = digest_eip3009(&domain, &auth);
        assert_eq!(
            digest,
            b32("0x24dfdd8152fbe559ba1ce0a1dd097e95fc4a430f319a85ca1bb343ec2429b0a8"),
            "digest must match viem's hashTypedData"
        );

        let sig = s65("0x0785178f1d841a523b3ae1dc5f3fff493815f8e5b5fa4e3ea80341693232b93428f1bf531c214162e68347c29f045b52760b8c2b51e8e1853179b9c1f682c2cd1b");
        let recovered = recover_eip3009(&domain, &auth, &sig).unwrap();
        assert_eq!(recovered, a20(SIGNER));
    }

    #[test]
    fn eip3009_rejects_a_tampered_recipient() {
        let domain = Eip712Domain {
            name: "USDC".into(),
            version: Some("2".into()),
            chain_id: 84532,
            verifying_contract: a20("0x036CbD53842c5426634e7929541eC2318f3dCF7e"),
        };
        // Same auth but recipient swapped to an attacker → recovered signer no longer matches.
        let tampered = Eip3009Auth {
            from: a20(SIGNER),
            to: a20("0x00000000000000000000000000000000DeaDBeef"),
            value: U256::from(100000u64),
            valid_after: U256::ZERO,
            valid_before: U256::from(1924992000u64),
            nonce: b32(&"11".repeat(32)),
        };
        let sig = s65("0x0785178f1d841a523b3ae1dc5f3fff493815f8e5b5fa4e3ea80341693232b93428f1bf531c214162e68347c29f045b52760b8c2b51e8e1853179b9c1f682c2cd1b");
        let recovered = recover_eip3009(&domain, &tampered, &sig).unwrap();
        assert_ne!(recovered, a20(SIGNER));
    }

    // ─── Permit2 witness vector generated by viem ───────────────────────────────
    #[test]
    fn permit2_digest_and_recovery_match_viem() {
        let domain = Eip712Domain {
            name: "Permit2".into(),
            version: None,
            chain_id: 84532,
            verifying_contract: a20("0x000000000022D473030F116dDEE9F6B43aC78BA3"),
        };
        let auth = Permit2Auth {
            token: a20("0x036CbD53842c5426634e7929541eC2318f3dCF7e"),
            amount: U256::from(100000u64),
            spender: a20("0x402085c248EeA27D92E8b30b2C58ed07f9E20001"),
            nonce: U256::from(7u64),
            deadline: U256::from(1924992000u64),
            witness_to: a20("0x000000000000000000000000000000000000dEaD"),
            witness_valid_after: U256::ZERO,
        };

        let digest = digest_permit2(&domain, &auth);
        assert_eq!(
            digest,
            b32("0x306c1e60b0a410cbf72d6302dbf3cdae01894c29a4eff1f1a35fbd6622433bc9"),
            "digest must match viem's hashTypedData for the Permit2 witness"
        );

        let sig = s65("0x67ba3ff26b3b1adf897034bef36d0c5c4ba510ba8028411c5ad6d15dae4cf98077b65c1f7274e1daf0222f9d698e18ab8c2f54e0cadd3c779c9c49439bdac16a1c");
        let recovered = recover_permit2(&domain, &auth, &sig).unwrap();
        assert_eq!(recovered, a20(SIGNER));
    }
}
