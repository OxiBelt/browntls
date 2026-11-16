//! Raw-key verification through the provider's scheme table, with
//! OpenSSL-made signatures.

use super::*;

// ---------------------------------------------------------------------------
// Verification through the provider's scheme table

#[test]
fn scheme_table_binds_key_algorithm_and_hash() {
    let key = TestKey::server(UNRESTRICTED);
    let mut sig = vec![0u8; 256];
    for (algorithm, valid) in [
        (RSAE_KEY, &RSAE[..3]),
        (UNRESTRICTED, &PSS_PSS[..]),
        (restricted(Sha256), &PSS_PSS[..1]),
        (restricted(Sha384), &PSS_PSS[1..2]),
        (restricted(Sha512), &PSS_PSS[2..]),
    ] {
        let spki = TestKey {
            algorithm,
            ..key.clone()
        }
        .spki();
        for scheme in RSAE[..3].iter().chain(&PSS_PSS) {
            key.key
                .sign_pss(scheme_hash(*scheme), b"msg", &OsRng, &mut sig)
                .unwrap();
            let res = verify_raw(&spki, *scheme, b"msg", &sig);
            if valid.contains(scheme) {
                res.unwrap();
                assert_eq!(
                    verify_raw(&spki, *scheme, b"msh", &sig),
                    Err(CertificateError::BadSignature.into())
                );
            } else {
                assert_eq!(
                    res,
                    Err(CertificateError::UnsupportedSignatureAlgorithm.into()),
                    "{algorithm:?} {scheme:?}"
                );
            }
        }
    }
}

// Public keys and signatures made by OpenSSL 3.0.13 (the same vectors as
// `crates/browntls-crypto/tests/rsa_sign.rs`, which records the commands;
// the private keys were discarded): an RSA-PSS key without parameters
// signing with SHA-512, and a key restricted to SHA-256.
const OPENSSL_MSG: &[u8] = b"browntls RSASSA-PSS test vector";
const OPENSSL_PSS_SPKI: &str = concat!(
    "30820120300b06092a864886f70d01010a0382010f003082010a0282010100af",
    "44706e28928bb898b9da6b657ca711e2edd287181904fe632899fab589edbb1c",
    "8cf30da93dec59859ab3d0fa1ef7cf26624cb35024607a1dcb15800949e091e8",
    "f6821e46a2deebe55de982adfe235fff0cd21a1b60c28d08dda7ff635045e9e2",
    "cabe0006720c1267fd8b747415d00a8d06a91eed75f5fb38deffed32154d4c15",
    "6363fb974787748eae2438fa4a549bbeab5dc366b9ca7801caaf618852d41ce5",
    "9d613a4750cd8186f68e18a9de1618cd613386f827326931ecf73a9fdfa3b713",
    "899d4e961ff931b4c542a3569dab2d6f77882d671d6b9f34868005585a632c87",
    "f4e1eceb193a56d842e3585f6ce3a7a44ea7283bbdd3863268d3eaf18fe66302",
    "03010001",
);
const OPENSSL_PSS_SHA512_SIG: &str = concat!(
    "3f90c4862183f6072d95b3bd076fd375622a7216bd17c2bd6d2c1f26deef9917",
    "59748af3dda4d066da226f025a1b76a602b2784ed310dc50e666f93e64153b5e",
    "a531ae8a9a513168d69edccb9e6767304b17d085c5e9a02307880ee239f68dd0",
    "2f637eaf5f1ddebbb1d88962864c66259728a364f330da985f53105c8561fbe0",
    "7bcb36aca0ebab1dbeba9ca96253d8df20a15fbc3f6cbdbd73a0062cc98f4326",
    "227a416e7949d80f4a3b326d6ba8854f22de9fb0e3e6a7b7127ecf313de960ff",
    "61fee2277df5b7f5dc176fa3044e3a2a160075c17f56202987c70e0efc6fce0a",
    "c6e8f6e7410503f89ab3f534f27cc0a305d28ee49924fcccdc87a17602d78e89",
);
const OPENSSL_PSS_SHA256_SPKI: &str = concat!(
    "30820156304106092a864886f70d01010a3034a00f300d060960864801650304",
    "02010500a11c301a06092a864886f70d010108300d0609608648016503040201",
    "0500a2030201200382010f003082010a0282010100a9cb3bd5a02e5eee5eb103",
    "a87e19eadedc9bd44c12bfc6fa189c1ff7f790ab8cd20bbf98f7d40b0c206e10",
    "1baaa398a1dc6cf7652ce86bef43215d2438fc65c09e4e767ef263c350d2b568",
    "b538dc1f6dc6af9585692587599a039b337e15964711236111c99131c0dce053",
    "367bafe29831ff44ec67a2d43c54dd310a260d7cdc73794e2e2792b91841091f",
    "4ece9f75435746a39c76fb45db30473be87cc507313e58fadde9f4a9ec56ea2f",
    "eb9d9d432b2d06aa0fc8b22db7280c00222a6f8829ee62d3e83bdd52c9aba5c6",
    "e360a01c1cbfee0048cf429ccb3c4f7f7b8d929d966326257101b395d3d9c231",
    "38f2566ae7a123b13cb683eb9abe362fa6749d3add0203010001",
);
const OPENSSL_PSS_SHA256_SIG: &str = concat!(
    "3b5c48fc32708b0875acfbab1f5bffc19e19af234ce6785b2e5baa8f45d04ba5",
    "d628b678ffef425e8199b43f516f02df2c00ef2d9d2962df46d931f086f5871c",
    "799895cee57aa53908687ecb41f1b0a219b481e022a1095ac01dda13479eeacc",
    "02cbc22754f8de487e093dbff2f77e8182e26d997d01187be3a989d6444c90cc",
    "024c009818115665425e96f576d537cd033cebcf5fcf6c2c0310115fe64ae61b",
    "b7d3fbbf8da0f4043aaffc7e0c02a49e8d7fbc843bc7f900bf2b470e0718fd2c",
    "1c8253e74f6ddfb62ab8fae0b823a12d649d004f9a559514271e012efb36258e",
    "730bcbc1a78ac5619bd511b4306b297ae48fc5f0ca366589ad138116664b2c08",
);

#[test]
fn openssl_signatures_verify_with_pss_pss_schemes() {
    let unrestricted = hex::decode(OPENSSL_PSS_SPKI).unwrap();
    let sig512 = hex::decode(OPENSSL_PSS_SHA512_SIG).unwrap();
    verify_raw(&unrestricted, S::RSA_PSS_PSS_SHA512, OPENSSL_MSG, &sig512).unwrap();
    // The same signature under the rsae scheme: the key is not rsaEncryption.
    assert_eq!(
        verify_raw(&unrestricted, S::RSA_PSS_SHA512, OPENSSL_MSG, &sig512),
        Err(CertificateError::UnsupportedSignatureAlgorithm.into())
    );
    assert_eq!(
        verify_raw(&unrestricted, S::RSA_PSS_PSS_SHA384, OPENSSL_MSG, &sig512),
        Err(CertificateError::BadSignature.into())
    );

    let sha256_only = hex::decode(OPENSSL_PSS_SHA256_SPKI).unwrap();
    let sig256 = hex::decode(OPENSSL_PSS_SHA256_SIG).unwrap();
    verify_raw(&sha256_only, S::RSA_PSS_PSS_SHA256, OPENSSL_MSG, &sig256).unwrap();
    for scheme in [
        S::RSA_PSS_PSS_SHA384,
        S::RSA_PSS_PSS_SHA512,
        S::RSA_PSS_SHA256,
    ] {
        assert_eq!(
            verify_raw(&sha256_only, scheme, OPENSSL_MSG, &sig256),
            Err(CertificateError::UnsupportedSignatureAlgorithm.into()),
            "{scheme:?}"
        );
    }

    // The native key loader computes the same SPKI form for its own keys.
    for algorithm in [UNRESTRICTED, restricted(Sha256)] {
        let key = TestKey::server(algorithm);
        let loaded = prov::KEY_PROVIDER
            .load_private_key(key.private_key())
            .unwrap();
        assert_eq!(loaded.public_key().unwrap().as_ref(), key.spki().as_slice());
        let reference = if algorithm == UNRESTRICTED {
            &unrestricted
        } else {
            &sha256_only
        };
        // Same AlgorithmIdentifier as OpenSSL's (offset of the BIT STRING
        // differs only by the modulus).
        let alg_len = 2 + usize::from(reference[5]);
        assert_eq!(key.spki()[4..4 + alg_len], reference[4..4 + alg_len]);
    }
}
