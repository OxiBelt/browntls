//! Starting inputs of the `tls_ech` target.

use browntls::ech::svcb::ECH_SVC_PARAM_KEY;

use super::{ECH_VERSION, Fields, KEMS, NAMES, base64, config_list, fixture};
use crate::input::{put_field, put_short_field};

// ------------------------------------------------------------------- seeds

/// How a seed asks [`pick_fields`] for a cipher suite.
///
/// [`pick_fields`]: super::pick_fields
#[derive(Clone, Copy)]
enum SuiteSeed {
    /// KDF and AEAD indices (0 to 2) of the native suites.
    Known(u8, u8),
    ExportOnly,
    Raw(u16, u16),
}

/// The input [`pick_fields`] reads for these fields. `kem` is an index of
/// [`KEMS`] (or a raw KEM id with `raw_kem`); `public_key` replaces the
/// fixture's key.
///
/// [`pick_fields`]: super::pick_fields
struct FieldsSeed<'a> {
    version: Option<u16>,
    config_id: u8,
    kem: u8,
    raw_kem: Option<u16>,
    public_key: Option<&'a [u8]>,
    suites: &'a [SuiteSeed],
    maximum_name_length: u8,
    /// An index of [`NAMES`], or raw bytes.
    name: Result<u8, &'a [u8]>,
    extensions: &'a [(u16, &'a [u8])],
}

impl FieldsSeed<'_> {
    const DEFAULT: FieldsSeed<'static> = FieldsSeed {
        version: None,
        config_id: 7,
        kem: 0,
        raw_kem: None,
        public_key: None,
        suites: &[SuiteSeed::Known(0, 0)],
        maximum_name_length: 32,
        name: Ok(0),
        extensions: &[],
    };

    fn write(&self, out: &mut Vec<u8>) {
        match self.version {
            Some(v) => {
                out.push(0);
                out.extend_from_slice(&v.to_be_bytes());
            }
            None => out.push(1),
        }
        out.push(self.config_id);
        match self.raw_kem {
            Some(kem) => {
                out.push(0);
                out.extend_from_slice(&kem.to_be_bytes());
            }
            None => out.extend_from_slice(&[1, self.kem]),
        }
        match (self.raw_kem, self.public_key) {
            (None, None) => out.push(0),
            (None, Some(pk)) => {
                out.push(5);
                put_short_field(out, pk);
            }
            (Some(_), pk) => {
                out.push(0);
                put_short_field(out, pk.unwrap_or(b"key"));
            }
        }
        out.push(self.suites.len() as u8);
        for suite in self.suites {
            match *suite {
                SuiteSeed::Known(kdf, aead) => out.extend_from_slice(&[2, kdf, aead]),
                SuiteSeed::ExportOnly => out.push(1),
                SuiteSeed::Raw(kdf, aead) => {
                    out.push(0);
                    out.extend_from_slice(&kdf.to_be_bytes());
                    out.extend_from_slice(&aead.to_be_bytes());
                }
            }
        }
        out.push(self.maximum_name_length);
        match self.name {
            Ok(index) => out.extend_from_slice(&[1, index]),
            Err(raw) => {
                out.push(0);
                put_short_field(out, raw);
            }
        }
        out.push(self.extensions.len() as u8);
        for (typ, data) in self.extensions {
            out.extend_from_slice(&typ.to_be_bytes());
            put_short_field(out, data);
        }
    }
}

/// A handshake operation: scenario, HelloRetryRequest, config id, maximum
/// name length, kept key, edit.
fn handshake_seed(scenario: u8, hrr: bool, config_id: u8, kept: bool, edit: bool) -> Vec<u8> {
    let mut seed = vec![
        7,
        scenario,
        u8::from(hrr),
        config_id,
        32,
        u8::from(kept),
        u8::from(edit),
    ];
    if edit {
        seed.extend_from_slice(&[0x01, 0x20, 0x40]);
    }
    seed
}

/// Starting inputs for `tls_ech`.
#[must_use]
pub fn seeds() -> Vec<Vec<u8>> {
    crate::init();
    let fixture = fixture();
    let mut seeds = Vec::new();

    let example = Fields {
        version: ECH_VERSION,
        config_id: 1,
        kem: KEMS[0].0,
        public_key: fixture.pairs[0].0.0.clone(),
        suites: vec![(1, 1)],
        maximum_name_length: 100,
        public_name: b"ech-sites.example.net".to_vec(),
        extensions: Vec::new(),
    };
    let list = config_list([&example.encode()[..]]);

    // 0: a list, for all suites, one KEM, one suite, a mask, and none
    for suites in [
        &[0u8][..],
        &[1, 0],
        &[2, 0],
        &[3, 0, 0, 0, 0, 0, 0, 0, 3],
        &[4],
    ] {
        let mut seed = vec![0];
        seed.extend_from_slice(suites);
        put_field(&mut seed, &list);
        seeds.push(seed);
    }

    // 1: configurations, all suites offered: each KEM with its key, then
    // variants the model must judge
    let base = FieldsSeed::DEFAULT;
    let mut configs: Vec<FieldsSeed<'_>> = (0..5u8)
        .map(|kem| FieldsSeed {
            kem,
            suites: &[SuiteSeed::Known(1, 2), SuiteSeed::Known(0, 0)],
            ..FieldsSeed::DEFAULT
        })
        .collect();
    configs.extend([
        FieldsSeed {
            public_key: Some(b"not a key"),
            ..base
        },
        FieldsSeed {
            version: Some(0xfe0c),
            ..base
        },
        FieldsSeed {
            raw_kem: Some(0x0099),
            ..base
        },
        FieldsSeed {
            extensions: &[(0x8001, b"x")],
            ..base
        },
        FieldsSeed {
            extensions: &[(0x0001, b"x"), (0x0001, b"")],
            ..base
        },
        FieldsSeed {
            extensions: &[(0x0001, b"x"), (0x0002, b"")],
            ..base
        },
        FieldsSeed {
            suites: &[],
            ..base
        },
        FieldsSeed {
            suites: &[SuiteSeed::ExportOnly, SuiteSeed::Raw(9, 9)],
            ..base
        },
        FieldsSeed {
            public_key: Some(b""),
            ..base
        },
        FieldsSeed {
            name: Err(b""),
            ..base
        },
        FieldsSeed {
            name: Err(b"\xff.example"),
            ..base
        },
    ]);
    for index in 2..NAMES.len() as u8 {
        configs.push(FieldsSeed {
            name: Ok(index),
            ..base
        });
    }
    for fields in &configs {
        let mut seed = vec![1];
        fields.write(&mut seed);
        seed.push(0);
        seeds.push(seed);
    }
    // a configuration served with a suite subset that does not match
    let mut seed = vec![1];
    base.write(&mut seed);
    seed.extend_from_slice(&[1, 2]);
    seeds.push(seed);

    // 2: generate for every KEM, with a bad name, with no suites; then
    // serve two kept keys
    for kem in 0..5u8 {
        seeds.push(vec![2, 3, 1, 0, 32, 1, kem]);
    }
    seeds.push(vec![2, 3, 1, 6, 0, 0]);
    seeds.push(vec![2, 3, 1, 0, 0, 4]);
    let mut seed = vec![2, 4, 0];
    put_short_field(&mut seed, b"ok.example");
    seed.extend_from_slice(&[0, 0, 2, 5, 1, 0, 0, 0, 3, 0b11, 3, 0]);
    seeds.push(seed);

    // 4: SVCB, raw and built
    let mut params = Vec::new();
    params.extend_from_slice(&1u16.to_be_bytes());
    put_field(&mut params, b"\x02h2");
    params.extend_from_slice(&ECH_SVC_PARAM_KEY.to_be_bytes());
    put_field(&mut params, &list);
    let mut seed = vec![4, 1];
    put_field(&mut seed, &params);
    seed.extend_from_slice(&[4, 1]);
    let mut rdata = vec![0, 1, 0];
    rdata.extend_from_slice(&params);
    put_field(&mut seed, &rdata);
    seeds.push(seed);
    // built: alpn-like key 1, then ech with the good list; priority 1; one
    // label
    let mut seed = vec![4, 0, 2];
    seed.extend_from_slice(&[1, 0, 1]);
    put_short_field(&mut seed, b"\x02h2");
    seed.extend_from_slice(&[1, 0, 1, 1, 0, 1, 1, 1, 3]);
    seeds.push(seed);
    // AliasMode; a label too long; out-of-order keys; a bad ech value
    seeds.push(vec![4, 0, 0, 0, 0, 0]);
    seeds.push(vec![4, 0, 0, 0, 1, 1, 0]);
    let mut seed = vec![4, 0, 2, 1, 0, 6];
    put_short_field(&mut seed, b"a");
    seed.extend_from_slice(&[1, 1, 0, 1]);
    put_short_field(&mut seed, b"b");
    seed.extend_from_slice(&[1, 0, 1, 0]);
    seeds.push(seed);
    let mut seed = vec![4, 0, 1, 0, 0];
    put_short_field(&mut seed, b"\x00\x01\x02");
    seed.extend_from_slice(&[1, 0, 1, 0]);
    seeds.push(seed);

    // 5: presentation
    for text in [
        base64(&list),
        format!("\"{}\"", base64(&list)),
        "AE j=".into(),
        "AAA=".into(),
    ] {
        let mut seed = vec![5];
        put_field(&mut seed, text.as_bytes());
        seeds.push(seed);
    }

    // 7: handshakes: accepted (with and without HelloRetryRequest), stale
    // (twice, one sharing the server's id), no server ECH, GREASE without
    // and with server ECH, and an edited flight
    for (scenario, hrr, id) in [
        (0u8, false, 7u8),
        (0, true, 7),
        (1, false, 7),
        (1, true, 8),
        (2, false, 7),
        (3, false, 0),
        (3, true, 1),
    ] {
        seeds.push(handshake_seed(scenario, hrr, id, false, false));
    }
    seeds.push(handshake_seed(0, false, 7, false, true));
    // split mode: accepted (whole, then byte by byte after a
    // HelloRetryRequest), stale (both local hand-offs), GREASE, random
    // identifiers with trial decryption, and an edited flight
    for (hrr, id, variant, chunk) in [
        (false, 7u8, 0u8, 255u8),
        (true, 7, 0, 0),
        (false, 7, 1, 3),
        (true, 8, 1, 2),
        (false, 7, 2, 9),
        (true, 7, 2, 40),
    ] {
        let mut seed = handshake_seed(4, hrr, id, false, false);
        seed.extend_from_slice(&[variant, chunk]);
        seeds.push(seed);
    }
    for (hrr, chunk) in [(false, 100u8), (true, 6)] {
        let mut seed = handshake_seed(5, hrr, 7, false, false);
        seed.push(chunk);
        seeds.push(seed);
    }
    let mut seed = handshake_seed(4, true, 7, false, true);
    seed.extend_from_slice(&[0, 255]);
    seeds.push(seed);
    // GREASE settings (generated, fixture placeholder, fuzzed placeholder),
    // then a handshake using them
    for grease in [&[6u8, 9, 1][..], &[6, 18, 0, 1], &[6, 27, 0, 0, 1, 7]] {
        let mut seed = grease.to_vec();
        seed.extend_from_slice(&handshake_seed(3, false, 1, false, false));
        seeds.push(seed);
    }
    // a generated key (P-256), then each scenario with it; a configured
    // key with a name lacking a certificate, then no server ECH
    for scenario in 0..3u8 {
        let mut seed = vec![2, 3, 1, 0, 32, 1, 1];
        seed.extend_from_slice(&handshake_seed(scenario, false, 9, true, false));
        seeds.push(seed);
    }
    let mut seed = vec![1];
    FieldsSeed {
        name: Ok(2),
        ..base
    }
    .write(&mut seed);
    seed.push(0);
    seed.extend_from_slice(&handshake_seed(2, false, 9, true, false));
    seeds.push(seed);
    seeds
}
