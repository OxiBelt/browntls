//! Configuration operations of the `tls_ech` target: `ECHConfigList`
//! parsing, server keys and server configurations, the SVCB/HTTPS record
//! helpers and GREASE settings.

use browntls::crypto::hpke::{Hpke, HpkePublicKey};
use browntls::crypto::native::hpke::ALL_SUPPORTED_SUITES;
use browntls::ech::svcb::{
    ECH_SVC_PARAM_KEY, ech_config_list_from_presentation, ech_config_list_from_svc_params,
    ech_config_list_from_svcb_rdata,
};
use browntls::ech::{EchConfig, EchGreaseConfig, EchServerConfig, EchServerKey};

use super::{
    ECH_VERSION, Fields, KEMS, Key, MAX_GENERATIONS, PUBLIC, State, base64, config_list, fixture,
    pick_fields, pick_name, pick_suites, public_name_ok,
};
use crate::input::{Input, put_field};

// ----------------------------------------------------------- configuration

/// Checks a configuration the client accepted against `offered`.
fn check_client_config(config: &EchConfig, offered: &[&'static dyn Hpke]) {
    assert!(public_name_ok(config.public_name().as_ref().as_bytes()));
    let suite = config.suite();
    assert!(
        offered.iter().any(|s| s.suite() == suite),
        "selected suite not offered"
    );
    let _ = format!("{config:?}");
}

/// The SVCB helpers must agree on `list`: as an `ech` SvcParam, in RDATA,
/// and in presentation format.
fn check_svcb_agree(list: &[u8]) {
    let presented = ech_config_list_from_presentation(&base64(list));
    if let Ok(decoded) = &presented {
        assert_eq!(decoded, list);
    }
    let quoted = ech_config_list_from_presentation(&format!("\"{}\"", base64(list)));
    assert_eq!(quoted.is_ok(), presented.is_ok());
    if list.len() + 8 > usize::from(u16::MAX) {
        return;
    }
    let mut params = Vec::new();
    params.extend_from_slice(&1u16.to_be_bytes());
    put_field(&mut params, b"\x02h2");
    params.extend_from_slice(&ECH_SVC_PARAM_KEY.to_be_bytes());
    put_field(&mut params, list);
    let from_params = ech_config_list_from_svc_params(&params);
    match (&presented, &from_params) {
        (Ok(_), Ok(Some(found))) => assert_eq!(found, list),
        (Err(_), Err(_)) => {}
        _ => panic!("SVCB helpers disagree: {presented:?} {from_params:?}"),
    }
    let mut rdata = vec![0, 1, 3, b's', b'v', b'c', 0];
    rdata.extend_from_slice(&params);
    let from_rdata = ech_config_list_from_svcb_rdata(&rdata);
    assert_eq!(from_rdata.is_ok(), from_params.is_ok());
    if let (Ok(a), Ok(b)) = (&from_rdata, &from_params) {
        assert_eq!(a, b);
    }
}

pub(super) fn list(input: &mut Input) {
    let offered = pick_suites(input);
    let bytes = input.field();
    if let Ok(config) = EchConfig::new(bytes, &offered) {
        check_client_config(&config, &offered);
        assert!(
            ech_config_list_from_presentation(&base64(bytes)).is_ok(),
            "a list the client uses is not a well-formed list"
        );
    }
    if !bytes.is_empty() {
        check_svcb_agree(bytes);
    }
}

pub(super) fn config(input: &mut Input, state: &mut State) {
    let (fields, sound) = pick_fields(input);
    let offered = pick_suites(input);
    let entry = fields.encode();
    let list = config_list([&entry[..]]);
    let fixture = fixture();
    let private_key = fixture.pairs[sound.unwrap_or(0)].1.clone();

    // The client side.
    match EchConfig::new(&list, &offered) {
        Ok(config) => {
            assert!(fields.usable_by_client(&offered), "{fields:?}");
            check_client_config(&config, &offered);
            assert_eq!(config.config_id(), fields.config_id);
            assert_eq!(
                config.public_name().as_ref().as_bytes(),
                &fields.public_name[..]
            );
            let (kdf, aead) = fields.client_suite(&offered).expect("model suite");
            let suite = config.suite();
            assert_eq!(
                (suite.kem.0, suite.sym.kdf_id.0, suite.sym.aead_id.0),
                (fields.kem, kdf, aead)
            );
        }
        Err(_) => assert!(!fields.usable_by_client(&offered), "{fields:?}"),
    }

    // The server side.
    match EchServerKey::new(&entry, private_key, &offered) {
        Ok(key) => {
            assert!(fields.usable_by_server(&offered), "{fields:?}");
            assert_eq!(key.ech_config(), &entry[..], "ECHConfig re-encoding");
            assert_eq!(key.config_id(), fields.config_id);
            assert_eq!(key.kem().0, fields.kem);
            let _ = format!("{key:?}");
            let server = EchServerConfig::new(vec![key.clone()]).expect("one key");
            assert_eq!(server.ech_config_list(), &list[..]);
            state.push(Key {
                key,
                sound: sound.is_some(),
                public_name: fields.public_name.clone(),
            });
        }
        Err(_) => assert!(!fields.usable_by_server(&offered), "{fields:?}"),
    }
    check_svcb_agree(&list);
}

pub(super) fn generate(input: &mut Input, state: &mut State) {
    let config_id = input.byte();
    let name = pick_name(input);
    let maximum_name_length = input.byte();
    let offered = pick_suites(input);
    if state.generations == MAX_GENERATIONS {
        return;
    }
    state.generations += 1;
    let Ok(text) = String::from_utf8(name.clone()) else {
        return;
    };
    let expected = !offered.is_empty() && public_name_ok(&name);
    let key = match EchServerKey::generate(config_id, &text, maximum_name_length, &offered) {
        Ok(key) => {
            assert!(expected, "generated with {text:?}");
            key
        }
        Err(_) => {
            assert!(!expected, "refused {text:?}");
            return;
        }
    };
    let kem = offered[0].suite().kem;
    assert_eq!(key.config_id(), config_id);
    assert_eq!(key.kem(), kem);
    assert!(!key.private_key().secret_bytes().is_empty());

    // The configuration is the model's encoding of what was asked for.
    let entry = key.ech_config();
    let pk_len = usize::from(u16::from_be_bytes([entry[7], entry[8]]));
    let mut suites = Vec::new();
    for s in &offered {
        let s = s.suite();
        if s.kem == kem {
            suites.push((s.sym.kdf_id.0, s.sym.aead_id.0));
        }
    }
    let fields = Fields {
        version: ECH_VERSION,
        config_id,
        kem: kem.0,
        public_key: entry[9..9 + pk_len].to_vec(),
        suites,
        maximum_name_length,
        public_name: name.clone(),
        extensions: Vec::new(),
    };
    assert_eq!(entry, &fields.encode()[..]);

    // A stored key round-trips through its parts.
    let again = EchServerKey::new(entry, key.private_key().clone(), &offered)
        .expect("a generated key loads");
    assert_eq!(again.ech_config(), entry);
    let list = config_list([entry]);
    let client = EchConfig::new(&list, &offered).expect("a generated key's config is usable");
    assert_eq!(client.config_id(), config_id);
    assert_eq!(client.public_name().as_ref().as_bytes(), &name[..]);
    state.push(Key {
        key,
        sound: true,
        public_name: name,
    });
}

pub(super) fn serve(input: &mut Input, state: &State) {
    let mask = input.byte();
    let keys: Vec<EchServerKey> = state
        .keys
        .iter()
        .enumerate()
        .filter(|(i, _)| mask >> i & 1 != 0)
        .map(|(_, k)| k.key.clone())
        .collect();
    let entries: Vec<Vec<u8>> = keys.iter().map(|k| k.ech_config().to_vec()).collect();
    let total: usize = entries.iter().map(Vec::len).sum();
    match EchServerConfig::new(keys) {
        Ok(server) => {
            assert!(!entries.is_empty() && total <= usize::from(u16::MAX));
            let expected = config_list(entries.iter().map(Vec::as_slice));
            assert_eq!(server.ech_config_list(), &expected[..]);
            // A client takes the first configuration it can use.
            if let Ok(config) = EchConfig::new(server.ech_config_list(), ALL_SUPPORTED_SUITES) {
                let first = state
                    .keys
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| mask >> i & 1 != 0)
                    .map(|(_, k)| k)
                    .find(|k| {
                        EchConfig::new(&config_list([k.key.ech_config()]), ALL_SUPPORTED_SUITES)
                            .is_ok()
                    })
                    .expect("a usable key");
                assert_eq!(config.config_id(), first.key.config_id());
            }
            check_svcb_agree(server.ech_config_list());
        }
        Err(_) => assert!(entries.is_empty() || total > usize::from(u16::MAX)),
    }
}

// -------------------------------------------------------------------- SVCB

/// RFC 9460 §2.2 SvcParams: strictly increasing keys, each with a 16-bit
/// length; the `ech` value must be a well-formed list.
fn model_svc_params(params: &[u8]) -> Result<Option<Vec<u8>>, ()> {
    let mut at = 0;
    let mut last: Option<u16> = None;
    let mut found = None;
    while at < params.len() {
        let header = params.get(at..at + 4).ok_or(())?;
        let key = u16::from_be_bytes([header[0], header[1]]);
        let len = usize::from(u16::from_be_bytes([header[2], header[3]]));
        let value = params.get(at + 4..at + 4 + len).ok_or(())?;
        if last.is_some_and(|prev| key <= prev) {
            return Err(());
        }
        last = Some(key);
        if key == ECH_SVC_PARAM_KEY {
            // Well-formedness of the list itself, decided by the
            // presentation decoder (checked against the other helpers in
            // `check_svcb_agree`).
            if value.is_empty() || ech_config_list_from_presentation(&base64(value)).is_err() {
                return Err(());
            }
            found = Some(value.to_vec());
        }
        at += 4 + len;
    }
    Ok(found)
}

pub(super) fn svcb(input: &mut Input) {
    let raw = input.bool();
    if raw {
        let bytes = input.field();
        let params = ech_config_list_from_svc_params(bytes);
        assert_eq!(params.as_ref().ok(), model_svc_params(bytes).ok().as_ref());
        let rdata = ech_config_list_from_svcb_rdata(bytes);
        if let Ok(Some(list)) = rdata.as_ref().map(Option::as_deref) {
            assert!(ech_config_list_from_presentation(&base64(list)).is_ok());
        }
        return;
    }
    // Parameters from fuzzed keys, usually with a usable ech value.
    let fixture = fixture();
    let good = Fields {
        version: ECH_VERSION,
        config_id: 1,
        kem: KEMS[0].0,
        public_key: fixture.pairs[0].0.0.clone(),
        suites: vec![(1, 1)],
        maximum_name_length: 0,
        public_name: PUBLIC.as_bytes().to_vec(),
        extensions: Vec::new(),
    }
    .encode();
    let good = config_list([&good[..]]);
    let mut params = Vec::new();
    let count = input.choose(6);
    for _ in 0..count {
        let key = match input.choose(4) {
            0 => ECH_SVC_PARAM_KEY,
            _ => input.u16() & 0x0f,
        };
        let value = if key == ECH_SVC_PARAM_KEY && input.bool() {
            good.clone()
        } else {
            input.short_field().to_vec()
        };
        params.extend_from_slice(&key.to_be_bytes());
        // A declared length past the end, sometimes.
        let declared = if input.choose(8) == 0 {
            value.len() + 1
        } else {
            value.len()
        };
        params.extend_from_slice(&(declared as u16).to_be_bytes());
        params.extend_from_slice(&value);
    }
    let from_params = ech_config_list_from_svc_params(&params);
    assert_eq!(
        from_params.as_ref().ok(),
        model_svc_params(&params).ok().as_ref(),
        "{params:?}"
    );

    // RDATA: priority, target name labels, params.
    let priority = input.u16();
    let mut rdata = priority.to_be_bytes().to_vec();
    let labels = input.choose(4);
    let mut target_ok = true;
    for _ in 0..labels {
        let len = match input.choose(8) {
            0 => 64,
            _ => input.choose(10),
        };
        if len == 0 {
            break;
        }
        target_ok &= len <= 63;
        rdata.push(len as u8);
        rdata.extend(std::iter::repeat_n(b'a', len));
    }
    rdata.push(0);
    rdata.extend_from_slice(&params);
    let from_rdata = ech_config_list_from_svcb_rdata(&rdata);
    match (target_ok, priority, &from_rdata) {
        (false, _, result) => assert!(result.is_err()),
        (true, 0, result) => assert_eq!(result, &Ok(None)),
        (true, _, result) => assert_eq!(result.as_ref().ok(), from_params.as_ref().ok()),
    }
}

pub(super) fn presentation(input: &mut Input) {
    let bytes = input.field();
    let Ok(text) = core::str::from_utf8(bytes) else {
        return;
    };
    if let Ok(list) = ech_config_list_from_presentation(text) {
        // Decoded lists are well formed and re-encode.
        assert_eq!(
            ech_config_list_from_presentation(&base64(&list)).as_ref(),
            Ok(&list)
        );
        let _ = EchConfig::new(&list, ALL_SUPPORTED_SUITES);
    }
}

pub(super) fn grease(input: &mut Input, state: &mut State) {
    let suite = *input.pick(ALL_SUPPORTED_SUITES);
    let mut valid = true;
    let config = if input.bool() {
        EchGreaseConfig::generate(suite).expect("GREASE key generation")
    } else {
        let fixture = fixture();
        let kem = KEMS
            .iter()
            .position(|k| *k == suite.suite().kem)
            .unwrap_or(0);
        let placeholder = if input.bool() {
            fixture.pairs[kem].0.clone()
        } else {
            valid = false;
            HpkePublicKey(input.short_field().to_vec())
        };
        EchGreaseConfig::new(suite, placeholder)
    };
    let _ = format!("{config:?}");
    state.grease = Some((config, valid));
}
