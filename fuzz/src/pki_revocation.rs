//! Decoding and evaluating the inputs to certificate revocation decisions.

use std::sync::OnceLock;

use crate::connection::Identity;

mod asynchronous;
mod clubcard;
mod drivers;
mod evidence;
mod fixtures;
mod handshake;
mod transparency;

const MAX_EVIDENCE_LEN: usize = 64 * 1024;

pub fn run(data: &[u8]) {
    let Some((&kind, bytes)) = data.split_first() else {
        return;
    };
    if bytes.len() > MAX_EVIDENCE_LEN {
        return;
    }
    match kind {
        4 => clubcard::run(bytes),
        5 => drivers::run(fixtures::Fixture::get(), bytes),
        6 => asynchronous::run(fixtures::Fixture::get(), bytes),
        7 => transparency::run(bytes),
        _ => match kind % 4 {
            0 => clubcard::filter(bytes),
            1 => evidence::ocsp(fixtures::Fixture::get(), bytes),
            2 => evidence::sct(fixtures::Fixture::get(), bytes),
            _ => {
                static IDENTITY: OnceLock<Identity> = OnceLock::new();
                let identity = IDENTITY.get_or_init(|| {
                    Identity::generate("localhost", rcgen::ExtendedKeyUsagePurpose::ServerAuth)
                });
                handshake::run(identity, bytes);
            }
        },
    }
}

pub fn seeds() -> Vec<Vec<u8>> {
    let mut seeds = vec![
        [&[0], clubcard::FULL_V3].concat(),
        [&[0], clubcard::FULL_V4].concat(),
        vec![1],
        vec![1, 0x30, 3, 0x0a, 1, 3],
        vec![2],
        vec![2, 0, 3, 0, 1, 0],
        vec![3, 1, 2, 3, 4],
        vec![3, 0, 4],
        vec![4],
        vec![4, 2],
        vec![4, 1, 0],
        vec![5, 0],
        vec![5, 1],
        vec![5, 4],
        vec![5, 6],
        vec![5, 8],
        vec![5, 9],
        vec![6, 0],
        vec![6, 1],
        vec![6, 2],
        vec![6, 3],
        vec![6, 4],
        vec![6, 5],
    ];
    seeds.extend(
        transparency::seeds()
            .into_iter()
            .map(|seed| [&[7][..], &seed].concat()),
    );
    seeds
}

#[cfg(test)]
mod tests {
    #[test]
    fn revocation_seeds_reach_their_scenarios() {
        for seed in super::seeds() {
            super::run(&seed);
        }
    }
}
