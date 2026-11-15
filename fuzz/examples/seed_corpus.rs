//! Writes the generated seed inputs to `corpus/<target>/` (relative to the
//! current directory, normally `fuzz/`), where `cargo fuzz run` looks.

use std::fs;
use std::path::Path;

fn main() -> std::io::Result<()> {
    for (name, _harness, seeds) in browntls_fuzz::seeds::TARGETS {
        let dir = Path::new("corpus").join(name);
        fs::create_dir_all(&dir)?;
        let seeds = seeds();
        for (i, seed) in seeds.iter().enumerate() {
            fs::write(dir.join(format!("seed-{i:03}")), seed)?;
        }
        println!("{name}: {} seeds", seeds.len());
    }
    Ok(())
}
