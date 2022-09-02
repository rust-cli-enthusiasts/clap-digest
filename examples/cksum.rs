use std::path::Path;

use anyhow::Result;
use clap::{Arg, Command, ValueEnum};
use clap_digest::Digest;
use digest::DynDigest;

fn hash_path(path: impl AsRef<Path>, hasher: &mut dyn DynDigest) -> Result<Box<[u8]>> {
    let content = std::fs::read_to_string(path)?;
    let bytes = content.as_bytes();
    hasher.update(bytes);
    Ok(hasher.finalize_reset())
}

fn main() -> Result<()> {
    let args = cli().get_matches();

    if args.contains_id("list-digests") {
        for digest in Digest::value_variants() {
            println!("{digest}");
        }
    } else {
        let inputs = args
            .values_of("input")
            .expect("at least one input is required via clap");

        let digest = *args
            .get_one::<Digest>("digest")
            .expect("has default via clap");

        let mut digest: Box<dyn DynDigest> = digest.into();

        for input in inputs {
            let hash = hash_path(input, &mut (*digest))?;
            let hash: String = hash.iter().map(|byte| format!("{:02x}", byte)).collect();

            println!("{hash}  {input}");
        }
    }

    Ok(())
}

fn cli() -> Command<'static> {
    let input = Arg::new("input")
        .help("input files")
        .required_unless_present("list-digests")
        .multiple_values(true);

    Command::new("cksum")
        .arg(input)
        .arg(clap_digest::arg::digest().required_unless_present("list-digests"))
        .arg(clap_digest::arg::list_digests())
        .about("simple cksum clone that hashes text files")
        .after_help("try `cargo run --example cksum -- -d MD5 Cargo.toml | md5sum -c`")
}
