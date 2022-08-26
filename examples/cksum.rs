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

    if args.is_present("list-algorithms") {
        for algorithm in Digest::value_variants() {
            println!("{algorithm}");
        }
    } else {
        let inputs = args
            .values_of("input")
            .expect("at least one input is required via clap");

        let digest = *args
            .get_one::<Digest>("algorithm")
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
    let algorithm = Arg::with_name("algorithm")
        .short('a')
        .long("algorithm")
        .help("digest algorithm")
        .takes_value(true)
        .required_unless_present("list-algorithms")
        .value_parser(clap::builder::EnumValueParser::<Digest>::new());

    let list_algorithms = Arg::with_name("list-algorithms")
        .long("--list-algorithms")
        .help("list supported digest algorithms");

    let input = Arg::with_name("input")
        .help("input files")
        .required_unless_present("list-algorithms")
        .multiple_values(true);

    Command::new("cksum")
        .arg(input)
        .arg(algorithm)
        .arg(list_algorithms)
        .about("simple cksum clone that hashes text files")
        .after_help("try `cargo run --example cksum -- -a MD5 Cargo.toml | md5sum -c`")
}
