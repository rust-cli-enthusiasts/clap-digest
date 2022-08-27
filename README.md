clap-digest
===========

Integration to choose [digest][] with [clap][] on a CLI.


Features
--------

1.  A [clap::ValueEnum][] implementation for the different digest algorithm
    types:

    ```rust
    let algorithm = Arg::with_name("algorithm")
        .short('a')
        .long("algorithm")
        .help("digest algorithm")
        .takes_value(true)
        // this here is the important bit:
        .value_parser(clap::builder::EnumValueParser::<Digest>::new());
    ```

1.  A conversion from `clap_digest::Digest` to `digest::DynDigest`:

    ```rust
    // fn doing some hashing, using any DynDigest implementation
    fn dyn_hash(hasher: &mut dyn DynDigest, data: &[u8]) -> String {
        hasher.update(data);
        let hash = hasher.finalize_reset();
        hash.iter().map(|byte| format!("{:02x}", byte)).collect()
    }

    // parse user-supplied CLI input to clap_digest::Digest with clap
    // suppose user runs this with: `command --algorithm MD5`
    // let args = cli.get_matches();
    let digest = *args.get_one::<Digest>("algorithm").unwrap();

    // convert to DynDigest
    let mut digest: Box<dyn DynDigest> = digest.into();

    // use with hashing function
    let hash = dyn_hash(&mut (*digest), b"foo");

    assert_eq!(hash, "acbd18db4cc2f85cedef654fccc4a4d8");
    ```

1.  Digest algorithm groups are feature-gated. Use `cargo feature
    clap-digest` for a complete listing. At least one digest algorithm
    group feature must be chosen. To limit the digest algorithm families
    you want to support in your crate, define your own features, e.g.:

    ```toml
    [features]
    default = ["sha2"]
    md5 = ["clap-digest/md5"]
    sha1 = ["clap-digest/sha1"]
    sha2 = ["clap-digest/sha2"]
    ```


Example
-------

For a complete CLI example, see `examples/cksum.rs`.

```console
$ cargo run --example cksum -- -a SHA1 Cargo.toml
7a96ee85606435fe1f39c3fa6bdf4cf9bbbc338c  Cargo.toml

$ sha1sum Cargo.toml
7a96ee85606435fe1f39c3fa6bdf4cf9bbbc338c  Cargo.toml

$ cargo run --example cksum -- -a MD5 Cargo.toml | md5sum -c
Cargo.toml: OK
```

List all supported algorithms:

```console
$ cargo run --example cksum -- --list-algorithms
BLAKE2b512
BLAKE2s256
BLAKE3
...
```

All algorithm groups are feature-gated, so you can choose:

```console
$ cargo run --example cksum --no-default-features --features md5,sha1,sha2 -- --list-algorithms
MD5
SHA1
SHA224
SHA256
SHA384
SHA512
SHA512/224
SHA512/256
```


[clap]: https://crates.io/crates/clap
[clap::ValueEnum]: https://docs.rs/clap/latest/clap/trait.ValueEnum.html
[digest]: https://github.com/RustCrypto/hashes#supported-algorithms
