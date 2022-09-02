clap-digest
===========

Integration to choose [digest][] with [clap][] on a CLI.


Features
--------

1.  A [`clap::ValueEnum`][] implementation for the different digest algorithm
    types:

    ```rust
    use clap::builder::{Arg, EnumValueParser};
    use clap_digest::Digest;

    Arg::new("digest")
        .takes_value(true)
        .value_parser(EnumValueParser::<Digest>::new())
    ```

1.  Ready-to-use [`clap::Arg`][] implementations:

    ```rust
    use clap::{Command, ValueEnum};
    use clap_digest::{Digest, DynDigest};

    let cli = Command::new("myapp")
        .arg(clap_digest::arg::digest().required_unless_present("list-digests"))
        .arg(clap_digest::arg::list_digests());

    let args = cli.get_matches_from(["myapp", "--list-digests"]);

    if args.contains_id("list-digests") {
        for digest in Digest::value_variants() {
            println!("{digest}");
        }
    } else {
        let digest = *args
            .get_one::<Digest>("digest")
            .expect("has default via clap");

        todo!()
    }
    ```

    See the [`clap_digest::arg`][crate::arg] module for more information.

1.  A conversion from `clap_digest::Digest` to `digest::DynDigest`:

    ```rust
    use clap_digest::{Digest, DynDigest};

    // fn doing some hashing, using any DynDigest implementation
    fn dyn_hash(hasher: &mut dyn DynDigest, data: &[u8]) -> String {
        hasher.update(data);
        let hash = hasher.finalize_reset();
        hash.iter().map(|byte| format!("{:02x}", byte)).collect()
    }

    // parse user-supplied CLI input to clap_digest::Digest with clap
    // suppose user runs this with: `command --digest MD5`
    // let args = cli.get_matches();
    let digest = *args.get_one::<Digest>("digest").unwrap();

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

For a complete CLI example, see [`examples/cksum.rs`](examples/cksum.rs).

```console
$ cargo run --example cksum -- -d SHA1 Cargo.toml
7a96ee85606435fe1f39c3fa6bdf4cf9bbbc338c  Cargo.toml

$ sha1sum Cargo.toml
7a96ee85606435fe1f39c3fa6bdf4cf9bbbc338c  Cargo.toml

$ cargo run --example cksum -- -d MD5 Cargo.toml | md5sum -c
Cargo.toml: OK
```

List all supported algorithms:

```console
$ cargo run --example cksum -- --list-digests
BLAKE2b512
BLAKE2s256
BLAKE3
...
```

All algorithm groups are feature-gated, so you can choose:

```console
$ cargo run --example cksum --no-default-features --features md5,sha1,sha2 -- --list-digests
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
[`clap::Arg`]: https://docs.rs/clap/latest/clap/struct.Arg.html
[`clap::ValueEnum`]: https://docs.rs/clap/latest/clap/trait.ValueEnum.html
[crate::arg]: https://docs.rs/clap_digest/latest/clap_digest/arg/index.html
[digest]: https://github.com/RustCrypto/hashes#supported-algorithms
