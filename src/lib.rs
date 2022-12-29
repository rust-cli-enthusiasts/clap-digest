//! Integration to choose [digest][] with [clap][] on a CLI.
//!
//!
//! Features
//! --------
//!
//! 1.  A [`clap::ValueEnum`] implementation for the different [`Digest`]
//!     algorithm types:
//!
//!     ```rust
//!     use clap::builder::{Arg, ArgAction, EnumValueParser};
//!     use clap_digest::Digest;
//!
//!     let digest = Arg::new("digest")
//!         .action(ArgAction::Set)
//!         .value_parser(EnumValueParser::<Digest>::new());
//!     ```
//!
//! 1.  Ready-to-use [`clap::Arg`] implementations:
//!
//!     ```
//!     use clap::Command;
//!
//!     let cli = Command::new("myapp")
//!         .arg(clap_digest::arg::digest().required_unless_present("list-digests"))
//!         .arg(clap_digest::arg::list_digests());
//!     ```
//!
//!     See the [`crate::arg`] module for more information.
//!
//! 1.  A conversion from [`crate::Digest`] to [`digest::DynDigest`]:
//!
//!     ```rust
//!     # use clap::Command;
//!     use clap_digest::{Digest, DynDigest};
//!     # let digest = clap_digest::arg::digest();
//!     # let list_digests = clap_digest::arg::list_digests();
//!     # let cli = Command::new("cksum").arg(digest).arg(list_digests);
//!     # let args = cli.get_matches_from(["cksum", "--digest", "MD5"]);
//!
//!     // fn doing some hashing, using any DynDigest implementation
//!     fn dyn_hash(hasher: &mut dyn DynDigest, data: &[u8]) -> String {
//!         hasher.update(data);
//!         let hash = hasher.finalize_reset();
//!         hash.iter().map(|byte| format!("{:02x}", byte)).collect()
//!     }
//!
//!     // parse user-supplied CLI input to clap_digest::Digest with clap
//!     // suppose user runs this with: `command --digest MD5`
//!     // let args = cli.get_matches();
//!     let digest = *args.get_one::<Digest>("digest").unwrap();
//!
//!     // convert to DynDigest
//!     let mut digest: Box<dyn DynDigest> = digest.into();
//!
//!     // use with hashing function
//!     let hash = dyn_hash(digest.as_mut(), b"foo");
//!
//!     assert_eq!(hash, "acbd18db4cc2f85cedef654fccc4a4d8");
//!     ```
//!
//! 1.  Digest algorithm groups are feature-gated. Use `cargo feature
//!     clap-digest` for a complete listing. At least one digest algorithm
//!     group feature must be chosen. To limit the digest algorithm families
//!     you want to support in your crate, define your own features, e.g.:
//!
//!     ```toml
//!     [features]
//!     default = ["sha2"]
//!     md5 = ["clap-digest/md5"]
//!     sha1 = ["clap-digest/sha1"]
//!     sha2 = ["clap-digest/sha2"]
//!     ...
//!     ```
//!
//!
//! Example
//! -------
//!
//! And now a complete CLI example (see also in `examples/cksum.rs`):
//!
//! ```rust,no_run
#![doc = include_str!("../examples/cksum.rs")]
//! ```
//!
//! A few example runs:
//!
//! ```console
//! $ cargo run --example cksum -- -d SHA1 Cargo.toml
//! 7a96ee85606435fe1f39c3fa6bdf4cf9bbbc338c  Cargo.toml
//!
//! $ sha1sum Cargo.toml
//! 7a96ee85606435fe1f39c3fa6bdf4cf9bbbc338c  Cargo.toml
//!
//! $ cargo run --example cksum -- -d MD5 Cargo.toml | md5sum -c
//! Cargo.toml: OK
//! ```
//!
//! List all supported algorithms:
//!
//! ```console
//! $ cargo run --example cksum -- --list-digests
//! BLAKE2b512
//! BLAKE2s256
//! BLAKE3
//! ...
//! ```
//!
//! All algorithm groups are feature-gated, so you can choose:
//!
//! ```console
//! $ cargo run --example cksum --no-default-features --features md5,sha1,sha2 -- --list-digests
//! MD5
//! SHA1
//! SHA224
//! SHA256
//! SHA384
//! SHA512
//! SHA512/224
//! SHA512/256
//! ```
//!
//!
//! [clap]: https://crates.io/crates/clap
//! [clap::ValueEnum]: https://docs.rs/clap/latest/clap/trait.ValueEnum.html
//! [digest]: https://github.com/RustCrypto/hashes#supported-algorithms

#![deny(clippy::all, missing_docs, unused_must_use)]
#![warn(clippy::pedantic, clippy::nursery, clippy::cargo)]

pub mod arg;

use std::fmt;

use clap::{builder::PossibleValue, ValueEnum};
pub use digest::DynDigest;

#[cfg(not(any(
    feature = "blake2",
    feature = "blake3",
    feature = "fsb",
    feature = "gost94",
    feature = "groestl",
    feature = "md2",
    feature = "md4",
    feature = "md5",
    feature = "ripemd",
    feature = "sha1",
    feature = "sha2",
    feature = "sha3",
    feature = "shabal",
    feature = "sm3",
    feature = "streebog",
    feature = "tiger",
    feature = "whirlpool"
)))]
compile_error!("at least one digest algorithm family feature needs to be enabled");

/// Supported digest algorithms.
#[allow(missing_docs)] // no docs for the variants
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum Digest {
    #[cfg(feature = "blake2")]
    BLAKE2b512,

    #[cfg(feature = "blake2")]
    BLAKE2s256,

    #[cfg(feature = "blake3")]
    BLAKE3,

    #[cfg(feature = "fsb")]
    FSB160,

    #[cfg(feature = "fsb")]
    FSB224,

    #[cfg(feature = "fsb")]
    FSB256,

    #[cfg(feature = "fsb")]
    FSB384,

    #[cfg(feature = "fsb")]
    FSB512,

    #[cfg(feature = "gost94")]
    GOST94CryptoPro,

    #[cfg(feature = "gost94")]
    GOST94UA,

    #[cfg(feature = "gost94")]
    GOST94s2015,

    #[cfg(feature = "groestl")]
    Groestl224,

    #[cfg(feature = "groestl")]
    Groestl256,

    #[cfg(feature = "groestl")]
    Groestl384,

    #[cfg(feature = "groestl")]
    Groestl512,

    #[cfg(feature = "md2")]
    MD2,

    #[cfg(feature = "md4")]
    MD4,

    #[cfg(feature = "md5")]
    MD5,

    #[cfg(feature = "ripemd")]
    RIPEMD160,

    #[cfg(feature = "ripemd")]
    RIPEMD256,

    #[cfg(feature = "ripemd")]
    RIPEMD320,

    #[cfg(feature = "sha1")]
    SHA1,

    #[cfg(feature = "sha2")]
    SHA224,

    #[cfg(feature = "sha2")]
    SHA256,

    #[cfg(feature = "sha2")]
    SHA384,

    #[cfg(feature = "sha2")]
    SHA512,

    #[cfg(feature = "sha2")]
    SHA512_224,

    #[cfg(feature = "sha2")]
    SHA512_256,

    #[cfg(feature = "sha3")]
    SHA3_224,

    #[cfg(feature = "sha3")]
    SHA3_256,

    #[cfg(feature = "sha3")]
    SHA3_384,

    #[cfg(feature = "sha3")]
    SHA3_512,

    #[cfg(feature = "shabal")]
    SHABAL192,

    #[cfg(feature = "shabal")]
    SHABAL224,

    #[cfg(feature = "shabal")]
    SHABAL256,

    #[cfg(feature = "shabal")]
    SHABAL384,

    #[cfg(feature = "shabal")]
    SHABAL512,

    #[cfg(feature = "sm3")]
    SM3,

    #[cfg(feature = "streebog")]
    Streebog256,

    #[cfg(feature = "streebog")]
    Streebog512,

    #[cfg(feature = "tiger")]
    Tiger,

    #[cfg(feature = "tiger")]
    Tiger2,

    #[cfg(feature = "whirlpool")]
    Whirlpool,
}

impl Digest {
    /// Returns the digest algorithm name.
    ///
    /// This is used for both [`std::fmt::Display`] as well as
    /// [`clap::ValueEnum::to_possible_value`].
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            #[cfg(feature = "blake2")]
            Self::BLAKE2b512 => "BLAKE2b512",

            #[cfg(feature = "blake2")]
            Self::BLAKE2s256 => "BLAKE2s256",

            #[cfg(feature = "blake3")]
            Self::BLAKE3 => "BLAKE3",

            #[cfg(feature = "fsb")]
            Self::FSB160 => "FSB160",

            #[cfg(feature = "fsb")]
            Self::FSB224 => "FSB224",

            #[cfg(feature = "fsb")]
            Self::FSB256 => "FSB256",

            #[cfg(feature = "fsb")]
            Self::FSB384 => "FSB384",

            #[cfg(feature = "fsb")]
            Self::FSB512 => "FSB512",

            #[cfg(feature = "gost94")]
            Self::GOST94CryptoPro => "GOST94CryptoPro",

            #[cfg(feature = "gost94")]
            Self::GOST94UA => "GOST94UA",

            #[cfg(feature = "gost94")]
            Self::GOST94s2015 => "GOST94s2015",

            #[cfg(feature = "groestl")]
            Self::Groestl224 => "Groestl224",

            #[cfg(feature = "groestl")]
            Self::Groestl256 => "Groestl256",

            #[cfg(feature = "groestl")]
            Self::Groestl384 => "Groestl384",

            #[cfg(feature = "groestl")]
            Self::Groestl512 => "Groestl512",

            #[cfg(feature = "md2")]
            Self::MD2 => "MD2",

            #[cfg(feature = "md4")]
            Self::MD4 => "MD4",

            #[cfg(feature = "md5")]
            Self::MD5 => "MD5",

            #[cfg(feature = "ripemd")]
            Self::RIPEMD160 => "RIPEMD160",

            #[cfg(feature = "ripemd")]
            Self::RIPEMD256 => "RIPEMD256",

            #[cfg(feature = "ripemd")]
            Self::RIPEMD320 => "RIPEMD320",

            #[cfg(feature = "sha1")]
            Self::SHA1 => "SHA1",

            #[cfg(feature = "sha2")]
            Self::SHA224 => "SHA224",

            #[cfg(feature = "sha2")]
            Self::SHA256 => "SHA256",

            #[cfg(feature = "sha2")]
            Self::SHA384 => "SHA384",

            #[cfg(feature = "sha2")]
            Self::SHA512 => "SHA512",

            #[cfg(feature = "sha2")]
            Self::SHA512_224 => "SHA512/224",

            #[cfg(feature = "sha2")]
            Self::SHA512_256 => "SHA512/256",

            #[cfg(feature = "sha3")]
            Self::SHA3_224 => "SHA3-224",

            #[cfg(feature = "sha3")]
            Self::SHA3_256 => "SHA3-256",

            #[cfg(feature = "sha3")]
            Self::SHA3_384 => "SHA3-384",

            #[cfg(feature = "sha3")]
            Self::SHA3_512 => "SHA3-512",

            #[cfg(feature = "shabal")]
            Self::SHABAL192 => "Shabal-192",

            #[cfg(feature = "shabal")]
            Self::SHABAL224 => "Shabal-224",

            #[cfg(feature = "shabal")]
            Self::SHABAL256 => "Shabal-256",

            #[cfg(feature = "shabal")]
            Self::SHABAL384 => "Shabal-384",

            #[cfg(feature = "shabal")]
            Self::SHABAL512 => "Shabal-512",

            #[cfg(feature = "sm3")]
            Self::SM3 => "SM3",

            #[cfg(feature = "streebog")]
            Self::Streebog256 => "Streebog-256",

            #[cfg(feature = "streebog")]
            Self::Streebog512 => "Streebog-512",

            #[cfg(feature = "tiger")]
            Self::Tiger => "Tiger",

            #[cfg(feature = "tiger")]
            Self::Tiger2 => "Tiger2",

            #[cfg(feature = "whirlpool")]
            Self::Whirlpool => "Whirlpool",
        }
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl ValueEnum for Digest {
    fn value_variants<'a>() -> &'a [Self] {
        &[
            #[cfg(feature = "blake2")]
            Self::BLAKE2b512,
            #[cfg(feature = "blake2")]
            Self::BLAKE2s256,
            #[cfg(feature = "blake3")]
            Self::BLAKE3,
            #[cfg(feature = "fsb")]
            Self::FSB160,
            #[cfg(feature = "fsb")]
            Self::FSB224,
            #[cfg(feature = "fsb")]
            Self::FSB256,
            #[cfg(feature = "fsb")]
            Self::FSB384,
            #[cfg(feature = "fsb")]
            Self::FSB512,
            #[cfg(feature = "gost94")]
            Self::GOST94CryptoPro,
            #[cfg(feature = "gost94")]
            Self::GOST94UA,
            #[cfg(feature = "gost94")]
            Self::GOST94s2015,
            #[cfg(feature = "groestl")]
            Self::Groestl224,
            #[cfg(feature = "groestl")]
            Self::Groestl256,
            #[cfg(feature = "groestl")]
            Self::Groestl384,
            #[cfg(feature = "groestl")]
            Self::Groestl512,
            #[cfg(feature = "md2")]
            Self::MD2,
            #[cfg(feature = "md4")]
            Self::MD4,
            #[cfg(feature = "md5")]
            Self::MD5,
            #[cfg(feature = "ripemd")]
            Self::RIPEMD160,
            #[cfg(feature = "ripemd")]
            Self::RIPEMD256,
            #[cfg(feature = "ripemd")]
            Self::RIPEMD320,
            #[cfg(feature = "sha1")]
            Self::SHA1,
            #[cfg(feature = "sha2")]
            Self::SHA224,
            #[cfg(feature = "sha2")]
            Self::SHA256,
            #[cfg(feature = "sha2")]
            Self::SHA384,
            #[cfg(feature = "sha2")]
            Self::SHA512,
            #[cfg(feature = "sha2")]
            Self::SHA512_224,
            #[cfg(feature = "sha2")]
            Self::SHA512_256,
            #[cfg(feature = "sha3")]
            Self::SHA3_224,
            #[cfg(feature = "sha3")]
            Self::SHA3_256,
            #[cfg(feature = "sha3")]
            Self::SHA3_384,
            #[cfg(feature = "sha3")]
            Self::SHA3_512,
            #[cfg(feature = "shabal")]
            Self::SHABAL192,
            #[cfg(feature = "shabal")]
            Self::SHABAL224,
            #[cfg(feature = "shabal")]
            Self::SHABAL256,
            #[cfg(feature = "shabal")]
            Self::SHABAL384,
            #[cfg(feature = "shabal")]
            Self::SHABAL512,
            #[cfg(feature = "sm3")]
            Self::SM3,
            #[cfg(feature = "streebog")]
            Self::Streebog256,
            #[cfg(feature = "streebog")]
            Self::Streebog512,
            #[cfg(feature = "tiger")]
            Self::Tiger,
            #[cfg(feature = "tiger")]
            Self::Tiger2,
            #[cfg(feature = "whirlpool")]
            Self::Whirlpool,
        ]
    }

    fn to_possible_value(&self) -> Option<PossibleValue> {
        Some(PossibleValue::new(self.name()))
    }
}

impl From<Digest> for Box<dyn DynDigest> {
    fn from(digest: Digest) -> Self {
        match digest {
            #[cfg(feature = "blake2")]
            Digest::BLAKE2b512 => Box::<blake2::Blake2b512>::default(),

            #[cfg(feature = "blake2")]
            Digest::BLAKE2s256 => Box::<blake2::Blake2s256>::default(),

            #[cfg(feature = "blake3")]
            Digest::BLAKE3 => Box::<blake3::Hasher>::default(),

            #[cfg(feature = "fsb")]
            Digest::FSB160 => Box::<fsb::Fsb160>::default(),

            #[cfg(feature = "fsb")]
            Digest::FSB224 => Box::<fsb::Fsb224>::default(),

            #[cfg(feature = "fsb")]
            Digest::FSB256 => Box::<fsb::Fsb256>::default(),

            #[cfg(feature = "fsb")]
            Digest::FSB384 => Box::<fsb::Fsb384>::default(),

            #[cfg(feature = "fsb")]
            Digest::FSB512 => Box::<fsb::Fsb512>::default(),

            #[cfg(feature = "gost94")]
            Digest::GOST94CryptoPro => Box::<gost94::Gost94CryptoPro>::default(),

            #[cfg(feature = "gost94")]
            Digest::GOST94UA => Box::<gost94::Gost94UA>::default(),

            #[cfg(feature = "gost94")]
            Digest::GOST94s2015 => Box::<gost94::Gost94s2015>::default(),

            #[cfg(feature = "groestl")]
            Digest::Groestl224 => Box::<groestl::Groestl224>::default(),

            #[cfg(feature = "groestl")]
            Digest::Groestl256 => Box::<groestl::Groestl256>::default(),

            #[cfg(feature = "groestl")]
            Digest::Groestl384 => Box::<groestl::Groestl384>::default(),

            #[cfg(feature = "groestl")]
            Digest::Groestl512 => Box::<groestl::Groestl512>::default(),

            #[cfg(feature = "md2")]
            Digest::MD2 => Box::<md2::Md2>::default(),

            #[cfg(feature = "md4")]
            Digest::MD4 => Box::<md4::Md4>::default(),

            #[cfg(feature = "md5")]
            Digest::MD5 => Box::<md5::Md5>::default(),

            #[cfg(feature = "ripemd")]
            Digest::RIPEMD160 => Box::<ripemd::Ripemd160>::default(),

            #[cfg(feature = "ripemd")]
            Digest::RIPEMD256 => Box::<ripemd::Ripemd256>::default(),

            #[cfg(feature = "ripemd")]
            Digest::RIPEMD320 => Box::<ripemd::Ripemd320>::default(),

            #[cfg(feature = "sha1")]
            Digest::SHA1 => Box::<sha1::Sha1>::default(),

            #[cfg(feature = "sha2")]
            Digest::SHA224 => Box::<sha2::Sha224>::default(),

            #[cfg(feature = "sha2")]
            Digest::SHA256 => Box::<sha2::Sha256>::default(),

            #[cfg(feature = "sha2")]
            Digest::SHA384 => Box::<sha2::Sha384>::default(),

            #[cfg(feature = "sha2")]
            Digest::SHA512 => Box::<sha2::Sha512>::default(),

            #[cfg(feature = "sha2")]
            Digest::SHA512_224 => Box::<sha2::Sha512_224>::default(),

            #[cfg(feature = "sha2")]
            Digest::SHA512_256 => Box::<sha2::Sha512_256>::default(),

            #[cfg(feature = "sha3")]
            Digest::SHA3_224 => Box::<sha3::Sha3_224>::default(),

            #[cfg(feature = "sha3")]
            Digest::SHA3_256 => Box::<sha3::Sha3_256>::default(),

            #[cfg(feature = "sha3")]
            Digest::SHA3_384 => Box::<sha3::Sha3_384>::default(),

            #[cfg(feature = "sha3")]
            Digest::SHA3_512 => Box::<sha3::Sha3_512>::default(),

            #[cfg(feature = "shabal")]
            Digest::SHABAL192 => Box::<shabal::Shabal192>::default(),

            #[cfg(feature = "shabal")]
            Digest::SHABAL224 => Box::<shabal::Shabal224>::default(),

            #[cfg(feature = "shabal")]
            Digest::SHABAL256 => Box::<shabal::Shabal256>::default(),

            #[cfg(feature = "shabal")]
            Digest::SHABAL384 => Box::<shabal::Shabal384>::default(),

            #[cfg(feature = "shabal")]
            Digest::SHABAL512 => Box::<shabal::Shabal512>::default(),

            #[cfg(feature = "sm3")]
            Digest::SM3 => Box::<sm3::Sm3>::default(),

            #[cfg(feature = "streebog")]
            Digest::Streebog256 => Box::<streebog::Streebog256>::default(),

            #[cfg(feature = "streebog")]
            Digest::Streebog512 => Box::<streebog::Streebog512>::default(),

            #[cfg(feature = "tiger")]
            Digest::Tiger => Box::<tiger::Tiger>::default(),

            #[cfg(feature = "tiger")]
            Digest::Tiger2 => Box::<tiger::Tiger2>::default(),

            #[cfg(feature = "whirlpool")]
            Digest::Whirlpool => Box::<whirlpool::Whirlpool>::default(),
        }
    }
}

// ----------------------------------------------------------------------------
// tests
// ----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    const fn test_send() {
        const fn assert_send<T: Send>() {}
        assert_send::<Digest>();
    }

    #[test]
    const fn test_sync() {
        const fn assert_sync<T: Sync>() {}
        assert_sync::<Digest>();
    }
}
