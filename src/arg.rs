//! Contains ready-to-use [`clap::Arg`] implementations.
//!
//! # Examples
//!
//! ```
//! use clap::{Command, ValueEnum};
//! use clap_digest::{Digest, DynDigest};
//!
//! let cli = Command::new("myapp")
//!     .arg(clap_digest::arg::digest().required_unless_present("list-digests"))
//!     .arg(clap_digest::arg::list_digests());
//!
//! let args = cli.get_matches_from(["myapp", "--list-digests"]);
//!
//! if args.contains_id("list-digests") {
//!     for digest in Digest::value_variants() {
//!         println!("{digest}");
//!     }
//! } else {
//!     let digest = *args
//!         .get_one::<Digest>("digest")
//!         .expect("has default via clap");
//!
//!     todo!()
//! }
//! ```

use clap::builder::{Arg, EnumValueParser};

use crate::Digest;

/// Returns a ready-to-use [`clap::Arg`] to choose a supported digest
/// algorithm.
///
/// # Examples
///
/// ```
/// use clap::Command;
/// use clap_digest::Digest;
///
/// let cli = Command::new("myapp").arg(clap_digest::arg::digest());
/// let args = cli.get_matches_from(["myapp", "--digest", "MD5"]);
///
/// let digest = *args
///     .get_one::<Digest>("digest")
///     .unwrap();
///
/// assert_eq!(digest, Digest::MD5);
/// ```
#[must_use]
pub fn digest<'a>() -> Arg<'a> {
    Arg::new("digest")
        .short('d')
        .long("digest")
        .help("digest algorithm")
        .long_help(
            "Use this digest algorithm. These algorithms are optional \
             dependencies/features that may be chosen during compilation.",
        )
        .takes_value(true)
        .value_parser(EnumValueParser::<Digest>::new())
}

/// Returns a ready-to-use [`clap::Arg`] to list supported digest
/// algorithms.
///
/// # Examples
///
/// ```
/// use clap::Command;
///
/// let cli = Command::new("myapp").arg(clap_digest::arg::list_digests());
/// let args = cli.get_matches_from(["myapp", "--list-digests"]);
///
/// assert!(args.contains_id("list-digests"));
/// ```
#[must_use]
pub fn list_digests<'a>() -> Arg<'a> {
    Arg::new("list-digests")
        .long("list-digests")
        .help("list supported digest algorithms")
}

// ----------------------------------------------------------------------------
// tests
// ----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use clap::Command;

    #[test]
    fn list_digests() {
        let cli = Command::new("myapp").arg(crate::arg::list_digests());
        let args = cli.get_matches_from(["myapp", "--list-digests"]);
        assert!(args.contains_id("list-digests"));
    }
}
