mod crypto;

use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

use clap::{Args, Parser};

use crate::crypto::{Argon2dParams, CryptoReader, CryptoWriter};

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
#[clap(subcommand_required = true)]
#[clap(next_line_help = true)]
#[clap(propagate_version = true)]
#[clap(help_expected = true)]
enum Cli {
    Encrypt(Encrypt),
    Decrypt(Decrypt),
}

/// Encrypts a file
#[derive(Args, Debug)]
#[clap(alias = "e")]
struct Encrypt {
    /// The file to encrypt
    #[clap(parse(from_os_str))]
    src_file: PathBuf,

    /// The encrypted file
    #[clap(parse(from_os_str))]
    dst_file: PathBuf,

    /// The amount of memory to use for Argon2d (in MiB's)
    #[clap(short, long, parse(try_from_str), default_value_t = 16)]
    memory: u32,

    /// The number of iterations to use for Argon2d
    #[clap(short, long, parse(try_from_str), default_value_t = 2)]
    iterations: u32,

    /// The degree of parallelism to use for Argon2d
    #[clap(short, long, parse(try_from_str), default_value_t = 2)]
    parallelism: u32,
}

/// Decompress minecraft world.
#[derive(Args, Debug)]
#[clap(alias = "d")]
struct Decrypt {
    /// The file to decrypt
    #[clap(parse(from_os_str))]
    src_file: PathBuf,

    /// The decrypted file
    #[clap(parse(from_os_str))]
    dst_file: PathBuf,
}

fn main() {
    let mut test = CryptoWriter::new(
        Cursor::new(Vec::new()),
        "test",
        &Argon2dParams::default(),
        4096,
    )
    .unwrap();

    test.write_all(b"hello").unwrap();

    let mut data = test.into_inner().unwrap();
    data.seek(SeekFrom::Start(0)).unwrap();

    let mut test = CryptoReader::new(data, "test", 4096).unwrap();
    let mut vec = Vec::new();

    test.read_to_end(&mut vec).unwrap();

    println!("{}", vec.escape_ascii());

    // let cli = Cli::parse();
    //
    // match &cli {
    //     Cli::Encrypt(encrypt) => {
    //         println!("Hello, world!");
    //     }
    //     Cli::Decrypt(decrypt) => {
    //
    //     }
    // }
}
