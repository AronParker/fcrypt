pub mod crypto;

use std::fs::File;
use std::path::PathBuf;
use std::{io, mem};

use clap::{Args, Parser};
use indicatif::{ProgressBar, ProgressStyle};

use crate::crypto::{Argon2dParams, CryptoReader, CryptoWriter, FileHeader};

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
    #[clap(short, long, parse(try_from_str), default_value_t = 64)]
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

const PB_TEMPLATE: &str = "{spinner:.green} [{elapsed_precise}] {msg} [{wide_bar}] \
                           {bytes}/{total_bytes} ({bytes_per_sec}, {eta})";

fn encrypt(enc: &Encrypt) -> io::Result<u64> {
    let mut input = File::open(&enc.src_file)?;
    let output = File::create(&enc.dst_file)?;
    let len = input.metadata()?.len();

    let pw = rpassword::prompt_password("Password: ").unwrap();
    let pw2 = rpassword::prompt_password("Retype password: ").unwrap();

    if pw != pw2 {
        eprintln!("Password mismatch.");
        std::process::exit(1);
    }

    let params = Argon2dParams {
        memory: enc.memory * 1024,
        iterations: enc.iterations,
        parallelism: enc.parallelism,
    };

    let mut output = CryptoWriter::new(output, pw, &params, 8192)?;
    let pb = ProgressBar::new(len)
        .with_message("Encrypting")
        .with_style(ProgressStyle::with_template(PB_TEMPLATE).unwrap());

    let r = io::copy(&mut pb.wrap_read(&mut input), &mut output);

    match &r {
        Ok(_) => pb.finish_with_message("Done"),
        Err(_) => pb.abandon_with_message("Error"),
    };

    r
}

fn decrypt(dec: &Decrypt) -> io::Result<u64> {
    let input = File::open(&dec.src_file)?;
    let mut output = File::create(&dec.dst_file)?;
    let len = input.metadata()?.len() - mem::size_of::<FileHeader>() as u64;

    let pw = rpassword::prompt_password("Password: ").unwrap();

    let mut input = CryptoReader::new(input, pw)?;
    let pb = ProgressBar::new(len)
        .with_message("Decrypting")
        .with_style(ProgressStyle::with_template(PB_TEMPLATE).unwrap());

    let r = io::copy(&mut pb.wrap_read(&mut input), &mut output);

    match &r {
        Ok(_) => pb.finish_with_message("Done"),
        Err(_) => pb.abandon_with_message("Error"),
    };

    r
}

fn main() {
    let cli = Cli::parse();

    match &cli {
        Cli::Encrypt(enc) => match encrypt(enc) {
            Ok(_) => {
                println!("Encryption successful.");
            }
            Err(err) => {
                eprintln!("An error occurred: {err}");
                std::process::exit(1);
            }
        },
        Cli::Decrypt(dec) => match decrypt(dec) {
            Ok(_) => {
                println!("Decryption successful.");
            }
            Err(err) => {
                eprintln!("An error occured: {err}");
                std::process::exit(1);
            }
        },
    }
}
