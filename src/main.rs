pub mod crypto;

use std::fs::{File, OpenOptions};
use std::io::Write;
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
    ChangePw(ChangePw),
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

/// Change password of a file
#[derive(Args, Debug)]
#[clap(alias = "c")]
struct ChangePw {
    /// The file to encrypt
    #[clap(parse(from_os_str))]
    file: PathBuf,

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

/// Decrypt a file
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

fn prompt_password(prompt: &str) -> io::Result<String> {
    rpassword::prompt_password(prompt).or_else(|_| {
        let mut s = String::new();
        io::stdout().write_all(prompt.as_bytes())?;
        io::stdout().flush()?;
        io::stdin().read_line(&mut s)?;

        if s.ends_with('\n') {
            s.pop();
        }

        if s.ends_with('\r') {
            s.pop();
        }

        Ok(s)
    })
}

fn encrypt(enc: &Encrypt) -> io::Result<u64> {
    let mut input = File::open(&enc.src_file)?;
    let len = input.metadata()?.len();

    let pw = prompt_password("Password: ").unwrap();
    let pw2 = prompt_password("Retype password: ").unwrap();

    if pw != pw2 {
        eprintln!("Password mismatch.");
        std::process::exit(1);
    }

    let params = Argon2dParams {
        memory: enc.memory * 1024,
        iterations: enc.iterations,
        parallelism: enc.parallelism,
    };

    let output = File::create(&enc.dst_file)?;
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
    let pw = prompt_password("Password: ").unwrap();

    let input = File::open(&dec.src_file)?;
    let len = input.metadata()?.len() - mem::size_of::<FileHeader>() as u64;
    let mut input = CryptoReader::new(input, pw)?;
    let mut output = File::create(&dec.dst_file)?;

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

fn change_pw(ch: &ChangePw) -> io::Result<()> {
    let old_pw = prompt_password("Old password: ").unwrap();

    let pw = prompt_password("New password: ").unwrap();
    let pw2 = prompt_password("Retype new password: ").unwrap();

    if pw != pw2 {
        eprintln!("Password mismatch.");
        std::process::exit(1);
    }

    let params = Argon2dParams {
        memory: ch.memory * 1024,
        iterations: ch.iterations,
        parallelism: ch.parallelism,
    };

    let mut file = OpenOptions::new().read(true).write(true).open(&ch.file)?;

    crypto::change_password(&mut file, old_pw, pw, &params)
}

fn main() {
    let cli = Cli::parse();

    match &cli {
        Cli::Encrypt(enc) => match encrypt(enc) {
            Ok(_) => {
                println!("Encryption successful.");
            }
            Err(err) => {
                eprintln!("An error occurred during encryption: {err}");
                std::process::exit(1);
            }
        },
        Cli::Decrypt(dec) => match decrypt(dec) {
            Ok(_) => {
                println!("Decryption successful.");
            }
            Err(err) => {
                eprintln!("An error occurred during decryption: {err}");
                std::process::exit(1);
            }
        },
        Cli::ChangePw(ch) => match change_pw(ch) {
            Ok(_) => {
                println!("Password changed successfully.");
            }
            Err(err) => {
                eprintln!("An error occurred during password change: {err}");
                std::process::exit(1);
            }
        },
    }
}
