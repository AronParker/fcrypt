pub mod read;
pub mod write;

use std::io::{Seek, SeekFrom};
use std::{io, mem};

use argon2::{Algorithm, Argon2, Params, Version};
use bincode::config::{Configuration, Fixint, Limit, LittleEndian, SkipFixedArrayLength};
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::{Key, XChaCha20, XNonce};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
pub use read::CryptoReader;
use sha2::Sha256;
pub use write::CryptoWriter;
use zeroize::{Zeroize, ZeroizeOnDrop};

const TAG_LEN: usize = 32;
const SECRET_LEN: usize = 32;
const SALT_LEN: usize = 16;
const MAC_KEY_LEN: usize = 32;
const SYM_KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;

const CONFIG: Configuration<
    LittleEndian,
    Fixint,
    SkipFixedArrayLength,
    Limit<{ mem::size_of::<FileHeader>() }>,
> = bincode::config::standard()
    .with_little_endian()
    .with_fixed_int_encoding()
    .skip_fixed_array_length()
    .with_limit::<{ mem::size_of::<FileHeader>() }>();

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, bincode::Encode, bincode::Decode)]
pub struct Argon2dParams {
    pub memory: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for Argon2dParams {
    fn default() -> Self {
        Argon2dParams {
            memory: 64 * 1024,
            iterations: 2,
            parallelism: 2,
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Default, bincode::Encode, bincode::Decode)]
pub struct FileHeader {
    params: Argon2dParams,
    salt: [u8; SALT_LEN],
    dek_tag: [u8; TAG_LEN],
    encrypted_dek: [u8; SECRET_LEN],
    auth_tag: [u8; TAG_LEN],
}

impl FileHeader {
    pub fn new(pw: &[u8], params: &Argon2dParams) -> (Self, Secret) {
        let mut header = FileHeader::default();
        let dek = Secret::new();

        header.write_dek(&dek, pw, params);

        (header, dek)
    }

    pub fn read_dek(&self, pw: &[u8]) -> io::Result<Secret> {
        let secret = argon2d(pw, &self.salt, &self.params);
        let (mut hasher, mut cipher) = secret.into_hasher_and_cipher();

        hasher.update(&self.encrypted_dek);

        let expected: blake3::Hash = self.dek_tag.into();
        let actual = hasher.finalize();

        if expected != actual {
            return Err(io::ErrorKind::InvalidData.into());
        }

        let mut dek = Secret::default();

        cipher
            .apply_keystream_b2b(&self.encrypted_dek, &mut dek.0)
            .unwrap();

        Ok(dek)
    }

    pub fn write_dek(&mut self, dek: &Secret, pw: &[u8], params: &Argon2dParams) {
        OsRng.fill_bytes(&mut self.salt);

        let secret = argon2d(pw, &self.salt, params);
        let (mut hasher, mut cipher) = secret.into_hasher_and_cipher();

        cipher
            .apply_keystream_b2b(&dek.0, &mut self.encrypted_dek)
            .unwrap();

        hasher.update(&self.encrypted_dek);
        self.dek_tag = hasher.finalize().into();
    }

    pub fn change_password(
        &mut self,
        old_pw: &[u8],
        new_pw: &[u8],
        params: &Argon2dParams,
    ) -> io::Result<()> {
        let dek = self.read_dek(old_pw)?;
        self.write_dek(&dek, new_pw, params);

        Ok(())
    }
}

#[derive(Default, ZeroizeOnDrop)]
pub struct Secret([u8; SECRET_LEN]);

impl Secret {
    pub fn new() -> Self {
        let mut dek = [0; SECRET_LEN];
        OsRng.fill_bytes(&mut dek);
        Self(dek)
    }

    pub fn into_hasher_and_cipher(self) -> (blake3::Hasher, XChaCha20) {
        let hkdf = Hkdf::<Sha256>::from_prk(&self.0).unwrap();

        let hash = {
            let mut mac_key = [0; MAC_KEY_LEN];
            hkdf.expand(b"mac_key", &mut mac_key).unwrap();

            let hash = blake3::Hasher::new_keyed(&mac_key);
            mac_key.zeroize();

            hash
        };

        let cipher = {
            let mut sym_key = [0; SYM_KEY_LEN];
            let mut nonce = [0; NONCE_LEN];

            hkdf.expand(b"sym_key", &mut sym_key).unwrap();
            hkdf.expand(b"nonce", &mut nonce).unwrap();

            let cipher = XChaCha20::new(Key::from_slice(&sym_key), XNonce::from_slice(&nonce));

            sym_key.zeroize();
            nonce.zeroize();

            cipher
        };

        (hash, cipher)
    }
}

pub fn change_password<F, POld, PNew>(
    file: &mut F,
    old_pw: POld,
    new_pw: PNew,
    params: &Argon2dParams,
) -> io::Result<()>
where
    F: io::Read + io::Write + Seek,
    POld: AsRef<[u8]>,
    PNew: AsRef<[u8]>,
{
    _change_password(file, old_pw.as_ref(), new_pw.as_ref(), params)
}

pub fn _change_password<F>(
    mut file: &mut F,
    old_pw: &[u8],
    new_pw: &[u8],
    params: &Argon2dParams,
) -> io::Result<()>
where
    F: io::Read + io::Write + Seek,
{
    let pos = file.stream_position()?;
    let mut header: FileHeader = bincode::decode_from_std_read(&mut file, CONFIG)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    header.change_password(old_pw, new_pw, params)?;
    file.seek(SeekFrom::Start(pos))?;

    bincode::encode_into_std_write(&header, &mut file, CONFIG)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    Ok(())
}

pub fn benchmark_argon2d(params: &Argon2dParams) -> io::Result<usize> {
    let argon2 = Argon2::new(
        Algorithm::Argon2d,
        Version::V0x13,
        Params::new(params.memory, params.iterations, params.parallelism, None)
            .expect("invalid parameters"),
    );

    let mut output = [0; SECRET_LEN];

    argon2
        .hash_password_into(&[], &[0; SALT_LEN], &mut output)
        .expect("failed to hash password.");

    Ok(output.iter().position(|x| *x == 0).unwrap_or(0))
}

fn argon2d(pw: &[u8], salt: &[u8], params: &Argon2dParams) -> Secret {
    let argon2 = Argon2::new(
        Algorithm::Argon2d,
        Version::V0x13,
        Params::new(params.memory, params.iterations, params.parallelism, None)
            .expect("invalid parameters"),
    );

    let mut dek = Secret::default();

    argon2
        .hash_password_into(pw, salt, &mut dek.0)
        .expect("failed to hash password.");

    dek
}
