pub mod read;
pub mod write;

use std::{io, mem};

use argon2::Algorithm::Argon2d;
use argon2::{Algorithm, Argon2, Params, Version};
use bincode::config::{
    Config, Configuration, Fixint, Limit, LittleEndian, SkipFixedArrayLength, WriteFixedArrayLength,
};
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::{Key, XChaCha20, XNonce};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
pub use read::CryptoReader;
use sha2::Sha256;
pub use write::CryptoWriter;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, bincode::Encode, bincode::Decode)]
pub struct Argon2dParams {
    memory: u32,
    iterations: u32,
    parallelism: u32,
    salt: [u8; SALT_LEN],
}

impl Default for Argon2dParams {
    fn default() -> Self {
        let mut salt = [0; SALT_LEN];
        OsRng.fill_bytes(&mut salt);

        // TODO change
        Argon2dParams {
            memory: 64 * 1024,
            iterations: 2,
            parallelism: 2,
            salt,
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Default, bincode::Encode, bincode::Decode)]
pub struct FileHeader {
    params: Argon2dParams,
    dek_tag: [u8; TAG_LEN],
    encrypted_dek: [u8; SECRET_LEN],
    auth_tag: [u8; TAG_LEN],
}

impl FileHeader {
    pub fn change_password(
        &mut self,
        old_pw: &[u8],
        new_pw: &[u8],
        params: &Argon2dParams,
    ) -> io::Result<()> {
        let dek = {
            let secret = argon2d(old_pw, &self.params);
            let (mut hasher, mut cipher) = expand(&secret);

            hasher.update(&self.encrypted_dek);

            let expected: blake3::Hash = self.dek_tag.into();
            let actual = hasher.finalize();

            if expected != actual {
                return Err(io::ErrorKind::InvalidData.into());
            }

            let mut dek = Secret::default();
            cipher
                .apply_keystream_b2b(&self.encrypted_dek, &mut dek.0)
                .expect("end of keystream reached");

            dek
        };

        {
            let secret = argon2d(new_pw, params);
            let (mut hasher, mut cipher) = expand(&secret);

            cipher
                .apply_keystream_b2b(&dek.0, &mut self.encrypted_dek)
                .expect("end of keystream reached");

            hasher.update(&self.encrypted_dek);
            self.dek_tag = hasher.finalize().into();
        }

        Ok(())
    }
}

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

#[derive(Default, ZeroizeOnDrop)]
struct Secret([u8; SECRET_LEN]);

impl Secret {
    pub fn new() -> Self {
        let mut dek = [0; SECRET_LEN];
        OsRng.fill_bytes(&mut dek);
        Self(dek)
    }
}

#[derive(ZeroizeOnDrop)]
struct Okm([u8; MAC_KEY_LEN + SYM_KEY_LEN + NONCE_LEN]);

impl Default for Okm {
    fn default() -> Self {
        Self([0; MAC_KEY_LEN + SYM_KEY_LEN + NONCE_LEN])
    }
}

fn argon2d(pw: &[u8], params: &Argon2dParams) -> Secret {
    let argon2 = Argon2::new(
        Algorithm::Argon2d,
        Version::V0x13,
        Params::new(params.memory, params.iterations, params.parallelism, None)
            .expect("invalid parameters"),
    );

    let mut dek = Secret::default();

    argon2
        .hash_password_into(pw, &params.salt, &mut dek.0)
        .expect("failed to hash password.");

    dek
}

fn expand(secret: &Secret) -> (blake3::Hasher, XChaCha20) {
    let hkdf = Hkdf::<Sha256>::from_prk(&secret.0).unwrap();

    let mut okm = Okm::default();
    hkdf.expand(b"fcrypt", &mut okm.0).unwrap();

    let remaining = okm.0.as_slice();
    let (mac_key, remaining) = remaining.split_at(MAC_KEY_LEN);
    let (sym_key, remaining) = remaining.split_at(SYM_KEY_LEN);
    let (nonce, remaining) = remaining.split_at(NONCE_LEN);
    assert!(remaining.is_empty());

    let hash = blake3::Hasher::new_keyed(mac_key.try_into().unwrap());
    let chacha20: XChaCha20 = XChaCha20::new(Key::from_slice(sym_key), XNonce::from_slice(nonce));

    (hash, chacha20)
}
