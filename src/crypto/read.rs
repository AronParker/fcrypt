use std::io::{Read, Seek, SeekFrom};
use std::{fmt, io};

use chacha20::cipher::StreamCipher;
use chacha20::XChaCha20;

use crate::crypto::{argon2d, expand, FileHeader, Secret, CONFIG};

pub struct CryptoReader<R: Read + Seek> {
    inner: R,
    cipher: XChaCha20,
}

impl<R: Read + Seek> CryptoReader<R> {
    pub fn new<P: AsRef<[u8]>>(inner: R, pw: P, buf_size: usize) -> io::Result<Self> {
        Self::create(inner, pw.as_ref(), buf_size)
    }

    fn create(mut inner: R, pw: &[u8], buf_size: usize) -> io::Result<Self> {
        assert_ne!(buf_size, 0);

        let mut header: FileHeader = bincode::decode_from_std_read(&mut inner, CONFIG)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        let (mut hasher, cipher) = {
            let secret = argon2d(pw, &header.params);
            let (mut hasher, mut cipher) = expand(&secret);

            hasher.update(&header.encrypted_dek);

            let expected: blake3::Hash = header.dek_tag.into();
            let actual = hasher.finalize();

            if expected != actual {
                return Err(io::ErrorKind::InvalidData.into());
            }

            let mut dek = Secret::default();
            cipher
                .apply_keystream_b2b(&header.encrypted_dek, &mut dek.0)
                .expect("end of keystream reached");

            expand(&dek)
        };

        let mut buf = vec![0; buf_size];

        {
            let pos = inner.stream_position()?;

            while let Ok(read) = inner.read(&mut buf) {
                if read == 0 {
                    break;
                }

                hasher.update(&buf[..read]);
            }

            let expected: blake3::Hash = header.auth_tag.into();
            let actual = hasher.finalize();

            if expected != actual {
                return Err(io::ErrorKind::InvalidData.into());
            }

            inner.seek(SeekFrom::Start(pos))?;
        }

        Ok(Self { inner, cipher })
    }

    pub fn get_ref(&self) -> &R {
        &self.inner
    }

    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read + Seek> Read for CryptoReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(buf)?;

        self.cipher.apply_keystream(&mut buf[..read]);

        Ok(read)
    }
}

impl<R: Read + Seek + fmt::Debug> fmt::Debug for CryptoReader<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CryptoReader")
            .field("inner", &self.inner)
            .finish_non_exhaustive()
    }
}
