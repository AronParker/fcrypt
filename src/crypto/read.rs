use std::io::{Read, Seek, SeekFrom, Write};
use std::{fmt, io};

use chacha20::cipher::StreamCipher;
use chacha20::XChaCha20;

use crate::crypto::{FileHeader, CONFIG};

pub struct CryptoReader<R: Read + Seek> {
    inner: R,
    cipher: XChaCha20,
}

impl<R: Read + Seek> CryptoReader<R> {
    pub fn new<P: AsRef<[u8]>>(inner: R, pw: P) -> io::Result<Self> {
        Self::create(inner, pw.as_ref())
    }

    fn create(mut inner: R, pw: &[u8]) -> io::Result<Self> {
        let header: FileHeader = bincode::decode_from_std_read(&mut inner, CONFIG)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        let (hasher, cipher) = header.read_dek(pw)?.into_hasher_and_cipher();

        {
            struct WriteHasher(blake3::Hasher);

            impl Write for WriteHasher {
                fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                    self.0.update(buf);
                    Ok(buf.len())
                }

                fn flush(&mut self) -> io::Result<()> {
                    Ok(())
                }
            }

            let mut write_hasher = WriteHasher(hasher);
            let pos = inner.stream_position()?;
            io::copy(&mut inner, &mut write_hasher)?;

            let expected: blake3::Hash = header.auth_tag.into();
            let actual = write_hasher.0.finalize();

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
