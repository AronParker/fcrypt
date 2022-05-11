use std::error::Error;
use std::io::{Seek, SeekFrom, Write};
use std::{fmt, io, mem, ptr};

use chacha20::cipher::StreamCipher;
use chacha20::XChaCha20;

use crate::crypto::{Argon2dParams, FileHeader, CONFIG};

pub struct CryptoWriter<W: Write + Seek> {
    header: FileHeader,
    inner: W,
    data_off: u64,
    hasher: blake3::Hasher,
    cipher: XChaCha20,
    buf: Vec<u8>,
    panicked: bool,
}

impl<W: Write + Seek> CryptoWriter<W> {
    pub fn new<P: AsRef<[u8]>>(
        inner: W,
        pw: P,
        params: &Argon2dParams,
        buf_size: usize,
    ) -> io::Result<Self> {
        Self::create(inner, pw.as_ref(), params, buf_size)
    }

    fn create(
        mut inner: W,
        pw: &[u8],
        params: &Argon2dParams,
        buf_size: usize,
    ) -> io::Result<Self> {
        assert_ne!(buf_size, 0);

        let (header, dek) = FileHeader::new(pw, params);
        let (hasher, cipher) = dek.into_hasher_and_cipher();

        let data_off = inner.seek(SeekFrom::Current(mem::size_of::<FileHeader>() as i64))?;

        Ok(Self {
            header,
            inner,
            data_off,
            hasher,
            cipher,
            buf: vec![0; buf_size],
            panicked: false,
        })
    }

    pub fn get_ref(&self) -> &W {
        &self.inner
    }

    pub fn get_mut(&mut self) -> &mut W {
        &mut self.inner
    }

    pub fn into_inner(mut self) -> Result<W, IntoInnerError<Self>> {
        match self.finish() {
            Err(e) => Err(IntoInnerError::new(self, e)),
            Ok(()) => Ok(self.into_parts().0),
        }
    }

    pub fn into_parts(self) -> (W, Result<Vec<u8>, WriterPanicked>) {
        let buf = bincode::encode_to_vec(&self.header, CONFIG).unwrap();
        let buf = if !self.panicked {
            Ok(buf)
        } else {
            Err(WriterPanicked { buf })
        };

        let inner = unsafe { ptr::read(&self.inner) };
        mem::forget(self);

        (inner, buf)
    }

    fn finish(&mut self) -> io::Result<()> {
        self.inner.seek(SeekFrom::Start(
            self.data_off - mem::size_of::<FileHeader>() as u64,
        ))?;

        self.header.auth_tag = self.hasher.finalize().into();

        bincode::encode_into_std_write(&self.header, &mut self.inner, CONFIG)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        Ok(())
    }
}

impl<W: Write + Seek> Write for CryptoWriter<W> {
    fn write(&mut self, mut buf: &[u8]) -> io::Result<usize> {
        if buf.len() > self.buf.len() {
            buf = &buf[..self.buf.len()];
        }

        self.panicked = true;
        self.cipher
            .apply_keystream_b2b(buf, &mut self.buf[..buf.len()])
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "end of keystream reached"))?;
        self.hasher.update(&self.buf[..buf.len()]);
        let r = self.inner.write_all(&self.buf[..buf.len()]);
        self.panicked = false;

        r?;

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<W: Write + Seek> Drop for CryptoWriter<W> {
    fn drop(&mut self) {
        if !self.panicked {
            let _ = self.finish();
        }
    }
}

impl<W: Write + Seek + fmt::Debug> fmt::Debug for CryptoWriter<W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CryptoWriter")
            .field("header", &self.header)
            .field("inner", &self.inner)
            .field("data_off", &self.data_off)
            .field("buf", &self.buf)
            .field("panicked", &self.panicked)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub struct IntoInnerError<W>(W, io::Error);

impl<W> IntoInnerError<W> {
    fn new(writer: W, error: io::Error) -> Self {
        Self(writer, error)
    }

    pub fn error(&self) -> &io::Error {
        &self.1
    }

    pub fn into_inner(self) -> W {
        self.0
    }

    pub fn into_error(self) -> io::Error {
        self.1
    }

    pub fn into_parts(self) -> (io::Error, W) {
        (self.1, self.0)
    }
}

impl<W> From<IntoInnerError<W>> for io::Error {
    fn from(iie: IntoInnerError<W>) -> Self {
        iie.1
    }
}

impl<W> fmt::Display for IntoInnerError<W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        fmt::Display::fmt(&self.1, f)
    }
}

impl<W: Send + fmt::Debug> Error for IntoInnerError<W> {}

pub struct WriterPanicked {
    buf: Vec<u8>,
}

impl WriterPanicked {
    pub fn into_inner(self) -> Vec<u8> {
        self.buf
    }
}

impl Error for WriterPanicked {}

impl fmt::Display for WriterPanicked {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ArchiveWriter inner writer panicked, what data remains unwritten is not known")
    }
}

impl fmt::Debug for WriterPanicked {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WriterPanicked")
            .field(
                "buffer",
                &format_args!("{}/{}", self.buf.len(), self.buf.capacity()),
            )
            .finish()
    }
}
