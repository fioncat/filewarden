use std::io::{BufRead, BufReader, Lines, Read, Write};

use aes_gcm::aead::{Aead, Nonce, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Key, KeyInit};
use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD as B64Engine;
use base64::Engine;
use pbkdf2::pbkdf2_hmac_array;
use sha2::Sha256;

const READ_BUFFER_SIZE: usize = 4096;
const NONCE_LENGTH: usize = 12;
const PBKDF2_ROUNDS: u32 = 600_000;

pub struct AesEncryptor<R: Read, W: Write> {
    source: BufReader<R>,
    dest: W,
}

impl<R: Read, W: Write> AesEncryptor<R, W> {
    pub fn load(source: R, dest: W) -> Self {
        let reader = BufReader::new(source);
        Self {
            source: reader,
            dest,
        }
    }

    pub fn run(mut self, user: &str, key: [u8; 32]) -> Result<()> {
        let mut buffer = [0; READ_BUFFER_SIZE];
        let key = Key::<Aes256Gcm>::from_slice(&key);

        let cipher = Aes256Gcm::new(key);
        // Generate the nonce in aes-256-gcm.
        let mut rng = OsRng;
        let nonce = Aes256Gcm::generate_nonce(&mut rng);
        assert_eq!(nonce.len(), NONCE_LENGTH);

        // Write user into file
        self.write_data(user.as_bytes())?;

        // Write nonce into file
        let nonce_b64 = B64Engine.encode(nonce);
        self.write_data(&nonce_b64.into_bytes())?;

        loop {
            // Encrypts 4096 bytes of data from the source file at a time and writes it
            // as one line to the destination file.
            // The reason for encrypting in batches is to prevent the program from
            // consuming excessive memory by loading the entire source data into memory,
            // especially when the source file is large.
            match self.source.read(&mut buffer) {
                Ok(0) => break,
                Ok(bytes_read) => {
                    let data = &buffer[..bytes_read];
                    let encrypted = match cipher.encrypt(&nonce, data) {
                        Ok(data) => data,
                        Err(err) => bail!("use aes256gcm to encrypt data: {err}"),
                    };
                    let line = B64Engine.encode(encrypted);
                    self.write_data(&line.into_bytes())?;
                }
                Err(err) => return Err(err).context("read plain data"),
            }
        }

        Ok(())
    }

    fn write_data(&mut self, data: &[u8]) -> Result<()> {
        self.dest.write_all(data).context("write data to dest")?;
        self.dest.write(b"\n").context("write break to dest")?;
        self.dest.flush().context("flush dest")?;
        Ok(())
    }
}

pub struct AesDecryptor<R: Read, W: Write> {
    user: String,
    source: Lines<BufReader<R>>,
    dest: W,
}

impl<R: Read, W: Write> AesDecryptor<R, W> {
    pub fn load(source: R, dest: W) -> Result<Self> {
        let reader = BufReader::new(source);
        let mut lines = reader.lines();

        let user = Self::must_next_line(&mut lines)?;
        if user.is_empty() {
            bail!("invalid encrypted data, missing user");
        }

        Ok(Self {
            user,
            source: lines,
            dest,
        })
    }

    pub fn user(&self) -> &str {
        &self.user
    }

    pub fn run(mut self, key: [u8; 32]) -> Result<()> {
        let nonce = B64Engine
            .decode(Self::must_next_line(&mut self.source)?)
            .context("decode header as base64 string")?;
        if nonce.len() != NONCE_LENGTH {
            bail!("invalid nonce of the encrypted data");
        }

        let key = Key::<Aes256Gcm>::from_slice(&key);
        let cipher = Aes256Gcm::new(key);

        let nonce = Nonce::<Aes256Gcm>::from_slice(&nonce);

        for line in self.source {
            // During decryption, each line represents a batch, and each batch of data
            // is decrypted one at a time.
            let line = line.context("read content from file")?;
            let buffer = B64Engine
                .decode(line)
                .context("decode content as base64 string")?;
            let buffer: &[u8] = &buffer;
            let plain = match cipher.decrypt(nonce, buffer) {
                Ok(data) => data,
                Err(_) => bail!("decrypt failed, incorrect password or content"),
            };
            self.dest
                .write_all(&plain)
                .context("write buffer to dest")?;
            self.dest.flush().context("flush dest")?;
        }

        Ok(())
    }

    fn must_next_line(lines: &mut Lines<BufReader<R>>) -> Result<String> {
        match lines.next() {
            Some(line) => line.context("read from encrypted data"),
            None => bail!("unexpected end of the encrypted data, the content is too short"),
        }
    }
}

pub fn generate_key(user: &str, password: &str) -> [u8; 32] {
    pbkdf2_hmac_array::<Sha256, 32>(password.as_bytes(), user.as_bytes(), PBKDF2_ROUNDS)
}
