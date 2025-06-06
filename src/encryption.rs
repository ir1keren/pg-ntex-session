//! Utilities for session encryption.
//! 
//! ## Package feature
//! 
//! * `StateEncryption`. A trait interfacing encryption-decryption on states/data saved in the DB
//! * `Simple`. A struct that implements ```StateEncryption```, based on [*simple_crypt*](https://docs.rs/simple_crypt/0.2.3/simple_crypt/index.html) crate.

use std::fmt::Display;

use simple_crypt::{decrypt, encrypt};

/// StateEncryption trait. An encryption/decryption struct must implement this trait.
/// 
/// Only has 2: ```encrypt``` and ```decrypt```
pub trait StateEncryption {
    fn encrypt(&self,plain_text:impl Display)->anyhow::Result<Vec<u8>>;
    fn decrypt(&self,encoded_text:impl AsRef<[u8]>)->anyhow::Result<String>;
}

/// Simple encryption and decryption, implements [*StateEncryption*](https://docs.rs/pg-ntex-session/0.1.0/encryption/trait.StateEncryption.html) trait
/// 
/// Based on [*simple_crypt*](https://docs.rs/simple_crypt/0.2.3/simple_crypt/index.html) crate.
#[derive(Debug,Clone)]
pub struct Simple(String);

impl Simple
{
/// Creates a new ```Simple``` instance, with 32 chars of password
/// 
    pub fn new(password:impl Display)->Self
    {
        Self(password.to_string())
    }
}

impl StateEncryption for Simple
{
/// Implements a decryption. Takes an encoded text (binary) as input.
/// Discouraged to use this manually, as [*PgNtexSession*](../struct.PgNtexSession.html) calls this internally
    fn decrypt(&self,encoded_text:impl AsRef<[u8]>)->anyhow::Result<String> {
        let plain=decrypt(encoded_text.as_ref(), self.0.as_bytes())?;
        Ok(String::from_utf8(plain)?)
    }

/// Implements an encryption. Takes an plain text as input.
/// Discouraged to use this manually, as [*PgNtexSession*](../struct.PgNtexSession.html) calls this internally
    fn encrypt(&self,plain_text:impl Display)->anyhow::Result<Vec<u8>> {
        let plain_text=plain_text.to_string();
        Ok(encrypt(plain_text.as_bytes(), self.0.as_bytes())?)
    }
}