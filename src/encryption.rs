use std::fmt::Display;

use simple_crypt::{decrypt, encrypt};

pub trait StateEncryption {
    fn encrypt(&self,plain_text:impl Display)->anyhow::Result<Vec<u8>>;
    fn decrypt(&self,encoded_text:impl AsRef<[u8]>)->anyhow::Result<String>;
}

#[derive(Debug,Clone)]
pub struct Simple(String);

impl Simple
{
    pub fn new(password:impl Display)->Self
    {
        Self(password.to_string())
    }
}

impl StateEncryption for Simple
{
    fn decrypt(&self,encoded_text:impl AsRef<[u8]>)->anyhow::Result<String> {
        let plain=decrypt(encoded_text.as_ref(), self.0.as_bytes())?;
        Ok(String::from_utf8(plain)?)
    }

    fn encrypt(&self,plain_text:impl Display)->anyhow::Result<Vec<u8>> {
        let plain_text=plain_text.to_string();
        Ok(encrypt(plain_text.as_bytes(), self.0.as_bytes())?)
    }
}