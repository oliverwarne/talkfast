extern crate ring;
#[macro_use] extern crate diesel;
#[macro_use] extern crate diesel_codegen;
extern crate dotenv;
#[macro_use] extern crate text_io;

use ring::aead::*;
use ring::pbkdf2::*;
use ring::rand::SystemRandom;

mod encrypt;
mod db;
mod schema;
mod models;

use encrypt::*;

fn main() {
    
    
    let message  = "yeahalright".to_owned().into_bytes();
    let password = "knobby".to_owned().into_bytes();
    let salt     = "wot".to_owned().into_bytes();
    let verified = "karl".to_owned().into_bytes();

    let nonce: Vec<u8> = vec![0;12];

    let mut key: [u8; 32] = [0; 32] ;
    derive(&HMAC_SHA256, 100, &salt, &password[..], &mut key);

    let encrypt = EncryptionData {
                    message : message,
                    key     : key,
                    verified: verified,
                    nonce   : nonce,
    };
    test_io(encrypt);

}

