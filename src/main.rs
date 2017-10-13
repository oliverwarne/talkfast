extern crate ring;
#[macro_use] extern crate text_io;

use ring::aead::*;
use ring::pbkdf2::*;
use ring::rand::SystemRandom;

#[derive(Debug, Clone)]
struct DecryptionData {
    encrypted: Vec<u8>, // The encrypted data
    verified : Vec<u8>, // verified message (username of receiver)
    nonce    : Vec<u8>,
    key      : [u8; 32],
}

#[derive(Debug, Clone)]
struct EncryptionData {
    /*
     * This is the data to be passed to the encryption algorithm
     */
    message : Vec<u8>,     // obviously, the unencrypted message
    salt    : Vec<u8>,     // the salt...
    key     : [u8; 32], // the key used to encrypt, based on pass and salt
    password: Vec<u8>,     // password to be used on both sides 
    verified: Vec<u8>,     // the verified message (prolly username)
    nonce   : Vec<u8>,     // the little bit of random data
}

struct message {
    message: String,
    time:    f32,
}

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
                    salt    : salt,
                    key     : key,
                    password: password,
                    verified: verified,
                    nonce   : nonce,
    };
    test_io(encrypt);

}

fn wmain() {

    /* 
     * This block prepares the message to be encrypted. 
     */

    println!("Enter message to be encrypted");
    
    let mut message = String::new();
    message = read!();

    let to_encrypt: Vec<u8> = message.into_bytes();
    
    /*
     * This block prepares the salt to be used
     */

    println!("Enter username of the encrypting person");

    let mut username = String::new();
    username = read!();

    let salt = username.into_bytes();

    /*
     * This block prepares the password to be used in encrypting
     */

    println!("Enter the password to be used");

    let mut raw_password = String::new();
    raw_password = read!();

    let password = raw_password.into_bytes();

    
    let mut key: [u8; 32] = [0; 32] ;
    derive(&HMAC_SHA256, 100, &salt, &password[..], &mut key);


    println!("Enter the username of recipient");

    /*
     * This block prepares the verified message that is in plaintext/clear.
     * Should be the username of the recipient
     */

    let mut recip = String::new();
    recip = read!();

    let verified = recip.into_bytes();

    // Create a copy of the input, because ring will overwrite it with encrypted data
    let mut in_out = to_encrypt.clone();

    println!("Tag len {}", CHACHA20_POLY1305.tag_len());
    for _ in 0..CHACHA20_POLY1305.tag_len() {
        in_out.push(0);
    }

    let opening_key = OpeningKey::new(&CHACHA20_POLY1305, &key).unwrap();

    let sealing_key = SealingKey::new(&CHACHA20_POLY1305, &key).unwrap();


    // the idea of a nonce is really fucking with me. how is the client supposed
    // to know the nonce? maybe i'll just make it an array of 0's and cry 🙈
    let mut nonce = vec![0; 12];

    let output_size = seal_in_place(&sealing_key, &nonce, &verified, 
                                    &mut in_out, CHACHA20_POLY1305.tag_len())
                                    .unwrap();

    println!("Encrypted data's size {}", output_size);

    let decrypted_data = open_in_place(&opening_key, &nonce, &verified,
                                       0, &mut in_out).unwrap();

    println!("{:?}", String::from_utf8(decrypted_data.to_vec()).unwrap());

    assert_eq!(to_encrypt, decrypted_data);

}

fn prompt_user() -> EncryptionData {

    /* 
     * This block prepares the message to be encrypted. 
     */

    println!("Enter message to be encrypted");
    
    let mut message = String::new();
    message = read!();

    let to_encrypt: Vec<u8> = message.into_bytes();
    
    /*
     * This block prepares the salt to be used
     */

    println!("Enter username of the encrypting person");

    let mut username = String::new();
    username = read!();

    let salt = username.into_bytes();

    /*
     * This block prepares the password to be used in encrypting
     */

    println!("Enter the password to be used");

    let mut raw_password = String::new();
    raw_password = read!();

    let password = raw_password.into_bytes();

    
    let mut key: [u8; 32] = [0; 32] ;
    derive(&HMAC_SHA256, 100, &salt, &password[..], &mut key);


    println!("Enter the username of recipient");

    /*
     * This block prepares the verified message that is in plaintext/clear.
     * Should be the username of the recipient
     */

    let mut recip = String::new();
    recip = read!();

    let verified = recip.into_bytes();

    let nonce: Vec<u8> = vec![0; 5]; // Yeah... i know... TODO

    let data = EncryptionData { message: to_encrypt, 
                                salt: salt, 
                                key: key, 
                                password: password, 
                                verified: verified, 
                                nonce: nonce };

    return data;
}


fn encrypt(data: EncryptionData) -> Vec<u8> {

    let mut in_out: Vec<u8> = data.message.clone();

    let nonce = vec![0; 12];
    let verified: Vec<u8> = "oy".to_owned().into_bytes();

    // this adds a bit of extra 0's onto the input... not 100% sure why
    
    for _ in 0..CHACHA20_POLY1305.tag_len() {
        in_out.push(0);
    }
    println!("sela_key");
    let sealing_key = SealingKey::new(&CHACHA20_POLY1305, &data.key).unwrap();
println!("encrypt");
    let encrypted_size  = seal_in_place(&sealing_key, &data.nonce, &data.verified, 
                                  &mut in_out, CHACHA20_POLY1305.tag_len()).unwrap();

    return in_out;

}

fn decrypt(data: DecryptionData) -> Vec<u8> {
println!("encrypt_key");
    let opening_key = OpeningKey::new(&CHACHA20_POLY1305, &data.key).unwrap();
    let mut in_out = data.encrypted.clone();
println!("decrypt");
    let decrypted_data = open_in_place(&opening_key, &data.nonce, &data.verified, 0, 
                                       &mut in_out).unwrap();

    return decrypted_data.to_vec();

}


fn test_io(data: EncryptionData) {
    let encrypted = encrypt(data.clone());
    let decrypt_data = DecryptionData {
                        encrypted: encrypted,
                        verified : data.verified,
                        nonce    : data.nonce,
                        key      : data.key,
    };
    let decrypted = decrypt(decrypt_data);

    assert_eq!(data.message, decrypted);
    println!("issa equal");
}
