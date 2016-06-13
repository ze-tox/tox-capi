#![allow(non_camel_case_types)]

extern crate tox;
extern crate libc;
extern crate sodiumoxide;

use std::{ slice, ptr };
use libc::size_t;
use sodiumoxide::crypto::pwhash::Salt;
use tox::toxencryptsave::*;


#[repr(C)]
pub enum TOX_ERR_KEY_DERIVATION {
    TOX_ERR_KEY_DERIVATION_OK,
    ///  Some input data, or maybe the output pointer, was null.
    TOX_ERR_KEY_DERIVATION_NULL,
    /// The crypto lib was unable to derive a key from the given passphrase,
    /// which is usually a lack of memory issue. The functions accepting keys
    /// do not produce this error.
    TOX_ERR_KEY_DERIVATION_FAILED
}

#[repr(C)]
pub enum TOX_ERR_ENCRYPTION {
    TOX_ERR_ENCRYPTION_OK,
    /// Some input data, or maybe the output pointer, was null.
    TOX_ERR_ENCRYPTION_NULL,
    /// The crypto lib was unable to derive a key from the given passphrase,
    /// which is usually a lack of memory issue. The functions accepting keys
    /// do not produce this error.
    TOX_ERR_ENCRYPTION_KEY_DERIVATION_FAILED,
    /// The encryption itself failed.
    TOX_ERR_ENCRYPTION_FAILED
}

#[repr(C)]
pub enum TOX_ERR_DECRYPTION {
    TOX_ERR_DECRYPTION_OK,
    /// Some input data, or maybe the output pointer, was null.
    TOX_ERR_DECRYPTION_NULL,
    /// The input data was shorter than TOX_PASS_ENCRYPTION_EXTRA_LENGTH bytes
    TOX_ERR_DECRYPTION_INVALID_LENGTH,
    /// The input data is missing the magic number (i.e. wasn't created by this
    /// module, or is corrupted)
    TOX_ERR_DECRYPTION_BAD_FORMAT,
    /// The crypto lib was unable to derive a key from the given passphrase,
    /// which is usually a lack of memory issue. The functions accepting keys
    /// do not produce this error.
    TOX_ERR_DECRYPTION_KEY_DERIVATION_FAILED,
    /// The encrypted byte array could not be decrypted. Either the data was
    /// corrupt or the password/key was incorrect.
    TOX_ERR_DECRYPTION_FAILED
}

/** Encrypts the given data with the given passphrase. The output array must be
    at least data_len + TOX_PASS_ENCRYPTION_EXTRA_LENGTH bytes long. This delegates
    to tox_derive_key_from_pass and tox_pass_key_encrypt.

    returns true on success
*/
#[no_mangle]
pub unsafe extern fn tox_pass_encrypt(
    data: *const u8,
    data_len: size_t,
    passphrase: *const u8,
    pplength: size_t,
    out: *mut u8,
    error: *mut TOX_ERR_ENCRYPTION
) -> bool {
    let data = slice::from_raw_parts(data, data_len);
    let passphrase = slice::from_raw_parts(passphrase, pplength);
    match pass_encrypt(data, passphrase) {
        Ok(output) => {
            ptr::copy(output.as_ptr(), out, output.len());
            ptr::write(error, TOX_ERR_ENCRYPTION::TOX_ERR_ENCRYPTION_OK);
            true
        },
        Err(EncryptionError::Null) => {
            ptr::write(error, TOX_ERR_ENCRYPTION::TOX_ERR_ENCRYPTION_NULL);
            false
        },
        Err(EncryptionError::KeyDerivation(_)) => {
            ptr::write(error, TOX_ERR_ENCRYPTION::TOX_ERR_ENCRYPTION_KEY_DERIVATION_FAILED);
            false
        }
    }
}

/** Decrypts the given data with the given passphrase. The output array must be
    at least data_len - TOX_PASS_ENCRYPTION_EXTRA_LENGTH bytes long. This delegates
    to tox_pass_key_decrypt.

    the output data has size data_length - TOX_PASS_ENCRYPTION_EXTRA_LENGTH

    returns true on success
*/
#[no_mangle]
pub unsafe extern fn tox_pass_decrypt(
    data: *const u8,
    data_len: size_t,
    passphrase: *const u8,
    pplength: size_t,
    out: *mut u8,
    error: *mut TOX_ERR_DECRYPTION
) -> bool {
    let data = slice::from_raw_parts(data, data_len);
    let passphrase = slice::from_raw_parts(passphrase, pplength);
    match pass_decrypt(data, passphrase) {
        Ok(output) => {
            ptr::copy(output.as_ptr(), out, output.len());
            ptr::write(error, TOX_ERR_DECRYPTION::TOX_ERR_DECRYPTION_OK);
            true
        },
        Err(DecryptionError::Null) => {
            ptr::write(error, TOX_ERR_DECRYPTION::TOX_ERR_DECRYPTION_NULL);
            false
        },
        Err(DecryptionError::InvalidLength) => {
            ptr::write(error, TOX_ERR_DECRYPTION::TOX_ERR_DECRYPTION_INVALID_LENGTH);
            false
        },
        Err(DecryptionError::BadFormat) => {
            ptr::write(error, TOX_ERR_DECRYPTION::TOX_ERR_DECRYPTION_BAD_FORMAT);
            false
        },
        Err(DecryptionError::KeyDerivation(_)) => {
            ptr::write(error, TOX_ERR_DECRYPTION::TOX_ERR_DECRYPTION_KEY_DERIVATION_FAILED);
            false
        },
        Err(DecryptionError::Failed) => {
            ptr::write(error, TOX_ERR_DECRYPTION::TOX_ERR_DECRYPTION_FAILED);
            false
        }
    }
}

/** This retrieves the salt used to encrypt the given data, which can then be passed to
    derive_key_with_salt to produce the same key as was previously used. Any encrpyted
    data with this module can be used as input.

    returns true if magic number matches
    success does not say anything about the validity of the data, only that data of
    the appropriate size was copied
*/
#[no_mangle]
pub unsafe extern fn tox_get_salt(data: *const u8, salt: *mut u8) -> bool {
    let data = slice::from_raw_parts(data, MAGIC_LENGTH + SALT_LENGTH);
    match get_salt(data) {
        Some(Salt(output)) => {
            ptr::copy(output.as_ptr(), salt, output.len());
            true
        },
        None => false
    }
}

/** Determines whether or not the given data is encrypted (by checking the magic number)
*/
#[no_mangle]
pub unsafe extern fn tox_is_data_encrypted(data: *const u8) -> bool {
    let data = slice::from_raw_parts(data, MAGIC_LENGTH);
    is_encrypted(data)
}

/** This key structure's internals should not be used by any client program, even
    if they are straightforward here.
*/
#[repr(C)]
pub struct TOX_PASS_KEY(PassKey);

/** Generates a secret symmetric key from the given passphrase. out_key must be at least
    TOX_PASS_KEY_LENGTH bytes long.
    Be sure to not compromise the key! Only keep it in memory, do not write to disk.
    The password is zeroed after key derivation.
    The key should only be used with the other functions in this module, as it
    includes a salt.
    Note that this function is not deterministic; to derive the same key from a
    password, you also must know the random salt that was used. See below.

    returns true on success
*/
#[no_mangle]
pub unsafe extern fn tox_derive_key_from_pass(
    passphrase: *const u8,
    pplength: size_t,
    out_key: *mut TOX_PASS_KEY,
    error: *mut TOX_ERR_KEY_DERIVATION
) -> bool {
    let passphrase = slice::from_raw_parts(passphrase, pplength);
    match PassKey::new(passphrase).map(TOX_PASS_KEY) {
        Ok(key) => {
            ptr::write(out_key, key);
            ptr::write(error, TOX_ERR_KEY_DERIVATION::TOX_ERR_KEY_DERIVATION_OK);
            true
        },
        Err(KeyDerivationError::Null) => {
            ptr::write(error, TOX_ERR_KEY_DERIVATION::TOX_ERR_KEY_DERIVATION_NULL);
            false
        },
        Err(KeyDerivationError::Failed) => {
            ptr::write(error, TOX_ERR_KEY_DERIVATION::TOX_ERR_KEY_DERIVATION_FAILED);
            false
        }
    }
}

/** Same as above, except use the given salt for deterministic key derivation.
    The salt must be TOX_PASS_SALT_LENGTH bytes in length.
*/
#[no_mangle]
pub unsafe extern fn tox_derive_key_with_salt(
    passphrase: *const u8,
    pplength: size_t,
    salt: *const u8,
    out_key: *mut TOX_PASS_KEY,
    error: *mut TOX_ERR_KEY_DERIVATION
) -> bool {
    let passphrase = slice::from_raw_parts(passphrase, pplength);
    let salt = slice::from_raw_parts(salt, SALT_LENGTH);
    match Salt::from_slice(salt)
        .ok_or(KeyDerivationError::Null)
        .and_then(|s| PassKey::with_salt(passphrase, s))
        .map(TOX_PASS_KEY)
    {
        Ok(key) => {
            ptr::write(out_key, key);
            ptr::write(error, TOX_ERR_KEY_DERIVATION::TOX_ERR_KEY_DERIVATION_OK);
            true
        },
        Err(KeyDerivationError::Null) => {
            ptr::write(error, TOX_ERR_KEY_DERIVATION::TOX_ERR_KEY_DERIVATION_NULL);
            false
        },
        Err(KeyDerivationError::Failed) => {
            ptr::write(error, TOX_ERR_KEY_DERIVATION::TOX_ERR_KEY_DERIVATION_FAILED);
            false
        }
    }
}

/** Encrypt arbitrary with a key produced by tox_derive_key_*. The output
    array must be at least data_len + TOX_PASS_ENCRYPTION_EXTRA_LENGTH bytes long.
    key must be TOX_PASS_KEY_LENGTH bytes.
    If you already have a symmetric key from somewhere besides this module, simply
    call encrypt_data_symmetric in toxcore/crypto_core directly.

    returns true on success
*/
#[no_mangle]
pub unsafe extern fn tox_pass_key_encrypt(
    data: *const u8,
    data_len: size_t,
    key: *const TOX_PASS_KEY,
    out: *mut u8,
    error: *mut TOX_ERR_ENCRYPTION
) -> bool {
    let data = slice::from_raw_parts(data, data_len);
    let TOX_PASS_KEY(key) = ptr::read(key);
    match key.encrypt(data) {
        Ok(output) => {
            ptr::copy(output.as_ptr(), out, output.len());
            ptr::write(error, TOX_ERR_ENCRYPTION::TOX_ERR_ENCRYPTION_OK);
            true
        },
        Err(_) => {
            ptr::write(error, TOX_ERR_ENCRYPTION::TOX_ERR_ENCRYPTION_NULL);
            false
        }
    }
}

/** This is the inverse of tox_pass_key_encrypt, also using only keys produced by
    tox_derive_key_from_pass.

    the output data has size data_length - TOX_PASS_ENCRYPTION_EXTRA_LENGTH

    returns true on success
*/
#[no_mangle]
pub unsafe extern fn tox_pass_key_decrypt(
    data: *const u8,
    data_len: size_t,
    key: *const TOX_PASS_KEY,
    out: *mut u8,
    error: *mut TOX_ERR_DECRYPTION
) -> bool {
    let data = slice::from_raw_parts(data, data_len);
    let TOX_PASS_KEY(key) = ptr::read(key);
    match key.decrypt(data) {
        Ok(output) => {
            ptr::copy(output.as_ptr(), out, output.len());
            ptr::write(error, TOX_ERR_DECRYPTION::TOX_ERR_DECRYPTION_OK);
            true
        },
        Err(DecryptionError::Null) => {
            ptr::write(error, TOX_ERR_DECRYPTION::TOX_ERR_DECRYPTION_NULL);
            false
        },
        Err(DecryptionError::InvalidLength) => {
            ptr::write(error, TOX_ERR_DECRYPTION::TOX_ERR_DECRYPTION_INVALID_LENGTH);
            false
        },
        Err(DecryptionError::BadFormat) => {
            ptr::write(error, TOX_ERR_DECRYPTION::TOX_ERR_DECRYPTION_BAD_FORMAT);
            false
        },
        Err(DecryptionError::Failed) => {
            ptr::write(error, TOX_ERR_DECRYPTION::TOX_ERR_DECRYPTION_FAILED);
            false
        },
        _ => unreachable!()
    }
}
