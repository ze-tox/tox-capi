#![allow(non_camel_case_types)]
extern crate tox;
extern crate libc;

use std::{ slice, ptr };
use libc::size_t;
use tox::toxencryptsave::encryptsave::*;


/** Since apparently no one actually bothered to learn about the module previously,
    the recently removed functions tox_encrypted_new and tox_get_encrypted_savedata
    may be trivially replaced by calls to tox_pass_decrypt -> tox_new or
    tox_get_savedata -> tox_pass_encrypt as appropriate. The removed functions
    were never more than 5 line wrappers of the other public API functions anyways.
    (As has always been, tox_pass_decrypt and tox_pass_encrypt are interchangeable
     with tox_pass_key_decrypt and tox_pass_key_encrypt, as the client program requires.)
*/
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
        Err(Encryption::Null) => {
            ptr::write(error, TOX_ERR_ENCRYPTION::TOX_ERR_ENCRYPTION_NULL);
            false
        },
        Err(Encryption::KeyDerivation(_)) => {
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
        Err(Decryption::Null) => {
            ptr::write(error, TOX_ERR_DECRYPTION::TOX_ERR_DECRYPTION_NULL);
            false
        },
        Err(Decryption::InvalidLength) => {
            ptr::write(error, TOX_ERR_DECRYPTION::TOX_ERR_DECRYPTION_INVALID_LENGTH);
            false
        },
        Err(Decryption::BadFormat) => {
            ptr::write(error, TOX_ERR_DECRYPTION::TOX_ERR_DECRYPTION_BAD_FORMAT);
            false
        },
        Err(Decryption::KeyDerivation(_)) => {
            ptr::write(error, TOX_ERR_DECRYPTION::TOX_ERR_DECRYPTION_KEY_DERIVATION_FAILED);
            false
        },
        Err(Decryption::Failed) => {
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
        Some(output) => {
            let output = output.as_ref();
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
