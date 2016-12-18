#![allow(non_camel_case_types)]

extern crate tox;
extern crate libc;
extern crate sodiumoxide;

use std::{ slice, ptr };
use libc::size_t;
use sodiumoxide::crypto::pwhash::Salt;
use tox::toxencryptsave::*;

#[no_mangle]
pub use tox::toxencryptsave::KEY_LENGTH as TOX_PASS_KEY_LENGTH;
#[no_mangle]
pub use tox::toxencryptsave::SALT_LENGTH as TOX_PASS_SALT_LENGTH;
#[no_mangle]
pub use tox::toxencryptsave::EXTRA_LENGTH as TOX_PASS_ENCRYPTION_EXTRA_LENGTH;


/** The size of the key part of a pass-key
*/
#[no_mangle]
pub extern fn tox_pass_key_length() -> u32 {
    TOX_PASS_KEY_LENGTH as u32
}

/** The size of the salt part of a pass-key
*/
#[no_mangle]
pub extern fn tox_pass_salt_length() -> u32 {
    TOX_PASS_SALT_LENGTH as u32
}

/** The amount of additional data requierd to store any encrypted byte array.
    Encrypting an array of N bytes requires N + TOX_PASS_ENCRYPTION_EXTRA_LENGTH
    bytes in the encrypted byte array.
*/
#[no_mangle]
pub extern fn tox_pass_encryption_extra_length() -> u32 {
    TOX_PASS_ENCRYPTION_EXTRA_LENGTH as u32
}


#[repr(C)]
pub enum TOX_ERR_KEY_DERIVATION {
    /// The function returned successfully.
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
    /// The function returned successfully.
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
    /// The function returned successfully.
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

/** Encrypts the given data with the given passphrase.

    The output array must be at least `plaintext_len + TOX_PASS_ENCRYPTION_EXTRA_LENGTH`
    bytes long. This delegates to tox_pass_key_derive and
    tox_pass_key_encrypt.

    @param plaintext A byte array of length `plaintext_len`.
    @param plaintext_len The length of the plain text array. Bigger than 0.
    @param passphrase The user-provided password.
    @param passphrase_len The length of the password.
    @param ciphertext The cipher text array to write the encrypted data to.

    @return true on success.
*/
#[no_mangle]
pub unsafe extern fn tox_pass_encrypt(
    plaintext: *const u8,
    plaintext_len: size_t,
    passphrase: *const u8,
    passphrase_len: size_t,
    ciphertext: *mut u8,
    error: *mut TOX_ERR_ENCRYPTION
) -> bool {
    let plaintext = slice::from_raw_parts(plaintext, plaintext_len);
    let passphrase = slice::from_raw_parts(passphrase, passphrase_len);
    match pass_encrypt(plaintext, passphrase) {
        Ok(output) => {
            ptr::copy(output.as_ptr(), ciphertext, output.len());
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

/** Decrypts the given data with the given passphrase.

    The output array must be at least `ciphertext_len - TOX_PASS_ENCRYPTION_EXTRA_LENGTH`
    bytes long. This delegates to tox_pass_key_decrypt.

    @param ciphertext A byte array of length `ciphertext_len`.
    @param ciphertext_len The length of the cipher text array. At least TOX_PASS_ENCRYPTION_EXTRA_LENGTH.
    @param passphrase The user-provided password.
    @param passphrase_len The length of the password.
    @param plaintext The plain text array to write the decrypted data to.

    @return true on success.
*/
#[no_mangle]
pub unsafe extern fn tox_pass_decrypt(
    ciphertext: *const u8,
    ciphertext_len: size_t,
    passphrase: *const u8,
    passphrase_len: size_t,
    plaintext: *mut u8,
    error: *mut TOX_ERR_DECRYPTION
) -> bool {
    let ciphertext = slice::from_raw_parts(ciphertext, ciphertext_len);
    let passphrase = slice::from_raw_parts(passphrase, passphrase_len);
    match pass_decrypt(ciphertext, passphrase) {
        Ok(output) => {
            ptr::copy(output.as_ptr(), plaintext, output.len());
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

/** Retrieves the salt used to encrypt the given data.

    The retrieved salt can then be passed to tox_pass_key_derive_with_salt to
    produce the same key as was previously used. Any data encrypted with this
    module can be used as input.

    The cipher text must be at least TOX_PASS_ENCRYPTION_EXTRA_LENGTH bytes in
    length.

    The salt must be TOX_PASS_SALT_LENGTH bytes in length.
    If the passed byte arrays are smaller than required, the behaviour is
    undefined.

    Success does not say anything about the validity of the data, only that
    data of the appropriate size was copied.

    @return true on success.
 */
#[no_mangle]
pub unsafe extern fn tox_get_salt(ciphertext: *const u8, salt: *mut u8) -> bool {
    let ciphertext = slice::from_raw_parts(ciphertext, MAGIC_LENGTH + SALT_LENGTH);
    match get_salt(ciphertext) {
        Some(Salt(output)) => {
            ptr::copy(output.as_ptr(), salt, output.len());
            true
        },
        None => false
    }
}

/** Determines whether or not the given data is encrypted by this module.

    It does this check by verifying that the magic number is the one put in
    place by the encryption functions.

    The data must be at least TOX_PASS_ENCRYPTION_EXTRA_LENGTH bytes in length.
    If the passed byte array is smaller than required, the behaviour is
    undefined.

    If the cipher text pointer is NULL, this function returns false.

    @return true if the data is encrypted by this module.
 */
#[no_mangle]
pub unsafe extern fn tox_is_data_encrypted(data: *const u8) -> bool {
    let data = slice::from_raw_parts(data, MAGIC_LENGTH);
    is_encrypted(data)
}

/** This type represents a pass-key.

    A pass-key and a password are two different concepts: a password is given
    by the user in plain text. A pass-key is the generated symmetric key used
    for encryption and decryption. It is derived from a salt and the user-
    provided password.

    The Tox_Pass_Key structure is hidden in the implementation. It can be
    allocated using tox_pass_key_new and must be deallocated using
    tox_pass_key_free.
*/
#[repr(C)]
pub struct Tox_Pass_Key(PassKey);


/** Create a new Tox_Pass_Key. The initial value of it is indeterminate. To
    initialise it, use one of the derive_* functions below.
*/
#[no_mangle]
pub extern fn tox_pass_key_new() -> *mut Tox_Pass_Key {
    // TODO: remove with 0.2, since its API nullifies need to create PassKey twice
    let pass = b"Can't have unsafe, empty PassKey, so create on with this pass";
    Box::into_raw(
        PassKey::new(pass)
        .map(Tox_Pass_Key)
        .map(Box::new)
        .expect("Failed to allocate memory?")
    )
}

/** Deallocate a Tox_Pass_Key. This function behaves like free(), so NULL is an
    acceptable argument value.
*/
#[no_mangle]
pub extern fn tox_pass_key_free(key: *mut Tox_Pass_Key) {
    drop(key);
}

/** Generates a secret symmetric key from the given passphrase.

    Be sure to not compromise the key! Only keep it in memory, do not write
    it to disk.

    Make sure to zero the password after key derivation.

    Note that this function is not deterministic; to derive the same key from
    a password, you also must know the random salt that was used. A
    deterministic version of this function is tox_pass_key_derive_with_salt.

    @param passphrase The user-provided password.
    @param passphrase_len The length of the password.

    @return true on success.
*/
#[no_mangle]
pub unsafe extern fn tox_pass_key_derive(
    key: *mut Tox_Pass_Key,
    passphrase: *const u8,
    passphrase_len: size_t,
    error: *mut TOX_ERR_KEY_DERIVATION
) -> bool {
    let passphrase = slice::from_raw_parts(passphrase, passphrase_len);
    match PassKey::new(passphrase).map(Tox_Pass_Key) {
        Ok(key_new) => {
            ptr::write(key, key_new);
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

    @param passphrase The user-provided password.
    @param passphrase_len The length of the password.
    @param salt An array of at least TOX_PASS_SALT_LENGTH bytes.

    @return true on success.
*/
#[no_mangle]
pub unsafe extern fn tox_derive_key_with_salt(
    key: *mut Tox_Pass_Key,
    passphrase: *const u8,
    passphrase_len: size_t,
    salt: *const u8,
    error: *mut TOX_ERR_KEY_DERIVATION
) -> bool {
    let passphrase = slice::from_raw_parts(passphrase, passphrase_len);
    let salt = slice::from_raw_parts(salt, SALT_LENGTH);
    match Salt::from_slice(salt)
        .ok_or(KeyDerivationError::Null)
        .and_then(|s| PassKey::with_salt(passphrase, s))
        .map(Tox_Pass_Key)
    {
        Ok(key_new) => {
            ptr::write(key, key_new);
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

/** Encrypt a plain text with a key produced by tox_pass_key_derive or
    tox_pass_key_derive_with_salt.

    The output array must be at least `plaintext_len + TOX_PASS_ENCRYPTION_EXTRA_LENGTH`
    bytes long.

    @param plaintext A byte array of length `plaintext_len`.
    @param plaintext_len The length of the plain text array. Bigger than 0.
    @param ciphertext The cipher text array to write the encrypted data to.

    @return true on success.
 */
#[no_mangle]
pub unsafe extern fn tox_pass_key_encrypt(
    key: *const Tox_Pass_Key,
    plaintext: *const u8,
    plaintext_len: size_t,
    ciphertext: *mut u8,
    error: *mut TOX_ERR_ENCRYPTION
) -> bool {
    let plaintext = slice::from_raw_parts(plaintext, plaintext_len);
    let Tox_Pass_Key(key) = ptr::read(key);
    match key.encrypt(plaintext) {
        Ok(output) => {
            ptr::copy(output.as_ptr(), ciphertext, output.len());
            ptr::write(error, TOX_ERR_ENCRYPTION::TOX_ERR_ENCRYPTION_OK);
            true
        },
        Err(_) => {
            ptr::write(error, TOX_ERR_ENCRYPTION::TOX_ERR_ENCRYPTION_NULL);
            false
        }
    }
}

/** This is the inverse of tox_pass_key_encrypt, also using only keys produced
    by tox_pass_key_derive or tox_pass_key_derive_with_salt.

    @param ciphertext A byte array of length `ciphertext_len`.
    @param ciphertext_len The length of the cipher text array. At least TOX_PASS_ENCRYPTION_EXTRA_LENGTH.
    @param plaintext The plain text array to write the decrypted data to.

    @return true on success.
*/
#[no_mangle]
pub unsafe extern fn tox_pass_key_decrypt(
    key: *const Tox_Pass_Key,
    ciphertext: *const u8,
    ciphertext_len: size_t,
    plaintext: *mut u8,
    error: *mut TOX_ERR_DECRYPTION
) -> bool {
    let ciphertext = slice::from_raw_parts(ciphertext, ciphertext_len);
    let Tox_Pass_Key(key) = ptr::read(key);
    match key.decrypt(ciphertext) {
        Ok(output) => {
            ptr::copy(output.as_ptr(), plaintext, output.len());
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
