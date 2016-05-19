
#ifndef cheddar_generated_toxencryptsave_h
#define cheddar_generated_toxencryptsave_h


#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>



typedef enum TOX_ERR_KEY_DERIVATION {
	TOX_ERR_KEY_DERIVATION_OK,
	///  Some input data, or maybe the output pointer, was null.
	TOX_ERR_KEY_DERIVATION_NULL,
	/// The crypto lib was unable to derive a key from the given passphrase,
	/// which is usually a lack of memory issue. The functions accepting keys
	/// do not produce this error.
	TOX_ERR_KEY_DERIVATION_FAILED,
} TOX_ERR_KEY_DERIVATION;

typedef enum TOX_ERR_ENCRYPTION {
	TOX_ERR_ENCRYPTION_OK,
	/// Some input data, or maybe the output pointer, was null.
	TOX_ERR_ENCRYPTION_NULL,
	/// The crypto lib was unable to derive a key from the given passphrase,
	/// which is usually a lack of memory issue. The functions accepting keys
	/// do not produce this error.
	TOX_ERR_ENCRYPTION_KEY_DERIVATION_FAILED,
	/// The encryption itself failed.
	TOX_ERR_ENCRYPTION_FAILED,
} TOX_ERR_ENCRYPTION;

typedef enum TOX_ERR_DECRYPTION {
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
	TOX_ERR_DECRYPTION_FAILED,
} TOX_ERR_DECRYPTION;

/** Encrypts the given data with the given passphrase. The output array must be
    at least data_len + TOX_PASS_ENCRYPTION_EXTRA_LENGTH bytes long. This delegates
    to tox_derive_key_from_pass and tox_pass_key_encrypt.

    returns true on success
*/
bool tox_pass_encrypt(uint8_t const* data, size_t data_len, uint8_t const* passphrase, size_t pplength, uint8_t* out, TOX_ERR_ENCRYPTION* error);

/** Decrypts the given data with the given passphrase. The output array must be
    at least data_len - TOX_PASS_ENCRYPTION_EXTRA_LENGTH bytes long. This delegates
    to tox_pass_key_decrypt.

    the output data has size data_length - TOX_PASS_ENCRYPTION_EXTRA_LENGTH

    returns true on success
*/
bool tox_pass_decrypt(uint8_t const* data, size_t data_len, uint8_t const* passphrase, size_t pplength, uint8_t* out, TOX_ERR_DECRYPTION* error);

/** This retrieves the salt used to encrypt the given data, which can then be passed to
    derive_key_with_salt to produce the same key as was previously used. Any encrpyted
    data with this module can be used as input.

    returns true if magic number matches
    success does not say anything about the validity of the data, only that data of
    the appropriate size was copied
*/
bool tox_get_salt(uint8_t const* data, uint8_t* salt);

/** Determines whether or not the given data is encrypted (by checking the magic number)
*/
bool tox_is_data_encrypted(uint8_t const* data);

/** This key structure's internals should not be used by any client program, even
    if they are straightforward here.
*/
typedef struct TOX_PASS_KEY TOX_PASS_KEY;

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
bool tox_derive_key_from_pass(uint8_t const* passphrase, size_t pplength, TOX_PASS_KEY* out_key, TOX_ERR_KEY_DERIVATION* error);

/** Same as above, except use the given salt for deterministic key derivation.
    The salt must be TOX_PASS_SALT_LENGTH bytes in length.
*/
bool tox_derive_key_with_salt(uint8_t const* passphrase, size_t pplength, uint8_t const* salt, TOX_PASS_KEY* out_key, TOX_ERR_KEY_DERIVATION* error);

/** Encrypt arbitrary with a key produced by tox_derive_key_*. The output
    array must be at least data_len + TOX_PASS_ENCRYPTION_EXTRA_LENGTH bytes long.
    key must be TOX_PASS_KEY_LENGTH bytes.
    If you already have a symmetric key from somewhere besides this module, simply
    call encrypt_data_symmetric in toxcore/crypto_core directly.

    returns true on success
*/
bool tox_pass_key_encrypt(uint8_t const* data, size_t data_len, TOX_PASS_KEY const* key, uint8_t* out, TOX_ERR_ENCRYPTION* error);

/** This is the inverse of tox_pass_key_encrypt, also using only keys produced by
    tox_derive_key_from_pass.

    the output data has size data_length - TOX_PASS_ENCRYPTION_EXTRA_LENGTH

    returns true on success
*/
bool tox_pass_key_decrypt(uint8_t const* data, size_t data_len, TOX_PASS_KEY const* key, uint8_t* out, TOX_ERR_DECRYPTION* error);



#ifdef __cplusplus
}
#endif


#endif
