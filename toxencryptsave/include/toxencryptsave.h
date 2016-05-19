
#ifndef cheddar_generated_toxencryptsave_h
#define cheddar_generated_toxencryptsave_h


#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>



/** Since apparently no one actually bothered to learn about the module previously,
    the recently removed functions tox_encrypted_new and tox_get_encrypted_savedata
    may be trivially replaced by calls to tox_pass_decrypt -> tox_new or
    tox_get_savedata -> tox_pass_encrypt as appropriate. The removed functions
    were never more than 5 line wrappers of the other public API functions anyways.
    (As has always been, tox_pass_decrypt and tox_pass_encrypt are interchangeable
     with tox_pass_key_decrypt and tox_pass_key_encrypt, as the client program requires.)
*/
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



#ifdef __cplusplus
}
#endif


#endif
