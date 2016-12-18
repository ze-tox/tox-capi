
#ifndef cheddar_generated_toxencryptsave_h
#define cheddar_generated_toxencryptsave_h


#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>



/** The size of the key part of a pass-key
*/
uint32_t tox_pass_key_length(void);

/** The size of the salt part of a pass-key
*/
uint32_t tox_pass_salt_length(void);

/** The amount of additional data requierd to store any encrypted byte array.
    Encrypting an array of N bytes requires N + TOX_PASS_ENCRYPTION_EXTRA_LENGTH
    bytes in the encrypted byte array.
*/
uint32_t tox_pass_encryption_extra_length(void);

typedef enum TOX_ERR_KEY_DERIVATION {
	/// The function returned successfully.
	TOX_ERR_KEY_DERIVATION_OK,
	///  Some input data, or maybe the output pointer, was null.
	TOX_ERR_KEY_DERIVATION_NULL,
	/// The crypto lib was unable to derive a key from the given passphrase,
	/// which is usually a lack of memory issue. The functions accepting keys
	/// do not produce this error.
	TOX_ERR_KEY_DERIVATION_FAILED,
} TOX_ERR_KEY_DERIVATION;

typedef enum TOX_ERR_ENCRYPTION {
	/// The function returned successfully.
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
	TOX_ERR_DECRYPTION_FAILED,
} TOX_ERR_DECRYPTION;

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
bool tox_pass_encrypt(uint8_t const* plaintext, size_t plaintext_len, uint8_t const* passphrase, size_t passphrase_len, uint8_t* ciphertext, TOX_ERR_ENCRYPTION* error);

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
bool tox_pass_decrypt(uint8_t const* ciphertext, size_t ciphertext_len, uint8_t const* passphrase, size_t passphrase_len, uint8_t* plaintext, TOX_ERR_DECRYPTION* error);

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
bool tox_get_salt(uint8_t const* ciphertext, uint8_t* salt);

/** Determines whether or not the given data is encrypted by this module.

    It does this check by verifying that the magic number is the one put in
    place by the encryption functions.

    The data must be at least TOX_PASS_ENCRYPTION_EXTRA_LENGTH bytes in length.
    If the passed byte array is smaller than required, the behaviour is
    undefined.

    If the cipher text pointer is NULL, this function returns false.

    @return true if the data is encrypted by this module.
 */
bool tox_is_data_encrypted(uint8_t const* data);

/** This type represents a pass-key.

    A pass-key and a password are two different concepts: a password is given
    by the user in plain text. A pass-key is the generated symmetric key used
    for encryption and decryption. It is derived from a salt and the user-
    provided password.

    The Tox_Pass_Key structure is hidden in the implementation. It can be
    allocated using tox_pass_key_new and must be deallocated using
    tox_pass_key_free.
*/
typedef struct Tox_Pass_Key Tox_Pass_Key;

/** Create a new Tox_Pass_Key. The initial value of it is indeterminate. To
    initialise it, use one of the derive_* functions below.
*/
Tox_Pass_Key* tox_pass_key_new(void);

/** Deallocate a Tox_Pass_Key. This function behaves like free(), so NULL is an
    acceptable argument value.
*/
void tox_pass_key_free(Tox_Pass_Key* key);

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
bool tox_pass_key_derive(Tox_Pass_Key* key, uint8_t const* passphrase, size_t passphrase_len, TOX_ERR_KEY_DERIVATION* error);

/** Same as above, except use the given salt for deterministic key derivation.

    @param passphrase The user-provided password.
    @param passphrase_len The length of the password.
    @param salt An array of at least TOX_PASS_SALT_LENGTH bytes.

    @return true on success.
*/
bool tox_derive_key_with_salt(Tox_Pass_Key* key, uint8_t const* passphrase, size_t passphrase_len, uint8_t const* salt, TOX_ERR_KEY_DERIVATION* error);

/** Encrypt a plain text with a key produced by tox_pass_key_derive or
    tox_pass_key_derive_with_salt.

    The output array must be at least `plaintext_len + TOX_PASS_ENCRYPTION_EXTRA_LENGTH`
    bytes long.

    @param plaintext A byte array of length `plaintext_len`.
    @param plaintext_len The length of the plain text array. Bigger than 0.
    @param ciphertext The cipher text array to write the encrypted data to.

    @return true on success.
 */
bool tox_pass_key_encrypt(Tox_Pass_Key const* key, uint8_t const* plaintext, size_t plaintext_len, uint8_t* ciphertext, TOX_ERR_ENCRYPTION* error);

/** This is the inverse of tox_pass_key_encrypt, also using only keys produced
    by tox_pass_key_derive or tox_pass_key_derive_with_salt.

    @param ciphertext A byte array of length `ciphertext_len`.
    @param ciphertext_len The length of the cipher text array. At least TOX_PASS_ENCRYPTION_EXTRA_LENGTH.
    @param plaintext The plain text array to write the decrypted data to.

    @return true on success.
*/
bool tox_pass_key_decrypt(Tox_Pass_Key const* key, uint8_t const* ciphertext, size_t ciphertext_len, uint8_t* plaintext, TOX_ERR_DECRYPTION* error);



#ifdef __cplusplus
}
#endif


#endif
