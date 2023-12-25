#include <gcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define GCRY_CIPHER GCRY_CIPHER_AES256
#define GCRY_MODE GCRY_CIPHER_MODE_CBC

#define KEY_LENGTH 32 // 256 bits
#define IV_LENGTH 16  // 128 bits

void handle_error(const char *msg) {
    fprintf(stderr, "Error: %s\n", msg);
    exit(EXIT_FAILURE);
}

void encrypt_file(const char *input_filename, const char *output_filename, const char *password) {
    gcry_cipher_hd_t handle;
    gcry_error_t err;

    FILE *input_file = fopen(input_filename, "rb");
    if (!input_file) {
        handle_error("Failed to open input file");
    }

    FILE *output_file = fopen(output_filename, "wb");
    if (!output_file) {
        fclose(input_file);
        handle_error("Failed to open output file");
    }

    // Derive a key from the password using a key derivation function (KDF)
    unsigned char key[KEY_LENGTH];
    err = gcry_kdf_derive(password, strlen(password), GCRY_KDF_PBKDF2, GCRY_MD_SHA256, "salt", 4, 4096, KEY_LENGTH, key);
    if (err) {
        handle_error("Key derivation failed");
    }

    // Generate a random initialization vector (IV)
    unsigned char iv[IV_LENGTH];
    gcry_randomize(iv, IV_LENGTH, GCRY_STRONG_RANDOM);

    // Write the IV to the output file
    fwrite(iv, 1, IV_LENGTH, output_file);

    // Initialize the cipher handle
    err = gcry_cipher_open(&handle, GCRY_CIPHER, GCRY_MODE, 0);
    if (err) {
        handle_error("Cipher initialization failed");
    }

    // Set the key for the cipher handle
    err = gcry_cipher_setkey(handle, key, KEY_LENGTH);
    if (err) {
        gcry_cipher_close(handle);
        handle_error("Failed to set cipher key");
    }

    // Set the IV for the cipher handle
    err = gcry_cipher_setiv(handle, iv, IV_LENGTH);
    if (err) {
        gcry_cipher_close(handle);
        handle_error("Failed to set cipher IV");
    }

    // Encrypt the file content block by block
    size_t block_size = gcry_cipher_get_algo_blklen(GCRY_CIPHER);
    unsigned char *buffer = malloc(block_size);

    while (1) {
        size_t bytes_read = fread(buffer, 1, block_size, input_file);
        if (bytes_read == 0) {
            break; // End of file
        }

        // Pad the last block if needed
        if (bytes_read < block_size) {
            memset(buffer + bytes_read, block_size - bytes_read, block_size - bytes_read);
        }

        // Encrypt the block
        err = gcry_cipher_encrypt(handle, buffer, block_size, NULL, 0);
        if (err) {
            free(buffer);
            gcry_cipher_close(handle);
            fclose(input_file);
            fclose(output_file);
            handle_error("Encryption failed");
        }

        // Write the encrypted block to the output file
        fwrite(buffer, 1, block_size, output_file);
    }

    free(buffer);
    gcry_cipher_close(handle);
    fclose(input_file);
    fclose(output_file);

    printf("Encryption complete.\n");
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <input_file> <output_file> <password>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *input_filename = argv[1];
    const char *output_filename = argv[2];
    const char *password = argv[3];

    // Initialize the libgcrypt library
    if (!gcry_check_version(GCRYPT_VERSION)) {
        handle_error("Libgcrypt version mismatch");
    }
    gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

    // Call the function to encrypt the file
    encrypt_file(input_filename, output_filename, password);

    // Clean up libgcrypt
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 1);

    return EXIT_SUCCESS;
}

