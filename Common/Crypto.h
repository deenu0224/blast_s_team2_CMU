#ifndef CRYPTO_H
#define CRYPTO_H

#include <vector>
#include <string>

#define HMAC_SIZE 32
#define SHA256_DIGEST_LENGTH 32
#define AES_BLOCK_SIZE 16
#define IV_LEN 16

std::vector<unsigned char> calculate_hmac(const char* key, 
    const void* data, size_t data_len);

bool aes_encrypt(const unsigned char* key, const unsigned char* iv,
    const unsigned char* plconsaintext, int plaintext_len,
    unsigned char* ciphertext, int& ciphertext_len);

bool aes_decrypt(const unsigned char* key, const unsigned char* iv,
    const unsigned char* ciphertext, int ciphertext_len,
    unsigned char* plaintext, int& plaintext_len);

std::vector<unsigned char> sha256(const std::string& str);
std::vector<unsigned char> generate_random_bytes(std::size_t length);

#endif // CRYPTO_H