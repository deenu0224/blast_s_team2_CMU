#include "Crypto.h"

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <iomanip>
#include <fstream>

std::vector<unsigned char> calculate_hmac(const char* key, const void* data, size_t data_len) {
    unsigned char* hmac_result;
    unsigned int len;
    hmac_result = HMAC(EVP_sha256(), key, HMAC_SIZE,
        reinterpret_cast<const unsigned char*>(data), data_len,
        NULL, &len);
    // HMAC 결과를 vector로 return
    return std::vector<unsigned char>(hmac_result, hmac_result + len);
}

bool aes_encrypt(const unsigned char* key, const unsigned char* iv,
    const unsigned char* plaintext, int plaintext_len,
    unsigned char* ciphertext, int& ciphertext_len) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    int len;
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool aes_decrypt(const unsigned char* key, const unsigned char* iv,
    const unsigned char* ciphertext, int ciphertext_len,
    unsigned char* plaintext, int& plaintext_len) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    int len;
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

std::vector<unsigned char> sha256(const std::string& str) {
    unsigned char hash[SHA256_DIGEST_LENGTH] = {0,};
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    const EVP_MD* md = EVP_sha256();

    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, str.c_str(), str.size());
    EVP_DigestFinal_ex(mdctx, hash, NULL);
    EVP_MD_CTX_free(mdctx);

    return std::vector<unsigned char>(hash, hash + SHA256_DIGEST_LENGTH);
}

std::vector<unsigned char> generate_random_bytes(std::size_t length) {
    // urandom 파일을 이진 모드로 엽니다
    std::ifstream urandom("/dev/urandom", std::ios::binary);

    if (!urandom.is_open()) {
        throw std::runtime_error("urandom 파일을 열 수 없습니다.");
    }

    // length 바이트를 저장할 벡터를 생성합니다
    std::vector<unsigned char> random_bytes(length);

    // length 바이트를 urandom으로부터 읽습니다
    urandom.read(reinterpret_cast<char*>(random_bytes.data()), random_bytes.size());

    if (urandom.gcount() != random_bytes.size()) {
        throw std::runtime_error("랜덤 바이트를 읽는 데 실패했습니다.");
    }

    urandom.close();

    return random_bytes;
}