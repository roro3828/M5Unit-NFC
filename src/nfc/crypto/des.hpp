#pragma once

#include <stdint.h>
#include <stddef.h>
#define DES_BLOCK_SIZE 8

namespace m5 {
namespace nfc {
namespace crypto {
namespace des {
  typedef struct {
    uint64_t subkey[16]; /* each uses lower 48 bits */
  } des_ctx_t;

  static inline uint64_t load64_be(const uint8_t b[DES_BLOCK_SIZE]) {
    return ((uint64_t)b[0] << 56) | ((uint64_t)b[1] << 48) |
          ((uint64_t)b[2] << 40) | ((uint64_t)b[3] << 32) |
          ((uint64_t)b[4] << 24) | ((uint64_t)b[5] << 16) |
          ((uint64_t)b[6] <<  8) | ((uint64_t)b[7] <<  0);
  }

  static inline void store64_be(uint64_t v, uint8_t b[DES_BLOCK_SIZE]) {
    b[0] = (uint8_t)(v >> 56); b[1] = (uint8_t)(v >> 48);
    b[2] = (uint8_t)(v >> 40); b[3] = (uint8_t)(v >> 32);
    b[4] = (uint8_t)(v >> 24); b[5] = (uint8_t)(v >> 16);
    b[6] = (uint8_t)(v >>  8); b[7] = (uint8_t)(v >>  0);
  }

  /* encrypt */
  uint64_t des_encrypt_uint64(const des_ctx_t *ctx, uint64_t in64);
  void des_encrypt(const des_ctx_t *ctx, const uint8_t in[DES_BLOCK_SIZE], uint8_t out[DES_BLOCK_SIZE]);
  /* IV behavior: if iv == NULL => all-zero IV */
  void des_cbc_encrypt(const des_ctx_t *ctx,
                      const uint8_t *in, uint8_t *out, size_t len,
                      const uint8_t iv[DES_BLOCK_SIZE] = nullptr);

  /* decrypt */
  uint64_t des_decrypt_uint64(const des_ctx_t *ctx, uint64_t in64);
  void des_decrypt(const des_ctx_t *ctx, const uint8_t in[DES_BLOCK_SIZE], uint8_t out[DES_BLOCK_SIZE]);
  void des_cbc_decrypt(const des_ctx_t *ctx,
                    const uint8_t *in, uint8_t *out, size_t len,
                    const uint8_t iv[DES_BLOCK_SIZE] = nullptr);

  /* Triple DES encrypt */
  uint64_t tdes_encrypt_uint64(const des_ctx_t *key1,
                                const des_ctx_t *key2,
                                const des_ctx_t *key3,
                                uint64_t in64);
  void tdes_encrypt_block(const des_ctx_t *key1,
                          const des_ctx_t *key2,
                          const des_ctx_t *key3,
                          const uint8_t in[DES_BLOCK_SIZE], uint8_t out[DES_BLOCK_SIZE]);
  /* Triple DES decrypt */
  uint64_t tdes_decrypt_uint64(const des_ctx_t *key1,
                                const des_ctx_t *key2,
                                const des_ctx_t *key3,
                                uint64_t in64);
  void tdes_decrypt_block(const des_ctx_t *key1,
                          const des_ctx_t *key2,
                          const des_ctx_t *key3,
                          const uint8_t in[DES_BLOCK_SIZE], uint8_t out[DES_BLOCK_SIZE]);

  /* Set key schedule (encryption order subkeys) */
  void des_set_key_uint64(des_ctx_t *ctx, uint64_t key64);
  void des_set_key(des_ctx_t *ctx, const uint8_t key[DES_BLOCK_SIZE]);

}  // namespace des
}  // namespace crypto
}  // namespace nfc
}  // namespace m5