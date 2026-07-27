#pragma once

#include <stdint.h>
#include <stddef.h>
#define DES_BLOCK_SIZE 8

namespace m5 {
namespace nfc {
namespace crypto {
  typedef struct {
    uint64_t subkey[16]; /* each uses lower 48 bits */
  } des_ctx_t;

  /* encrypt */
  void des_encrypt(const des_ctx_t *ctx, const uint8_t in[DES_BLOCK_SIZE], uint8_t out[DES_BLOCK_SIZE]);
  /* IV behavior: if iv == NULL => all-zero IV */
  void des_cbc_encrypt(const des_ctx_t *ctx,
                      const uint8_t *in, uint8_t *out, size_t len,
                      const uint8_t iv[DES_BLOCK_SIZE] = nullptr);

  /* decrypt */
  void des_decrypt(const des_ctx_t *ctx, const uint8_t in[DES_BLOCK_SIZE], uint8_t out[DES_BLOCK_SIZE]);
  void des_cbc_decrypt(const des_ctx_t *ctx,
                    const uint8_t *in, uint8_t *out, size_t len,
                    const uint8_t iv[DES_BLOCK_SIZE] = nullptr);

  /* Triple DES encrypt */
  void tdes_encrypt_block(const des_ctx_t *key1,
                          const des_ctx_t *key2,
                          const des_ctx_t *key3,
                          const uint8_t in[DES_BLOCK_SIZE], uint8_t out[DES_BLOCK_SIZE]);
  /* Triple DES decrypt */
  void tdes_decrypt_block(const des_ctx_t *key1,
                          const des_ctx_t *key2,
                          const des_ctx_t *key3,
                          const uint8_t in[DES_BLOCK_SIZE], uint8_t out[DES_BLOCK_SIZE]);

  /* Set key schedule (encryption order subkeys) */
  void des_set_key(des_ctx_t *ctx, const uint8_t key[DES_BLOCK_SIZE]);


}  // namespace crypto
}  // namespace nfc
}  // namespace m5