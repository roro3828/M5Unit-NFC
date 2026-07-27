/*
 * SPDX-FileCopyrightText: 2026 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*
  UnitTest for DES
*/
#include <gtest/gtest.h>
#include "nfc/crypto/des.hpp"
#include <cstring>

using namespace m5::nfc::crypto;

namespace {

void hex_to_bytes(const char* hex, uint8_t* out, const size_t len)
{
    for (size_t i = 0; i < len; ++i) {
        char buf[3] = {hex[i * 2], hex[i * 2 + 1], 0};
        out[i]      = static_cast<uint8_t>(std::strtoul(buf, nullptr, 16));
    }
}

}  // namespace

TEST(DES, ECBVector)
{
    uint8_t key[DES_BLOCK_SIZE]{};
    uint8_t in[DES_BLOCK_SIZE]{};
    uint8_t out[DES_BLOCK_SIZE]{};
    uint8_t expected[DES_BLOCK_SIZE]{};

    hex_to_bytes("0123456789abcdef", key, DES_BLOCK_SIZE);
    hex_to_bytes("fedcba9876543210", in, DES_BLOCK_SIZE);
    hex_to_bytes("12c626af058b433b", expected, DES_BLOCK_SIZE);

    des_ctx_t ctx;
    des_set_key(&ctx, key);
    des_encrypt(&ctx, in, out);
    EXPECT_TRUE(std::memcmp(out, expected, DES_BLOCK_SIZE) == 1);
}
