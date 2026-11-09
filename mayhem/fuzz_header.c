// Header encryption (src/header_encryption.c): packet_header_decrypt() on a raw packet, and on the
// same packet after packet_header_encrypt() so the "n2__" magic and header length are valid.
//
// Input layout: bytes 0..1 select the header length for the encrypted variant, the rest is the packet.
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "n2n.h"
#include "n2n_wire.h"
#include "header_encryption.h"
#include "pearson.h"
#include "random_numbers.h"

static char community[N2N_COMMUNITY_SIZE] = "abc123def456";
static he_context_t *ctx_static, *ctx_dynamic, *ctx_iv_static, *ctx_iv_dynamic;

int LLVMFuzzerInitialize (int *argc, char ***argv) {

    setTraceLevel(-1);
    pearson_hash_init();
    n2n_srand(1);
    packet_header_setup_key(community, &ctx_static, &ctx_dynamic, &ctx_iv_static, &ctx_iv_dynamic);

    return 0;
}

static void decrypt_all (const uint8_t *pkt, size_t len) {

    uint64_t stamp;

    // packet_header_decrypt() works in place and takes a uint16_t length
    uint8_t *copy = (uint8_t *)malloc(len ? len : 1);
    if(!copy) {
        return;
    }

    memcpy(copy, pkt, len);
    if(packet_header_decrypt(copy, (uint16_t)len, community, ctx_dynamic, ctx_iv_dynamic, &stamp)) {
        n2n_common_t cmn;
        size_t rem = len;
        size_t idx = 0;
        decode_common(&cmn, copy, &rem, &idx);
    }

    memcpy(copy, pkt, len);
    packet_header_decrypt(copy, (uint16_t)len, community, ctx_static, ctx_iv_static, &stamp);

    free(copy);
}

int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size) {

    if((size < 2) || (size - 2 > N2N_PKT_BUF_SIZE)) {
        return -1;
    }

    uint16_t selector = (uint16_t)(data[0] | (data[1] << 8));
    const uint8_t *pkt = data + 2;
    size_t len = size - 2;

    decrypt_all(pkt, len);

    // packet_header_encrypt() requires packet_len >= 24 and header_len <= packet_len
    if(len >= 24) {
        uint16_t header_len = (uint16_t)(24 + (selector % (len - 23)));
        uint8_t *enc = (uint8_t *)malloc(len);
        if(!enc) {
            return 0;
        }
        memcpy(enc, pkt, len);
        if(packet_header_encrypt(enc, header_len, (uint16_t)len, ctx_dynamic, ctx_iv_dynamic, time_stamp()) == 0) {
            decrypt_all(enc, len);
        }
        free(enc);
    }

    return 0;
}
