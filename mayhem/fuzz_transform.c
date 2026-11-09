// Payload transforms (null, tf, aes, cc20, speck, lzo): the decoder (->rev) on raw payload bytes,
// as the edge calls it on whatever follows the PACKET header, and a fwd/rev round trip.
//
// Input layout: byte 0 selects the transform, the rest is the payload.
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "n2n.h"
#include "pearson.h"
#include "random_numbers.h"

typedef int (*transop_init_f)(const n2n_edge_conf_t *conf, n2n_trans_op_t *ttt);

static const transop_init_f inits[] = {
    n2n_transop_null_init,
    n2n_transop_tf_init,
    n2n_transop_aes_init,
    n2n_transop_cc20_init,
    n2n_transop_speck_init,
    n2n_transop_lzo_init,
};
#define MAX_TAP_FRAME 1600
#define NUM_TRANSOPS (sizeof(inits) / sizeof(inits[0]))

int LLVMFuzzerInitialize (int *argc, char ***argv) {

    setTraceLevel(-1);
    pearson_hash_init();
    n2n_srand(1);

    return 0;
}

int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size) {

    // payload buffers in n2n are N2N_PKT_BUF_SIZE bytes
    if((size < 1) || (size - 1 > N2N_PKT_BUF_SIZE)) {
        return -1;
    }

    n2n_edge_conf_t conf;
    n2n_trans_op_t op;
    n2n_mac_t mac = {0, 1, 2, 3, 4, 5};

    edge_init_conf_defaults(&conf);
    strncpy((char *)conf.community_name, "abc123def456", sizeof(conf.community_name));
    conf.encrypt_key = "SoMEVer!S$cUREPassWORD";

    if(inits[data[0] % NUM_TRANSOPS](&conf, &op) != 0) {
        return -1;
    }

    const uint8_t *payload = data + 1;
    size_t len = size - 1;

    uint8_t *in = (uint8_t *)malloc(len ? len : 1);
    uint8_t *out = (uint8_t *)malloc(N2N_PKT_BUF_SIZE);
    uint8_t *enc = (uint8_t *)malloc(2 * N2N_PKT_BUF_SIZE);
    uint8_t *dec = (uint8_t *)malloc(N2N_PKT_BUF_SIZE);

    if(in && out && enc && dec) {
        memcpy(in, payload, len);
        op.rev(&op, out, N2N_PKT_BUF_SIZE, in, len, mac);

        // a transform must give back what it was given; the edge only encodes frames read from the TAP
        // device (MTU-sized), and transop_encode_aes() overflows its N2N_PKT_BUF_SIZE assembly buffer
        // for plaintexts within 16 bytes of that size
        int enc_len = (len <= MAX_TAP_FRAME) ? op.fwd(&op, enc, 2 * N2N_PKT_BUF_SIZE, in, len, mac) : 0;
        if(enc_len > 0) {
            int dec_len = op.rev(&op, dec, N2N_PKT_BUF_SIZE, enc, enc_len, mac);
            if((dec_len != (int)len) || (memcmp(dec, payload, len) != 0)) {
                abort();
            }
        }
    }

    free(in);
    free(out);
    free(enc);
    free(dec);
    op.deinit(&op);

    return 0;
}
