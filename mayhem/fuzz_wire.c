// Wire-format decoders: decode_common, then the message-specific decoder the
// supernode/edge would pick from the packet code (src/sn_utils.c, src/edge_utils.c).
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "n2n.h"
#include "n2n_wire.h"

int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size) {

    // receive buffers in n2n are N2N_PKT_BUF_SIZE bytes, and the receive paths drop anything shorter
    // than the 24-byte common header before decoding (src/sn_utils.c, src/edge_utils.c)
    if((size < 24) || (size > N2N_PKT_BUF_SIZE)) {
        return -1;
    }

    // exact-size copy so ASan sees reads past the end of the packet
    uint8_t *buf = (uint8_t *)malloc(size ? size : 1);
    if(!buf) {
        return -1;
    }
    memcpy(buf, data, size);

    n2n_common_t cmn;
    size_t rem = size;
    size_t idx = 0;

    if(decode_common(&cmn, buf, &rem, &idx) < 0) {
        free(buf);
        return -1;
    }

    switch(cmn.pc) {
        case MSG_TYPE_REGISTER: {
            n2n_REGISTER_t reg;
            decode_REGISTER(&reg, &cmn, buf, &rem, &idx);
            break;
        }
        case MSG_TYPE_REGISTER_ACK: {
            n2n_REGISTER_ACK_t ack;
            decode_REGISTER_ACK(&ack, &cmn, buf, &rem, &idx);
            break;
        }
        case MSG_TYPE_REGISTER_SUPER: {
            n2n_REGISTER_SUPER_t reg;
            decode_REGISTER_SUPER(&reg, &cmn, buf, &rem, &idx);
            break;
        }
        case MSG_TYPE_UNREGISTER_SUPER: {
            n2n_UNREGISTER_SUPER_t unreg;
            decode_UNREGISTER_SUPER(&unreg, &cmn, buf, &rem, &idx);
            break;
        }
        case MSG_TYPE_REGISTER_SUPER_ACK: {
            n2n_REGISTER_SUPER_ACK_t ack;
            uint8_t tmpbuf[REG_SUPER_ACK_PAYLOAD_SPACE];
            decode_REGISTER_SUPER_ACK(&ack, &cmn, buf, &rem, &idx, tmpbuf);
            break;
        }
        case MSG_TYPE_REGISTER_SUPER_NAK: {
            n2n_REGISTER_SUPER_NAK_t nak;
            decode_REGISTER_SUPER_NAK(&nak, &cmn, buf, &rem, &idx);
            break;
        }
        case MSG_TYPE_PACKET: {
            n2n_PACKET_t pkt;
            decode_PACKET(&pkt, &cmn, buf, &rem, &idx);
            break;
        }
        case MSG_TYPE_PEER_INFO: {
            n2n_PEER_INFO_t pi;
            decode_PEER_INFO(&pi, &cmn, buf, &rem, &idx);
            break;
        }
        case MSG_TYPE_QUERY_PEER: {
            n2n_QUERY_PEER_t qp;
            decode_QUERY_PEER(&qp, &cmn, buf, &rem, &idx);
            break;
        }
        default: {
            // codes without a dedicated decoder: the socket encoding is still reachable
            n2n_sock_t sock;
            decode_sock(&sock, buf, &rem, &idx);
            break;
        }
    }

    free(buf);
    return 0;
}
