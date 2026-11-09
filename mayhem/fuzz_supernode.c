// Supernode packet handler: process_udp() (src/sn_utils.c) on one datagram, against a freshly
// initialised supernode that has the federation as its only community, as src/supernode.c sets it up.
// process_udp() is static, so the translation unit is included here.
//
// Input layout: byte 0 bit 0 = encrypt the header with the federation key, bit 1 = IPv6 sender;
// byte 1 selects the header length for the encrypted variant; the rest is the datagram.
#include "sn_utils.c"

#include <netinet/in.h>

static void sn_cleanup (n2n_sn_t *sss) {

    struct sn_community *comm, *tmp;
    node_supernode_association_t *assoc, *tmp_assoc;
    n2n_tcp_connection_t *conn, *tmp_conn;

    HASH_ITER(hh, sss->tcp_connections, conn, tmp_conn) {
        HASH_DEL(sss->tcp_connections, conn);
        free(conn);
    }

    HASH_ITER(hh, sss->communities, comm, tmp) {
        clear_peer_list(&comm->edges);
        free(comm->header_encryption_ctx_static);
        free(comm->header_encryption_ctx_dynamic);
        free(comm->header_iv_ctx_static);
        free(comm->header_iv_ctx_dynamic);
        HASH_ITER(hh, comm->assoc, assoc, tmp_assoc) {
            HASH_DEL(comm->assoc, assoc);
            free(assoc);
        }
        HASH_DEL(sss->communities, comm);
        free(comm);
    }
}

int LLVMFuzzerInitialize (int *argc, char ***argv) {

    setTraceLevel(-1);

    return 0;
}

int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size) {

    // the supernode reads datagrams into an N2N_SN_PKTBUF_SIZE buffer
    if((size < 2) || (size - 2 > N2N_SN_PKTBUF_SIZE)) {
        return -1;
    }

    n2n_sn_t sss;
    if(sn_init_defaults(&sss) != 0 || !sss.federation) {
        return -1;
    }
    sss.sock = -1;
    sss.tcp_sock = -1;
    sss.mgmt_sock = -1;
    HASH_ADD_STR(sss.communities, community, sss.federation);

    uint8_t flags = data[0];
    uint8_t selector = data[1];
    size_t len = size - 2;

    uint8_t *pkt = (uint8_t *)malloc(len ? len : 1);
    if(pkt) {
        memcpy(pkt, data + 2, len);

        // packet_header_encrypt() requires packet_len >= 24 and header_len <= packet_len
        if((flags & 1) && (len >= 24)) {
            uint16_t header_len = (uint16_t)(24 + (selector % (len - 23)));
            packet_header_encrypt(pkt, header_len, (uint16_t)len,
                                  sss.federation->header_encryption_ctx_dynamic,
                                  sss.federation->header_iv_ctx_dynamic, time_stamp());
        }

        struct sockaddr_storage sender;
        socklen_t sender_len;
        memset(&sender, 0, sizeof(sender));
        if(flags & 2) {
            struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&sender;
            sa6->sin6_family = AF_INET6;
            sa6->sin6_port = htons(7654);
            sa6->sin6_addr.s6_addr[15] = 1;
            sender_len = sizeof(*sa6);
        } else {
            struct sockaddr_in *sa4 = (struct sockaddr_in *)&sender;
            sa4->sin_family = AF_INET;
            sa4->sin_port = htons(7654);
            sa4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            sender_len = sizeof(*sa4);
        }

        process_udp(&sss, (struct sockaddr *)&sender, sender_len, sss.sock, pkt, len, time(NULL));
        free(pkt);
    }

    sn_cleanup(&sss);
    free(sss.community_file);

    return 0;
}
