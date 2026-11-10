/*
 * wg_codec - see wg_codec.h.
 */

#include "wg_codec.h"
#include "wg_msg.h"

int wg_codec_length_ok(uint32_t type, size_t len)
{
    switch (type) {
    case WG_MSG_INITIATION: return len == WG_INIT_LEN;
    case WG_MSG_RESPONSE:   return len == WG_RESP_LEN;
    case WG_MSG_COOKIE:     return len == WG_COOKIE_MSG_LEN;
    case WG_MSG_DATA:       return len >= WG_DATA_HEADER_LEN + 16;
    default:                return 0;
    }
}

/* The type field is the message type; nothing else is on the wire. */
static int wireguard_classify(void* st, uint8_t* dgram, size_t len, uint32_t* type, size_t* offset,
                              size_t* msg_len)
{
    (void)st;
    if (len < 4) return 0;
    *type = wg_load32(dgram);
    *offset = 0;
    *msg_len = len;
    return wg_codec_length_ok(*type, len);
}

const wg_codec_ops wg_codec_wireguard = {
    "wireguard",
    NULL,                   /* stamp: canonical */
    NULL,                   /* wrap: as is */
    NULL,                   /* before_initiation: nothing */
    wireguard_classify,
    NULL,                   /* padding: WireGuard's */
    NULL,                   /* authentic: nothing to learn */
};
