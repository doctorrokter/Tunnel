/*
 * wg_session - see wg_session.h. The keypair rotation follows Linux's noise.c (add_new_keypair,
 * wg_noise_received_with_keypair), the replay window wireguard-go's RFC 6479 filter.
 */

#include "wg_session.h"

#include <string.h>

#define BLOCK_BITS  64
#define BLOCK_MASK  (WG_REPLAY_BLOCKS - 1)

typedef char wg_replay_blocks_power_of_two[(WG_REPLAY_BLOCKS & BLOCK_MASK) == 0 ? 1 : -1];

/* --------------------------------------------------------------------- replay window */

void wg_replay_init(wg_replay* w)
{
    memset(w, 0, sizeof(*w));
}

int wg_replay_check(const wg_replay* w, uint64_t counter)
{
    if (counter >= WG_REJECT_AFTER_MESSAGES) return 0;
    if (counter > w->last) return 1;
    if (w->last - counter > WG_REPLAY_WINDOW) return 0;
    return !(w->ring[(counter / BLOCK_BITS) & BLOCK_MASK] & (1ULL << (counter % BLOCK_BITS)));
}

int wg_replay_accept(wg_replay* w, uint64_t counter)
{
    uint64_t block = counter / BLOCK_BITS;
    uint64_t bit, *slot;

    if (counter >= WG_REJECT_AFTER_MESSAGES) return 0;

    if (counter > w->last) {
        /* Slide forward: blocks between the old newest and this one are new ground. A jump past
         * the whole ring clears all of it. */
        uint64_t cur = w->last / BLOCK_BITS;
        uint64_t diff = block - cur;
        uint64_t i;

        if (diff > WG_REPLAY_BLOCKS) diff = WG_REPLAY_BLOCKS;
        for (i = cur + 1; i <= cur + diff; i++) w->ring[i & BLOCK_MASK] = 0;
        w->last = counter;
    } else if (w->last - counter > WG_REPLAY_WINDOW) {
        return 0;
    }

    bit = 1ULL << (counter % BLOCK_BITS);
    slot = &w->ring[block & BLOCK_MASK];
    if (*slot & bit) return 0;
    *slot |= bit;
    return 1;
}

/* --------------------------------------------------------------------- keypairs */

/* Wipes a keypair and gives its index back. NULL is fine. */
static void keypair_drop(wg_session* s, wg_keypair* kp)
{
    if (!kp) return;
    if (s->local && s->local->index_drop) s->local->index_drop(s->local->ctx, kp->local_index);
    wg_wipe(kp, sizeof(*kp));
}

static int slot_in_use(const wg_session* s, const wg_keypair* kp)
{
    return kp == s->next || kp == s->current || kp == s->previous;
}

void wg_session_init(wg_session* s, wg_noise_local* l)
{
    memset(s, 0, sizeof(*s));
    s->local = l;
    s->reject_after_ns = WG_REJECT_AFTER_TIME_NS;
}

void wg_session_add(wg_session* s, const wg_noise_keys* keys, uint64_t now_ns)
{
    wg_keypair* kp = NULL;
    int i;

    if (keys->initiator) {
        /* Our initiation was answered, so the new keys are good to send with at once. */
        keypair_drop(s, s->previous);
        if (s->next) {
            /* A responder keypair that was never confirmed: Linux keeps it as `previous` (packets
             * on it may still come) and lets the old current go. */
            keypair_drop(s, s->current);
            s->previous = s->next;
            s->next = NULL;
        } else {
            s->previous = s->current;
        }
        s->current = NULL;
    } else {
        /* We answered an initiation: wait for its first data. `previous` would be pushed out by
         * the confirmation anyway, so it goes now; an older unconfirmed `next` is superseded. */
        keypair_drop(s, s->next);
        keypair_drop(s, s->previous);
        s->next = NULL;
        s->previous = NULL;
    }

    /* At most one old keypair survived above, so a slot is always free. */
    for (i = 0; i < 3 && !kp; i++)
        if (!slot_in_use(s, &s->slot[i])) kp = &s->slot[i];

    memset(kp, 0, sizeof(*kp));
    memcpy(kp->send_key, keys->send_key, WG_KEY_LEN);
    memcpy(kp->recv_key, keys->recv_key, WG_KEY_LEN);
    kp->local_index = keys->local_index;
    kp->remote_index = keys->remote_index;
    kp->initiator = keys->initiator;
    kp->birth_ns = now_ns;
    kp->send_valid = 1;
    kp->recv_valid = 1;

    if (keys->initiator) s->current = kp;
    else                 s->next = kp;
}

wg_keypair* wg_session_find(wg_session* s, uint32_t local_index)
{
    if (s->current && s->current->local_index == local_index) return s->current;
    if (s->next && s->next->local_index == local_index) return s->next;
    if (s->previous && s->previous->local_index == local_index) return s->previous;
    return NULL;
}

/* The initiator has used the responder's `next`: it becomes `current`. */
static void confirm_next(wg_session* s)
{
    keypair_drop(s, s->previous);
    s->previous = s->current;
    s->current = s->next;
    s->next = NULL;
}

void wg_session_expire(wg_session* s)
{
    if (s->next) s->next->send_valid = 0;
    if (s->current) s->current->send_valid = 0;
}

void wg_session_clear(wg_session* s)
{
    keypair_drop(s, s->next);
    keypair_drop(s, s->current);
    keypair_drop(s, s->previous);
    s->next = s->current = s->previous = NULL;
}

/* --------------------------------------------------------------------- data messages */

size_t wg_data_padding(size_t len, size_t mtu)
{
    size_t last = len, padded;

    if (mtu && last > mtu) last %= mtu;
    padded = (last + WG_PADDING_MULTIPLE - 1) & ~(size_t)(WG_PADDING_MULTIPLE - 1);
    if (mtu && padded > mtu) padded = mtu;
    return padded - last;
}

int wg_session_encrypt(wg_session* s, uint8_t* out, size_t* out_len,
                       const uint8_t* pkt, size_t len, size_t pad, uint64_t now_ns)
{
    wg_keypair* kp = s->current;
    uint8_t* body = out + WG_DATA_HEADER_LEN;
    uint64_t counter;

    if (!kp || !kp->send_valid) return 0;
    if (now_ns - kp->birth_ns >= s->reject_after_ns || kp->send_counter >= WG_REJECT_AFTER_MESSAGES) {
        kp->send_valid = 0;
        return 0;
    }
    /* The counter is spent even if sealing fails below: a gap is harmless, a reuse is not. */
    counter = kp->send_counter++;

    if (len && body != pkt) memmove(body, pkt, len);
    memset(body + len, 0, pad);
    wg_store32(out + WG_DATA_OFF_TYPE, WG_MSG_DATA);
    wg_store32(out + WG_DATA_OFF_RECEIVER, kp->remote_index);
    wg_store64(out + WG_DATA_OFF_COUNTER, counter);
    if (!wg_aead_encrypt(body, kp->send_key, counter, body, len + pad, NULL, 0)) return 0;

    *out_len = WG_DATA_MSG_LEN(len + pad);
    return 1;
}

int wg_session_decrypt(wg_session* s, uint8_t* out, const uint8_t* msg, size_t len,
                       uint64_t now_ns, wg_recv* rv)
{
    wg_keypair* kp;
    uint64_t counter;
    size_t ctlen;

    memset(rv, 0, sizeof(*rv));

    if (len < WG_DATA_MSG_LEN(0)) {
        rv->drop = WG_DROP_MALFORMED;
        return 0;
    }
    kp = wg_session_find(s, wg_load32(msg + WG_DATA_OFF_RECEIVER));
    if (!kp) {
        rv->drop = WG_DROP_UNKNOWN_INDEX;
        return 0;
    }
    counter = wg_load64(msg + WG_DATA_OFF_COUNTER);
    if (!kp->recv_valid || now_ns - kp->birth_ns >= s->reject_after_ns) {
        kp->recv_valid = 0;
        rv->drop = WG_DROP_EXPIRED;
        return 0;
    }
    if (counter >= WG_REJECT_AFTER_MESSAGES) {
        rv->drop = WG_DROP_EXPIRED;
        return 0;
    }
    /* A replay costs no decryption. The window itself moves only after the tag checks out. */
    if (!wg_replay_check(&kp->replay, counter)) {
        rv->drop = WG_DROP_REPLAY;
        return 0;
    }

    ctlen = len - WG_DATA_HEADER_LEN;
    if (!wg_aead_decrypt(out, kp->recv_key, counter, msg + WG_DATA_HEADER_LEN, ctlen, NULL, 0)) {
        rv->drop = WG_DROP_FORGED;
        return 0;
    }
    if (!wg_replay_accept(&kp->replay, counter)) {      /* cannot fail after the check above */
        wg_wipe(out, ctlen - WG_TAG_LEN);
        rv->drop = WG_DROP_REPLAY;
        return 0;
    }

    if (kp == s->next) {
        confirm_next(s);
        rv->confirmed = 1;
    }
    rv->len = ctlen - WG_TAG_LEN;
    return 1;
}
