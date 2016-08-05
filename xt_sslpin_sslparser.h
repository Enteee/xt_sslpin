/*
 * xt_sslpin_sslparser.h
 *
 * Copyright (C) 2010-2013 fredburger (github.com/fredburger)
 *
 * This program is free software; you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program; if not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#ifndef _LINUX_NETFILTER_XT_SSLPIN_SSLPARSER_H
#define _LINUX_NETFILTER_XT_SSLPIN_SSLPARSER_H

#include <linux/err.h>
#include <linux/scatterlist.h>

#include "ssl_tls.h"

typedef enum {
    SSLPARSER_RES_NONE,
    SSLPARSER_RES_CONTINUE,
    SSLPARSER_RES_INVALID,
    SSLPARSER_RES_FINISHED
} sslparser_res_t;


typedef void (*sslparser_hash_cb)(const __u8 * const val, void* data);

#define SSLPARSER_MAX_COMMON_NAME_LEN               SSLPIN_MAX_COMMON_NAME_UTF8_BYTELEN
#define SSLPARSER_MAX_PUBLIC_KEY_BYTELEN            SSLPIN_MAX_PUBLIC_KEY_BYTELEN
#define SSLPARSER_MAX_PUBLIC_KEY_ALG_OID_BYTELEN    SSLPIN_MAX_PUBLIC_KEY_ALG_OID_BYTELEN

#define SSLPARSER_STATE_INVALID                     (__u8)-1
#define SSLPARSER_STATE_FINISHED                    (__u8)-2

struct sslparser_ctx {
    /* Parser state variables */
    __u8        state;
    bool        debug : 1;
    __u8        tls_ver_minor : 4;
    bool        cert_msg_seen : 1;
    __u16       state_remain;
    __u16       a, b, c;
    __u8        record_type;
    __u8        msg_type;
    __u16       record_remain;
    __u16       msg_remain;
    __u16       cert_remain;

    /* Hashing state variables */
    struct {
        struct shash_desc * desc;
        __u8 *              val;
    } hash;

    /* Callbacks */
    struct {
      sslparser_hash_cb     cert_fingerprint;
      void *                cert_fingerprint_data;

#define SSLPARSER_CTX_REGISTER_CALLBACK(ctx, name, callback, data)                \
    ctx->cb.name = callback;                                                      \
    ctx->cb.name ## _data = data;
    } cb;

    /* Parser results */
    struct {
    } results;
};


#pragma push_macro("ul")
#pragma push_macro("l")
#pragma push_macro("invalid")
#pragma push_macro("finished")
#pragma push_macro("need_more_data")
#pragma push_macro("debug")
#pragma push_macro("go_state")
#pragma push_macro("data_remain")
#pragma push_macro("bind_state_remain")
#pragma push_macro("state_remain")
#pragma push_macro("step_proto")
#pragma push_macro("_step_state")
#pragma push_macro("step_state")
#pragma push_macro("step_state_to")


#define ul(x)       unlikely(x)
#define l(x)        likely(x)

#define invalid(fmt, ...)                                                                                           \
    if (ul(state->debug)) {                                                                                         \
        pr_err("xt_sslpin: sslparser: " fmt, ##__VA_ARGS__);                                                        \
    }                                                                                                               \
    state->state = SSLPARSER_STATE_INVALID;                                                                         \
    return SSLPARSER_RES_INVALID;

#define finished()                                                                                                  \
    state->state = SSLPARSER_STATE_FINISHED;                                                                        \
    return SSLPARSER_RES_FINISHED;

#define need_more_data()                                                                                            \
    state->state = statev;                                                                                          \
    return SSLPARSER_RES_CONTINUE;

#define debug(fmt, ...)                                                                                             \
    if (ul(state->debug)) {                                                                                         \
        pr_info("xt_sslpin: sslparser: " fmt, ##__VA_ARGS__);                                                       \
    }

#define go_state(new_state, label)                                                                                  \
    statev = new_state;                                                                                             \
    goto label;

#define data_remain()                                                                                               \
    (data_end - data)

#define bind_state_remain(remain)                                                                                   \
    state->state_remain = remain;                                                                                   \
    state_end = data + remain;

#define state_remain()                                                                                              \
    (state_end - data)

#define step_proto()                                                                                                \
    if (ul(++data == data_end)) {                                                                                   \
        state->state = ++statev;                                                                                    \
        state->state_remain = state_remain();                                                                       \
        need_more_data();                                                                                           \
    }                                                                                                               \
    statev++;

#define _step_state()                                                                                               \
    if (ul(++data > state_end)) {                                                                                   \
        invalid("expected more data");                                                                              \
    }

#define step_state()                                                                                                \
    _step_state();                                                                                                  \
    if (ul(data == data_end)) {                                                                                     \
        state->state = ++statev;                                                                                    \
        state->state_remain = state_remain();                                                                       \
        need_more_data();                                                                                           \
    }                                                                                                               \
    statev++;

#define step_state_to(new_state, label)                                                                             \
    _step_state();                                                                                                  \
    if (ul(data == data_end)) {                                                                                     \
        state->state = statev = new_state;                                                                          \
        state->state_remain = state_remain();                                                                       \
        need_more_data();                                                                                           \
    }                                                                                                               \
    go_state(new_state, label);


static sslparser_res_t sslparser(struct sslparser_ctx * const state, const __u8 *data, const __u32 data_len)
{
    const __u8 *const data_end          = data + data_len;
    const __u8 *state_end               = data + state->state_remain;
    __u8        statev                  = state->state;
    const char *str;

    if (ul(statev >= SSLPARSER_STATE_FINISHED)) {
        return l(statev == SSLPARSER_STATE_FINISHED) ? SSLPARSER_RES_FINISHED : SSLPARSER_RES_INVALID;
    }
    if (ul(!data_len)) {
        need_more_data();
    }

    switch (statev) {

state0_record_begin:
        /* SSL/TLS record: first byte: record type */
        case 0:
            state->record_type = *data;
            if (ul((state->record_type != SSL3_RT_HANDSHAKE) && (state->record_type != SSL3_RT_CHANGE_CIPHER_SPEC))) {
                invalid("invalid SSL/TLS record type %d; expected SSL3_RT_HANDSHAKE\n", state->record_type);
            }
            step_proto();

        /* bytes 1-2: SSL version (major/minor); see ssl_tls.h: SSL3_VERSION */
        case 1:
            if (ul(*data != 3)) {
                invalid("unknown SSL/TLS major version %d\n", *data);
            }
            step_proto();
        case 2:
            if (ul((*data) > 3)) {
                invalid("unknown SSL/TLS minor version %d\n", *data);
            }
            if (l(!state->tls_ver_minor)) {
                state->tls_ver_minor = *data + 1;
            } else if (ul(*data != state->tls_ver_minor - 1)) {
                invalid("records have different SSL/TLS minor versions\n");
            }
            step_proto();

        /* bytes 3-4: Record data length (excluding header) */
        case 3:
            state->record_remain = *data << 8;
            step_proto();
        case 4:
            state->record_remain |= *data;
            bind_state_remain(state->record_remain + 1);
            step_proto();

state5_message_begin:
        /* byte 5: message type: expect Handshake or ChangeCipherSpec */
        case 5:
            if (ul(!data_remain())) {
                debug("message begin: need more data");
                need_more_data();
            }

            state->msg_type = *data;

            /* ChangeCipherSpec record? */
            if (ul(state->record_type == SSL3_RT_CHANGE_CIPHER_SPEC)) {
                if (ul((state->msg_type != 1) || (state_remain() != 1))) {
                    invalid("invalid ChangeCipherSpec record (len = %ld, ccs_proto = %d)\n",
                        (long)state_remain(), state->msg_type);
                }
                debug("ChangeCipherSpec record\n");
                finished();
            }

            /* Handshake record */
            if (ul(state_remain() < 4)) {
                invalid("handshake record len == %ld (minimum is 4)\n", (long)state_remain());
            }
            step_state();

        /* byte 6-8: Handshake message length */
        case 6:
            state->msg_remain = *data << 16;
            step_state();
        case 7:
            state->msg_remain |= *data << 8;
            step_state();
        case 8:
            state->msg_remain |= *data;

            str = sslpin_ssl_handshake_mt_to_string(state->msg_type);
            if (ul(!str)) {
                invalid("unknown handshake message type %d (len = %d)\n", state->msg_type, state->msg_remain);
            }

            debug("%s handshake message (len = %d)\n", str, state->msg_remain);
            if (ul(state->msg_remain > state_remain() - 1)) {
                invalid("message len %d > remaining record len %ld\n", state->msg_remain, (long)state_remain() - 1);
            }

            /* Certificate message? */
            if (ul(state->msg_type == SSL3_MT_CERTIFICATE)) {
                step_state_to(40, state40_parse_certificate_message);
            }

            step_state_to(20, state20_skip_message);

state20_skip_message:
        /* skip over message, then go to either state5_message_begin or state0_record_begin */
        case 20:
            if (ul(data_remain() <= state->msg_remain)) {
                state->msg_remain -= data_remain();
                state->state_remain = state_remain() - data_remain();
                need_more_data();
            }

            data += state->msg_remain;
            if (l(state_remain())) {
                go_state(5, state5_message_begin);
            }

            /* no more messages in record */
            go_state(0, state0_record_begin);

state40_parse_certificate_message:
        /* Certificate message parsing */
        case 40:
            if (ul(state->msg_remain < 32)) {
                invalid("certificate message len == %d\n", state->msg_remain);
            }
            if (ul(state->cert_msg_seen)) {
                invalid("more than one Certificate message\n");
            }

            state->cert_msg_seen = true;
            state->a = *data << 16;
            step_state();
        case 41:
            state->a |= *data << 8;
            step_state();
        case 42:
            state->a |= *data;
            state->msg_remain -= 3;
            if (ul(state->a != state->msg_remain)) {
                invalid("certificates data length %d != msg_remain %d\n", state->a, state->msg_remain);
            }

            state->record_remain = state_remain() - state->msg_remain;
            bind_state_remain(state->msg_remain + 1);

            step_state_to(50, state50_finger_print_certificate);

state50_finger_print_certificate:
        /* parse certificate length (3 bytes) */
        case 50:
            state->cert_remain = *data << 16;
            step_state();
        case 51:
            state->cert_remain |= *data << 8;
            step_state();
        case 52:
            state->cert_remain |= *data;
            if (ul((state->cert_remain > state_remain() - 1))) {
                invalid("certificate data length: %d\n", state->cert_remain);
            }

            if(ul(crypto_shash_init(state->hash.desc) < 0)){
                invalid("faild (re-) iniaializing hash description\n");
            }

            step_state();
        case 53:
            if (ul(data_remain() < state->cert_remain)) {
                state->cert_remain -= data_remain();
                state->state_remain = state_remain() - data_remain();

                if(ul(crypto_shash_update(state->hash.desc, data, data_remain()) < 0)){
                    invalid("hash update failed\n");
                }
                need_more_data();
            }

            if(ul(crypto_shash_update(state->hash.desc, data, state->cert_remain) < 0)){
                invalid("hash update failed\n");
            }

            // hash finished: callback
            if(ul(crypto_shash_final(state->hash.desc, state->hash.val) < 0)){
                invalid("hash final failed\n");
            }

            debug("finger print: %hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n",
                state->hash.val[0],
                state->hash.val[1],
                state->hash.val[2],
                state->hash.val[3],
                state->hash.val[4],
                state->hash.val[5],
                state->hash.val[6],
                state->hash.val[7],
                state->hash.val[8],
                state->hash.val[9],
                state->hash.val[10],
                state->hash.val[11],
                state->hash.val[12],
                state->hash.val[13],
                state->hash.val[14],
                state->hash.val[15],
                state->hash.val[16],
                state->hash.val[17],
                state->hash.val[18],
                state->hash.val[19]
            );
            
            // callback
            if(state->cb.cert_fingerprint){
                state->cb.cert_fingerprint(state->hash.val, state->cb.cert_fingerprint_data);
            }

            data += state->cert_remain - 1;
            if(state_remain() != 1){
                // more certificates: loop
                debug("more certificates\n");
                step_state_to(50, state50_finger_print_certificate);
            }

            // message end
            step_state_to(5, state5_message_begin);
    }

    invalid("error in parser: unhandled state %d\n", statev);
}


#pragma push_macro("step_state_to")
#pragma push_macro("step_state")
#pragma push_macro("_step_state")
#pragma push_macro("step_proto")
#pragma push_macro("state_remain")
#pragma push_macro("bind_state_remain")
#pragma push_macro("data_remain")
#pragma push_macro("go_state")
#pragma push_macro("debug")
#pragma push_macro("need_more_data")
#pragma push_macro("finished")
#pragma push_macro("invalid")
#pragma push_macro("l")
#pragma push_macro("ul")


#endif /* _LINUX_NETFILTER_XT_SSLPIN_SSLPARSER_H */
