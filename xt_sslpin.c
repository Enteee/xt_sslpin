/*
 * xt_sslpin.c
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

#include <string.h>

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/fs.h>

#include <linux/hashtable.h>

#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/seq_file.h>

#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/netfilter/x_tables.h>
#include <linux/skbuff.h>
#include <linux/highmem.h>
#include <linux/netfilter/nf_conntrack_common.h>
#include <net/netfilter/nf_conntrack_ecache.h>

#include "xt_sslpin.h"
#include "hexutils.h"
#include "ipfragment.h"
#include "xt_globals.h"
#include "xt_sslpin_connstate.h"
#include "xt_sslpin_sslparser.h"

MODULE_AUTHOR       ( "Enteee (duckpond.ch) ");
MODULE_DESCRIPTION  ( "xtables: match SSL/TLS certificate finger prints" );
MODULE_LICENSE      ( "GPL" );
MODULE_ALIAS        ( "ipt_sslpin" );

/* forward decls */
static struct nf_ct_event_notifier  sslpin_conntrack_notifier;
static struct xt_match              sslpin_mt_reg               __read_mostly;
static struct kobject *             sslpin_kobj                 __read_mostly;
static struct kmem_cache            *cert_finger_print_cache    __read_mostly;

typedef __u8 finger_print[20]; // 20: 160bit = sizeof(sha1)
typedef int (*sslpin_read_finger_print_cb)(finger_print *fp, int mask);

struct cert_finger_print {
    int                 mask;
    finger_print        fp;
    struct hlist_node   next;
};

#define CERT_FINGER_PRINTS_HASH_BITS 10
DEFINE_HASHTABLE(cert_finger_prints, CERT_FINGER_PRINTS_HASH_BITS);

static ssize_t show_cert_finger_prints(struct kobject *kobj, struct kobj_attribute *attr, char *buf);
static ssize_t add_cert_finger_prints(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count);
static ssize_t rm_cert_finger_prints(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count);

struct cert_finger_print_list {
#define DEF_FINGER_PRINT_LIST(id) {                                                     \
  .name = STR(id),                                                                      \
  .mask = 1 << id,                                                                      \
  .add = __ATTR(                                                                        \
      fpl_ ## id ## _add,                                                               \
      S_IWUSR | S_IRUGO,                                                                \
      show_cert_finger_prints,                                                          \
      add_cert_finger_prints                                                            \
  )                                                                                     \
  .rm = __ATTR(                                                                         \
      fpl_ ## id ## _rm,                                                                \
      S_IWUSR | S_IRUGO,                                                                \
      show_cert_finger_prints,                                                          \
      rm_cert_finger_prints                                                             \
  )                                                                                     \
}
  char *                    name;
  int                       mask;
  struct kobj_attribute     add;
  struct kobj_attribute     rm;
};

struct cert_finger_print_list cert_finger_print_lists[] = {
    DEF_FINGER_PRINT_LIST(1),  DEF_FINGER_PRINT_LIST(2),  DEF_FINGER_PRINT_LIST(3),
};

#define SSLPIN_FINGER_PRINT_LIST_SIZE (sizeof(cert_finger_print_lists)/sizeof(*cert_finger_print_lists))
#define SSLPIN_FINGER_PRINT_LIST_SIZE_MAX (8*sizeof(int))


/* module init function */
static int __init sslpin_mt_init(void)
{
    int ret;
    size_t i;
    
    pr_info("xt_sslpin " XT_SSLPIN_VERSION " (SSL/TLS pinning)\n");
    
    if(SSLPIN_FINGER_PRINT_LIST_SIZE > SSLPIN_FINGER_PRINT_LIST_SIZE_MAX){
        pr_err("xt_sslpin: too many finger print lists defined. recompile the module.\n");
        ret = -1;
        goto err;
    }

    sslpin_hash = crypto_alloc_shash(XT_SSLPIN_HASH_ALGO, 0, CRYPTO_ALG_TYPE_SHASH);
    if(IS_ERR(sslpin_hash)){
        pr_err("xt_sslpin: coult not allocate hashing metadata\n");
        ret = PTR_ERR(sslpin_hash);
        goto err_crypto_alloc_shash;
    }

    sslpin_kobj = kobject_create_and_add(XT_SSLPIN_KOBJ_NAME, kernel_kobj);
    if(!sslpin_kobj){
        pr_err("xt_sslpin: could not create kobject " XT_SSLPIN_KOBJ_NAME "\n");
        ret = EINVAL;
        goto err_create_kobj;
    }

    for(i = 0; i < SSLPIN_FINGER_PRINT_LIST_SIZE; ++i){
        struct cert_finger_print_list * fpl = &(cert_finger_print_lists[i]);
        ret = sysfs_create_file(sslpin_kobj, &(fpl->add.attr));
        if(ret){
            pr_err("xt_sslpin: failed to create certificate finger print add-api (name = %s)\n", fpl->name);
            ret = EINVAL;
            goto err_finger_print_sysfs;
        }
        ret = sysfs_create_file(sslpin_kobj, &(fpl->rm.attr));
        if(ret){
            pr_err("xt_sslpin: failed to create certificate finger print rm-api (name = %s)\n", fpl->name);
            ret = EINVAL;
            goto err_finger_print_sysfs;
        }
    }

    cert_finger_print_cache = kmem_cache_create("xt_sslpin_cert_finger_print_cache", sizeof(struct cert_finger_print), 0, 0, NULL);
    if(!cert_finger_print_cache){
        pr_err("xt_sslpin: could not allocate cert_finger_print_cache");
        ret = ENOMEM;
        goto err_cert_finger_print_cache_init;
    }

    if (!sslpin_connstate_cache_init(sslpin_hash)) {
        pr_err("xt_sslpin: could not allocate sslpin_connstate cache\n");
        ret = ENOMEM;
        goto err_connstate_cache_init;
    }

    ret = nf_conntrack_register_notifier(&init_net, &sslpin_conntrack_notifier);
    if (ret < 0) {
        pr_err("xt_sslpin: could not register conntrack event listener\n");
        goto err_conntrack_register_notifier;
    }

    ret = xt_register_match(&sslpin_mt_reg);
    if (ret != 0) {
        pr_err("xt_sslpin: error registering sslpin match\n");
        goto err_xt_register_match;
    }

    return ret;

err_xt_register_match:
    nf_conntrack_unregister_notifier(&init_net, &sslpin_conntrack_notifier);
err_conntrack_register_notifier:
    sslpin_connstate_cache_destroy();
err_connstate_cache_init:
    kmem_cache_destroy(cert_finger_print_cache);
err_cert_finger_print_cache_init:
err_finger_print_sysfs:
    kobject_put(sslpin_kobj);
err_create_kobj:
    crypto_free_shash(sslpin_hash);
err_crypto_alloc_shash:
err:
    return ret;

}

/* module exit function */
static void __exit sslpin_mt_exit(void){
    int bkt;
    struct cert_finger_print *i

    hash_for_each(cert_finger_prints, bkt, next, i){
        kmem_cache_free(i);
    }
    xt_unregister_match(&sslpin_mt_reg);
    nf_conntrack_unregister_notifier(&init_net, &sslpin_conntrack_notifier);
    sslpin_connstate_cache_destroy();
    kmem_cache_destroy(cert_finger_print_cache);
    kobject_put(sslpin_kobj);
    crypto_free_shash(sslpin_hash);

    pr_info("xt_sslpin: " XT_SSLPIN_VERSION " unloaded\n");
}


/* module instance/rule destroy
 * when a rule is added or removed, sslpin_mt_check() will first be called once for each remaining rule,
 * then sslpin_mt_destroy() will be called */
static void sslpin_mt_destroy(const struct xt_mtdtor_param *par)
{
    spin_lock_bh(&sslpin_mt_lock);
    sslpin_mt_checked_after_destroy = false;
    spin_unlock_bh(&sslpin_mt_lock);
}


/* validate options passed in from usermode */
static int sslpin_mt_check(const struct xt_mtchk_param *par)
{
    struct sslpin_mtruleinfo *mtruleinfo = par->matchinfo;
    /* sanity check input options */
    if(mtruleinfo->fpl_id <= 0 || mtruleinfo->fpl_id > SSLPIN_FINGER_PRINT_LIST_SIZE){
        pr_err("invalid finger print list id\n");
        return EINVAL;
    }

    /* update sslpin_mt_has_debug_rules */
    spin_lock_bh(&sslpin_mt_lock);
    if (likely(sslpin_mt_checked_after_destroy)) {
        if (unlikely(sslpin_debug_enabled(mtruleinfo))) {
            sslpin_mt_has_debug_rules = true;
        }
    } else {
        sslpin_mt_has_debug_rules = mtruleinfo->flags & SSLPIN_RULE_FLAG_DEBUG;
        sslpin_mt_checked_after_destroy = true;
    }
    spin_unlock_bh(&sslpin_mt_lock);

    return 0;
}

static int sslpin_add_cert_finger_print(finger_print *fp, int mask){
    int ret = 0;
    struct cert_finger_print * i;

    spin_lock_bh(&sslpin_mt_lock);

    hash_for_each_possible(cert_finger_prints, i, next, *fp){
        if(!memcmp(*fp, i->fp, sizeof(*fp))){
            // found: add to mask
            i->mask |= mask;

            goto out;
        }
    }
    // not found: add new finger print to hashmap
    i = kmem_cache_zalloc(sslpin_finger_print_cache, GFP_ATOMIC);
    if(!i){
        pr_err("failed allocating space for new finger print\n");

        ret = ENOMEM;
        goto out;
    }
    i.mask = mask;
    memcpy(i.fp, *fp, SSLPINT_FINGER_PRINT_SIZE);
    hash_add(cert_finger_prints, &(i.next), i.fp);

out:
    spin_unlock_bh(&sslpin_mt_lock);
    return ret;
}

static int sslpin_remove_cert_finger_print(finger_print *fp, int mask){
    int ret = EINVAL; // default: finger print not found
    struct cert_finger_print * i;
    spin_lock_bh(&sslpin_mt_lock);

    hash_for_each_possible(cert_finger_prints, i, next, *fp){
        if(!memcmp(*fp, i->fp, sizeof(*fp))){
            // found: unmask
            i->mask &= ~mask;
            if(!i->mask){
                // empty mask: remove cert finger print
                hash_del(&i->next);
                kmem_cache_free(i);
            }

            ret = 0;
            goto out;
        }
    }

out:
    spin_unlock_bh(&sslpin_mt_lock);
    return ret;
}

static ssize_t sslpin_read_finger_print(const char *buf, size_t count, sslpin_read_finger_print_cb cb, int mask){
    size_t i = 0;
    finger_print fp = {0};
    size_t fp_pos = 0; 

    for(i = 0; i < count ; ++i){
        __u8 val = hex2int(buf[i]);

        if(val > 15){
            pr_err("skipping invalid hex char in certificate finger print: %c\n", buf[i]);
            continue;
        }

        fp[fp_pos] = val;
        pos = (++pos) % sizeof(fp);
        if(!pos){
            if(cb(&fp, mask)){
                return i;
            }
        }
    }
    return i;
}

static ssize_t add_cert_finger_prints(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count){
    struct cert_finger_print_list *fpl = container_of(attr, struct cert_finger_print_list, add);
    return sslpin_read_finger_print(buf, count, sslpin_add_cert_finger_print, fpl->mask);
}

static ssize_t rm_cert_finger_prints(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count){
    struct cert_finger_print_list *fpl = container_of(attr, struct cert_finger_print_list, rm);
    return sslpin_read_finger_print(buf, count, sslpin_remove_cert_finger_print, fpl->mask);
}

static ssize_t show_cert_finger_prints(struct kobject *kobj, struct kobj_attribute *attr, char *buf){
    // TODO: implement
    return sprintf(buf, "something something, dark side!\n");
}

/* compare rule specification against parsed certificate / public key */
static bool sslpin_match_certificate(const struct sslpin_mtruleinfo * const mtruleinfo,
            const struct sslparser_ctx * const parser_ctx){
    const bool invert = mtruleinfo->flags & SSLPIN_RULE_FLAG_INVERT;

    return !invert;
}

void cert_finger_print_cb(const __u8 * const val, void * data){
    pr_info("xt_sslpin: cert_finger_print_cb called!");
}

/*
 * main packet matching function
 *
 * Per connection, the incoming handshake data is parsed once across all -m sslpin iptables rules;
 * upon receiving the SSL/TLS handshake ChangeCipherSpec message, the parsed certificate is checked by all rules.
 *
 * After this, the connection is marked as "finished", and xt_sslpin will not do any further checking.
 * (Re-handshaking will not be checked in order to incur minimal overhead, and as the server has already proved
 * its identity).
 *
 * Up until the ChangeCipherSpec message is received, xt_sslpin will drop out-of-order TCP segments to
 * parse the data linearly without buffering. Conntrack takes care of IP fragment reassembly up-front, but packets
 * can still have non-linear memory layout; see skb_is_nonlinear().
 *
 * If SYN is received on a time-wait state conn/flow, conntrack will destroy the old cf_conn
 * and create a new cf_conn. Thus, our per-conn state transitions are simply new->open->destroyed (no reopen).
 *
 * Todo:
 *   - ECParameters/namedCurve pinning in addition to current alg+pubkey pinning
 *   - Optional buffering for reordered TCP segments during handshake (no RTT penalty / overhead)
 *   - TCP Fast Open (TFO) support (+ protect against spoofed TFO SYN/ACKs when has not been requested,
 *     but this should be handled by checking sequence numbers (SYN/ACK data accounted for in the following
 *     packets))
 *   - Supported TCP Options verification to ensure xp_sslpin is always in sync. with the TCP stack.
 *     Could pass all packets through an internal instance of the TCP stack before parsing payload data.
 *   - IPv6 support
 *   - Consider using the Linux ASN.1 compiler/decoder
 */
static bool sslpin_mt(const struct sk_buff *skb, struct xt_action_param *par)
{
    const struct sslpin_mtruleinfo * const mtruleinfo = par->matchinfo;
    const bool debug_enabled = sslpin_debug_enabled(mtruleinfo);
    const struct iphdr *ip;
    const struct tcphdr *tcp;
    struct sslpin_connstate *state;
    __u32 tcp_seq, data_len, nonpaged_len, i, num_frags;
    __u8 *data;
    skb_frag_t *frag;
    int frag_size;
    sslparser_res_t res;
    bool matched;

    /* check that conntrack flow binding is provided */
    if (unlikely(!skb->nfct)) {
        par->hotdrop = true;
        if (unlikely(debug_enabled)) {
            pr_err("xt_sslpin: no conntrack data (conntrack not enabled?) - dropping packet!\n");
        }
        return false;
    }

    /* check connection state - only handle established replies */
    if (unlikely(skb->nfctinfo != IP_CT_ESTABLISHED_REPLY)) {
        return false;
    }

    /* acquire module-wide lock */
    spin_lock_bh(&sslpin_mt_lock);

    /* lookup sslpin_connstate for connection */
    state = sslpin_connstate_find_or_init((struct nf_conn *)skb->nfct);

    if (unlikely(!state)) {
        spin_unlock_bh(&sslpin_mt_lock);
        par->hotdrop = true;
        if (unlikely(debug_enabled)) {
            pr_err("xt_sslpin: unable to allocate sslpin_connstate - dropping packet!\n");
        }
        return false;
    }

    /* check if this connection has been marked as FINISHED (certificate has been checked
     * or connection was already established when xt_sslpin was loaded (SYN/ACK not seen) */
    if (likely(state->state == SSLPIN_CONNSTATE_FINISHED)) {
        spin_unlock_bh(&sslpin_mt_lock);
        return false;
    }

    /* check if this connection has been marked as INVALID (e.g. invalid SSL/TLS/x509 data or parser error) */
    if (unlikely(state->state == SSLPIN_CONNSTATE_INVALID)) {
        spin_unlock_bh(&sslpin_mt_lock);
        par->hotdrop = true;
        return false;
    }

    /* get IP header */
    ip = ip_hdr(skb);
    if (unlikely(!ip)) {
        spin_unlock_bh(&sslpin_mt_lock);
        par->hotdrop = true;
        if (unlikely(debug_enabled)) {
            pr_err("xt_sslpin: no IP header - dropping packet!\n");
        }
        return false;
    }

    /* require IPv4 */
    if (unlikely(ip->version != 4)) {
        spin_unlock_bh(&sslpin_mt_lock);
        par->hotdrop = true;
        if (unlikely(debug_enabled)) {
            pr_err("xt_sslpin: IPv6 not yet supported\n");
        }
        return false;
    }

    /* check protocol TCP */
    if (unlikely(ip->protocol != IPPROTO_TCP)) {
        spin_unlock_bh(&sslpin_mt_lock);
        par->hotdrop = true;
        if (unlikely(debug_enabled)) {
            pr_err("xt_sslpin: unknown IP protocol %d - dropping packet!\n", ip->protocol);
        }
        return false;
    }

    /* check for fragment offset > 0 or "more fragments" bit set */
    if (unlikely(is_ip_fragment(par->fragoff | ip->frag_off))) {
        spin_unlock_bh(&sslpin_mt_lock);
        par->hotdrop = true;
        if (unlikely(debug_enabled)) {
            pr_err("xt_sslpin: IP fragment seen (conntrack not enabled?) - dropping packet!\n");
        }
        return false;
    }

    /* get TCP header */
    tcp = (struct tcphdr*)((__u32*)ip + ip->ihl);
    tcp_seq = ntohl(tcp->seq);
    data_len = ntohs(ip->tot_len) - (tcp->doff << 2) - (ip->ihl << 2);

    /* check for SYN/ACK on new connections */
    if (unlikely(tcp->syn)) {
        if (unlikely(data_len)) {
            spin_unlock_bh(&sslpin_mt_lock);
            par->hotdrop = true;
            if (unlikely(debug_enabled)) {
                pr_err("xt_sslpin: received SYN/ACK packet with data!? dropping packet"
                    " (TCP Fast Open not current supported by xt_sslpin)\n");
            }
            return false;
        }

        if (unlikely(!tcp->ack)) {
            state->state = SSLPIN_CONNSTATE_INVALID;
            spin_unlock_bh(&sslpin_mt_lock);
            par->hotdrop = true;
            if (unlikely(debug_enabled)) {
                pr_err("xt_sslpin: received SYN packet (without ACK)"
                    " - dropping packet and marking connection as invalid\n");
            }
            return false;
        }

        if (unlikely(state->state >= SSLPIN_CONNSTATE_GOT_DATA)) {
            state->state = SSLPIN_CONNSTATE_INVALID;
            if (unlikely(state->parser_ctx)) {
                sslpin_connstate_unbind_parser(state);
            }
            spin_unlock_bh(&sslpin_mt_lock);
            par->hotdrop = true;
            if (unlikely(debug_enabled)) {
                pr_err("xt_sslpin: received SYN/ACK for connection that has received data"
                    " - dropping packet and marking connection as invalid\n");
            }
            return false;
        }

        if (unlikely(debug_enabled && (state->state == SSLPIN_CONNSTATE_GOT_SYNACK))
            && (tcp_seq != state->last_seq))
        {
            pr_info("xt_sslpin: received duplicate SYN/ACK with different seq\n");
        }

        /* valid SYN/ACK connection establishment */
        state->state = SSLPIN_CONNSTATE_GOT_SYNACK;
        state->last_seq = tcp_seq;
        state->last_len = 1;        /* SYN phantom byte */
        spin_unlock_bh(&sslpin_mt_lock);
        return false;
    }

    /* check for connections without SYN/ACK seen (already established when xt_sslpin was loaded) */
    if (unlikely(state->state < SSLPIN_CONNSTATE_GOT_SYNACK)) {
        state->state = SSLPIN_CONNSTATE_FINISHED;
        spin_unlock_bh(&sslpin_mt_lock);
        if (unlikely(debug_enabled)) {
            pr_err("xt_sslpin: SYN/ACK not seen for connection (already established when xt_sslpin was loaded)"
                " - ignoring connection\n");
        }
        return false;
    }

    /* handle duplicated packets (also when xt_sslpin is invoked once per rule with the same packet) */
    if (likely((tcp_seq == state->last_seq) && (ip->id == state->last_ipid) && (data_len == state->last_len))) {
        if (unlikely((state->state != SSLPIN_CONNSTATE_CHECK_RULES) || (!state->parser_ctx))) {
            /* packet data was already parsed, and a certificate was not seen */
            spin_unlock_bh(&sslpin_mt_lock);
            return false;
        }
        /* fall through to certificate handling */
    } else {
        /* if previous state is SSLPIN_CONNSTATE_CHECK_RULES, transition to SSLPIN_CONNSTATE_FINISHED */
        if (unlikely(state->state == SSLPIN_CONNSTATE_CHECK_RULES)) {
            if (likely(state->parser_ctx)) {
                sslpin_connstate_unbind_parser(state);
            }
            state->state = SSLPIN_CONNSTATE_FINISHED;
            spin_unlock_bh(&sslpin_mt_lock);
            return false;
        }

        /* new packet - check TCP sequence number - drop out-of-order packets */
        if (unlikely(tcp_seq != state->last_seq + state->last_len)) {
            if (unlikely(debug_enabled)) {
                pr_err("xt_sslpin: out-of-order TCP segment (expecting seq 0x%08x, packet has 0x%08x)"
                    " - dropping packet\n",
                    state->last_seq + state->last_len,
                    tcp_seq);
            }
            spin_unlock_bh(&sslpin_mt_lock);
            par->hotdrop = true;
            return false;
        }

        /* sanity check TCP segment length */
        if (unlikely(data_len > 1 << 30)) {
            spin_unlock_bh(&sslpin_mt_lock);
            par->hotdrop = true;
            if (unlikely(debug_enabled)) {
                pr_err("xt_sslpin: data_len == %d - dropping packet!\n", data_len);
            }
            return false;
        }

        /* update seq */
        state->last_seq = tcp_seq;
        state->last_len = data_len;
        state->last_ipid = ip->id;

        /* exit for empty packets */
        if (unlikely(!data_len)) {
            spin_unlock_bh(&sslpin_mt_lock);
            return false;
        }

        /* parse new data */
        if (unlikely(state->state < SSLPIN_CONNSTATE_GOT_DATA)) {
            state->state = SSLPIN_CONNSTATE_GOT_DATA;
        }

        /* allocate parser ctx for conn */
        if (unlikely(!state->parser_ctx)) {
            if (unlikely(!sslpin_connstate_bind_parser(state, sslpin_hash, sslpin_mt_has_debug_rules))) {
                state->state = SSLPIN_CONNSTATE_INVALID;
                spin_unlock_bh(&sslpin_mt_lock);
                par->hotdrop = true;
                if (unlikely(debug_enabled)) {
                    pr_err("xt_sslpin: unable to allocate parser context for connection"
                        " - dropping packet and marking connection as invalid\n");
                }
                return false;
            }
            /* register callback */
            SSLPARSER_CTX_REGISTER_CALLBACK(state->parser_ctx, cert_finger_print, cert_finger_print_cb, NULL);
        }

        /* non-paged data */
        nonpaged_len = skb->len - skb->data_len - (tcp->doff << 2) - (ip->ihl << 2);
        data = (__u8 *)tcp + (tcp->doff << 2);
        res = sslparser(state->parser_ctx, data, nonpaged_len);

        if (unlikely((res == SSLPARSER_RES_CONTINUE) && skb_is_nonlinear(skb))) {
            /* paged data */
            num_frags = skb_shinfo(skb)->nr_frags;
            for (i = 0; i < num_frags; i++) {
                frag = &skb_shinfo(skb)->frags[i];
                frag_size = skb_frag_size(frag);
                if (unlikely(frag_size <= 0)) {
                    continue;
                }

                data = kmap_atomic(skb_frag_page(frag));
                res = sslparser(state->parser_ctx, data + frag->page_offset, frag_size);
                kunmap_atomic(data);

                if (unlikely(res != SSLPARSER_RES_CONTINUE)) {
                    break;
                }
            }
        }

        if (likely(res == SSLPARSER_RES_CONTINUE)) {
            spin_unlock_bh(&sslpin_mt_lock);
            return false;
        }

        if (unlikely(res != SSLPARSER_RES_FINISHED)) {
            if (likely(state->parser_ctx)) {
                sslpin_connstate_unbind_parser(state);
            }
            state->state = SSLPIN_CONNSTATE_INVALID;
            spin_unlock_bh(&sslpin_mt_lock);
            par->hotdrop = true;
            if (unlikely(debug_enabled)) {
                pr_warn("xt_sslpin: invalid SSL/TLS/X509 data received"
                    " - dropping packet and marking connection as invalid\n");
            }
            return false;
        }

        /* parser returned certificate - transition connection to SSLPIN_CONNSTATE_CHECK_RULES state */
        state->state = SSLPIN_CONNSTATE_CHECK_RULES;
    }


    /* check if matched */
    matched = likely(state->parser_ctx) && sslpin_match_certificate(mtruleinfo, state->parser_ctx);

    if (unlikely(debug_enabled)) {
        pr_info("xt_sslpin: rule %smatched\n", matched ? "" : "not ");
    }

    spin_unlock_bh(&sslpin_mt_lock);
    return matched;
}


/* conntrack event listener (remove closed conns) */
static int sslpin_conntrack_event(unsigned int events, struct nf_ct_event *item)
{
    struct sslpin_connstate *state;

    if (likely(((events & (1 << IPCT_DESTROY)) == 0) || (!item))) {
        return NOTIFY_DONE;
    }

    // todo: check for IPv4 TCP yes/no without acquiring spinlock or traversing the rb-tree

    spin_lock_bh(&sslpin_mt_lock);

    state = sslpin_connstate_find(item->ct, NULL);
    if (likely(!state)) {
        spin_unlock_bh(&sslpin_mt_lock);
        return NOTIFY_DONE;
    }

    sslpin_connstate_remove(state);
    if (unlikely(sslpin_mt_has_debug_rules)) {
        sslpin_connstate_debug_count();
    }

    spin_unlock_bh(&sslpin_mt_lock);
    return NOTIFY_DONE;
}


/* conntrack event listener registration data */
static struct nf_ct_event_notifier sslpin_conntrack_notifier = {
    .fcn = sslpin_conntrack_event,
};


/* registry information for the match checking functions */
static struct xt_match  sslpin_mt_reg  __read_mostly = {
    .name = "sslpin",
    .revision = 0,
    .family = NFPROTO_IPV4,
    .match = sslpin_mt,
    .checkentry = sslpin_mt_check,
    .destroy = sslpin_mt_destroy,
    .matchsize = XT_ALIGN(sizeof(struct sslpin_mtruleinfo)),
    .me = THIS_MODULE,
};


/* bind module init & exit */
module_init(sslpin_mt_init);
module_exit(sslpin_mt_exit);
