/*
 * xt_sslpin.h
 *
 * Copyright (C) 2016 Enteee (duckpond.ch)
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

#ifndef _LINUX_NETFILTER_XT_SSLPIN_H
#define _LINUX_NETFILTER_XT_SSLPIN_H

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

#define XT_SSLPIN_VERSION "2.0"
#define XT_SSLPIN_CERT_FINGERPRINTS_HASHTABLE_SIZE 11 /* half a page */

#define XT_SSLPIN_HASH_ALGO "sha1"

#define XT_SSLPIN_KOBJ_NAME "xt_sslpin"

/* xt_sslpin rule flags */
typedef enum {
    SSLPIN_RULE_FLAG_INVERT       = 1 << 1,
} sslpin_rule_flags_t;


/* xt_sslpin kernel module data
   shared between kernel & userspace up until kernpriv struct (kernel-only private data)
   per rule */
struct sslpin_mtruleinfo {
    sslpin_rule_flags_t           flags;
    int                           fpl_id;
    struct {
    } kernpriv __attribute__((aligned(8)));
};


#define SSLPIN_MTRULEINFO_KERN_SIZE      XT_ALIGN(sizeof(struct sslpin_mtruleinfo))
#define SSLPIN_MTRULEINFO_USER_SIZE      offsetof(struct sslpin_mtruleinfo, kernpriv)

#endif /* _LINUX_NETFILTER_XT_SSLPIN_H */
