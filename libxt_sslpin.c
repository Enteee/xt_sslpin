/*
 * libxt_sslpin.c
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

#include <xtables.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>

#include "xt_sslpin.h"


/* parameter definitions */
static const struct option sslpin_mt_opts[] = {
    { .name = "debug",      .has_arg = false,   .val = 'd' },
    { .name = "fpl",        .has_arg = true,    .val = 'f' },
    { NULL },
};

/* xtables_register_match() module init callback */

/*
static void sslpin_mt_init(struct xt_entry_match *match)
{
    struct sslpin_mtruleinfo *mtruleinfo = (struct sslpin_mtruleinfo*)(match->data);

}
*/


/* invoked by iptables -m sslpin -h */
static void sslpin_mt_help(void) {
    printf(
        "sslpin match options:\n"
        " [!] --fpl id     finger print list id\n"
        "     --debug      verbose mode (see kernel log)\n"
        "\n"
    );
}


/* parse options */
static int sslpin_mt_parse(int c, char** argv, int invert, unsigned int* flags, const void* entry,
                           struct xt_entry_match** match) {
    char* end;
    struct sslpin_mtruleinfo* mtruleinfo = (struct sslpin_mtruleinfo*)(*match)->data;

    switch (c) {
        case 'f':
            if (*flags) {
                xtables_error(PARAMETER_PROBLEM, "sslpin: --fpl can only be specified once");
                goto err;
            }
            mtruleinfo->fpl_id = strtol(optarg, &end, 10);
            if (optarg == end || mtruleinfo->fpl_id < 0) {
                xtables_error(PARAMETER_PROBLEM, "sslpin: --fpl invalid id argument");
                goto err;
            }
            if (invert) {
                mtruleinfo->flags |= SSLPIN_RULE_FLAG_INVERT;
            }
            *flags = 1;  // id set
            break;
        case 'd':
            mtruleinfo->flags |= SSLPIN_RULE_FLAG_DEBUG;
            break;
        default:
            goto err;
    }

    return 1;

err:
    return -1;
}


/* check options after parsing */
static void sslpin_mt_check(unsigned int flags) {
    if (flags == 0) {
        xtables_error(PARAMETER_PROBLEM, "sslpin: must specify a finger print list");
    }
}


/* invoked for iptables --list;  print options in human-friendly format */
static void sslpin_mt_print(const void* entry, const struct xt_entry_match* match, int numeric) {
    struct sslpin_mtruleinfo* mtruleinfo = (struct sslpin_mtruleinfo*)(match->data);

    printf(" sslpin:");

    if (mtruleinfo->flags & SSLPIN_RULE_FLAG_DEBUG) {
        printf(" debug");
    }
    if (mtruleinfo->flags & SSLPIN_RULE_FLAG_INVERT) {
        printf(" !");
    }
    printf(" %d", mtruleinfo->fpl_id);
}


/* invoked for iptables-save and iptables --list-rules;  print options in exact format */
static void sslpin_mt_save(const void* entry, const struct xt_entry_match* match) {
    struct sslpin_mtruleinfo* mtruleinfo = (struct sslpin_mtruleinfo*)(match->data);

    if (mtruleinfo->flags & SSLPIN_RULE_FLAG_DEBUG) {
        printf(" --debug");
    }
    if (mtruleinfo->flags & SSLPIN_RULE_FLAG_INVERT) {
        printf(" !");
    }
    printf(" %d", mtruleinfo->fpl_id);
}


/* xtables_register_match() module info */
static struct xtables_match sslpin_mt_reg = {
    .name           = "sslpin",
    .family         = NFPROTO_IPV4,
    .version        = XTABLES_VERSION,
    .revision       = 0,
    .size           = SSLPIN_MTRULEINFO_KERN_SIZE,
    .userspacesize  = SSLPIN_MTRULEINFO_USER_SIZE,
    .help           = sslpin_mt_help,
    .parse          = sslpin_mt_parse,
    .final_check    = sslpin_mt_check,
    .print          = sslpin_mt_print,
    .save           = sslpin_mt_save,
    .extra_opts     = sslpin_mt_opts,
//    .init           = sslpin_mt_init,
};


/* init function (module loaded by iptables) */
void _init(void) {
    xtables_register_match(&sslpin_mt_reg);
}

