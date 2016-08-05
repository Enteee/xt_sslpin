/*
 * libxt_sslpin.c
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

#include <xtables.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>

#include "xt_sslpin.h"
#include "hexutils.h"


/* parameter definitions */
static const struct option sslpin_mt_opts[] = {
    { .name = "debug",      .has_arg = false,   .val = 'd' },
    { NULL },
};

/* xtables_register_match() module init callback */         /* not needed */
/*
    static void sslpin_mt_init(struct xt_entry_match *match)
    {
    }
*/


/* invoked by iptables -m sslpin -h */
static void sslpin_mt_help(void)
{
    printf(
        "sslpin match options:\n"
        "    --debug      verbose mode (see kernel log)\n"
        "\n"
        );
}


/* parse options */
static int sslpin_mt_parse(int c, char **argv, int invert, unsigned int *flags, const void *entry,
            struct xt_entry_match **match)
{
    struct sslpin_mtruleinfo *mtruleinfo = (struct sslpin_mtruleinfo*)(*match)->data;

    switch (c) {
        case 'd':
            mtruleinfo->flags |= SSLPIN_RULE_FLAG_DEBUG;
            break;
        default:
            return false;
    }

    return true;
}


/* check options after parsing */
static void sslpin_mt_check(unsigned int flags)
{
//    if (flags == 0) {
//        xtables_error(PARAMETER_PROBLEM, "sslpin: must specify a name");
//    }
}


/* invoked for iptables --list;  print options in human-friendly format */
static void sslpin_mt_print(const void *entry, const struct xt_entry_match *match, int numeric)
{
    struct sslpin_mtruleinfo *mtruleinfo = (struct sslpin_mtruleinfo*)(match->data);

    printf(" sslpin:");

    if (mtruleinfo->flags & SSLPIN_RULE_FLAG_DEBUG) {
        printf(" debug");
    }
    if (mtruleinfo->flags & SSLPIN_RULE_FLAG_INVERT) {
        printf(" !");
    }
}


/* invoked for iptables-save and iptables --list-rules;  print options in exact format */
static void sslpin_mt_save(const void *entry, const struct xt_entry_match *match)
{
    struct sslpin_mtruleinfo *mtruleinfo = (struct sslpin_mtruleinfo*)(match->data);

    if (mtruleinfo->flags & SSLPIN_RULE_FLAG_DEBUG) {
        printf(" --debug");
    }
    if (mtruleinfo->flags & SSLPIN_RULE_FLAG_INVERT) {
        printf(" !");
    }
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
/*    .init           = sslpin_mt_init, */      /* not needed */
};


/* init function (module loaded by iptables) */
void _init(void)
{
    xtables_register_match(&sslpin_mt_reg);
}

