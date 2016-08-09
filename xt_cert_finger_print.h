/*
 * xt_cert_finger_print.h
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

#ifndef _LINUX_NETFILTER_XT_SSLPIN_CERT_FINGER_PRINT_H
#define _LINUX_NETFILTER_XT_SSLPIN_CERT_FINGER_PRINT_H

#define SSLPIN_CERT_FINGER_PRINTS_HASH_BITS 10
#define SSLPIN_FINGER_PRINT_SIZE 20 // 20*8 = 160bit = sizeof(sha1)
#define SSLPIN_FINGER_PRINT_STR_SIZE 40 // 2 * SSLPIN_FINGER_PRINT_SIZE


typedef __u8 finger_print[SSLPIN_FINGER_PRINT_SIZE];
typedef char finger_print_str[SSLPIN_FINGER_PRINT_STR_SIZE + 1]; // string representation of a finger print

typedef int (*sslpin_read_finger_print_cb)(finger_print* fp, int mask);


struct cert_finger_print {
    int                 mask;
    finger_print        fp;
    struct hlist_node   next;
};

struct cert_finger_print_list {
#define DEF_CERT_FINGER_PRINT_LIST(id) {                                                \
  .name = STR(id),                                                                      \
  .mask = 1 << (id - 1),                                                                \
  .add = __ATTR(                                                                        \
      fpl_ ## id ## _add,                                                               \
      S_IWUSR | S_IRUGO,                                                                \
      show_sslpin_cert_finger_prints,                                                   \
      add_sslpin_cert_finger_prints                                                     \
  ),                                                                                    \
  .rm = __ATTR(                                                                         \
      fpl_ ## id ## _rm,                                                                \
      S_IWUSR | S_IRUGO,                                                                \
      show_sslpin_cert_finger_prints,                                                   \
      rm_sslpin_cert_finger_prints                                                      \
  )                                                                                     \
}
    char*                     name;
    int                       mask;
    struct kobj_attribute     add;
    struct kobj_attribute     rm;
};


/* forward decls */
static struct kmem_cache*   sslpin_cert_finger_print_cache      __read_mostly;
DEFINE_HASHTABLE(sslpin_cert_finger_prints,          SSLPIN_CERT_FINGER_PRINTS_HASH_BITS);
#define FINGER_PRINT_BUCKET(fp) ((size_t)fp) >> (sizeof(size_t) * 8 - HASH_BITS(sslpin_cert_finger_prints))

static struct cert_finger_print* sslpin_get_cert_finger_print(finger_print* fp) {
    struct cert_finger_print* ret =  NULL;
    struct cert_finger_print* i;

    hlist_for_each_entry(i, &sslpin_cert_finger_prints[FINGER_PRINT_BUCKET(*fp)], next) {
        if (!memcmp(*fp, i->fp, sizeof(*fp))) {
            ret = i;
            goto out;
        }
    }

out:
    return ret;
}

static int sslpin_add_cert_finger_print(finger_print* fp, int mask) {
    int ret = 0;
    struct cert_finger_print* cfp;
    finger_print_str fp_str = {0}; 
    bin2hex(fp_str, *fp, sizeof(*fp));

    spin_lock_bh(&sslpin_mt_lock);

    cfp = sslpin_get_cert_finger_print(fp);
    if (!cfp) {
        // not found: add new finger print to hashmap
        cfp = kmem_cache_zalloc(sslpin_cert_finger_print_cache, GFP_ATOMIC);
        if (!cfp) {
            pr_err("failed allocating space for new finger print\n");

            ret = ENOMEM;
            goto out;
        }
        memcpy(cfp->fp, *fp, sizeof(*fp));
        hlist_add_head(&cfp->next, &sslpin_cert_finger_prints[FINGER_PRINT_BUCKET(*cfp->fp)]);

        pr_info("xt_sslpin: added finger print (mask = %x, fp = %s)\n", mask, fp_str);
    }
    cfp->mask |= mask;


out:
    spin_unlock_bh(&sslpin_mt_lock);
    return ret;
}

static int sslpin_remove_cert_finger_print(finger_print* fp, int mask) {
    int ret = EINVAL; // default: finger print not found
    struct cert_finger_print* cfp;
    finger_print_str fp_str = {0}; 
    bin2hex(fp_str, *fp, sizeof(*fp));

    spin_lock_bh(&sslpin_mt_lock);

    cfp = sslpin_get_cert_finger_print(fp);
    if (cfp) {
        // found: unmask
        cfp->mask &= ~mask;
        if (!cfp->mask) {
            // empty mask: remove cert fcfpnger prcfpnt
            hash_del(&cfp->next);
            kmem_cache_free(sslpin_cert_finger_print_cache, cfp);
        }

        ret = 0;

        pr_info("xt_sslpin: removed finger print (mask = %x, fp = %s)\n", mask, fp_str);
    }

    spin_unlock_bh(&sslpin_mt_lock);
    return ret;
}

static ssize_t sslpin_read_finger_print(const char* buf, size_t count, sslpin_read_finger_print_cb cb, int mask) {
    finger_print fp;
    const char* buf_end = buf + count; 

    // read finger prints
    while(buf + SSLPIN_FINGER_PRINT_STR_SIZE <= buf_end){
        int ret = hex2bin(fp, buf, sizeof(fp));
        if(ret){
            pr_err("invalid finger print hex representation: %." STR(SSLPIN_FINGER_PRINT_STR_SIZE) "s\n", buf);
            goto err_invalid_hex_repr;
        }

        cb(&fp, mask);
        buf += SSLPIN_FINGER_PRINT_STR_SIZE; // next
    }
    return count;

err_invalid_hex_repr:
    return count;
}

static ssize_t add_sslpin_cert_finger_prints(struct kobject* kobj, struct kobj_attribute* attr, const char* buf,
                                             size_t count) {
    struct cert_finger_print_list* fpl = container_of(attr, struct cert_finger_print_list, add);
    return sslpin_read_finger_print(buf, count, sslpin_add_cert_finger_print, fpl->mask);
}

static ssize_t rm_sslpin_cert_finger_prints(struct kobject* kobj, struct kobj_attribute* attr, const char* buf,
                                            size_t count) {
    struct cert_finger_print_list* fpl = container_of(attr, struct cert_finger_print_list, rm);
    return sslpin_read_finger_print(buf, count, sslpin_remove_cert_finger_print, fpl->mask);
}

static ssize_t show_sslpin_cert_finger_prints(struct kobject* kobj, struct kobj_attribute* attr, char* buf) {
    // TODO: implement
    return sprintf(buf, "something something, dark side!\n");
}

struct cert_finger_print_list cert_finger_print_lists[] = {
    DEF_CERT_FINGER_PRINT_LIST(1),  DEF_CERT_FINGER_PRINT_LIST(2),  DEF_CERT_FINGER_PRINT_LIST(3),
};

#define SSLPIN_FINGER_PRINT_LIST_SIZE (sizeof(cert_finger_print_lists)/sizeof(*cert_finger_print_lists))
#define SSLPIN_FINGER_PRINT_LIST_SIZE_MAX (8*sizeof(int))


static int sslpin_cert_finger_print_init(struct kobject* sslpin_kobj) {
    int ret = 0;
    size_t i;

    /**
     * Check if defines are correct: we can't do this during compilation because
     * sizeof won't work in #if
     */
    if (SSLPIN_FINGER_PRINT_LIST_SIZE > SSLPIN_FINGER_PRINT_LIST_SIZE_MAX) {
        pr_err("xt_sslpin: too many finger print lists defined. recompile the module.\n");
        ret = -1;
        goto err_defines;
    }

    for (i = 0; i < SSLPIN_FINGER_PRINT_LIST_SIZE; ++i) {
        struct cert_finger_print_list* fpl = &(cert_finger_print_lists[i]);
        ret = sysfs_create_file(sslpin_kobj, &(fpl->add.attr));
        if (ret) {
            pr_err("xt_sslpin: failed to create certificate finger print add-api (name = %s)\n", fpl->name);
            ret = EINVAL;
            goto err_sysfs;
        }
        ret = sysfs_create_file(sslpin_kobj, &(fpl->rm.attr));
        if (ret) {
            pr_err("xt_sslpin: failed to create certificate finger print rm-api (name = %s)\n", fpl->name);
            ret = EINVAL;
            goto err_sysfs;
        }
    }

    sslpin_cert_finger_print_cache = kmem_cache_create("xt_sslpin_cert_finger_print_cache",
                                                       sizeof(struct cert_finger_print), 0, 0, NULL);
    if (!sslpin_cert_finger_print_cache) {
        pr_err("xt_sslpin: could not allocate cert_finger_print_cache");
        ret = ENOMEM;
        goto err_cache_init;
    }

    return ret;

err_defines:
err_sysfs:
err_cache_init:
    return ret;
}

static void sslpin_cert_finger_print_destroy(void) {
    size_t bkt;
    struct cert_finger_print* i;
    hash_for_each(sslpin_cert_finger_prints, bkt, i, next) {
        kmem_cache_free(sslpin_cert_finger_print_cache, i);
    }
    kmem_cache_destroy(sslpin_cert_finger_print_cache);
}

#endif
