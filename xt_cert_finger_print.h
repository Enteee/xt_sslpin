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

#define SSLPIN_FINGER_PRINT_SIZE 20 // 20*8 = 160bit = sizeof(sha1)
#define SSLPIN_FINGER_PRINT_STR_SIZE 40 // 2 * SSLPIN_FINGER_PRINT_SIZE

/**
  * determines bucket of finger print
  * @fp     finger print for which to get the bucket
  *
  * Return:
  * bucket index
  */
#define SSLPIN_CERT_FINGER_PRINT_BUCKET(fp)                                             \
    (size_t)(                                                                           \
          (fp)[0] <<  8                                                                 \
        | (fp)[1] <<  0                                                                 \
    )

#define SSLPIN_CERT_FINGER_PRINTS_HASH_BITS 16


#define SSLPIN_FINGER_PRINT_FMT                                                         \
    "%2.2hhx%2.2hhx%2.2hhx%2.2hhx%2.2hhx%2.2hhx%2.2hhx%2.2hhx"                          \
    "%2.2hhx%2.2hhx%2.2hhx%2.2hhx%2.2hhx%2.2hhx%2.2hhx%2.2hhx"                          \
    "%2.2hhx%2.2hhx%2.2hhx%2.2hhx"


#define SSLPIN_FINGER_PRINT_PRINT(fp)                                                   \
    (fp)[0],  (fp)[1],  (fp)[2],  (fp)[3],  (fp)[4],  (fp)[5],  (fp)[6],  (fp)[7],      \
    (fp)[8],  (fp)[9],  (fp)[10], (fp)[11], (fp)[12], (fp)[13], (fp)[14], (fp)[15],     \
    (fp)[16], (fp)[17], (fp)[18], (fp)[19]

typedef __u8 finger_print[SSLPIN_FINGER_PRINT_SIZE];

typedef int (*sslpin_read_finger_print_cb)(finger_print* fp, int mask);


struct cert_finger_print {
    int                 mask;
    finger_print        fp;
    struct hlist_node   next;
};

struct cert_finger_print_list {
#define DEF_CERT_FINGER_PRINT_LIST(id) {                                                \
  .name = STR(id),                                                                      \
  .mask = 1 << id ,                                                                     \
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

static struct cert_finger_print* sslpin_get_cert_finger_print(finger_print* fp) {
    struct cert_finger_print* ret =  NULL;
    struct cert_finger_print* i;

    hlist_for_each_entry(i, &sslpin_cert_finger_prints[SSLPIN_CERT_FINGER_PRINT_BUCKET(*fp)], next) {
        pr_debug("xt_sslpin: checking finger print (bucket = %zd, "SSLPIN_FINGER_PRINT_FMT" ?= "SSLPIN_FINGER_PRINT_FMT")\n",
                 SSLPIN_CERT_FINGER_PRINT_BUCKET(*fp),
                 SSLPIN_FINGER_PRINT_PRINT(*fp),
                 SSLPIN_FINGER_PRINT_PRINT(i->fp)
                );

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

    spin_lock_bh(&sslpin_mt_lock);

    cfp = sslpin_get_cert_finger_print(fp);
    if (!cfp) {
        pr_debug("xt_sslpin: new finger print (mask = %x, fp = "SSLPIN_FINGER_PRINT_FMT", bucket = %zd)\n",
                 mask,
                 SSLPIN_FINGER_PRINT_PRINT(*fp),
                 SSLPIN_CERT_FINGER_PRINT_BUCKET(*fp)
                );

        cfp = kmem_cache_zalloc(sslpin_cert_finger_print_cache, GFP_ATOMIC);
        if (!cfp) {
            pr_err("failed allocating space for new finger print\n");

            ret = ENOMEM;
            goto out;
        }
        memcpy(cfp->fp, *fp, sizeof(*fp));
        hlist_add_head(&cfp->next, &sslpin_cert_finger_prints[SSLPIN_CERT_FINGER_PRINT_BUCKET(cfp->fp)]);
    }else{
        pr_debug("xt_sslpin: add mask to finger print (mask = %x, fp = "SSLPIN_FINGER_PRINT_FMT", bucket = %zd)\n",
                 mask,
                 SSLPIN_FINGER_PRINT_PRINT(cfp->fp),
                 SSLPIN_CERT_FINGER_PRINT_BUCKET(cfp->fp)
                );
    }
    cfp->mask |= mask;


out:
    spin_unlock_bh(&sslpin_mt_lock);
    return ret;
}

static int sslpin_remove_cert_finger_print(finger_print* fp, int mask) {
    int ret = EINVAL; // default: finger print not found
    struct cert_finger_print* cfp;

    spin_lock_bh(&sslpin_mt_lock);

    cfp = sslpin_get_cert_finger_print(fp);
    if (cfp) {
        // found: unmask
        cfp->mask &= ~mask;
        if (!cfp->mask) {
            pr_debug("xt_sslpin: removed finger print (mask = %x, fp = "SSLPIN_FINGER_PRINT_FMT")\n",
                     mask,
                     SSLPIN_FINGER_PRINT_PRINT(cfp->fp)
                    );

            hash_del(&cfp->next);
            kmem_cache_free(sslpin_cert_finger_print_cache, cfp);
        } else {
            pr_debug("xt_sslpin: removed mask from finger print (mask = %x, fp = "SSLPIN_FINGER_PRINT_FMT")\n",
                     mask,
                     SSLPIN_FINGER_PRINT_PRINT(cfp->fp)
                    );
        }

        ret = 0;

    }

    spin_unlock_bh(&sslpin_mt_lock);
    return ret;
}

static ssize_t sslpin_read_finger_print(const char* buf, size_t count, sslpin_read_finger_print_cb cb, int mask) {
    finger_print fp;
    const char* buf_end = buf + count;

    // read finger prints
    while (buf + SSLPIN_FINGER_PRINT_STR_SIZE <= buf_end) {
        int ret = hex2bin(fp, buf, sizeof(fp));
        if (ret) {
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
    DEF_CERT_FINGER_PRINT_LIST(0),  DEF_CERT_FINGER_PRINT_LIST(1),  DEF_CERT_FINGER_PRINT_LIST(2),
    DEF_CERT_FINGER_PRINT_LIST(3),  DEF_CERT_FINGER_PRINT_LIST(4),  DEF_CERT_FINGER_PRINT_LIST(5),
    DEF_CERT_FINGER_PRINT_LIST(6),  DEF_CERT_FINGER_PRINT_LIST(7),  DEF_CERT_FINGER_PRINT_LIST(8),
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
