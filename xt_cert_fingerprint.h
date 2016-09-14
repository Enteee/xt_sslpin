/*
 * xt_cert_fingerprint.h
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

#ifndef _LINUX_NETFILTER_XT_SSLPIN_CERT_FINGERPRINT_H
#define _LINUX_NETFILTER_XT_SSLPIN_CERT_FINGERPRINT_H

#define SSLPIN_FINGERPRINT_SIZE 20 // 20*8 = 160bit = sizeof(sha1)
#define SSLPIN_FINGERPRINT_STR_SIZE 40 // 2 * SSLPIN_FINGERPRINT_SIZE

/**
  * determines bucket of fingerprint
  * @fp     fingerprint for which to get the bucket
  *
  * Return:
  * bucket index
  */
#define SSLPIN_CERT_FINGERPRINT_BUCKET(fp)                                             \
    (size_t)(                                                                           \
          (fp)[0] <<  8                                                                 \
        | (fp)[1] <<  0                                                                 \
    )

#define SSLPIN_CERT_FINGERPRINTS_HASH_BITS 16

#define SSLPIN_FINGERPRINT_PRINT_FMT                                                   \
    "%2.2hhX%2.2hhX%2.2hhX%2.2hhX%2.2hhX%2.2hhX"                                        \
    "%2.2hhX%2.2hhX%2.2hhX%2.2hhX%2.2hhX%2.2hhX"                                        \
    "%2.2hhX%2.2hhX%2.2hhX%2.2hhX%2.2hhX%2.2hhX"                                        \
    "%2.2hhX%2.2hhX"

#define SSLPIN_FINGERPRINT_PRINT(fp)                                                   \
    (fp)[0],  (fp)[1],  (fp)[2],  (fp)[3],  (fp)[4],  (fp)[5],                          \
    (fp)[6],  (fp)[7],  (fp)[8],  (fp)[9],  (fp)[10], (fp)[11],                         \
    (fp)[12], (fp)[13], (fp)[14], (fp)[15], (fp)[16], (fp)[17],                         \
    (fp)[18], (fp)[19]


/*
 * Reading with sscanf does not work, thus these defines are useless.
 * see: https://stackoverflow.com/questions/38900645/sscanf-linux-kernel-differs-from-sscanf-glibc
 */
#define SSLPIN_FINGERPRINT_READ_FMT                                                    \
    "%2hhX%2hhX%2hhX%2hhX%2hhX%2hhX"                                                    \
    "%2hhX%2hhX%2hhX%2hhX%2hhX%2hhX"                                                    \
    "%2hhX%2hhX%2hhX%2hhX%2hhX%2hhX"                                                    \
    "%2hhX%2hhX"

#define SSLPIN_FINGERPRINT_READ(fp)                                                    \
    &(fp)[0],  &(fp)[1],  &(fp)[2],  &(fp)[3],  &(fp)[4],  &(fp)[5],                    \
    &(fp)[6],  &(fp)[7],  &(fp)[8],  &(fp)[9],  &(fp)[10], &(fp)[11],                   \
    &(fp)[12], &(fp)[13], &(fp)[14], &(fp)[15], &(fp)[16], &(fp)[17],                   \
    &(fp)[18], &(fp)[19]

typedef __u8 fingerprint[SSLPIN_FINGERPRINT_SIZE];

struct cert_fingerprint {
    int                 mask;
#define SSLPIN_CERT_FINGERPRINT_MASK_FMT "%#*.*x"
#define SSLPIN_CERT_FINGERPRINT_MASK_PRINT(mask) (int)sizeof(mask), (int)sizeof(mask), mask
    fingerprint        fp;
    char                name[SSLPIN_FINGERPRINT_SIZE * 2 + 1];
    struct attribute    attr;   // TODO: check if we've to create a attribute struct per fp and list
    struct hlist_node   next;
};

struct cert_fingerprint_list {
#define DEF_CERT_FINGERPRINT_LIST(id) {                                                \
  .name = STR(id),                                                                      \
  .mask = 1 << id,                                                                      \
  .dir_name = STR(id),                                                                  \
  .dir = NULL,                                                                          \
  .add = __ATTR(                                                                        \
      id ## _add,                                                                       \
      S_IWUSR | S_IRUGO,                                                                \
      add_show_cert_fingerprint_list,                                                  \
      add_store_cert_fingerprint_list                                                  \
  ),                                                                                    \
  .rm = __ATTR(                                                                         \
      id ## _rm,                                                                        \
      S_IWUSR | S_IRUGO,                                                                \
      rm_show_cert_fingerprint_list,                                                   \
      rm_store_cert_fingerprint_list                                                   \
  )                                                                                     \
}
    char*                   name;
    int                     mask;
    char*                   dir_name;
    struct kobject*         dir;
    struct kobj_attribute   add;
    struct kobj_attribute   rm;
};


/* forward decls */
static struct kmem_cache*   sslpin_cert_fingerprint_cache      __read_mostly;
DEFINE_HASHTABLE(sslpin_cert_fingerprints,          SSLPIN_CERT_FINGERPRINTS_HASH_BITS);

static struct cert_fingerprint* sslpin_get_cert_fingerprint(fingerprint* fp) {
    struct cert_fingerprint* ret =  NULL;
    struct cert_fingerprint* i;

    hlist_for_each_entry(i, &sslpin_cert_fingerprints[SSLPIN_CERT_FINGERPRINT_BUCKET(*fp)], next) {
        pr_debug("xt_sslpin: checking fingerprint (bucket = %zd, "SSLPIN_FINGERPRINT_PRINT_FMT" ?= "SSLPIN_FINGERPRINT_PRINT_FMT")\n",
                 SSLPIN_CERT_FINGERPRINT_BUCKET(*fp),
                 SSLPIN_FINGERPRINT_PRINT(*fp),
                 SSLPIN_FINGERPRINT_PRINT(i->fp)
                );

        if (!memcmp(*fp, i->fp, sizeof(*fp))) {
            ret = i;
            goto out;
        }
    }

out:
    return ret;
}

static int sslpin_add_cert_fingerprint(fingerprint* fp, struct cert_fingerprint_list* fpl) {
    int ret = 0;
    struct cert_fingerprint* cfp;

    spin_lock_bh(&sslpin_mt_lock);

    cfp = sslpin_get_cert_fingerprint(fp);
    if (likely(!cfp)) {
        pr_debug("xt_sslpin: new fingerprint (list = %s, fp = "SSLPIN_FINGERPRINT_PRINT_FMT", bucket = %zd)\n",
                 fpl->name,
                 SSLPIN_FINGERPRINT_PRINT(*fp),
                 SSLPIN_CERT_FINGERPRINT_BUCKET(*fp)
                );

        cfp = kmem_cache_zalloc(sslpin_cert_fingerprint_cache, GFP_ATOMIC);
        if (unlikely(!cfp)) {
            pr_err("failed allocating space for new fingerprint\n");

            ret = ENOMEM;
            goto out;
        }
        // initialize fingerprint
        memcpy(cfp->fp, *fp, sizeof(*fp));
        ret = snprintf(cfp->name, sizeof(cfp->name), SSLPIN_FINGERPRINT_PRINT_FMT, SSLPIN_FINGERPRINT_PRINT(*fp));
        if (unlikely(ret != (sizeof(cfp->name) - 1))) {
            pr_err("faild converting fingerprint to string");
            goto out;
        }
        cfp->attr.name = cfp->name;
        hlist_add_head(&cfp->next, &sslpin_cert_fingerprints[SSLPIN_CERT_FINGERPRINT_BUCKET(cfp->fp)]);
    } else {
        pr_debug("xt_sslpin: add mask to fingerprint (list = %s, fp = "SSLPIN_FINGERPRINT_PRINT_FMT", bucket = %zd)\n",
                 fpl->name,
                 SSLPIN_FINGERPRINT_PRINT(cfp->fp),
                 SSLPIN_CERT_FINGERPRINT_BUCKET(cfp->fp)
                );
    }

    if (!(cfp->mask & fpl->mask)) {
        // fp not yet in list
        ret = sysfs_create_file(fpl->dir, &cfp->attr);
        if (ret) {
            pr_err("xt_sslpin: failed to create certificate fingerprint list entry (list = %s fp = "SSLPIN_FINGERPRINT_PRINT_FMT")\n",
                   fpl->name,
                   SSLPIN_FINGERPRINT_PRINT(cfp->fp)
                  );
            ret = EBADF;
            goto out;
        }
    }

    cfp->mask |= fpl->mask;
out:
    spin_unlock_bh(&sslpin_mt_lock);
    return ret;
}

static int sslpin_remove_cert_fingerprint(fingerprint* fp, struct cert_fingerprint_list* fpl) {
    int ret = EINVAL; // default: fingerprint not found
    struct cert_fingerprint* cfp;

    spin_lock_bh(&sslpin_mt_lock);

    cfp = sslpin_get_cert_fingerprint(fp);
    if (cfp && (cfp->mask & fpl->mask)) {
        // found and in list
        sysfs_remove_file(fpl->dir, &cfp->attr);

        cfp->mask &= ~fpl->mask;
        if (!cfp->mask) {
            pr_debug("xt_sslpin: removed fingerprint (list = %s, fp = "SSLPIN_FINGERPRINT_PRINT_FMT")\n",
                     fpl->name,
                     SSLPIN_FINGERPRINT_PRINT(cfp->fp)
                    );

            hash_del(&cfp->next);
            kmem_cache_free(sslpin_cert_fingerprint_cache, cfp);
        } else {
            pr_debug("xt_sslpin: removed mask from fingerprint (list = %s, fp = "SSLPIN_FINGERPRINT_PRINT_FMT")\n",
                     fpl->name,
                     SSLPIN_FINGERPRINT_PRINT(cfp->fp)
                    );
        }

        ret = 0;
    }

    spin_unlock_bh(&sslpin_mt_lock);
    return ret;
}

typedef int (*sslpin_read_fingerprint_cb)(fingerprint* fp, struct cert_fingerprint_list* fpl);
static ssize_t sslpin_read_fingerprints(const char* buf, size_t count, sslpin_read_fingerprint_cb cb,
                                         struct cert_fingerprint_list* fpl) {
    fingerprint fp;
    const char* buf_end = buf + count;

    // read fingerprints
    while (buf + SSLPIN_FINGERPRINT_STR_SIZE <= buf_end) {
        int ret = hex2bin(fp, buf, sizeof(fp));
        if (ret) {
            pr_err("invalid fingerprint hex representation: %." STR(SSLPIN_FINGERPRINT_STR_SIZE) "s\n", buf);
            goto err_invalid_hex_repr;
        }

        cb(&fp, fpl);
        buf += SSLPIN_FINGERPRINT_STR_SIZE; // next
   }

err_invalid_hex_repr:
    return count;
}

static ssize_t add_store_cert_fingerprint_list(struct kobject* kobj, struct kobj_attribute* attr, const char* buf,
                                                size_t count) {
    struct cert_fingerprint_list* fpl = container_of(attr, struct cert_fingerprint_list, add);
    return sslpin_read_fingerprints(buf, count, sslpin_add_cert_fingerprint, fpl);
}

static ssize_t rm_store_cert_fingerprint_list(struct kobject* kobj, struct kobj_attribute* attr, const char* buf,
                                               size_t count) {
    struct cert_fingerprint_list* fpl = container_of(attr, struct cert_fingerprint_list, rm);
    return sslpin_read_fingerprints(buf, count, sslpin_remove_cert_fingerprint, fpl);
}

static ssize_t sslpin_show_fingerprint_list(struct cert_fingerprint_list* fpl, char* buf) {
    size_t bkt;
    struct cert_fingerprint* i;
    size_t count = 0;

    spin_lock_bh(&sslpin_mt_lock);
    hash_for_each(sslpin_cert_fingerprints, bkt, i, next) {
        if (i->mask & fpl->mask) {
            count++;
        }
    }
    spin_unlock_bh(&sslpin_mt_lock);

    return sprintf(buf,
                   "name:          %s\n"
                   "mask:          "SSLPIN_CERT_FINGERPRINT_MASK_FMT"\n"
                   "fingerprints: %zd\n",
                   fpl->name,
                   SSLPIN_CERT_FINGERPRINT_MASK_PRINT(fpl->mask),
                   count);
}

static ssize_t add_show_cert_fingerprint_list(struct kobject* kobj, struct kobj_attribute* attr, char* buf) {
    struct cert_fingerprint_list* fpl = container_of(attr, struct cert_fingerprint_list, add);
    return sslpin_show_fingerprint_list(fpl, buf);
}

static ssize_t rm_show_cert_fingerprint_list(struct kobject* kobj, struct kobj_attribute* attr, char* buf) {
    struct cert_fingerprint_list* fpl = container_of(attr, struct cert_fingerprint_list, rm);
    return sslpin_show_fingerprint_list(fpl, buf);
}

struct cert_fingerprint_list cert_fingerprint_lists[] = {
    DEF_CERT_FINGERPRINT_LIST(0),  DEF_CERT_FINGERPRINT_LIST(1),  DEF_CERT_FINGERPRINT_LIST(2),
    DEF_CERT_FINGERPRINT_LIST(3),  DEF_CERT_FINGERPRINT_LIST(4),  DEF_CERT_FINGERPRINT_LIST(5),
    DEF_CERT_FINGERPRINT_LIST(6),  DEF_CERT_FINGERPRINT_LIST(7),  DEF_CERT_FINGERPRINT_LIST(8),
};

#define SSLPIN_FINGERPRINT_LIST_SIZE (sizeof(cert_fingerprint_lists)/sizeof(*cert_fingerprint_lists))
#define SSLPIN_FINGERPRINT_LIST_SIZE_MAX (8*sizeof(int))


static int sslpin_cert_fingerprint_init(struct kobject* sslpin_kobj) {
    int ret = 0;
    size_t i;

    /**
     * Check if defines are correct: we can't do this during compilation because
     * sizeof won't work in #if
     */
    if (SSLPIN_FINGERPRINT_LIST_SIZE > SSLPIN_FINGERPRINT_LIST_SIZE_MAX) {
        pr_err("xt_sslpin: too many fingerprint lists defined. recompile the module.\n");
        ret = -1;
        goto err_defines;
    }

    for (i = 0; i < SSLPIN_FINGERPRINT_LIST_SIZE; ++i) {
        struct cert_fingerprint_list* fpl = &(cert_fingerprint_lists[i]);
        fpl->dir = kobject_create_and_add(fpl->dir_name, sslpin_kobj);
        if (!fpl->dir) {
            pr_err("xt_sslpin: failed to create certificate fingerprint list directory (name = %s)\n", fpl->dir_name);
            ret = EBADF;
            goto err_sysfs;
        }
        ret = sysfs_create_file(sslpin_kobj, &(fpl->add.attr));
        if (ret) {
            pr_err("xt_sslpin: failed to create certificate fingerprint list add-api (name = %s)\n", fpl->name);
            ret = EBADF;
            goto err_sysfs;
        }
        ret = sysfs_create_file(sslpin_kobj, &(fpl->rm.attr));
        if (ret) {
            pr_err("xt_sslpin: failed to create certificate fingerprint list rm-api (name = %s)\n", fpl->name);
            ret = EBADF;
            goto err_sysfs;
        }
    }

    sslpin_cert_fingerprint_cache = kmem_cache_create("xt_sslpin_cert_fingerprint_cache",
                                                       sizeof(struct cert_fingerprint), 0, 0, NULL);
    if (!sslpin_cert_fingerprint_cache) {
        pr_err("xt_sslpin: could not allocate cert_fingerprint_cache");
        ret = ENOMEM;
        goto err_cache_init;
    }

    return ret;

err_defines:
err_sysfs:
err_cache_init:
    return ret;
}

static void sslpin_cert_fingerprint_destroy(void) {
    size_t i;
    size_t bkt;
    struct cert_fingerprint* cfp;

    for (i = 0; i < SSLPIN_FINGERPRINT_LIST_SIZE; ++i) {
        struct cert_fingerprint_list* fpl = &(cert_fingerprint_lists[i]);
        kobject_put(fpl->dir);
    }

    hash_for_each(sslpin_cert_fingerprints, bkt, cfp, next) {
        pr_debug("xt_sslpin: removed fingerprint (fp = "SSLPIN_FINGERPRINT_PRINT_FMT")\n",
                 SSLPIN_FINGERPRINT_PRINT(cfp->fp)
                );
        kmem_cache_free(sslpin_cert_fingerprint_cache, cfp);
    }
    kmem_cache_destroy(sslpin_cert_fingerprint_cache);
}

#endif
