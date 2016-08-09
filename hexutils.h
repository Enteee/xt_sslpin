/*
 * hexutils.h
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

#ifndef _LINUX_NETFILTER_XT_SSLPIN_HEXUTILS_H
#define _LINUX_NETFILTER_XT_SSLPIN_HEXUTILS_H


#if LINUX_VERSION_CODE <= KERNEL_VERSION(3,17,0)

/**
 * bin2hex - convert binary data to an ascii hexadecimal string
 * @dst: ascii hexadecimal result
 * @src: binary data
 * @count: binary data length
 */
char *bin2hex(char *dst, const void *src, size_t count)
{
    const unsigned char *_src = src;

    while (count--)
        dst = hex_byte_pack(dst, *_src++);
    return dst;
}

#endif

#endif /* _LINUX_NETFILTER_XT_SSLPIN_HEXUTILS_H */
