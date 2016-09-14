# xt_sslpin 
_netfilter/xtables module: match SSL/TLS certificate fingerprints_

## SYNOPSIS

    iptables -I <chain> .. -m sslpin [!] --fpl <fingerprint list id> ..

## DESCRIPTION

For an introduction to SSL/TLS certificate pinning refer to the [OWASP pinning cheat sheet](https://www.owasp.org/index.php/Pinning_Cheat_Sheet). xt_sslpin lets you do certificate pinning at the netfilter level. xt_sslpin will match certificate fingerprints in SSL/TLS connections (with minimal performance impact). Applications are expected to do further certificate chain validation and signature checks (i.e. normal SSL/TLS processing).

## EXAMPLE

1. Mark connections matching on list `0`
    ```shell
    iptables -I INPUT -p tcp --sport 443 \
        -m conntrack --ctstate ESTABLISHED \
        -m sslpin --fpl 0 \
        -j CONNMARK --set-mark 1
    ```

2. Add https://github.com certificate to list `0`
    ```shell
    echo \
    | openssl s_client -connect github.com:443 -servername github.com 2>/dev/null \
    | openssl x509 -outform DER \
    | sha1sum > /sys/kernel/xt_sslpin/0_add
    ```

3. Drop marked connections
    ```shell
    iptables -I INPUT -j CONNMARK --restore-mark
    iptables -A INPUT -m connmark --mark 1 -j DROP
    iptables -A INPUT -j CONNMARK --save-mark
    ```

4. Test (should time out)
    ```shell
    curl --connect-timeout 5  https://github.com
    ```

5. Reset (_will remove all rules from INPUT chain_)
    ```shell
    iptables -F INPUT
    ```

## INSTALLATION

Prerequisites

* linux kernel > 3.7
* kernel-headers
* iptables-dev
* gcc
* git

then:

```shell
git clone https://github.com/Enteee/xt_sslpin.git
cd xt_sslpin
sudo apt-get install iptables-dev # xtables.h
```

Build and install:

```shell
make
sudo make install
```

Verify installation:

```shell
iptables -m sslpin -h
```

### Uninstalling

```shell
make clean
sudo make uninstall
```

## OPTIONS

Options preceded by an exclamation mark negate the comparison: the rule will match if the presented SSL/TLS certificate fingerprint is NOT found in the specified list.

### `[!] --fpl <list id>` 

If a "Certificate" message is seen, match if one of the certificates matches a fingerprint in the given list.

## LIST API

The list API is exposed under: `/sys/kernel/xt_sslpin/`.

| Operation | Command |
| --------- | ------- |
| ADD       | `echo fingerprint-sha1 > /sys/kernel/xt_sslpin/<list id>_add` |
| REMOVE    | `echo fingerprint-sha1 > /sys/kernel/xt_sslpin/<list id>_rm`  |
| LIST      | `ls /sys/kernel/xt_sslpin/<list id>` |

## IMPLEMENTATION NOTES

Per connection, the incoming handshake data is parsed once across all -m sslpin iptables rules;
upon receiving the SSL/TLS handshake ServerCertificate message, the parsed certificates are checked by all rules.

![xt_sslpin intercepted SSL/TLS handshake](https://raw.githubusercontent.com/Enteee/xt_sslpin/master/doc/handshake_xt_sslpin.png)

After this, the connection is marked as "finished", and xt_sslpin will not do any further checking.
(Re-handshaking will not be checked in order to incur minimal overhead, and as the server has already proved
its identity).

Up until the ServerCertificate message is received, xt_sslpin will drop out-of-order TCP segments to
parse the data linearly without buffering. Conntrack takes care of IP fragment reassembly up-front, but packets
can still have non-linear memory layout; see skb_is_nonlinear().

If SYN is received on a time-wait state conn/flow, conntrack will destroy the old cf_conn
and create a new cf_conn. Thus, our per-conn state transitions are simply new->open->destroyed (no reopen).

## DEBUG

Compile and install the module in debug mode

```shell
sudo make debug install
```

and it will log connection information, fingerprints and parsing information:

```
kernel: [353.333720] xt_sslpin 2.0 (SSL/TLS pinning)
kernel: [353.333722] xt_sslpin: debug enabled
kernel: [353.191650] xt_sslpin: new fingerprint (list = 0, fp = AD7CEA1CD3C13E1DE21C6ED5C16E4D156CE651E6, bucket = 44412)
kernel: [353.191753] xt_sslpin: new fingerprint (list = 0, fp = 65548323AA33D1FE5A1FE1AF5EA35E4846AEF466, bucket = 28865)
kernel: [353.191830] xt_sslpin: new fingerprint (list = 0, fp = 9DBFAD0F0EEDC153E1D51E56165ED165E16E165E, bucket = 40383)
kernel: [353.332684] xt_sslpin: 1 connection (0 actively monitored)
kernel: [353.332707] xt_sslpin: SYN/ACK not seen for connection (already established when xt_sslpin was loaded) - ignoring connection
kernel: [353.575060] xt_sslpin: 2 connections (0 actively monitored)
kernel: [353.575082] xt_sslpin: SYN/ACK not seen for connection (already established when xt_sslpin was loaded) - ignoring connection
```

## TODO

* Optional buffering for reordered TCP segments during handshake (no RTT penalty / overhead)
* TCP Fast Open (TFO) support
* Restrict TCP Options / TCP stack passthrough
* IPv6 support

## Acknowledgment

This module is a fork from [xt_sslpin by fredburger (github.com/fredburger)](https://github.com/fredburger/xt_sslpin).

Thank you!

## LICENSE

xt_sslpin is Copyright (C) 2016 Enteee (duckpond.ch).

This program is free software; you can redistribute it and/or modify it under the terms of the
GNU General Public License as published by the Free Software Foundation; version 2 of the License.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, write to
the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
