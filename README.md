# Pun-NETSED
v0.1

This work based on the original `nfqsed` by [@rgerganov](https://github.com/rgerganov/nfqsed)

`pun-netsed` is a command line utility that transparently modifies network traffic using a predefined set of substitution rules. It runs on Linux and uses the `netfilter_queue` library. It is similar to `netsed` but it also allows modifying the network traffic passing through an ethernet bridge. This is especially useful in situations where the source MAC address needs to stay unchanged. Compared with `netsed` at the press time, `pun-netsed` is implemented case-sensitive, binary and regex rules.

## Usage

```
Usage: pun-netsed [-s /val1/val2] [-b /val1/val2] [-f file] [-v] [-q num]
  -s val1/val2     - replaces occurences of val1 with val2 in the packet payload
  -b val1/val2     - replaces in hexa format (eg: -b /616263/646566 )
  -f file          - read replacement rules from the specified file
  -q num           - bind to queue with number 'num' (default 0)
  -v               - be quite
```

## Setting Up

### Forwarding TCP packets using `iptables`

* Transparent Proxy (`FORWARD`)
```
    # iptables -A FORWARD -p tcp --destination-port 2323 -j NFQUEUE --queue-num 0
    # iptables -A FORWARD -p tcp --source-port 2323 -j NFQUEUE --queue-num 1
```

* On app-server (`INPUT` and `OUTPUT`)
```
    # iptables -A INPUT -p tcp --destination-port 2323 -j NFQUEUE --queue-num 0
    # iptables -A OUTPUT -p tcp --source-port 2323 -j NFQUEUE --queue-num 1
```


## Example

Replace occurrences of `foo` with `bar` and occurrences of `good` with `evil` in all forwarded packets that have destination port 554:

```
    # pun-netsed -q 0 -s /foo/bar -s /good/evil
    # pun-netsed -q 1 -s /bar/foo -s /evil/good
```

Or working with rules file `rules.txt` and `rules.txt`
```
    # pun-netsed -q 0 -f rules.txt
    # pun-netsed -q 1 -f rules2.txt
```

## TODO

 * UDP support
 * different lengths of val1 and val2
