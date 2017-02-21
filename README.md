# Pun-NETSED
v0.1

This work based on the original `nfqsed` by [@rgerganov](https://github.com/rgerganov/nfqsed)

`pun-netsed` is a command line utility that transparently modifies network traffic using a predefined set of substitution rules. It runs on Linux and uses the `netfilter_queue` library. It is similar to `netsed` but it also allows modifying the network traffic passing through an ethernet bridge. This is especially useful in situations where the source MAC address needs to stay unchanged. Compared with `netsed` at the press time, `pun-netsed` is implemented case-sensitive and binary rules.

## Usage

```
Usage: pun-netsed -s /val1/val2 [-s /val1/val2] [-b /val1/val2] [-f file] [-v] [-q num]
  -s val1/val2     - replaces occurences of val1 with val2 in the packet payload
  -b val1/val2     - replaces in hexa format (eg: -b /616263/646566 )
  -f file          - read replacement rules from the specified file
  -q num           - bind to queue with number 'num' (default 0)
  -v               - be quite
```

## Example

Replace occurrences of `foo` with `bar` and occurrences of `good` with `evil` in all forwarded packets that have destination port 554:

```
    # iptables -A FORWARD -p tcp --destination-port 554 -j NFQUEUE --queue-num 0
    # nfqsed -s /foo/bar -s /good/evil
```

## TODO

 * UDP support
 * different lengths of val1 and val2
