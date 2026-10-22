# Firewall Simulator

A simple firewall simulator in Python (no installs needed). It does not touch real network traffic. You describe "fake packets" and it decides whether to ALLOW or BLOCK them using your rules.

## Run
```
python firewall.py            # interactive shell to configure rules
python firewall.py --demo     # sample rules + sample traffic
python test_firewall.py       # run the 11 example test cases
```

## Features
| Requirement | How |
|---|---|
| Block specific IPs | `block ip=203.0.113.7` (also ranges: `block ip=10.0.0.0/24`) |
| Block/allow ports | `block port=23`, `allow port=443`, ranges like `port=20-25` |
| Block by protocol / traffic type | `block proto=ICMP`, `block type=SSH` |
| Log of allowed/blocked actions | every check is written to `firewall.log` (time, action, packet, rule that decided) |
| CLI to configure rules | commands: `block`, `allow`, `rules`, `delete N`, `policy`, `test`, `log`, `demo`, `quit` |

Rules are saved in `rules.json`, so they survive restarts.

## How the firewall logic works
1. A **packet** has: source IP, destination port, protocol (TCP/UDP/ICMP) and traffic type (HTTP, SSH, DNS... guessed from the port; ICMP = PING).
2. A **rule** has an action (ALLOW or BLOCK) and one or more conditions (ip, port, proto, type). A rule matches only if **all** its conditions match.
3. Rules are checked **from top to bottom, and the first match wins**. So order matters: put specific rules (allow one trusted IP) before general ones (block the whole subnet).
4. If **no rule matches**, the **default policy** decides (ALLOW at the start; change it with `policy block` for a strict "deny everything not allowed" firewall).
5. Every decision, with the rule that caused it, is logged.

## Example session
```
fw> block ip=203.0.113.7
fw> block port=23
fw> test ip=203.0.113.7 port=80
... BLOCK src=203.0.113.7 port=80 proto=TCP type=HTTP <- rule #1
fw> test ip=1.2.3.4 port=80
... ALLOW src=1.2.3.4 port=80 proto=TCP type=HTTP <- default policy (ALLOW)
```

## Example test cases (all in test_firewall.py)
| Test | Rules | Packet | Expected |
|---|---|---|---|
| Block an IP | block ip=203.0.113.7 | from 203.0.113.7 / from 203.0.113.8 | BLOCK / ALLOW |
| Block a subnet | block ip=10.0.0.0/24 | 10.0.0.99 / 10.0.1.1 | BLOCK / ALLOW |
| Block ports | block port=23, block port=20-25 | port 23, 22 / port 80 | BLOCK / ALLOW |
| Block protocol | block proto=ICMP | ping / TCP 80 | BLOCK / ALLOW |
| Block traffic type | block type=SSH | port 22 / port 443 | BLOCK / ALLOW |
| First match wins | allow ip=10.0.0.5, then block 10.0.0.0/24 | 10.0.0.5 / 10.0.0.6 | ALLOW / BLOCK |
| Default policy block | policy block, allow port=443 | port 443 / port 80 | ALLOW / BLOCK |
| All conditions must match | block ip=10.0.0.5 port=22 | port 22 / port 80 | BLOCK / ALLOW |
| Logging | block ip=9.9.9.9 | 2 packets | 2 log lines, naming the rule |
| Persistence and delete | one rule, restart, delete | - | rule reloaded, then removed |
| Bad input | invalid IP, port 70000, unknown protocol | - | error shown, no crash |

## Limitations
It is a teaching simulator: no real packets, no connection tracking (stateful inspection), IPv4 and IPv6 addresses only as text, and no rule priorities beyond list order.
