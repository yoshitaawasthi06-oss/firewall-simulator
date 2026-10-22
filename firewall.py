"""Simple Firewall Simulator (pure Python, no installs needed).

Run:  python firewall.py          -> interactive rule-configuration shell
      python firewall.py --demo   -> loads sample rules and tests sample traffic
"""
import cmd
import ipaddress
import json
import os
import shlex
import sys
from datetime import datetime

# Traffic types we can recognise from the port (a real firewall inspects the packet).
PORT_TYPES = {80: "HTTP", 443: "HTTPS", 22: "SSH", 21: "FTP", 23: "TELNET", 53: "DNS", 25: "SMTP"}
PROTOCOLS = {"TCP", "UDP", "ICMP"}


def parse_port(text):
    """'80' -> (80, 80); '20-25' -> (20, 25)."""
    lo, _, hi = str(text).partition("-")
    lo, hi = int(lo), int(hi or lo)
    if not (0 <= lo <= hi <= 65535):
        raise ValueError("port must be 0-65535 (or a range like 20-25)")
    return lo, hi


class Rule:
    def __init__(self, action, ip=None, port=None, proto=None, ttype=None):
        action = action.upper()
        if action not in ("ALLOW", "BLOCK"):
            raise ValueError("action must be allow or block")
        if ip:
            ipaddress.ip_network(ip, strict=False)           # validates IP or CIDR like 10.0.0.0/24
        if port is not None:
            parse_port(port)
        proto = proto.upper() if proto else None
        if proto and proto not in PROTOCOLS:
            raise ValueError("proto must be TCP, UDP or ICMP")
        if not any([ip, port, proto, ttype]):
            raise ValueError("a rule needs at least one of ip= port= proto= type=")
        self.action, self.ip, self.port, self.proto = action, ip, port, proto
        self.ttype = ttype.upper() if ttype else None

    def matches(self, pkt):
        """A rule matches only if EVERY condition it sets matches the packet."""
        if self.ip and ipaddress.ip_address(pkt["ip"]) not in ipaddress.ip_network(self.ip, strict=False):
            return False
        if self.port is not None:
            lo, hi = parse_port(self.port)
            if pkt["port"] is None or not (lo <= pkt["port"] <= hi):
                return False
        if self.proto and pkt["proto"] != self.proto:
            return False
        if self.ttype and pkt["type"] != self.ttype:
            return False
        return True

    def to_dict(self):
        return {"action": self.action, "ip": self.ip, "port": self.port, "proto": self.proto, "type": self.ttype}

    def __str__(self):
        parts = [f"{k}={v}" for k, v in
                 (("ip", self.ip), ("port", self.port), ("proto", self.proto), ("type", self.ttype)) if v]
        return f"{self.action:<5} " + " ".join(parts)


class Firewall:
    def __init__(self, rules_file="rules.json", log_file="firewall.log"):
        self.rules_file, self.log_file = rules_file, log_file
        self.rules, self.policy = [], "ALLOW"        # policy = what happens if no rule matches
        self.load()

    # ---- rule management ----
    def add(self, rule, position=None):
        self.rules.insert(len(self.rules) if position is None else position, rule)
        self.save()

    def delete(self, index):
        removed = self.rules.pop(index)
        self.save()
        return removed

    def set_policy(self, policy):
        policy = policy.upper()
        if policy not in ("ALLOW", "BLOCK"):
            raise ValueError("policy must be allow or block")
        self.policy = policy
        self.save()

    # ---- the core logic: first matching rule wins ----
    def check(self, ip, port=None, proto="TCP", ttype=None):
        ipaddress.ip_address(ip)                       # raises ValueError for a bad IP
        proto = proto.upper()
        port = int(port) if port not in (None, "") else None
        ttype = (ttype or ("PING" if proto == "ICMP" else PORT_TYPES.get(port, "OTHER"))).upper()
        pkt = {"ip": ip, "port": port, "proto": proto, "type": ttype}
        for i, rule in enumerate(self.rules, 1):
            if rule.matches(pkt):
                return self._log(pkt, rule.action, f"rule #{i} ({rule})")
        return self._log(pkt, self.policy, f"default policy ({self.policy})")

    def _log(self, pkt, action, reason):
        line = (f"{datetime.now():%Y-%m-%d %H:%M:%S} {action:<5} src={pkt['ip']} port={pkt['port']} "
                f"proto={pkt['proto']} type={pkt['type']} <- {reason}")
        with open(self.log_file, "a") as f:
            f.write(line + "\n")
        return action, line

    # ---- saving ----
    def save(self):
        with open(self.rules_file, "w") as f:
            json.dump({"policy": self.policy, "rules": [r.to_dict() for r in self.rules]}, f, indent=2)

    def load(self):
        if not os.path.exists(self.rules_file):
            return
        with open(self.rules_file) as f:
            data = json.load(f)
        self.policy = data.get("policy", "ALLOW")
        self.rules = [Rule(r["action"], r["ip"], r["port"], r["proto"], r["type"]) for r in data["rules"]]


def parse_kv(args):
    """['ip=1.2.3.4', 'port=80'] -> {'ip': '1.2.3.4', 'port': '80'}"""
    out = {}
    for a in args:
        k, sep, v = a.partition("=")
        if not sep or k not in ("ip", "port", "proto", "type"):
            raise ValueError(f"bad option '{a}' (use ip= port= proto= type=)")
        out[k] = v
    return out


class Shell(cmd.Cmd):
    intro = "Firewall Simulator. Type 'help' for commands, 'demo' for an example.\n"
    prompt = "fw> "

    def __init__(self, fw):
        super().__init__()
        self.fw = fw

    def _run(self, fn):
        try:
            fn()
        except (ValueError, IndexError) as e:
            print(f"Error: {e}")

    def do_block(self, arg):
        """block ip=1.2.3.4 [port=80] [proto=TCP] [type=HTTP]   - add a BLOCK rule (ip may be 10.0.0.0/24)"""
        def go():
            kv = parse_kv(shlex.split(arg))
            self.fw.add(Rule("block", kv.get("ip"), kv.get("port"), kv.get("proto"), kv.get("type")))
            print("Rule added.")
        self._run(go)

    def do_allow(self, arg):
        """allow ip=1.2.3.4 [port=80] [proto=TCP] [type=HTTP]   - add an ALLOW rule"""
        def go():
            kv = parse_kv(shlex.split(arg))
            self.fw.add(Rule("allow", kv.get("ip"), kv.get("port"), kv.get("proto"), kv.get("type")))
            print("Rule added.")
        self._run(go)

    def do_rules(self, arg):
        """rules   - list all rules (order matters: first match wins)"""
        for i, r in enumerate(self.fw.rules, 1):
            print(f"  {i}. {r}")
        print(f"  default policy: {self.fw.policy}")

    def do_delete(self, arg):
        """delete <number>   - delete a rule by its number"""
        self._run(lambda: print("Deleted:", self.fw.delete(int(arg) - 1)))

    def do_policy(self, arg):
        """policy allow|block   - what to do with traffic that matches no rule"""
        self._run(lambda: (self.fw.set_policy(arg), print("Default policy:", self.fw.policy)))

    def do_test(self, arg):
        """test ip=1.2.3.4 [port=80] [proto=TCP] [type=HTTP]   - send a fake packet through the firewall"""
        def go():
            kv = parse_kv(shlex.split(arg))
            if "ip" not in kv:
                raise ValueError("test needs ip=")
            action, line = self.fw.check(kv["ip"], kv.get("port"), kv.get("proto", "TCP"), kv.get("type"))
            print(line)
        self._run(go)

    def do_log(self, arg):
        """log [n]   - show the last n log lines (default 10)"""
        if not os.path.exists(self.fw.log_file):
            return print("Log is empty.")
        with open(self.fw.log_file) as f:
            for line in f.readlines()[-(int(arg) if arg.strip().isdigit() else 10):]:
                print(line, end="")

    def do_demo(self, arg):
        """demo   - add sample rules and test sample traffic"""
        run_demo(self.fw)

    def do_quit(self, arg):
        """quit   - exit"""
        return True
    do_exit = do_quit

    def do_EOF(self, arg):
        print()
        return True


def run_demo(fw):
    fw.rules, fw.policy = [], "ALLOW"
    for r in [Rule("block", ip="203.0.113.7"), Rule("block", ip="10.0.0.0/24", port="22"),
              Rule("allow", port="443", proto="TCP"), Rule("block", proto="ICMP"),
              Rule("block", port="23")]:
        fw.add(r)
    print("Rules:")
    for i, r in enumerate(fw.rules, 1):
        print(f"  {i}. {r}")
    print("\nTraffic:")
    for ip, port, proto in [("203.0.113.7", 80, "TCP"), ("10.0.0.5", 22, "TCP"), ("8.8.8.8", 443, "TCP"),
                            ("8.8.8.8", None, "ICMP"), ("1.2.3.4", 23, "TCP"), ("1.2.3.4", 80, "TCP")]:
        print(" ", fw.check(ip, port, proto)[1])


if __name__ == "__main__":
    fw = Firewall()
    if "--demo" in sys.argv:
        run_demo(fw)
    else:
        Shell(fw).cmdloop()
