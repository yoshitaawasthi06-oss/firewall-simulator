"""Example test cases. Run:  python test_firewall.py"""
import os, tempfile
from firewall import Firewall, Rule


def make():
    d = tempfile.mkdtemp()
    return Firewall(os.path.join(d, "r.json"), os.path.join(d, "l.log"))


def result(fw, *a, **k):
    return fw.check(*a, **k)[0]


def test_block_ip():
    fw = make(); fw.add(Rule("block", ip="203.0.113.7"))
    assert result(fw, "203.0.113.7", 80) == "BLOCK"
    assert result(fw, "203.0.113.8", 80) == "ALLOW"          # other IPs unaffected

def test_block_ip_range():
    fw = make(); fw.add(Rule("block", ip="10.0.0.0/24"))
    assert result(fw, "10.0.0.99", 80) == "BLOCK"
    assert result(fw, "10.0.1.1", 80) == "ALLOW"

def test_port_rules():
    fw = make(); fw.add(Rule("block", port="23")); fw.add(Rule("block", port="20-25"))
    assert result(fw, "1.1.1.1", 23) == "BLOCK"
    assert result(fw, "1.1.1.1", 22) == "BLOCK"             # inside range 20-25
    assert result(fw, "1.1.1.1", 80) == "ALLOW"

def test_protocol_block():
    fw = make(); fw.add(Rule("block", proto="ICMP"))
    assert result(fw, "1.1.1.1", None, "ICMP") == "BLOCK"   # ping blocked
    assert result(fw, "1.1.1.1", 80, "TCP") == "ALLOW"

def test_traffic_type():
    fw = make(); fw.add(Rule("block", ttype="SSH"))
    assert result(fw, "1.1.1.1", 22) == "BLOCK"              # port 22 recognised as SSH
    assert result(fw, "1.1.1.1", 443) == "ALLOW"

def test_first_match_wins():
    fw = make(); fw.add(Rule("allow", ip="10.0.0.5")); fw.add(Rule("block", ip="10.0.0.0/24"))
    assert result(fw, "10.0.0.5", 80) == "ALLOW"             # specific allow comes first
    assert result(fw, "10.0.0.6", 80) == "BLOCK"

def test_default_policy_block():
    fw = make(); fw.set_policy("block"); fw.add(Rule("allow", port="443"))
    assert result(fw, "1.1.1.1", 443) == "ALLOW"
    assert result(fw, "1.1.1.1", 80) == "BLOCK"              # nothing matched -> default

def test_all_conditions_must_match():
    fw = make(); fw.add(Rule("block", ip="10.0.0.5", port="22"))
    assert result(fw, "10.0.0.5", 22) == "BLOCK"
    assert result(fw, "10.0.0.5", 80) == "ALLOW"             # right IP, wrong port

def test_logging():
    fw = make(); fw.add(Rule("block", ip="9.9.9.9"))
    fw.check("9.9.9.9", 80); fw.check("8.8.8.8", 80)
    lines = open(fw.log_file).read().splitlines()
    assert len(lines) == 2 and "BLOCK" in lines[0] and "ALLOW" in lines[1] and "rule #1" in lines[0]

def test_rules_persist_and_delete():
    fw = make(); fw.add(Rule("block", ip="9.9.9.9"))
    fw2 = Firewall(fw.rules_file, fw.log_file)               # "restart"
    assert len(fw2.rules) == 1
    fw2.delete(0)
    assert result(fw2, "9.9.9.9", 80) == "ALLOW"

def test_bad_input():
    for bad in [lambda: Rule("block"), lambda: Rule("block", ip="999.1.1.1"),
                lambda: Rule("block", port="70000"), lambda: Rule("block", proto="XYZ"),
                lambda: Rule("maybe", ip="1.1.1.1")]:
        try: bad(); assert False, "should have raised"
        except ValueError: pass


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t(); print("PASS", t.__name__)
    print(f"\nALL {len(tests)} TESTS PASSED")
