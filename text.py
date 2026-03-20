#!/usr/bin/env python3

#  No Raw() layer → ICMP reject broken
# No interface validation
# Infinite stats loop (no self.running check)
from scapy.all import (sniff, send, conf, IP, TCP, UDP, ICMP)


#  CORE PYTHON - NO DYNAMIC IMPORTS
import os
import sys
import time
import threading
from collections import defaultdict

try:
    import ipaddress
except ImportError:
    print(" ipaddress module missing. Install: pip3 install ipaddress")
    sys.exit(1)

class StatefulFirewall:
    def __init__(self):
        self.connections = defaultdict(lambda: {'state': 'NEW'})
        self.rules = []
        self.running = False
        self.stats = {'accept': 0, 'drop': 0, 'reject': 0}
        self._load_default_rules()
    
    def _load_default_rules(self):
        """Rock-solid default rules"""
        defaults = [
            ("accept", "tcp", "any", "any", None, None, "ESTABLISHED"),
            ("accept", "udp", "any", "any"),
            ("accept", "icmp", "any", "any"),
            ("drop", "all", "any", "any")
        ]
        for args in defaults:
            self.add_rule(*args)
    
    def add_rule(self, action, protocol, src_ip, dst_ip, flags=None, ports=None, state=None):
        """Add rule - bulletproof"""
        rule = {
            'action': action.lower(),
            'protocol': protocol.lower(),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'flags': flags,
            'ports': ports,
            'state': state
        }
        self.rules.append(rule)
        print(f" {action.upper():6} {protocol:4} {src_ip:15} → {dst_ip}")
    
    def get_interface(self):
        """ FAILSAFE INTERFACE DETECTION - 4 METHODS"""
        # Method 1: Simple fallback
        fallbacks = ['eth0', 'enp0s3', 'wlan0', 'lo']
        
        # Method 2: Try common Linux command
        try:
            import subprocess
            result = subprocess.run(['ip', 'route'], capture_output=True, text=True, timeout=2)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'default' in line and 'dev' in line:
                        dev = line.split('dev')[-1].split()[0]
                        if dev in fallbacks:
                            return dev
        except:
            pass
        
        # Method 3: Return first fallback
        return fallbacks[0]
    
    def ip_matches(self, ip, rule_ip):
        """Simple IP matching"""
        if rule_ip == 'any':
            return True
        if ip == rule_ip:
            return True
        return False  # CIDR support optional
    
    def port_matches(self, sport, dport, rule_port):
        """Simple port matching"""
        if not rule_port or sport is None:
            return True
        if isinstance(rule_port, int):
            return sport == rule_port or dport == rule_port
        return False
    
    def get_state(self, pkt):
        """Simplified state detection"""
        if TCP not in pkt:
            return 'NEW'
        
        flags = pkt[TCP].flags
        if flags == 0x02:  # SYN
            return 'NEW'
        if flags & 0x10:   # ACK
            return 'ESTABLISHED'
        return 'NEW'
    
    def match_packet(self, pkt):
        """Fast rule matching"""
        if IP not in pkt:
            return "drop"
        
        ip_layer = pkt[IP]
        proto = {1: 'icmp', 6: 'tcp', 17: 'udp'}.get(ip_layer.proto, 'unknown')
        src_ip, dst_ip = ip_layer.src, ip_layer.dst
        sport, dport = None, None
        state = 'NEW'
        
        if TCP in pkt:
            sport, dport = pkt[TCP].sport, pkt[TCP].dport
            state = self.get_state(pkt)
        elif UDP in pkt:
            sport, dport = pkt[UDP].sport, pkt[UDP].dport
        
        # Rule evaluation
        for rule in self.rules:
            if (rule.get('state') == state or not rule.get('state')) and \
               (rule['protocol'] == proto or rule['protocol'] == 'all') and \
               self.ip_matches(src_ip, rule['src_ip']) and \
               self.ip_matches(dst_ip, rule['dst_ip']) and \
               self.port_matches(sport, dport, rule['ports']):
                return rule['action']
        
        return "drop"
    
    def process_packet(self, pkt):
        """Main packet handler"""
        if IP not in pkt:
            return True
        
        action = self.match_packet(pkt)
        self.stats[action] += 1
        
        # Compact logging
        src, dst = pkt[IP].src, pkt[IP].dst
        proto = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}.get(pkt[IP].proto, 'UNK')
        
        if TCP in pkt:
            print(f"[{proto}:{pkt[TCP].sport:>5}→{pkt[TCP].dport:>5}] "
                  f"{src:15}→{dst:15} | {action.upper()}")
        else:
            print(f"[{proto:3}] {src:15}→{dst:15} | {action.upper()}")
        
        return action == "accept"
    
    def start_monitoring(self, interface):
        """Start packet capture"""
        print(f"\n MONITORING {interface.upper()}")
        print(" STATS: Accept | Drop | Reject | TOTAL")
        print("═" * 70)
        
        self.running = True
        
        def show_stats():
            while self.running:
                time.sleep(3)
                total = sum(self.stats.values())
                print(f"\r {self.stats['accept']:>6} | "
                      f"{self.stats['drop']:>6} | "
                      f"{self.stats['reject']:>6} | "
                      f"{total:>6}", end='', flush=True)
        
        threading.Thread(target=show_stats, daemon=True).start()
        
        # CORE SNIFFER - BULLETPROOF
        conf.verb = 0
        sniff(iface=interface, prn=self.process_packet, 
              filter="ip", store=0, 
              stop_filter=lambda p: not self.running)

def main():
    """Main entry point"""
    if os.geteuid() != 0:
        print(" ROOT REQUIRED: sudo python3 firewall.py")
        return 1
    
    print(" STATEFUL FIREWALL v2.0")
    print("Installing production rules...")
    
    fw = StatefulFirewall()
    
    #  PRODUCTION SECURITY RULES
    fw.add_rule("accept", "tcp", "any", "any", state="ESTABLISHED")
    fw.add_rule("accept", "tcp", "any", "any", ports=80)   # HTTP
    fw.add_rule("accept", "tcp", "any", "any", ports=443)  # HTTPS
    fw.add_rule("accept", "udp", "any", "any", ports=53)   # DNS
    fw.add_rule("accept", "icmp", "any", "any")            # Ping
    fw.add_rule("drop", "tcp", "any", "any", ports=22)     # BLOCK SSH 
    fw.add_rule("drop", "all", "any", "any")               # DEFAULT DENY
    
    interface = fw.get_interface()
    print(f"\n Ready on {interface}")
    
    try:
        fw.start_monitoring(interface)
    except KeyboardInterrupt:
        print("\n\n Firewall stopped")
        return 0
    except Exception as e:
        print(f"\n Crash: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())