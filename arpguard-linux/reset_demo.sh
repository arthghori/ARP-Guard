#!/bin/bash
echo "Resetting ARP Guard demo environment..."
sudo arptables -F 2>/dev/null && echo "arptables cleared" || echo "arptables: nothing to clear"
sudo iptables -F INPUT 2>/dev/null && echo "iptables INPUT cleared" || echo "iptables: nothing to clear"
sudo ip neigh flush all
echo "Done. Run: sudo \$(which python3) main.py"
