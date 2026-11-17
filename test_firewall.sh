#!/bin/bash
# Check destination blocking with and without TUN forwarding

TARGET_IP="8.8.8.8"

echo "Applying iptables rule to block direct access to $TARGET_IP"
sudo iptables -A OUTPUT -d $TARGET_IP -j DROP

echo "--------------------------------------------------------"
echo "Rule applied!"
echo "1. First, try to ping $TARGET_IP in a normal terminal. It should FAIL."
echo "   Command: ping $TARGET_IP -c 3"
echo "2. Next, launch MA3104 VPN and connect in TUN mode."
echo "3. Try the ping command again. It should SUCCEED, proving the traffic goes through the server."
echo "--------------------------------------------------------"
echo "When you are done testing, remove the block rule with this command:"
echo "sudo iptables -D OUTPUT -d $TARGET_IP -j DROP"
