#!/bin/bash

# ==============================================================================
# Script Name: ufw_professional_setup.sh
# Description: Professional UFW Firewall Configuration Script
# ==============================================================================


GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[!] Error: Please run this script with root privileges (sudo).${NC}"
    exit 1
fi

echo -e "${GREEN}[*] Starting professional UFW firewall configuration...${NC}"


echo -e "${YELLOW}[*] Resetting previous UFW rules...${NC}"
ufw --force reset


echo -e "${YELLOW}[*] Setting default policies (Deny Incoming / Allow Outgoing)...${NC}"
ufw default deny incoming
ufw default allow outgoing

echo -e "${YELLOW}[*] Detecting SSH port automatically...${NC}"
SSH_PORT=$(grep -E '^Port [0-9]+' /etc/ssh/sshd_config | awk '{print $2}')


if [ -z "$SSH_PORT" ]; then
    SSH_PORT="22"
fi
echo -e "${GREEN}[+] Detected SSH port: $SSH_PORT${NC}"

ALLOWED_PORTS=(
    "80"
    "443"
    "2096"
    "8443"
    "8080"
    "62050"
    "42542"
    "42538"
    "3350"
    "2083"
)

ufw allow "$SSH_PORT/tcp" > /dev/null
echo -e "  [+] Port $SSH_PORT (SSH) ${GREEN}Allowed${NC}"

echo -e "${YELLOW}[*] Opening other allowed inbound ports...${NC}"
for port in "${ALLOWED_PORTS[@]}"; do
    ufw allow "$port" > /dev/null
    echo -e "  [+] Port $port ${GREEN}Allowed${NC}"
done

DENIED_OUTBOUND=(
    "10.0.0.0/8"
    "172.16.0.0/12"
    "192.168.0.0/16"
    "100.64.0.0/10"
    "198.18.0.0/15"
    "240.0.0.0/4"
    "192.0.0.0/24"
    "102.195.124.0/24"
    "102.130.88.0/24"
    "102.65.81.0/24"
    "102.193.10.0/24"
    "151.139.128.0/24"
    "205.185.208.0/24"
    "185.121.225.0/24"
    "102.214.134.0/24"
    "89.35.131.0/24"
    "102.197.178.0/24"
    "102.192.167.0/24"
    "5.79.71.0/24"
    "216.218.185.0/24"
    "25.0.0.0/8"
    "93.88.205.0/24"
)

echo -e "${YELLOW}[*] Blocking outbound access to specified subnets...${NC}"
for subnet in "${DENIED_OUTBOUND[@]}"; do
    ufw deny out to "$subnet" > /dev/null
    echo -e "  [-] Outbound to $subnet ${RED}Blocked${NC}"
done

echo -e "${YELLOW}[*] Enabling UFW and applying changes...${NC}"
ufw --force enable
systemctl enable ufw > /dev/null 2>&1

echo -e "${GREEN}[+] Firewall configured and enabled successfully!${NC}"
echo -e "${YELLOW}--------------------------------------------------${NC}"

ufw status verbose
