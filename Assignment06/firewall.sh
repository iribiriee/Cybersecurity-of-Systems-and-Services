#!/bin/bash
# You are NOT allowed to change the files' names!
config="config.txt"
rulesV4="rulesV4"
rulesV6="rulesV6"

function firewall() {
    if [ "$EUID" -ne 0 ];then
        printf "Please run as root.\n"
        exit 1
    fi
    if [ "$1" = "-config"  ]; then
        # Configure adblock rules based on domain names and IPs of $config file.
        while read -r line || [[ -n "$line" ]]; do
            # Skip empty lines
            [ -z "$line" ] && continue
            
            # Use 'host' to resolve the domain/IP to get both A (IPv4) and AAAA (IPv6) records
            # We run these in the background to handle the large config.txt quickly
            (
                # Extract IPv4 addresses and add iptables rules
                host -t A "$line" | awk '/has address/ { print $4 }' | while read ip; do
                    iptables -A INPUT -s "$ip" -j REJECT
                    iptables -A OUTPUT -d "$ip" -j REJECT
                done
                
                # Extract IPv6 addresses and add ip6tables rules
                host -t AAAA "$line" | awk '/has IPv6 address/ { print $5 }' | while read ip6; do
                    ip6tables -A INPUT -s "$ip6" -j REJECT
                    ip6tables -A OUTPUT -d "$ip6" -j REJECT
                done
            ) &
        done < "$config"
        
        wait # Wait for all background DNS resolutions to finish
        printf "Configuration complete.\n"
        
    elif [ "$1" = "-save"  ]; then
        # Save current kernel rules to the specified files
        iptables-save > "$rulesV4"
        ip6tables-save > "$rulesV6"
        printf "Rules saved to $rulesV4 and $rulesV6.\n"
        
    elif [ "$1" = "-load"  ]; then
        # Restore rules from the saved files into the kernel
        iptables-restore < "$rulesV4"
        ip6tables-restore < "$rulesV6"
        printf "Rules loaded from $rulesV4 and $rulesV6.\n"
        
    elif [ "$1" = "-reset"  ]; then
        # Flush all rules (-F), delete user chains (-X), and set policy to ACCEPT (-P)
        for cmd in iptables ip6tables; do
            $cmd -F
            $cmd -X
            $cmd -P INPUT ACCEPT
            $cmd -P FORWARD ACCEPT
            $cmd -P OUTPUT ACCEPT
        done
        printf "Firewall reset to default (Accept All).\n"
        
    elif [ "$1" = "-list"  ]; then
        printf "%s\n" "--- IPv4 Rules ---"
        iptables -L -n -v
        printf "\n%s\n" "--- IPv6 Rules ---"
        ip6tables -L -n -v
        
    elif [ "$1" = "-help"  ]; then
        # Help text already provided in corpus...
        printf "This script is responsible for creating a simple firewall mechanism. It rejects connections from specific domain names or IP addresses using iptables/ip6tables.\n\n"
        printf "Usage: $0  [OPTION]\n\n"
        printf "Options:\n\n"
        printf "  -config\t  Configure adblock rules based on the domain names and IPs of '$config' file.\n"
        printf "  -save\t\t  Save rules to '$rulesV4' and '$rulesV6'  files.\n"
        printf "  -load\t\t  Load rules from '$rulesV4' and '$rulesV6' files.\n"
        printf "  -list\t\t  List current rules for IPv4 and IPv6.\n"
        printf "  -reset\t  Reset rules to default settings (i.e. accept all).\n"
        printf "  -help\t\t  Display this help and exit.\n"
        exit 0
    else
        printf "Wrong argument. Exiting...\n"
        exit 1
    fi
}

firewall $1
exit 0