Security of Systems-n-Services (2025-2026)

Assignment06


Project Description:
This assignment implements a Linux-based firewall using iptables and ip6tables to reject traffic from advertising domains and IP addresses. The script resolves domains from config.txt into IPv4 and IPv6 addresses and applies rules to both the INPUT and OUTPUT chains. For efficient processing of multiple domains, the script utilizes background execution and synchronization.


A hand's on analysis:
The firewall successfully blocks most advertisements, causing them to fail to load within the browser. Some ads may remain visible if they are served directly from the primary website's domain, use hardcoded IP addresses not included in the configuration file, or utilize browser-level features like DNS over HTTPS (DoH) which bypasses standard system-level firewall rules.


Usage Instructions 
The script requires root privileges. First, make it executable: chmod +x firewall.sh.

Now the script can be used as prefered:

Options:
  -config     Configure firewall rules from config.txt"
  -save       Save current firewall rules to rulesV4 and rulesV6"
  -load       Load firewall rules from rulesV4 and rulesV6"
  -list       List current firewall rules"
  -reset      Reset firewall rules to default (accept all)"
  -help       Display this help message"

Important: the tool will take some time to configure and to list the rules


Example usage:

Configure: sudo ./firewall.sh -config
List Rules: sudo ./firewall.sh -list
Save/Load: sudo ./firewall.sh -save / sudo ./firewall.sh -load
Reset: sudo ./firewall.sh -reset