rule detect_supply_chain_attack
{
    meta:
        description = "Detects Paramiko files infected with PWNED malware"
        author = "iribiriee"
        severity = "High"

    strings:
        $malicious_string = "You are PWNED!"

    condition:
        $malicious_string
}
