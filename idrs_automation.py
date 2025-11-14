--snort_custom.rules--

# File: snort_custom.rules
# Custom rules for detecting specific web shell upload attempts.
# SID range 9000000+ is reserved for local/custom rules.

# Detects PHP file upload attempts containing the 'eval(' function, 
# a common method for achieving remote code execution (RCE).
alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (
    msg:"ATTEMPTED-USER PHP Web Shell Upload via EVAL Function"; 
    flow:established,to_server; 
    content:"POST"; http_method; 
    content:".php"; http_uri; 
    content:"eval("; 
    nocase; 
    classtype:attempted-user; 
    sid:9000001; rev:1;
)

# Detects simple port scanning activity by looking for a high volume of SYN packets 
# directed toward many different ports within a short period.
alert tcp $EXTERNAL_NET any -> $HOME_NET any (
    msg:"SCAN-SHORTER Port Scan Detected (High SYN count)"; 
    flags:S; 
    threshold: type limit, track by_src, count 20, seconds 60; 
    classtype:attempted-recon; 
    sid:9000002; rev:1;
)

--idrs_restore.sh--

#!/bin/bash
# File: idrs_restore.sh
# Ensures IPTables rules are saved and restored across reboots.

# Define the location to save and load the rule set
RULE_FILE="/etc/iptables/rules.v4"

# --- Function to Save Rules ---
save_rules() {
    echo "Saving current IPTables rules to ${RULE_FILE}..."
    # Saves IPv4 rules
    sudo iptables-save > "${RULE_FILE}"
    if [ $? -eq 0 ]; then
        echo "Rules successfully saved."
    else
        echo "Error saving rules. Check permissions."
    fi
}

# --- Function to Restore Rules ---
restore_rules() {
    if [ -f "${RULE_FILE}" ]; then
        echo "Restoring IPTables rules from ${RULE_FILE}..."
        # Restores IPv4 rules
        sudo iptables-restore < "${RULE_FILE}"
        if [ $? -eq 0 ]; then
            echo "Rules successfully restored."
        else
            echo "Error restoring rules. Check file integrity or permissions."
        fi
    else
        echo "No saved rule file found at ${RULE_FILE}. Starting with default rules."
    fi
}

# --- Execution ---
case "$1" in
    save)
        save_rules
        ;;
    restore)
        restore_rules
        ;;
    *)
        echo "Usage: $0 {save|restore}"
        exit 1
esac

exit 0

--gitignore--

# Python artifacts
*.pyc
__pycache__/

# Snort/Network Logs and Data (CRITICAL for security)
/var/log/snort/*
/var/log/suricata/*
*.pcap
*.cap

# Operating System generated files
.DS_Store
Thumbs.db

# Virtual Environment
/venv/
