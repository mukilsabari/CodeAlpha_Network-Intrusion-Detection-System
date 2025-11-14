import time
import subprocess
import re

# --- CONFIGURATION ---
SNORT_ALERT_LOG = "/var/log/snort/alert"
BLOCK_DURATION_SECONDS = 300  # Block for 5 minutes
WHITELIST = ["127.0.0.1", "10.0.4.5"]  # Essential services that must never be blocked

# Regex pattern to extract the source IP from a common Snort 3 log line
# Pattern looks for 'SRC: [IP Address]'
IP_PATTERN = re.compile(r"SRC:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")

def execute_iptables_command(command_list):
    """Executes a command with sudo privileges and logs the action."""
    # NOTE: In a production environment, use a tool like 'fail2ban' or a dedicated
    # service account instead of relying directly on sudo in the script.
    try:
        command = ["sudo"] + command_list
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        print(f"[ACTION] Successfully executed: {' '.join(command)}")
        print(f"[LOG] {result.stdout}")
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] IPTables command failed: {e}")
        print(f"[ERROR] Stderr: {e.stderr}")
    except FileNotFoundError:
        print("[CRITICAL ERROR] 'sudo' or 'iptables' command not found.")

def block_ip(attacker_ip):
    """Adds a rule to IPTables to drop all traffic from the specified IP."""
    print(f"[DEFENSE] Blocking malicious IP: {attacker_ip} for {BLOCK_DURATION_SECONDS}s")
    
    # 1. Add the rule to DROP all incoming packets from the source IP
    # -I INPUT 1 inserts the rule at the top of the chain (rule 1) for priority
    drop_command = ["iptables", "-I", "INPUT", "1", "-s", attacker_ip, "-j", "DROP"]
    execute_iptables_command(drop_command)

    # 2. Schedule the unblock action (Simple but risky in a script; a real system uses a cron job/service)
    time.sleep(BLOCK_DURATION_SECONDS)
    unblock_ip(attacker_ip)

def unblock_ip(attacker_ip):
    """Removes the IPTables rule, allowing the IP to communicate again."""
    print(f"[DEFENSE] Unblocking IP: {attacker_ip}")
    # -D INPUT removes the exact rule from the chain
    remove_command = ["iptables", "-D", "INPUT", "-s", attacker_ip, "-j", "DROP"]
    execute_iptables_command(remove_command)

def monitor_snort_logs():
    """Tails the Snort log file and processes new alerts."""
    # NOTE: The 'tail -f' approach is a simple proof-of-concept. 
    # A professional solution would use log rotation services (e.g., logrotate) or a Kafka/Splunk integration.
    
    print(f"[MONITOR] Starting log tail on {SNORT_ALERT_LOG}...")
    
    # Simple tail command to continuously read new lines
    tail_process = subprocess.Popen(["tail", "-F", SNORT_ALERT_LOG], 
                                    stdout=subprocess.PIPE, 
                                    stderr=subprocess.PIPE, 
                                    text=True)

    for line in iter(tail_process.stdout.readline, ''):
        if not line:
            continue
            
        print(f"[ALERT] New Snort Alert: {line.strip()}")
        
        # 1. Extract the IP
        match = IP_PATTERN.search(line)
        if match:
            attacker_ip = match.group(1)
            
            # 2. Check Whitelist
            if attacker_ip in WHITELIST:
                print(f"[INFO] IP {attacker_ip} is whitelisted. No action taken.")
                continue

            # 3. Initiate defense
            print(f"[DEFENSE] Attacker IP found: {attacker_ip}")
            # NOTE: Blocking needs to happen in a separate thread/process to keep the monitor alive.
            # This sequential call will block the log monitor for 5 minutes! 
            block_ip(attacker_ip)

        
if __name__ == "__main__":
    # Ensure IPTables is cleaned before starting if you are testing
    # execute_iptables_command(["iptables", "-F"]) 
    
    monitor_snort_logs()
