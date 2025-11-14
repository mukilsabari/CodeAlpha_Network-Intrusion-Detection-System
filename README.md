# 🛡️ Intrusion Detection and Response System (IDRS)

## 🌐 Project Overview

This project represents the successful evolution from a **passive Network Intrusion Detection System (NIDS)** into an **active Intrusion Detection and Response System (IDRS)**—a system that doesn’t just detect malicious activity but **automatically responds** to neutralize threats in real-time using firewall automation.

The core objective was to achieve **autonomous defense**, building a system capable of **detecting, deciding, and defending** without manual intervention.

---

## ⚙️ Technical Architecture

### Technology Stack:
* **Detection:** Snort 3 (Real-time monitoring)
* **Response:** Linux IPTables (Dynamic blocking)
* **Automation/Resilience:** Python (Multi-threading for non-blocking log analysis)
* **Environment:** Kali Linux (Virtualized Network, Tested on `10.0.4.0/22` range)

### 🧠 Workflow Diagram:
Incoming Traffic → Snort Detection → **Python Log Analysis (Threaded)** → IPTables Firewall → **IP Blocked**

---

## 🐍 2. Code: `idrs_automation.py` (Resilient Version)

This Python script is the brain of your IDRS. It uses **multi-threading** to ensure that blocking an IP for a duration does **not** stop the main log monitor—a crucial fix for system resilience.

This should be saved as **`idrs_automation.py`**.

```python
import time
import subprocess
import re
import threading
import sys

# --- CONFIGURATION (Review and adjust your IP ranges here) ---
SNORT_ALERT_LOG = "/var/log/snort/alert"
BLOCK_DURATION_SECONDS = 300  # 5 minutes block time
WHITELIST = ["127.0.0.1", "10.0.4.5"]  # Add your known safe internal IPs here

# Regex pattern to extract the source IP from a common Snort 3 log line
IP_PATTERN = re.compile(r"SRC:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
# Simple dictionary to track currently blocked IPs
BLOCKED_IPS = {} 

class IDRSManager:
    """Manages the lifecycle of detection and automated response."""

    def execute_iptables_command(self, command_list):
        """Executes a command with sudo privileges and logs the action."""
        try:
            command = ["sudo"] + command_list
            subprocess.run(command, check=True, capture_output=True, text=True)
            print(f"[ACTION] Successfully executed: {' '.join(command)}")
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] IPTables command failed: {e.cmd}")
            print(f"[ERROR] Stderr: {e.stderr.strip()}")
        except FileNotFoundError:
            print("[CRITICAL ERROR] 'sudo' or 'iptables' command not found. Check installation and PATH.")

    def block_and_schedule_unblock(self, attacker_ip):
        """
        Blocks the IP immediately and schedules the unblock action in the background.
        This is the core of the multi-threading solution.
        """
        if attacker_ip in BLOCKED_IPS:
            print(f"[INFO] IP {attacker_ip} is already actively blocked.")
            return

        print(f"[DEFENSE] Initiating block for IP: {attacker_ip} for {BLOCK_DURATION_SECONDS}s")
        BLOCKED_IPS[attacker_ip] = time.time() # Add to tracking list

        # 1. Add the DROP rule (priority 1)
        drop_command = ["iptables", "-I", "INPUT", "1", "-s", attacker_ip, "-j", "DROP"]
        self.execute_iptables_command(drop_command)

        # 2. Schedule the unblock in a new thread
        unblock_timer = threading.Timer(
            BLOCK_DURATION_SECONDS, 
            self.unblock_ip, 
            args=[attacker_ip]
        )
        unblock_timer.start()
        print(f"[THREAD] Unblock scheduled for {attacker_ip} in {BLOCK_DURATION_SECONDS} seconds.")

    def unblock_ip(self, attacker_ip):
        """Removes the IPTables rule."""
        print(f"[DEFENSE] Unblocking IP: {attacker_ip}")
        remove_command = ["iptables", "-D", "INPUT", "-s", attacker_ip, "-j", "DROP"]
        self.execute_iptables_command(remove_command)
        
        if attacker_ip in BLOCKED_IPS:
            del BLOCKED_IPS[attacker_ip] # Remove from tracking list
        print(f"[INFO] Block removed for {attacker_ip}.")


    def monitor_snort_logs(self):
        """Tails the Snort log file and processes new alerts continuously."""
        print(f"[MONITOR] Starting log tail on {SNORT_ALERT_LOG}...")
        print("[MONITOR] Press Ctrl+C to stop the system gracefully.")
        
        # Open a subprocess to continuously read new lines from the Snort alert file
        try:
            tail_process = subprocess.Popen(["tail", "-F", SNORT_ALERT_LOG], 
                                            stdout=subprocess.PIPE, 
                                            stderr=subprocess.PIPE, 
                                            text=True)
        except FileNotFoundError:
            print("[CRITICAL ERROR] 'tail' command not found or log file path is incorrect.")
            return

        for line in iter(tail_process.stdout.readline, ''):
            if not line:
                continue
            
            print(f"[ALERT] New Alert: {line.strip()}")
            
            # 1. Extract the IP
            match = IP_PATTERN.search(line)
            if match:
                attacker_ip = match.group(1)
                
                # 2. Check Whitelist and current block status
                if attacker_ip in WHITELIST:
                    print(f"[INFO] IP {attacker_ip} is whitelisted. No action taken.")
                    continue
                
                if attacker_ip not in BLOCKED_IPS:
                    # 3. Initiate defense in a separate thread
                    self.block_and_schedule_unblock(attacker_ip)
                else:
                    print(f"[INFO] IP {attacker_ip} is already blocked.")

        # Clean up process on exit
        tail_process.terminate()


if __name__ == "__main__":
    manager = IDRSManager()
    
    # Set up signal handler for graceful shutdown
    def cleanup_exit(sig, frame):
        print("\n[STOP] Shutting down IDRS. Clearing all active threads and state.")
        # Optional: Clear all dynamically added IPTables rules on shutdown here
        # manager.execute_iptables_command(["iptables", "-F", "INPUT"]) 
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup_exit)
    
    # Start the core monitoring loop
    try:
        manager.monitor_snort_logs()
    except Exception as e:
        print(f"[CRITICAL FAILURE] An unexpected error stopped the monitor: {e}")
