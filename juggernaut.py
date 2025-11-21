import subprocess
import os
import pwd
import grp
import re
import sys
import shutil
import curses
import datetime
import logging

# --- Configuration ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INPUT_DIR = os.path.join(BASE_DIR, "Input")
LOG_FILE = os.path.join(BASE_DIR, "juggernaut_v2.log")

# Input Files
USERS_FILE = os.path.join(INPUT_DIR, "users.txt")
ADMINS_FILE = os.path.join(INPUT_DIR, "admins.txt")
GROUPS_FILE = os.path.join(INPUT_DIR, "groups.txt")
SERVICES_FILE = os.path.join(INPUT_DIR, "services.txt")
PASSWORD_FILE = os.path.join(INPUT_DIR, "password.txt")

# Globals
NEW_PASSWORD = ""
OS_DISTRO = ""
AUTHORIZED_USERS = []
AUTHORIZED_ADMINS = []
REQUIRED_GROUPS = {}
REQUIRED_SERVICES = []

# Constants
HACKING_TOOLS = ["hydra", "john", "nmap", "netcat", "nc", "wireshark", "aircrack-ng", "ophcrack", "nikto", "sqlmap", "kismet", "medusa", "dsniff", "ettercap", "rkhunter", "chkrootkit"]
GAMES = ["aisleriot", "gnome-mines", "gnome-sudoku", "freeciv", "openarena"]

SERVICE_PORTS = {
    "ssh": 22, "openssh-server": 22,
    "apache2": [80, 443], "nginx": [80, 443],
    "vsftpd": 21, "proftpd": 21,
    "mysql": 3306, "mariadb": 3306, "mysql-server": 3306,
    "postgresql": 5432,
    "samba": [139, 445], "smbd": [139, 445],
}

# --- Helper Functions ---

def setup_logging():
    """Configures the logging system."""
    logging.basicConfig(
        filename=LOG_FILE,
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

def run_command(command, input_data=None, silent=False):
    """Executes a shell command and logs it."""
    logging.info(f"EXECUTING: {command}")
    
    try:
        # Ensure non-interactive execution for apt commands
        env = os.environ.copy()
        env["DEBIAN_FRONTEND"] = "noninteractive"
        
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, input=input_data, text=True, env=env)
        
        # Log success and a snippet of stdout if present
        if result.stdout.strip():
             logging.info(f"SUCCESS (STDOUT Snippet): {result.stdout.strip()[:200]}")
        else:
             logging.info(f"SUCCESS: {command}")
        return result.stdout.strip()
        
    except subprocess.CalledProcessError as e:
        # Log failure and error output
        error_message = f"FAILED: {command}\nSTDERR: {e.stderr.strip()}"
        logging.error(error_message)
        
        if not silent:
            print_status(f"Command failed: {command}\nStderr: {e.stderr.strip()}", False)
        return None
    except Exception as e:
        logging.error(f"EXCEPTION: {e} during command {command}")
        if not silent:
            print_status(f"An unexpected error occurred: {e}", False)
        return None

def print_header(title):
    print(f"\n{'='*60}\n\033[34m=== {title} ===\033[0m\n{'='*60}")

def print_status(message, success=True):
    if success is True:
        status = "\033[32m[+]\033[0m"
    elif success is False:
        status = "\033[31m[-]\033[0m"
    else: # Neutral/Warning
        status = "\033[33m[!]\033[0m"
    print(f"{status} {message}")

def setup_directories():
    """Creates necessary directories and dummy files if they don't exist."""
    if not os.path.exists(INPUT_DIR):
        os.makedirs(INPUT_DIR, exist_ok=True)

        try:
            # Get the user who invoked sudo, otherwise default
            current_user = os.getenv("SUDO_USER", os.getenv("USER", "operator"))
        except:
            current_user = "operator"

        files_to_create = {
            USERS_FILE: f"{current_user}\n",
            ADMINS_FILE: f"{current_user}\n",
            GROUPS_FILE: "# Format: group_name:user1,user2\n",
            SERVICES_FILE: "ssh\n",
            PASSWORD_FILE: "CyberP@triot!State2025\n"
        }
        for filepath, content in files_to_create.items():
            if not os.path.exists(filepath):
                with open(filepath, 'w') as f:
                    f.write(content)
        
        print(f"Setup Complete: Created Input directory.")
        print(f"Please populate the files in {INPUT_DIR} based on the README.")
        print("Then run the script again with sudo.")
        sys.exit(0)

def load_input_files():
    """Loads configuration from the input directory."""
    global NEW_PASSWORD, AUTHORIZED_USERS, AUTHORIZED_ADMINS, REQUIRED_SERVICES, REQUIRED_GROUPS
    try:
        with open(PASSWORD_FILE, 'r') as f:
            NEW_PASSWORD = f.read().strip()
        if not NEW_PASSWORD:
             print_status("Error: Password file is empty.", False); sys.exit(1)

        with open(USERS_FILE, 'r') as f:
            AUTHORIZED_USERS = [line.strip() for line in f if line.strip() and not line.startswith("#")]

        with open(ADMINS_FILE, 'r') as f:
            AUTHORIZED_ADMINS = [line.strip() for line in f if line.strip() and not line.startswith("#")]

        for admin in AUTHORIZED_ADMINS:
            if admin not in AUTHORIZED_USERS:
                AUTHORIZED_USERS.append(admin)

        with open(SERVICES_FILE, 'r') as f:
            REQUIRED_SERVICES = [line.strip().lower() for line in f if line.strip() and not line.startswith("#")]

        with open(GROUPS_FILE, 'r') as f:
            for line in f:
                if ":" in line and line.strip() and not line.startswith("#"):
                    group, users_str = line.strip().split(":", 1)
                    REQUIRED_GROUPS[group] = users_str.split(",")

        print_status(f"Input files loaded. Users: {len(AUTHORIZED_USERS)}, Admins: {len(AUTHORIZED_ADMINS)}, Services: {len(REQUIRED_SERVICES)}")

    except FileNotFoundError as e:
        print_status(f"Error loading input files: {e}.", False)
        sys.exit(1)

# --- Phase 1: Initialization, Updates & Stabilization ---

def initialization_and_updates():
    """Checks for root, detects OS, stabilizes system, and runs full updates."""
    print_header("Phase 1: Initialization, Updates & Stabilization")

    # Check for root, allow setup phase if not root
    if os.geteuid() != 0:
        setup_directories()
        # If setup ran, it will exit. If we are here and not root, exit.
        print_status("This script must be run as root. Use sudo.", False); sys.exit(1)

    setup_logging()
    load_input_files()

    # 1. Detect OS Version and Check Compatibility
    global OS_DISTRO
    try:
        OS_VERSION = run_command("lsb_release -rs")
        OS_DISTRO = run_command("lsb_release -is").lower()
        print_status(f"Detected OS: {OS_DISTRO} {OS_VERSION}")
        logging.info(f"Detected OS: {OS_DISTRO} {OS_VERSION}")

    except Exception as e:
        print_status(f"Could not detect OS version: {e}", False); sys.exit(1)

    # 2. Remove Immutable Bits
    print_status("Removing immutable bits (chattr -i)...")
    run_command("chattr -iaR /etc /home /opt /root /var /usr /srv /bin /sbin", silent=True)

    # 3. Fix Repositories and Run Full Update/Upgrade
    print_status("Fixing sources.list and preparing for updates...")
    try:
        codename = None
        sources_file_path = "/etc/apt/sources.list"

        # Determine the correct codename (Mint relies on Ubuntu base)
        if OS_DISTRO == "linuxmint":
            base_codename = run_command("awk -F'=' '/UBUNTU_CODENAME=/{print $2}' /etc/os-release").strip()
            if base_codename:
                codename = base_codename
                # Write to a specific list file for Mint to avoid conflicts with Mint GUI tools
                sources_file_path = "/etc/apt/sources.list.d/juggernaut-base.list"
                print_status(f"Mint detected. Using Ubuntu base repositories ({codename}).")
        elif OS_DISTRO == "ubuntu":
             codename = run_command("lsb_release -cs").strip()

        if codename:
            sources_content = f"""
deb http://archive.ubuntu.com/ubuntu/ {codename} main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu/ {codename}-updates main restricted universe multiverse
deb http://security.ubuntu.com/ubuntu/ {codename}-security main restricted universe multiverse
"""
            # Use run_command to handle writing the file with root privileges
            if run_command(f"echo '{sources_content}' > {sources_file_path}") is None:
                print_status("Failed to write sources.list.", False)
        else:
             print_status("Could not determine codename. Skipping repository fix.", None)

        # Execute Updates and Upgrades
        print_status("Running apt update...")
        if run_command("apt update -y") is None:
             print_status("apt update failed. Attempting dpkg fix...", None)
             run_command("dpkg --configure -a") # Attempt to fix interrupted installs

        print_status("WARNING: Running 'apt upgrade'. This can take significant time (5-30+ mins).", None)
        
        # In a competition environment, we usually want to upgrade automatically.
        print_status("Running apt upgrade (This may take several minutes)...")
        # Use Dpkg options to automatically handle config file prompts robustly
        upgrade_command = "apt upgrade -yq -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold'"
        if run_command(upgrade_command) is None:
            print_status("apt upgrade failed.", False)
        else:
            print_status("System upgrade complete.")
            run_command("apt autoremove -y")

    except Exception as e:
        print_status(f"Failed during update/upgrade phase: {e}", False)

# --- Phase 2: Interactive Media Hunt (Curses TUI) ---
# (Implementation omitted for brevity, identical to previous robust version)

def interactive_media_hunt(stdscr):
    """Uses curses TUI for selecting files to delete."""
    curses.curs_set(0)
    if curses.has_colors():
        curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(2, curses.COLOR_RED, curses.COLOR_BLACK)
        GREEN = curses.color_pair(1)
        RED = curses.color_pair(2)
    else:
        GREEN = curses.A_NORMAL
        RED = curses.A_BOLD

    media_exts = ["*.mp3", "*.mp4", "*.avi", "*.mkv", "*.mov", "*.wav", "*.flac"]
    script_exts = ["*.sh", "*.py", "*.pl", "*.rb", "*.php", "*.cgi"]
    image_exts = ["*.jpg", "*.jpeg", "*.png", "*.gif"]
    
    extensions = media_exts + script_exts + image_exts
    
    search_command = f"find /home /var/www /srv /tmp /opt -type f \( -iname {' -o -iname '.join(extensions)} \) 2>/dev/null"
    files_found = run_command(search_command, silent=True)

    if not files_found:
        stdscr.addstr(0, 0, "No prohibited files found. Press any key.")
        stdscr.refresh(); stdscr.getch(); return

    file_list = [f for f in files_found.split('\n') if f]
    selected_files = set()
    current_row = 0

    def draw_menu():
        stdscr.clear()
        height, width = stdscr.getmaxyx()
        stdscr.addstr(0, 0, "Select files to DELETE (Spacebar). Press ENTER when done. 'q' to cancel.", curses.A_BOLD)

        visible_rows = height - 3
        if visible_rows < 1: visible_rows = 1
        
        start_index = max(0, min(current_row - visible_rows // 2, len(file_list) - visible_rows))
        end_index = min(len(file_list), start_index + visible_rows)

        for idx in range(start_index, end_index):
            file_path = file_list[idx]
            display_idx = idx - start_index + 2

            mode = curses.A_REVERSE if idx == current_row else curses.A_NORMAL

            if file_path in selected_files:
                stdscr.addstr(display_idx, 2, "[X] ", RED | mode)
            else:
                stdscr.addstr(display_idx, 2, "[ ] ", GREEN | mode)

            display_path = file_path if len(file_path) < width - 8 else "..." + file_path[-(width - 11):]
            try:
                stdscr.addstr(display_idx, 6, display_path, mode)
            except curses.error:
                pass

        stdscr.refresh()

    while True:
        draw_menu()
        key = stdscr.getch()

        if key == curses.KEY_UP and current_row > 0:
            current_row -= 1
        elif key == curses.KEY_DOWN and current_row < len(file_list) - 1:
            current_row += 1
        elif key == ord(' '):
            file_path = file_list[current_row]
            if file_path in selected_files:
                selected_files.remove(file_path)
            else:
                selected_files.add(file_path)
        elif key == 10: break # Enter key
        elif key == ord('q'): return

    # Delete selected files
    if selected_files:
        stdscr.clear()
        stdscr.addstr(0, 0, f"Deleting {len(selected_files)} files...", curses.A_BOLD)
        for i, file_path in enumerate(selected_files):
            try:
                os.remove(file_path)
                logging.info(f"DELETED FILE: {file_path}")
                stdscr.addstr(i+1, 0, f"Deleted: {file_path}")
            except Exception as e:
                stdscr.addstr(i+1, 0, f"Error deleting {file_path}: {e}", RED)
        stdscr.addstr("\nDeletion complete. Press any key.")
        stdscr.refresh(); stdscr.getch()

def run_media_hunt():
    print_header("Phase 2: Interactive Media Hunt")
    print_status("WARNING: Answer forensics questions BEFORE deleting files.", None)
    input("Press Enter to launch the media hunt interface...")
    try:
        curses.wrapper(interactive_media_hunt)
    except Exception as e:
        print_status(f"Curses interface failed: {e}. Manual deletion required.", False)


# --- Phase 3: User Management Blitz ---
# (Implementation omitted for brevity, identical to previous robust version)

def user_management_blitz():
    """Handles user creation, deletion, admin rights, groups, and passwords."""
    print_header("Phase 3: User Management Blitz")

    # 1. Get Current System State
    current_users = {}
    for user in pwd.getpwall():
        if user.pw_uid >= 1000 or user.pw_uid == 0:
             current_users[user.pw_name] = {'uid': user.pw_uid}

    # 2. Unauthorized User Purge
    print_status("Auditing unauthorized users...")
    for username in current_users:
        if username != 'root' and username not in AUTHORIZED_USERS and username != 'nobody':
            print_status(f"Deleting unauthorized user: {username}...", False)
            run_command(f"userdel -r {username}", silent=True)

    # 3. Ensure Authorized Users Exist
    for username in AUTHORIZED_USERS:
        if username not in current_users:
            print_status(f"Creating missing authorized user: {username}...")
            run_command(f"useradd -m -s /bin/bash {username}", silent=True)

    # 4. Administrator Audit (The Reset Strategy)
    print_status("Resetting administrator privileges (sudo/adm)...")
    admin_groups = ["sudo", "adm"]

    # Remove unauthorized admins
    for group_name in admin_groups:
        try:
            members = grp.getgrnam(group_name).gr_mem
            for member in members:
                if member not in AUTHORIZED_ADMINS:
                     run_command(f"deluser {member} {group_name}", silent=True)
        except KeyError:
            pass # Group doesn't exist

    # Add authorized admins
    for admin in AUTHORIZED_ADMINS:
        for group_name in admin_groups:
             run_command(f"usermod -a -G {group_name} {admin}", silent=True)

    # 5. Group Management
    print_status("Managing group memberships...")
    for group, users in REQUIRED_GROUPS.items():
        try:
            grp.getgrnam(group)
        except KeyError:
            run_command(f"groupadd {group}", silent=True)
        
        for user in users:
            if user in AUTHORIZED_USERS:
                run_command(f"usermod -a -G {group} {user}", silent=True)

    # 6. Password Standardization
    print_status("Standardizing passwords...")
    users_to_change = AUTHORIZED_USERS + ['root']
    chpasswd_input = ""
    for username in users_to_change:
        try:
            pwd.getpwnam(username)
            chpasswd_input += f"{username}:{NEW_PASSWORD}\n"
        except KeyError:
            pass

    if run_command("chpasswd", input_data=chpasswd_input) is not None:
        # Force password change on next login
        for username in AUTHORIZED_USERS:
            run_command(f"chage -d 0 {username}", silent=True)

    # 7. Advanced Checks
    # UID 0 Audit
    print_status("Auditing for UID 0 users (Root imposters)...")
    uid_counter = 1500
    for user in pwd.getpwall():
        if user.pw_uid == 0 and user.pw_name != 'root':
            print_status(f"Found UID 0 user: {user.pw_name}. Changing UID to {uid_counter}...", False)
            run_command(f"usermod -u {uid_counter} {user.pw_name}", silent=True)
            uid_counter += 1

    # Shell Audit
    print_status("Auditing user shells...")
    for user in pwd.getpwall():
        if user.pw_uid < 1000 and user.pw_uid != 0: # System users
            if user.pw_shell not in ["/bin/false", "/usr/sbin/nologin", "/sbin/nologin"]:
                run_command(f"usermod -s /usr/sbin/nologin {user.pw_name}", silent=True)
        elif user.pw_uid >= 1000 and user.pw_name != 'nobody': # Human users
             if user.pw_shell != "/bin/bash":
                run_command(f"usermod -s /bin/bash {user.pw_name}", silent=True)

    # Lock Root Account
    run_command("passwd -l root", silent=True)

# --- Phase 4: Advanced Configuration Hardening (Intelligent Editing) ---

def configure_pam_common_auth():
    """Dynamically configures /etc/pam.d/common-auth for Ubuntu 22.04/Mint 21 (pam_faillock)."""
    print_status("Configuring PAM common-auth (pam_faillock)...")
    
    # Ensure necessary packages are installed
    run_command("apt install libpam-modules libpam-faillock -y")

    AUTH_FILE = "/etc/pam.d/common-auth"
    
    # Backup the original file
    shutil.copyfile(AUTH_FILE, f"{AUTH_FILE}.bak_juggernaut")

    # Define the required pam_faillock configuration for 22.04+ (pam_tally2 is deprecated)
    # Settings: deny after 5 attempts, unlock after 15 minutes (900s), apply to root
    faillock_settings = "deny=5 unlock_time=900 even_deny_root"
    
    # The 3 required lines:
    preauth_line = f"auth required pam_faillock.so preauth silent {faillock_settings}"
    authfail_line = f"auth [default=die] pam_faillock.so authfail {faillock_settings}"
    authsucc_line = f"auth sufficient pam_faillock.so authsucc {faillock_settings}"

    try:
        with open(AUTH_FILE, 'r') as f:
            lines = f.readlines()

        # Stage 1: Clean up existing configuration
        cleaned_lines = []
        for line in lines:
            # Remove deprecated pam_tally2 and existing pam_faillock to ensure correct order
            if "pam_faillock.so" in line or "pam_tally2.so" in line:
                logging.info(f"PAM: Removing conflicting line: {line.strip()}")
                continue
            
            # Remove 'nullok' from pam_unix.so (Security Vulnerability)
            if "pam_unix.so" in line and "nullok" in line:
                line = line.replace("nullok_secure", "").replace("nullok", "")
                logging.info("PAM: Removed 'nullok' from pam_unix.so")
            
            cleaned_lines.append(line)

        # Stage 2: Insert new configuration
        new_lines = []
        unix_found = False

        # Insert Preauth at the beginning of the auth stack
        new_lines.append(f"\n# Juggernaut Script: pam_faillock configuration (Inserted at top)\n")
        new_lines.append(f"{preauth_line}\n")

        # Process cleaned lines and insert Authfail/Authsucc immediately after pam_unix.so
        for line in cleaned_lines:
            new_lines.append(line)
            # Find the primary pam_unix.so authentication line
            if "pam_unix.so" in line and line.strip().startswith("auth") and not unix_found:
                unix_found = True
                new_lines.append(f"\n# Juggernaut Script: pam_faillock (Inserted after pam_unix)\n")
                new_lines.append(f"{authfail_line}\n")
                new_lines.append(f"{authsucc_line}\n")

        if not unix_found:
             print_status("Warning: Primary pam_unix.so line not found in common-auth. PAM lockout may not function correctly.", None)

        # Write the new configuration
        with open(AUTH_FILE, 'w') as f:
            f.writelines(new_lines)
        
        print_status("PAM common-auth configured successfully.")

    except Exception as e:
        print_status(f"CRITICAL: Failed to configure common-auth. System stability at risk! Error: {e}", False)


def configure_pam_common_password():
    """Dynamically configures /etc/pam.d/common-password for complexity and history."""
    print_status("Configuring PAM common-password (pwquality/history)...")

    # Ensure necessary packages are installed
    run_command("apt install libpam-pwquality -y")

    PASSWORD_FILE = "/etc/pam.d/common-password"
    
    # Backup the original file
    shutil.copyfile(PASSWORD_FILE, f"{PASSWORD_FILE}.bak_juggernaut")

    # 1. Password Complexity (pam_pwquality) - Based on User's robust example
    pwquality_settings = "retry=3 minlen=15 difok=8 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 reject_username maxrepeat=2 gecoscheck enforce_for_root"
    
    # 2. Password History (Using pam_unix for history is standard and reliable)
    history_setting = "remember=5"

    try:
        with open(PASSWORD_FILE, 'r') as f:
            lines = f.readlines()

        new_lines = []

        for line in lines:
            # Modify existing pam_pwquality.so line
            if "pam_pwquality.so" in line and line.strip().startswith("password"):
                # Preserve 'requisite' but update settings
                new_line = re.sub(r"(password\s+requisite\s+pam_pwquality\.so).*", rf"\1 {pwquality_settings}", line)
                new_lines.append(new_line)
                continue

            # Modify pam_unix.so for history, hashing, and removing insecure options
            elif "pam_unix.so" in line and line.strip().startswith("password"):
                # Remove insecure options and outdated complexity checks
                line = line.replace("nullok_secure", "").replace("nullok", "").replace("obscure", "")
                
                # Ensure sha512 is present
                if "sha512" not in line:
                    line = line.strip() + " sha512"
                
                # Ensure history setting is present (and remove existing ones to ensure correct value)
                line = re.sub(r"remember=\d+", "", line)
                # Add history setting if not already added by the regex replacement
                if history_setting not in line:
                    line = line.strip() + f" {history_setting}"
                
                new_lines.append(line.strip() + "\n")
                continue
            
            # Keep other lines
            new_lines.append(line)

        # Write the new configuration
        with open(PASSWORD_FILE, 'w') as f:
            f.writelines(new_lines)

        print_status("PAM common-password configured successfully.")

    except Exception as e:
        print_status(f"CRITICAL: Failed to configure common-password. Error: {e}", False)


def configuration_hardening():
    """Applies system-wide security configurations."""
    print_header("Phase 4: Advanced Configuration Hardening")

    # 1. Password Aging (/etc/login.defs)
    print_status("Configuring password aging and hashing (/etc/login.defs)...")
    run_command("sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs")
    run_command("sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   7/' /etc/login.defs")
    
    # Ensure SHA512 hashing
    if not run_command("grep -q '^ENCRYPT_METHOD SHA512' /etc/login.defs", silent=True):
         # Try replacing existing method first
         run_command("sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/' /etc/login.defs", silent=True)
         # If it wasn't there to replace, append it.
         if not run_command("grep -q '^ENCRYPT_METHOD SHA512' /etc/login.defs", silent=True):
            run_command("echo 'ENCRYPT_METHOD SHA512' >> /etc/login.defs")

    # 2. Advanced PAM Configuration
    configure_pam_common_auth()
    configure_pam_common_password()

    # 3. Kernel Hardening (/etc/sysctl.conf)
    print_status("Applying Kernel Hardening (/etc/sysctl.conf)...")
    sysctl_settings = {
        "net.ipv4.tcp_syncookies": 1,           # Protect against SYN flood attacks
        "net.ipv4.conf.all.rp_filter": 1,       # IP Spoofing protection
        "net.ipv4.conf.all.accept_redirects": 0, # Disable ICMP redirects
        "net.ipv6.conf.all.accept_redirects": 0,
        "net.ipv4.conf.all.send_redirects": 0,
        "fs.suid_dumpable": 0,                  # Prevent core dumps from SUID programs
        "net.ipv6.conf.all.disable_ipv6": 1     # Often scored if IPv6 isn't needed
    }
    for key, value in sysctl_settings.items():
        run_command(f"sed -i '/{key}/d' /etc/sysctl.conf", silent=True)
        run_command(f"echo '{key} = {value}' >> /etc/sysctl.conf")

    run_command("sysctl -p")

    # 4. GUI Hardening (Disable Guest)
    print_status("Disabling Guest Account (LightDM/GDM)...")
    # LightDM (Often used in Mint)
    if os.path.exists("/etc/lightdm/"):
        os.makedirs("/etc/lightdm/lightdm.conf.d", exist_ok=True)
        run_command("echo '[Seat:*]\nallow-guest=false\ngreeter-show-manual-login=true\ngreeter-hide-users=true' > /etc/lightdm/lightdm.conf.d/50-secure-greeter.conf")
    
    # GDM (Standard Ubuntu)
    if os.path.exists("/etc/gdm3/custom.conf"):
         # Ensure the [daemon] section exists
         if not run_command("grep -q '\[daemon\]' /etc/gdm3/custom.conf", silent=True):
             run_command("echo '\n[daemon]' >> /etc/gdm3/custom.conf")
         run_command("sed -i '/^\[daemon\]/a AutomaticLoginEnable=false\nAllowGuest=false\nTimedLoginEnable=false' /etc/gdm3/custom.conf", silent=True)

    # 5. Advanced System Hardening (State Round Level)
    # Secure Shared Memory (/etc/fstab)
    print_status("Securing shared memory (/dev/shm) in fstab...")
    if not run_command("grep '/run/shm' /etc/fstab | grep 'noexec'", silent=True):
        shutil.copy("/etc/fstab", "/etc/fstab.bak")
        # Add secure mount options: noexec (cannot run binaries), nosuid (ignore SUID bit)
        run_command("echo 'tmpfs /run/shm tmpfs defaults,noexec,nosuid,nodev 0 0' >> /etc/fstab")
        run_command("mount -o remount /run/shm", silent=True)

    # Secure GRUB Permissions
    print_status("Securing GRUB configuration permissions...")
    if os.path.exists("/boot/grub/grub.cfg"):
        run_command("chown root:root /boot/grub/grub.cfg")
        run_command("chmod 400 /boot/grub/grub.cfg") # Read-only for root

# --- Phase 5: Software, Services, and Advanced Hardening ---

def harden_ssh():
    if os.path.exists("/etc/ssh/sshd_config"):
        print_status("Applying Advanced SSH Hardening...")
        ssh_config = "/etc/ssh/sshd_config"
        
        def update_ssh_config(key, value):
            # Use sed to uncomment and set the value, or add it if it doesn't exist
            if run_command(f"grep -qE '^[#]?{key}' {ssh_config}", silent=True) is not None:
                 run_command(f"sed -i 's/^[#]?{key}.*/{key} {value}/' {ssh_config}")
            else:
                 run_command(f"echo '{key} {value}' >> {ssh_config}")

        update_ssh_config("PermitRootLogin", "no")
        update_ssh_config("Protocol", "2")
        update_ssh_config("PermitEmptyPasswords", "no")
        update_ssh_config("X11Forwarding", "no")
        update_ssh_config("MaxAuthTries", "4")
        update_ssh_config("IgnoreRhosts", "yes")
        update_ssh_config("HostbasedAuthentication", "no")
        update_ssh_config("LogLevel", "VERBOSE")
        
        run_command("systemctl restart ssh", silent=True)

def harden_vsftpd():
    if os.path.exists("/etc/vsftpd.conf"):
        print_status("Applying Advanced VSFTPD Hardening (SSL/TLS, Chroot)...")
        
        def update_vsftpd_conf(key, value):
             run_command(f"sed -i '/^{key}=/d' /etc/vsftpd.conf", silent=True)
             run_command(f"echo '{key}={value}' >> /etc/vsftpd.conf")

        update_vsftpd_conf("anonymous_enable", "NO")
        update_vsftpd_conf("local_enable", "YES")
        
        # Chroot Jails
        update_vsftpd_conf("chroot_local_user", "YES")
        update_vsftpd_conf("allow_writeable_chroot", "YES")

        # Force SSL/TLS
        update_vsftpd_conf("ssl_enable", "YES")
        update_vsftpd_conf("force_local_data_ssl", "YES")
        update_vsftpd_conf("force_local_logins_ssl", "YES")
        update_vsftpd_conf("ssl_tlsv1_2", "YES")
        update_vsftpd_conf("ssl_sslv2", "NO")
        update_vsftpd_conf("ssl_sslv3", "NO")

        # Point to default SSL certs if they exist
        if os.path.exists("/etc/ssl/certs/ssl-cert-snakeoil.pem"):
             update_vsftpd_conf("rsa_cert_file", "/etc/ssl/certs/ssl-cert-snakeoil.pem")
        if os.path.exists("/etc/ssl/private/ssl-cert-snakeoil.key"):
             update_vsftpd_conf("rsa_private_key_file", "/etc/ssl/private/ssl-cert-snakeoil.key")
        
        print_status("NOTE: VSFTPD SSL configured. Verify certificate paths if errors occur.", None)
        run_command("systemctl restart vsftpd", silent=True)

def harden_apache_php():
    # Apache2 Hardening
    if os.path.exists("/etc/apache2/conf-enabled/security.conf"):
        print_status("Applying Advanced Apache2 Hardening...")
        sec_conf = "/etc/apache2/conf-enabled/security.conf"

        run_command(f"sed -i 's/^ServerTokens.*/ServerTokens Prod/' {sec_conf}")
        run_command(f"sed -i 's/^ServerSignature.*/ServerSignature Off/' {sec_conf}")
        run_command(f"sed -i '/^TraceEnable/d' {sec_conf}")
        run_command(f"echo 'TraceEnable Off' >> {sec_conf}")

        run_command("systemctl restart apache2", silent=True)

    # PHP Hardening (Web Shell Prevention)
    print_status("Applying Advanced PHP Hardening (Web Shell Prevention)...")
    php_inis = run_command("find /etc/php -name php.ini 2>/dev/null")
    if php_inis:
        # List of dangerous functions
        disabled_functions = "exec,passthru,shell_exec,system,proc_open,popen,curl_exec,show_source,pcntl_exec,dl,symlink,proc_nice"
        for ini_file in php_inis.split('\n'):
            if ini_file.strip():
                run_command(f"sed -i 's/.*disable_functions.*/disable_functions = {disabled_functions}/' {ini_file}")
                run_command(f"sed -i 's/.*expose_php.*/expose_php = Off/' {ini_file}")
                run_command(f"sed -i 's/.*allow_url_fopen.*/allow_url_fopen = Off/' {ini_file}")
                run_command(f"sed -i 's/.*display_errors.*/display_errors = Off/' {ini_file}")

def harden_samba():
    if os.path.exists("/etc/samba/smb.conf"):
        print_status("Applying Advanced Samba Hardening...")
        smb_conf = "/etc/samba/smb.conf"

        def update_samba_config(key, value):
            # Remove existing entry first to prevent duplicates in the global section
            # This is simplistic; complex Samba configs might need manual review.
            run_command(f"sed -i '/\[global\]/,/^\[/ {{ /{key} = /d; }}' {smb_conf}", silent=True)
            # Insert new entry right after [global]
            run_command(f"sed -i '/\[global\]/a \   {key} = {value}' {smb_conf}")

        # Disable anonymous/guest access
        update_samba_config("map to guest", "Bad User")
        run_command(f"sed -i 's/guest ok = yes/guest ok = no/g' {smb_conf}")

        # Enforce encryption and signing
        update_samba_config("server signing", "mandatory")
        # update_samba_config("smb encrypt", "required") # Use with caution, may break older clients
        update_samba_config("server min protocol", "SMB2") # Disable SMB1

        run_command("systemctl restart smbd", silent=True)

def software_services_and_hardening():
    """Manages software, services, and applies hardening."""
    print_header("Phase 5: Software, Services, and Advanced Hardening")

    # 1. Install Tools & Enable Core Security Services
    print_status("Installing security tools (ufw, auditd, debsums, apparmor-utils)...")
    tools_to_install = ["ufw", "auditd", "debsums", "net-tools", "apparmor-utils"]
    run_command(f"apt install {' '.join(tools_to_install)} -y")
    
    # Enable auditd and AppArmor
    run_command("systemctl enable --now auditd", silent=True)
    run_command("auditctl -e 1")
    run_command("systemctl enable --now apparmor", silent=True)

    # 2. Prohibited Software Purge
    print_status("Purging hacking tools and games...")
    software_to_purge = HACKING_TOOLS + GAMES
    run_command(f"apt purge {' '.join(software_to_purge)} -y")
    run_command("apt autoremove -y")

    # 3. Service Alignment (Install and Enable required services)
    print_status("Aligning services with requirements...")
    if REQUIRED_SERVICES:
        # Attempt install, silencing errors in case they are already installed
        run_command(f"apt install {' '.join(REQUIRED_SERVICES)} -y", silent=True)

        for service in REQUIRED_SERVICES:
            service_name = service
            if service == "openssh-server": service_name = "ssh"
            elif service == "samba": service_name = "smbd"
            
            run_command(f"systemctl unmask {service_name}", silent=True)
            run_command(f"systemctl enable --now {service_name}", silent=True)

    
    # 4. Advanced Service Hardening (Deep Dive)
    harden_ssh()
    if "vsftpd" in REQUIRED_SERVICES:
        harden_vsftpd()
    if "samba" in REQUIRED_SERVICES or "smbd" in REQUIRED_SERVICES:
        harden_samba()
    if "apache2" in REQUIRED_SERVICES or "nginx" in REQUIRED_SERVICES:
        harden_apache_php()


# --- Phase 6: Integrity Check and Persistence Hunt ---

def integrity_and_persistence_hunt():
    """Checks for poisoned binaries and hunts for common persistence mechanisms."""
    print_header("Phase 6: Integrity Check and Persistence Hunt")

    # 1. Integrity Check (Debsums)
    print_status("Checking for poisoned binaries (debsums -c)...")
    debsums_output = run_command("debsums -c 2>/dev/null", silent=True)

    if debsums_output:
        failed_files = []
        for line in debsums_output.split('\n'):
             match = re.search(r"(.+):.+FAILED", line)
             if match:
                 failed_files.append(match.group(1).strip())

        if failed_files:
            print_status(f"CRITICAL: Found {len(failed_files)} modified system binaries!", False)
            logging.warning(f"DEBSUMS FAILED FILES: {failed_files}")
            print("\n".join(failed_files[:15])) # Print first 15
            
            response = input("\nDo you want to attempt reinstalling the affected packages? (Recommended: Y) (y/N): ").strip().lower()
            if response == 'y':
                packages_to_reinstall = set()
                for file_path in failed_files:
                    pkg = run_command(f"dpkg -S {file_path} | cut -d: -f1", silent=True)
                    if pkg:
                        packages_to_reinstall.add(pkg)

                if packages_to_reinstall:
                    print_status("Reinstalling affected packages...")
                    run_command(f"apt install --reinstall {' '.join(packages_to_reinstall)} -yq")
    else:
        print_status("System binaries appear clean.")

    # 2. Persistence Hunt: Cron Jobs and Startup Files
    print_status("Auditing Cron Jobs and Startup Files for persistence...")
    locations = ["/etc/crontab", "/etc/init.d/"]
    # Add dynamic locations
    cron_d_output = run_command("ls /etc/cron.*/* 2>/dev/null", silent=True)
    if cron_d_output:
        locations.extend(cron_d_output.split('\n'))
    crontabs_output = run_command("ls /var/spool/cron/crontabs/* 2>/dev/null", silent=True)
    if crontabs_output:
        locations.extend(crontabs_output.split('\n'))

    # Add user home directories for .bashrc/.profile checks
    user_homes_output = run_command("grep '/home/' /etc/passwd | cut -d: -f6", silent=True)
    user_homes = user_homes_output.split('\n') if user_homes_output else []
    user_homes.append("/root")
    
    for home in user_homes:
        if home and home.strip():
            locations.append(f"{home}/.bashrc")
            locations.append(f"{home}/.profile")

    # Keywords often found in backdoors
    suspicious_keywords = ["nc ", "netcat", "/tmp/", "http://", "wget ", "curl ", "base64 -d", "python -c", "perl -e", "bash -i"]
    found_suspicious = False

    for location in locations:
        if location and location.strip() and os.path.exists(location):
             # Handle directories vs files
            if os.path.isdir(location):
                files = [os.path.join(location, f) for f in os.listdir(location)]
            else:
                files = [location]

            for file_path in files:
                if os.path.isfile(file_path):
                    content = run_command(f"cat {file_path}", silent=True)
                    if content:
                        for line in content.split('\n'):
                            if line.strip() and not line.strip().startswith("#"):
                                for keyword in suspicious_keywords:
                                    if keyword in line:
                                        print_status(f"SUSPICIOUS ENTRY in {file_path}: {line}", False)
                                        logging.warning(f"SUSPICIOUS ENTRY FOUND: {file_path}: {line}")
                                        found_suspicious = True
                                        break
    
    if not found_suspicious:
        print_status("Persistence locations appear clean.")
    else:
        print_status("NOTE: Suspicious entries found. Manual investigation required.", None)

# --- Phase 7: Firewall Activation ---

def firewall_activation():
    """Configures UFW."""
    print_header("Phase 7: Firewall Activation")

    run_command("ufw reset --force")
    run_command("ufw default deny incoming")
    run_command("ufw default allow outgoing")
    run_command("ufw logging medium")

    # Allow required ports
    ports_allowed = set()
    for service in REQUIRED_SERVICES:
        found_ports = None
        for key in SERVICE_PORTS:
            if service.lower().startswith(key):
                found_ports = SERVICE_PORTS[key]
                break
        
        if found_ports:
            # Handle single port or list of ports
            if not isinstance(found_ports, list):
                found_ports = [found_ports]

            for port in found_ports:
                if port not in ports_allowed:
                    print_status(f"Allowing port {port} for {service}...")
                    # Rate limiting for SSH
                    if port == 22:
                        run_command(f"ufw limit {port}/tcp")
                    else:
                        # Allow both TCP/UDP for Samba ports
                        if port in [139, 445]:
                             run_command(f"ufw allow {port}")
                        else:
                             run_command(f"ufw allow {port}/tcp")
                    ports_allowed.add(port)

    print_status("Enabling UFW...")
    run_command("echo 'y' | ufw enable")
    run_command("ufw status verbose")

# --- Main Execution ---

def main():
    # Phase 1: Initialize, Update, Stabilize (Handles setup checks and root requirements)
    initialization_and_updates()

    # Phase 2: Media Hunt
    run_media_hunt()

    # Phase 3: User Management
    user_management_blitz()

    # Phase 4: Configuration Hardening (PAM, System)
    configuration_hardening()

    # Phase 5: Service Hardening
    software_services_and_hardening()

    # Phase 6: Integrity and Persistence
    integrity_and_persistence_hunt()

    # Phase 7: Firewall
    firewall_activation()

    print_header("Script Execution Complete")
    logging.info("Juggernaut v2 Script Finished")
    print_status(f"Automation finished. Review the log file: {LOG_FILE}")
    print_status("CRITICAL MANUAL CHECKS:", None)
    print_status("1. Verify PAM stability: Open a NEW terminal and run 'sudo ls'. If it fails, revert PAM backups (/etc/pam.d/*.bak_juggernaut).", None)
    print_status("2. Audit /etc/sudoers (visudo) for NOPASSWD entries.", None)
    print_status("3. Investigate Persistence Hunt findings (Cron/Bashrc) and remove manually.", None)
    print_status("4. Check SUID/SGID bits (find / -perm /6000 -type f 2>/dev/null).", None)
    print_status("5. Verify complex service configurations (e.g., specific Apache site configs, database access).", None)

if __name__ == "__main__":
    # Ensure Input directory exists before starting the main flow
    if not os.path.exists(INPUT_DIR):
        setup_directories()
    main()