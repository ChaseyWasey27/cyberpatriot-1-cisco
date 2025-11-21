import subprocess
import os
import pwd
import grp
import re
import sys
import shutil
import curses

# --- Configuration ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INPUT_DIR = os.path.join(BASE_DIR, "Input")
CONFIG_BASE_DIR = os.path.join(BASE_DIR, "Configs")

# Input Files
USERS_FILE = os.path.join(INPUT_DIR, "users.txt")
ADMINS_FILE = os.path.join(INPUT_DIR, "admins.txt")
GROUPS_FILE = os.path.join(INPUT_DIR, "groups.txt")
SERVICES_FILE = os.path.join(INPUT_DIR, "services.txt")
PASSWORD_FILE = os.path.join(INPUT_DIR, "password.txt")

# Globals
NEW_PASSWORD = ""
OS_VERSION = ""
CONFIG_DIR = ""
AUTHORIZED_USERS = []
AUTHORIZED_ADMINS = []
REQUIRED_GROUPS = {}
REQUIRED_SERVICES = []

# Constants
HACKING_TOOLS = ["hydra", "john", "nmap", "netcat", "nc", "wireshark", "aircrack-ng", "ophcrack", "nikto", "sqlmap", "kismet", "medusa", "dsniff", "ettercap"]
GAMES = ["aisleriot", "gnome-mines", "gnome-sudoku", "freeciv", "openarena"]

SERVICE_PORTS = {
    "ssh": 22, "openssh-server": 22,
    "apache2": 80, "nginx": 80,
    "vsftpd": 21, "proftpd": 21,
    "mysql": 3306, "mariadb": 3306, "mysql-server": 3306,
    "postgresql": 5432,
}

# --- Helper Functions ---

def run_command(command, input_data=None, silent=False):
    """Executes a shell command."""
    try:
        env = os.environ.copy()
        env["DEBIAN_FRONTEND"] = "noninteractive"
        
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, input=input_data, text=True, env=env)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        if not silent:
            print_status(f"Command failed: {command}\nStderr: {e.stderr.strip()}", False)
        return None
    except Exception as e:
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
    if not os.path.exists(INPUT_DIR) or not os.path.exists(CONFIG_BASE_DIR):
        os.makedirs(INPUT_DIR, exist_ok=True)
        os.makedirs(os.path.join(CONFIG_BASE_DIR, "20.04/pam.d"), exist_ok=True)
        os.makedirs(os.path.join(CONFIG_BASE_DIR, "22.04/pam.d"), exist_ok=True)

        try:
            current_user = os.getenv("SUDO_USER", "operator")
        except:
            current_user = "operator"

        files_to_create = {
            USERS_FILE: f"{current_user}\n",
            ADMINS_FILE: f"{current_user}\n",
            GROUPS_FILE: "example_group:user1,user2\n",
            SERVICES_FILE: "ssh\n",
            PASSWORD_FILE: "ChangeMe!2025$\n"
        }
        for filepath, content in files_to_create.items():
            if not os.path.exists(filepath):
                with open(filepath, 'w') as f:
                    f.write(content)
        
        print(f"Setup Complete: Created Input and Config directories.")
        print(f"Please populate the files in {INPUT_DIR} based on the README.")
        print(f"Ensure 'Golden Configs' (PAM files) are placed in {CONFIG_BASE_DIR}.")
        print("Run the script again with sudo.")
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
            AUTHORIZED_USERS = [line.strip() for line in f if line.strip()]

        with open(ADMINS_FILE, 'r') as f:
            AUTHORIZED_ADMINS = [line.strip() for line in f if line.strip()]

        # Ensure admins are authorized users
        for admin in AUTHORIZED_ADMINS:
            if admin not in AUTHORIZED_USERS:
                AUTHORIZED_USERS.append(admin)

        with open(SERVICES_FILE, 'r') as f:
            REQUIRED_SERVICES = [line.strip() for line in f if line.strip()]

        # Load Groups (Format: group:user1,user2)
        with open(GROUPS_FILE, 'r') as f:
            for line in f:
                if ":" in line and line.strip():
                    group, users_str = line.strip().split(":", 1)
                    REQUIRED_GROUPS[group] = users_str.split(",")

        print_status(f"Input files loaded. Users: {len(AUTHORIZED_USERS)}, Admins: {len(AUTHORIZED_ADMINS)}, Groups: {len(REQUIRED_GROUPS)}")

    except FileNotFoundError as e:
        print_status(f"Error loading input files: {e}.", False)
        sys.exit(1)

# --- Phase 1: Initialization & Stabilization ---

def initialization():
    """Checks for root, removes immutable bits, detects OS, and updates."""
    print_header("Phase 1: Initialization & Stabilization")

    if os.geteuid() != 0:
        print_status("This script must be run as root. Use sudo.", False); sys.exit(1)

    load_input_files()

    # 1. Remove Immutable Bits (The CP Meta)
    print_status("Removing immutable bits (chattr -i)...")
    run_command("chattr -iaR /etc /home /opt /root /var /usr /srv /bin /sbin", silent=True)

    # 2. Detect OS Version and Set Config Path
    global OS_VERSION, CONFIG_DIR
    try:
        OS_VERSION = run_command("lsb_release -rs")
        print_status(f"Detected OS Version: {OS_VERSION}")
        
        # Determine Config Directory
        version_float = 0.0
        try:
            version_match = re.match(r"(\d+\.\d+)", OS_VERSION)
            if version_match:
                version_float = float(version_match.group(1))
        except:
            pass

        if version_float >= 22.04:
            CONFIG_DIR = os.path.join(CONFIG_BASE_DIR, "22.04")
        elif version_float >= 18.04:
             CONFIG_DIR = os.path.join(CONFIG_BASE_DIR, "20.04")
        else:
            CONFIG_DIR = os.path.join(CONFIG_BASE_DIR, "20.04") # Fallback
            print_status(f"Unknown or older OS version. Falling back to {CONFIG_DIR}", None)

    except Exception as e:
        print_status(f"Could not detect OS version: {e}", False)
        sys.exit(1)

    # 3. Fix Repositories and Update
    print_status("Fixing sources.list and running apt update...")
    try:
        codename = run_command("lsb_release -cs")
        if codename:
            # Assuming standard Ubuntu repositories
            sources_content = f"""
deb http://archive.ubuntu.com/ubuntu/ {codename} main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu/ {codename}-updates main restricted universe multiverse
deb http://security.ubuntu.com/ubuntu/ {codename}-security main restricted universe multiverse
"""
            with open("/etc/apt/sources.list", "w") as f:
                f.write(sources_content)
            run_command("apt update -y")
        else:
            print_status("Could not determine codename. Skipping repository fix.", None)
    except Exception as e:
        print_status(f"Failed to update repositories: {e}", False)

# --- Phase 2: Interactive Media Hunt (Curses TUI) ---

def interactive_media_hunt(stdscr):
    """Uses curses TUI for selecting files to delete."""
    curses.curs_set(0)
    curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)
    curses.init_pair(2, curses.COLOR_RED, curses.COLOR_BLACK)

    media_exts = ["*.mp3", "*.mp4", "*.avi", "*.mkv", "*.mov", "*.jpg", "*.jpeg", "*.png", "*.gif", "*.wav"]
    script_exts = ["*.sh", "*.py", "*.pl", "*.rb"]
    extensions = media_exts + script_exts
    
    search_command = f"find /home /var/www /srv /tmp -type f \( -iname {' -o -iname '.join(extensions)} \) 2>/dev/null"
    files_found = run_command(search_command)

    if not files_found:
        stdscr.addstr(0, 0, "No prohibited media or suspicious scripts found. Press any key.")
        stdscr.refresh(); stdscr.getch(); return

    file_list = [f for f in files_found.split('\n') if f]
    selected_files = set()
    current_row = 0

    def draw_menu():
        stdscr.clear()
        height, width = stdscr.getmaxyx()
        stdscr.addstr(0, 0, "Select files to DELETE (Spacebar). Press ENTER when done. 'q' to cancel.", curses.A_BOLD)

        # Handle Scrolling
        visible_rows = height - 3
        if visible_rows < 1: visible_rows = 1
        
        start_index = max(0, min(current_row - visible_rows // 2, len(file_list) - visible_rows))
        end_index = min(len(file_list), start_index + visible_rows)

        for idx in range(start_index, end_index):
            file_path = file_list[idx]
            display_idx = idx - start_index + 2

            mode = curses.A_REVERSE if idx == current_row else curses.A_NORMAL

            if file_path in selected_files:
                stdscr.addstr(display_idx, 2, "[X] ", curses.color_pair(2) | mode)
            else:
                stdscr.addstr(display_idx, 2, "[ ] ", curses.color_pair(1) | mode)

            # Truncate path
            display_path = file_path if len(file_path) < width - 8 else "..." + file_path[-(width - 11):]
            try:
                stdscr.addstr(display_idx, 6, display_path, mode)
            except curses.error:
                pass # Handle writing near the edge

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
                stdscr.addstr(i+1, 0, f"Deleted: {file_path}")
            except Exception as e:
                stdscr.addstr(i+1, 0, f"Error deleting {file_path}: {e}", curses.color_pair(2))
        stdscr.addstr("\nDeletion complete. Press any key.")
        stdscr.refresh(); stdscr.getch()

def run_media_hunt():
    print_header("Phase 2: Interactive Media Hunt")
    print_status("WARNING: Answer forensics questions BEFORE deleting files.", None)
    input("Press Enter to launch the media hunt interface...")
    try:
        curses.wrapper(interactive_media_hunt)
    except Exception as e:
        print_status(f"Curses interface failed (e.g., terminal resize or error): {e}. Manual deletion required.", False)


# --- Phase 3: User Management Blitz ---

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
        # Ensure group exists
        try:
            grp.getgrnam(group)
        except KeyError:
            print_status(f"Creating missing group: {group}...", None)
            run_command(f"groupadd {group}", silent=True)
        
        # Add users to the group
        for user in users:
            if user in AUTHORIZED_USERS:
                print_status(f"Adding {user} to {group}...")
                run_command(f"usermod -a -G {group} {user}", silent=True)
            else:
                print_status(f"Skipping group assignment for unauthorized/missing user: {user}", None)

    # 6. Password Standardization
    print_status("Standardizing passwords...")
    users_to_change = AUTHORIZED_USERS + ['root']
    chpasswd_input = ""
    for username in users_to_change:
        # Check if user exists before trying to change password
        try:
            pwd.getpwnam(username)
            chpasswd_input += f"{username}:{NEW_PASSWORD}\n"
        except KeyError:
            pass

    if run_command("chpasswd", input_data=chpasswd_input) is not None:
        # Force password change on next login (often scored)
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
    print_status("Locking root account (passwd -l root)...")
    run_command("passwd -l root", silent=True)

# --- Phase 4: Configuration Hardening (Golden Config Strategy) ---

def configuration_hardening():
    """Applies security configurations using the Golden Config strategy."""
    print_header("Phase 4: Configuration Hardening")

    # Install necessary packages for PAM
    run_command("apt install libpam-pwquality libpam-modules -y")

    # 1. Password Aging (/etc/login.defs)
    print_status("Configuring password aging (/etc/login.defs)...")
    run_command("sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs")
    run_command("sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   7/' /etc/login.defs")
    # Ensure SHA512 hashing
    if not run_command("grep '^ENCRYPT_METHOD SHA512' /etc/login.defs", silent=True):
         run_command("echo 'ENCRYPT_METHOD SHA512' >> /etc/login.defs")

    # 2. PAM Configuration (Golden Config Strategy)
    print_status(f"Applying PAM configurations from {CONFIG_DIR}...")
    PAM_DIR = os.path.join(CONFIG_DIR, "pam.d")
    
    if os.path.exists(PAM_DIR) and os.listdir(PAM_DIR):
        # Backup existing PAM
        shutil.copytree("/etc/pam.d", "/etc/pam.d.bak", dirs_exist_ok=True)
        
        # Copy Golden Configs (Safer than dynamic editing)
        try:
            # Use cp command for robustness
            if run_command(f"cp {PAM_DIR}/* /etc/pam.d/") is not None:
                print_status("PAM configuration applied successfully.")
            else:
                 print_status(f"Failed to apply PAM configs. System may be unstable!", False)
        except Exception as e:
            print_status(f"Error during PAM copy: {e}. System may be unstable!", False)
    else:
        print_status(f"CRITICAL: PAM directory not found or empty at {PAM_DIR}. Skipping PAM hardening.", False)

    # 3. Kernel Hardening (/etc/sysctl.conf)
    print_status("Applying Kernel Hardening (/etc/sysctl.conf)...")
    sysctl_settings = {
        "net.ipv4.tcp_syncookies": 1,
        "net.ipv4.conf.all.rp_filter": 1,
        "net.ipv4.conf.all.accept_redirects": 0,
        "net.ipv6.conf.all.accept_redirects": 0,
        "net.ipv4.conf.all.send_redirects": 0,
        "net.ipv6.conf.all.disable_ipv6": 1 # Often scored
    }
    for key, value in sysctl_settings.items():
        run_command(f"sed -i '/^{key}/d' /etc/sysctl.conf", silent=True)
        run_command(f"echo '{key} = {value}' >> /etc/sysctl.conf")

    run_command("sysctl -p")

    # 4. GUI Hardening (Disable Guest)
    print_status("Disabling Guest Account...")
    # LightDM
    if os.path.exists("/etc/lightdm/"):
        os.makedirs("/etc/lightdm/lightdm.conf.d", exist_ok=True)
        run_command("echo '[Seat:*]\nallow-guest=false' > /etc/lightdm/lightdm.conf.d/50-no-guest.conf")
    # GDM
    if os.path.exists("/etc/gdm3/custom.conf"):
         run_command("sed -i '/^\[daemon\]/a AutomaticLoginEnable=false\nAllowGuest=false' /etc/gdm3/custom.conf", silent=True)

# --- Phase 5: Software, Services, and Integrity ---

def software_services_integrity():
    """Manages software, services, and runs debsums."""
    print_header("Phase 5: Software, Services, and Integrity")

    # 1. Install Tools
    print_status("Installing security tools (ufw, auditd, debsums)...")
    tools_to_install = ["ufw", "auditd", "debsums", "net-tools"]
    run_command(f"apt install {' '.join(tools_to_install)} -y")
    # Enable auditd
    run_command("systemctl enable --now auditd", silent=True)
    run_command("auditctl -e 1")

    # 2. Prohibited Software Purge
    print_status("Purging hacking tools and games...")
    software_to_purge = HACKING_TOOLS + GAMES
    run_command(f"apt purge {' '.join(software_to_purge)} -y")
    run_command("apt autoremove -y")

    # 3. Service Alignment
    print_status("Aligning services with requirements...")
    if REQUIRED_SERVICES:
        run_command(f"apt install {' '.join(REQUIRED_SERVICES)} -y")

        for service in REQUIRED_SERVICES:
            service_name = service
            if service == "openssh-server": service_name = "ssh"
            elif service == "samba": service_name = "smbd"
            
            run_command(f"systemctl unmask {service_name}", silent=True)
            run_command(f"systemctl enable --now {service_name}", silent=True)
    
    # 4. Advanced Service Hardening
    # SSH Hardening
    if os.path.exists("/etc/ssh/sshd_config"):
        print_status("Hardening SSH configuration...")
        run_command("sed -i 's/.*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config")
        run_command("sed -i 's/.*X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config")
        run_command("systemctl restart ssh", silent=True)

    # VSFTPD Hardening (State Round Level)
    if os.path.exists("/etc/vsftpd.conf"):
        print_status("Hardening VSFTPD (Disabling Anon, Forcing SSL)...")
        
        def update_vsftpd_conf(key, value):
             run_command(f"sed -i '/^{key}=/d' /etc/vsftpd.conf", silent=True)
             run_command(f"echo '{key}={value}' >> /etc/vsftpd.conf")

        update_vsftpd_conf("anonymous_enable", "NO")
        update_vsftpd_conf("local_enable", "YES")
        update_vsftpd_conf("chroot_local_user", "YES")
        # Force SSL/TLS (Requires manual certificate setup)
        update_vsftpd_conf("ssl_enable", "YES")
        update_vsftpd_conf("force_local_data_ssl", "YES")
        update_vsftpd_conf("force_local_logins_ssl", "YES")
        
        run_command("systemctl restart vsftpd", silent=True)


    # PHP Hardening (State Round Level - Web Shell Prevention)
    if "apache2" in REQUIRED_SERVICES or "nginx" in REQUIRED_SERVICES:
        print_status("Web server detected. Applying PHP hardening...")
        php_inis = run_command("find /etc/php -name php.ini 2>/dev/null")
        if php_inis:
            disabled_functions = "exec,passthru,shell_exec,system,proc_open,popen,curl_exec,show_source,pcntl_exec"
            for ini_file in php_inis.split('\n'):
                if ini_file.strip():
                    run_command(f"sed -i 's/.*disable_functions.*/disable_functions = {disabled_functions}/' {ini_file}")
                    run_command(f"sed -i 's/.*expose_php.*/expose_php = Off/' {ini_file}")

    # 5. Integrity Check (Debsums)
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
            print("\n".join(failed_files))
            response = input("\nDo you want to attempt reinstalling the affected packages? (Recommended: Y) (y/N): ").strip().lower()
            if response == 'y':
                packages_to_reinstall = set()
                for file_path in failed_files:
                    pkg = run_command(f"dpkg -S {file_path} | cut -d: -f1", silent=True)
                    if pkg:
                        packages_to_reinstall.add(pkg)

                if packages_to_reinstall:
                    print_status("Reinstalling affected packages...")
                    run_command(f"apt install --reinstall {' '.join(packages_to_reinstall)} -y")
    else:
        print_status("System binaries appear clean.")

# --- Phase 6: Firewall Activation ---

def firewall_activation():
    """Configures UFW."""
    print_header("Phase 6: Firewall Activation")

    run_command("ufw reset --force")
    run_command("ufw default deny incoming")
    run_command("ufw default allow outgoing")
    run_command("ufw logging on")

    # Allow required ports
    ports_allowed = set()
    for service in REQUIRED_SERVICES:
        found_port = None
        for key in SERVICE_PORTS:
            if service.startswith(key):
                found_port = SERVICE_PORTS[key]
                break
        
        if found_port and found_port not in ports_allowed:
            print_status(f"Allowing port {found_port} for {service}...")
            # Rate limiting for SSH
            if found_port == 22:
                run_command(f"ufw limit {found_port}/tcp")
            else:
                run_command(f"ufw allow {found_port}/tcp")
            ports_allowed.add(found_port)

    print_status("Enabling UFW...")
    run_command("echo 'y' | ufw enable")
    run_command("ufw status verbose")

# --- Main Execution ---

def main():
    # Setup Check
    setup_directories()

    # Phase 1
    initialization()

    # Phase 2
    run_media_hunt()

    # Phase 3
    user_management_blitz()

    # Phase 4
    configuration_hardening()

    # Phase 5
    software_services_integrity()

    # Phase 6
    firewall_activation()

    print_header("Script Execution Complete")
    print_status("Automation finished. Proceed to manual checks:")
    print_status("1. Verify PAM stability (try 'sudo ls' in a new terminal). CRITICAL if errors occurred during Phase 4.", None)
    print_status("2. Audit /etc/sudoers (visudo) for NOPASSWD entries.", None)
    print_status("3. Audit Crontabs (cat /etc/crontab) and SUID/SGID bits.", None)
    print_status("4. Configure complex services (Apache Headers, VSFTPD SSL Certs, MySQL/PostgreSQL).", None)

if __name__ == "__main__":
    main()