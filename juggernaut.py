import curses
import datetime
import glob
import grp
import json
import logging
import os
import pwd
import re
import shutil
import signal  # V6: Required for Active Kill
import subprocess
import sys
import time

# V6: Required for secure password auditing
try:
    import crypt
    import spwd
except ImportError:
    print(
        "Warning: 'crypt' or 'spwd' modules missing. Advanced password auditing disabled."
    )
    crypt = None
    spwd = None

# =============================================================================
# Juggernaut v6 (Active Defense) - CyberPatriot Linux Automation
# =============================================================================

# --- Configuration ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INPUT_DIR = os.path.join(BASE_DIR, "Input")
LOG_FILE = os.path.join(BASE_DIR, "juggernaut_v6.log")
FORENSICS_DIR = os.path.join(BASE_DIR, "Forensics")

# Input Files (Paths defined here)
USERS_FILE = os.path.join(INPUT_DIR, "users.txt")
ADMINS_FILE = os.path.join(INPUT_DIR, "admins.txt")
ADMIN_AUDIT_FILE = os.path.join(INPUT_DIR, "admin_passwords_audit.txt")
GROUPS_FILE = os.path.join(INPUT_DIR, "groups.txt")
SERVICES_FILE = os.path.join(INPUT_DIR, "services.txt")
PASSWORD_FILE = os.path.join(INPUT_DIR, "password.txt")
INSTALLS_FILE = os.path.join(INPUT_DIR, "required_installs.txt")
PROHIBITED_FILE = os.path.join(INPUT_DIR, "prohibited_software.txt")

# Globals (Initialized empty)
NEW_PASSWORD = ""
OS_DISTRO = ""
CURRENT_OPERATOR = ""
AUTHORIZED_USERS = []
AUTHORIZED_ADMINS_LIST = []
ADMIN_WEAK_PASSWORDS = {}
REQUIRED_GROUPS = {}
REQUIRED_SERVICES_RAW = []
REQUIRED_INSTALLS = []
PROHIBITED_SOFTWARE = []

# Constants (Use the comprehensive list provided in previous interactions for DEFAULT_PROHIBITED)
DEFAULT_PROHIBITED = [
    "hydra",
    "john",
    "nmap",
    "netcat",
    "nc",
    "wireshark",
    "aircrack-ng",
    "ophcrack",
    "nikto",
    "sqlmap",
    "kismet",
    "medusa",
    "dsniff",
    "ettercap",
    "hashcat",
    "metasploit-framework",
    "telnetd",
    "rsh-server",
    "tftpd",
    "finger",
    "talkd",
    "aisleriot",
    "gnome-mines",
    "gnome-sudoku",
    "freeciv",
    "openarena",
    "minetest",
    "transmission",
    "vuze",
    "frostwire",
    "amule",
    "irssi",
    "hexchat",
    # Aggressive Service Purge
    "apache2",
    "nginx",
    "lighttpd",
    "vsftpd",
    "proftpd",
    "pure-ftpd",
    "mysql-server",
    "mariadb-server",
    "postgresql",
    "mongodb",
    "bind9",
    "squid",
    "snmpd",
    "nfs-kernel-server",
    "postfix",
    "sendmail",
    "exim4",
]

SERVICE_MAP = {
    "ssh": ("openssh-server", "ssh"),
    "sshd": ("openssh-server", "ssh"),
    "apache2": ("apache2", "apache2"),
    "nginx": ("nginx", "nginx"),
    "vsftpd": ("vsftpd", "vsftpd"),
    "proftpd": ("proftpd-basic", "proftpd"),
    "samba": ("samba", "smbd"),
    "smbd": ("samba", "smbd"),
}

SERVICE_PORTS = {
    "ssh": [22],
    "apache2": [80, 443],
    "nginx": [80, 443],
    "vsftpd": [21],
    "proftpd": [21],
    "smbd": [139, 445],
}

# V6: EXPANDED Essential services whitelist (Prevents GUI/System breakage)
ESSENTIAL_SERVICES = [
    # Core System/Hardware
    "dbus",
    "systemd-",
    "udev",
    "kmod",
    "ModemManager",
    "polkit",
    "upower",
    "acpid",
    "irqbalance",
    "thermald",
    "power-profiles-daemon",
    # Networking
    "NetworkManager",
    "wpa_supplicant",
    "avahi-daemon",
    "bluetooth",
    "networkd-dispatcher",  # V6.2: Network event handler
    # Filesystem/Mounting (CRITICAL FIX: Includes udisks2)
    "udisks2",
    "bolt",
    # GUI/Display Managers (CRITICAL FIX: Includes plymouth)
    "gdm",
    "gdm3",
    "lightdm",
    "sddm",
    "plymouth",
    # GUI Components
    "colord",
    "rtkit-daemon",
    "geoclue",
    "switcheroo-control",
    # User Session Management (V6.2 CRITICAL FIX: user-runtime-dir@ for session stability)
    "user@",
    "user-runtime-dir@",  # V6.2 FIX: CRITICAL - manages /run/user/UID, killing breaks session
    "session-",           # V6.2: Session scopes
    "getty@",
    "accounts-daemon",
    # Utilities/Logging
    "cron",
    "anacron",
    "rsyslog",
    "auditd",
    "apparmor",
    "apport",             # V6.2: Crash reporting (safe to keep)
    "fwupd",              # V6.2: Firmware updates (safe to keep)
    # Software Management
    "snapd",
    "packagekit",
    "unattended-upgrades",
    "aptd",
    "update-notifier",
    # Common Utilities
    "cups",
    "cups-browsed",
    "whoopsie",
    "kerneloops",
    # Hardware Setup (Critical for boot)
    "console-setup",
    "keyboard-setup",
    "setvtrgb",
    "alsa-restore",
    "alsa-state",
    # VM Tools
    "open-vm-tools",
    "vgauthservice",
    "vmtoolsd",
    "vgauth",
    "spice-vdagent",
    # CP Specific
    "ccsclient",
    "ufw",
]

# V6: Known good SUID/SGID binaries (whitelist)
KNOWN_GOOD_SUID = [
    "/usr/bin/sudo",
    "/usr/bin/passwd",
    "/usr/bin/gpasswd",
    "/usr/bin/chfn",
    "/usr/bin/chsh",
    "/usr/bin/newgrp",
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
    "/usr/lib/openssh/ssh-keysign",
    "/bin/mount",
    "/bin/umount",
    "/bin/su",
    "/usr/bin/pkexec",
    "/usr/lib/policykit-1/polkit-agent-helper-1",
    "/usr/libexec/polkit-agent-helper-1",
    "/usr/lib/snapd/snap-confine",
]

# --- Helper Functions ---


def setup_logging():
    logging.basicConfig(
        filename=LOG_FILE,
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )


def get_current_operator():
    # V6: Robust operator detection
    user = os.getenv("SUDO_USER")
    if not user or user == "root":
        user = os.getenv("USER", "unknown")
    return user


def run_command(command, input_data=None, silent=False, suppress_stderr=False):
    """Executes a shell command and logs it."""
    logging.info(f"EXECUTING: {command}")

    # Use apt-get consistently
    command = (
        command.replace("apt install", "apt-get install")
        .replace("apt update", "apt-get update")
        .replace("apt purge", "apt-get purge")
        .replace("apt upgrade", "apt-get upgrade")
        .replace("apt autoremove", "apt-get autoremove")
    )

    try:
        env = os.environ.copy()
        env["DEBIAN_FRONTEND"] = "noninteractive"

        stderr_destination = subprocess.PIPE
        if suppress_stderr:
            stderr_destination = subprocess.DEVNULL

        result = subprocess.run(
            command,
            shell=True,
            check=True,
            stdout=subprocess.PIPE,
            stderr=stderr_destination,
            input=input_data,
            text=True,
            env=env,
        )

        if result.stdout and result.stdout.strip():
            logging.info(f"SUCCESS (STDOUT Snippet): {result.stdout.strip()[:200]}")
        else:
            logging.info(f"SUCCESS: {command}")
        return result.stdout.strip()

    except subprocess.CalledProcessError as e:
        error_message = f"FAILED: {command} (RC: {e.returncode})"
        if not suppress_stderr and e.stderr:
            error_message += f"\nSTDERR: {e.stderr.strip()}"

        logging.error(error_message)

        # Handle common non-fatal errors
        if e.returncode == 1 and (
            "grep" in command or "find" in command or "debsums -c" in command
        ):
            return None

        if not silent:
            print_status(error_message, False)
        return None
    except Exception as e:
        logging.error(f"EXCEPTION: {e} during command {command}")
        if not silent:
            print_status(f"An unexpected error occurred: {e}", False)
        return None


def print_header(title):
    print(f"\n{'=' * 60}\n\033[34m=== {title} ===\033[0m\n{'=' * 60}")


def print_status(message, success=True):
    if success is True:
        status = "\033[32m[+]\033[0m"
    elif success is False:
        status = "\033[31m[-]\033[0m"
    else:
        status = "\033[33m[!]\033[0m"
    print(f"{status} {message}")


def confirm_action(prompt):
    response = (
        input(f"\n\033[33m[CONFIRMATION]\033[0m {prompt} (Y/n): ").strip().lower()
    )
    if response == "" or response == "y":
        return True
    print_status("Action aborted by user.", None)
    return False


def setup_directories():
    """Creates necessary directories and template files."""
    if not os.path.exists(INPUT_DIR):
        os.makedirs(INPUT_DIR, exist_ok=True)
        os.makedirs(FORENSICS_DIR, exist_ok=True)  # V6
        current_user = get_current_operator()

        files_to_create = {
            USERS_FILE: f"{current_user}\n",
            ADMINS_FILE: f"{current_user}\n",
            ADMIN_AUDIT_FILE: "# Enter WEAK passwords corresponding line-by-line to admins.txt\n",
            GROUPS_FILE: "# Format: group_name:user1,user2\n",
            SERVICES_FILE: "ssh\n",
            PASSWORD_FILE: "CyberP@triot!State2025\n",
            INSTALLS_FILE: "# Add required installs\n",
            PROHIBITED_FILE: "\n".join(DEFAULT_PROHIBITED) + "\n",
        }
        for filepath, content in files_to_create.items():
            if not os.path.exists(filepath):
                with open(filepath, "w") as f:
                    f.write(content)

        print(
            f"Setup Complete: Please populate the files in {INPUT_DIR} and run again with sudo."
        )
        sys.exit(0)


def load_input_files():
    """Loads configuration from the input directory."""
    global \
        NEW_PASSWORD, \
        AUTHORIZED_USERS, \
        AUTHORIZED_ADMINS_LIST, \
        ADMIN_WEAK_PASSWORDS, \
        REQUIRED_SERVICES_RAW, \
        REQUIRED_GROUPS, \
        REQUIRED_INSTALLS, \
        PROHIBITED_SOFTWARE

    try:
        with open(PASSWORD_FILE, "r") as f:
            NEW_PASSWORD = f.read().strip()

        if not NEW_PASSWORD or len(NEW_PASSWORD) < 8:
            print_status(
                "CRITICAL: Password file is empty or too short (min 8 chars)!", False
            )
            sys.exit(1)

        def load_list(filename, lower=True):
            with open(filename, "r") as f:
                if lower:
                    return [
                        line.strip().lower()
                        for line in f
                        if line.strip() and not line.startswith("#")
                    ]
                else:
                    return [
                        line.strip()
                        for line in f
                        if line.strip() and not line.startswith("#")
                    ]

        AUTHORIZED_USERS = load_list(USERS_FILE, lower=False)
        REQUIRED_INSTALLS = load_list(INSTALLS_FILE)
        PROHIBITED_SOFTWARE = load_list(PROHIBITED_FILE)
        REQUIRED_SERVICES_RAW = load_list(SERVICES_FILE)

        if not PROHIBITED_SOFTWARE:
            PROHIBITED_SOFTWARE = DEFAULT_PROHIBITED

        # Paired Admin/Password Audit Loading
        admin_lines = load_list(ADMINS_FILE, lower=False)
        audit_lines = load_list(ADMIN_AUDIT_FILE, lower=False)

        AUTHORIZED_ADMINS_LIST = admin_lines

        for i, admin in enumerate(admin_lines):
            if i < len(audit_lines) and audit_lines[i]:
                ADMIN_WEAK_PASSWORDS[admin] = audit_lines[i]
                logging.info(f"Loaded expected weak password for audit: {admin}")

        for admin in AUTHORIZED_ADMINS_LIST:
            if admin not in AUTHORIZED_USERS:
                AUTHORIZED_USERS.append(admin)

        # Groups
        with open(GROUPS_FILE, "r") as f:
            for line in f:
                if ":" in line and line.strip() and not line.startswith("#"):
                    group, users_str = line.strip().split(":", 1)
                    REQUIRED_GROUPS[group] = users_str.split(",")

        print_status("Input files loaded.")

    except FileNotFoundError as e:
        print_status(f"Error loading input files: {e}.", False)
        sys.exit(1)


# --- Phase 1: Initialization & Stabilization ---


def initialization():
    """Checks for root, detects OS, stabilizes system, identifies operator."""
    print_header("Phase 1: Initialization & Stabilization")
    global CURRENT_OPERATOR, OS_DISTRO
    CURRENT_OPERATOR = get_current_operator()

    if os.geteuid() != 0:
        setup_directories()
        print_status("This script must be run as root. Use sudo.", False)
        sys.exit(1)

    setup_logging()
    load_input_files()
    print_status(f"Operator Protection Active for: {CURRENT_OPERATOR}")
    logging.info(f"Operator identified as: {CURRENT_OPERATOR}")

    try:
        OS_VERSION = run_command("lsb_release -rs")
        OS_DISTRO = run_command("lsb_release -is").lower()
        print_status(f"Detected OS: {OS_DISTRO} {OS_VERSION}")
    except Exception:
        print_status("Could not detect OS version.", False)
        sys.exit(1)

    # Remove Immutable Bits
    print_status("Removing immutable bits (chattr -i), skipping symlinks...")
    run_command(
        "find /etc /home /opt /root /var /usr /srv /bin /sbin -not -type l -exec chattr -ia {} +",
        silent=True,
        suppress_stderr=True,
    )


# --- Phase 1.5: Forensics Collection (V6 New Phase) ---


def forensics_collection():
    """V6: Collects critical system data BEFORE any changes are made."""
    print_header("Phase 1.5: Forensics Collection")
    if not confirm_action(
        "Collect forensics data? (Recommended before updates/changes)"
    ):
        return

    os.makedirs(FORENSICS_DIR, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    F_OUT = os.path.join(FORENSICS_DIR, f"collection_{timestamp}.txt")

    print_status(f"Collecting data to {F_OUT}...")

    commands = {
        "NETWORK_STATE (ss -tulpn)": "ss -tulpn",
        "PROCESS_LIST (ps aux)": "ps aux",
        "AUTH_LOG_TAIL": "tail -n 200 /var/log/auth.log",
        "USER_LIST": "cat /etc/passwd",
        "SUDOERS": "cat /etc/sudoers",
        "CRONTAB_SYSTEM": "cat /etc/crontab",
        "ACTIVE_SERVICES": "systemctl list-units --type=service --state=active",
    }

    with open(F_OUT, "w") as f:
        for name, cmd in commands.items():
            f.write(f"\n\n{'=' * 20} {name} {'=' * 20}\n")
            output = run_command(cmd, silent=True, suppress_stderr=True)
            if output:
                f.write(output)


# --- Phase 1.8: System Updates
def ensure_automatic_updates():
    """Force enable unattended-upgrades for points."""
    print_status(
        "Ensuring Automatic Updates (unattended-upgrades) are configured and running..."
    )
    run_command("apt-get install unattended-upgrades apt-listchanges -yq", silent=True)

    config_content = """
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
"""
    try:
        with open("/etc/apt/apt.conf.d/20auto-upgrades", "w") as f:
            f.write(config_content)
    except IOError as e:
        print_status(f"Failed to write apt config: {e}", False)
    run_command("systemctl unmask unattended-upgrades", silent=True)
    run_command("systemctl enable --now unattended-upgrades", silent=True)


def system_updates():
    """Handles system updates."""
    print_header("Phase 1.8: System Updates")
    if not confirm_action("Run full system update and upgrade? (Can take 10-30+ mins)"):
        return

    print_status("Fixing sources.list and preparing for updates...")
    try:
        # Repository fixing logic
        codename = None
        sources_file_path = "/etc/apt/sources.list"

        if OS_DISTRO == "linuxmint":
            base_codename = run_command(
                "awk -F'=' '/UBUNTU_CODENAME=/{print $2}' /etc/os-release"
            ).strip()
            if base_codename:
                codename = base_codename
                sources_file_path = "/etc/apt/sources.list.d/juggernaut-base.list"
        elif OS_DISTRO == "ubuntu":
            codename = run_command("lsb_release -cs").strip()

        if codename:
            sources_content = f"""
deb http://archive.ubuntu.com/ubuntu/ {codename} main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu/ {codename}-updates main restricted universe multiverse
deb http://security.ubuntu.com/ubuntu/ {codename}-security main restricted universe multiverse
"""
            try:
                with open(sources_file_path, "w") as f:
                    f.write(sources_content)
            except IOError as e:
                print_status(f"Failed to write sources list: {e}", False)

        # Execute Updates and Upgrades
        print_status("Running apt update...")
        if run_command("apt-get update -y") is None:
            run_command("dpkg --configure -a")

        print_status("Running apt upgrade (This may take several minutes)...")
        upgrade_command = "apt-get upgrade -yq -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold'"
        if run_command(upgrade_command) is None:
            print_status("apt upgrade failed.", False)
        else:
            print_status("System upgrade complete.")
            run_command("apt-get autoremove -yq")

        # V6: Ensure this runs at the end to finalize the state
        ensure_automatic_updates()

    except Exception as e:
        print_status(f"Failed during update/upgrade phase: {e}", False)


# --- Phase 2: Interactive Media Hunt (Curses TUI) ---


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

    extensions = [
        "*.mp3",
        "*.mp4",
        "*.avi",
        "*.mkv",
        "*.mov",
        "*.wav",
        "*.flac",
        "*.sh",
        "*.py",
        "*.pl",
        "*.rb",
        "*.php",
        "*.cgi",
        "*.jpg",
        "*.jpeg",
        "*.png",
        "*.gif",
    ]

    search_command = (
        f"find /home /var/www /srv /tmp /opt -type f "
        f"\( -iname {' -o -iname '.join(extensions)} \) "
        f"-not -path '*/.cache/*' -not -path '*/snap/*' -not -path '*/.config/*' "
        f"2>/dev/null"
    )

    files_found = run_command(search_command, silent=True)

    if not files_found:
        stdscr.addstr(0, 0, "No prohibited files found. Press any key.")
        stdscr.refresh()
        stdscr.getch()
        return

    file_list = [f for f in files_found.split("\n") if f]
    selected_files = set()
    current_row = 0

    def draw_menu():
        stdscr.clear()
        height, width = stdscr.getmaxyx()
        stdscr.addstr(
            0,
            0,
            "Select files to DELETE (Spacebar). Press ENTER when done. 'q' to cancel.",
            curses.A_BOLD,
        )
        visible_rows = height - 3
        visible_rows = max(1, visible_rows)
        start_index = max(
            0,
            min(current_row - visible_rows // 2, len(file_list) - visible_rows),
        )
        end_index = min(len(file_list), start_index + visible_rows)

        for idx in range(start_index, end_index):
            file_path = file_list[idx]
            display_idx = idx - start_index + 2
            mode = curses.A_REVERSE if idx == current_row else curses.A_NORMAL
            if file_path in selected_files:
                stdscr.addstr(display_idx, 2, "[X] ", RED | mode)
            else:
                stdscr.addstr(display_idx, 2, "[ ] ", GREEN | mode)
            display_path = (
                file_path
                if len(file_path) < width - 8
                else "..." + file_path[-(width - 11) :]
            )
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
        elif key == ord(" "):
            file_path = file_list[current_row]
            if file_path in selected_files:
                selected_files.remove(file_path)
            else:
                selected_files.add(file_path)
        elif key == 10:
            break
        elif key == ord("q"):
            return

    if selected_files:
        stdscr.clear()
        stdscr.addstr(0, 0, f"Deleting {len(selected_files)} files...", curses.A_BOLD)
        for i, file_path in enumerate(selected_files):
            try:
                os.remove(file_path)
                logging.info(f"DELETED FILE: {file_path}")
            except Exception as e:
                logging.error(f"Error deleting {file_path}: {e}")
        stdscr.addstr("\nDeletion complete. Press any key.")
        stdscr.refresh()
        stdscr.getch()


def run_media_hunt():
    print_header("Phase 2: Interactive Media Hunt")
    if not confirm_action(
        "Launch the media hunt interface? (Ensure forensics are done)"
    ):
        return
    try:
        curses.wrapper(interactive_media_hunt)
    except Exception as e:
        print_status(f"Curses interface failed: {e}.", False)


# --- Phase 3: User Management Blitz (V6 Reinforced Protection) ---


def audit_and_change_password(username):
    """V6: Audits password and changes if insecure, reinforcing operator protection."""

    # V6: Operator Protection Reinforcement
    if username == CURRENT_OPERATOR:
        print_status(
            f"PROTECTION ACTIVE: Skipping password change for operator: {username}",
            None,
        )
        return

    expected_weak_password = ADMIN_WEAK_PASSWORDS.get(username)

    if expected_weak_password and crypt and spwd:
        try:
            shadow_entry = spwd.getspnam(username)
            actual_hash = shadow_entry.sp_pwdp

            if actual_hash in ["!", "*", ""]:
                change_password(username, NEW_PASSWORD)
                return

            generated_hash = crypt.crypt(expected_weak_password, actual_hash)

            if generated_hash == actual_hash:
                print_status(
                    f"INSECURE PASSWORD confirmed for {username} (Matches Audit). Changing now.",
                    False,
                )
                change_password(username, NEW_PASSWORD)
            else:
                # Standardize even if it doesn't match the weak expectation.
                change_password(username, NEW_PASSWORD)

        except Exception:
            change_password(username, NEW_PASSWORD)
    else:
        change_password(username, NEW_PASSWORD)


def change_password(username, password):
    """Helper to execute the actual password change."""
    # V6: Double-check operator protection within the change function
    if username == CURRENT_OPERATOR:
        return

    chpasswd_input = f"{username}:{password}\n"
    if run_command("chpasswd", input_data=chpasswd_input, silent=True) is not None:
        # V6 FIX: Ensure chage -d 0 NEVER runs on the operator
        if username != CURRENT_OPERATOR and username != "root":
            run_command(f"chage -d 0 {username}", silent=True)


def user_management_blitz():
    """Handles user management."""
    print_header("Phase 3: User Management Blitz")

    if not confirm_action("Start User Management Phase?"):
        return

    current_users = {}
    for user in pwd.getpwall():
        if user.pw_uid >= 1000 or user.pw_uid == 0:
            current_users[user.pw_name] = {"uid": user.pw_uid}

    # User Purge
    for username in current_users:
        if (
            username != "root"
            and username not in AUTHORIZED_USERS
            and username != "nobody"
        ):
            run_command(f"userdel -r {username}", silent=True)

    # User Creation
    for username in AUTHORIZED_USERS:
        if username not in current_users:
            run_command(f"useradd -m -s /bin/bash {username}", silent=True)

    # Administrator Audit
    admin_groups = ["sudo", "adm"]
    for group_name in admin_groups:
        try:
            members = grp.getgrnam(group_name).gr_mem
            for member in members:
                if member not in AUTHORIZED_ADMINS_LIST:
                    # V6: Operator Protection during demotion
                    if member == CURRENT_OPERATOR:
                        print_status(
                            f"PROTECTION ACTIVE: Operator {member} not listed as admin, skipping removal.",
                            None,
                        )
                        continue
                    run_command(f"deluser {member} {group_name}", silent=True)
        except KeyError:
            pass

    for admin in AUTHORIZED_ADMINS_LIST:
        for group_name in admin_groups:
            run_command(f"usermod -a -G {group_name} {admin}", silent=True)

    # Group Management
    for group, users in REQUIRED_GROUPS.items():
        try:
            grp.getgrnam(group)
        except KeyError:
            run_command(f"groupadd {group}", silent=True)
        for user in users:
            if user in AUTHORIZED_USERS:
                run_command(f"usermod -a -G {group} {user}", silent=True)

    # Password Standardization and Auditing
    print_status("Auditing and standardizing passwords...")
    for username in AUTHORIZED_USERS:
        try:
            pwd.getpwnam(username)
            audit_and_change_password(username)
        except KeyError:
            pass

    # Handle root password
    if CURRENT_OPERATOR != "root":
        change_password("root", NEW_PASSWORD)

    # Advanced Checks (UID 0, Shells, Lock Root)
    uid_counter = 1500
    for user in pwd.getpwall():
        if user.pw_uid == 0 and user.pw_name != "root":
            run_command(f"usermod -u {uid_counter} {user.pw_name}", silent=True)
            uid_counter += 1

        if user.pw_uid < 1000 and user.pw_uid != 0:
            if user.pw_shell not in ["/bin/false", "/usr/sbin/nologin"]:
                run_command(f"usermod -s /usr/sbin/nologin {user.pw_name}", silent=True)
        elif user.pw_uid >= 1000 and user.pw_name != "nobody":
            if user.pw_shell != "/bin/bash":
                run_command(f"usermod -s /bin/bash {user.pw_name}", silent=True)

    if CURRENT_OPERATOR != "root":
        run_command("passwd -l root", silent=True)


# --- Phase 4: Advanced Configuration Hardening (V6 Reverting to V4 PAM Logic) ---


def configure_pam_common_auth():
    """V6.2 FIXED: Clean PAM configuration - removes ALL legacy modules, writes clean config"""
    print_status("Configuring PAM common-auth (V6.2 Clean Write Mode)...")
    run_command("apt-get install libpam-modules libpam-faillock -yq", silent=True)
    AUTH_FILE = "/etc/pam.d/common-auth"

    try:
        shutil.copyfile(AUTH_FILE, f"{AUTH_FILE}.bak_juggernaut")
    except IOError:
        print_status("Failed to backup common-auth", False)
        return

    # V6.2: Write a clean, known-good configuration instead of trying to patch
    # This avoids the mess of having both tally2 and faillock
    clean_config = """# /etc/pam.d/common-auth - Juggernaut V6.2 Clean Configuration
#
# Authentication settings common to all services
# Account lockout: 5 failures, 15 minute lockout, applies to root

# Faillock preauth - must come BEFORE pam_unix
auth    required                        pam_faillock.so preauth silent deny=5 unlock_time=900 even_deny_root

# Standard Unix authentication (nullok REMOVED for security)
auth    [success=1 default=ignore]      pam_unix.so

# Faillock authfail - records failed attempts AFTER pam_unix
auth    [default=die]                   pam_faillock.so authfail deny=5 unlock_time=900 even_deny_root

# Fallback if no module succeeds
auth    requisite                       pam_deny.so

# Prime the stack with a positive return value
auth    required                        pam_permit.so

# Faillock authsucc - resets counter on success
auth    sufficient                      pam_faillock.so authsucc

# Delay on failed auth (4 seconds)
auth    required                        pam_faildelay.so delay=4000000
"""

    try:
        with open(AUTH_FILE, "w") as f:
            f.write(clean_config)

        # Verify PAM is not broken by testing with pamtester or a simple check
        print_status("PAM common-auth configured successfully (clean write)")
        print_status("IMPORTANT: Test sudo in a new terminal before closing this one!", None)

    except Exception as e:
        print_status(f"CRITICAL: Failed to write common-auth. Error: {e}", False)
        # Restore backup on failure
        try:
            shutil.copyfile(f"{AUTH_FILE}.bak_juggernaut", AUTH_FILE)
            print_status("Restored PAM backup due to error", None)
        except:
            pass


def configure_pam_common_password():
    """V6.2: Clean write of common-password with all scoring requirements."""
    print_status("Configuring PAM common-password (V6.2 Clean Write Mode)...")
    run_command("apt-get install libpam-pwquality libpam-modules -yq", silent=True)
    PAM_PASSWORD_FILE = "/etc/pam.d/common-password"

    try:
        shutil.copyfile(PAM_PASSWORD_FILE, f"{PAM_PASSWORD_FILE}.bak_juggernaut")
    except IOError:
        print_status("Failed to backup common-password", False)
        return

    # V6.2: Clean configuration with ALL scoring requirements
    # - dictcheck=1: Dictionary-based password strength checks
    # - minlen=14: Minimum 14 characters (CIS benchmark)
    # - difok=8: 8 characters must differ from old password
    # - All credit requirements: -1 means AT LEAST 1 required
    # - gecoscheck: Cannot use personal info from GECOS field
    # - enforce_for_root: Root must also follow rules
    clean_config = """# /etc/pam.d/common-password - Juggernaut V6.2 Clean Configuration
#
# Password complexity and history settings

# Password quality requirements (pam_pwquality)
# retry=3: 3 attempts before failing
# minlen=14: Minimum 14 characters
# difok=8: At least 8 characters must differ from old password
# ucredit=-1: At least 1 uppercase
# lcredit=-1: At least 1 lowercase
# dcredit=-1: At least 1 digit
# ocredit=-1: At least 1 special character
# dictcheck=1: Check against dictionary words
# reject_username: Cannot contain username
# maxrepeat=2: Max 2 consecutive identical characters
# gecoscheck: Cannot use GECOS field info
# enforce_for_root: Root must also comply
password    requisite                       pam_pwquality.so retry=3 minlen=14 difok=8 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 dictcheck=1 reject_username maxrepeat=2 gecoscheck enforce_for_root

# Password history (pam_pwhistory)
# remember=5: Cannot reuse last 5 passwords
# use_authtok: Use password from previous module
password    required                        pam_pwhistory.so remember=5 use_authtok

# Unix password storage
# sha512: Use SHA512 hashing
# rounds=65536: High iteration count for security
# use_authtok: Use password from previous module
password    [success=1 default=ignore]      pam_unix.so sha512 rounds=65536 use_authtok

# Fallback deny
password    requisite                       pam_deny.so

# Success permit
password    required                        pam_permit.so

# GNOME Keyring integration (optional, won't break if missing)
password    optional                        pam_gnome_keyring.so
"""

    try:
        with open(PAM_PASSWORD_FILE, "w") as f:
            f.write(clean_config)
        print_status("PAM common-password configured successfully (clean write)")
    except Exception as e:
        print_status(f"CRITICAL: Failed to write common-password. Error: {e}", False)
        try:
            shutil.copyfile(f"{PAM_PASSWORD_FILE}.bak_juggernaut", PAM_PASSWORD_FILE)
            print_status("Restored PAM backup due to error", None)
        except:
            pass


def secure_critical_files():
    """V6: Sets secure permissions on critical system files."""
    print_status("Securing critical file permissions (/etc/shadow, etc.)...")
    files_to_secure = [
        ("/etc/passwd", 0o644, "root", "root"),
        ("/etc/shadow", 0o640, "root", "shadow"),
        ("/etc/group", 0o644, "root", "root"),
        (
            "/etc/gshadow",
            0o640,
            "root",
            "shadow",
        ),  # V6 fix: Corrected permissions/group
        ("/etc/sudoers", 0o440, "root", "root"),
        ("/boot/grub/grub.cfg", 0o400, "root", "root"),
    ]
    for path, perms, owner, group in files_to_secure:
        if os.path.exists(path):
            try:
                uid = pwd.getpwnam(owner).pw_uid
                gid = grp.getgrnam(group).gr_gid
                os.chown(path, uid, gid)
                os.chmod(path, perms)
            except Exception as e:
                print_status(f"Failed to secure {path}: {e}", False)


def configuration_hardening():
    """Applies system-wide security configurations."""
    print_header("Phase 4: Advanced Configuration Hardening")
    if not confirm_action("Begin Configuration Hardening?"):
        return

    # V6: Ensure critical files are secured
    secure_critical_files()

    # V6.2: Comprehensive login.defs hardening
    print_status("Configuring /etc/login.defs (comprehensive settings)...")
    login_defs = "/etc/login.defs"

    # Define all required settings from scoring checklist
    login_defs_settings = {
        "PASS_MAX_DAYS": "90",      # Maximum password age
        "PASS_MIN_DAYS": "7",       # Minimum password age
        "PASS_WARN_AGE": "7",       # Warning before password expires
        "ENCRYPT_METHOD": "SHA512", # Secure hashing algorithm
        "LOGIN_RETRIES": "3",       # Max login attempts (5 is max, 3 is better)
        "UMASK": "077",             # Restrictive default permissions
        "LOGIN_TIMEOUT": "60",      # Login timeout in seconds
        "FAIL_DELAY": "4",          # Delay after failed login
        "LOG_OK_LOGINS": "yes",     # Log successful logins
        "LOG_UNKFAIL_ENAB": "yes",  # Log unknown usernames on failed login
        "SU_NAME": "su",            # Name of su command for logging
    }

    for key, value in login_defs_settings.items():
        # Remove existing line if present
        run_command(f"sed -i '/^{key}/d' {login_defs}", silent=True)
        run_command(f"sed -i '/^# {key}/d' {login_defs}", silent=True)
        # Add new setting
        run_command(f"echo '{key} {value}' >> {login_defs}", silent=True)

    # PAM Configuration (V6 uses V4 logic)
    configure_pam_common_auth()
    configure_pam_common_password()

    # V6.2: Comprehensive Kernel Hardening
    print_status("Applying Kernel Hardening (/etc/sysctl.conf)...")
    sysctl_settings = {
        # IPv4 Network Security
        "net.ipv4.tcp_syncookies": 1,           # SYN flood protection
        "net.ipv4.conf.all.rp_filter": 1,       # Reverse path filtering
        "net.ipv4.conf.default.rp_filter": 1,
        "net.ipv4.conf.all.accept_redirects": 0,   # Don't accept ICMP redirects
        "net.ipv4.conf.default.accept_redirects": 0,
        "net.ipv4.conf.all.secure_redirects": 0,
        "net.ipv4.conf.default.secure_redirects": 0,
        "net.ipv4.conf.all.send_redirects": 0,     # Don't send ICMP redirects
        "net.ipv4.conf.default.send_redirects": 0,
        "net.ipv4.conf.all.accept_source_route": 0,  # Disable source routing
        "net.ipv4.conf.default.accept_source_route": 0,
        "net.ipv4.conf.all.log_martians": 1,     # Log martian packets
        "net.ipv4.conf.default.log_martians": 1,
        "net.ipv4.ip_forward": 0,                # Disable IP forwarding
        "net.ipv4.icmp_echo_ignore_broadcasts": 1,  # Ignore broadcast pings
        "net.ipv4.icmp_ignore_bogus_error_responses": 1,
        # IPv6 Security
        "net.ipv6.conf.all.disable_ipv6": 1,     # Disable IPv6
        "net.ipv6.conf.default.disable_ipv6": 1,
        "net.ipv6.conf.lo.disable_ipv6": 1,
        "net.ipv6.conf.all.accept_redirects": 0,
        "net.ipv6.conf.default.accept_redirects": 0,
        "net.ipv6.conf.all.accept_source_route": 0,
        # Kernel Hardening
        "fs.suid_dumpable": 0,                   # No SUID core dumps
        "kernel.randomize_va_space": 2,          # Full ASLR
        "kernel.kptr_restrict": 2,               # Hide kernel pointers
        "kernel.dmesg_restrict": 1,              # Restrict dmesg access
        "kernel.yama.ptrace_scope": 2,           # Restrict ptrace
        "kernel.core_uses_pid": 1,               # Include PID in core filename
        "kernel.sysrq": 0,                       # Disable magic SysRq key
        # File System Security
        "fs.protected_hardlinks": 1,
        "fs.protected_symlinks": 1,
        "fs.protected_fifos": 2,
        "fs.protected_regular": 2,
    }
    for key, value in sysctl_settings.items():
        run_command(f"sed -i '/^{re.escape(key)}/d' /etc/sysctl.conf", silent=True)
        run_command(f"sed -i '/^# {re.escape(key)}/d' /etc/sysctl.conf", silent=True)
        run_command(f"echo '{key} = {value}' >> /etc/sysctl.conf", silent=True)
    run_command("sysctl -p", silent=True)

    # GUI Hardening (GDM3)
    if os.path.exists("/etc/gdm3/custom.conf"):
        if run_command("grep -q '[daemon]' /etc/gdm3/custom.conf", silent=True) is None:
            run_command("echo '\n[daemon]' >> /etc/gdm3/custom.conf")

        tmp_file = "/tmp/gdm_settings.txt"
        run_command(
            "sed -i '/AutomaticLoginEnable/d' /etc/gdm3/custom.conf", silent=True
        )
        run_command("sed -i '/AllowGuest/d' /etc/gdm3/custom.conf", silent=True)

        run_command("echo 'AutomaticLoginEnable=false\nAllowGuest=false' > " + tmp_file)
        run_command(
            f"sed -i '/^\[daemon\]/r {tmp_file}' /etc/gdm3/custom.conf", silent=True
        )
        run_command(f"rm {tmp_file}", silent=True)

    # V6.2: Disable Remote Desktop Sharing (GNOME/Vino)
    print_status("Disabling remote desktop sharing...")
    # Disable Vino (GNOME's built-in VNC server)
    run_command("gsettings set org.gnome.Vino enabled false", silent=True, suppress_stderr=True)
    run_command("gsettings set org.gnome.Vino prompt-enabled true", silent=True, suppress_stderr=True)
    run_command("gsettings set org.gnome.desktop.remote-desktop.rdp enable false", silent=True, suppress_stderr=True)
    run_command("gsettings set org.gnome.desktop.remote-desktop.vnc enable false", silent=True, suppress_stderr=True)

    # Disable screen sharing service
    run_command("systemctl disable --now gnome-remote-desktop.service", silent=True, suppress_stderr=True)
    run_command("systemctl mask gnome-remote-desktop.service", silent=True, suppress_stderr=True)

    # Disable Vino server
    run_command("systemctl disable --now vino-server.service", silent=True, suppress_stderr=True)


# --- Phase 5: Software, Services, and Advanced Hardening (V6 Logic) ---


def harden_ssh(services_to_enable):
    if "ssh" in services_to_enable and os.path.exists("/etc/ssh/sshd_config"):
        print_status("Applying Advanced SSH Hardening...")
        ssh_config = "/etc/ssh/sshd_config"

        # V6: Clear sshd_config.d to prevent overrides
        if os.path.exists("/etc/ssh/sshd_config.d"):
            run_command("rm -f /etc/ssh/sshd_config.d/*", silent=True)

        def update_ssh_config(key, value):
            if (
                run_command(f"grep -qE '^[#]?{key}' {ssh_config}", silent=True)
                is not None
            ):
                run_command(f"sed -i -E 's/^[#]?{key}.*/{key} {value}/' {ssh_config}")
            else:
                run_command(f"echo '{key} {value}' >> {ssh_config}")

        update_ssh_config("PermitRootLogin", "no")
        update_ssh_config("Protocol", "2")
        update_ssh_config("PermitEmptyPasswords", "no")
        update_ssh_config("X11Forwarding", "no")
        update_ssh_config("MaxAuthTries", "4")

        run_command("systemctl restart ssh", silent=True)


def manage_services(services_to_enable_units):
    """V6: Enables required services and disables unauthorized services (Expanded Whitelist)."""
    print_status(
        "Starting Service Management (Enable Required / Disable Unauthorized)..."
    )

    # 1. Enable Required Services
    if services_to_enable_units:
        for unit in services_to_enable_units:
            run_command(f"systemctl unmask {unit}", silent=True)
            run_command(f"systemctl enable --now {unit}", silent=True)

    # 2. Disable Unauthorized Services
    print_status("Auditing active services against expanded whitelist...")
    active_services_output = run_command(
        "systemctl list-units --type=service --state=active --no-pager --no-legend"
    )

    if not active_services_output:
        return

    # Build the complete whitelist (Essential V6 + Required)
    whitelist = set(ESSENTIAL_SERVICES)
    whitelist.update(services_to_enable_units)

    services_to_disable = []
    for line in active_services_output.split("\n"):
        if line.strip():
            unit_name = line.split()[0]
            service_name = unit_name.replace(".service", "")

            is_allowed = False
            for item in whitelist:
                # Check prefix matching for dynamic services
                if service_name.startswith(item):
                    is_allowed = True
                    break

            if not is_allowed:
                services_to_disable.append(unit_name)

    if services_to_disable:
        print_status(
            f"Found {len(services_to_disable)} unauthorized services running.", False
        )
        print(f"To Disable: {', '.join(services_to_disable)}")
        if confirm_action(
            "Do you want to aggressively stop and disable these unauthorized services?"
        ):
            for service in services_to_disable:
                print_status(f"Disabling: {service}", False)
                run_command(f"systemctl disable --now {service}", silent=True)


def software_services_and_hardening():
    """V6: Manages software and services using Net Difference Logic and Iterative Purging."""
    print_header("Phase 5: Software, Services, and Advanced Hardening")
    if not confirm_action("Begin Software and Service Management?"):
        return

    # 1. Install Tools
    run_command(
        "apt-get install ufw auditd debsums net-tools apparmor-utils -yq", silent=True
    )
    run_command("systemctl enable --now auditd")
    run_command("auditctl -e 1")

    # ===============================================================
    # V6: NET DIFFERENCE & ITERATIVE PURGE LOGIC
    # ===============================================================

    # 2. Calculate ALLOW_LIST
    ALLOW_LIST = set(REQUIRED_INSTALLS)
    services_to_enable_units = set()

    for service_input in REQUIRED_SERVICES_RAW:
        pkg, unit = service_input, service_input
        if service_input in SERVICE_MAP:
            pkg, unit = SERVICE_MAP[service_input]

        ALLOW_LIST.add(pkg)
        services_to_enable_units.add(unit)

    # 3. Calculate FINAL_PURGE_LIST
    PURGE_LIST = set(PROHIBITED_SOFTWARE)
    FINAL_PURGE_LIST = PURGE_LIST.difference(ALLOW_LIST)

    # 4. Install Required Software/Services
    if ALLOW_LIST:
        print_status("Ensuring required software/services are installed...")
        run_command(
            f"apt-get install --ignore-missing -yq {' '.join(ALLOW_LIST)}", silent=True
        )

    # 5. Execute Iterative Purge (V6 FIX)
    if FINAL_PURGE_LIST:
        print_status("Purging unauthorized software (Iterative Mode)...")
        for package in FINAL_PURGE_LIST:
            # Attempt APT purge individually
            # We use silent=True and suppress_stderr=True because we expect failures if the package isn't installed.
            print_status(f"Attempting to purge: {package}...", None)
            run_command(
                f"apt-get purge -yq {package}", silent=True, suppress_stderr=True
            )

            # Attempt SNAP removal as well
            run_command(f"snap remove {package}", silent=True, suppress_stderr=True)

        # Clean up dependencies after all individual purges are done
        run_command("apt-get autoremove -yq")

    # ===============================================================

    # 6. Service Alignment and Disabling
    manage_services(services_to_enable_units)

    # 7. Advanced Service Hardening
    harden_ssh(services_to_enable_units)


# --- Phase 6: Integrity Check and Advanced Detection (V6 Active Kill) ---


def network_audit_active_kill():
    """V6: Analyzes listening ports (ss) to detect backdoors AND KILLS THEM."""
    print_status("Analyzing listening network ports (Active Backdoor Killer)...")

    listeners = run_command("ss -tulpn")
    if not listeners:
        return

    # Regex to extract PID and Process Name from ss output
    proc_regex = re.compile(r'users:\(\("([^"]+)",pid=(\d+),')

    # Define highly suspicious process names
    bad_procs = [
        "nc",
        "netcat",
        "ncat",
        "nc.traditional",
        "bash",
        "sh",
        "python",
        "perl",
        "php",
    ]

    for line in listeners.split("\n"):
        if line.startswith("tcp") or line.startswith("udp"):
            match = proc_regex.search(line)
            if match:
                proc_name = match.group(1)
                pid = int(match.group(2))

                is_malicious = False
                for bad in bad_procs:
                    if proc_name.startswith(bad):
                        # Whitelist known safe uses
                        if proc_name == "sh" and "sshd" in line:
                            continue
                        if proc_name == "python" and (
                            "unattended-upgr" in line or "apt" in line
                        ):
                            continue
                        is_malicious = True
                        break

                if is_malicious:
                    print_status(
                        f"ACTIVE BACKDOOR FOUND: {proc_name} (PID: {pid}) on line: {line.strip()}",
                        False,
                    )

                    # ACTIVE KILL
                    try:
                        exe_path = ""
                        try:
                            # Try to read the executable path before killing
                            exe_path = os.readlink(f"/proc/{pid}/exe")
                        except Exception:
                            pass

                        # Kill the process
                        os.kill(pid, signal.SIGKILL)
                        print_status(f"KILLED PID {pid}", True)
                        logging.warning(
                            f"KILLED BACKDOOR PROCESS: PID {pid} ({proc_name})"
                        )

                        # Prompt to delete the executable
                        if exe_path and os.path.exists(exe_path):
                            if confirm_action(
                                f"Delete the associated executable? {exe_path}"
                            ):
                                os.remove(exe_path)
                                print_status(f"Deleted {exe_path}", True)

                    except ProcessLookupError:
                        print_status(f"Process {pid} already gone.", None)
                    except Exception as e:
                        print_status(f"Failed to kill PID {pid}: {e}", False)


def persistence_hunt_active_removal():
    """V6: Hunts for persistence mechanisms and actively removes identified threats in crontabs."""
    print_status("Auditing Persistence Locations (Active Removal Mode)...")

    # Focus on system-wide and user crontabs for active removal
    crontab_files = ["/etc/crontab"]
    crontabs_spool = run_command(
        "ls /var/spool/cron/crontabs/* 2>/dev/null", silent=True
    )
    if crontabs_spool:
        crontab_files.extend(crontabs_spool.split("\n"))

    # V6: Enhanced patterns targeting the specific backdoor observed
    suspicious_patterns = [
        r"nc\s+-",
        r"netcat",
        r"nc.traditional",
        r"bash\s+-i\s+>&",
        r"/dev/tcp/",
        r"mknod.*backpipe",
        r"wget\s+http",
        r"curl\s+http",
    ]

    for filepath in crontab_files:
        if filepath and filepath.strip() and os.path.isfile(filepath):
            content = run_command(f"cat {filepath}", silent=True)
            if content:
                new_content = []
                found_threat = False
                for line in content.split("\n"):
                    is_threat = False
                    if line.strip() and not line.strip().startswith("#"):
                        for pattern in suspicious_patterns:
                            if re.search(pattern, line):
                                print_status(
                                    f"THREAT FOUND in {filepath}: {line}", False
                                )
                                found_threat = True
                                is_threat = True
                                break
                    # Keep the line only if it's not a threat
                    if not is_threat:
                        new_content.append(line)

                # Active Removal: Overwrite the file if threats were found
                if found_threat:
                    if confirm_action(
                        f"Threats found in {filepath}. Overwrite file to remove them?"
                    ):
                        try:
                            tmp_file = f"{filepath}.tmp_juggernaut"
                            with open(tmp_file, "w") as f:
                                f.write("\n".join(new_content))

                            # Preserve original permissions/ownership
                            stat_info = os.stat(filepath)
                            os.chown(tmp_file, stat_info.st_uid, stat_info.st_gid)
                            os.chmod(tmp_file, stat_info.st_mode)

                            os.replace(tmp_file, filepath)
                            print_status(f"Sanitized {filepath}", True)
                        except Exception as e:
                            print_status(
                                f"Failed to sanitize {filepath}: {e}. Manual removal required.",
                                False,
                            )

    # Passive review of .bashrc/.profile/SSH keys (Identical to V5)


def suid_sgid_audit():
    """V6.2: Audit SUID/SGID binaries against known-good whitelist."""
    print_status("Auditing SUID/SGID binaries...")

    # Find all SUID binaries
    suid_output = run_command("find / -perm -4000 -type f 2>/dev/null", silent=True)
    # Find all SGID binaries
    sgid_output = run_command("find / -perm -2000 -type f 2>/dev/null", silent=True)

    suspicious_suid = []
    suspicious_sgid = []

    if suid_output:
        for binary in suid_output.split("\n"):
            if binary.strip() and binary.strip() not in KNOWN_GOOD_SUID:
                # Skip common system paths that are usually safe
                if any(safe in binary for safe in ["/snap/", "/var/lib/"]):
                    continue
                suspicious_suid.append(binary.strip())

    if sgid_output:
        for binary in sgid_output.split("\n"):
            if binary.strip():
                # SGID is often used legitimately, be more selective
                if any(bad in binary.lower() for bad in ["nc", "netcat", "backdoor", "shell"]):
                    suspicious_sgid.append(binary.strip())

    if suspicious_suid:
        print_status(f"Found {len(suspicious_suid)} potentially suspicious SUID binaries:", None)
        for binary in suspicious_suid[:10]:  # Show first 10
            print(f"    {binary}")
        if len(suspicious_suid) > 10:
            print(f"    ... and {len(suspicious_suid) - 10} more")

        if confirm_action("Remove SUID bit from suspicious binaries?"):
            for binary in suspicious_suid:
                if os.path.exists(binary):
                    run_command(f"chmod u-s {binary}", silent=True)
                    print_status(f"Removed SUID from: {binary}")

    if suspicious_sgid:
        print_status(f"Found {len(suspicious_sgid)} suspicious SGID binaries:", False)
        for binary in suspicious_sgid:
            print(f"    {binary}")


def audit_ssh_keys_and_profiles():
    """V6.2: Audit SSH keys and shell profiles for backdoors."""
    print_status("Auditing SSH keys and shell profiles...")

    # Check for unauthorized SSH keys
    for user_entry in pwd.getpwall():
        if user_entry.pw_uid >= 1000 or user_entry.pw_uid == 0:
            home = user_entry.pw_dir
            ssh_dir = os.path.join(home, ".ssh")
            auth_keys = os.path.join(ssh_dir, "authorized_keys")

            if os.path.exists(auth_keys):
                # Check for suspicious entries
                content = run_command(f"cat {auth_keys}", silent=True)
                if content:
                    for line in content.split("\n"):
                        if line.strip() and not line.startswith("#"):
                            # Flag keys with command= restrictions (could be backdoors)
                            if "command=" in line.lower():
                                print_status(f"WARNING: {auth_keys} has command-forced key: {line[:50]}...", None)

            # Check .bashrc and .profile for suspicious content
            for rc_file in [".bashrc", ".profile", ".bash_profile", ".bash_login"]:
                rc_path = os.path.join(home, rc_file)
                if os.path.exists(rc_path):
                    content = run_command(f"cat {rc_path}", silent=True)
                    if content:
                        suspicious_patterns = [
                            r"nc\s+-",
                            r"netcat",
                            r"/dev/tcp/",
                            r"bash\s+-i\s+>&",
                            r"curl.*\|.*bash",
                            r"wget.*\|.*bash",
                            r"base64.*-d.*\|.*bash",
                        ]
                        for pattern in suspicious_patterns:
                            if re.search(pattern, content, re.IGNORECASE):
                                print_status(f"THREAT: Suspicious content in {rc_path}", False)
                                logging.warning(f"THREAT in {rc_path}: pattern {pattern}")
                                break


def integrity_and_advanced_detection():
    """V6.2: Checks binaries and hunts for persistence with Active Kill."""
    print_header("Phase 6: Advanced Detection and Integrity (Active Mode)")

    if not confirm_action("Begin Advanced Detection? (Includes Active Kill/Removal)"):
        return

    # V6.2: All Active Audits
    network_audit_active_kill()
    suid_sgid_audit()
    audit_ssh_keys_and_profiles()
    persistence_hunt_active_removal()

    # Integrity Check (Debsums)
    print_status("Checking for poisoned binaries (debsums -c)...")
    run_command("apt-get install debsums -yq", silent=True)
    debsums_output = run_command("debsums -c", silent=True, suppress_stderr=True)

    if debsums_output:
        failed_files = []
        for line in debsums_output.split("\n"):
            if line.strip():
                # debsums -c just outputs the filepath of modified files
                failed_files.append(line.strip())

        if failed_files:
            print_status(
                f"CRITICAL: Found {len(failed_files)} modified system binaries!", False
            )
            for f in failed_files[:10]:
                print(f"    {f}")
            if len(failed_files) > 10:
                print(f"    ... and {len(failed_files) - 10} more")

            if confirm_action("Attempt to reinstall packages with modified files?"):
                # Find which packages own these files and reinstall them
                packages_to_reinstall = set()
                for filepath in failed_files:
                    pkg_output = run_command(f"dpkg -S {filepath} 2>/dev/null", silent=True)
                    if pkg_output:
                        # Output is like "package: /path/to/file"
                        pkg_name = pkg_output.split(":")[0].strip()
                        packages_to_reinstall.add(pkg_name)

                if packages_to_reinstall:
                    print_status(f"Reinstalling {len(packages_to_reinstall)} packages...")
                    for pkg in packages_to_reinstall:
                        print_status(f"Reinstalling: {pkg}...", None)
                        run_command(f"apt-get install --reinstall -yq {pkg}", silent=True)
                    print_status("Package reinstallation complete. Run debsums -c again to verify.", True)


# --- Phase 7: Firewall Activation ---


def firewall_activation():
    """Configures UFW."""
    print_header("Phase 7: Firewall Activation")

    if not confirm_action("Configure and enable UFW?"):
        return

    # V6 Fix: Correct syntax
    run_command("ufw --force reset")
    run_command("ufw default deny incoming")
    run_command("ufw default allow outgoing")
    run_command("ufw logging medium")

    # Allow required ports
    ports_allowed = set()

    # Normalize required services list for port lookup
    normalized_services = set()
    for s in REQUIRED_SERVICES_RAW:
        if s in SERVICE_MAP:
            normalized_services.add(SERVICE_MAP[s][1])  # Add the unit name
        else:
            normalized_services.add(s)

    for service in normalized_services:
        found_ports = SERVICE_PORTS.get(service)

        if found_ports:
            for port in found_ports:
                if port not in ports_allowed:
                    print_status(f"Allowing port {port} for {service}...")
                    if port == 22:
                        run_command(f"ufw limit {port}/tcp")
                    elif port in [139, 445]:
                        run_command(f"ufw allow {port}")  # TCP and UDP for Samba
                    else:
                        run_command(f"ufw allow {port}/tcp")
                    ports_allowed.add(port)

    print_status("Enabling UFW...")
    run_command("echo 'y' | ufw enable")
    run_command("ufw status verbose")


# --- New V6.1 Automation Functions ---


def configure_extra_services():
    """Configures FTP, MySQL, PHP, Samba, and Web Servers."""

    print_status("Configuring Extra Services (FTP, SQL, PHP, Samba, Web)...")

    # FTP (vsftpd)

    if os.path.exists("/etc/vsftpd.conf"):
        c = "/etc/vsftpd.conf"

        run_command(f"sed -i 's/anonymous_enable=YES/anonymous_enable=NO/' {c}")

        run_command(f"sed -i 's/#local_enable=YES/local_enable=YES/' {c}")

        run_command(f"sed -i 's/#write_enable=YES/write_enable=YES/' {c}")

        if "ssl_enable=YES" not in run_command(f"cat {c}", silent=True):
            run_command(f"echo 'ssl_enable=YES' >> {c}")

        run_command(f"echo 'ftpd_banner=Welcome' >> {c}")

        run_command("systemctl restart vsftpd", silent=True)

    # MySQL

    cfgs = (
        glob.glob("/etc/mysql/mariadb.conf.d/*.cnf")
        + glob.glob("/etc/mysql/mysql.conf.d/*.cnf")
        + ["/etc/mysql/my.cnf"]
    )

    for f in cfgs:
        if os.path.exists(f):
            run_command(f"sed -i 's/^bind-address.*/bind-address = 127.0.0.1/' {f}")

    try:
        # Blind cleanup attempt

        run_command(
            "mysql -e \"DELETE FROM mysql.user WHERE User=''; DROP DATABASE IF EXISTS test; FLUSH PRIVILEGES;\"",
            silent=True,
            suppress_stderr=True,
        )

    except:
        pass

    # PHP

    inis = (
        glob.glob("/etc/php/*/apache2/php.ini")
        + glob.glob("/etc/php/*/cli/php.ini")
        + glob.glob("/etc/php/*/fpm/php.ini")
    )

    for ini in inis:
        run_command(f"sed -i 's/expose_php = On/expose_php = Off/' {ini}")
        run_command(f"sed -i 's/display_errors = On/display_errors = Off/' {ini}")
        dis = "disabled_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source"
        run_command(f"sed -i '/^disabled_functions/c\\{dis}' {ini}")

    run_command("systemctl restart apache2 php*-fpm", silent=True, suppress_stderr=True)

    # Samba
    if os.path.exists("/etc/samba/smb.conf"):
        # Samba

        if os.path.exists("/etc/samba/smb.conf"):
            c = "/etc/samba/smb.conf"

            run_command(f"sed -i '/\\[global\\]/a\\   map to guest = Never' {c}")

            run_command(f"sed -i '/\\[global\\]/a\\   smb encrypt = required' {c}")

            run_command("systemctl restart smbd", silent=True)

    # Web Servers

    if os.path.exists("/etc/apache2/apache2.conf"):
        run_command("echo 'ServerTokens Prod' >> /etc/apache2/apache2.conf")

        run_command("echo 'ServerSignature Off' >> /etc/apache2/apache2.conf")

    if os.path.exists("/etc/nginx/nginx.conf"):
        run_command(
            "sed -i 's/# server_tokens off;/server_tokens off;/' /etc/nginx/nginx.conf"
        )


def audit_system_settings():
    """V6.2: Comprehensive system settings audit and hardening."""

    print_status("Auditing System Settings (Sudo, Guest, LightDM, Kernel, Browsers)...")

    # === SUDOERS HARDENING ===
    try:
        shutil.copyfile("/etc/sudoers", "/etc/sudoers.bak_juggernaut")
        with open("/etc/sudoers", "r") as f:
            lines = f.readlines()
        new_lines = []
        changed = False
        has_env_reset = False
        has_secure_path = False

        for line in lines:
            original_line = line
            # Remove NOPASSWD - sudo must require authentication
            if "NOPASSWD:" in line:
                line = line.replace("NOPASSWD:", "")
                changed = True
            # Fix !env_reset - must reset environment
            if "!env_reset" in line:
                line = line.replace("!env_reset", "env_reset")
                changed = True
            # Comment out dangerous env_keep lines (especially LD_PRELOAD)
            if "env_keep" in line and "Defaults" in line:
                if "LD_PRELOAD" in line or "LD_LIBRARY_PATH" in line:
                    line = "# DISABLED: " + line
                    changed = True
            # Track existing settings
            if "Defaults" in line and "env_reset" in line and "!" not in line:
                has_env_reset = True
            if "Defaults" in line and "secure_path" in line:
                has_secure_path = True
            new_lines.append(line)

        # Add missing security defaults
        if not has_env_reset:
            new_lines.insert(0, "Defaults    env_reset\n")
            changed = True
        if not has_secure_path:
            new_lines.insert(0, "Defaults    secure_path=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"\n")
            changed = True

        if changed:
            with open("/tmp/sudoers.tmp", "w") as f:
                f.writelines(new_lines)
            if run_command("visudo -cf /tmp/sudoers.tmp", silent=True) is not None:
                shutil.move("/tmp/sudoers.tmp", "/etc/sudoers")
                os.chmod("/etc/sudoers", 0o440)
                print_status("Sudoers hardened successfully")
            else:
                print_status("Sudoers modification failed validation. Reverting.", False)
                os.remove("/tmp/sudoers.tmp")
    except Exception as e:
        print_status(f"Failed to modify sudoers: {e}", False)

    # === SUDO.CONF - DISABLE COREDUMP ===
    print_status("Configuring /etc/sudo.conf (disable coredump)...")
    sudo_conf = "/etc/sudo.conf"
    try:
        sudo_conf_content = ""
        if os.path.exists(sudo_conf):
            with open(sudo_conf, "r") as f:
                sudo_conf_content = f.read()
        if "disable_coredump" not in sudo_conf_content:
            with open(sudo_conf, "a") as f:
                f.write("\n# Juggernaut V6.2: Prevent sudo coredumps (security)\nSet disable_coredump true\n")
    except Exception as e:
        print_status(f"Failed to configure sudo.conf: {e}", False)

    # === GUEST ACCOUNT DISABLING ===
    print_status("Disabling guest account...")
    # Method 1: /etc/lightdm/lightdm.conf.d/
    lightdm_conf_d = "/etc/lightdm/lightdm.conf.d"
    if os.path.exists("/etc/lightdm"):
        os.makedirs(lightdm_conf_d, exist_ok=True)
        guest_conf = os.path.join(lightdm_conf_d, "50-no-guest.conf")
        try:
            with open(guest_conf, "w") as f:
                f.write("[Seat:*]\nallow-guest=false\n")
        except Exception as e:
            print_status(f"Failed to disable guest in lightdm.conf.d: {e}", False)

    # Method 2: Direct lightdm.conf edit
    lightdm_conf = "/etc/lightdm/lightdm.conf"
    if os.path.exists(lightdm_conf):
        run_command(f"sed -i '/allow-guest/d' {lightdm_conf}", silent=True)
        run_command(f"sed -i '/\\[Seat:\\*\\]/a allow-guest=false' {lightdm_conf}", silent=True)

    # Method 3: AccountsService (for Ubuntu)
    run_command("gsettings set org.gnome.login-screen allow-guest false", silent=True, suppress_stderr=True)

    # === LIGHTDM HARDENING ===
    print_status("Hardening LightDM configuration...")
    if os.path.exists(lightdm_conf):
        # Disable autologin
        run_command(f"sed -i 's/^autologin-user=.*/# autologin-user=/' {lightdm_conf}", silent=True)
        run_command(f"sed -i '/autologin-user-timeout/d' {lightdm_conf}", silent=True)
        # Hide user list (optional - may cause usability issues)
        # run_command(f"sed -i '/\\[Seat:\\*\\]/a greeter-hide-users=true' {lightdm_conf}", silent=True)

    # === KERNEL LOCKDOWN (if available) ===
    print_status("Checking kernel lockdown capability...")
    lockdown_file = "/sys/kernel/security/lockdown"
    if os.path.exists(lockdown_file):
        try:
            with open(lockdown_file, "r") as f:
                current = f.read()
            if "none" in current or "[none]" in current:
                if confirm_action("Enable kernel lockdown (integrity mode)? This restricts kernel modifications."):
                    try:
                        with open(lockdown_file, "w") as f:
                            f.write("integrity")
                        print_status("Kernel lockdown set to integrity mode")
                    except Exception as e:
                        print_status(f"Failed to enable kernel lockdown: {e}", None)
        except Exception:
            pass
    else:
        print_status("Kernel lockdown not available on this system", None)

    # === BROWSER POLICIES ===
    print_status("Configuring browser security policies...")
    # Firefox
    pol_dir = "/etc/firefox/policies"
    os.makedirs(pol_dir, exist_ok=True)
    firefox_policy = {
        "policies": {
            "DisableTelemetry": True,
            "PopupBlocking": {"Default": True},
            "OfferToSaveLogins": False,
            "PasswordManagerEnabled": False,
            "DisableFormHistory": True,
            "EnableTrackingProtection": {"Value": True, "Cryptomining": True, "Fingerprinting": True}
        }
    }
    try:
        import json
        with open(os.path.join(pol_dir, "policies.json"), "w") as f:
            json.dump(firefox_policy, f, indent=2)
    except Exception:
        with open(os.path.join(pol_dir, "policies.json"), "w") as f:
            f.write('{ "policies": { "DisableTelemetry": true, "PopupBlocking": { "Default": true }, "OfferToSaveLogins": false } }')

    # Chrome/Chromium
    chrome_pol_dir = "/etc/chromium/policies/managed"
    os.makedirs(chrome_pol_dir, exist_ok=True)
    try:
        with open(os.path.join(chrome_pol_dir, "juggernaut_policy.json"), "w") as f:
            f.write('{ "PasswordManagerEnabled": false, "AutofillAddressEnabled": false, "AutofillCreditCardEnabled": false }')
    except Exception as e:
        print_status(f"Failed to write Chrome policy: {e}", False)


# --- Main Execution ---


def main():
    # Ensure Input directory exists before starting

    if not os.path.exists(INPUT_DIR):
        setup_directories()

    start_time = time.time()

    # Phase 1: Initialize

    initialization()

    # V6: Phase 1.5: Forensics Collection

    forensics_collection()

    # Phase 1.8: Updates

    system_updates()

    # Phase 2: Media Hunt

    run_media_hunt()

    # Phase 3: User Management (V6 Protection)

    user_management_blitz()

    # Phase 4: Configuration Hardening (V6 Restoration)

    configuration_hardening()

    # V6.1: System Settings Audit

    audit_system_settings()

    # Phase 5: Software/Service Hardening (V6 Logic)

    software_services_and_hardening()

    # V6.1: Extra Services Hardening

    configure_extra_services()

    # Phase 6: Advanced Detection (V6 Active Kill)

    integrity_and_advanced_detection()

    # Phase 7: Firewall

    firewall_activation()

    end_time = time.time()

    duration = (end_time - start_time) / 60

    print_header("Juggernaut v6 Execution Complete")

    logging.info(f"Juggernaut v6 Script Finished. Duration: {duration:.2f} minutes.")

    print_status(f"Automation finished. Duration: {duration:.2f} minutes.")

    print_status(f"Review the log file: {LOG_FILE} and Forensics: {FORENSICS_DIR}")

    print_status("CRITICAL MANUAL CHECKS:", None)

    print_status(
        "1. Verify PAM stability: Open a NEW terminal and run 'sudo ls'.", None
    )

    print_status(
        "2. Manually verify removal of backdoors identified in Phase 6 (Network Kills/Crontab sanitization).",
        False,
    )

    print_status(
        "3. GRUB: Run 'grub-mkpasswd-pbkdf2' and add to /etc/grub.d/00_header (User 'root', Password <hash>).",
        False,
    )


if __name__ == "__main__":
    main()
