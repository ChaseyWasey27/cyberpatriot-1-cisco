import curses
import grp
import logging
import os
import pwd
import re
import signal
import subprocess
import sys
import time

# V5: Required for secure password auditing
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
# Juggernaut v5 (Ultimate) - CyberPatriot Linux Automation
# =============================================================================

# --- Configuration ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INPUT_DIR = os.path.join(BASE_DIR, "Input")
LOG_FILE = os.path.join(BASE_DIR, "juggernaut_v5.log")

# Input Files
USERS_FILE = os.path.join(INPUT_DIR, "users.txt")
ADMINS_FILE = os.path.join(INPUT_DIR, "admins.txt")
ADMIN_AUDIT_FILE = os.path.join(INPUT_DIR, "admin_passwords_audit.txt")
GROUPS_FILE = os.path.join(INPUT_DIR, "groups.txt")
SERVICES_FILE = os.path.join(INPUT_DIR, "services.txt")
PASSWORD_FILE = os.path.join(INPUT_DIR, "password.txt")
INSTALLS_FILE = os.path.join(INPUT_DIR, "required_installs.txt")
PROHIBITED_FILE = os.path.join(INPUT_DIR, "prohibited_software.txt")

# Globals
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

# Constants
DEFAULT_PROHIBITED = [
    "hydra",
    "hydra-gtk",
    "john",
    "john-data",
    "medusa",
    "nikto",
    "sqlmap",
    "aircrack-ng",
    "ophcrack",
    "ophcrack-cli",
    "hashcat",
    "metasploit-framework",
    "kismet",
    "p0f",
    "yersinia",
    "hping3",
    "crunch",
    "cewl",
    "fcrackzip",
    "pdfcrack",
    "exploitdb",
    "wapiti",
    "beef-xss",
    "responder",
    "impacket-scripts",
    "wpscan",
    "nmap",
    "zenmap",
    "wireshark",
    "wireshark-common",
    "tshark",
    "tcpdump",
    "ettercap",
    "ettercap-common",
    "ettercap-graphical",
    "dsniff",
    "netdiscover",
    "arp-scan",
    "netcat",
    "nc",
    "netcat-traditional",
    "netcat-openbsd",
    "cryptcat",
    "socat",
    "rkhunter",
    "chkrootkit",
    "telnet",
    "telnetd",
    "inetutils-telnetd",
    "rsh-server",
    "rsh-client",
    "inetd",
    "openbsd-inetd",
    "xinetd",
    "tftp",
    "tftpd",
    "tftpd-hpa",
    "finger",
    "talk",
    "talkd",
    "nis",
    "ypbind",
    "vino",
    "tightvncserver",
    "vnc4server",
    "x11vnc",
    "xrdp",
    "remmina",
    "rdesktop",
    "vinagre",
    "aisleriot",
    "gnome-mines",
    "gnome-sudoku",
    "freeciv",
    "openarena",
    "minetest",
    "doomsday",
    "gnome-mahjongg",
    "kpat",
    "kmines",
    "gnome-chess",
    "wesnoth",
    "supertuxkart",
    "supertux",
    "steam",
    "lutris",
    "iagno",
    "swell-foop",
    "quadrapassel",
    "chromium-bsu",
    "0ad",
    "games-arcade",
    "games-board",
    "games-card",
    "irssi",
    "hexchat",
    "weechat",
    "transmission",
    "transmission-gtk",
    "transmission-daemon",
    "deluge",
    "qbittorrent",
    "vuze",
    "frostwire",
    "amule",
    "vlc",
    "pidgin",
]

# V5: Service Mapping (Input Name -> Package Name, Service Unit Name)
SERVICE_MAP = {
    "ssh": ("openssh-server", "ssh"),
    "sshd": ("openssh-server", "ssh"),
    "apache": ("apache2", "apache2"),
    "apache2": ("apache2", "apache2"),
    "nginx": ("nginx", "nginx"),
    "ftp": ("vsftpd", "vsftpd"),
    "vsftpd": ("vsftpd", "vsftpd"),
    "proftpd": ("proftpd-basic", "proftpd"),
    "samba": ("samba", "smbd"),
    "smbd": ("samba", "smbd"),
    "mysql": ("mysql-server", "mysql"),
    "mariadb": ("mariadb-server", "mariadb"),
    "postgresql": ("postgresql", "postgresql"),
}

SERVICE_PORTS = {
    "ssh": [22],
    "apache2": [80, 443],
    "nginx": [80, 443],
    "vsftpd": [21],
    "proftpd": [21],
    "smbd": [139, 445],
}

# V5: Essential services whitelist (Do not disable automatically)
# FIX APPLIED: Added critical VM tools, Firewall, and Update services
ESSENTIAL_SERVICES = [
    "dbus",
    "gdm",
    "gdm3",
    "lightdm",
    "systemd-",
    "NetworkManager",
    "cron",
    "anacron",
    "rsyslog",
    "networkd-dispatcher",
    "polkit",
    "snapd",
    "udev",
    "user@",
    "getty@",
    "vgauthservice",
    "vmtoolsd",
    "auditd",
    "apparmor",
    "irqbalance",
    "ModemManager",
    "accounts-daemon",
    "whoopsie",
    "kerneloops",
    "cups",
    "cups-browsed",
    "ccsclient",  # CyberPatriot specific
    # --- FIX START ---
    "unattended-upgrades",  # Keeps points for auto updates
    "aptd",
    "update-notifier",
    "upower",  # GUI Power management
    "colord",  # GUI Color profiles
    "packagekit",  # GUI Package management
    "rtkit-daemon",  # Realtime kit (Audio/GUI)
    "avahi-daemon",
    "bluetooth",
    "wpa_supplicant",
    "ufw",  # Firewall (Critical)
    "x2goserver",  # Required Install
    "x2gocleansessions",  # Required Install
    "open-vm-tools",  # VM Stability
    "vgauth",  # VM Stability
    # --- FIX END ---
]

# V5: Known good SUID/SGID binaries (whitelist)
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
    "/usr/bin/wall",
    "/usr/bin/chage",
    "/usr/bin/write",
    "/usr/sbin/unix_chkpwd",
    "/usr/bin/sudoedit",
    "/usr/lib/snapd/snap-confine",
    "/usr/libexec/polkit-agent-helper-1",
]

# --- Helper Functions ---


def setup_logging():
    logging.basicConfig(
        filename=LOG_FILE,
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )


def get_current_operator():
    return os.getenv("SUDO_USER", os.getenv("USER", "unknown"))


def run_command(command, input_data=None, silent=False, suppress_stderr=False):
    """Executes a shell command and logs it."""
    logging.info(f"EXECUTING: {command}")

    # V5: Use apt-get consistently for scripting robustness
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
        error_message = f"FAILED: {command}"
        if not suppress_stderr and e.stderr:
            error_message += f"\nSTDERR: {e.stderr.strip()}"

        logging.error(error_message)

        # V5: Handle common non-fatal errors gracefully
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
    else:  # Neutral/Warning
        status = "\033[33m[!]\033[0m"
    print(f"{status} {message}")


def confirm_action(prompt):
    """Prompts the user for confirmation."""
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

        current_user = get_current_operator()

        files_to_create = {
            USERS_FILE: f"{current_user}\n# Add other authorized users\n",
            ADMINS_FILE: f"{current_user}\n# Add other authorized admins\n",
            ADMIN_AUDIT_FILE: "# Enter WEAK passwords from README below, corresponding line-by-line to admins.txt\n",
            GROUPS_FILE: "# Format: group_name:user1,user2\n",
            SERVICES_FILE: "ssh\n# Add critical services (e.g., apache2, vsftpd)\n",
            PASSWORD_FILE: "CyberP@triot!State2025\n",
            INSTALLS_FILE: "# Add required installs (e.g., x2goserver)\n",
            PROHIBITED_FILE: "# Add software to purge\n"
            + "\n".join(DEFAULT_PROHIBITED)
            + "\n",
        }
        for filepath, content in files_to_create.items():
            if not os.path.exists(filepath):
                with open(filepath, "w") as f:
                    f.write(content)

        print(
            f"Setup Complete: Please populate the files in {INPUT_DIR} based on the README."
        )
        print("Then run the script again with sudo.")
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

        admin_lines = load_list(ADMINS_FILE, lower=False)
        audit_lines = load_list(
            ADMIN_AUDIT_FILE, lower=False
        )  # Passwords are case sensitive

        AUTHORIZED_ADMINS_LIST = admin_lines

        for i, admin in enumerate(admin_lines):
            if i < len(audit_lines) and audit_lines[i]:
                ADMIN_WEAK_PASSWORDS[admin] = audit_lines[i]
                logging.info(f"Loaded expected weak password for audit: {admin}")

        for admin in AUTHORIZED_ADMINS_LIST:
            if admin not in AUTHORIZED_USERS:
                AUTHORIZED_USERS.append(admin)

        with open(GROUPS_FILE, "r") as f:
            for line in f:
                if ":" in line and line.strip() and not line.startswith("#"):
                    group, users_str = line.strip().split(":", 1)
                    REQUIRED_GROUPS[group] = users_str.split(",")

        print_status(
            f"Input files loaded. Users: {len(AUTHORIZED_USERS)}, Admins: {len(AUTHORIZED_ADMINS_LIST)}."
        )

    except FileNotFoundError as e:
        print_status(f"Error loading input files: {e}.", False)
        sys.exit(1)


# --- Phase 1: Initialization, Updates & Stabilization ---


def ensure_automatic_updates():
    """V5: Force enable unattended-upgrades for points."""
    print_status("Ensuring Automatic Updates are ENABLED (For Scoring)...")
    run_command("apt-get install unattended-upgrades apt-listchanges -yq", silent=True)

    # Create the configuration file explicitly
    config_content = """
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
"""
    run_command(f"echo '{config_content}' > /etc/apt/apt.conf.d/20auto-upgrades")

    # Start the service
    run_command("systemctl unmask unattended-upgrades", silent=True)
    run_command("systemctl enable --now unattended-upgrades", silent=True)
    run_command("systemctl start unattended-upgrades", silent=True)


def initialization_and_updates():
    """Checks for root, detects OS, stabilizes system, identifies operator, and updates."""
    print_header("Phase 1: Initialization, Updates & Stabilization")
    global CURRENT_OPERATOR, OS_DISTRO
    CURRENT_OPERATOR = get_current_operator()

    if os.geteuid() != 0:
        setup_directories()
        print_status("This script must be run as root. Use sudo.", False)
        sys.exit(1)

    setup_logging()
    load_input_files()
    print_status(f"Operator Protection Active for: {CURRENT_OPERATOR}")

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

    if not confirm_action("Run full system update and upgrade? (Can take 10-30+ mins)"):
        return

    print_status("Fixing sources.list and preparing for updates...")
    try:
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
            run_command(f"echo '{sources_content}' > {sources_file_path}")

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

        ensure_automatic_updates()  # V5 Fix

    except Exception as e:
        print_status(f"Failed during update/upgrade phase: {e}", False)


# --- Phase 2: Interactive Media Hunt (Curses TUI) ---


def interactive_media_hunt(stdscr):
    """Uses curses TUI for selecting files to delete. (Restored V4 Logic)"""
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
            0, min(current_row - visible_rows // 2, len(file_list) - visible_rows)
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


# --- Phase 3: User Management Blitz ---


def audit_and_change_password(username):
    """V5: Audits password and changes if insecure."""
    if username == CURRENT_OPERATOR:
        print_status(f"Skipping password change for current operator: {username}", None)
        return

    expected_weak_password = ADMIN_WEAK_PASSWORDS.get(username)

    if expected_weak_password and crypt and spwd:
        try:
            shadow_entry = spwd.getspnam(username)
            actual_hash = shadow_entry.sp_pwdp

            if actual_hash in ["!", "*", ""]:
                print_status(
                    f"User {username} has no password/is locked. Applying standard password.",
                    None,
                )
                change_password(username, NEW_PASSWORD)
                return

            # Generate hash of the expected weak password using the actual salt
            generated_hash = crypt.crypt(expected_weak_password, actual_hash)

            # Compare hashes
            if generated_hash == actual_hash:
                print_status(
                    f"INSECURE PASSWORD confirmed for {username} (Matches README Audit). Changing now.",
                    False,
                )
                change_password(username, NEW_PASSWORD)
            else:
                print_status(
                    f"Password for {username} does not match weak audit expectation. Standardizing.",
                    True,
                )
                change_password(username, NEW_PASSWORD)

        except Exception as e:
            print_status(
                f"Error auditing password for {username}: {e}. Applying standard password.",
                None,
            )
            change_password(username, NEW_PASSWORD)
    else:
        change_password(username, NEW_PASSWORD)


def change_password(username, password):
    chpasswd_input = f"{username}:{password}\n"
    if run_command("chpasswd", input_data=chpasswd_input, silent=True) is not None:
        if username != CURRENT_OPERATOR and username != "root":
            run_command(f"chage -d 0 {username}", silent=True)
    else:
        print_status(f"Failed to change password for {username}.", False)


def user_management_blitz():
    print_header("Phase 3: User Management Blitz")

    if not confirm_action(
        "Start User Management Phase (Purge/Create/Modify/Passwords)?"
    ):
        return

    current_users = {}
    for user in pwd.getpwall():
        if user.pw_uid >= 1000 or user.pw_uid == 0:
            current_users[user.pw_name] = {"uid": user.pw_uid}

    # Unauthorized User Purge
    for username in current_users:
        if (
            username != "root"
            and username not in AUTHORIZED_USERS
            and username != "nobody"
        ):
            print_status(f"Deleting unauthorized user: {username}...", False)
            run_command(f"userdel -r {username}", silent=True)

    # Ensure Authorized Users Exist
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
                    if member == CURRENT_OPERATOR:
                        print_status(
                            f"WARNING: Operator {member} not listed as admin, skipping removal.",
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

    # Password Standardization
    print_status("Auditing and standardizing passwords...")
    for username in AUTHORIZED_USERS:
        try:
            pwd.getpwnam(username)
            audit_and_change_password(username)
        except KeyError:
            pass

    change_password("root", NEW_PASSWORD)

    # Advanced Checks
    print_status("Auditing UID 0 users and shells...")
    uid_counter = 1500
    for user in pwd.getpwall():
        if user.pw_uid == 0 and user.pw_name != "root":
            print_status(f"Found UID 0 user: {user.pw_name}. Changing UID.", False)
            run_command(f"usermod -u {uid_counter} {user.pw_name}", silent=True)
            uid_counter += 1

        if user.pw_uid < 1000 and user.pw_uid != 0:
            if user.pw_shell not in [
                "/bin/false",
                "/usr/sbin/nologin",
                "/sbin/nologin",
            ]:
                run_command(f"usermod -s /usr/sbin/nologin {user.pw_name}", silent=True)
        elif user.pw_uid >= 1000 and user.pw_name != "nobody":
            if user.pw_shell != "/bin/bash":
                run_command(f"usermod -s /bin/bash {user.pw_name}", silent=True)

    run_command("passwd -l root", silent=True)


# --- Phase 4: Advanced Configuration Hardening (V5 Safe Mode) ---


def safe_pam_configure():
    """V5: Edit existing PAM files instead of overwriting (Protects Sudo)"""
    print_status("Applying PAM Hardening (Safe Mode via SED)...")
    run_command("apt-get install libpam-pwquality libpam-modules -yq", silent=True)

    # 1. Common Password (PWQuality + History)
    cp = "/etc/pam.d/common-password"
    # Ensure pwquality line exists and has scoring params
    if "pam_pwquality.so" in run_command(f"cat {cp}"):
        run_command(
            f"sed -i '/pam_pwquality.so/s/$/ minlen=14 retry=3/' {cp}", silent=True
        )
    else:
        run_command(
            f"sed -i '/pam_unix.so/i password requisite pam_pwquality.so minlen=14 retry=3' {cp}",
            silent=True,
        )

    # Ensure history
    if "pam_pwhistory.so" not in run_command(f"cat {cp}"):
        run_command(
            f"sed -i '/pam_unix.so/i password required pam_pwhistory.so use_authtok remember=5' {cp}",
            silent=True,
        )

    # 2. Common Auth (Faillock - Ubuntu 22.04 standard)
    ca = "/etc/pam.d/common-auth"
    # Only add faillock if not present to avoid lockout loops
    if "pam_faillock.so" not in run_command(f"cat {ca}"):
        print_status("Enabling faillock via sed injection (Safe Mode)...")
        # Preauth (start of file)
        run_command(
            f"sed -i '1i auth required pam_faillock.so preauth silent deny=5 unlock_time=900' {ca}",
            silent=True,
        )
        # Authfail (after pam_unix)
        run_command(
            f"sed -i '/pam_unix.so/a auth [default=die] pam_faillock.so authfail deny=5 unlock_time=900' {ca}",
            silent=True,
        )
        # Authsucc (after pam_unix)
        run_command(
            f"sed -i '/pam_unix.so/a auth sufficient pam_faillock.so authsucc deny=5 unlock_time=900' {ca}",
            silent=True,
        )


def secure_critical_files():
    """Sets secure permissions on critical system files."""
    print_status("Securing critical file permissions...")
    files_to_secure = [
        ("/etc/passwd", 0o644, "root", "root"),
        ("/etc/shadow", 0o640, "root", "shadow"),
        ("/etc/group", 0o644, "root", "root"),
        ("/etc/gshadow", 0o600, "root", "shadow"),
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
    if not confirm_action(
        "Begin Configuration Hardening? (Modifies PAM, Kernel, Permissions, GUI)"
    ):
        return

    secure_critical_files()

    # Password Aging & Hashing
    print_status("Configuring password aging and hashing (/etc/login.defs)...")
    run_command("sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs")
    run_command("sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   7/' /etc/login.defs")

    if (
        run_command("grep -q '^ENCRYPT_METHOD SHA512' /etc/login.defs", silent=True)
        is None
    ):
        run_command("sed -i '/^ENCRYPT_METHOD/d' /etc/login.defs", silent=True)
        run_command("echo 'ENCRYPT_METHOD SHA512' >> /etc/login.defs")

    # Advanced PAM Configuration (V5 Safe Mode)
    safe_pam_configure()

    # Kernel Hardening
    print_status("Applying Kernel Hardening (/etc/sysctl.conf)...")
    sysctl_settings = {
        "net.ipv4.tcp_syncookies": 1,
        "net.ipv4.conf.all.rp_filter": 1,
        "net.ipv4.conf.all.accept_redirects": 0,
        "net.ipv4.ip_forward": 0,
        "fs.suid_dumpable": 0,
        "net.ipv6.conf.all.disable_ipv6": 1,
        "net.ipv4.conf.all.log_martians": 1,
    }
    for key, value in sysctl_settings.items():
        run_command(f"sed -i '/^{re.escape(key)}/d' /etc/sysctl.conf", silent=True)
        run_command(f"echo '{key} = {value}' >> /etc/sysctl.conf")

    run_command("sysctl -p")

    # GUI Hardening
    print_status("Applying GUI Hardening (GDM/LightDM/APT)...")

    # LightDM
    if os.path.exists("/etc/lightdm/"):
        os.makedirs("/etc/lightdm/lightdm.conf.d", exist_ok=True)
        run_command(
            "echo '[Seat:*]\nallow-guest=false\ngreeter-show-manual-login=true\ngreeter-hide-users=true' > /etc/lightdm/lightdm.conf.d/50-secure-greeter.conf"
        )

    # GDM
    if os.path.exists("/etc/gdm3/custom.conf"):
        if (
            run_command("grep -q '\[daemon\]' /etc/gdm3/custom.conf", silent=True)
            is None
        ):
            run_command("echo '\n[daemon]' >> /etc/gdm3/custom.conf")

        tmp_file = "/tmp/gdm_settings.txt"
        run_command(
            "sed -i '/AutomaticLoginEnable/d' /etc/gdm3/custom.conf", silent=True
        )
        run_command("sed -i '/AllowGuest/d' /etc/gdm3/custom.conf", silent=True)
        run_command("sed -i '/TimedLoginEnable/d' /etc/gdm3/custom.conf", silent=True)
        run_command(
            "echo 'AutomaticLoginEnable=false\nAllowGuest=false\nTimedLoginEnable=false' > "
            + tmp_file
        )
        run_command(
            f"sed -i '/^\[daemon\]/r {tmp_file}' /etc/gdm3/custom.conf", silent=True
        )
        run_command(f"rm {tmp_file}", silent=True)

    # FIX: REMOVED /run/shm noexec hardening to prevent GNOME/Wayland crash
    print_status("Skipping /run/shm hardening to protect GUI stability...")


# --- Phase 5: Software, Services, and Advanced Hardening (V5 Logic) ---


def harden_ssh(services_to_enable):
    if "ssh" in services_to_enable and os.path.exists("/etc/ssh/sshd_config"):
        print_status("Applying Advanced SSH Hardening...")
        ssh_config = "/etc/ssh/sshd_config"

        # V5: Recursive Cleaning
        if os.path.exists("/etc/ssh/sshd_config.d"):
            print_status(
                "Cleaning /etc/ssh/sshd_config.d/ to prevent override issues..."
            )
            run_command("rm -f /etc/ssh/sshd_config.d/*", silent=True)

        def update_ssh_config(key, value):
            if (
                run_command(f"grep -qE '^[#]?{key}' {ssh_config}", silent=True)
                is not None
            ):
                run_command(f"sed -i 's/^[#]?{key}.*/{key} {value}/' {ssh_config}")
            else:
                run_command(f"echo '{key} {value}' >> {ssh_config}")

        update_ssh_config("PermitRootLogin", "no")
        update_ssh_config("Protocol", "2")
        update_ssh_config("PermitEmptyPasswords", "no")
        update_ssh_config("X11Forwarding", "no")
        update_ssh_config("MaxAuthTries", "4")
        update_ssh_config("HostbasedAuthentication", "no")

        run_command("systemctl restart ssh", silent=True)


def manage_services(services_to_enable_units):
    """V5: Enables required services and disables unauthorized services (Whitelist Strategy)."""
    print_status(
        "Starting Service Management (Enable Required / Disable Unauthorized)..."
    )

    if services_to_enable_units:
        print_status("Enabling required services...")
        for unit in services_to_enable_units:
            run_command(f"systemctl unmask {unit}", silent=True)
            run_command(f"systemctl enable --now {unit}", silent=True)

    print_status("Auditing active services against whitelist (Aggressive Disabling)...")
    active_services_output = run_command(
        "systemctl list-units --type=service --state=active --no-pager --no-legend"
    )

    if not active_services_output:
        return

    whitelist = set(ESSENTIAL_SERVICES)
    whitelist.update(services_to_enable_units)

    services_to_disable = []
    for line in active_services_output.split("\n"):
        if line.strip():
            unit_name = line.split()[0]
            service_name = unit_name.replace(".service", "")

            is_allowed = False
            for item in whitelist:
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
        else:
            print_status("Service disabling skipped by operator.", None)


def software_services_and_hardening():
    """V5: Manages software and services using Net Difference Logic."""
    print_header("Phase 5: Software, Services, and Advanced Hardening")
    if not confirm_action(
        "Begin Software and Service Management? (Installs/Removes software, stops services)"
    ):
        return

    run_command(
        "apt-get install ufw auditd debsums net-tools apparmor-utils -yq", silent=True
    )
    run_command("systemctl enable --now auditd", silent=True)
    run_command("auditctl -e 1", silent=True)

    print_status("Calculating software Allow List (Protected Packages)...")
    ALLOW_LIST = set(REQUIRED_INSTALLS)

    services_to_enable_units = set()
    for service_input in REQUIRED_SERVICES_RAW:
        pkg, unit = service_input, service_input
        if service_input in SERVICE_MAP:
            pkg, unit = SERVICE_MAP[service_input]

        ALLOW_LIST.add(pkg)
        services_to_enable_units.add(unit)

    PURGE_LIST = set(PROHIBITED_SOFTWARE)
    FINAL_PURGE_LIST = PURGE_LIST.difference(ALLOW_LIST)

    overridden_purges = PURGE_LIST.intersection(ALLOW_LIST)
    if overridden_purges:
        print_status(
            f"OVERRIDE ACTIVE: Protecting required packages from purge: {list(overridden_purges)}",
            None,
        )

    if ALLOW_LIST:
        print_status("Ensuring required software/services are installed...")
        run_command(
            f"apt-get install --ignore-missing -yq {' '.join(ALLOW_LIST)}", silent=True
        )

    if FINAL_PURGE_LIST:
        print_status("Purging unauthorized software...")
        purge_command = (
            f"apt-get purge --ignore-missing -yq {' '.join(FINAL_PURGE_LIST)}"
        )
        run_command(purge_command)
        # V5: Snap Support for Aisleriot
        for p in FINAL_PURGE_LIST:
            run_command(f"snap remove {p}", silent=True)

        run_command("apt-get autoremove -yq")

    manage_services(services_to_enable_units)
    harden_ssh(services_to_enable_units)


# --- Phase 6: Integrity Check and Advanced Detection (V5 Active Mode) ---


def network_audit():
    """Analyzes listening ports (ss) to detect backdoors AND KILLS THEM."""
    print_status("Analyzing listening network ports (ss -tulpn)...")
    system_ports = {
        "22",
        "53",
        "68",
        "631",
        "80",
        "443",
        "21",
        "25",
        "111",
        "3306",
        "5432",
        "139",
        "445",
    }
    listeners = run_command("ss -tulpn")
    if not listeners:
        return

    for line in listeners.split("\n"):
        if line.startswith("tcp") or line.startswith("udp"):
            parts = line.split()
            if len(parts) < 5:
                continue
            port = parts[4].split(":")[-1]
            process_info = parts[-1] if len(parts) > 5 else "Unknown"

            # Logic: Find suspicious processes listening
            if "users:((" in line:
                try:
                    proc_part = line.split("users:((")[1]
                    proc_name = proc_part.split('"')[1]
                    pid = int(proc_part.split("pid=")[1].split(",")[0])

                    bad_procs = ["nc", "netcat", "ncat", "john", "hydra"]

                    # V5 Fix: Don't flag sshd as 'sh'
                    if proc_name in bad_procs or (
                        proc_name == "sh" and "sshd" not in line
                    ):
                        print_status(
                            f"ACTIVE BACKDOOR FOUND: {proc_name} (PID: {pid})", False
                        )
                        # ACTIVE KILL
                        try:
                            os.kill(pid, signal.SIGKILL)
                            print_status(f"KILLED PID {pid}", True)
                            # Find and delete executable
                            exe = os.readlink(f"/proc/{pid}/exe")
                            if os.path.exists(exe) and confirm_action(
                                f"Delete executable {exe}?"
                            ):
                                os.remove(exe)
                        except Exception as e:
                            print(f"Failed to kill/delete: {e}")
                except:
                    pass

            elif port not in system_ports:
                try:
                    if int(port) > 1024:
                        print_status(
                            f"UNEXPECTED PORT: Port {port} open by {process_info}", None
                        )
                except ValueError:
                    continue


def suid_sgid_audit():
    """Scans for SUID/SGID binaries and flags anomalies."""
    print_status("Auditing SUID/SGID binaries...")
    suid_files = run_command(
        "find / -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null", silent=True
    )
    if not suid_files:
        return

    for filepath in suid_files.split("\n"):
        if filepath.strip():
            is_safe = False
            for safe_path in KNOWN_GOOD_SUID:
                if filepath.startswith(safe_path):
                    is_safe = True
                    break

            if not is_safe and not filepath.startswith("/snap/"):
                details = run_command(f"ls -l {filepath}", silent=True)
                basename = os.path.basename(filepath)
                if basename in [
                    "vim",
                    "find",
                    "less",
                    "more",
                    "nmap",
                    "bash",
                    "python",
                    "perl",
                ]:
                    print_status(
                        f"CRITICAL SUID/SGID (Potential Exploit): {details}", False
                    )
                else:
                    print_status(f"ANOMALOUS SUID/SGID Binary: {details}", None)


def sudoers_audit():
    """Scans /etc/sudoers and /etc/sudoers.d/ for dangerous configurations."""
    print_status("Auditing Sudoers configuration for threats (NOPASSWD)...")
    sudoers_files = ["/etc/sudoers"]
    if os.path.exists("/etc/sudoers.d"):
        files = run_command("ls /etc/sudoers.d/* 2>/dev/null", silent=True)
        if files:
            sudoers_files.extend(files.split("\n"))

    threats = ["NOPASSWD:", "!authenticate"]

    for filepath in sudoers_files:
        if filepath and os.path.isfile(filepath):
            content = run_command(f"cat {filepath}", silent=True)
            if content:
                for line in content.split("\n"):
                    if (
                        line.strip()
                        and not line.strip().startswith("#")
                        and not line.strip().startswith("Defaults")
                    ):
                        for threat in threats:
                            if threat in line:
                                print_status(
                                    f"DANGEROUS SUDOERS ENTRY in {filepath}: {line.strip()}",
                                    False,
                                )


def persistence_hunt():
    """Hunts for common persistence mechanisms."""
    print_status("Auditing Cron Jobs, Startup Files, and SSH Keys for persistence...")
    locations = ["/etc/crontab"]
    locations.extend(
        run_command("ls /etc/cron.*/* 2>/dev/null", silent=True).split("\n")
    )
    locations.extend(
        run_command("ls /var/spool/cron/crontabs/* 2>/dev/null", silent=True).split(
            "\n"
        )
    )

    user_homes_output = run_command(
        "grep '/home/' /etc/passwd | cut -d: -f6", silent=True
    )
    user_homes = user_homes_output.split("\n") if user_homes_output else []
    user_homes.append("/root")

    for home in user_homes:
        if home and home.strip():
            locations.append(f"{home}/.bashrc")
            locations.append(f"{home}/.profile")
            keys_file = f"{home}/.ssh/authorized_keys"
            if os.path.exists(keys_file):
                print_status(
                    f"FOUND SSH KEY FILE: {keys_file}. Review manually for unauthorized keys.",
                    False,
                )

    suspicious_patterns = [
        r"nc\s+-",
        r"netcat\s+-",
        r"/tmp/.*\.sh",
        r"wget\s+http",
        r"curl\s+http",
        r"base64\s+-d",
        r"python\s+-c",
        r"perl\s+-e",
        r"bash\s+-i\s+>&",
        r"/dev/tcp/",
    ]

    for location in locations:
        if location and location.strip() and os.path.isfile(location):
            content = run_command(f"cat {location}", silent=True)
            if content:
                for line in content.split("\n"):
                    if line.strip() and not line.strip().startswith("#"):
                        for pattern in suspicious_patterns:
                            if re.search(pattern, line):
                                print_status(
                                    f"SUSPICIOUS ENTRY in {location}: {line}", False
                                )


def integrity_and_advanced_detection():
    """Checks binaries and hunts for persistence."""
    print_header("Phase 6: Advanced Detection and Integrity")

    if not confirm_action(
        "Begin Advanced Detection? (Scans network, binaries, persistence)"
    ):
        return

    # Advanced Audits
    network_audit()
    suid_sgid_audit()
    sudoers_audit()
    persistence_hunt()

    # Integrity Check (Debsums)
    print_status("Checking for poisoned binaries (debsums -c)...")
    run_command("apt-get install debsums -yq", silent=True)
    debsums_output = run_command("debsums -c", silent=True, suppress_stderr=True)

    if debsums_output:
        failed_files = []
        for line in debsums_output.split("\n"):
            match = re.search(r"(.+):.+FAILED", line)
            if match:
                failed_files.append(match.group(1).strip())

        if failed_files:
            print_status(
                f"CRITICAL: Found {len(failed_files)} modified system binaries!", False
            )
            if confirm_action(
                "Do you want to attempt reinstalling the affected packages?"
            ):
                packages_to_reinstall = set()
                for file_path in failed_files:
                    pkg = run_command(f"dpkg -S {file_path} | cut -d: -f1", silent=True)
                    if pkg:
                        packages_to_reinstall.add(pkg)

                if packages_to_reinstall:
                    run_command(
                        f"apt-get install --reinstall {' '.join(packages_to_reinstall)} -yq"
                    )


# --- Phase 7: Firewall Activation ---


def firewall_activation():
    """Configures UFW."""
    print_header("Phase 7: Firewall Activation")

    if not confirm_action("Configure and enable UFW?"):
        return

    run_command("ufw --force reset")
    run_command("ufw default deny incoming")
    run_command("ufw default allow outgoing")
    run_command("ufw logging medium")

    # Allow required ports
    ports_allowed = set()
    normalized_services = set()
    for s in REQUIRED_SERVICES_RAW:
        if s in SERVICE_MAP:
            normalized_services.add(SERVICE_MAP[s][1])

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


# --- Main Execution ---


def main():
    # Ensure Input directory exists before starting
    if not os.path.exists(INPUT_DIR):
        setup_directories()

    start_time = time.time()

    initialization_and_updates()
    run_media_hunt()
    user_management_blitz()
    configuration_hardening()
    software_services_and_hardening()
    integrity_and_advanced_detection()
    firewall_activation()

    end_time = time.time()
    duration = (end_time - start_time) / 60

    print_header("Juggernaut v5 Execution Complete")
    logging.info(f"Juggernaut v5 Script Finished. Duration: {duration:.2f} minutes.")
    print_status(f"Automation finished. Duration: {duration:.2f} minutes.")
    print_status(f"Review the log file: {LOG_FILE}")
    print_status("CRITICAL MANUAL CHECKS:", None)
    print_status(
        "1. Verify PAM stability: Open a NEW terminal and run 'sudo ls'.",
        None,
    )
    print_status(
        "2. Manually investigate all findings from Phase 6.",
        False,
    )


if __name__ == "__main__":
    main()
