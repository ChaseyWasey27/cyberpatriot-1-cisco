# juggernaut_windows_secure.py
# Windows hardening skeleton for CyberPatriot-style scoring
# Requires Python 3.8+ and administrative privileges.
# Usage: run elevated (Administrator). Use --force to skip confirmations.

import os
import sys
import subprocess
import logging
import argparse
import shutil
import datetime
import glob

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INPUT_DIR = os.path.join(BASE_DIR, "Input")
FORENSICS_DIR = os.path.join(BASE_DIR, "Forensics")
LOG_FILE = os.path.join(BASE_DIR, "juggernaut_windows.log")

# Input file placeholders to keep same structure as original
USERS_FILE = os.path.join(INPUT_DIR, "users.txt")
ADMINS_FILE = os.path.join(INPUT_DIR, "admins.txt")
PASSWORD_FILE = os.path.join(INPUT_DIR, "password.txt")
PROHIBITED_FILE = os.path.join(INPUT_DIR, "prohibited_software.txt")
SERVICES_FILE = os.path.join(INPUT_DIR, "services.txt")
INSTALLS_FILE = os.path.join(INPUT_DIR, "required_installs.txt")

# Configure logging
def setup_logging():
    logging.basicConfig(
        filename=LOG_FILE,
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )
    logging.getLogger().addHandler(logging.StreamHandler(sys.stdout))


# Helpers --------------------------------------------------------------------
def is_admin():
    try:
        # On Windows, powershell whoami /groups can indicate admin, but easiest:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def run_powershell(cmd, capture=False, ignore_errors=False):
    # Use -ExecutionPolicy Bypass to allow script operations
    full = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cmd]
    logging.info("PS: %s", cmd)
    try:
        if capture:
            out = subprocess.run(full, capture_output=True, text=True)
            if out.returncode != 0 and not ignore_errors:
                logging.error("Command failed: %s\nSTDERR: %s", cmd, out.stderr.strip())
            return out.stdout or ""
        else:
            out = subprocess.run(full)
            if out.returncode != 0 and not ignore_errors:
                logging.error("Command failed: %s (RC %d)", cmd, out.returncode)
            return None
    except Exception as e:
        logging.exception("Failed to run powershell command")
        return None


def confirm(prompt, force=False):
    if force:
        logging.info("Auto-confirm enabled, proceeding: %s", prompt)
        return True
    ans = input(f"{prompt} (Y/n): ").strip().lower()
    return ans == "" or ans == "y"


def ensure_directories():
    os.makedirs(INPUT_DIR, exist_ok=True)
    os.makedirs(FORENSICS_DIR, exist_ok=True)
    # Create input stubs if missing
    templates = {
        USERS_FILE: "Administrator\n",
        ADMINS_FILE: "Administrator\n",
        PASSWORD_FILE: "StrongPassw0rd!2025\n",
        PROHIBITED_FILE: "wireshark\nnmap\nhashcat\n",
        SERVICES_FILE: "# windows service names (one per line)\nTermService\n",
        INSTALLS_FILE: "# list required installs (choco package names)\n",
    }
    for p, txt in templates.items():
        if not os.path.exists(p):
            with open(p, "w", encoding="utf-8") as f:
                f.write(txt)


# Forensics ------------------------------------------------------------------
def collect_forensics():
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = os.path.join(FORENSICS_DIR, f"forensics_{timestamp}.txt")
    logging.info("Collecting forensics to %s", out)
    with open(out, "w", encoding="utf-8") as f:
        f.write("=== SYSTEMINFO ===\n")
        f.write(run_powershell("Get-ComputerInfo | Out-String", capture=True))
        f.write("\n=== PROCESSES ===\n")
        f.write(run_powershell("Get-Process | Out-String", capture=True))
        f.write("\n=== LISTENING PORTS ===\n")
        f.write(run_powershell("Get-NetTCPConnection | Out-String", capture=True))
        f.write("\n=== EVENT LOGS (APPLICATION last 200) ===\n")
        f.write(run_powershell("Get-EventLog -LogName Application -Newest 200 | Out-String", capture=True))
        f.write("\n=== LOCAL USERS ===\n")
        f.write(run_powershell("Get-LocalUser | Out-String", capture=True))
    logging.info("Forensics collection complete.")


# Core Hardening Actions -----------------------------------------------------
def add_remote_desktop_users_from_file(force=False):
    # Read USERS_FILE; add each listed user to "Remote Desktop Users"
    try:
        if not os.path.exists(USERS_FILE):
            logging.warning("Users file missing: %s", USERS_FILE)
            return
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            users = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        for u in users:
            cmd = f'Add-LocalGroupMember -Group "Remote Desktop Users" -Member "{u}" -ErrorAction SilentlyContinue'
            logging.info("Adding %s to Remote Desktop Users", u)
            run_powershell(cmd, ignore_errors=True)
    except Exception:
        logging.exception("Failed to add remote desktop users")


def enable_nla_for_rdp():
    # Ensure NLA (Network Level Authentication) is required for RDP connections
    # Set UserAuthentication to 1 and SecurityLayer to 1 for RDP-Tcp
    try:
        run_powershell('Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" -Name "UserAuthentication" -Value 1', ignore_errors=True)
        run_powershell('Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" -Name "SecurityLayer" -Value 1', ignore_errors=True)
        logging.info("Enabled NLA for RDP (registry keys adjusted)")
    except Exception:
        logging.exception("Failed to enable NLA")


def disable_blank_passwords():
    # Enforce that accounts with blank passwords cannot be used to log on locally
    # Set LimitBlankPasswordUse = 1 under HKLM\SYSTEM\CurrentControlSet\Control\Lsa
    try:
        run_powershell('Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa" -Name "LimitBlankPasswordUse" -Value 1', ignore_errors=True)
        logging.info("Disabled local use of blank passwords (LimitBlankPasswordUse=1)")
    except Exception:
        logging.exception("Failed to set LimitBlankPasswordUse")


def install_windows_updates(force=False):
    # Installs PSWindowsUpdate module if missing, then triggers updates.
    # Note: This requires internet and may reboot the machine.
    logging.info("Installing Windows updates (may reboot). This step can take a long time.")
    # Try to install PSWindowsUpdate and then run Install-WindowsUpdate
    cmd_install_module = "if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) { Install-PackageProvider -Name NuGet -Force -Scope CurrentUser; Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser -AllowClobber }"
    run_powershell(cmd_install_module, ignore_errors=True)
    # Accept all updates and auto-reboot
    cmd_updates = "Import-Module PSWindowsUpdate; Get-WindowsUpdate -AcceptAll -Install -AutoReboot"
    run_powershell(cmd_updates, ignore_errors=True)


def enable_firewall():
    # Enable Windows Firewall for all profiles
    try:
        run_powershell("Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True", ignore_errors=True)
        logging.info("Windows Firewall enabled for Domain/Private/Public")
    except Exception:
        logging.exception("Failed to enable firewall")


def disable_anonymous_sam_enumeration():
    # Block anonymous enumeration of SAM and accounts: set restrictanonymous and restrictanonymoussam (where applicable)
    try:
        # RestrictAnonymous = 1 (or 2 for more strict). 1 = no name lookups
        run_powershell('Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa" -Name "restrictanonymous" -Value 1 -Type DWord', ignore_errors=True)
        # Restrict anonymous SAM? legacy: "RestrictAnonymousSAM" = 1
        run_powershell('Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa" -Name "RestrictAnonymousSAM" -Value 1 -Type DWord', ignore_errors=True)
        logging.info("Configured LSA to restrict anonymous SAM/account enumeration")
    except Exception:
        logging.exception("Failed to restrict anonymous SAM enumeration")


def disable_remote_assistance():
    # Disable Remote Assistance via registry and service
    try:
        run_powershell('Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Remote Assistance" -Name "fAllowToGetHelp" -Value 0 -Type DWord', ignore_errors=True)
        # Also disable Remote Assistance group policy equivalent
        run_powershell('Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services" -Name "fAllowUnsolicited" -Value 0 -Type DWord', ignore_errors=True)
        logging.info("Disabled Remote Assistance")
    except Exception:
        logging.exception("Failed to disable Remote Assistance")


def apply_password_and_lockout_policy():
    # Use secedit to apply security template might be more robust but for simplicity use net accounts and registry for complexity
    try:
        # Minimum password length to 14 (net accounts affects workstation policies)
        run_powershell('net accounts /minpwlen:14', ignore_errors=True)
        # Max password age (in days)
        run_powershell('net accounts /maxpwage:90', ignore_errors=True)
        # Min password age
        run_powershell('net accounts /minpwage:7', ignore_errors=True)
        # Lockout threshold (use registry to set domain/workstation policies)
        # Use Local Security Policy via secedit template for account lockout
        sec_template = os.path.join(BASE_DIR, "juggernaut_secpol.inf")
        with open(sec_template, "w", encoding="utf-8") as f:
            f.write("""
[System Access]
LockoutBadCount = 5
ResetLockoutCount = 15
LockoutDuration = 15
MinimumPasswordLength = 14
PasswordComplexity = 1
""")
        run_powershell(f"secedit /configure /db %windir%\\security\\local.sdb /cfg \"{sec_template}\" /areas SECURITYPOLICY", ignore_errors=True)
        logging.info("Password complexity and account lockout policies applied")
    except Exception:
        logging.exception("Failed to apply password/lockout policy")


def disable_guest_and_anonymous_accounts():
    try:
        run_powershell('Disable-LocalUser -Name "Guest" -ErrorAction SilentlyContinue', ignore_errors=True)
        # Ensure Administrator account exists but consider renaming (we will not rename automatically to avoid lockout)
        logging.info("Disabled Guest account where present")
    except Exception:
        logging.exception("Failed to disable guest account")


def secure_services_and_features():
    # Example: disable IIS if not required, disable Telnet client/service, disable Remote Registry service, disable SMBv1
    try:
        # Disable Remote Registry service
        run_powershell('Stop-Service -Name "RemoteRegistry" -ErrorAction SilentlyContinue; Set-Service -Name "RemoteRegistry" -StartupType Disabled -ErrorAction SilentlyContinue', ignore_errors=True)
        # Disable Telnet service if present
        run_powershell('if (Get-Service -Name tlntsvr -ErrorAction SilentlyContinue) { Stop-Service -Name tlntsvr -Force; Set-Service -Name tlntsvr -StartupType Disabled }', ignore_errors=True)
        # Disable SMBv1 (strongly recommended)
        run_powershell('Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart', ignore_errors=True)
        # Turn on Windows Defender real-time if available
        run_powershell('Set-MpPreference -DisableRealtimeMonitoring $false', ignore_errors=True)
        logging.info("Adjusted services: RemoteRegistry disabled, SMBv1 disabled where possible")
    except Exception:
        logging.exception("Failed service hardening steps")


def purge_prohibited_software():
    # Look in PROHIBITED_FILE and attempt to uninstall via Chocolatey or Powershell Uninstall-Package if found
    if not os.path.exists(PROHIBITED_FILE):
        return
    try:
        with open(PROHIBITED_FILE, "r", encoding="utf-8") as f:
            prohibited = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        for pkg in prohibited:
            logging.info("Attempting to remove prohibited package: %s", pkg)
            # Try common uninstallers: winget, choco, msiexec search
            run_powershell(f'winget uninstall --id "{pkg}" -e --silent', ignore_errors=True)
            run_powershell(f'choco uninstall {pkg} -y', ignore_errors=True)
            # Attempt WMI uninstall by name
            run_powershell(f'Get-WmiObject -Class Win32_Product -Filter "Name LIKE \'%{pkg}%\'" | ForEach-Object {{ $_.Uninstall() }}', ignore_errors=True)
    except Exception:
        logging.exception("Failed to purge prohibited software")


def run_media_hunt_and_cleanup(force=False):
    # Find potentially dangerous files (scripts, known extensions) in user directories and offer deletion.
    patterns = ["**/*.ps1", "**/*.bat", "**/*.exe", "**/*.vbs", "**/*.py", "**/*.zip", "**/*.rar"]
    user_dirs = [os.path.join("C:\\Users", d) for d in os.listdir("C:\\Users") if os.path.isdir(os.path.join("C:\\Users", d))]
    matches = []
    for u in user_dirs:
        for pat in patterns:
            path_pattern = os.path.join(u, pat)
            for match in glob.glob(path_pattern, recursive=True):
                if os.path.isfile(match):
                    matches.append(match)
    if not matches:
        logging.info("No suspicious user files found during media hunt")
        return
    logging.info("Found %d suspicious files (first 20 shown):", len(matches))
    for m in matches[:20]:
        logging.info("  %s", m)
    if confirm("Delete found suspicious files?", force):
        for m in matches:
            try:
                os.remove(m)
                logging.info("Deleted %s", m)
            except Exception:
                logging.exception("Failed to delete %s", m)


# Main -----------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Juggernaut Windows Hardening for CyberPatriot")
    parser.add_argument("--force", action="store_true", help="Auto-confirm actions")
    parser.add_argument("--no-updates", action="store_true", help="Skip Windows Update step")
    args = parser.parse_args()
    setup_logging()
    ensure_directories()
    if not is_admin():
        logging.error("This script must be run as Administrator. Exiting.")
        sys.exit(1)

    logging.info("Starting Juggernaut Windows hardening run")
    collect_forensics()
    add_remote_desktop_users_from_file(force=args.force)
    enable_nla_for_rdp()
    disable_blank_passwords()
    if not args.no_updates:
        if confirm("Install Windows updates now? This may reboot the system.", args.force):
            install_windows_updates(force=args.force)
    enable_firewall()
    disable_anonymous_sam_enumeration()
    disable_remote_assistance()
    apply_password_and_lockout_policy()
    disable_guest_and_anonymous_accounts()
    secure_services_and_features()
    purge_prohibited_software()
    run_media_hunt_and_cleanup(force=args.force)

    logging.info("Hardening run complete. Review %s for details and re-run as needed.", LOG_FILE)
    print("Hardening complete. Check log:", LOG_FILE)


if __name__ == "__main__":
    main()
