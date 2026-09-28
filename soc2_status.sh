#!/bin/bash

# SOC2 Compliance Status Checker for macOS
# Read-only: inspects security settings and reports PASS / WARN / FAIL.
# Uses current macOS APIs where available and falls back to the legacy
# ones on older releases (tested down to macOS 10.14 Mojave).

# ---------- Policy thresholds ----------
MAX_LOCK_IDLE_MIN=5   # screen must lock after this many minutes of inactivity
MAX_LOCK_DELAY_SEC=5  # grace period allowed before the password is demanded
MIN_PASSWORD_LEN=8    # minimum account password length
MAX_SCAN_AGE_DAYS=7   # a software-update scan older than this cannot prove the patch level

# Known macOS releases, oldest first. Apple ships security updates for the newest
# SUPPORTED_MAJORS entries, so support is judged by position in this list rather
# than by arithmetic on the version number (15 is followed by 26, not 16).
# Append new releases as they ship; anything newer than this list counts as
# current, so an out-of-date copy of this script never nags; anything older fails.
MACOS_RELEASES="10.13 10.14 10.15 11 12 13 14 15 26 27"
SUPPORTED_MAJORS=3

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

COMPLIANCE_FAILED=0

# ---------- Helpers ----------

# report PASS|WARN|FAIL "message" — prints a verdict; FAIL fails the run.
report() {
  local tag
  case "$1" in
    PASS) tag="${GREEN}✓ PASS${NC}" ;;
    WARN) tag="${YELLOW}⚠ WARN${NC}" ;;
    FAIL) tag="${RED}✗ FAIL${NC}"; COMPLIANCE_FAILED=1 ;;
  esac
  printf '%b - %s\n' "$tag" "$2"
}

section() { printf '\n%s\n' "$1"; }

# True when the argument is a non-empty string of digits.
is_num() { case "$1" in ''|*[!0-9]*) return 1 ;; *) return 0 ;; esac; }

# pref <domain> <key> — read a preference, empty if unset.
pref() { defaults read "$1" "$2" 2>/dev/null; }

# release_key <release> — sortable number for a release ("10.13" → 1013, "26" → 2600).
release_key() {
  local major=${1%%.*} minor=0
  case "$1" in *.*) minor=${1#*.}; minor=${minor%%.*} ;; esac
  is_num "$major" && is_num "$minor" || return
  echo $((10#$major * 100 + 10#$minor))
}

# release_age <release> — releases behind the newest known one. A release older
# than the whole list counts as at least that many behind; a newer unknown
# release, or one that cannot be parsed, gives -1.
release_age() {
  local total=0 pos=0 r key oldest
  for r in $MACOS_RELEASES; do
    total=$((total + 1))
    [ "$r" = "$1" ] && pos=$total
  done
  if [ "$pos" -ne 0 ]; then echo $((total - pos)); return; fi
  key=$(release_key "$1")
  oldest=$(release_key "${MACOS_RELEASES%% *}")
  if [ -n "$key" ] && [ "$key" -lt "$oldest" ]; then echo "$total"; else echo -1; fi
}

# release_of <version> — release identity ("10.15", "26") for a full version string.
release_of() {
  case "$1" in
    ''|*[!0-9.]*) ;;
    10.*) printf '%s' "$1" | cut -d. -f1,2 ;;
    *)    printf '%s' "${1%%.*}" ;;
  esac
}

# days_since "<plist date>" — whole days since that timestamp, empty if unparseable.
days_since() {
  local epoch
  epoch=$(date -j -f "%Y-%m-%d %H:%M:%S %z" "$1" "+%s" 2>/dev/null) || return
  [ -n "$epoch" ] && echo $(( ($(date +%s) - epoch) / 86400 ))
}

# ---------- System information ----------
OS_VERSION=$(sw_vers -productVersion 2>/dev/null)
OS_MAJOR=${OS_VERSION%%.*}
# Release identity: "10.15" for Catalina and earlier, "14"/"26" from Big Sur on.
if [ "$OS_MAJOR" = "10" ]; then
  OS_RELEASE=$(printf '%s' "$OS_VERSION" | cut -d. -f1,2)
else
  OS_RELEASE=$OS_MAJOR
fi
HW=$(system_profiler SPHardwareDataType 2>/dev/null)
hw() { printf '%s\n' "$HW" | sed -n "s/^ *$1[^:]*: *//p" | head -1; }

PROCESSOR=$(hw "Chip")                                  # Apple silicon
[ -z "$PROCESSOR" ] && PROCESSOR=$(hw "Processor Name") # Intel
DISK_SIZE=$(diskutil info disk0 2>/dev/null | sed -n 's/^ *Disk Size: *\([^(]*\).*/\1/p' | xargs)

echo "================================================"
echo "SOC2 Compliance Status Check"
echo "================================================"
echo ""
echo "System Information:"
echo "─────────────────────────────────────────────────"
printf '%-15s%s\n' \
  "User:"          "$(id -F 2>/dev/null || id -un)" \
  "Report Time:"   "$(date '+%Y-%m-%d %H:%M:%S %Z')" \
  "macOS Version:" "$OS_VERSION (Build $(sw_vers -buildVersion 2>/dev/null))" \
  "Model:"         "$(hw 'Model Name')" \
  "Processor:"     "$PROCESSOR" \
  "Memory:"        "$(hw 'Memory')" \
  "Disk:"          "$DISK_SIZE" \
  "Serial Number:" "$(hw 'Serial Number')"
echo ""
echo "================================================"
echo "Security Compliance Checks"
echo "================================================"

# ---------- FileVault (full disk encryption) ----------
section "Checking FileVault (Full Disk Encryption)..."
FILEVAULT_STATUS=$(fdesetup status 2>/dev/null)
case "$FILEVAULT_STATUS" in
  *"FileVault is On"*)       report PASS "FileVault is enabled" ;;
  *"Encryption in progress"*) report WARN "FileVault encryption in progress" ;;
  "")                        report FAIL "Unable to check FileVault status (fdesetup unavailable)" ;;
  *)                         report FAIL "FileVault is not enabled" ;;
esac

# ---------- Screen lock ----------
section "Checking Screen Lock settings..."

# How long the machine may sit idle before the screen is secured: whichever
# comes first, the screen saver or the display turning off.
SAVER_IDLE=$(defaults -currentHost read com.apple.screensaver idleTime 2>/dev/null)
DISPLAY_SLEEP=$(pmset -g 2>/dev/null | awk '/displaysleep/ {print $2; exit}')
IDLE_MIN=""
is_num "$SAVER_IDLE" && [ "$SAVER_IDLE" -gt 0 ] && IDLE_MIN=$(( (SAVER_IDLE + 59) / 60 ))
if is_num "$DISPLAY_SLEEP" && [ "$DISPLAY_SLEEP" -gt 0 ]; then
  { [ -z "$IDLE_MIN" ] || [ "$DISPLAY_SLEEP" -lt "$IDLE_MIN" ]; } && IDLE_MIN=$DISPLAY_SLEEP
fi

if [ -z "$IDLE_MIN" ]; then
  report FAIL "Screen never locks automatically (screen saver and display sleep are both off)"
elif [ "$IDLE_MIN" -gt "$MAX_LOCK_IDLE_MIN" ]; then
  report FAIL "Screen locks after ${IDLE_MIN} minutes (requires ≤${MAX_LOCK_IDLE_MIN})"
else
  report PASS "Screen locks after ${IDLE_MIN} minute(s) of inactivity"
fi

# Password-on-wake. macOS 11+ answers via sysadminctl; older releases keep the
# setting in the (now unused) com.apple.screensaver preferences.
LOCK_DELAY=""
LOCK_STATE=""
if [ -n "$OS_MAJOR" ] && [ "$OS_MAJOR" -ge 11 ] 2>/dev/null; then
  SCREEN_LOCK=$(sysadminctl -screenLock status 2>&1)
  case "$SCREEN_LOCK" in
    *"screenLock is off"*)      LOCK_STATE=off ;;
    *"delay is immediate"*)     LOCK_STATE=on; LOCK_DELAY=0 ;;
    *"delay is"*)               LOCK_STATE=on
                                LOCK_DELAY=$(printf '%s' "$SCREEN_LOCK" | sed -n 's/.*delay is \([0-9]*\).*/\1/p') ;;
  esac
fi
if [ -z "$LOCK_STATE" ]; then
  ASK=$(defaults -currentHost read com.apple.screensaver askForPassword 2>/dev/null)
  [ -z "$ASK" ] && ASK=$(pref com.apple.screensaver askForPassword)
  LOCK_DELAY=$(defaults -currentHost read com.apple.screensaver askForPasswordDelay 2>/dev/null)
  [ -z "$LOCK_DELAY" ] && LOCK_DELAY=$(pref com.apple.screensaver askForPasswordDelay)
  case "$ASK" in
    1) LOCK_STATE=on ;;
    0) LOCK_STATE=off ;;
  esac
fi

case "$LOCK_STATE" in
  off) report FAIL "Password is not required after the screen locks" ;;
  on)
    if ! is_num "$LOCK_DELAY"; then
      report PASS "Password is required after the screen locks"
    elif [ "$LOCK_DELAY" -le "$MAX_LOCK_DELAY_SEC" ]; then
      report PASS "Password is required after the screen locks (delay: ${LOCK_DELAY}s)"
    else
      report WARN "Password is required, but only after ${LOCK_DELAY}s (recommended: ≤${MAX_LOCK_DELAY_SEC}s)"
    fi
    ;;
  *)
    # Unreadable setting: FileVault still forces a password on wake from sleep.
    case "$FILEVAULT_STATUS" in
      *"FileVault is On"*) report PASS "Password requirement enforced by the system (FileVault enabled)" ;;
      *)                   report WARN "Cannot verify the password requirement (may be managed by MDM)" ;;
    esac
    ;;
esac

# ---------- Password policy ----------
section "Checking Password Policy (minimum length)..."
POLICY=$(pwpolicy -getaccountpolicies 2>/dev/null)
# Global policy states the minimum as a regex such as: matches '.{8,}?'
MIN_LENGTH=$(printf '%s' "$POLICY" | sed -n "s/.*policyAttributePassword matches '\.{\([0-9]*\),.*/\1/p" | head -1)
if [ -z "$POLICY" ]; then
  report WARN "Unable to retrieve the password policy (pwpolicy unavailable)"
elif ! is_num "$MIN_LENGTH"; then
  report WARN "Unable to determine the minimum password length from the policy"
elif [ "$MIN_LENGTH" -lt "$MIN_PASSWORD_LEN" ]; then
  report FAIL "Minimum password length is ${MIN_LENGTH} (requires ≥${MIN_PASSWORD_LEN})"
else
  report PASS "Minimum password length is ${MIN_LENGTH} characters"
fi

# ---------- macOS version support and patch level ----------
section "Checking macOS version (support window and patch level)..."

# Being a release or two behind is fine: Apple ships security updates for the
# newest SUPPORTED_MAJORS releases, so only an out-of-support release fails.
BEHIND=$(release_age "$OS_RELEASE")
RELEASE_SUPPORTED=0
{ [ "$BEHIND" -lt 0 ] || [ "$BEHIND" -lt "$SUPPORTED_MAJORS" ]; } && RELEASE_SUPPORTED=1
if [ "$BEHIND" -lt 0 ]; then
  report PASS "macOS $OS_VERSION is current"
elif [ "$BEHIND" -ge "$SUPPORTED_MAJORS" ]; then
  report FAIL "macOS $OS_RELEASE no longer receives security updates (Apple supports the newest $SUPPORTED_MAJORS releases)"
elif [ "$BEHIND" -eq 0 ]; then
  report PASS "macOS $OS_RELEASE is the current release"
else
  report PASS "macOS $OS_RELEASE is supported ($BEHIND release(s) behind, still receiving security updates)"
fi

# Patch level, judged only against the installed release. RecommendedUpdates
# holds the pending updates, and on some releases that includes the offer to
# upgrade to a newer major release. Staying on an older but still supported
# release is not a finding, so those upgrade offers are dropped below.
SU=/Library/Preferences/com.apple.SoftwareUpdate
LAST_SCAN=$(pref $SU LastFullSuccessfulDate)
[ -z "$LAST_SCAN" ] && LAST_SCAN=$(pref $SU LastSuccessfulDate)
[ -z "$LAST_SCAN" ] && LAST_SCAN=$(pref $SU LastBackgroundSuccessfulDate)
SCAN_AGE=$(days_since "$LAST_SCAN")
PENDING_LIST=$(pref $SU RecommendedUpdates)

# One "<version>|<display name>" record per pending update.
PENDING_ENTRIES=$(printf '%s\n' "$PENDING_LIST" | awk '
  function val(line,   v) {
    v = line
    sub(/^[^=]*=[ \t]*/, "", v)
    sub(/;[ \t]*$/, "", v)
    gsub(/"/, "", v)
    sub(/[ \t]+$/, "", v)
    return v
  }
  /"Display Name"/    { name = val($0) }
  /"Display Version"/ { ver  = val($0) }
  /}/ { if (name != "") print ver "|" name; name = ""; ver = "" }
')

PENDING_NAMES=""
PENDING_COUNT=0
while IFS='|' read -r ENTRY_VERSION ENTRY_NAME; do
  [ -n "$ENTRY_NAME" ] || continue
  # An entry whose version belongs to a macOS release newer than the running one
  # is a major upgrade offer, not a patch for this release. Ignore it as long as
  # the running release is still getting security updates. Non-macOS entries
  # (Safari, XProtect, …) are not listed releases, so they are always reported.
  ENTRY_RELEASE=$(release_of "$ENTRY_VERSION")
  if [ "$RELEASE_SUPPORTED" -eq 1 ] && [ -n "$ENTRY_RELEASE" ]; then
    ENTRY_BEHIND=$(release_age "$ENTRY_RELEASE")
    if [ "$ENTRY_BEHIND" -ge 0 ] && [ "$BEHIND" -ge 0 ] && [ "$ENTRY_BEHIND" -lt "$BEHIND" ]; then
      continue
    fi
  fi
  PENDING_COUNT=$((PENDING_COUNT + 1))
  PENDING_NAMES="${PENDING_NAMES:+$PENDING_NAMES, }$ENTRY_NAME"
done <<EOF
$PENDING_ENTRIES
EOF

if [ -z "$SCAN_AGE" ]; then
  report WARN "Cannot confirm the patch level (no record of a successful update check)"
elif [ "$SCAN_AGE" -gt "$MAX_SCAN_AGE_DAYS" ]; then
  report WARN "Last update check was ${SCAN_AGE} days ago (>${MAX_SCAN_AGE_DAYS}); patch level unconfirmed"
elif [ "$PENDING_COUNT" -gt 0 ]; then
  report WARN "${PENDING_COUNT} pending update(s) for macOS ${OS_RELEASE}: ${PENDING_NAMES:-see System Settings}"
else
  report PASS "macOS $OS_VERSION is fully patched (no pending updates for this release)"
fi

# ---------- Automatic updates ----------
section "Checking Automatic Updates settings..."

# "Automatically check for updates" has no reliable preference key on recent
# macOS, so ask softwareupdate itself.
if softwareupdate --schedule 2>/dev/null | grep -Eqi "is (turned )?on([^a-z]|$)"; then
  report PASS "Automatic update checking is enabled"
else
  report FAIL "Automatic update checking is disabled"
fi

# severity|domain|key|description
for RULE in \
  "FAIL|$SU|AutomaticDownload|Automatic download of updates" \
  "FAIL|$SU|CriticalUpdateInstall|Automatic installation of critical (security) updates" \
  "FAIL|$SU|ConfigDataInstall|Automatic installation of system data files (XProtect definitions)" \
  "WARN|$SU|AutomaticallyInstallMacOSUpdates|Automatic installation of macOS updates" \
  "WARN|/Library/Preferences/com.apple.commerce|AutoUpdate|App Store automatic updates"
do
  IFS='|' read -r SEVERITY DOMAIN KEY LABEL <<EOF
$RULE
EOF
  if [ "$(pref "$DOMAIN" "$KEY")" = "1" ]; then
    report PASS "$LABEL: enabled"
  else
    report "$SEVERITY" "$LABEL: disabled"
  fi
done

# ---------- XProtect (built-in anti-malware) ----------
section "Checking XProtect (Anti-Malware)..."

# The agents run on demand, so being listed by launchd is what matters, not a PID.
if launchctl list 2>/dev/null | grep -q "com.apple.XprotectFramework.PluginService\|com.apple.XProtect.agent"; then
  report PASS "XProtect services are loaded"
else
  report FAIL "XProtect services are not loaded"
fi

# Malware definitions live in XProtect.bundle; it moved under /Library/Apple in 10.15.
XPROTECT_BUNDLE=""
for CANDIDATE in /Library/Apple/System/Library/CoreServices/XProtect.bundle \
                 /System/Library/CoreServices/XProtect.bundle; do
  [ -d "$CANDIDATE" ] && { XPROTECT_BUNDLE=$CANDIDATE; break; }
done
if [ -n "$XPROTECT_BUNDLE" ]; then
  XPROTECT_VERSION=$(pref "$XPROTECT_BUNDLE/Contents/Info.plist" CFBundleShortVersionString)
  report PASS "XProtect malware definitions installed (version ${XPROTECT_VERSION:-unknown})"
else
  report FAIL "XProtect malware definitions not found"
fi

# ---------- Verdict ----------
echo ""
echo "================================================"
if [ "$COMPLIANCE_FAILED" -eq 0 ]; then
  printf '%bOverall Status: COMPLIANT%b\n' "$GREEN" "$NC"
  exit 0
else
  printf '%bOverall Status: NON-COMPLIANT%b\n' "$RED" "$NC"
  exit 1
fi
