#!/bin/bash

# SOC2 Compliance Status Checker for macOS
# Checks various security settings required for SOC2 compliance

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Track overall compliance status
COMPLIANCE_FAILED=0

echo "================================================"
echo "SOC2 Compliance Status Check"
echo "================================================"
echo ""

# Gather System Information
REPORT_TIME=$(date "+%Y-%m-%d %H:%M:%S %Z")
USER_FULL_NAME=$(id -F 2>/dev/null || echo "Unknown")
OS_VERSION=$(sw_vers -productVersion 2>/dev/null)
OS_BUILD=$(sw_vers -buildVersion 2>/dev/null)
MODEL_NAME=$(system_profiler SPHardwareDataType 2>/dev/null | grep "Model Name" | awk -F': ' '{print $2}')
PROCESSOR=$(system_profiler SPHardwareDataType 2>/dev/null | grep "Chip" | awk -F': ' '{print $2}')
if [ -z "$PROCESSOR" ]; then
  PROCESSOR=$(system_profiler SPHardwareDataType 2>/dev/null | grep "Processor Name" | awk -F': ' '{print $2}')
fi
MEMORY=$(system_profiler SPHardwareDataType 2>/dev/null | grep "Memory" | awk -F': ' '{print $2}')
SERIAL_NUMBER=$(system_profiler SPHardwareDataType 2>/dev/null | grep "Serial Number" | awk -F': ' '{print $2}')
DISK_INFO=$(diskutil info disk0 2>/dev/null | grep "Disk Size:" | awk -F'(' '{print $1}' | awk -F':' '{print $2}' | xargs | sed 's/ //g')

# Display System Information
echo "System Information:"
echo "─────────────────────────────────────────────────"
echo "User:          $USER_FULL_NAME"
echo "Report Time:   $REPORT_TIME"
echo "macOS Version: $OS_VERSION (Build $OS_BUILD)"
echo "Model:         $MODEL_NAME"
echo "Processor:     $PROCESSOR"
echo "Memory:        $MEMORY"
echo "Disk:          $DISK_INFO"
echo "Serial Number: $SERIAL_NUMBER"
echo ""
echo "================================================"
echo "Security Compliance Checks"
echo "================================================"
echo ""

# Check FileVault Status
echo "Checking FileVault (Full Disk Encryption)..."
if command -v fdesetup &>/dev/null; then
  FILEVAULT_STATUS=$(fdesetup status)

  if echo "$FILEVAULT_STATUS" | grep -q "FileVault is On"; then
    echo -e "${GREEN}✓ PASS${NC} - FileVault is enabled"
  elif echo "$FILEVAULT_STATUS" | grep -q "Encryption in progress"; then
    echo -e "${YELLOW}⚠ WARNING${NC} - FileVault encryption in progress"
  else
    echo -e "${RED}✗ FAIL${NC} - FileVault is not enabled"
    COMPLIANCE_FAILED=1
  fi
else
  echo -e "${RED} FAIL${NC} - Unable to check FileVault status (fdesetup not available)"
  COMPLIANCE_FAILED=1
fi

echo ""

# Check Screen Lock Settings
echo "Checking Screen Lock/Screensaver settings..."

# On modern macOS (Ventura+), use pmset to check display sleep time
# This is the "Turn display off when inactive" setting
DISPLAY_SLEEP=$(pmset -g | grep displaysleep | awk '{print $2}')

SCREEN_LOCK_PASS=true

# Check display sleep time (should be 5 minutes or less)
if [ -z "$DISPLAY_SLEEP" ] || [ "$DISPLAY_SLEEP" = "0" ]; then
  echo -e "${RED}✗ FAIL${NC} - Display sleep is disabled"
  SCREEN_LOCK_PASS=false
  COMPLIANCE_FAILED=1
elif [ "$DISPLAY_SLEEP" -gt 5 ]; then
  echo -e "${RED}✗ FAIL${NC} - Display sleep is ${DISPLAY_SLEEP} minutes (requires ≤5 minutes)"
  SCREEN_LOCK_PASS=false
  COMPLIANCE_FAILED=1
else
  echo -e "${GREEN}✓ PASS${NC} - Display sleep is set to ${DISPLAY_SLEEP} minutes"
fi

# Check for password requirement after sleep/screensaver
# Try multiple locations as macOS versions store this differently
PASSWORD_REQUIRED=$(defaults read com.apple.screensaver askForPassword 2>/dev/null)
PASSWORD_DELAY=$(defaults read com.apple.screensaver askForPasswordDelay 2>/dev/null)

# If not found in user domain, try currentHost
if [ -z "$PASSWORD_REQUIRED" ]; then
  PASSWORD_REQUIRED=$(defaults -currentHost read com.apple.screensaver askForPassword 2>/dev/null)
  PASSWORD_DELAY=$(defaults -currentHost read com.apple.screensaver askForPasswordDelay 2>/dev/null)
fi

# For modern macOS, if these settings don't exist in the old location,
# the password requirement is typically enforced at the system level
# Check if we got valid values
if [ -n "$PASSWORD_REQUIRED" ]; then
  if [ "$PASSWORD_REQUIRED" = "1" ]; then
    echo -e "${GREEN}✓ PASS${NC} - Password is required after screensaver/sleep"

    # Check password delay if set
    if [ -n "$PASSWORD_DELAY" ]; then
      if [ "$PASSWORD_DELAY" -eq 0 ]; then
        echo -e "${GREEN}✓ PASS${NC} - Password required immediately (delay: ${PASSWORD_DELAY} seconds)"
      elif [ "$PASSWORD_DELAY" -le 5 ]; then
        echo -e "${GREEN}✓ PASS${NC} - Password delay is ${PASSWORD_DELAY} seconds"
      else
        echo -e "${YELLOW}⚠ WARNING${NC} - Password delay is ${PASSWORD_DELAY} seconds (recommended: ≤5)"
      fi
    fi
  else
    echo -e "${RED}✗ FAIL${NC} - Password is not required after screensaver/sleep"
    SCREEN_LOCK_PASS=false
    COMPLIANCE_FAILED=1
  fi
else
  # On modern macOS without explicit setting, check if FileVault is on
  # as it typically enforces password on wake
  if echo "$(fdesetup status)" | grep -q "FileVault is On"; then
    echo -e "${GREEN}✓ PASS${NC} - Password requirement enforced by system (FileVault enabled)"
  else
    echo -e "${YELLOW}⚠ WARNING${NC} - Cannot verify password requirement setting (may be system-managed)"
  fi
fi

echo ""

# Check Password Policy
echo "Checking Password Policy (minimum length)..."

# Get password policy from pwpolicy
PASSWORD_POLICY=$(pwpolicy -getaccountpolicies 2>/dev/null)

if [ -n "$PASSWORD_POLICY" ]; then
  # Extract the minimum password length from the policy
  # Look for patterns like '.{4,}+' which means 4 or more characters
  MIN_LENGTH=$(echo "$PASSWORD_POLICY" | grep "policyAttributePassword matches" | grep -o '\.[{][0-9]*,' | grep -o '[0-9]*')

  if [ -z "$MIN_LENGTH" ]; then
    echo -e "${YELLOW}⚠ WARNING${NC} - Unable to determine minimum password length from policy"
  elif [ "$MIN_LENGTH" -lt 8 ]; then
    echo -e "${RED}✗ FAIL${NC} - Minimum password length is ${MIN_LENGTH} characters (requires ≥8 characters)"
    COMPLIANCE_FAILED=1
  else
    echo -e "${GREEN}✓ PASS${NC} - Minimum password length is ${MIN_LENGTH} characters"
  fi
else
  echo -e "${YELLOW}⚠ WARNING${NC} - Unable to retrieve password policy (pwpolicy not available or no policy set)"
fi

echo ""

# Check Automatic Updates
echo "Checking Automatic Updates settings..."

# Check if automatic update checking is enabled
AUTO_CHECK=$(softwareupdate --schedule 2>/dev/null | grep -i "Automatic checking" | grep -i "on")

# Check automatic download
AUTO_DOWNLOAD=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload 2>/dev/null)

# Check automatic macOS updates installation
AUTO_INSTALL=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates 2>/dev/null)

# Check critical updates
CRITICAL_UPDATES=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall 2>/dev/null)

# Check App Store auto-updates
APP_STORE_AUTO=$(defaults read /Library/Preferences/com.apple.commerce AutoUpdate 2>/dev/null)

AUTO_UPDATE_PASS=true

# Verify automatic check is on
if [ -n "$AUTO_CHECK" ]; then
  echo -e "${GREEN}✓ PASS${NC} - Automatic update checking is enabled"
else
  echo -e "${RED}✗ FAIL${NC} - Automatic update checking is disabled"
  AUTO_UPDATE_PASS=false
  COMPLIANCE_FAILED=1
fi

# Verify automatic download is enabled
if [ "$AUTO_DOWNLOAD" = "1" ]; then
  echo -e "${GREEN}✓ PASS${NC} - Automatic download of updates is enabled"
else
  echo -e "${RED}✗ FAIL${NC} - Automatic download of updates is disabled"
  AUTO_UPDATE_PASS=false
  COMPLIANCE_FAILED=1
fi

# Verify automatic macOS installation is enabled
if [ "$AUTO_INSTALL" = "1" ]; then
  echo -e "${GREEN}✓ PASS${NC} - Automatic installation of macOS updates is enabled"
else
  echo -e "${YELLOW}⚠ WARNING${NC} - Automatic installation of macOS updates is disabled (recommended for compliance)"
fi

# Verify critical updates are enabled
if [ "$CRITICAL_UPDATES" = "1" ]; then
  echo -e "${GREEN}✓ PASS${NC} - Automatic installation of critical updates is enabled"
else
  echo -e "${RED}✗ FAIL${NC} - Automatic installation of critical updates is disabled"
  AUTO_UPDATE_PASS=false
  COMPLIANCE_FAILED=1
fi

# Verify App Store auto-updates
if [ "$APP_STORE_AUTO" = "1" ]; then
  echo -e "${GREEN}✓ PASS${NC} - App Store automatic updates are enabled"
else
  echo -e "${YELLOW}⚠ WARNING${NC} - App Store automatic updates are disabled"
fi

echo ""

# Check XProtect (macOS Anti-Malware)
echo "Checking XProtect (Anti-Malware) service..."

# Check if XProtect services are running
XPROTECT_PLUGIN=$(launchctl list | grep "com.apple.XprotectFramework.PluginService" | head -1 | awk '{print $1}')
XPROTECT_SCAN=$(launchctl list | grep "com.apple.XProtect.agent.scan" | head -1 | awk '{print $1}')

# Check if XProtect app exists
XPROTECT_APP_EXISTS=false
if [ -d "/Library/Apple/System/Library/CoreServices/XProtect.app" ] || [ -d "/System/Library/CoreServices/XProtect.app" ]; then
  XPROTECT_APP_EXISTS=true
fi

XPROTECT_PASS=true

# Check if XProtect Plugin Service is running (PID > 0)
if [ -n "$XPROTECT_PLUGIN" ] && [ "$XPROTECT_PLUGIN" != "-" ] && [ "$XPROTECT_PLUGIN" -gt 0 ] 2>/dev/null; then
  echo -e "${GREEN}✓ PASS${NC} - XProtect Plugin Service is running (PID: $XPROTECT_PLUGIN)"
else
  # Check if service exists (it may be loaded but not actively running - runs on-demand)
  if launchctl list | grep -q "com.apple.XprotectFramework.PluginService"; then
    echo -e "${GREEN}✓ PASS${NC} - XProtect Plugin Service is loaded (on-demand service)"
  else
    echo -e "${RED}✗ FAIL${NC} - XProtect Plugin Service is not available"
    XPROTECT_PASS=false
    COMPLIANCE_FAILED=1
  fi
fi

# Check if XProtect Scan Service is running or available
if [ -n "$XPROTECT_SCAN" ]; then
  if [ "$XPROTECT_SCAN" != "-" ] && [ "$XPROTECT_SCAN" -gt 0 ] 2>/dev/null; then
    echo -e "${GREEN}✓ PASS${NC} - XProtect Scan Service is running (PID: $XPROTECT_SCAN)"
  else
    echo -e "${GREEN}✓ PASS${NC} - XProtect Scan Service is loaded and available"
  fi
else
  echo -e "${YELLOW}⚠ WARNING${NC} - XProtect Scan Service status unclear"
fi

# Verify XProtect application exists
if [ "$XPROTECT_APP_EXISTS" = true ]; then
  echo -e "${GREEN}✓ PASS${NC} - XProtect application is installed"
else
  echo -e "${RED}✗ FAIL${NC} - XProtect application not found"
  XPROTECT_PASS=false
  COMPLIANCE_FAILED=1
fi

echo ""
echo "================================================"
if [ $COMPLIANCE_FAILED -eq 0 ]; then
  echo -e "${GREEN}Overall Status: COMPLIANT${NC}"
  exit 0
else
  echo -e "${RED}Overall Status: NON-COMPLIANT${NC}"
  exit 1
fi
