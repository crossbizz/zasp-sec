#!/bin/bash
set -eu
# The system LaunchAgents directory handles future logins. Load the watcher in
# the current employee session as well when MDM installs during the workday.
[[ "${3:-/}" == "/" ]] || exit 0
uid=$(/usr/bin/stat -f %u /dev/console)
[[ "$uid" =~ ^[1-9][0-9]*$ ]] || exit 0
domain="gui/$uid"
/bin/launchctl print "$domain" >/dev/null 2>&1 || exit 0
if /bin/launchctl print "$domain/ai.zasp.skill-inventory" >/dev/null 2>&1; then
  /bin/launchctl kickstart -k "$domain/ai.zasp.skill-inventory"
else
  /bin/launchctl bootstrap "$domain" /Library/LaunchAgents/ai.zasp.skill-inventory.plist
fi
