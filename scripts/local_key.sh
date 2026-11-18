#!/bin/bash
# Give the agent a key of its own and point it at the stand-in manager, so it starts its modules
# without enrolling anywhere. The key is random and only ever used on this runner.
set -euo pipefail
conf=/Library/Ossec/etc/ossec.conf
key=$(openssl rand -hex 32)
echo "001 ci-cpu-test any ${key}" > /Library/Ossec/etc/client.keys
chown root:wazuh /Library/Ossec/etc/client.keys
chmod 640 /Library/Ossec/etc/client.keys
perl -0pi -e 's|<address>[^<]*</address>|<address>127.0.0.1</address>|g' "$conf"
if grep -q '<enrollment>' "$conf"; then
  perl -0pi -e 's|<enrollment>.*?</enrollment>|<enrollment><enabled>no</enabled></enrollment>|s' "$conf"
else
  perl -0pi -e 's|<client>|<client>\n    <enrollment><enabled>no</enabled></enrollment>|' "$conf"
fi
