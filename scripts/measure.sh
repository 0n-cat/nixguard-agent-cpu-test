#!/bin/bash
# Samples the agent's CPU every 5 seconds for MINUTES minutes, in three phases:
#   start    the agent has just started (inventory, configuration checks, and the first file scan
#            where the settings scan on start)
#   steady   the agent running in the background
#   rescan   the agent restarted with a full file scan forced, the heaviest moment it has
# A light workload runs throughout: a few files changed every 10 seconds in a watched folder, 5,000 files
# in a node_modules folder beside them, and a sudo call every 30 seconds (the agent watches sudo in the macOS log).
set -uo pipefail
MINUTES=${1:-300}
OUT=${2:-out}
mkdir -p "$OUT"
TOTAL=$((MINUTES * 60))
START_END=$((TOTAL / 4)); [ "$START_END" -lt 300 ] && START_END=300
RESCAN_AT=$((TOTAL / 2))
conf=/Library/Ossec/etc/ossec.conf

# Workload
mkdir -p /etc/nixguard-cputest/node_modules
for i in $(seq 1 5000); do echo "$i" > "/etc/nixguard-cputest/node_modules/f$i.js"; done
( while true; do
    for i in $(seq 1 20); do date +%s%N > "/etc/nixguard-cputest/changing-$i.txt"; done
    sleep 10
  done ) &
CHURN=$!
( while true; do sudo -n true; sleep 30; done ) &
SUDO=$!

echo "t,phase,pid,ppid,cputime,command" > "$OUT/samples.csv"
t0=$(date +%s)
phase=start
rescanned=no
while true; do
  now=$(date +%s); t=$((now - t0))
  [ "$t" -ge "$TOTAL" ] && break
  if [ "$t" -ge "$RESCAN_AT" ] && [ "$rescanned" = no ]; then
    perl -0pi -e 's|<scan_on_start>no</scan_on_start>|<scan_on_start>yes</scan_on_start>|g' "$conf"
    /Library/Ossec/bin/wazuh-control restart > "$OUT/restart-rescan.txt" 2>&1
    rescanned=yes; phase=rescan
  elif [ "$rescanned" = no ] && [ "$t" -ge "$START_END" ]; then
    phase=steady
  fi
  lc=$(pgrep -f wazuh-logcollector | tr '\n' ' ')
  ps -axo pid=,ppid=,time=,command= | awk -v t="$t" -v ph="$phase" -v lc=" $lc " '
    {
      cmd=""; for (i=4;i<=NF;i++) cmd=cmd (i>4?" ":"") $i
      gsub(/,/, ";", cmd)
      if (cmd ~ /\/Library\/Ossec/ || index(lc, " " $2 " ") > 0)
        printf "%s,%s,%s,%s,%s,%s\n", t, ph, $1, $2, $3, substr(cmd,1,120)
    }' >> "$OUT/samples.csv"
  sleep 5
done

kill "$CHURN" "$SUDO" 2>/dev/null
/Library/Ossec/bin/wazuh-control status > "$OUT/status-end.txt" 2>&1
cp /Library/Ossec/logs/ossec.log "$OUT/ossec.log"
grep -E "File integrity monitoring (real-time Whodata engine started|scan started|scan ended)|syscollector|sca|rootcheck|ERROR|CRITICAL" \
  /Library/Ossec/logs/ossec.log > "$OUT/key-log-lines.txt" || true
echo "rescan_at_seconds=$RESCAN_AT start_end_seconds=$START_END total_seconds=$TOTAL" > "$OUT/phases.txt"
