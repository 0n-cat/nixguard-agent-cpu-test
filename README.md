# NixGuard agent: macOS CPU test

Measures how much CPU the NixGuard endpoint agent (Wazuh 4.7.4) uses on an Apple Silicon Mac, on GitHub's
hosted `macos-15` runners. Two runs go side by side:

- **nixguard**: installed with NixGuard's own install script, as a customer would install it
  ([`mac/agent-automatic-setup.sh`](https://github.com/thenexlabs/nixguard-agent-setup/blob/main/mac/agent-automatic-setup.sh)).
- **wazuh-default**: the same agent with Wazuh's default settings, for comparison.

Each run samples the agent's CPU every 5 seconds in three phases: just after install, steady in the
background, and after a restart that forces a full file scan. A light workload runs throughout.
The agents connect to a real Wazuh 4.7.4 manager that runs in the same workflow (the `manager` job), reached through a bore.pub tunnel. Agent traffic is encrypted (AES; TLS for enrollment).

Results are in each run's summary and in its `results-*` artifact (`summary.md`, `intervals.csv`,
`cpu.png`, the agent's `ossec.conf` and its log).

**Limits.** The runner is a virtual machine on an Apple M1 with 3 cores, not a physical MacBook, and it has
no user files, so the file scans cover less than a real laptop's.
