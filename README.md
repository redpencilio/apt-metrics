# apt-metrics

A containerized daemon that exports pending Ubuntu security update metrics for
Prometheus via the node_exporter textfile collector.

It reads the **host's** apt state through bind mounts (no `apt-get update`
inside the container) and enriches security updates with CVE priority data from
the Ubuntu Security API.

The container needs read-only access to the host's apt/dpkg state and
reboot-required flag, and write access to the node_exporter textfile directory.


```yaml
    volumes:
      # Host apt/dpkg state (read-only)
      - /var/lib/apt:/var/lib/apt:ro
      - /var/lib/dpkg:/var/lib/dpkg:ro
      - /etc/apt:/etc/apt:ro
      # Reboot flag (read-only) — mount the parent dir to avoid Docker
      # creating a placeholder directory if the file doesn't exist yet
      - /var/run:/host/var/run:ro
```

## Metrics

| Metric                                         | Type  | Description                                                                                     |
|------------------------------------------------|-------|-------------------------------------------------------------------------------------------------|
| `node_security_updates_total`                  | gauge | All pending package upgrades                                                                    |
| `node_security_updates_security`               | gauge | Updates from the `-security` pocket                                                             |
| `node_security_updates_by_priority{priority}`  | gauge | Security updates by CVE priority (`critical`, `high`, `medium`, `low`, `negligible`, `unknown`) |
| `node_security_updates_reboot_required`        | gauge | `1` if `/var/run/reboot-required` exists on the host                                            |
| `node_security_updates_last_check`             | gauge | Unix timestamp of the last successful check                                                     |
| `node_security_updates_check_duration_seconds` | gauge | Time taken by the last check                                                                    |
