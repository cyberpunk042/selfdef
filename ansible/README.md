# Ansible playbooks

Deployment to your hosts. Populated in M3 once the .deb is produced.

Planned playbooks:
- `install.yml`           — install the .deb on a target, configure, enable.
- `update.yml`            — pull latest release, verify cosign signature, upgrade.
- `panic.yml`             — emergency: switch all hosts to panic config.
- `harvest.yml`           — pull cold archives back for incident analysis.
