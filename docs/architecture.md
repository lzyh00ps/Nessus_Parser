# Architecture

## Core entities

### Scan finding

A normalized record from a `.nessus` file:

- host
- port
- protocol
- plugin_id
- plugin_name
- severity
- plugin_output

### Playbook

A reusable validation definition for a finding or class of findings:

- match keys: `plugin_id`, optional title/family/service hints
- command template
- status rules
- reason mapping
- source references
- review metadata

### Validation run

A host-specific execution result:

- command executed
- stdout / stderr
- exit code
- derived status
- reason
- execution timestamp

## Status model

Recommended normalized statuses:

- `validated`
- `not_validated`
- `inconclusive`
- `host_down`
- `port_closed`
- `port_filtered`
- `auth_failed`
- `error`

## Plugin metadata strategy

Do not make the tool depend on live scraping of Tenable content.

Preferred sources, in order:

1. metadata exported from your scanner environment
2. plugin details parsed from scan files
3. analyst-curated plugin metadata files

## Near-term milestones

1. import `.nessus` scans into SQLite
2. define playbook format and CRUD commands
3. import plugin metadata from local file sources
4. execute validations with timeout and status mapping
5. generate grouped reports

