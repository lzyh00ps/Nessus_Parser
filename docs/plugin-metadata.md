# Plugin Metadata Import

The tool should support importing plugin metadata from files you already control.

## Recommended first format

Start with JSON arrays shaped like this:

```json
[
  {
    "plugin_id": 104743,
    "plugin_name": "TLS Version 1.0 Protocol Detection",
    "family": "General",
    "severity": "medium",
    "synopsis": "The remote service supports TLS 1.0.",
    "description": "Detailed plugin description here.",
    "solution": "Disable TLS 1.0 where possible."
  }
]
```

## Where to get it

Short-term options:

- export plugin data from internal tooling if you already have it
- build records from `.nessus` findings first, then enrich later
- maintain a curated JSON file for the plugins you validate most often

## Future importers

Likely useful next:

- Nessus-generated plugin export formats
- scanner-local files from an installed Nessus instance
- analyst-enriched metadata merged with scan-derived records

## NASL directory importer

You can also seed the plugin catalog directly from the Nessus plugins directory:

```bash
PYTHONPATH=src python -m nessus_parser.cli.main import-plugins-nasl /opt/nessus/lib/nessus/plugins
```

What it does:

- reads `*.nasl` files
- derives `plugin_id` from the filename or `script_id()`
- extracts basic fields such as name, family, synopsis, description, solution, and risk factor when present

Limits:

- NASL files are not a stable public export format, so field extraction is best-effort
- some metadata is richer in the scan output than in the NASL header
- importing hundreds of thousands of files will take noticeably longer than scan import
