# Validation Policy

This project uses non-exploit validation only.

## Outdated software or service

Use `nmap` for banner grabbing and version identification.

- no exploitation
- no proof-of-concept execution
- no CVE trigger attempts

Recommended pattern:

```bash
nmap -Pn -sV --version-light -p <port> <host>
```

For CVE findings tied to outdated software, the goal is to confirm the exposed product and version from the service banner or protocol fingerprint.

## TLS / SSL weak ciphers and certificate issues

Use `sslscan` or `testssl.sh`.

- weak ciphers: prefer `sslscan --show-ciphers`
- certificate details: prefer `sslscan --show-certificate`
- certificate weakness or policy checks: prefer `testssl.sh`

Examples:

```bash
sslscan --no-colour --show-ciphers <host>:<port>
sslscan --no-colour --show-certificate <host>:<port>
testssl.sh --quiet --warnings batch --color 0 --server-defaults <host>:<port>
```

## STARTTLS-enabled services

When the target is STARTTLS-capable, use tool-specific STARTTLS options instead of raw TLS.

Supported mappings in the current playbook engine include:

- FTP
- SMTP
- POP3
- IMAP
- LDAP
- XMPP
- XMPP server-to-server
- PostgreSQL

## Playbook rule

If a finding fits one of the categories above, the generated or curated playbook should follow these tool choices unless there is a strong reason to do otherwise.
