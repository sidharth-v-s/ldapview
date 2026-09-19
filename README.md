# ldapview

A keyboard-driven terminal LDAP browser and directory investigation client, built for SSH/TUI workflows. Inspired by Apache Directory Studio.

It assists **manual** enumeration and inspection. It is not an attack framework, scanner, or spraying tool.

## Status: MVP (v0.1)

- Connection manager (name, host, port, LDAP / StartTLS / LDAPS, anonymous / simple bind)
- TLS certificate verification **on by default**; custom CA file supported; skip-verify is opt-in with a warning
- Passwords are never written to disk and prompted per connect
- Root DSE inspection (naming contexts, controls, extensions, SASL mechs, features)
- Lazy directory tree (one-level searches, `hasSubordinates` aware)
- Entry viewer: user attributes first, operational attributes after; multi-valued attrs
- Binary attributes: hex / base64 view, save to file; `objectSid` / `objectGUID` decoded
- Search: base / one / sub scope, filter, attribute list, size/time limits, partial results on limit
- Friendly LDAP result-code errors
- Copy DN / value via OSC 52 (works over SSH in supporting terminals)

## Build

    make build && ./bin/ldapview
    make test

Requires Go 1.22+. Config lives at `~/.config/ldapview/connections.yaml` (no secrets).

## Keys

| key      | action                                     |
| -------- | ------------------------------------------ |
| j/k, h/l | move / collapse / expand                   |
| enter    | open entry (binary value: hex/base64 view) |
| tab      | switch pane                                |
| s or /   | search (base = selected node)              |
| r        | refresh node                               |
| c / y    | copy DN / value                            |
| R        | Root DSE                                   |
| ?        | help                                       |
| q        | back / disconnect                          |

## Testing

Unit tests run offline. Integration tests need a live server:

    LDAPVIEW_TEST_HOST=127.0.0.1 LDAPVIEW_TEST_PORT=389 make integration

They expect `dc=example,dc=com` with `cn=admin` / `secret`, `ou=People` (alice, bob) and `ou=Groups`.
TLS tests additionally expect LDAPS on :3636 and a CA at `/tmp/ldaptest/ca.crt`.

## Roadmap

0.2 add/modify/delete/ModifyDN, LDIF + JSON export, history, bookmarks, paging.
0.3 schema browser, filter builder, controls, referrals, operation log.
0.4 raw LDAP message + ASN.1/BER view, command palette.
0.5 AD-aware presentation, presets, relationship view.
