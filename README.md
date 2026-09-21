# ldapview

A keyboard-driven terminal LDAP browser and directory investigation client for SSH/TUI workflows,
in the spirit of Apache Directory Studio. It assists **manual** inspection: it is not an attack
framework, scanner, spraying or credential tool.

## Features

**Connections** — saved profiles (no secrets on disk), LDAP / StartTLS / LDAPS, anonymous, simple and SASL
(DIGEST-MD5, NTLM, EXTERNAL) binds, CA file + client certificate, per-profile read-only mode, connection test,
duplicate/edit/delete, referral targets opened as separate profiles (credentials are never forwarded).
TLS verification is **on by default**; skipping it is opt-in with a red warning. Passwords live in memory only.

**Browse** — lazy directory tree (`hasSubordinates` aware), go-to-DN, quick find, Root DSE, entry pane with
views for attributes · LDIF · raw bytes · relationships (outgoing + reverse membership) · schema check
(MUST/MAY ✓/✗) · security descriptor. Binary values: hex / base64 / save; `objectSid`, `objectGUID` decoded.

**Search** — base/one/sub, filter builder (AND/OR/NOT tree, auto-escaping, raw ↔ tree), presets (generic + AD),
history and bookmarks, attribute lists, size/time limits, deref, simple paged results with next/previous,
server-side sort when advertised, ManageDsaIT / Show Deleted / Show Recycled controls, partial results on limits,
client-side sort and filter of results, referral list, BER preview of the request, export to LDIF / JSON / CSV
(CSV is formula-injection safe).

**Modify** (always confirmed, never silent) — add entry (schema-driven required attributes, preview),
edit / add / delete values (schema syntax warnings), delete entry, rename / move (ModifyDN), LDIF import
(add / modify / delete / modrdn; stops at first error), `:readonly on` to block all writes.

**Also** — anonymous-bind probe and security summary (`:secinfo`), server detection with a confidence level
(`:server`), Who am I? and an extended-operations screen, DirSync/VLV request controls, referral *Follow*
(anonymous, read-only, never automatic), LDIF viewer/validator and an `$EDITOR`-based LDIF editor
(`:ldif edit`), recently-visited-entry cache (invalidated on every write), default bookmarks, spinner.

**Insight** — schema browser (classes, attributes, syntaxes, matching rules, inheritance), operation log,
raw protocol viewer (decoded BER tree per message, hex; passwords and secret attribute values masked and raw
bytes withheld for credential-bearing messages), TLS details, controls / extensions / SASL listings,
Who am I?, entry comparison, AD-aware annotations (userAccountControl, groupType, FILETIME, SID names,
functional levels), ACL/security-descriptor decoding, `:sid` / `:guid` lookups.

## Command line

    ldapview                                    interactive TUI
    ldapview connect <profile|ldap-url>         TUI, connected to a target (URL base/filter open the search form)
    ldapview search  <profile|ldap-url> [-filter F -base DN -scope sub -attrs a,b -format ldif|json|csv|txt]
    ldapview export  <profile|ldap-url> -o FILE   (.ldif .json .csv .txt, file mode 0600)
    ldapview ldif    <file.ldif> [-validate] [-format json|txt|ldif]   offline viewer / validator / converter

Targets are saved profile names or RFC 4516 URLs: `ldap://host[:port]/base?attrs?scope?filter`.
Passwords are **never** accepted as arguments (visible in the process list): use `LDAPVIEW_PASSWORD`,
`-password-file FILE`, or `-password-stdin`. Other flags: `-user DN -starttls -ca FILE -insecure -timeout N`.
`ldapview ldif -validate` exits 1 on errors, so it works in scripts and CI.

## Build

    go mod tidy
    make build && ./bin/ldapview
    make test

Go 1.22+. Config: `~/.config/ldapview/` — `connections.yaml`, `history.yaml`, `bookmarks.yaml` (all 0600).
History stores base/scope/filter text; clear it with `:clear history`.

## Keys

| key                 | action                                                                         |
| ------------------- | ------------------------------------------------------------------------------ |
| `j k h l`, enter    | move / collapse / expand + load entry                                          |
| `tab`               | switch tree ↔ entry pane                                                       |
| `v`                 | cycle entry view (attributes → LDIF → raw → relationships → schema → security) |
| `g` `/` `n` `N`     | go to DN · find in tree · next · previous                                      |
| `s`                 | search (base = selected node)                                                  |
| `a` `e` `d` `D` `m` | add · edit · delete value/entry · delete entry · rename/move                   |
| `c` `y` `Y` `x`     | copy DN · value · entry as LDIF · export entry                                 |
| `=`                 | mark entry; press again on another entry to diff                               |
| `R` `S` `L` `P`     | Root DSE · schema · operation log · protocol viewer                            |
| `A`                 | read security descriptor (AD)                                                  |
| `:`                 | command palette                                                                |
| `?` `q`             | help · back / disconnect                                                       |

Search form: `enter` run · `ctrl+f` builder · `ctrl+p` presets · `ctrl+h` history · `ctrl+b` bookmarks ·
`ctrl+k` save bookmark · `ctrl+e` BER preview.
Results: `enter` open · `i` details · `c y x` copy/export · `n p` pages · `o O` sort · `/` filter · `b` base · `a A` copy attribute · `x X` export page/all · `F` referrals.

Palette: `help goto search refresh rootdse info server secinfo tls sasl controls extops whoami schema ops proto filter
presets history bookmarks export import ldif readonly view add delete rename copy diff unmark sid guid reconnect clear quit`.

## Testing

    make test                       # unit tests (offline)
    LDAPVIEW_TEST_HOST=127.0.0.1 LDAPVIEW_TEST_PORT=389 make integration

Integration tests expect `dc=example,dc=com`, `cn=admin` / `secret`, `ou=People` (alice, bob), `ou=Groups`;
TLS tests expect LDAPS on :3636 and a CA at `/tmp/ldaptest/ca.crt`.
