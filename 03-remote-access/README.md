# 03-remote-access/ - remote-access, jump-host and cellular gateway logs

Platforms: `ICS-0013` (cellular and industrial remote-access gateways) and
the Windows jump hosts in the OT DMZ. Data sources: `ICS-DS-0012` (gateway
logs), `ICS-DS-0005` (remote-access logs). Detection pack: `ICS-PACK-0001`.
Hunts: `ICS-HUNT-0004`, `ICS-HUNT-0007`.

## Rules

| File | Log | Detects | Rests on |
|---|---|---|---|
| `gateway_dropbear_ssh_auth_succeeded.yml` | Gateway syslog (Dropbear) | Successful SSH login on a modem or gateway | AA26-097A; Dropbear source |
| `gateway_dropbear_ssh_auth_failed.yml` | Gateway syslog (Dropbear) | Failed SSH logins (bad password, nonexistent user, bad key signature) | AA26-097A; Dropbear source |
| `jump_host_break_glass_account_logon.yml` | Windows Security 4624 | Break-glass account logon on a jump host or remote-access server | NCSC-led secure connectivity principles |

## Deploying

- **Dropbear messages** are copied from the current Dropbear source
  (`src/svr-authpasswd.c`, `src/svr-authpubkey.c`, `src/svr-auth.c`).
  Gateway firmware may carry an older or vendor-patched build with different
  wording. Before trusting silence, confirm that one known login on the
  device produces a matching line at the syslog receiver. The rules use
  `product: linux` / `service: syslog`; scope them to the gateway hosts.
- **Forward first.** Gateway logs are small and volatile; Teltonika keeps
  system logs in RAM by default, presumed lost on reboot (ICS-0013). Only
  forwarded copies help in an incident. Do not reboot or reset a gateway to
  collect from it.
- **Break-glass rule needs editing.** Its account names are placeholders.
  Replace them with the site's break-glass accounts or the rule matches
  nothing.

## Not here, and why

- **Gateway web-UI logins and configuration changes** (Sierra Wireless
  AirLink OS, Teltonika RutOS, Moxa, Digi): the vendor message formats were
  not read verbatim this round, so no strings are guessed. ICS-HUNT-0007
  covers them as a configuration diff and a log review.
- **VPN concentrator and vendor remote-access platform logs**: no product
  documentation was read (ICS-DS-0005 gap).
- **Failed break-glass attempts (Windows 4625)**: the event's field reference
  was not read; the principle covers attempts, so add it once confirmed.
