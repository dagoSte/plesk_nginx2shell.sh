# plesk_nginx2shell.sh

Audit HTTP/2 exposure on Plesk for Linux. The script inspects the NGINX configuration and checks which HTTP version each tested HTTPS endpoint negotiates. It can also apply Plesk's server-wide HTTP/2 workaround and verify the result.

## Requirements

- Run on the Plesk for Linux server with NGINX installed and root or `sudo` access.
- Use Bash and a build of curl with `HTTP2` in the `Features:` line of `curl --version`.
- Verification with `--check` requires an active `nginx` systemd service. Changing the HTTP/2 setting requires an interactive terminal and support for the corresponding Plesk `http2_pref` command.
- Debian and Ubuntu package information comes from `dpkg-query` and the local APT cache. Other systems may show an unknown package version or a blank candidate.

## Download

```sh
curl -fL -o plesk_nginx2shell.sh \
  https://raw.githubusercontent.com/dagoSte/plesk_nginx2shell.sh/v6.3/plesk_nginx2shell.sh
less plesk_nginx2shell.sh
bash ./plesk_nginx2shell.sh --help
```

## Usage

### Check the workaround without changing server settings

```sh
sudo bash ./plesk_nginx2shell.sh --check --no-color
```

The check covers all domains returned by the Plesk domain inventory. It returns `PASS` when its configuration patterns find no HTTP/2 enable directives, the NGINX configuration passes validation, the service is active, and every tested endpoint responds over HTTP/1.1. It writes local reports.

### Scan one domain or all Plesk domains

```sh
sudo bash ./plesk_nginx2shell.sh --host example.org
sudo bash ./plesk_nginx2shell.sh --all --timeout 10
```

Either command may offer to **disable HTTP/2 for the whole server**, including when you select just one domain. Press Enter or answer `n` to leave the setting as it is. Answer `y` to apply the workaround. Plesk warns of a possible brief service interruption. Run `--check` afterward to verify the result across the domain inventory. [Plesk security advisory](https://support.plesk.com/hc/en-us/articles/45139407796119-Vulnerability-CVE-2026-123007-CVE-2026-123633-CVE-2026-123634-CVE-2026-121810-and-CVE-2026-113425-NGINX2Root-Remote-code-execution-in-NGINX-shipped-with-Plesk-for-Linux)

### Re-enable HTTP/2 after patching

Confirm that the applicable Plesk security update is installed before restoring HTTP/2. The command prompts for confirmation and enables HTTP/2 server-wide. Restore any custom directives you removed separately. [Plesk HTTP/2 configuration](https://support.plesk.com/hc/en-us/articles/12377341566615-How-to-enable-HTTP-2-support-for-Nginx-in-Plesk)

```sh
sudo bash ./plesk_nginx2shell.sh --all --revert
```

## Options

| Option | Behavior |
| --- | --- |
| `--host DOMAIN`, `-H DOMAIN` | Test one HTTPS hostname. |
| `--all` | Test the domains returned by `plesk bin domain --list`. |
| `--check` | Verify the workaround across all listed domains without changing NGINX settings. |
| `--revert` | Offer to re-enable HTTP/2 globally. Scans all listed domains by default. |
| `--timeout SECONDS` | Set the per-domain connection timeout to 1–99 seconds. Default is 5. The total curl request limit adds 3 seconds. |
| `--no-color` | Disable ANSI colors. |
| `--help`, `-h` | Print usage without root access. |

## Reports and exit status

Each run that starts an audit writes reports under `/root/nginx2shell-triage-YYYYMMDD-HHMMSS/`. Keep the directory private. The NGINX configuration snapshots can contain sensitive settings, and the reports identify hosted domains.

| File | Contents |
| --- | --- |
| `report.txt` | Console output, versions and results. |
| `domains-before.tsv` | Negotiated HTTP version and status code, or a curl error, for each tested hostname. |
| `domains-after.tsv` | Follow-up probes when the Plesk command completes successfully. |
| `nginx-config-PRIVATE.txt` and `nginx-config-after-PRIVATE.txt` | NGINX configuration snapshots. The second is collected after a confirmed change. |

For automation, use `--check`. Exit status `0` means the verification passed, `1` means it failed or was inconclusive, `2` indicates invalid arguments or missing prerequisites, and `3` indicates a configuration dump or domain inventory failure. Review the report after interactive runs because a regular scan can finish with status `0` even when applying the workaround fails. The restore mode also uses `4` when the restore command or terminal is unavailable, `5` when Plesk fails to restore HTTP/2, and `6` when the NGINX syntax check fails after restoration.

## Scope

- The HTTP/2 check covers one part of the [Plesk NGINX2Root mitigation](https://support.plesk.com/hc/en-us/articles/45139407796119-Vulnerability-CVE-2026-123007-CVE-2026-123633-CVE-2026-123634-CVE-2026-121810-and-CVE-2026-113425-NGINX2Root-Remote-code-execution-in-NGINX-shipped-with-Plesk-for-Linux). Check the advisory for patch status and the steps that apply to HTTP/3, custom directives, and other affected NGINX components.
- Each HTTPS probe follows DNS resolution from the Plesk server. A CDN or reverse proxy can answer in place of the origin. Check origin addresses, IPv4 and IPv6, and any aliases or subdomains omitted by the Plesk inventory separately. DNS, TLS and connection failures are inconclusive.
- Directive counts use line-based patterns for `http2 on;` and `listen ... http2`. Inspect custom templates and directives, especially inline or multi-line declarations. Use Plesk's package and security advisories to establish whether the installed build is patched. [NGINX security advisories](https://nginx.org/en/security_advisories.html)

Original script by Stefano ([@dagoSte](https://github.com/dagoSte)).
