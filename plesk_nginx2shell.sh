#!/usr/bin/env bash
# PLESK NGINX2SHELL SECURITY SCANNER - Stefano 0x640x610x670x6f
# https://github.com/dagoSte
# Plesk HTTP/2 exposure audit, per-domain ALPN check, optional GLOBAL workaround.
set -uo pipefail
umask 077
HOST=''; ALL=0; REVERT=0; CHECK=0; NO_COLOR=0; TIMEOUT=5
usage(){ cat <<EOF
╔════════════════════════════════════════════════════════════════════╗
║  PLESK NGINX2SHELL SECURITY SCANNER  - Stefano 0x640x610x670x6f    ║
║  https://github.com/dagoSte                                         ║
╚════════════════════════════════════════════════════════════════════╝

USAGE: sudo bash $(basename "$0") [OPTIONS]

OPTIONS:
  -h, --help          Show this help
  --host DOMAIN       Scan one domain
  --all               Scan all Plesk domains
  --revert            Offer to re-enable HTTP/2 globally (confirmation required)
  --check             Read-only post-mitigation check of all Plesk domains
  --no-color          Disable ANSI colors
  --timeout SECONDS   Per-domain connection timeout (1-99; default: 5)

EXAMPLES:
  sudo bash $(basename "$0") --all
  sudo bash $(basename "$0") --host example.org
  sudo bash $(basename "$0") --all --revert
  sudo bash $(basename "$0") --check

NOTE: The workaround disables HTTP/2 globally; it does not install a security patch.
EOF
}
while (($#)); do
 case "$1" in
  --all) ALL=1; shift;;
  --revert) REVERT=1; shift;;
  --check) CHECK=1; ALL=1; shift;;
  --host|-H) [[ $# -ge 2 ]] || { usage; exit 2; }; HOST="$2"; shift 2;;
  --no-color) NO_COLOR=1; shift;;
  --timeout) [[ $# -ge 2 && "$2" =~ ^[1-9][0-9]?$ ]] || { usage; exit 2; }; TIMEOUT="$2"; shift 2;;
  --help|-h) usage; exit 0;;
  *) usage; exit 2;;
 esac
done
(( ALL == 0 )) || [[ -z "$HOST" ]] || { echo 'Choose --all OR --host.'; exit 2; }
if ((CHECK && REVERT)); then echo "--check cannot be combined with --revert."; exit 2; fi
if ((REVERT)) && (( ! ALL )) && [[ -z "$HOST" ]]; then ALL=1; fi
[[ -z "$HOST" || "$HOST" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] || { echo 'Invalid hostname'; exit 2; }
[[ $EUID -eq 0 ]] || { echo 'Run as root (sudo).'; exit 2; }
command -v plesk >/dev/null && command -v nginx >/dev/null && command -v curl >/dev/null || { echo 'Required: plesk, nginx, curl'; exit 2; }
OUT="/root/nginx2shell-triage-$(date +%Y%m%d-%H%M%S)"; mkdir -p "$OUT"
if [[ -t 1 && $NO_COLOR -eq 0 && ${TERM:-dumb} != dumb ]]; then
 R=$'\033[1;31m'; Y=$'\033[1;33m'; G=$'\033[1;32m'; B=$'\033[1;36m'; Z=$'\033[0m'
else R=''; Y=''; G=''; B=''; Z=''; fi
exec 3>&1
exec > >(tee "$OUT/report.txt" >&3) 2>&1
banner(){
 printf '\n%s╔════════════════════════════════════════════════════════════════════╗%s\n' "$B" "$Z"
 printf '%s║  PLESK NGINX2SHELL SECURITY SCANNER  - Stefano 0x640x610x670x6f    ║%s\n' "$B" "$Z"
 printf '%s║  https://github.com/dagoSte                                         ║%s\n' "$B" "$Z"
 printf '%s╚════════════════════════════════════════════════════════════════════╝%s\n' "$B" "$Z"
}
section(){ printf '\n%s━━ %s ━━%s\n' "$B" "$1" "$Z"; }
item(){ printf '  %-26s %s\n' "$1" "$2"; }
warn(){ printf '%s[!] %s%s\n' "$Y" "$*" "$Z"; }
ok(){ printf '%s[+] %s%s\n' "$G" "$*" "$Z"; }
bad(){ printf '%s[!] %s%s\n' "$R" "$*" "$Z"; }
# Confirmation always reads /dev/tty, independent of domain scan and subprocess stdin.
# Probes actual public HTTPS DNS endpoint(s); does not guarantee every address or vhost path was checked.
probe(){
 local host="$1" result rc
 result=$(curl --noproxy '*' --http2 --connect-timeout "$TIMEOUT" --max-time "$((TIMEOUT+3))" -sS -o /dev/null -w '%{http_version} %{http_code}' "https://$host/" 2>/dev/null); rc=$?
 if ((rc)); then printf 'ERROR (curl %s)' "$rc"; else printf 'HTTP/%s status=%s' "${result%% *}" "${result#* }"; fi
}
get_domains(){
 # Domain names from Plesk, not a scan of arbitrary hosts.
 local raw
 if ! raw=$(plesk bin domain --list 2>"$OUT/domain-list-errors.txt"); then
  bad 'Cannot enumerate Plesk domains; aborting --all.'; exit 3
 fi
 printf '%s\n' "$raw" | sed 's/\r$//' | awk 'NF==1 && $1 ~ /^[[:alnum:]][[:alnum:].-]*[[:alnum:]]$/ {print $1}' | sort -u > "$OUT/domains.txt"
 [[ -s "$OUT/domains.txt" ]] || { bad 'No domains returned; aborting --all.'; exit 3; }
}
scan_domains(){
 local phase="$1" domain res total=0 h2=0 h1=0 err=0
 printf 'Domain\tResult\n' > "$OUT/domains-${phase}.tsv"
 while IFS= read -r domain; do
  [[ -n "$domain" ]] || continue
  res=$(probe "$domain")
  printf '%-47s %s\n' "$domain" "$res"
  printf '%s\t%s\n' "$domain" "$res" >> "$OUT/domains-${phase}.tsv"
  ((total+=1)); case "$res" in HTTP/2*) ((h2+=1));; HTTP/1.1*) ((h1+=1));; *) ((err+=1));; esac
 done < "$OUT/domains.txt"
 item 'Domain count' "$total"; item 'HTTP/2' "$h2"; item 'HTTP/1.1' "$h1"; item 'Errors / other' "$err"
 if ((h2)); then bad "$h2 domains negotiated HTTP/2"; fi
 if ((err)); then warn "$err domains could not be conclusively tested (DNS/TLS/network/proxy)."; fi
 return 0
}
banner
item 'Timestamp' "$(date -Is)"; item 'Plesk' "$(plesk version 2>/dev/null | head -1)"
item 'Mode' "$( ((CHECK)) && echo CHECK-ONLY || { ((REVERT)) && echo REVERT-HTTP2 || { ((ALL)) && echo ALL-PLESK-DOMAINS || echo SINGLE-HOST; }; } )"
item 'NGINX' "$(nginx -v 2>&1)"
item 'sw-nginx' "$(dpkg-query -W -f='${Version}' sw-nginx 2>/dev/null || echo unknown)"
item 'APT candidate (cached)' "$(apt-cache policy sw-nginx 2>/dev/null | awk '/Candidate:/ {print $2}')"
section '01 / CONFIGURATION'
if ! nginx -T > "$OUT/nginx-config-PRIVATE.txt" 2>"$OUT/nginx-test.txt"; then bad 'nginx -T failed; no changes will be made.'; exit 3; fi
chmod 600 "$OUT/nginx-config-PRIVATE.txt"
H2_ON=$(grep -Ec '^[[:space:]]*http2[[:space:]]+on[[:space:]]*;' "$OUT/nginx-config-PRIVATE.txt" || true)
H2_LISTEN=$(grep -Ec '^[[:space:]]*listen[[:space:]][^#;]*[[:space:]]http2([[:space:];]|$)' "$OUT/nginx-config-PRIVATE.txt" || true)
item 'http2 on' "$H2_ON"; item 'listen ... http2' "$H2_LISTEN"
warn 'HTTP/2 exposure does not prove CVE exploitability or absence of vendor backports.'
section '02 / DOMAIN INVENTORY AND LIVE ALPN'
if ((ALL)); then get_domains; else
 [[ -n "$HOST" ]] || { bad 'Specify --all or --host example.org'; exit 2; }
 printf '%s\n' "$HOST" > "$OUT/domains.txt"
fi
scan_domains before
if ((CHECK)); then
 section '03 / POST-MITIGATION CHECK (READ ONLY)'
 config_ok=1; domains_ok=1; service_ok=1
 if (( H2_ON == 0 && H2_LISTEN == 0 )); then
  ok 'No explicit HTTP/2 enable directives in loaded NGINX configuration.'
 else
  bad "HTTP/2 enable directives remain (http2 on: $H2_ON; listen http2: $H2_LISTEN)."
  config_ok=0
 fi
 if nginx -t > "$OUT/nginx-check.txt" 2>&1 && systemctl is-active --quiet nginx; then
  ok 'NGINX configuration valid and service active.'
 else
  bad 'NGINX syntax invalid or service not active; see nginx-check.txt.'
  service_ok=0
 fi
 count_h2=$(awk -F '\t' 'NR>1 && $2 ~ /^HTTP\/2([ .]|$)/ {n++} END {print n+0}' "$OUT/domains-before.tsv")
 count_other=$(awk -F '\t' 'NR>1 && $2 !~ /^HTTP\/1\.1 status=/ {n++} END {print n+0}' "$OUT/domains-before.tsv")
 if (( count_h2 == 0 && count_other == 0 )); then
  ok 'All enumerated domains negotiated HTTP/1.1 in this test.'
 else
  bad "Unconfirmed domains: $count_other (including HTTP/2: $count_h2)."
  domains_ok=0
 fi
 section '04 / FINAL RESULT'
 if (( config_ok && domains_ok && service_ok )); then
  ok 'PASS: HTTP/2 workaround verified for loaded config and tested domain endpoints.'
  warn 'Not proof of patched NGINX; aliases, DNS targets, IPv4/IPv6 and proxy paths may require separate checks.'
  result=0
 else
  bad 'NOT VERIFIED: mitigation incomplete or some checks inconclusive.'
  result=1
 fi
 item 'Report' "$OUT/report.txt"
 item 'Domain results' "$OUT/domains-before.tsv"
 item 'Private config' "$OUT/nginx-config-PRIVATE.txt (DO NOT SHARE)"
 exit "$result"
fi
if ((REVERT)); then
 section '03 / HTTP/2 RESTORE (GLOBAL)'
 warn 'This enables HTTP/2 GLOBALLY; it is NOT a security patch or an exact restore of previous per-domain settings.'
 warn 'If the CVE remains unpatched, restoring HTTP/2 may re-expose the server.'
 if ! plesk bin http2_pref --help </dev/null >"$OUT/http2_pref_help.txt" 2>&1 || ! grep -q -- '--enable' "$OUT/http2_pref_help.txt"; then
  bad 'Plesk http2_pref --enable not supported/verified. No changes made.'; exit 4
 fi
 ok 'Supported command: plesk bin http2_pref --enable'
 if [[ ! -r /dev/tty ]]; then bad 'Interactive terminal required; no changes made.'; exit 4; fi
 printf '\n%sRestore GLOBAL HTTP/2 now? [y/N]: %s' "$Y" "$Z"
 IFS= read -r confirm </dev/tty || confirm='' 
 case "$confirm" in
  y|Y|yes|YES|Yes)
   if ! plesk bin http2_pref --enable </dev/null; then bad 'Plesk restore failed.'; exit 5; fi
   ok 'Plesk HTTP/2 enable command completed.'
   if ! nginx -t; then bad 'NGINX configuration invalid; investigate immediately.'; exit 6; fi
   ok 'NGINX syntax valid.'
   section '04 / POST-RESTORE VERIFICATION'
   sleep 2
   scan_domains after
   if nginx -T > "$OUT/nginx-config-after-PRIVATE.txt" 2>"$OUT/nginx-test-after.txt"; then
    chmod 600 "$OUT/nginx-config-after-PRIVATE.txt"
    remaining=$(grep -Ec '^[[:space:]]*http2[[:space:]]+on[[:space:]]*;|^[[:space:]]*listen[[:space:]][^#;]*[[:space:]]http2([[:space:];]|$)' "$OUT/nginx-config-after-PRIVATE.txt" || true)
    item 'Enabled H2 directives' "$remaining"
   fi
   warn 'Check failed domains, aliases, subdomains, IPv4 and IPv6 separately.'
   ;;
  *) ok 'Restore cancelled; no changes made.';;
 esac
 section '05 / REPORT'
 item 'Report' "$OUT/report.txt"
 item 'Domain results' "$OUT/domains-before.tsv"
 item 'Private config' "$OUT/nginx-config-PRIVATE.txt (DO NOT SHARE)"
 exit 0
fi
section '03 / WORKAROUND'
if ! plesk bin http2_pref --help </dev/null >"$OUT/http2_pref_help.txt" 2>&1 || ! grep -q -- '--disable' "$OUT/http2_pref_help.txt"; then
 bad 'Plesk http2_pref --disable not verified. No changes made.'
else
 ok 'Supported Plesk workaround: plesk bin http2_pref --disable'
 warn 'GLOBAL change: HTTP/2 will be disabled for ALL hosted domains, even with --host.'
 warn 'This is NOT a patch to the NGINX binary. HTTP/1.1 remains available.'
 if [[ ! -r /dev/tty ]]; then
  warn 'No interactive terminal: skipped. Run in an interactive SSH session.'
 else
  printf '\n%sApply GLOBAL HTTP/2 workaround now? [y/N]: %s' "$Y" "$Z"
  IFS= read -r confirm </dev/tty || confirm='' 
  case "$confirm" in
   Y|y|YES|Yes|yes)
    if plesk bin http2_pref --disable </dev/null; then
     ok 'Plesk command completed.'
     if nginx -t; then ok 'NGINX syntax valid.'; else bad 'NGINX syntax check failed; investigate immediately.'; fi
     section '04 / POST-MITIGATION VERIFICATION'
     sleep 2
     scan_domains after
     if nginx -T > "$OUT/nginx-config-after-PRIVATE.txt" 2>"$OUT/nginx-test-after.txt"; then
      chmod 600 "$OUT/nginx-config-after-PRIVATE.txt"
      remaining=$(grep -Ec '^[[:space:]]*http2[[:space:]]+on[[:space:]]*;|^[[:space:]]*listen[[:space:]][^#;]*[[:space:]]http2([[:space:];]|$)' "$OUT/nginx-config-after-PRIVATE.txt" || true)
      item 'Remaining H2 directives' "$remaining"
      ((remaining==0)) && ok 'No explicit H2 enable directives in loaded config.' || bad 'Some HTTP/2 directives remain enabled.'
     else bad 'Unable to re-read NGINX configuration.'; fi
     warn 'Check any failed domains and each public IPv4/IPv6 endpoint separately.'
    else bad 'Plesk workaround command failed; mitigation NOT confirmed.'; fi
    ;;
   *) ok 'Skipped: no changes made.';;
  esac
 fi
fi
section '05 / REPORT'
item 'Report' "$OUT/report.txt"
item 'Domain results' "$OUT/domains-before.tsv"
item 'Private config' "$OUT/nginx-config-PRIVATE.txt (DO NOT SHARE)"
warn 'Do not treat HTTP/1.1 as proof of a patched binary; check Plesk security advisories.'
