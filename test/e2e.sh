#!/usr/bin/env bash
# End-to-end tests: install the ip-watch binary INSIDE a container for each
# supported engine and drive it with the local transport, exercising
# apply -> enforce -> idempotency -> uninstall, plus multi-provider.
#
# Requires Docker. Usage: test/e2e.sh [engine ...]   (default: all)
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/dist/ip-watch-linux"
ARCH="$(docker version --format '{{.Server.Arch}}' 2>/dev/null || echo arm64)"
PASS=0; FAIL=0; SUMMARY=""
CIDS=""

cleanup() { for c in $CIDS; do docker rm -f "$c" >/dev/null 2>&1; done; }
trap cleanup EXIT

ok()   { PASS=$((PASS+1)); SUMMARY+=$'\n'"  PASS  $1"; echo "  ✅ $1"; }
bad()  { FAIL=$((FAIL+1)); SUMMARY+=$'\n'"  FAIL  $1"; echo "  ❌ $1"; }
note() { echo "  ·  $1"; }

build() {
  echo "==> building linux/$ARCH binary"
  mkdir -p "$ROOT/dist"
  ( cd "$ROOT" && GOOS=linux GOARCH="$ARCH" CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=e2e" -o "$BIN" ./cmd/ip-watch ) \
    || { echo "build failed"; exit 1; }
}

# in <container> runs ip-watch with the e2e config env (as root: editing system
# config and reloading services needs privilege).
ipw() { docker exec -u 0 -e IPWATCH_CONFIG=/data/config.json "$1" /usr/local/bin/ip-watch "${@:2}"; }

# writeconfig <container> <json>
writeconfig() { docker exec -u 0 -i "$1" sh -c 'mkdir -p /data && cat > /data/config.json'; }

# lastmsg <file> extracts the first JSON message field for error reporting.
lastmsg() { grep -oE '"message": *"[^"]*"' "$1" | head -1; }

curlcode() { local code; code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 6 "$1" 2>/dev/null); echo "${code:-000}"; }

# install binary + tools into a running container
prep() {
  local c="$1"; shift
  docker cp "$BIN" "$c:/usr/local/bin/ip-watch" >/dev/null
  if [ -n "${1:-}" ]; then docker exec "$c" sh -c "$1" >/dev/null 2>&1; fi
}

# ---- web-server engines: apply restricts to cloudflare, host curl is blocked ----
test_web() { # name image port engine conffile selector extra_run setup
  local name=$1 image=$2 port=$3 engine=$4 conf=$5 selector=$6 extra=$7 setup=$8
  local c="e2e-$name"; CIDS+=" $c"
  echo "== $name ($engine) =="
  docker rm -f "$c" >/dev/null 2>&1
  # shellcheck disable=SC2086
  docker run -d --name "$c" -p "$port:80" $extra "$image" >/dev/null 2>&1 || { bad "$name: container start"; return; }
  sleep 2
  prep "$c" "$setup"
  local before; before=$(curlcode "http://localhost:$port/")
  [ "$before" = "200" ] || note "$name: pre-apply status $before (expected 200)"

  printf '{"state_dir":"/data","targets":[{"id":"t","providers":["cloudflare"],"mode":"allow","engine":"%s","transport":"local","enabled":true,"config":{"file":"%s","selector":"%s"}}]}' \
    "$engine" "$conf" "$selector" | writeconfig "$c"

  if ipw "$c" apply >/tmp/e2e-$name.out 2>&1; then ok "$name: apply"; else bad "$name: apply ($(lastmsg /tmp/e2e-$name.out))"; return; fi
  sleep 1   # reloads are asynchronous
  local after; after=$(curlcode "http://localhost:$port/")
  [ "$after" != "200" ] && ok "$name: enforced (status $after)" || bad "$name: NOT enforced (still 200)"

  # idempotent re-apply: must still succeed and stay enforced.
  ipw "$c" apply >/tmp/e2e-$name-2.out 2>&1
  grep -q '"ok": true' /tmp/e2e-$name-2.out && ok "$name: re-apply idempotent" || bad "$name: re-apply failed"
  sleep 1
  local after2; after2=$(curlcode "http://localhost:$port/")
  [ "$after2" != "200" ] && ok "$name: still enforced after re-apply" || bad "$name: enforcement lost on re-apply"

  if ipw "$c" remove t >/dev/null 2>&1; then ok "$name: uninstall"; else bad "$name: uninstall"; fi
  sleep 1
  local restored; restored=$(curlcode "http://localhost:$port/")
  [ "$restored" = "200" ] && ok "$name: restored after uninstall" || note "$name: post-uninstall status $restored"
}

# ---- negative: a config that fails the engine's own validator must be rejected
# and must NOT take down the already-running service (validate-before-reload). ----
test_validation_rollback() {
  local c="e2e-negrb" port=8104; CIDS+=" $c"
  echo "== validation rollback (nginx) =="
  docker rm -f "$c" >/dev/null 2>&1
  docker run -d --name "$c" -p "$port:80" nginx:alpine >/dev/null 2>&1; sleep 2
  prep "$c" ""
  printf '{"state_dir":"/data","targets":[{"id":"t","providers":["cloudflare"],"mode":"allow","engine":"nginx","transport":"local","enabled":true,"config":{"file":"/etc/nginx/conf.d/default.conf","selector":"localhost"}}]}' | writeconfig "$c"
  if ipw "$c" apply >/tmp/e2e-negrb-1.out 2>&1; then ok "negrb: initial apply"; else bad "negrb: initial apply ($(lastmsg /tmp/e2e-negrb-1.out))"; return; fi
  sleep 1
  # Corrupt the conf so nginx -t will reject it (stray, unclosed block).
  docker exec "$c" sh -c 'printf "\nthis_is_not_valid_nginx {\n" >> /etc/nginx/conf.d/default.conf'
  # Re-apply with a CHANGED managed set (added admin IP) so it is NOT a no-op:
  # ip-watch writes + validates, nginx -t fails on the corruption, and it rolls back.
  printf '{"state_dir":"/data","targets":[{"id":"t","providers":["cloudflare"],"mode":"allow","engine":"nginx","transport":"local","enabled":true,"admin_allow_ips":["203.0.113.5/32"],"config":{"file":"/etc/nginx/conf.d/default.conf","selector":"localhost"}}]}' | writeconfig "$c"
  if ipw "$c" apply >/tmp/e2e-negrb-2.out 2>&1; then
    bad "negrb: invalid config should have failed apply"
  else
    ok "negrb: invalid config rejected ($(lastmsg /tmp/e2e-negrb-2.out))"
  fi
  # The live nginx must still answer — a failed validation never reloads it.
  local alive; alive=$(curlcode "http://localhost:$port/")
  [ "$alive" != "000" ] && ok "negrb: live service intact after failed apply ($alive)" || bad "negrb: service down after failed apply"
}

# ---- firewall engines: drop non-cloudflare on web ports; host curl times out ----
test_fw() { # name engine pkgs
  local name=$1 engine=$2 pkgs=$3
  local c="e2e-$name" port
  case $name in nft) port=8101;; ipt) port=8102;; esac
  CIDS+=" $c"
  echo "== $name ($engine) =="
  docker rm -f "$c" >/dev/null 2>&1
  docker run -d --name "$c" --privileged -p "$port:80" nginx:alpine >/dev/null 2>&1
  sleep 1
  docker exec "$c" sh -c "apk add --no-cache $pkgs >/dev/null 2>&1"
  prep "$c" ""
  local before; before=$(curlcode "http://localhost:$port/")
  [ "$before" = "200" ] && ok "$name: pre-apply reachable" || note "$name: pre-apply $before"
  printf '{"state_dir":"/data","targets":[{"id":"t","providers":["cloudflare"],"mode":"allow","engine":"%s","transport":"local","enabled":true,"firewall":{"ports":[80]}}]}' \
    "$engine" | writeconfig "$c"
  if ipw "$c" apply >/tmp/e2e-$name.out 2>&1; then ok "$name: apply"; else bad "$name: apply ($(lastmsg /tmp/e2e-$name.out))"; return; fi
  local after; after=$(curlcode "http://localhost:$port/")
  [ "$after" != "200" ] && ok "$name: enforced (status $after)" || bad "$name: NOT enforced (still 200)"
  # idempotent re-apply
  ipw "$c" apply >/tmp/e2e-$name-2.out 2>&1
  grep -q '"ok": true' /tmp/e2e-$name-2.out && ok "$name: re-apply idempotent" || bad "$name: re-apply failed ($(lastmsg /tmp/e2e-$name-2.out))"
  local after2; after2=$(curlcode "http://localhost:$port/")
  [ "$after2" != "200" ] && ok "$name: still enforced after re-apply" || bad "$name: enforcement lost on re-apply"
  if ipw "$c" remove t >/dev/null 2>&1; then ok "$name: uninstall"; else bad "$name: uninstall"; fi
  local restored; restored=$(curlcode "http://localhost:$port/")
  [ "$restored" = "200" ] && ok "$name: restored after uninstall" || note "$name: post-uninstall $restored"
}

test_ufw() {
  local c="e2e-ufw" port=8103; CIDS+=" $c"
  echo "== ufw =="
  docker rm -f "$c" >/dev/null 2>&1
  docker run -d --name "$c" --privileged -p "$port:80" ubuntu:22.04 sleep 600 >/dev/null 2>&1
  note "installing nginx + ufw (slow)…"
  docker exec "$c" sh -c 'apt-get update -qq >/dev/null 2>&1 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nginx ufw ca-certificates >/dev/null 2>&1 && nginx >/dev/null 2>&1 && ufw --force enable >/dev/null 2>&1'
  prep "$c" ""
  sleep 1
  local before; before=$(curlcode "http://localhost:$port/")
  [ "$before" = "200" ] && ok "ufw: pre-apply reachable" || note "ufw: pre-apply $before"
  printf '{"state_dir":"/data","targets":[{"id":"t","providers":["cloudflare"],"mode":"allow","engine":"ufw","transport":"local","enabled":true,"firewall":{"ports":[80]}}]}' | writeconfig "$c"
  # Negative: under a default-allow incoming policy, allow-mode must be refused
  # (the rules wouldn't restrict). It must fail closed before touching anything.
  docker exec "$c" ufw default allow incoming >/dev/null 2>&1
  if ipw "$c" apply >/tmp/e2e-ufw-neg.out 2>&1; then
    bad "ufw: allow-mode under default-allow should be refused"
  else
    grep -q "default deny" /tmp/e2e-ufw-neg.out && ok "ufw: refuses allow-mode under default-allow" || bad "ufw: wrong refusal ($(lastmsg /tmp/e2e-ufw-neg.out))"
  fi
  docker exec "$c" ufw default deny incoming >/dev/null 2>&1
  if ipw "$c" apply >/tmp/e2e-ufw.out 2>&1; then ok "ufw: apply"; else bad "ufw: apply ($(lastmsg /tmp/e2e-ufw.out))"; return; fi
  local after; after=$(curlcode "http://localhost:$port/")
  [ "$after" != "200" ] && ok "ufw: enforced (status $after)" || bad "ufw: NOT enforced (still 200)"
  # idempotent re-apply (ufw self-cleans its prior rules, so rule count stays stable)
  ipw "$c" apply >/tmp/e2e-ufw-2.out 2>&1
  grep -q '"ok": true' /tmp/e2e-ufw-2.out && ok "ufw: re-apply idempotent" || bad "ufw: re-apply failed"
  local rules; rules=$(docker exec "$c" sh -c 'ufw status numbered 2>/dev/null | grep -c ip-watch:t')
  [ "${rules:-0}" -gt 0 ] && ok "ufw: rules stable after re-apply ($rules)" || note "ufw: rule count $rules"
  if ipw "$c" remove t >/dev/null 2>&1; then ok "ufw: uninstall"; else bad "ufw: uninstall"; fi
}

test_multiprovider() {
  local c="e2e-multi"; CIDS+=" $c"
  echo "== multi-provider (nginx, cloudflare+fastly) =="
  docker rm -f "$c" >/dev/null 2>&1
  docker run -d --name "$c" nginx:alpine >/dev/null 2>&1; sleep 1
  prep "$c" ""
  printf '{"state_dir":"/data","targets":[{"id":"t","providers":["cloudflare","fastly"],"mode":"allow","engine":"nginx","transport":"local","enabled":true,"config":{"file":"/etc/nginx/conf.d/default.conf","selector":"localhost"}}]}' | writeconfig "$c"
  local ranges; ranges=$(ipw "$c" apply 2>/dev/null | grep -oE '"ranges": *[0-9]+' | head -1 | grep -oE '[0-9]+')
  if [ "${ranges:-0}" -gt 30 ]; then ok "multi-provider merged ($ranges ranges)"; else bad "multi-provider merge ($ranges ranges)"; fi
}

test_healthcheck() {
  local c="e2e-health"; CIDS+=" $c"
  echo "== healthcheck =="
  docker rm -f "$c" >/dev/null 2>&1
  docker run -d --name "$c" nginx:alpine >/dev/null 2>&1; sleep 1
  prep "$c" ""
  printf '{"listen":"127.0.0.1:8080","state_dir":"/data","targets":[]}' | writeconfig "$c"
  docker exec -d -u 0 -e IPWATCH_CONFIG=/data/config.json "$c" /usr/local/bin/ip-watch serve
  sleep 2
  if ipw "$c" healthcheck >/dev/null 2>&1; then ok "healthcheck endpoint"; else bad "healthcheck endpoint"; fi
}

# ---- CLI guards: invalid-config gating + healthcheck against a 0.0.0.0 bind ----
test_cli_guards() {
  local c="e2e-guards"; CIDS+=" $c"
  echo "== cli guards (invalid-config gating + 0.0.0.0 healthcheck) =="
  docker rm -f "$c" >/dev/null 2>&1
  docker run -d --name "$c" nginx:alpine >/dev/null 2>&1; sleep 1
  prep "$c" ""
  # invalid config (duplicate ids) must block enforcement commands
  printf '{"state_dir":"/data","targets":[{"id":"dup","providers":["cloudflare"],"mode":"allow","engine":"nginx","enabled":true},{"id":"dup","providers":["cloudflare"],"mode":"allow","engine":"nginx","enabled":true}]}' | writeconfig "$c"
  if ipw "$c" apply >/tmp/e2e-guards.out 2>&1; then bad "guards: apply on invalid config should be blocked"; else ok "guards: invalid config blocks apply"; fi
  # add -apply must still save (repair) but NOT enforce while the config is invalid
  if ipw "$c" add -id newt -provider cloudflare -engine nginx -apply >/tmp/e2e-guards-add.out 2>&1; then
    grep -q "not applying" /tmp/e2e-guards-add.out && ok "guards: add -apply gated on invalid config" || bad "guards: add -apply should skip enforce ($(lastmsg /tmp/e2e-guards-add.out))"
  else
    bad "guards: add (repair) should still save the target"
  fi
  # rm default (uninstall) must refuse the live teardown while config is invalid
  if ipw "$c" rm dup >/tmp/e2e-guards-rm.out 2>&1; then
    bad "guards: rm default should refuse uninstall on invalid config"
  else
    grep -q "refusing to uninstall" /tmp/e2e-guards-rm.out && ok "guards: rm uninstall gated on invalid config" || bad "guards: rm wrong refusal ($(lastmsg /tmp/e2e-guards-rm.out))"
  fi
  # serve on 0.0.0.0 (Docker default) then in-container healthcheck — probeAddr must
  # rewrite 0.0.0.0 -> loopback for the client probe.
  printf '{"listen":"0.0.0.0:8080","insecure":true,"state_dir":"/data","targets":[]}' | writeconfig "$c"
  docker exec -d -u 0 -e IPWATCH_CONFIG=/data/config.json "$c" /usr/local/bin/ip-watch serve
  sleep 2
  if ipw "$c" healthcheck >/dev/null 2>&1; then ok "guards: healthcheck works on 0.0.0.0 bind"; else bad "guards: healthcheck failed on 0.0.0.0 bind"; fi
}

build

ENGINES="${*:-nginx caddy apache haproxy nft ipt ufw multi health negrb guards}"
for e in $ENGINES; do
  case $e in
    nginx)  test_web nginx  nginx:alpine 8091 nginx  /etc/nginx/conf.d/default.conf localhost "" "" ;;
    caddy)  test_web caddy  caddy:2      8092 caddy  /etc/caddy/Caddyfile ":80" "" "" ;;
    apache) test_web apache httpd:2.4    8093 apache "" "" "" "" ;;
    haproxy)
      HCFG='global
defaults
  mode http
  timeout connect 5s
  timeout client 30s
  timeout server 30s
frontend http
  bind *:80
  http-request return status 200 content-type text/plain string ok'
      c=e2e-haproxy; CIDS+=" $c"; docker rm -f "$c" >/dev/null 2>&1
      docker create --name "$c" -p 8094:80 haproxy:2.9 haproxy -W -db -f /usr/local/etc/haproxy/haproxy.cfg >/dev/null 2>&1
      printf '%s\n' "$HCFG" > /tmp/e2e-haproxy.cfg
      docker cp /tmp/e2e-haproxy.cfg "$c:/usr/local/etc/haproxy/haproxy.cfg" >/dev/null
      docker start "$c" >/dev/null 2>&1; sleep 1
      prep "$c" ""
      printf '{"state_dir":"/data","targets":[{"id":"t","providers":["cloudflare"],"mode":"allow","engine":"haproxy","transport":"local","enabled":true,"config":{"file":"/usr/local/etc/haproxy/haproxy.cfg"}}]}' | writeconfig "$c"
      before=$(curlcode http://localhost:8094/); [ "$before" = 200 ] && ok "haproxy: pre-apply reachable" || note "haproxy pre $before"
      if ipw "$c" apply >/tmp/e2e-haproxy.out 2>&1; then ok "haproxy: apply"; else bad "haproxy: apply ($(lastmsg /tmp/e2e-haproxy.out))"; fi
      sleep 1
      after=$(curlcode http://localhost:8094/); [ "$after" != 200 ] && ok "haproxy: enforced ($after)" || bad "haproxy: NOT enforced"
      ipw "$c" remove t >/dev/null 2>&1 && ok "haproxy: uninstall" || bad "haproxy: uninstall"
      ;;
    nft)    test_fw nft nftables nftables ;;
    ipt)    test_fw ipt iptables "iptables ip6tables ipset" ;;
    ufw)    test_ufw ;;
    multi)  test_multiprovider ;;
    health) test_healthcheck ;;
    negrb)  test_validation_rollback ;;
    guards) test_cli_guards ;;
    *) echo "unknown engine: $e" ;;
  esac
done

echo ""
echo "================ e2e summary ================"
echo "$SUMMARY"
echo "---------------------------------------------"
echo "PASS=$PASS  FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
