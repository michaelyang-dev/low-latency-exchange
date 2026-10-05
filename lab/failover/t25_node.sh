#!/usr/bin/env bash
# One data node of a T25 failover trial, on its host (METHODOLOGY §17; plan 10 §7).
# bench/failover/run_trials.py --lab runs it on hosts A and B over ssh (or locally, in a
# network namespace, for the VM dry run), with the node's exchanged configuration that
# exchange_failover_trial --render-config wrote and the runner deployed.
#
#   t25_node.sh --state DIR --build DIR --conf FILE [--netns NS] [--nics "IF ..."]
#               [--nics-restore CMD] [--emulate-host-faults] COMMAND
# COMMAND:
#   start [--fresh]        start exchanged in the background (--fresh: empty data directory,
#                          a new day); its pid goes to DIR/pid, its exit status to
#                          DIR/exit_code (128 + N: killed by signal N), its output to DIR/node.out
#   signal SIG             kill -SIG the node (KILL, STOP, CONT)
#   exit-code              the exit status once the node ended, else "running"
#   output                 the node's output since the last --fresh start
#   pack-journal           the day's journal directory as a tar stream on stdout
#   pack-nlog              the node's nlog file on stdout
#   nics down|up           every data NIC (--nics) down or up (F3); run over the
#                          management network. Taking a NIC down drops its static routes:
#                          after "up", --nics-restore (a shell line) puts them back
#   panic                  kernel panic (sysrq 'c'; the host reboots with panic=5) (F4)
#   kill-during-snapshot   wait (60 s at most) for snapshotd's .snap.tmp, then SIGKILL the
#                          node; prints "caught" or "timeout" (F9)
#   snapshotd start|stop   snapshotd --follow on the node's journal (F9)
# --emulate-host-faults (the VM dry run): panic is a SIGKILL of the node.
set -uo pipefail
state="" build="" conf="" netns="" nics="" restore="" emulate=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --state) state=$2; shift 2 ;;
    --build) build=$2; shift 2 ;;
    --conf) conf=$2; shift 2 ;;
    --netns) netns=$2; shift 2 ;;
    --nics) nics=$2; shift 2 ;;
    --nics-restore) restore=$2; shift 2 ;;
    --emulate-host-faults) emulate=1; shift ;;
    *) break ;;
  esac
done
cmd=${1:?usage: t25_node.sh --state DIR --build DIR --conf FILE [--netns NS] [--nics "IF ..."] COMMAND}
shift
[[ -n "$state" && -n "$conf" ]] || { echo "t25_node.sh: --state and --conf are required" >&2; exit 64; }
mkdir -p "$state"

# [node] data_dir and name, [day] date from the configuration.
conf_value() {  # section key
  awk -v s="[$1]" -v k="$2" '
    /^[ \t]*\[/ { sec = $0; gsub(/[ \t]/, "", sec); next }
    sec == s { line = $0; sub(/#.*/, "", line); n = index(line, "=");
               if (n > 0) { key = substr(line, 1, n - 1); gsub(/[ \t]/, "", key);
                            if (key == k) { v = substr(line, n + 1); gsub(/^[ \t]+|[ \t]+$/, "", v); print v; exit } } }' "$conf"
}
data=$(conf_value node data_dir)
name=$(conf_value node name)
day=$(conf_value day date)
pid() { cat "$state/pid" 2>/dev/null; }
in_ns() { if [[ -n "$netns" ]]; then ip netns exec "$netns" "$@"; else "$@"; fi; }

case "$cmd" in
  start)
    [[ -n "$build" ]] || { echo "t25_node.sh: --build is required" >&2; exit 64; }
    exe="$build/apps/exchanged/exchanged"
    [[ -x "$exe" ]] || { echo "t25_node.sh: no $exe" >&2; exit 2; }
    if [[ "${1:-}" == "--fresh" ]]; then
      [[ -n "$data" && "$data" != "/" ]] || { echo "t25_node.sh: no data_dir in $conf" >&2; exit 2; }
      if [[ -e "$state/pid" ]] && kill -0 "$(pid)" 2>/dev/null; then kill -KILL "$(pid)"; fi
      # A node of an earlier trial whose state is gone, and its snapshotd.
      pkill -KILL -f -- "exchanged --config $conf" 2>/dev/null
      pkill -KILL -f -- "snapshotd --journal $data/" 2>/dev/null
      sleep 0.2
      rm -rf "$data"
      : > "$state/node.out"
    fi
    rm -f "$state/pid" "$state/exit_code"
    # The wrapper records the node's pid and, when it ends, its exit status.
    nohup setsid bash -c '
      st="$1"; ns="$2"; shift 2
      if [[ -n "$ns" ]]; then ip netns exec "$ns" "$@" >> "$st/node.out" 2>&1 & else "$@" >> "$st/node.out" 2>&1 & fi
      echo $! > "$st/pid"
      wait $!
      echo $? > "$st/exit_code"' _ "$state" "$netns" "$exe" --config "$conf" > /dev/null 2>&1 < /dev/null &
    for _ in $(seq 1 100); do [[ -s "$state/pid" ]] && exit 0; sleep 0.05; done
    echo "t25_node.sh: the node did not start" >&2
    exit 1
    ;;
  signal)
    p=$(pid)
    [[ -n "$p" ]] || { echo "t25_node.sh: no pid" >&2; exit 1; }
    kill "-${1:?signal}" "$p"
    ;;
  exit-code)
    if [[ -s "$state/exit_code" ]]; then cat "$state/exit_code"; else echo running; fi
    ;;
  output)
    cat "$state/node.out" 2>/dev/null
    ;;
  pack-journal)
    tar -C "$data/journal/$day" -cf - .
    ;;
  pack-nlog)
    cat "$data/logs/$name-$day.nlog"
    ;;
  nics)
    for nic in $nics; do in_ns ip link set dev "$nic" "${1:?down|up}" || exit 1; done
    if [[ "$1" == up && -n "$restore" ]]; then in_ns sh -c "$restore" || exit 1; fi
    ;;
  panic)
    if [[ $emulate -eq 1 ]]; then
      kill -KILL "$(pid)"
      echo "emulated: SIGKILL of the node (the VM has no host to crash)"
      exit 0
    fi
    echo 1 > /proc/sys/kernel/sysrq
    # Detached, so the ssh session that started it returns first.
    nohup setsid sh -c 'sleep 0.2; echo c > /proc/sysrq-trigger' > /dev/null 2>&1 < /dev/null &
    echo "panic in 0.2 s"
    ;;
  kill-during-snapshot)
    snaps="$data/snapshots/$day"
    end=$((SECONDS + 60))
    while [[ $SECONDS -lt $end ]]; do
      if compgen -G "$snaps/*.snap.tmp" > /dev/null; then
        kill -KILL "$(pid)"
        echo caught
        exit 0
      fi
    done
    kill -KILL "$(pid)"
    echo timeout
    ;;
  snapshotd)
    case "${1:?start|stop}" in
      start)
        [[ -n "$build" ]] || { echo "t25_node.sh: --build is required" >&2; exit 64; }
        mkdir -p "$data/snapshots/$day"
        nohup "$build/apps/snapshotd/snapshotd" --journal "$data/journal/$day" --snapshots "$data/snapshots/$day" \
          --day "$day" --follow --poll-ms 1 > "$state/snapshotd.out" 2>&1 < /dev/null &
        echo $! > "$state/snapshotd.pid"
        ;;
      stop)
        [[ -s "$state/snapshotd.pid" ]] && kill -TERM "$(cat "$state/snapshotd.pid")" 2>/dev/null
        rm -f "$state/snapshotd.pid"
        ;;
    esac
    ;;
  *)
    echo "t25_node.sh: unknown command $cmd" >&2
    exit 64
    ;;
esac
