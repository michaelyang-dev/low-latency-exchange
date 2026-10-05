#!/usr/bin/env bash
# tshark interop check of MoldUDP64 pcaps written by apps/mold_pcap (T08, docs/verification/protocols.md).
# usage: tools/spec/mold_tshark_check.sh FILE.pcap...   (UDP port 26477; needs tshark)
set -uo pipefail
for f in "$@"; do
  echo "== $f"
  tshark -r "$f" -c 3 -d udp.port==26477,moldudp64 2>&1 | head -5
  echo "frames: $(tshark -r "$f" -d udp.port==26477,moldudp64 2>/dev/null | wc -l)"
  echo "malformed or expert >= warning: $(tshark -r "$f" -d udp.port==26477,moldudp64 -Y '_ws.malformed || _ws.expert.severity >= 4194304' 2>/dev/null | wc -l)"
  tshark -r "$f" -d udp.port==26477,moldudp64 -T fields -e moldudp64.sequence -e moldudp64.count 2>/dev/null |
    awk 'BEGIN{want=-1; gaps=0; msgs=0; eos=0; hb=0} {seq=$1; c=$2; if (c==65535) {eos++; next} if (c==0) {hb++; if (want>=0 && seq!=want) gaps++; next} if (want>=0 && seq!=want) gaps++; msgs+=c; want=seq+c} END{print "messages: " msgs ", heartbeats: " hb ", end-of-session: " eos ", sequence gaps: " gaps}'
done
