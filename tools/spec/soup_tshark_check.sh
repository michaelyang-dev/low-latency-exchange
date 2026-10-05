#!/usr/bin/env bash
# tshark interop check of SoupBinTCP traffic captured from exchanged (T09,
# docs/verification/protocols.md). Dissects the given TCP ports as SoupBinTCP and
# counts malformed packets, the dissector's own SoupBinTCP warnings, and packets per
# SoupBinTCP type.
# Wireshark's heuristic payload dissectors on SoupBinTCP (ouch_soupbintcp, an older
# NASDAQ OUCH, and bist_ouch_soupbintcp, Borsa Istanbul's OUCH) are disabled: they
# claim OUCH 5.0 payloads they do not implement and would report them as malformed.
# Kernel TCP analysis notes on loopback (retransmissions, D-SACK) are listed for
# information only; they are not SoupBinTCP findings.
# usage: tools/spec/soup_tshark_check.sh FILE.pcapng PORT...   (needs tshark)
set -uo pipefail
f=$1; shift
d=(--disable-heuristic ouch_soupbintcp --disable-heuristic bist_ouch_soupbintcp)
for p in "$@"; do d+=(-d "tcp.port==$p,soupbintcp"); done
echo "== $f (SoupBinTCP on tcp ports $*)"
echo "soupbintcp packets: $(tshark -r "$f" "${d[@]}" -Y soupbintcp -T fields -e soupbintcp.packet_type 2>/dev/null | tr ',' '\n' | grep -c .)"
echo "malformed: $(tshark -r "$f" "${d[@]}" -Y '_ws.malformed' 2>/dev/null | wc -l | tr -d ' ')"
echo "soupbintcp warnings (invalid sequence numbers): $(tshark -r "$f" "${d[@]}" -Y 'soupbintcp.req_seq_num.invalid || soupbintcp.next_seq_num.invalid' 2>/dev/null | wc -l | tr -d ' ')"
echo "by type:"
tshark -r "$f" "${d[@]}" -Y soupbintcp -T fields -e soupbintcp.packet_type 2>/dev/null | tr ',' '\n' | grep . | sort | uniq -c
echo "tcp analysis notes (information only):"
tshark -r "$f" "${d[@]}" -Y 'tcp.analysis.flags' -T fields -e _ws.expert.message 2>/dev/null | tr ',' '\n' | sort | uniq -c | sort -rn | head -5
