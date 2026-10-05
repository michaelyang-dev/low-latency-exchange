// mold_pcap: packetize an ITCH 5.0 BinaryFILE with our MoldUDP64 publisher core
// (proto/moldudp64/packetizer.h) and write the packets to a pcap, so external
// dissectors (Wireshark/tshark's MoldUDP64 and NASDAQ ITCH dissectors) can check
// them independently (target T08 interop, 03-protocols §9).
//
//   mold_pcap --in FILE --out OUT.pcap [--skip N] [--max-records N]
//             [--flush-every K] [--max-packet B] [--session NAME] [--port P]
//
// Packets carry Ethernet/IPv4/UDP headers (10.0.0.1 -> 239.1.1.1:P) and the
// ITCH timestamp of their last message (nanosecond pcap). The open packet is
// flushed every K messages (varying sizes and packing), heartbeats are emitted
// across gaps of more than one second, and the session ends with end-of-session
// packets. A summary line reports packets, messages and bytes.
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#include "common/endian.h"
#include "proto/itch50/binary_file.h"
#include "proto/moldudp64/packetizer.h"

namespace {

using namespace lle;

struct Args {
  std::string in, out, session = "LLE0000001";
  std::uint64_t skip = 0, max_records = 0;
  std::uint64_t flush_every = 7;
  std::size_t max_packet = 1400;
  std::uint16_t port = 26477;
};

class PcapWriter {
 public:
  explicit PcapWriter(std::FILE* f) : f_(f) {
    std::byte h[24]{};
    store_le32(h + 0, 0xA1B23C4Du);  // nanosecond-resolution pcap
    store_le16(h + 4, 2);
    store_le16(h + 6, 4);
    store_le32(h + 16, 65535);       // snaplen
    store_le32(h + 20, 1);           // LINKTYPE_ETHERNET
    put(h, sizeof h);
  }
  void packet(Nanos ts, std::span<const std::byte> udp_payload, std::uint16_t port) {
    const std::size_t udp_len = 8 + udp_payload.size();
    const std::size_t ip_len = 20 + udp_len;
    const std::size_t frame = 14 + ip_len;
    std::byte rec[16];
    store_le32(rec + 0, static_cast<std::uint32_t>(ts / kNsPerSec));
    store_le32(rec + 4, static_cast<std::uint32_t>(ts % kNsPerSec));
    store_le32(rec + 8, static_cast<std::uint32_t>(frame));
    store_le32(rec + 12, static_cast<std::uint32_t>(frame));
    put(rec, sizeof rec);
    std::byte hdr[42]{};
    // Ethernet: multicast MAC for 239.1.1.1, source 02:00:00:00:00:01, IPv4.
    const unsigned char dst_mac[6] = {0x01, 0x00, 0x5e, 0x01, 0x01, 0x01};
    const unsigned char src_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    std::memcpy(hdr, dst_mac, 6);
    std::memcpy(hdr + 6, src_mac, 6);
    store_be16(hdr + 12, 0x0800);
    std::byte* ip = hdr + 14;
    ip[0] = std::byte{0x45};
    store_be16(ip + 2, static_cast<std::uint16_t>(ip_len));
    store_be16(ip + 4, ip_id_++);
    ip[8] = std::byte{64};  // TTL
    ip[9] = std::byte{17};  // UDP
    store_be32(ip + 12, 0x0A000001);
    store_be32(ip + 16, 0xEF010101);
    std::uint32_t sum = 0;
    for (int i = 0; i < 20; i += 2) sum += load_be16(ip + i);
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    store_be16(ip + 10, static_cast<std::uint16_t>(~sum & 0xFFFF));
    std::byte* udp = ip + 20;
    store_be16(udp + 0, port);
    store_be16(udp + 2, port);
    store_be16(udp + 4, static_cast<std::uint16_t>(udp_len));
    // UDP checksum 0 (optional over IPv4).
    put(hdr, sizeof hdr);
    put(udp_payload.data(), udp_payload.size());
    ++packets_;
  }
  [[nodiscard]] std::uint64_t packets() const { return packets_; }
  [[nodiscard]] bool ok() const { return ok_; }

 private:
  void put(const void* p, std::size_t n) {
    if (std::fwrite(p, 1, n, f_) != n) ok_ = false;
  }
  std::FILE* f_;
  std::uint16_t ip_id_ = 1;
  std::uint64_t packets_ = 0;
  bool ok_ = true;
};

[[noreturn]] void usage(const char* m) {
  std::fprintf(stderr, "mold_pcap: %s\nusage: mold_pcap --in FILE --out OUT.pcap [--skip N] [--max-records N] "
                       "[--flush-every K] [--max-packet B] [--session NAME] [--port P]\n", m);
  std::exit(2);
}

}  // namespace

int main(int argc, char** argv) {
  Args a;
  for (int i = 1; i < argc; ++i) {
    const std::string_view k = argv[i];
    auto val = [&]() -> const char* {
      if (i + 1 >= argc) usage("missing value");
      return argv[++i];
    };
    if (k == "--in") a.in = val();
    else if (k == "--out") a.out = val();
    else if (k == "--skip") a.skip = std::strtoull(val(), nullptr, 10);
    else if (k == "--max-records") a.max_records = std::strtoull(val(), nullptr, 10);
    else if (k == "--flush-every") a.flush_every = std::strtoull(val(), nullptr, 10);
    else if (k == "--max-packet") a.max_packet = std::strtoull(val(), nullptr, 10);
    else if (k == "--session") a.session = val();
    else if (k == "--port") a.port = static_cast<std::uint16_t>(std::strtoul(val(), nullptr, 10));
    else usage("unknown option");
  }
  if (a.in.empty() || a.out.empty()) usage("--in and --out are required");
  if (a.flush_every == 0) a.flush_every = 1;

  itch50::BinaryFileReader rd;
  if (auto r = rd.open(a.in); !r) usage(r.error().c_str());
  std::FILE* f = std::fopen(a.out.c_str(), "wb");
  if (f == nullptr) usage("cannot open output");
  PcapWriter pcap(f);

  mold::PacketizerConfig cfg;
  cfg.session = mold::Session(a.session);
  cfg.max_packet = a.max_packet;
  cfg.heartbeat_interval = kNsPerSec;
  cfg.end_of_session_linger = 3 * kNsPerSec;
  mold::Packetizer pk(cfg);
  Nanos now = 0;
  auto emit = [&](std::span<const std::byte> p) { pcap.packet(now, p, a.port); };

  std::uint64_t seen = 0, used = 0;
  for (;;) {
    const itch50::Record rec = rd.next();
    if (rec.status != itch50::RecordStatus::Message) {
      if (rec.status == itch50::RecordStatus::EndOfSession) continue;
      break;
    }
    if (seen++ < a.skip) continue;
    if (a.max_records != 0 && used == a.max_records) break;
    const Nanos ts = static_cast<Nanos>(load_be48(rec.data.data() + 5));
    if (used == 0) now = ts;  // the clock starts at the first message, not at midnight
    if (ts > now) {
      // Let the publisher see time pass (heartbeats across idle gaps).
      while (now + kNsPerSec < ts) {
        now += kNsPerSec;
        pk.on_timer(now, emit);
      }
      now = ts;
    }
    pk.append(rec.data, now, emit);
    if (++used % a.flush_every == 0) pk.flush(now, emit);
  }
  pk.flush(now, emit);
  pk.end_session(now, emit);
  for (int i = 0; i < 3; ++i) {
    now += kNsPerSec;
    pk.on_timer(now, emit);
  }
  const bool ok = pcap.ok() && std::fclose(f) == 0;
  const auto& st = pk.stats();
  std::printf("mold_pcap: %" PRIu64 " messages in %" PRIu64 " data packets, %" PRIu64 " heartbeats, %" PRIu64
              " end-of-session packets, %" PRIu64 " pcap frames\n",
              st.messages, st.data_packets, st.heartbeats, st.end_of_session_packets, pcap.packets());
  return ok ? 0 : 1;
}
