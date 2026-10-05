// Fuzzes utcp::Connection. The first byte picks a mode:
//
//  - single endpoint (mode even): one Connection (active or passive open) receives
//    fuzzer-built segments whose sequence/ack numbers are offsets around its own
//    state (so they hit every acceptability branch), raw fuzzer frames, timer jumps,
//    writes, reads, close and abort. After every step the internal invariants must
//    hold and every emitted frame must parse with valid checksums and lie inside the
//    sent sequence space.
//  - pair (mode odd): two Connections talk through a fuzzer-controlled channel that
//    drops, duplicates, reorders and delays frames. Whatever each side delivers must be
//    an exact prefix of what the other side wrote (byte-stream exactness).
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <vector>

#include "common/assert.h"
#include "net/utcp/connection.h"

namespace {

using namespace lle;
using namespace lle::net::utcp;

constexpr MacAddr kMacA{{2, 0, 0, 0, 0, 0xA}};
constexpr MacAddr kMacB{{2, 0, 0, 0, 0, 0xB}};
constexpr std::uint32_t kIpA = 0x0A000001;
constexpr std::uint32_t kIpB = 0x0A000002;

class Input {
 public:
  Input(const std::uint8_t* d, std::size_t n) : d_(d), n_(n) {}
  bool empty() const { return i_ >= n_; }
  std::uint8_t u8() { return i_ < n_ ? d_[i_++] : 0; }
  std::uint16_t u16() { return static_cast<std::uint16_t>(u8() | (u8() << 8)); }
  std::uint32_t u32() { return static_cast<std::uint32_t>(u16()) | (static_cast<std::uint32_t>(u16()) << 16); }
  std::span<const std::byte> bytes(std::size_t n) {
    n = std::min(n, n_ - std::min(i_, n_));
    const auto* p = reinterpret_cast<const std::byte*>(d_ + i_);
    i_ += n;
    return {p, n};
  }

 private:
  const std::uint8_t* d_;
  std::size_t n_;
  std::size_t i_ = 0;
};

ConnConfig config_from(Input& in) {
  ConnConfig c;
  c.mss = static_cast<std::uint16_t>(48 + in.u8() * 6);
  c.rx_buffer = 64u + in.u16() % 70000u;
  c.tx_buffer = 64u + in.u16() % 70000u;
  c.max_inflight = 48u + in.u16();
  c.min_rto = 1'000'000;
  c.initial_rto = 10'000'000;
  c.max_rto = 1'000'000'000;
  c.time_wait = 50'000'000;
  c.fin_wait2_timeout = 500'000'000;
  c.max_retransmits = static_cast<std::uint8_t>(1 + in.u8() % 8);
  c.max_syn_retransmits = static_cast<std::uint8_t>(1 + in.u8() % 4);
  c.dupack_threshold = static_cast<std::uint8_t>(in.u8() % 4);
  return c;
}

FlowAddr flow(bool a) {
  return a ? FlowAddr{kMacA, kMacB, kIpA, kIpB, 40000, 8080} : FlowAddr{kMacB, kMacA, kIpB, kIpA, 8080, 40000};
}

// Every frame utcp emits must be well formed and within the sequence space it has used.
void check_output(const Connection& c, std::span<const std::byte> f) {
  auto s = parse_tcp(f, LinkType::Ethernet, true);
  LLE_ASSERT(s.has_value(), "emitted frame does not parse");
  LLE_ASSERT(s->src_port == c.flow().local_port && s->dst_port == c.flow().remote_port, "emitted ports");
  LLE_ASSERT(s->payload.size() <= c.config().mss, "segment larger than MSS");
  if (!s->has(tcp_flag::kRst) && c.state() != State::Closed) {
    LLE_ASSERT(seq_le(s->seq + s->seg_len(), c.snd_max()), "segment beyond SND.MAX");
  }
}

void single(Input& in) {
  const bool active = (in.u8() & 1) != 0;
  Connection c(config_from(in));
  Nanos now = 0;
  std::array<std::byte, 70000> out{};
  std::uint32_t peer_seq = in.u32();
  if (active) {
    (void)c.connect(flow(true), in.u32(), now);
  } else {
    TcpSegment syn;
    syn.src_ip = kIpB;
    syn.dst_ip = kIpA;
    syn.src_port = 8080;
    syn.dst_port = 40000;
    syn.seq = peer_seq;
    syn.window = in.u16();
    syn.mss = in.u16();
    syn.flags = tcp_flag::kSyn;
    (void)c.accept(flow(true), syn, in.u32(), now);
  }
  for (int steps = 0; steps < 400 && !in.empty(); ++steps) {
    switch (in.u8() % 9) {
      case 0:
      case 1: {  // a segment with numbers near our state
        TcpHeaderSpec h;
        h.src_mac = kMacB;
        h.dst_mac = kMacA;
        h.src_ip = kIpB;
        h.dst_ip = kIpA;
        h.src_port = 8080;
        h.dst_port = 40000;
        const auto sdelta = static_cast<std::int16_t>(in.u16());
        const auto adelta = static_cast<std::int16_t>(in.u16());
        const bool from_irs = (in.u8() & 1) != 0;
        h.seq = (from_irs ? peer_seq : c.rcv_nxt()) + static_cast<std::uint32_t>(sdelta);
        h.ack = c.snd_una() + static_cast<std::uint32_t>(adelta);
        h.flags = static_cast<std::uint8_t>(in.u8() & 0x3F);
        h.window = in.u16();
        h.mss_option = (in.u8() & 7) == 0 ? in.u16() : std::uint16_t{0};
        const std::size_t plen = in.u8() * 8u;
        static std::array<std::byte, 2048> payload{};
        const std::size_t n = build_tcp(out, LinkType::Ethernet, h, std::span(payload).first(plen), {}, false);
        (void)c.on_segment(std::span<const std::byte>(out.data(), n), now);
        break;
      }
      case 2: {  // raw bytes as a frame
        const auto b = in.bytes(in.u8());
        (void)c.on_segment(b, now);
        break;
      }
      case 3:
        now += static_cast<Nanos>(in.u16()) * 100'000;
        (void)c.on_timer(now);
        break;
      case 4: {
        static std::array<std::byte, 8192> w{};
        (void)c.send(std::span(w).first(in.u16() % w.size()), now);
        break;
      }
      case 5: (void)c.consume(in.u16(), now); break;
      case 6: (void)c.close(now); break;
      case 7:
        if ((in.u8() & 15) == 0) (void)c.abort(now);
        break;
      default:
        break;
    }
    for (int k = 0; k < 256; ++k) {
      const std::size_t n = c.next_tx(out, now);
      if (n == 0) break;
      check_output(c, std::span<const std::byte>(out.data(), n));
    }
    LLE_ASSERT(c.invariants_ok(), "connection invariants");
  }
}

struct Frame {
  std::vector<std::byte> b;
  bool to_b;
};

void pair(Input& in) {
  Connection a(config_from(in));
  Connection b(config_from(in));
  Nanos now = 0;
  std::array<std::byte, 70000> out{};
  std::deque<Frame> wire;
  std::uint64_t a_written = 0, b_written = 0, a_read = 0, b_read = 0;
  auto pattern = [](bool from_a, std::uint64_t i) {
    return std::byte{static_cast<unsigned char>((i * 131 + (from_a ? 7 : 91)) >> 3)};
  };
  (void)a.connect(flow(true), in.u32(), now);
  bool b_open = false;
  auto drain = [&](Connection& c, bool from_a) {
    for (int k = 0; k < 512; ++k) {
      const std::size_t n = c.next_tx(out, now);
      if (n == 0) break;
      check_output(c, std::span<const std::byte>(out.data(), n));
      if (wire.size() < 4096) wire.push_back(Frame{std::vector<std::byte>(out.begin(), out.begin() + static_cast<std::ptrdiff_t>(n)), from_a});
    }
  };
  auto read_all = [&](Connection& c, bool from_a_stream, std::uint64_t& rd) {
    const ByteRing::Spans sp = c.readable();
    std::uint64_t i = rd;
    for (auto x : sp.first) LLE_ASSERT(x == pattern(from_a_stream, i++), "stream byte mismatch");
    for (auto x : sp.second) LLE_ASSERT(x == pattern(from_a_stream, i++), "stream byte mismatch");
    rd = i;
    (void)c.consume(sp.size(), now);
  };
  for (int steps = 0; steps < 2000 && !in.empty(); ++steps) {
    drain(a, true);
    if (b_open) drain(b, false);
    const std::uint8_t op = in.u8();
    switch (op % 8) {
      case 0:
      case 1:
      case 2: {  // deliver (or drop/duplicate) the frame at a fuzzer-chosen position
        if (wire.empty()) break;
        const std::size_t idx = in.u8() % std::min<std::size_t>(wire.size(), 8);
        Frame fr = wire[idx];
        const std::uint8_t fate = in.u8() % 16;
        if (fate != 0) wire.erase(wire.begin() + static_cast<std::ptrdiff_t>(idx));  // fate 0: duplicate
        if (fate == 1) break;                                                       // drop
        const std::span<const std::byte> f(fr.b.data(), fr.b.size());
        if (fr.to_b) {
          if (!b_open) {
            auto s = parse_tcp(f, LinkType::Ethernet, true);
            if (s && s->flags == tcp_flag::kSyn) {
              (void)b.accept(flow(false), *s, in.u32(), now);
              b_open = true;
            }
          } else {
            (void)b.on_segment(f, now);
          }
        } else {
          (void)a.on_segment(f, now);
        }
        break;
      }
      case 3:
        now += static_cast<Nanos>(in.u8()) * 1'000'000;
        (void)a.on_timer(now);
        if (b_open) (void)b.on_timer(now);
        break;
      case 4: {
        const std::size_t n = in.u16() % 6000;
        static std::vector<std::byte> w(6000);
        Connection& c = (op & 0x80) != 0 && b_open ? b : a;
        const bool from_a = &c == &a;
        std::uint64_t& wr = from_a ? a_written : b_written;
        for (std::size_t i = 0; i < n; ++i) w[i] = pattern(from_a, wr + i);
        wr += c.send(std::span(w).first(n), now).accepted;
        break;
      }
      case 5:
        read_all(a, false, a_read);
        if (b_open) read_all(b, true, b_read);
        break;
      case 6:
        if ((in.u8() & 7) == 0) (void)((op & 0x80) != 0 && b_open ? b : a).close(now);
        break;
      default:
        break;
    }
    LLE_ASSERT(a.invariants_ok() && b.invariants_ok(), "pair invariants");
    LLE_ASSERT(a_read <= b_written && b_read <= a_written, "delivered more than written");
  }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  Input in(data, size);
  if ((in.u8() & 1) == 0) {
    single(in);
  } else {
    pair(in);
  }
  return 0;
}

extern "C" std::size_t lle_fuzz_seed(std::size_t index, std::uint8_t* buf, std::size_t cap) {
  // Seeds: a single-endpoint session and a pair session with mostly in-order delivery.
  std::vector<std::uint8_t> s;
  if (index == 0) {
    s = {0, 1, 100, 0, 16, 0, 16, 0, 1, 3, 2, 3, 0, 0, 0, 1};
    for (int i = 0; i < 64; ++i) {
      const std::uint8_t ops[] = {0, 0, 0, 0, 0, 1, 0, 0x10, 0, 0, 0, 4, 64, 0, 5, 64, 0, 3, 10, 0};
      s.insert(s.end(), std::begin(ops), std::end(ops));
    }
  } else if (index == 1) {
    s = {1, 100, 0, 16, 0, 16, 0, 1, 3, 2, 3, 120, 0, 16, 0, 16, 0, 1, 3, 2, 3, 1, 2, 3, 4};
    for (int i = 0; i < 200; ++i) {
      const std::uint8_t ops[] = {0, 0, 5, 4, 200, 1, 1, 0, 7, 5, 3, 1, 0x84, 100, 0};
      s.insert(s.end(), std::begin(ops), std::end(ops));
    }
  } else {
    return 0;
  }
  if (s.size() > cap) s.resize(cap);
  std::memcpy(buf, s.data(), s.size());
  return s.size();
}
