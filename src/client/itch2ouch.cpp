#include "client/itch2ouch.h"

#include <zlib.h>

#include <cstdio>
#include <algorithm>
#include <cstring>

#include "common/endian.h"
#include "proto/itch50/binary_file.h"

namespace lle::client::i2o {

Converter::Converter(const ConvertConfig& cfg)
    : cfg_(cfg), urn_(std::size_t{cfg.sessions} + 1, 0), sym_(std::make_unique<Symbol8[]>(std::size_t{1} << 16)) {
  LLE_ASSERT(cfg.sessions >= 1);
  orders_.reserve(std::size_t{1} << 21);
}

std::size_t Converter::encode_enter(const OState& o, Qty qty, PxE4 px, ouch50::Side side, ouch50::TimeInForce tif,
                                    OrderRef cl) {
  ouch50::in::EnterOrder e;
  e.user_ref_num = o.urn;
  e.side = side;
  e.quantity = qty;
  e.symbol = sym_[o.locate];
  e.price = static_cast<std::uint64_t>(px);
  e.time_in_force = tif;
  e.display = ouch50::Display::Visible;
  e.capacity = ouch50::Capacity::Agency;
  e.inter_market_sweep_eligibility = ouch50::IsoEligibility::NotEligible;
  e.cross_type = ouch50::CrossType::Continuous;
  char id[24];
  const int k = std::snprintf(id, sizeof id, "%llu", static_cast<unsigned long long>(cl));
  e.cl_ord_id = Alpha<14>(std::string_view(id, static_cast<std::size_t>(k > 14 ? 14 : k)));
  return ouch50::encode(std::span<std::byte>(buf_), e);
}

// --- script writer ------------------------------------------------------------------------
namespace {

bool gz_write_all(gzFile f, const void* p, std::size_t n) {
  return n == 0 || gzwrite(f, p, static_cast<unsigned>(n)) == static_cast<int>(n);
}

bool gz_read_all(gzFile f, void* p, std::size_t n) {
  return n == 0 || gzread(f, p, static_cast<unsigned>(n)) == static_cast<int>(n);
}

}  // namespace

ScriptWriter::~ScriptWriter() {
  if (gz_ != nullptr) gzclose(static_cast<gzFile>(gz_));
}

bool ScriptWriter::open(const std::string& path, const ScriptHeader& h, std::string* err) {
  const bool gz = path.size() > 3 && path.compare(path.size() - 3, 3, ".gz") == 0;
  gzFile f = gzopen(path.c_str(), gz ? "wb6" : "wbT");
  if (f == nullptr) {
    if (err) *err = "cannot create " + path;
    return false;
  }
  gz_ = f;
  std::vector<std::byte> b(32 + h.symbols.size() * 16);
  std::memcpy(b.data(), kMagic.data(), kMagic.size());
  store_be32(b.data() + 8, kVersion);
  store_be32(b.data() + 12, h.date);
  store_be16(b.data() + 16, h.sessions);
  store_be16(b.data() + 18, h.flags);
  store_be32(b.data() + 20, static_cast<std::uint32_t>(h.symbols.size()));
  store_be64(b.data() + 24, h.source_messages);
  for (std::size_t i = 0; i < h.symbols.size(); ++i) {
    std::byte* s = b.data() + 32 + i * 16;
    h.symbols[i].symbol.to_wire(s);
    store_be32(s + 8, h.symbols[i].round_lot);
    store_be16(s + 12, h.symbols[i].locate);
    s[14] = static_cast<std::byte>(h.symbols[i].luld_tier);
    s[15] = static_cast<std::byte>(h.symbols[i].etp);
  }
  if (!gz_write_all(f, b.data(), b.size())) {
    if (err) *err = "write failed: " + path;
    return false;
  }
  return true;
}

bool ScriptWriter::write(Nanos t, std::uint16_t session, std::span<const std::byte> ouch) {
  std::byte hdr[12];
  store_be16(hdr, static_cast<std::uint16_t>(10 + ouch.size()));
  store_be64(hdr + 2, static_cast<std::uint64_t>(t));
  store_be16(hdr + 10, session);
  auto* f = static_cast<gzFile>(gz_);
  ++records_;
  return gz_write_all(f, hdr, sizeof hdr) && gz_write_all(f, ouch.data(), ouch.size());
}

bool ScriptWriter::close() {
  if (gz_ == nullptr) return false;
  const std::byte end[2] = {};
  auto* f = static_cast<gzFile>(gz_);
  const bool ok = gz_write_all(f, end, 2);
  const bool closed = gzclose(f) == Z_OK;
  gz_ = nullptr;
  return ok && closed;
}

// --- script reader ------------------------------------------------------------------------
ScriptReader::~ScriptReader() {
  if (gz_ != nullptr) gzclose(static_cast<gzFile>(gz_));
}

bool ScriptReader::open(const std::string& path, std::string* err) {
  gzFile f = gzopen(path.c_str(), "rb");
  if (f == nullptr) {
    if (err) *err = "cannot open " + path;
    return false;
  }
  gz_ = f;
  std::byte b[32];
  if (!gz_read_all(f, b, sizeof b) || std::memcmp(b, kMagic.data(), kMagic.size()) != 0) {
    if (err) *err = path + ": not an order-flow script (bad magic)";
    return false;
  }
  if (load_be32(b + 8) != kVersion) {
    if (err) *err = path + ": unsupported script version";
    return false;
  }
  h_.date = load_be32(b + 12);
  h_.sessions = load_be16(b + 16);
  h_.flags = load_be16(b + 18);
  const std::uint32_t n = load_be32(b + 20);
  h_.source_messages = load_be64(b + 24);
  if (h_.sessions == 0 || n > 65'536) {
    if (err) *err = path + ": bad header";
    return false;
  }
  h_.symbols.resize(n);
  for (std::uint32_t i = 0; i < n; ++i) {
    std::byte s[16];
    if (!gz_read_all(f, s, sizeof s)) {
      if (err) *err = path + ": truncated header";
      return false;
    }
    h_.symbols[i].symbol = Symbol8::from_wire(s);
    h_.symbols[i].round_lot = load_be32(s + 8);
    h_.symbols[i].locate = load_be16(s + 12);
    h_.symbols[i].luld_tier = static_cast<char>(s[14]);
    h_.symbols[i].etp = static_cast<char>(s[15]);
  }
  return true;
}

bool ScriptReader::next(ScriptRecord& r) {
  auto* f = static_cast<gzFile>(gz_);
  std::byte l[2];
  if (!gz_read_all(f, l, 2)) {
    err_ = "truncated script (no end marker)";
    return false;
  }
  const std::size_t len = load_be16(l);
  if (len == 0) return false;
  if (len < 11 || !gz_read_all(f, buf_.data(), len)) {
    err_ = "truncated or malformed record";
    return false;
  }
  r.t = static_cast<Nanos>(load_be64(buf_.data()));
  r.session = load_be16(buf_.data() + 8);
  r.ouch = std::span<const std::byte>(buf_.data() + 10, len - 10);
  return true;
}

bool scan_symbols(const std::string& itch_path, std::uint64_t max_messages, std::vector<SymbolInfo>& out,
                  std::string* err) {
  itch50::BinaryFileReader rd;
  if (auto r = rd.open(itch_path); !r) {
    if (err) *err = r.error();
    return false;
  }
  std::vector<bool> seen(65'536, false);
  for (std::uint64_t n = 0; max_messages == 0 || n < max_messages; ++n) {
    const itch50::Record r = rd.next();
    if (r.status != itch50::RecordStatus::Message) {
      if (r.status == itch50::RecordStatus::IoError || r.status == itch50::RecordStatus::Truncated) {
        if (err) *err = "read error: " + rd.error();
        return false;
      }
      break;
    }
    if (r.data.size() != itch50::StockDirectoryView::kLen || static_cast<char>(r.data[0]) != 'R') continue;
    const itch50::StockDirectoryView v(r.data.data());
    if (seen[v.stock_locate()]) continue;  // the duplicate R of the day
    seen[v.stock_locate()] = true;
    SymbolInfo s;
    s.symbol = v.stock();
    s.round_lot = v.round_lot_size() == 0 ? 100 : v.round_lot_size();
    s.locate = v.stock_locate();
    s.luld_tier = static_cast<char>(v.luld_tier());
    s.etp = static_cast<char>(v.etp_flag());
    out.push_back(s);
  }
  std::sort(out.begin(), out.end(), [](const SymbolInfo& a, const SymbolInfo& b) { return a.locate < b.locate; });
  return true;
}

}  // namespace lle::client::i2o
