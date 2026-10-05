// nlog_decode: offline decoder for nlog binary log files (11-logging-observability §1).
//
//   nlog_decode [options] FILE
//     --format text|jsonl     output format (default text)
//     --time wall|tsc|none    timestamp column (default wall: UTC from calibration records)
//     --level LEVEL           minimum level: debug, info, warn, error
//     --site N                only site ID N (repeatable)
//     --thread N              only thread ID N (repeatable)
//     --from NS / --to NS     wall-clock range [from, to) in ns since the UNIX epoch
//     --from-tsc N / --to-tsc N   counter range [from, to)
//     --full-paths            print source paths as recorded (default: basename)
//     --dict                  print the site dictionary and exit
//     --stats                 print file statistics to stderr
//     --no-crc                skip CRC checks (debugging damaged files)
//
// Exit status: 0 decoded (a truncated/corrupt tail is reported on stderr),
// 1 usage or I/O error, 2 not an nlog file / unsupported version.
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <charconv>
#include <cstdio>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <string_view>

#include "log/decoder.h"
#include "log/level.h"

namespace {

using namespace lle::nlog;

void usage() {
  std::fputs(
      "usage: nlog_decode [--format text|jsonl] [--time wall|tsc|none] [--level L] [--site N]...\n"
      "                   [--thread N]... [--from NS] [--to NS] [--from-tsc N] [--to-tsc N]\n"
      "                   [--full-paths] [--dict] [--stats] [--no-crc] FILE\n",
      stderr);
}

template <class T>
std::optional<T> parse_int(std::string_view s) {
  T v{};
  const auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
  if (ec != std::errc{} || p != s.data() + s.size()) return std::nullopt;
  return v;
}

class MappedFile {
 public:
  bool open(const char* path) {
    fd_ = ::open(path, O_RDONLY | O_CLOEXEC);
    if (fd_ < 0) return false;
    struct stat st {};
    if (::fstat(fd_, &st) != 0) return false;
    size_ = static_cast<std::size_t>(st.st_size);
    if (size_ == 0) return true;
    void* p = ::mmap(nullptr, size_, PROT_READ, MAP_PRIVATE, fd_, 0);
    if (p == MAP_FAILED) return false;
    data_ = static_cast<const std::byte*>(p);
    return true;
  }
  ~MappedFile() {
    if (data_ != nullptr) ::munmap(const_cast<std::byte*>(data_), size_);
    if (fd_ >= 0) ::close(fd_);
  }
  [[nodiscard]] std::span<const std::byte> bytes() const noexcept { return {data_, size_}; }

 private:
  int fd_ = -1;
  const std::byte* data_ = nullptr;
  std::size_t size_ = 0;
};

}  // namespace

int main(int argc, char** argv) {
  decode::RenderOptions ro;
  decode::ParseOptions po;
  bool dict = false;
  bool stats = false;
  const char* path = nullptr;
  for (int i = 1; i < argc; ++i) {
    const std::string_view a = argv[i];
    auto value = [&]() -> std::optional<std::string_view> {
      if (i + 1 >= argc) return std::nullopt;
      return std::string_view{argv[++i]};
    };
    bool ok = true;
    if (a == "--format") {
      const auto v = value();
      if (v == "text") {
        ro.format = decode::OutputFormat::kText;
      } else if (v == "jsonl") {
        ro.format = decode::OutputFormat::kJsonl;
      } else {
        ok = false;
      }
    } else if (a == "--time") {
      const auto v = value();
      if (v == "wall") {
        ro.time = decode::TimeMode::kWall;
      } else if (v == "tsc") {
        ro.time = decode::TimeMode::kTsc;
      } else if (v == "none") {
        ro.time = decode::TimeMode::kNone;
      } else {
        ok = false;
      }
    } else if (a == "--level") {
      const auto v = value();
      const auto l = v ? parse_level(*v) : std::nullopt;
      ok = l.has_value();
      if (ok) ro.filter.min_level = static_cast<std::uint8_t>(*l);
    } else if (a == "--site" || a == "--thread") {
      const auto v = value();
      const auto n = v ? parse_int<std::uint32_t>(*v) : std::nullopt;
      ok = n.has_value();
      if (ok) (a == "--site" ? ro.filter.sites : ro.filter.threads).push_back(*n);
    } else if (a == "--from" || a == "--to") {
      const auto v = value();
      const auto n = v ? parse_int<std::int64_t>(*v) : std::nullopt;
      ok = n.has_value();
      if (ok) (a == "--from" ? ro.filter.from_ns : ro.filter.to_ns) = *n;
    } else if (a == "--from-tsc" || a == "--to-tsc") {
      const auto v = value();
      const auto n = v ? parse_int<std::uint64_t>(*v) : std::nullopt;
      ok = n.has_value();
      if (ok) (a == "--from-tsc" ? ro.filter.from_tsc : ro.filter.to_tsc) = *n;
    } else if (a == "--full-paths") {
      ro.full_paths = true;
    } else if (a == "--dict") {
      dict = true;
    } else if (a == "--stats") {
      stats = true;
    } else if (a == "--no-crc") {
      po.verify_crc = false;
    } else if (a == "-h" || a == "--help") {
      usage();
      return 0;
    } else if (!a.empty() && a.front() != '-' && path == nullptr) {
      path = argv[i];
    } else {
      ok = false;
    }
    if (!ok) {
      std::fprintf(stderr, "nlog_decode: bad argument near '%s'\n", argv[i]);
      usage();
      return 1;
    }
  }
  if (path == nullptr) {
    usage();
    return 1;
  }
  MappedFile mf;
  if (!mf.open(path)) {
    std::fprintf(stderr, "nlog_decode: cannot read %s: %s\n", path, std::strerror(errno));
    return 1;
  }
  const decode::LogFile f = decode::LogFile::parse(mf.bytes(), po);
  const decode::ScanInfo& info = f.info();
  if (info.status == decode::Status::kBadHeader || info.status == decode::Status::kUnsupportedVersion) {
    std::fprintf(stderr, "nlog_decode: %s: %s\n", path, std::string(decode::status_name(info.status)).c_str());
    return 2;
  }
  if (dict) {
    const std::string d = decode::dictionary_text(f);
    std::fwrite(d.data(), 1, d.size(), stdout);
    return 0;
  }
  const decode::RenderStats rs =
      decode::render(f, ro, [](std::string_view line) { std::fwrite(line.data(), 1, line.size(), stdout); });
  std::fflush(stdout);
  if (stats) {
    const std::string d = decode::describe(f);
    std::fwrite(d.data(), 1, d.size(), stderr);
    std::fprintf(stderr, "  records decoded %zu printed %zu bad_extents %zu\n", rs.merge.records, rs.records_out,
                 rs.merge.bad_extents);
  }
  if (info.status != decode::Status::kOk || rs.merge.bad_extents != 0) {
    std::fprintf(stderr, "nlog_decode: warning: %s after %zu valid bytes (%zu bad extents); decoded what precedes it\n",
                 std::string(decode::status_name(info.status)).c_str(), info.valid_bytes, rs.merge.bad_extents);
  } else if (!info.clean_end) {
    std::fprintf(stderr, "nlog_decode: note: no END chunk (writer still running or crashed)\n");
  }
  return 0;
}
