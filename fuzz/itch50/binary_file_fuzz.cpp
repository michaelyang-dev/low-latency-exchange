// Fuzz target: BinaryFILE parsing over in-memory buffers, plus the streaming
// reader over the same bytes through a temporary file every 64th input.
// Properties: no crash; records exactly partition the input (prefixes + data
// + optional truncated tail == input size); the streaming reader yields the
// same records as the zero-copy view; every decodable record round-trips.
#include <unistd.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <span>
#include <string>
#include <vector>

#include "common/assert.h"
#include "common/endian.h"
#include "proto/itch50/binary_file.h"
#include "proto/itch50/itch50.h"
#include "proto/itch50/validator.h"

using namespace lle::itch50;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  const std::span<const std::byte> in(reinterpret_cast<const std::byte*>(data), size);
  BinaryFileView view(in);
  Validator val(true);
  std::array<std::byte, kMaxMsgLen> out{};
  std::size_t covered = 0, records = 0;
  std::vector<std::pair<RecordStatus, std::size_t>> seen;
  for (;;) {
    const Record r = view.next();
    if (r.status == RecordStatus::EndOfFile) break;
    LLE_ASSERT(r.status != RecordStatus::IoError);
    seen.emplace_back(r.status, r.data.size());
    if (r.status == RecordStatus::Truncated) {
      covered += r.data.size();
      LLE_ASSERT(view.next().status == RecordStatus::EndOfFile);
      break;
    }
    covered += 2 + r.data.size();
    ++records;
    if (r.status == RecordStatus::Message) {
      val.check(r.data);
      (void)visit(r.data, [&](auto v) {
        const std::size_t n = encode(out, v.to_struct());
        LLE_ASSERT(n == r.data.size() && std::memcmp(out.data(), r.data.data(), n) == 0);
      });
    }
  }
  LLE_ASSERT(covered == size, "records must partition the input");
  LLE_ASSERT(val.messages() <= records);

  // Streaming reader equivalence (file I/O is slow: sample every 64th input).
  static std::uint64_t calls = 0;
  if (++calls % 64 == 0 && size > 0) {
    static const std::string path =
        (std::filesystem::temp_directory_path() / ("lle_binary_file_fuzz_" + std::to_string(::getpid()) + ".bin"))
            .string();
    std::FILE* f = std::fopen(path.c_str(), "wb");
    if (f != nullptr) {
      std::fwrite(data, 1, size, f);
      std::fclose(f);
      BinaryFileReader reader;
      if (reader.open(path, BinaryFileReader::kMinBufferBytes)) {
        // A file that happens to start with the gzip magic is decompressed instead.
        if (!reader.compressed()) {
          for (const auto& [status, len] : seen) {
            const Record r = reader.next();
            LLE_ASSERT(r.status == status && r.data.size() == len, "reader and view disagree");
          }
          LLE_ASSERT(reader.next().status == RecordStatus::EndOfFile);
        } else {
          for (int i = 0; i < 1000 && reader.next().status <= RecordStatus::EndOfSession; ++i) {
          }
        }
      }
      std::remove(path.c_str());
    }
  }
  return 0;
}

// Seeds: short valid streams (every type once, zero-length end of session, a truncated tail).
extern "C" std::size_t lle_fuzz_seed(std::size_t index, std::uint8_t* buf, std::size_t cap) {
  if (index >= 3) return 0;
  std::vector<std::uint8_t> s;
  std::array<std::byte, kMaxMsgLen> raw{};
  for (char t : kMessageTypes) {
    const std::size_t len = kMsgLen[static_cast<unsigned char>(t)];
    for (std::size_t i = 0; i < len; ++i) raw[i] = static_cast<std::byte>(0x30 + i);
    raw[0] = static_cast<std::byte>(t);
    s.push_back(0);
    s.push_back(static_cast<std::uint8_t>(len));
    for (std::size_t i = 0; i < len; ++i) s.push_back(static_cast<std::uint8_t>(raw[i]));
  }
  if (index >= 1) {
    s.push_back(0);
    s.push_back(0);  // end of session
  }
  if (index == 2) {
    s.push_back(0);
    s.push_back(36);
    s.push_back('A');  // truncated record
  }
  if (s.size() > cap) return 0;
  std::memcpy(buf, s.data(), s.size());
  return s.size();
}
