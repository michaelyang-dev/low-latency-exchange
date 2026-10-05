#include "outlog/format.h"

#include <cstring>

#include "common/crc32c.h"
#include "common/endian.h"

namespace lle::outlog {

const char* to_string(Error e) noexcept {
  switch (e) {
    case Error::NotOpen:
      return "not open";
    case Error::EmptyMessage:
      return "empty message";
    case Error::MessageTooLarge:
      return "message longer than 65535 bytes";
    case Error::Io:
      return "I/O error";
    case Error::OutOfRange:
      return "sequence number out of range";
    case Error::ScratchTooSmall:
      return "scratch buffer too small";
    case Error::Corrupt:
      return "data changed underneath the reader";
    case Error::Locked:
      return "file is locked by a writer";
  }
  return "unknown error";
}

std::array<std::byte, kIndexHeaderBytes> encode_index_header() noexcept {
  std::array<std::byte, kIndexHeaderBytes> h{};
  std::memcpy(h.data(), kIndexMagic.data(), kIndexMagic.size());
  store_le32(h.data() + 8, kIndexVersion);
  store_le32(h.data() + 12, kIndexInterval);
  // [16, 28) reserved: already zero.
  store_le32(h.data() + kIndexCrcOffset, crc32c(h.data(), kIndexCrcOffset));
  return h;
}

bool index_header_valid(std::span<const std::byte> header) noexcept {
  if (header.size() < kIndexHeaderBytes) return false;
  const std::byte* p = header.data();
  return std::memcmp(p, kIndexMagic.data(), kIndexMagic.size()) == 0 && load_le32(p + 8) == kIndexVersion &&
         load_le32(p + 12) == kIndexInterval && load_le64(p + 16) == 0 && load_le32(p + 24) == 0 &&
         load_le32(p + kIndexCrcOffset) == crc32c(p, kIndexCrcOffset);
}

std::string index_path(const std::string& data_path) { return data_path + ".idx"; }

}  // namespace lle::outlog
