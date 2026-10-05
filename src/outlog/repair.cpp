#include "outlog/repair.h"

namespace lle::outlog {

RepairResult repair(const std::string& path) {
  PosixFs fs;
  return repair(fs, path);
}

std::expected<void, Error> truncate_to(const std::string& path, SeqNo count) {
  PosixFs fs;
  return truncate_to(fs, path, count);
}

std::optional<SeqNo> first_difference(const std::string& a, const std::string& b) {
  PosixFs fs;
  return first_difference(fs, a, b);
}

}  // namespace lle::outlog
