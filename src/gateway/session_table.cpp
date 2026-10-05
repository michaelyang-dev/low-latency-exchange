#include "gateway/session_table.h"

#include <algorithm>

namespace lle::gw {

namespace {

// Username comparison without allocating: trim, then compare case-insensitively.
std::string_view trim(std::string_view s) noexcept {
  std::size_t b = 0, e = s.size();
  while (b < e && s[b] == ' ') ++b;
  while (e > b && s[e - 1] == ' ') --e;
  return s.substr(b, e - b);
}

char upper(char c) noexcept { return (c >= 'a' && c <= 'z') ? static_cast<char>(c - 'a' + 'A') : c; }

// <0, 0, >0 comparing a normalized name with a raw (unnormalized) one.
int compare_user(std::string_view norm, std::string_view raw) noexcept {
  raw = trim(raw);
  const std::size_t n = std::min(norm.size(), raw.size());
  for (std::size_t i = 0; i < n; ++i) {
    const char a = norm[i], b = upper(raw[i]);
    if (a != b) return a < b ? -1 : 1;
  }
  if (norm.size() == raw.size()) return 0;
  return norm.size() < raw.size() ? -1 : 1;
}

}  // namespace

std::expected<SessionTable, std::string> SessionTable::build(std::vector<SessionSpec> specs, std::size_t gateways) {
  SessionTable t;
  for (SessionSpec& s : specs) {
    s.username = normalize_credential(s.username);
    if (s.session_id == 0) return std::unexpected(std::string("session id 0 is reserved"));
    if (s.username.empty() || s.username.size() > kMaxUsername)
      return std::unexpected("session " + std::to_string(s.session_id) + ": username must be 1..6 characters");
    if (!s.credential.valid()) return std::unexpected("session " + std::to_string(s.session_id) + ": no credential");
    if (s.gateway >= gateways)
      return std::unexpected("session " + std::to_string(s.session_id) + ": gateway " + std::to_string(s.gateway) +
                             " does not exist");
  }
  std::sort(specs.begin(), specs.end(),
            [](const SessionSpec& a, const SessionSpec& b) { return a.session_id < b.session_id; });
  for (std::size_t i = 1; i < specs.size(); ++i) {
    if (specs[i].session_id == specs[i - 1].session_id)
      return std::unexpected("duplicate session id " + std::to_string(specs[i].session_id));
  }
  t.by_id_ = std::move(specs);
  t.by_user_.resize(t.by_id_.size());
  for (std::size_t i = 0; i < t.by_user_.size(); ++i) t.by_user_[i] = static_cast<std::uint32_t>(i);
  std::sort(t.by_user_.begin(), t.by_user_.end(),
            [&](std::uint32_t a, std::uint32_t b) { return t.by_id_[a].username < t.by_id_[b].username; });
  for (std::size_t i = 1; i < t.by_user_.size(); ++i) {
    if (t.by_id_[t.by_user_[i]].username == t.by_id_[t.by_user_[i - 1]].username)
      return std::unexpected("duplicate username " + t.by_id_[t.by_user_[i]].username);
  }
  return t;
}

const SessionSpec* SessionTable::find_user(std::string_view username) const noexcept {
  std::size_t lo = 0, hi = by_user_.size();
  while (lo < hi) {
    const std::size_t mid = lo + (hi - lo) / 2;
    const int c = compare_user(by_id_[by_user_[mid]].username, username);
    if (c == 0) return &by_id_[by_user_[mid]];
    if (c < 0) lo = mid + 1;
    else hi = mid;
  }
  return nullptr;
}

const SessionSpec* SessionTable::find_id(std::uint32_t session_id) const noexcept {
  const auto it = std::lower_bound(by_id_.begin(), by_id_.end(), session_id,
                                   [](const SessionSpec& s, std::uint32_t id) { return s.session_id < id; });
  return it != by_id_.end() && it->session_id == session_id ? &*it : nullptr;
}

}  // namespace lle::gw
