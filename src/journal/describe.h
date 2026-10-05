#pragma once
// Human-readable rendering of journal records and the format schema, for
// journal_inspect / journal_diff / journal_replay (06 §11). Cold path.
#include <string>
#include <string_view>

#include "journal/record.h"

namespace lle::journal {

// One line: header fields, content crc, and the decoded payload (or the decode error).
[[nodiscard]] std::string describe(const RecordView& r, std::uint32_t content_crc);

// The first header field (or "payload") in which two records differ, or "" if equal
// apart from the medium seal.
[[nodiscard]] std::string_view first_difference(const RecordView& a, const RecordView& b) noexcept;

// The record and segment formats (journal_inspect schema).
[[nodiscard]] std::string_view schema_text() noexcept;

}  // namespace lle::journal
