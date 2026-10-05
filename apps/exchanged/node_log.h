#pragma once
// nlog events of the node's start-up code. (They were inline helpers to keep GCC from
// rejecting a translation unit that mixed nlog sites in inline and non-inline functions,
// "section type conflict"; log/nlog.h now keys every site's slot by the site itself, so
// the mix compiles, NlogSites.InlineAndPlainSitesShareATranslationUnit.)
#include <cstddef>
#include <cstdint>
#include <string_view>

#include "log/nlog.h"

namespace lle::exch::nodelog {

inline void journal_recovered(std::uint64_t records, std::uint64_t last, bool torn) {
  NLOG_INFO("journal: recovered {} records (last index {}), torn tail {}", records, last, torn);
}
inline void replayed(std::uint64_t last, std::uint64_t verified, std::uint64_t appended) {
  NLOG_INFO("recovery: replayed {} records, output log {} verified {} regenerated", last, verified, appended);
}
inline void day_started(std::uint32_t date, std::uint64_t records) {
  NLOG_INFO("seq: day {} started, {} records", date, records);
}
inline void rejoin_truncated(std::uint64_t t, std::size_t recycled) {
  NLOG_WARN("rejoin: journal truncated to {} ({} segments recycled)", t, recycled);
}
inline void l2_restored(std::uint64_t records, std::uint64_t last) {
  NLOG_WARN("L2: restored {} records (last index {}) into the journal", records, last);
}
inline void note(std::string_view line) { NLOG_INFO("{}", line); }
inline void outlog_rewrite(std::size_t files) {
  NLOG_WARN("recovery: {} output-log files differ from the journal: rewriting them", files);
}

}  // namespace lle::exch::nodelog
