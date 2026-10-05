// journal_diff <dir-a> <dir-b> (06 §11): the first divergence between two journals
// (rejoin truncation tests, primary vs backup). Records are compared by content (every
// field and the payload; the per-medium seal is ignored), in index order.
// Exit status: 0 identical, 1 divergent or one is a strict prefix of the other,
// 2 usage or I/O error.
#include <cinttypes>
#include <cstdio>
#include <string>

#include "journal/describe.h"
#include "journal/posix_segment_dir.h"
#include "journal/reader.h"

namespace {

using namespace lle::journal;

bool open_dir(const char* path, PosixSegmentDir& out) {
  auto d = PosixSegmentDir::open(path, false, PosixDeviceOptions{.read_only = true});
  if (!d) {
    std::fprintf(stderr, "journal_diff: %s\n", d.error().c_str());
    return false;
  }
  out = std::move(*d);
  return true;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc != 3) {
    std::fprintf(stderr, "usage: journal_diff <journal-dir-a> <journal-dir-b>\n");
    return 2;
  }
  PosixSegmentDir da, db;
  if (!open_dir(argv[1], da) || !open_dir(argv[2], db)) return 2;
  JournalCursor<PosixSegmentDir> a(da), b(db);
  std::uint64_t same = 0;
  for (;;) {
    const RecordView ra = a.next();
    const RecordView rb = b.next();
    if (a.stop() == ReadStop::IoError || b.stop() == ReadStop::IoError) {
      std::fprintf(stderr, "journal_diff: I/O error after %" PRIu64 " equal records\n", same);
      return 2;
    }
    if (ra.empty() && rb.empty()) {
      std::printf("identical: %" PRIu64 " records (last index %" PRIu64 ", chain head %08x)\n", same,
                  a.chain().last_index, a.chain().last_crc);
      return 0;
    }
    if (ra.empty() || rb.empty()) {
      const char* shorter = ra.empty() ? "a" : "b";
      const RecordView& more = ra.empty() ? rb : ra;
      const auto& cur = ra.empty() ? b : a;
      std::printf("prefix: %s ends after %" PRIu64 " equal records; the other continues with:\n  %s\n", shorter,
                  same, describe(more, cur.sealer().content_of(more.data())).c_str());
      return 1;
    }
    const std::string_view field = first_difference(ra, rb);
    if (!field.empty()) {
      std::printf("diverge at record %" PRIu64 " (index a=%" PRIu64 " b=%" PRIu64 "), first different field: %.*s\n",
                  same + 1, ra.index(), rb.index(), static_cast<int>(field.size()), field.data());
      std::printf("  a: %s\n", describe(ra, a.sealer().content_of(ra.data())).c_str());
      std::printf("  b: %s\n", describe(rb, b.sealer().content_of(rb.data())).c_str());
      return 1;
    }
    ++same;
  }
}
