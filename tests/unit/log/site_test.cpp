// Linker-section site registry (site.h): dictionary walk, IDs, dedup of inline
// sites and compile-time level filtering.
#include "log/site.h"

#include <gtest/gtest.h>

#include <string_view>
#include <vector>

#include "log/memory_sink.h"
#include "log/nlog.h"
#include "site_helpers.h"
#include "test_util.h"

namespace lle::nlog {
namespace {

std::vector<std::uint32_t> sites_with_fmt(std::string_view fmt) {
  std::vector<std::uint32_t> out;
  for (std::uint32_t i = 0; i < site_count(); ++i) {
    const LogSite* s = site_at(i);
    if (s != nullptr && std::string_view{s->fmt} == fmt) out.push_back(i);
  }
  return out;
}

constexpr std::uint32_t kFirstSiteLine = __LINE__ + 2;
void log_two_sites() {
  NLOG_INFO("site-test first {}", 1);
  NLOG_WARN("site-test second {} {}", std::uint64_t{2}, std::string_view{"x"});
}

TEST(NlogSites, SectionWalkFindsEverySiteWithMetadata) {
  ASSERT_GT(site_count(), 0u);
  const auto first = sites_with_fmt("site-test first {}");
  const auto second = sites_with_fmt("site-test second {} {}");
  ASSERT_EQ(first.size(), 1u);
  ASSERT_EQ(second.size(), 1u);
  EXPECT_NE(first[0], second[0]);
  const LogSite* s = site_at(first[0]);
  EXPECT_EQ(s->level, Level::kInfo);
  EXPECT_EQ(s->line, kFirstSiteLine);
  EXPECT_TRUE(std::string_view{s->file}.ends_with("site_test.cpp"));
  EXPECT_EQ(s->nargs, 1);
  EXPECT_EQ(s->kinds[0], ArgKind::kI32);
  const LogSite* t = site_at(second[0]);
  EXPECT_EQ(t->level, Level::kWarn);
  EXPECT_EQ(t->nargs, 2);
  EXPECT_EQ(t->kinds[0], ArgKind::kU64);
  EXPECT_EQ(t->kinds[1], ArgKind::kStr);
  EXPECT_EQ(site_at(site_count()), nullptr);
}

TEST(NlogSites, RecordsCarryTheSiteIdOfTheirCallSite) {
  test::drain_and_discard();
  ThreadScope scope({.ring_bytes = 1 << 16});
  ASSERT_TRUE(scope.ok());
  for (int i = 0; i < 3; ++i) log_two_sites();
  MemorySink sink;
  ASSERT_TRUE(sink.attach());
  ASSERT_EQ(sink.drain(), 6u);
  const auto first = sites_with_fmt("site-test first {}");
  const auto second = sites_with_fmt("site-test second {} {}");
  for (std::size_t i = 0; i < 6; ++i) {
    EXPECT_EQ(sink.records()[i].site_idx, (i % 2 == 0 ? first[0] : second[0]));
    EXPECT_EQ(sink.records()[i].site, site_at(sink.records()[i].site_idx));
  }
}

TEST(NlogSites, InlineFunctionSiteIsEmittedOnce) {
  test::drain_and_discard();
  const auto ids = sites_with_fmt("inline-site-dedup {}");
  ASSERT_EQ(ids.size(), 1u);
  ThreadScope scope({.ring_bytes = 1 << 16});
  test::call_inline_from_a();
  test::call_inline_from_b();
  MemorySink sink;
  ASSERT_TRUE(sink.attach());
  ASSERT_EQ(sink.drain(), 2u);
  EXPECT_EQ(sink.records()[0].site_idx, ids[0]);
  EXPECT_EQ(sink.records()[1].site_idx, ids[0]);
}

TEST(NlogSites, InlineAndPlainSitesShareATranslationUnit) {
  test::drain_and_discard();
  const auto inline_ids = sites_with_fmt("inline-site-dedup {}");
  const auto plain_ids = sites_with_fmt("mixed-tu-plain-site {}");
  ASSERT_EQ(inline_ids.size(), 1u) << "the inline site is listed once";
  ASSERT_EQ(plain_ids.size(), 1u);
  // Its slots: one per translation unit that compiled it (site_inline_a, site_inline_b,
  // site_mixed), all mapped to the one ID.
  std::uint32_t raw = 0;
  for (std::uint32_t i = 0; i < site_count(); ++i) {
    const LogSite* s = slot_site(i);
    if (s != nullptr && std::string_view{s->fmt} == "inline-site-dedup {}") {
      ++raw;
      EXPECT_EQ(canonical_site(i), inline_ids[0]);
    }
  }
  EXPECT_GE(raw, 2u);
  ThreadScope scope({.ring_bytes = 1 << 16});
  test::log_from_mixed_tu();
  MemorySink sink;
  ASSERT_TRUE(sink.attach());
  ASSERT_EQ(sink.drain(), 2u);
  EXPECT_EQ(sink.records()[0].site_idx, inline_ids[0]);
  EXPECT_EQ(sink.records()[1].site_idx, plain_ids[0]);
}

TEST(NlogSites, LevelsBelowMinimumAreCompiledOut) {
  test::drain_and_discard();
  EXPECT_TRUE(sites_with_fmt("filtered-debug-site {}").empty());
  EXPECT_TRUE(sites_with_fmt("filtered-info-site {}").empty());
  EXPECT_TRUE(sites_with_fmt("filtered-ev-site {}").empty());
  EXPECT_EQ(sites_with_fmt("filtered-warn-site {}").size(), 1u);
  EXPECT_EQ(sites_with_fmt("filtered-error-site").size(), 1u);
  ThreadScope scope({.ring_bytes = 1 << 16});
  test::log_filtered_levels();
  EXPECT_EQ(test::filtered_side_effects(), 0) << "arguments of compiled-out calls must not be evaluated";
  MemorySink sink;
  ASSERT_TRUE(sink.attach());
  ASSERT_EQ(sink.drain(), 2u);
  EXPECT_EQ(sink.records()[0].site->level, Level::kWarn);
  EXPECT_EQ(sink.records()[1].site->level, Level::kError);
}

TEST(NlogSites, SiteIndexIsSlotOffsetOverPointerSize) {
  // The anchor slot from registry.cpp is always present.
  const auto anchors = sites_with_fmt("nlog: section anchor");
  ASSERT_EQ(anchors.size(), 1u);
  const LogSite* const* slot =
      reinterpret_cast<const LogSite* const*>(LLE_NLOG_SECTION_START_ADDR + anchors[0] * kSlotBytes);
  EXPECT_EQ(site_index(slot), anchors[0]);
}

}  // namespace
}  // namespace lle::nlog
