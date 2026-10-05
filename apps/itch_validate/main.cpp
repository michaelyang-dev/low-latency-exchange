// itch_validate: checks an ITCH 5.0 BinaryFILE stream (03-protocols §3).
// Default mode checks framing (length, type); --strict adds enum value sets,
// Issue Sub-Type / Trading Action Reason codes, the locate-0 rule and timestamp
// monotonicity. Violations are counted, never fatal.
//
//   itch_validate [--strict] [--max-records N] FILE...
//
// Exit status: 0 if no violations, 1 otherwise, 2 on usage or I/O errors.
#include <cstdio>
#include <algorithm>
#include <cstdlib>
#include <string>
#include <vector>

#include "proto/itch50/binary_file.h"
#include "proto/itch50/validator.h"

namespace {

using lle::itch50::Validator;
using ull = unsigned long long;

int run(const std::string& path, bool strict, std::uint64_t max_records) {
  lle::itch50::BinaryFileReader reader;
  if (auto ok = reader.open(path); !ok) {
    std::fprintf(stderr, "itch_validate: %s\n", ok.error().c_str());
    return 2;
  }
  Validator v(strict);
  std::uint64_t records = 0, end_of_session = 0, framing = 0;
  bool io_error = false;
  for (; records < max_records; ++records) {
    const lle::itch50::Record r = reader.next();
    if (r.status == lle::itch50::RecordStatus::Message) {
      v.check(r.data);
    } else if (r.status == lle::itch50::RecordStatus::EndOfSession) {
      ++end_of_session;  // BinaryFILE end-of-session marker, not an ITCH message
    } else {
      if (r.status == lle::itch50::RecordStatus::Truncated) ++framing;
      if (r.status == lle::itch50::RecordStatus::IoError) {
        io_error = true;
        std::fprintf(stderr, "itch_validate: read error: %s\n", reader.error().c_str());
      }
      break;
    }
  }
  std::printf("file: %s (%s mode)\n", path.c_str(), strict ? "strict" : "framing");
  std::printf("  records %llu  messages %llu  end_of_session %llu  truncated_records %llu\n",
              static_cast<ull>(records), static_cast<ull>(v.messages()), static_cast<ull>(end_of_session),
              static_cast<ull>(framing));
  std::printf("  violations %llu\n", static_cast<ull>(v.violations() + framing));
  for (std::size_t i = 0; i < Validator::kNumRules; ++i) {
    const auto rule = static_cast<Validator::Rule>(i);
    if (v.count(rule) == 0) continue;
    const auto name = Validator::rule_name(rule);
    std::printf("    %-20.*s %12llu  by type:", static_cast<int>(name.size()), name.data(),
                static_cast<ull>(v.count(rule)));
    for (unsigned t = 0; t < 256; ++t)
      if (v.count(rule, static_cast<char>(t)) != 0)
        std::printf(" %c=%llu", t >= 32 && t < 127 ? static_cast<char>(t) : '?',
                    static_cast<ull>(v.count(rule, static_cast<char>(t))));
    std::printf("\n");
  }
  for (std::size_t f = 0; f < static_cast<std::size_t>(lle::itch50::FieldId::kCount); ++f) {
    const auto id = static_cast<lle::itch50::FieldId>(f);
    if (v.field_count(id) == 0) continue;
    const auto name = lle::itch50::field_name(id);
    std::printf("    field %-40.*s %12llu\n", static_cast<int>(name.size()), name.data(),
                static_cast<ull>(v.field_count(id)));
  }
  if (!v.examples().empty()) std::printf("  first violations:\n");
  for (const auto& e : v.examples()) {
    const auto rn = Validator::rule_name(e.rule);
    const auto fn = e.field == lle::itch50::FieldId::kCount ? std::string_view{} : lle::itch50::field_name(e.field);
    std::printf("    msg %llu type %c %.*s %.*s value %llu\n", static_cast<ull>(e.index),
                e.type >= 32 && e.type < 127 ? e.type : '?', static_cast<int>(rn.size()), rn.data(),
                static_cast<int>(fn.size()), fn.data(), static_cast<ull>(e.value));
  }
  const bool ok = v.violations() == 0 && framing == 0 && !io_error;
  std::printf("RESULT %s\n", ok ? "PASS" : "FAIL");
  return io_error ? 2 : (ok ? 0 : 1);
}

}  // namespace

int main(int argc, char** argv) {
  bool strict = false;
  std::uint64_t max_records = UINT64_MAX;
  std::vector<std::string> files;
  for (int i = 1; i < argc; ++i) {
    const std::string a = argv[i];
    if (a == "--strict") {
      strict = true;
    } else if (a == "--max-records" && i + 1 < argc) {
      max_records = std::strtoull(argv[++i], nullptr, 10);
    } else if (a == "-h" || a == "--help") {
      std::printf("usage: itch_validate [--strict] [--max-records N] FILE...\n");
      return 0;
    } else {
      files.push_back(a);
    }
  }
  if (files.empty()) {
    std::fprintf(stderr, "usage: itch_validate [--strict] [--max-records N] FILE...\n");
    return 2;
  }
  int rc = 0;
  for (const auto& f : files) rc = std::max(rc, run(f, strict, max_records));
  return rc;
}
