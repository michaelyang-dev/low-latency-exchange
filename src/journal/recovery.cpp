#include "journal/recovery.h"

#include "journal/posix_segment_dir.h"
#include "journal/reader.h"

namespace lle::journal {

std::string_view to_string(RecoveryStatus s) noexcept {
  switch (s) {
    case RecoveryStatus::Ok: return "ok";
    case RecoveryStatus::Empty: return "empty";
    case RecoveryStatus::Corruption: return "corruption";
    case RecoveryStatus::IoError: return "io-error";
  }
  return "unknown";
}

std::string_view to_string(CorruptionKind k) noexcept {
  switch (k) {
    case CorruptionKind::None: return "none";
    case CorruptionKind::DuplicateSegment: return "duplicate segment";
    case CorruptionKind::SegmentChainBreak: return "segment chain break";
    case CorruptionKind::DataAfterSealedSegment: return "data after end of sealed segment";
    case CorruptionKind::ValidRecordBeyondWindow: return "valid record beyond in-flight window";
  }
  return "unknown";
}

std::string_view to_string(ReadStop s) noexcept {
  switch (s) {
    case ReadStop::End: return "end of valid records";
    case ReadStop::Callback: return "stopped by callback";
    case ReadStop::ToIndex: return "reached to-index";
    case ReadStop::ChainBreak: return "segment chain break";
    case ReadStop::Duplicate: return "duplicate segment";
    case ReadStop::IoError: return "I/O error";
    case ReadStop::Empty: return "empty";
  }
  return "unknown";
}

RecoveryResult recover(const std::string& dir_path, const RecoveryOptions& opts) {
  auto dir = PosixSegmentDir::open(dir_path, false, PosixDeviceOptions{.read_only = !opts.repair});
  if (!dir) {
    RecoveryResult r;
    r.status = RecoveryStatus::IoError;
    r.detail = dir.error();
    return r;
  }
  return recover(*dir, opts);
}

}  // namespace lle::journal
