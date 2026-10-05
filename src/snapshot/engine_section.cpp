#include "snapshot/engine_section.h"

#include <algorithm>

#include "common/endian.h"

namespace lle::snap {

SnapshotMeta engine_meta(const engine::Engine& e, const EngineSnapshotIds& ids) {
  SnapshotMeta m;
  m.day = ids.day != 0 ? ids.day : e.date();
  m.epoch = ids.epoch;
  m.index = ids.index;
  m.snapshot_id = ids.snapshot_id;
  m.mold_seq = e.itch_count();
  m.state_hash = e.state_hash();
  m.build_id = ids.build_id;
  return m;
}

std::vector<SessionSeq> engine_sessions(const engine::Engine& e) {
  std::vector<SessionSeq> v;
  for (const auto& [id, sent] : e.session_outputs()) v.push_back(SessionSeq{id, sent + 1});
  std::sort(v.begin(), v.end(), [](const SessionSeq& a, const SessionSeq& b) { return a.session_id < b.session_id; });
  return v;
}

void write_engine(const engine::Engine& e, Writer& w) {
  std::vector<std::byte> payload;
  e.snapshot(payload);
  w.write(payload);
}

std::expected<std::string, Error> save_engine(const engine::Engine& e, const EngineSnapshotIds& ids,
                                              const std::string& day_dir, const WriterOptions& opts) {
  const auto sessions = engine_sessions(e);
  auto w = Writer::create(day_dir, engine_meta(e, ids), sessions, opts);
  if (!w) return std::unexpected(w.error());
  write_engine(e, *w);
  return w->commit();
}

std::expected<std::string, Error> save_engine(Storage& storage, const engine::Engine& e, const EngineSnapshotIds& ids,
                                              const std::string& day_dir, const WriterOptions& opts) {
  const auto sessions = engine_sessions(e);
  auto w = Writer::create(storage, day_dir, engine_meta(e, ids), sessions, opts);
  if (!w) return std::unexpected(w.error());
  write_engine(e, *w);
  return w->commit();
}

std::expected<std::vector<std::byte>, Error> engine_image(const engine::Engine& e, const EngineSnapshotIds& ids,
                                                          const WriterOptions& opts) {
  const auto sessions = engine_sessions(e);
  auto w = Writer::create_in_memory(engine_meta(e, ids), sessions, opts);
  if (!w) return std::unexpected(w.error());
  write_engine(e, *w);
  return w->finish_image();
}

std::string_view to_string(EngineLoadError e) noexcept {
  switch (e) {
    case EngineLoadError::NotEngine: return "not an engine snapshot";
    case EngineLoadError::BadVersion: return "unsupported engine section version";
    case EngineLoadError::Restore: return "engine rejected the payload";
    case EngineLoadError::StateHash: return "state hash mismatch";
    case EngineLoadError::MoldSeq: return "S(P) mismatch";
    case EngineLoadError::Sessions: return "session table mismatch";
  }
  return "?";
}

std::expected<void, EngineLoadError> load_engine(Reader& r, engine::Engine& e) {
  std::vector<std::byte> payload(r.remaining());
  if (payload.size() < 12 || !r.read(payload)) return std::unexpected(EngineLoadError::NotEngine);
  if (load_le64(payload.data()) != kEngineMagic) return std::unexpected(EngineLoadError::NotEngine);
  if (load_le32(payload.data() + 8) != kEngineVersion) return std::unexpected(EngineLoadError::BadVersion);
  if (!e.restore(payload)) return std::unexpected(EngineLoadError::Restore);
  auto fail = [&](EngineLoadError x) -> std::expected<void, EngineLoadError> {
    (void)e.restore({});  // leaves an empty, reset engine
    return std::unexpected(x);
  };
  if (e.state_hash() != r.meta().state_hash) return fail(EngineLoadError::StateHash);
  if (e.itch_count() != r.meta().mold_seq) return fail(EngineLoadError::MoldSeq);
  const auto want = engine_sessions(e);
  if (!std::equal(want.begin(), want.end(), r.sessions().begin(), r.sessions().end()))
    return fail(EngineLoadError::Sessions);
  return {};
}

}  // namespace lle::snap
