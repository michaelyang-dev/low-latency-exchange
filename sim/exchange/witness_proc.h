#pragma once
// witnessd (apps/witnessd/main.cpp, --listen) as a simulated process image: the
// production core (witness/witness.h) behind the node's UDP port, its state file's two
// 4 KiB slots on the node's disk written with O_DSYNC (one write in flight), every
// reply sent only once the state it reflects is durable, and a failed write stopping W
// (witnessd dies; its supervisor restarts it on the durable state). W refuses to start
// without a valid slot, as witnessd does.
//
// As sim/ha's witness, with the world's view as hooks instead of the ha harness.
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <optional>
#include <span>
#include <string>

#include "sim/disk.h"
#include "sim/network.h"
#include "sim/node.h"
#include "witness/control.h"
#include "witness/witness.h"

namespace lle::sim::exch {

class WitnessProc final : public Process {
 public:
  static constexpr std::size_t kStateBytes = witness::kSlotBytes * witness::kSlots;

  struct Hooks {
    std::function<void(const witness::Grant&)> grant;          // every GRANT as it leaves W
    std::function<void(const std::string&)> refused;           // no valid slot: W does not start
    std::function<void(const witness::State&)> started;        // the durable state W starts from
  };

  // The initial state file of a day (witnessd --init --primary P --inc0 1 --inc1 1).
  static std::array<std::byte, kStateBytes> initial_state(witness::NodeId primary) {
    witness::State s;
    s.epoch = 1;
    s.primary = primary;
    s.members = 0b11;
    s.inc = {1, 1};
    std::array<std::byte, kStateBytes> img{};
    const witness::SlotImage s0 = witness::encode_slot(s, 1);
    std::memcpy(img.data(), s0.data(), s0.size());
    return img;
  }

  WitnessProc(Node& n, std::uint16_t port, const std::string& state_file, Nanos tie_break, Hooks hooks)
      : node_(n), hooks_(std::move(hooks)), port_(n, port), file_(n, state_file), stage_{this} {
    std::array<std::byte, kStateBytes> img{};
    (void)file_.read(0, img);
    const auto d = witness::choose(std::span<const std::byte>(img).first(witness::kSlotBytes),
                                   std::span<const std::byte>(img).subspan(witness::kSlotBytes));
    if (!d) {
      if (hooks_.refused) hooks_.refused("no valid state slot: refusing to start");
      return;
    }
    core_.emplace(witness::Config{tie_break}, *d, n.clock().now_mono());
    durable_state_ = d->state;
    if (hooks_.started) hooks_.started(d->state);
    n.add_stage(stage_, "witness");
  }

  [[nodiscard]] const witness::Witness* core() const noexcept { return core_ ? &*core_ : nullptr; }
  // What a restart of W comes back with (the last state written durably).
  [[nodiscard]] const witness::State& durable_state() const noexcept { return durable_state_; }

 private:
  struct Stage {
    WitnessProc* p;
    bool poll() { return p->poll(); }
  };

  bool poll() {
    bool did = false;
    file_.poll([&](const env::DiskCompletion& c) {
      did = true;
      writing_ = false;
      if (failed_) return;
      if (c.result < 0) {
        core_->on_write_failed();
        failed_ = true;
        node_.request_crash();  // witnessd: a failed state write stops W
        return;
      }
      core_->on_persisted(c.tag);
      durable_state_ = writing_state_;
    });
    if (failed_ || !core_) return did;
    const Nanos now = node_.clock().now_mono();
    port_.poll_rx([&](const env::RxDatagram& d) {
      did = true;
      if (const auto m = witness::decode(d.data)) core_->handle(*m, d.src, now);
    });
    if (!writing_) {
      if (auto job = core_->begin_write()) {
        writing_state_ = core_->state();
        if (file_.submit_write(static_cast<std::uint64_t>(job->slot) * witness::kSlotBytes, job->image, true,
                               job->generation)) {
          writing_ = true;
          did = true;
        } else {
          core_->on_write_failed();
          failed_ = true;
          node_.request_crash();
        }
      }
    }
    core_->drain([&](const env::Endpoint& to, std::span<const std::byte> b) {
      if (hooks_.grant) {
        if (const auto m = witness::decode(b)) {
          if (const auto* g = std::get_if<witness::Grant>(&*m)) hooks_.grant(*g);
        }
      }
      port_.send(to, b);
      did = true;
    });
    return did;
  }

  Node& node_;
  Hooks hooks_;
  DatagramPort port_;
  DiskFile file_;
  std::optional<witness::Witness> core_;
  witness::State durable_state_;
  witness::State writing_state_;
  Stage stage_;
  bool writing_ = false;
  bool failed_ = false;
};

}  // namespace lle::sim::exch
