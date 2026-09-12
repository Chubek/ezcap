#pragma once

#include <ezcap/event.hpp>

#include "capture/event_normalizer.hpp"
#include "capture/packet_parser.hpp"

#include <functional>
#include <memory>
#include <string>
#include <thread>

// Forward-declare to avoid leaking <pcap.h> into this header.
struct pcap;
using pcap_t = struct pcap;

namespace ezcap::capture {

/// Abstract capture backend. The daemon consumes only normalized events
/// through the callback; no libpcap or eBPF types leak past this interface.
class CaptureBackend {
 public:
  virtual ~CaptureBackend() = default;

  /// Human-readable backend name ("pcap", "ebpf").
  [[nodiscard]] virtual const char* name() const noexcept = 0;

  /// Start capturing. Returns false with `error` populated on failure
  /// (missing permissions, bad filter, unavailable interface...).
  virtual bool start(std::string& error) = 0;

  /// Stop capturing and release resources. Safe to call when not started.
  virtual void stop() noexcept = 0;

  /// True between successful start() and stop().
  [[nodiscard]] virtual bool running() const noexcept = 0;
};

/// libpcap-backed fallback backend. Captures metadata-only: the BPF filter
/// is applied in-kernel where possible, and the callback receives only
/// parsed header metadata, never payload spans.
class PcapCaptureBackend final : public CaptureBackend {
 public:
  /// Called for every normalized event. Runs on the capture thread: must
  /// be cheap and must not block.
  using EventCallback = std::function<void(const ezcap::Event&)>;

  PcapCaptureBackend(std::string interface_name, std::string filter,
                     EventCallback callback);
  ~PcapCaptureBackend() override;

  const char* name() const noexcept override { return "pcap"; }

  bool start(std::string& error) override;
  void stop() noexcept override;
  bool running() const noexcept override;

 private:
  void run_loop();

  std::string interface_name_;
  std::string filter_;
  EventCallback callback_;
  EventNormalizer normalizer_;

  pcap_t* handle_{nullptr};
  bool running_{false};
  std::unique_ptr<std::thread> thread_;
};

}  // namespace ezcap::capture
