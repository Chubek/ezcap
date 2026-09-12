#pragma once

#include <ezcap/event.hpp>

#include "capture/pcap/pcap_capture.hpp"  // CaptureBackend

#include <atomic>
#include <functional>
#include <memory>
#include <string>
#include <thread>
#include <string_view>

namespace ezcap::capture {

/// Userspace eBPF loader and manager. Checks kernel/BTF compatibility,
/// loads the minimal required programs, drains the ring buffer, and
/// converts kernel events into normalized events. When the host system
/// lacks eBPF support or permissions, start() fails with a clear error and
/// the daemon falls back to pcap in a degraded (process-attribution-less)
/// mode — never to unsafe behavior.
class EbpfCaptureBackend final : public CaptureBackend {
 public:
  using EventCallback = std::function<void(const ezcap::Event&)>;

  explicit EbpfCaptureBackend(EventCallback callback);
  ~EbpfCaptureBackend() override;

  const char* name() const noexcept override { return "ebpf"; }

  bool start(std::string& error) override;
  void stop() noexcept override;
  bool running() const noexcept override;

  /// True when the host kernel and userspace toolchain look eBPF-capable
  /// (kernel BTF present). Used for status reporting before attempting a
  /// privileged load.
  [[nodiscard]] static bool host_supported(std::string& reason) noexcept;

  /// Resolve the eBPF object file to load.
  /// Keeps the compiled-in path as the primary choice and searches known
  /// fallback locations for installed/build-tree deployments.
  [[nodiscard]] static std::string resolve_object_path() noexcept;

 private:
  void poll_loop();

  EventCallback callback_;
  std::atomic<bool> running_{false};
  std::unique_ptr<std::thread> thread_;

  // Opaque libbpf objects; defined in the .cpp to keep libbpf headers out
  // of the daemon-wide interface.
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace ezcap::capture
