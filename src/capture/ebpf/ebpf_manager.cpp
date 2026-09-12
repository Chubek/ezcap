#include "ebpf_manager.hpp"

#include "common/logging.hpp"
#include "ebpf_events.hpp"

#include <bpf/libbpf.h>

#include <cstdlib>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace ezcap::capture {

namespace {

/// Boot wall time, used to anchor ktime timestamps.
std::chrono::system_clock::time_point boot_walltime() noexcept {
  // /proc/stat "btime" is seconds since boot.
  std::chrono::system_clock::time_point boot{};
  if (int fd = ::open("/proc/stat", O_RDONLY | O_CLOEXEC); fd >= 0) {
    char buf[4096];
    ssize_t n = ::read(fd, buf, sizeof(buf) - 1);
    ::close(fd);
    if (n > 0) {
      buf[n] = '\0';
      const char* p = std::strstr(buf, "btime ");
      if (p != nullptr) {
        const long long secs = std::atoll(p + 6);
        if (secs > 0) {
          boot = std::chrono::system_clock::time_point{
              std::chrono::seconds{secs}};
        }
      }
    }
  }
  return boot;
}

}  // namespace

struct EbpfCaptureBackend::Impl {
  struct bpf_object* object{nullptr};
  struct ring_buffer* ringbuf{nullptr};
  int connect_map_fd{-1};
};

EbpfCaptureBackend::EbpfCaptureBackend(EventCallback callback)
    : callback_{std::move(callback)}, impl_{std::make_unique<Impl>()} {}

EbpfCaptureBackend::~EbpfCaptureBackend() { stop(); }

bool EbpfCaptureBackend::host_supported(std::string& reason) noexcept {
  struct stat st{};
  if (::stat("/sys/kernel/btf/vmlinux", &st) != 0) {
    reason = "kernel BTF not available";
    return false;
  }
  return true;
}

bool EbpfCaptureBackend::start(std::string& error) {
  if (running_) {
    return true;
  }

  std::string reason;
  if (!host_supported(reason)) {
    error = reason;
    return false;
  }

  // Programs are built by scripts/build-ebpf.sh into ebpf/generated/.
  // The path is fixed; never user-configurable, to avoid loading
  // arbitrary objects.
  const char* object_path = EZCAP_EBPF_OBJECT_PATH;
  impl_->object = bpf_object__open_file(object_path, nullptr);
  if (impl_->object == nullptr) {
    error = "eBPF object not found (built only when supported)";
    EZCAP_LOG_INFO("ebpf backend unavailable: object missing");
    return false;
  }

  if (bpf_object__load(impl_->object) != 0) {
    error = "eBPF load failed (kernel version or permissions)";
    EZCAP_LOG_INFO("ebpf backend unavailable: load failed");
    bpf_object__close(impl_->object);
    impl_->object = nullptr;
    return false;
  }

  // Attach every program in the object: all of them are purpose-specific
  // ezcap probes; nothing else is loaded.
  struct bpf_program* prog;
  bpf_object__for_each_program(prog, impl_->object) {
    if (bpf_program__attach(prog) == nullptr) {
      error = "eBPF attach failed";
      bpf_object__close(impl_->object);
      impl_->object = nullptr;
      return false;
    }
  }

  // Find the events ring buffer map. All programs share the
  // "events" map name.
  struct bpf_map* map = bpf_object__find_map_by_name(impl_->object, "events");
  if (map == nullptr) {
    error = "events map missing from eBPF object";
    bpf_object__close(impl_->object);
    impl_->object = nullptr;
    return false;
  }

  impl_->ringbuf = ring_buffer__new(
      bpf_map__fd(map),
      [](void* ctx, void* data, std::size_t size) -> int {
        auto* self = static_cast<EbpfCaptureBackend*>(ctx);
        if (size < sizeof(ezcap_event_header)) {
          return 0;  // truncated record: drop, never crash
        }
        const auto* hdr = static_cast<const ezcap_event_header*>(data);
        if (hdr->version != EZCAP_EVENT_VERSION) {
          EZCAP_LOG_WARN("ebpf event version mismatch; dropped");
          return 0;
        }
        const auto boot = boot_walltime();
        switch (hdr->tag) {
          case EZCAP_EVENT_TAG_CONNECT:
            if (size >= sizeof(ezcap_connect_event)) {
              self->callback_(normalize_connect_event(
                  *static_cast<const ezcap_connect_event*>(data), boot));
            }
            break;
          case EZCAP_EVENT_TAG_DNS:
            if (size >= sizeof(ezcap_dns_event)) {
              self->callback_(normalize_dns_event(
                  *static_cast<const ezcap_dns_event*>(data), boot));
            }
            break;
          case EZCAP_EVENT_TAG_SOCKET_STATE:
            if (size >= sizeof(ezcap_socket_state_event)) {
              self->callback_(normalize_socket_state_event(
                  *static_cast<const ezcap_socket_state_event*>(data), boot));
            }
            break;
          default:
            break;  // unknown tag: drop
        }
        return 0;
      },
      this, nullptr);

  if (impl_->ringbuf == nullptr) {
    error = "ring buffer allocation failed";
    bpf_object__close(impl_->object);
    impl_->object = nullptr;
    return false;
  }

  running_ = true;
  thread_ = std::make_unique<std::thread>(&EbpfCaptureBackend::poll_loop, this);
  EZCAP_LOG_INFO("ebpf backend started");
  return true;
}

void EbpfCaptureBackend::stop() noexcept {
  if (!running_) {
    return;
  }
  running_ = false;
  if (thread_ && thread_->joinable()) {
    thread_->join();
  }
  thread_.reset();
  if (impl_->ringbuf != nullptr) {
    ring_buffer__free(impl_->ringbuf);
    impl_->ringbuf = nullptr;
  }
  if (impl_->object != nullptr) {
    bpf_object__close(impl_->object);
    impl_->object = nullptr;
  }
  EZCAP_LOG_INFO("ebpf backend stopped");
}

bool EbpfCaptureBackend::running() const noexcept { return running_; }

void EbpfCaptureBackend::poll_loop() {
  constexpr int kPollTimeoutMs = 250;
  while (running_) {
    const int rc = ring_buffer__poll(impl_->ringbuf, kPollTimeoutMs);
    if (rc == -EINTR) {
      continue;
    }
    if (rc < 0) {
      EZCAP_LOG_ERROR("ebpf ring buffer poll error; stopping backend");
      running_ = false;
      break;
    }
  }
}

}  // namespace ezcap::capture
