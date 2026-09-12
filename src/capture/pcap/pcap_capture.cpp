#include "pcap_capture.hpp"

#include "common/logging.hpp"

#include <pcap.h>

#include <atomic>
#include <chrono>
#include <cstring>

namespace ezcap::capture {

namespace {

// pcap_dispatch batch size per loop iteration.
constexpr int kDispatchCount = 64;

}  // namespace

PcapCaptureBackend::PcapCaptureBackend(std::string interface_name,
                                       std::string filter,
                                       EventCallback callback)
    : interface_name_{std::move(interface_name)},
      filter_{std::move(filter)},
      callback_{std::move(callback)},
      normalizer_{"pcap"} {}

PcapCaptureBackend::~PcapCaptureBackend() { stop(); }

bool PcapCaptureBackend::start(std::string& error) {
  if (running_) {
    return true;
  }

  char errbuf[PCAP_ERRBUF_SIZE]{};
  handle_ = ::pcap_create(interface_name_.c_str(), errbuf);
  if (handle_ == nullptr) {
    error = "pcap_create failed on interface (permission or missing device)";
    EZCAP_LOG_WARN("pcap backend unavailable: create failed");
    return false;
  }

  // Metadata-friendly snaplen: we only ever need headers (Ethernet + IP +
  // transport + DNS question). Small snaplen limits exposure and overhead.
  if (::pcap_set_snaplen(handle_, 512) != 0 ||
      ::pcap_set_promisc(handle_, 0) != 0 ||
      ::pcap_set_timeout(handle_, 250) != 0) {
    error = "pcap configuration failed";
    ::pcap_close(handle_);
    handle_ = nullptr;
    return false;
  }

  if (::pcap_activate(handle_) != 0) {
    error = "pcap_activate failed (permission or busy device)";
    EZCAP_LOG_WARN("pcap backend unavailable: activate failed");
    ::pcap_close(handle_);
    handle_ = nullptr;
    return false;
  }

  // Apply the capture filter early so the kernel drops non-matching packets
  // before they reach userspace.
  bpf_program program{};
  if (::pcap_compile(handle_, &program, filter_.c_str(), 1 /*optimize*/,
                     PCAP_NETMASK_UNKNOWN) != 0) {
    error = "capture filter rejected";
    ::pcap_close(handle_);
    handle_ = nullptr;
    return false;
  }
  const int set_filter_rc = ::pcap_setfilter(handle_, &program);
  ::pcap_freecode(&program);
  if (set_filter_rc != 0) {
    error = "pcap_setfilter failed";
    ::pcap_close(handle_);
    handle_ = nullptr;
    return false;
  }

  if (::pcap_set_datalink(handle_, ::pcap_datalink(handle_)) != 0) {
    // Non-fatal: keep the default datalink.
  }

  running_ = true;
  thread_ = std::make_unique<std::thread>(&PcapCaptureBackend::run_loop, this);
  EZCAP_LOG_INFO("pcap backend started");
  return true;
}

void PcapCaptureBackend::stop() noexcept {
  if (!running_) {
    return;
  }
  running_ = false;
  if (thread_ && thread_->joinable()) {
    // pcap_breakloop unblocks a dispatch in progress.
    if (handle_ != nullptr) {
      ::pcap_breakloop(handle_);
    }
    thread_->join();
  }
  thread_.reset();
  if (handle_ != nullptr) {
    ::pcap_close(handle_);
    handle_ = nullptr;
  }
  EZCAP_LOG_INFO("pcap backend stopped");
}

bool PcapCaptureBackend::running() const noexcept { return running_; }

void PcapCaptureBackend::run_loop() {
  while (running_) {
    // Packet handler context: the callback receives only parsed metadata.
    struct Ctx {
      PcapCaptureBackend* self;
      std::string interface;
    } ctx{this, interface_name_};

    auto handler = [](std::uint8_t* user, const pcap_pkthdr* header,
                      const std::uint8_t* bytes) {
      auto* context = reinterpret_cast<Ctx*>(user);
      if (header->caplen > header->len) {
        return;  // malformed capture record
      }
      // Parse headers only; payload bytes beyond headers are never read.
      PacketMetadata meta = parse_ethernet_frame(
          {bytes, static_cast<std::size_t>(header->caplen)});
      if (!meta.valid) {
        return;
      }
      const auto ts = std::chrono::system_clock::time_point{
          std::chrono::seconds{header->ts.tv_sec} +
          std::chrono::microseconds{header->ts.tv_usec}};

      const bool dns =
          meta.dns_query_name.empty() == false ||
          (meta.transport == Transport::Udp &&
           (static_cast<std::uint16_t>(meta.destination_port) == 53 ||
            static_cast<std::uint16_t>(meta.source_port) == 53));
      if (dns) {
        context->self->callback_(
            context->self->normalizer_.dns_from_packet_metadata(meta, ts,
                                                                context->interface));
      } else {
        context->self->callback_(
            context->self->normalizer_.from_packet_metadata(meta, ts,
                                                            context->interface));
      }
    };

    const int rc = ::pcap_dispatch(handle_, kDispatchCount, handler,
                                   reinterpret_cast<std::uint8_t*>(&ctx));
    if (rc == PCAP_ERROR_BREAK) {
      break;  // stop() requested
    }
    if (rc == PCAP_ERROR) {
      EZCAP_LOG_ERROR("pcap dispatch error; stopping backend");
      running_ = false;
      break;
    }
    // rc == 0 (timeout) or packet count: loop.
  }
}

}  // namespace ezcap::capture
