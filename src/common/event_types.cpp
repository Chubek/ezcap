#include <ezcap/event_types.hpp>

#include <string_view>

namespace ezcap {

namespace {

bool equals_ci(std::string_view a, std::string_view b) noexcept {
  if (a.size() != b.size()) return false;
  for (std::size_t i = 0; i < a.size(); ++i) {
    const char ca = a[i] >= 'A' && a[i] <= 'Z'
                        ? static_cast<char>(a[i] - 'A' + 'a')
                        : a[i];
    const char cb = b[i] >= 'A' && b[i] <= 'Z'
                        ? static_cast<char>(b[i] - 'A' + 'a')
                        : b[i];
    if (ca != cb) return false;
  }
  return true;
}

}  // namespace

ConfidenceBand confidence_band(double confidence) noexcept {
  if (confidence >= 0.90) return ConfidenceBand::Direct;
  if (confidence >= 0.70) return ConfidenceBand::Strong;
  if (confidence >= 0.40) return ConfidenceBand::Probable;
  return ConfidenceBand::Weak;
}

const char* event_type_name(EventType type) noexcept {
  switch (type) {
    case EventType::Connection:
      return "connection";
    case EventType::Dns:
      return "dns";
    case EventType::Navigation:
      return "navigation";
    case EventType::Process:
      return "process";
    case EventType::Status:
      return "status";
    case EventType::Error:
      return "error";
  }
  return "error";
}

bool event_type_from_name(const std::string& name, EventType& out) noexcept {
  if (equals_ci(name, "connection")) {
    out = EventType::Connection;
  } else if (equals_ci(name, "dns")) {
    out = EventType::Dns;
  } else if (equals_ci(name, "navigation")) {
    out = EventType::Navigation;
  } else if (equals_ci(name, "process")) {
    out = EventType::Process;
  } else if (equals_ci(name, "status")) {
    out = EventType::Status;
  } else if (equals_ci(name, "error")) {
    out = EventType::Error;
  } else {
    return false;
  }
  return true;
}

const char* event_source_name(EventSource source) noexcept {
  switch (source) {
    case EventSource::Ebpf:
      return "ebpf";
    case EventSource::Pcap:
      return "pcap";
    case EventSource::Browser:
      return "browser";
  }
  return "pcap";
}

bool event_source_from_name(const std::string& name, EventSource& out) noexcept {
  if (equals_ci(name, "ebpf")) {
    out = EventSource::Ebpf;
  } else if (equals_ci(name, "pcap")) {
    out = EventSource::Pcap;
  } else if (equals_ci(name, "browser")) {
    out = EventSource::Browser;
  } else {
    return false;
  }
  return true;
}

const char* transport_name(Transport transport) noexcept {
  switch (transport) {
    case Transport::Tcp:
      return "tcp";
    case Transport::Udp:
      return "udp";
    case Transport::Icmp:
      return "icmp";
    case Transport::Other:
      return "other";
  }
  return "other";
}

bool transport_from_name(const std::string& name, Transport& out) noexcept {
  if (equals_ci(name, "tcp")) {
    out = Transport::Tcp;
  } else if (equals_ci(name, "udp")) {
    out = Transport::Udp;
  } else if (equals_ci(name, "icmp")) {
    out = Transport::Icmp;
  } else if (equals_ci(name, "other")) {
    out = Transport::Other;
  } else {
    return false;
  }
  return true;
}

const char* direction_name(Direction direction) noexcept {
  switch (direction) {
    case Direction::Inbound:
      return "inbound";
    case Direction::Outbound:
      return "outbound";
    case Direction::Unknown:
      return "unknown";
  }
  return "unknown";
}

bool direction_from_name(const std::string& name, Direction& out) noexcept {
  if (equals_ci(name, "inbound")) {
    out = Direction::Inbound;
  } else if (equals_ci(name, "outbound")) {
    out = Direction::Outbound;
  } else if (equals_ci(name, "unknown")) {
    out = Direction::Unknown;
  } else {
    return false;
  }
  return true;
}

const char* confidence_band_name(ConfidenceBand band) noexcept {
  switch (band) {
    case ConfidenceBand::Weak:
      return "weak";
    case ConfidenceBand::Probable:
      return "probable";
    case ConfidenceBand::Strong:
      return "strong";
    case ConfidenceBand::Direct:
      return "direct";
  }
  return "weak";
}

}  // namespace ezcap
