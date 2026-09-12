#include <ezcap/ipc_protocol.hpp>

#include <string_view>

namespace ezcap::ipc {

const char* operation_name(Operation op) noexcept {
  switch (op) {
    case Operation::Hello:
      return "hello";
    case Operation::GetStatus:
      return "get_status";
    case Operation::Subscribe:
      return "subscribe";
    case Operation::Unsubscribe:
      return "unsubscribe";
    case Operation::SetPolicy:
      return "set_policy";
    case Operation::GetPolicy:
      return "get_policy";
    case Operation::Shutdown:
      return "shutdown";
  }
  return "";
}

bool operation_from_name(const std::string& name, Operation& out) noexcept {
  // Exact match: the wire enum is lowercase and unknown values must never
  // resolve to a default handler.
  if (name == "hello") {
    out = Operation::Hello;
  } else if (name == "get_status") {
    out = Operation::GetStatus;
  } else if (name == "subscribe") {
    out = Operation::Subscribe;
  } else if (name == "unsubscribe") {
    out = Operation::Unsubscribe;
  } else if (name == "set_policy") {
    out = Operation::SetPolicy;
  } else if (name == "get_policy") {
    out = Operation::GetPolicy;
  } else if (name == "shutdown") {
    out = Operation::Shutdown;
  } else {
    return false;
  }
  return true;
}

}  // namespace ezcap::ipc
