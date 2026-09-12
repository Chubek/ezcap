# Development guide

## Prerequisites

- Linux, kernel with BTF (`/sys/kernel/btf/vmlinux`) for the eBPF backend
- CMake ≥ 3.24, a C++20 compiler (GCC 12+ or Clang 15+)
- System packages: `libpcap`, `libbpf`, `libcap`, `libseccomp`, `spdlog`,
  `sqlite` (headers + lib)
- Bundled as submodules: `nlohmann/json` (and `spdlog`/`fmt` as fallback
  if the system lacks them)
- Node.js ≥ 18 for the extension build (TypeScript only; no runtime deps)
- Optional: `clang` with BPF target + `bpftool` for eBPF; `clang-format`
  and `clang-tidy` for linting

```sh
git submodule update --init --recursive
```

## Building the daemon

```sh
cmake --preset default          # or: debug, release, no-ebpf, asan
cmake --build --preset default
ctest --preset default
```

Presets (see `CMakePresets.json`):

| Preset | Notes |
|---|---|
| `default` | eBPF enabled when toolchain detected, tests on |
| `debug` / `release` | build type variants |
| `no-ebpf` | pcap-only build (for hosts without the BPF toolchain) |
| `asan` | debug + address/undefined-behavior sanitizers |

CMake options: `-DEZCAP_WITH_EBPF=OFF`, `-DEZCAP_BUILD_TESTS=OFF`,
`-DEZCAP_ENABLE_LTO=ON`, `-DEZCAP_EXTENSION_ID_CHROMIUM=<id>`,
`-DEZCAP_EXTENSION_ID_FIREFOX=<id>`.

Note: ninja is not used; the presets default to Unix Makefiles. Pass
`-G Ninja` if you prefer and have it installed.

## Building the extension

The extension is built as part of the CMake build (`add_subdirectory(extension)`),
so `cmake --build --preset default` also produces `extension/dist/chromium` and
`extension/dist/firefox`. If `node`/`npm` (or a TypeScript compiler) is missing,
the extension target is skipped with a status message and the rest of ezcap
still builds.

To additionally package browser-loadable archives:

```sh
cmake --preset default -DCMAKE_BUILD_EXT_ARCHIVE=ON
cmake --build --preset default
```

This produces `build/extension/ezcap-chromium-<version>.zip` and
`build/extension/ezcap-firefox-<version>.xpi`, each containing the manifest at
the archive root. The option is `OFF` by default.

Builds can also be run directly, without CMake:

```sh
cd extension
npm install        # devDependency: typescript
npm run check      # type-check only
npm run build      # builds both browsers into dist/chromium, dist/firefox
```

`build.mjs` compiles with `tsc`, then assembles each browser's `dist/`
directory: manifest, compiled JS, shared styles/icons, and generated
popup/options HTML. Load the resulting directory via your browser's
"load unpacked".

## Project layout

```
protocol/        JSON Schemas + examples (source of truth for wire formats)
include/ezcap/   shared C++ headers (event, ipc, policy, error types)
ebpf/            eBPF programs + shared event struct header
src/             daemon sources (capture, attribution, policy, ipc, storage, security)
native_host/     native messaging bridge
extension/       cross-browser TypeScript extension
tests/           unit + integration tests (no external framework)
packaging/       systemd unit, tmpfiles, sample config, udev example, debian notes
scripts/         build/format/lint/package helpers
docs/            the documents you are reading
```

## Testing

Tests are plain executables that return non-zero on failure — no gtest
dependency, so the suite runs anywhere the daemon builds.

```sh
ctest --preset default              # all tests
./build/tests/test_redactor         # one test directly
```

- `tests/unit/` — packet parser, IPC codec, redactor, policy engine,
  correlator (incl. confidence cap).
- `tests/integration/` — native host framing round-trip, daemon IPC
  (hello/subscribe/status over a real socket), capture pipeline
  end-to-end with synthetic packets.

## Linting & formatting

```sh
scripts/lint.sh        # clang-tidy (if installed) + tsc --noEmit
scripts/format.sh      # clang-format over C/C++ (also supports --check)
```

## eBPF development

```sh
scripts/generate-vmlinux.sh   # regenerates ebpf/generated/vmlinux.h
scripts/build-ebpf.sh         # compiles the .bpf.c programs standalone
```

Remember: eBPF programs read only metadata fields, emit versioned
compact structs, and never touch payload bytes. If you find yourself
wanting `bpf_probe_read` on packet *data*, stop — that is out of scope
by design.

## Configuration

The daemon reads `--config` (default `/etc/ezcap/ezcap.conf.json`).
Validate without running: `ezcap-daemon --check-config <path>`. Unknown
keys, relative paths, and out-of-range values are rejected. See
`packaging/systemd/ezcap.conf.sample.json`.

## Installing

```sh
cmake --install build --prefix /usr/local
/usr/local/share/ezcap/install-linux.sh    # register native host manifests
```
