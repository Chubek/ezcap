FROM debian:12 AS build

ARG DEBIAN_FRONTEND=noninteractive
ARG BUILD_WITH_EBPF=OFF
ARG BUILD_TESTS=OFF

WORKDIR /opt/ezcap

RUN set -eux; \
    deps="ca-certificates build-essential cmake git pkg-config make \
      libcap-dev libseccomp-dev libpcap-dev libbpf-dev libelf-dev \
      libsqlite3-dev zlib1g-dev"; \
    if [ "$BUILD_WITH_EBPF" = "ON" ]; then \
      deps="$deps clang llvm bpftool"; \
    fi; \
    apt-get update; \
    apt-get install -y --no-install-recommends $deps; \
    rm -rf /var/lib/apt/lists/*

COPY . .

RUN cmake -S . -B build \
      -DCMAKE_BUILD_TYPE=Release \
      -DBUILD_TESTING=${BUILD_TESTS} \
      -DEZCAP_WITH_EBPF=${BUILD_WITH_EBPF} \
      -DCMAKE_INSTALL_PREFIX=/usr/local && \
    cmake --build build -j"$(nproc)" && \
    cmake --install build && \
    if [ "$BUILD_TESTS" = "ON" ]; then \
      ctest --test-dir build --output-on-failure; \
    fi && \
    mkdir -p /opt/ezcap-artifacts/usr/bin \
             /opt/ezcap-artifacts/usr/local/share/ezcap \
             /opt/ezcap-artifacts/usr/local/lib/ezcap \
             /opt/ezcap-artifacts/etc/ezcap \
             /opt/ezcap-artifacts/usr/share/ezcap/extension \
             /opt/ezcap-artifacts/usr/share/ezcap/drivers; \
    cp /usr/local/bin/ezcap-daemon /usr/local/bin/ezcap-native-host \
       /opt/ezcap-artifacts/usr/bin/; \
    [ -f /etc/ezcap/ezcap.conf.json ] && \
      cp /etc/ezcap/ezcap.conf.json /opt/ezcap-artifacts/etc/ezcap/ || true; \
    if [ -d /usr/local/share/ezcap ]; then \
      cp -r /usr/local/share/ezcap/* /opt/ezcap-artifacts/usr/local/share/ezcap/; \
    fi; \
    if [ -f /usr/local/lib/ezcap/ezcap.bpf.o ]; then \
      cp /usr/local/lib/ezcap/ezcap.bpf.o /opt/ezcap-artifacts/usr/local/lib/ezcap/; \
    fi; \
    if [ -d /opt/ezcap/extension/dist/chromium ] || [ -d /opt/ezcap/extension/dist/firefox ]; then \
      cp -r /opt/ezcap/extension/dist /opt/ezcap-artifacts/usr/share/ezcap/extension/; \
    fi

FROM debian:12-slim AS runtime

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      libcap2 libseccomp2 libpcap0.8 libbpf1 libelf1 libsqlite3-0 zlib1g && \
    rm -rf /var/lib/apt/lists/*

RUN adduser --system --no-create-home --uid 1001 --disabled-password \
    --gecos '' ezcap

WORKDIR /var/lib/ezcap

COPY --from=build /opt/ezcap-artifacts/usr/bin/ezcap-daemon /usr/local/bin/ezcap-daemon
COPY --from=build /opt/ezcap-artifacts/usr/bin/ezcap-native-host /usr/local/bin/ezcap-native-host
COPY --from=build /opt/ezcap-artifacts/usr/local/share/ezcap /usr/share/ezcap
COPY --from=build /opt/ezcap-artifacts/usr/local/lib/ezcap /usr/local/lib/ezcap
COPY --from=build /opt/ezcap-artifacts/etc/ezcap/ezcap.conf.json /etc/ezcap/ezcap.conf.json
COPY --from=build /opt/ezcap-artifacts/usr/share/ezcap/extension /usr/share/ezcap/extension

RUN mkdir -p /run/ezcap /var/lib/ezcap && \
    chown -R ezcap:ezcap /run/ezcap /var/lib/ezcap /usr/share/ezcap /etc/ezcap

VOLUME ["/run/ezcap", "/var/lib/ezcap", "/etc/ezcap"]

USER ezcap

ENTRYPOINT ["/usr/local/bin/ezcap-daemon"]
CMD ["--config", "/etc/ezcap/ezcap.conf.json"]
