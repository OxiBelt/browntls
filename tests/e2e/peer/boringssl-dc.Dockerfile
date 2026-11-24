FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf AS build
RUN apk add --no-cache build-base cmake git go linux-headers ninja perl
WORKDIR /build
RUN git init boringssl \
    && git -C boringssl remote add origin https://boringssl.googlesource.com/boringssl \
    && git -C boringssl fetch --depth 1 origin 4764de153d52fa6a60740c68b2d4cc82f44da915 \
    && git -C boringssl checkout --detach FETCH_HEAD \
    && test "$(git -C boringssl rev-parse HEAD)" = 4764de153d52fa6a60740c68b2d4cc82f44da915 \
    && cmake -S boringssl -B boringssl-build -GNinja -DCMAKE_BUILD_TYPE=Release \
    && cmake --build boringssl-build --target ssl crypto --parallel 4
COPY boringssl-dc.c /build/
RUN cc -std=c11 -O2 -Wall -Wextra -Werror \
      -I/build/boringssl/include /build/boringssl-dc.c \
      /build/boringssl-build/libssl.a \
      /build/boringssl-build/libcrypto.a -pthread -lstdc++ -o /build/boringssl-dc-server

FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
RUN apk add --no-cache openssl python3
COPY --from=build /build/boringssl-dc-server /usr/local/bin/
COPY boringssl-dc-pki.py /usr/local/share/browntls-e2e/
LABEL org.opencontainers.image.source="https://boringssl.googlesource.com/boringssl"
LABEL org.opencontainers.image.revision="4764de153d52fa6a60740c68b2d4cc82f44da915"
