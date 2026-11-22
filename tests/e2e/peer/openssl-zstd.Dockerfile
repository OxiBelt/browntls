# The distro OpenSSL disables Zstandard. Enable it in the test peer build.
FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf AS build
RUN apk add --no-cache build-base ca-certificates curl linux-headers perl zstd-dev
WORKDIR /build
RUN curl --fail --location --silent --show-error -o openssl-4.0.3.tar.gz \
      https://github.com/openssl/openssl/releases/download/openssl-4.0.3/openssl-4.0.3.tar.gz \
    && echo '325b5c806167c13b40b1ffeadfe0248197c00eccc4cf123ec1e28d2d2fd216d9  openssl-4.0.3.tar.gz' | sha256sum -c - \
    && tar -xzf openssl-4.0.3.tar.gz
WORKDIR /build/openssl-4.0.3
RUN ./Configure --prefix=/opt/openssl --openssldir=/opt/openssl/ssl --libdir=lib \
      enable-zstd no-sslkeylog no-shared no-tests \
    && make -j8 \
    && make install_sw install_ssldirs
COPY openssl-zstd.c /build/
RUN cc -std=c11 -O2 -Wall -Wextra -Werror -I/opt/openssl/include \
      /build/openssl-zstd.c -L/opt/openssl/lib -lssl -lcrypto -lzstd -pthread -o /build/openssl-zstd

FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
RUN apk add --no-cache zstd-libs
COPY --from=build /opt/openssl/bin/openssl /usr/local/bin/openssl
COPY --from=build /opt/openssl/ssl/openssl.cnf /opt/openssl/ssl/openssl.cnf
COPY --from=build /build/openssl-zstd /usr/local/bin/openssl-zstd
COPY gen-pki.sh /usr/local/share/browntls-e2e/gen-pki.sh
RUN openssl version | grep -E '^OpenSSL 4\.0\.3 ' \
    && ! openssl list -disabled | grep -x ZSTD
