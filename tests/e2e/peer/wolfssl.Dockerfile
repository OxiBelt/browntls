FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf AS build
RUN apk add --no-cache build-base cmake curl
WORKDIR /build
# wolfSSL v5.9.4-stable, built for use in the isolated test network only.
RUN curl -fsSL https://codeload.github.com/wolfSSL/wolfssl/tar.gz/3c5eead44904df64e6a5a1f4ebdce377d35a849a -o wolfssl.tar.gz \
    && echo '20fceb75ecac0fdb241f6d683e8cd1b579db0297f6d506d13eca9656262d72a5  wolfssl.tar.gz' | sha256sum -c - \
    && mkdir source \
    && tar -xzf wolfssl.tar.gz -C source --strip-components=1 \
    && cmake -S source -B out -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF \
        -DWOLFSSL_DTLS=yes -DWOLFSSL_DTLS13=yes -DWOLFSSL_DTLS_CID=yes -DWOLFSSL_EXAMPLES=no \
        -DWOLFSSL_MLKEM=yes -DWOLFSSL_PQC_HYBRIDS=yes -DWOLFSSL_CURVE25519=yes \
        -DWOLFSSL_DTLS_CH_FRAG=yes -DWOLFSSL_DTLS_MTU=yes \
        -DWOLFSSL_PSK=yes -DWOLFSSL_CERT_WITH_EXTERN_PSK=yes \
        -DWOLFSSL_SECURE_RENEGOTIATION=yes \
        -DCMAKE_C_FLAGS=-DWOLFSSL_COOKIE_LEN=128 \
        -DWOLFSSL_CRYPT_TESTS=no -DWOLFSSL_OPENSSLEXTRA=yes \
    && cmake --build out --parallel 4
COPY wolfssl-dtls.c .
COPY wolfssl-extern-psk.c .
RUN cc -std=c11 -Wall -Wextra -Werror -Iout -Isource wolfssl-dtls.c \
    out/libwolfssl.a -pthread -lm -o wolfssl-dtls \
    && cc -std=c11 -Wall -Wextra -Werror -Iout -Isource wolfssl-extern-psk.c \
    out/libwolfssl.a -pthread -lm -o wolfssl-extern-psk

FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
LABEL org.opencontainers.image.source="https://github.com/wolfSSL/wolfssl"
LABEL org.opencontainers.image.revision="3c5eead44904df64e6a5a1f4ebdce377d35a849a"
RUN apk add --no-cache openssl
COPY --from=build /build/wolfssl-dtls /usr/local/bin/wolfssl-dtls
COPY --from=build /build/wolfssl-extern-psk /usr/local/bin/wolfssl-extern-psk
COPY --from=build /build/source/COPYING /usr/local/share/licenses/wolfssl/COPYING
COPY gen-pki.sh /usr/local/share/browntls-e2e/
