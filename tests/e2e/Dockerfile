# The browntls end-to-end peer image: the statically linked `browntls-e2e`
# binary and nothing else. `tests/e2e/e2e.py build` compiles the binary on
# the host (cross-compiling where needed) and builds this file in a temporary
# context, so the image can be built for any platform without emulation.
FROM scratch
COPY browntls-e2e /usr/local/bin/browntls-e2e
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/browntls-e2e"]
