FROM golang:1.27-bookworm@sha256:ce59b41415e2524ae99926fe1f37ce48ba8c194dcbd2a56a65436cdcefa2bd34
LABEL org.opencontainers.image.title="bog-verifiers"
WORKDIR /verifier
ENV GOWORK=off GOTOOLCHAIN=local GOPROXY=off LC_ALL=C.UTF-8
# Verifier Jobs run with a 1-CPU limit. Compiling the standard library from a cold cache
# on every Job pushed `go build ./cmd/bog` past its timeout under load, so bake a warm
# cache built with the same -trimpath flag verify.py uses. Bog has no module dependencies.
RUN mkdir -p /verifier/gocache && GOCACHE=/verifier/gocache go build -trimpath std \
    && chown -R 65532:65532 /verifier/gocache
COPY verify.sh verify.py journeys.py /verifier/
COPY journeys/ /verifier/journeys/
COPY corpus/ /verifier/corpus/
COPY probes/ /verifier/probes/
RUN chmod 0755 /verifier/verify.sh && command -v git && command -v python3 && command -v timeout \
    && test "$(go env GOOS)" = linux && go version | grep -Eq '^go version go1[.]27([.]| )'
USER 65532:65532
ENV HOME=/tmp GOCACHE=/verifier/gocache GOMODCACHE=/tmp/gomodcache
ENTRYPOINT ["/verifier/verify.sh"]
