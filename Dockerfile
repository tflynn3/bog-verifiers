FROM golang:1.27-bookworm@sha256:ce59b41415e2524ae99926fe1f37ce48ba8c194dcbd2a56a65436cdcefa2bd34
LABEL org.opencontainers.image.title="bog-verifiers"
WORKDIR /verifier
COPY verify.sh verify.py /verifier/
COPY corpus/ /verifier/corpus/
RUN chmod 0755 /verifier/verify.sh && command -v git && command -v python3 && command -v timeout \
    && test "$(go env GOOS)" = linux && go version | grep -Eq '^go version go1[.]27([.]| )'
USER 65532:65532
ENV HOME=/tmp GOCACHE=/tmp/gocache GOMODCACHE=/tmp/gomodcache GOWORK=off GOTOOLCHAIN=local GOPROXY=off LC_ALL=C.UTF-8
ENTRYPOINT ["/verifier/verify.sh"]
