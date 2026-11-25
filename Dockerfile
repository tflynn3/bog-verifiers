FROM golang:1.27-bookworm@sha256:ce59b41415e2524ae99926fe1f37ce48ba8c194dcbd2a56a65436cdcefa2bd34
RUN command -v git && command -v python3 && command -v timeout
WORKDIR /verifier
COPY --chmod=0755 verify.sh /verifier/verify.sh
COPY verify.py /verifier/verify.py
COPY corpus/replay.ndjson /verifier/corpus/replay.ndjson
USER 65532:65532
ENV HOME=/tmp GOCACHE=/tmp/gocache GOMODCACHE=/tmp/gomodcache GOWORK=off GOTOOLCHAIN=local GOPROXY=off
ENTRYPOINT ["/verifier/verify.sh"]
