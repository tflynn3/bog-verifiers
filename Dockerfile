FROM golang:1.27-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates python3 curl && rm -rf /var/lib/apt/lists/*
WORKDIR /verifier
COPY verify.sh /verifier/verify.sh
RUN chmod +x /verifier/verify.sh
USER 65532:65532
ENV HOME=/tmp GOCACHE=/tmp/gocache GOMODCACHE=/tmp/gomodcache
ENTRYPOINT ["/verifier/verify.sh"]
