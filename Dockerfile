# Multi-stage build for the kms remote signer.
# CGO is required (pkcs11 backend), so we build on a glibc toolchain and run on
# glibc Debian slim.

FROM golang:1.26-bookworm AS build
WORKDIR /src

# Cache module downloads separately from source.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
# KMS_VERSION is overridable; the Makefile's git-describe default is unavailable
# without a .git, so pass a build arg when you want a real version stamp.
ARG KMS_VERSION=0.0.0-docker
RUN mkdir -p /out && make build KMS_VERSION=$KMS_VERSION KMS_OUTPUT=/out/kms

FROM debian:bookworm-slim
# Runtime libraries for pkcs11 are opt-in via PKCS11=true.
#            The packages below cover SoftHSM2 (software token) and OpenSC (smartcard
#            /PIV). For a real HSM, COPY the vendor library in instead and point
#            the config `module:` at it.
ARG PKCS11=false
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
  && if [ "$PKCS11" = "true" ]; then \
  apt-get install -y --no-install-recommends softhsm2 opensc-pkcs11; \
  fi \
  && rm -rf /var/lib/apt/lists/*

COPY --from=build /out/kms /usr/local/bin/kms

# Mount kms.yaml + key file into the home dir and reach the
# gRPC listener on this port (match grpc.listen in the mounted config).
ENV KMS_HOME=/home/kms
RUN useradd --uid 10001 --create-home --home-dir /home/kms kms
USER kms
WORKDIR /home/kms
EXPOSE 9090

ENTRYPOINT ["kms", "--home", "/home/kms", "start"]
