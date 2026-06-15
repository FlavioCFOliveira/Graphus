#!/bin/sh
# Graphus container entrypoint.
#
# Responsibilities (run as root, then drop privileges):
#   1. Make the mounted data directory writable by the unprivileged `graphus`
#      user (a freshly mounted host volume is often root-owned).
#   2. Provision a per-deployment random JWT secret on first boot (persisted on
#      the volume) so the REST listener has a real secret without the operator
#      having to supply one — unless GRAPHUS_JWT_SECRET is already set.
#   3. Provision a self-signed TLS certificate on first boot (persisted on the
#      volume) so the Bolt-TCP and REST listeners can run encrypted out of the
#      box — unless GRAPHUS_TLS_CERT_PATH / GRAPHUS_TLS_KEY_PATH are already set.
#      Bolt-TCP always requires TLS; this makes the image work with zero config.
#   4. Drop to the `graphus` user via gosu and exec the server.
#
# It also passes through arbitrary commands (e.g. an interactive `sh`), so
# `docker run --rm -it graphus sh` drops you into the container for inspection.
set -eu

DATA_DIR="${GRAPHUS_DATA_DIR:-/data}"

# If no command was given, or the first token is a flag/config path, run the
# server. Otherwise (e.g. `graphus-cli`, `sh`) honour the requested command.
if [ "$#" -eq 0 ]; then
    set -- graphus-server
elif [ "${1#-}" != "$1" ]; then
    set -- graphus-server "$@"
fi

if [ "$1" = "graphus-server" ] && [ "$(id -u)" = "0" ]; then
    # Ensure the data directory exists and is owned by the unprivileged user.
    mkdir -p "$DATA_DIR"
    # Only chown the top-level mount point (fast); the server creates its
    # store/socket beneath it as the graphus user.
    chown graphus:graphus "$DATA_DIR" 2>/dev/null || true

    # Provision a durable, per-deployment JWT secret unless one was supplied.
    if [ -z "${GRAPHUS_JWT_SECRET:-}" ]; then
        SECRET_FILE="$DATA_DIR/.jwt_secret"
        if [ ! -s "$SECRET_FILE" ]; then
            # 32 random bytes, hex-encoded.
            od -An -tx1 -N32 /dev/urandom | tr -d ' \n' > "$SECRET_FILE"
            chown graphus:graphus "$SECRET_FILE" 2>/dev/null || true
            chmod 600 "$SECRET_FILE" 2>/dev/null || true
        fi
        GRAPHUS_JWT_SECRET="$(cat "$SECRET_FILE")"
        export GRAPHUS_JWT_SECRET
    fi

    # Provision a durable, self-signed TLS certificate unless one was supplied.
    # Bolt-TCP always requires TLS, and REST is served over TLS too; this lets
    # the image run encrypted with zero configuration. The certificate is
    # self-signed — clients connect with bolt+ssc:// (Bolt) or curl -k (REST).
    if [ -z "${GRAPHUS_TLS_CERT_PATH:-}" ] && [ -z "${GRAPHUS_TLS_KEY_PATH:-}" ]; then
        TLS_DIR="$DATA_DIR/tls"
        CERT_FILE="$TLS_DIR/cert.pem"
        KEY_FILE="$TLS_DIR/key.pem"
        if [ ! -s "$CERT_FILE" ] || [ ! -s "$KEY_FILE" ]; then
            mkdir -p "$TLS_DIR"
            openssl req -x509 -newkey rsa:2048 -nodes \
                -keyout "$KEY_FILE" -out "$CERT_FILE" \
                -days 3650 -subj "/CN=graphus-local" \
                -addext "subjectAltName=DNS:localhost,DNS:graphus,IP:127.0.0.1" \
                >/dev/null 2>&1
            chown -R graphus:graphus "$TLS_DIR" 2>/dev/null || true
            chmod 600 "$KEY_FILE" 2>/dev/null || true
        fi
        export GRAPHUS_TLS_CERT_PATH="$CERT_FILE"
        export GRAPHUS_TLS_KEY_PATH="$KEY_FILE"
    fi

    # Re-exec as the unprivileged user, preserving the environment.
    exec gosu graphus "$@"
fi

exec "$@"
