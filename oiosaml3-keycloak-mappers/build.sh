#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Magenta ApS <info@magenta.dk>
# SPDX-License-Identifier: AGPL-3.0-only
#
# Runs the unit tests and builds target/oiosaml3-mappers.jar.
# Copy that JAR into Keycloak's providers/ directory (see README.md).
#
# Extra arguments go to Maven, e.g.
#   ./build.sh -DskipTests
#   ./build.sh -Dkeycloak.version=26.4.0
#   PROVIDERS_DIR=/opt/keycloak/providers ./build.sh   # also install the JAR
#
# Uses a Maven container when mvn is not installed locally, so the build needs
# nothing on the host but Docker (or Podman).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
jar="$here/target/oiosaml3-mappers.jar"

if command -v mvn >/dev/null 2>&1; then
    (cd "$here" && mvn -B package "$@")
else
    runtime=docker
    if ! command -v docker >/dev/null 2>&1; then
        if command -v podman >/dev/null 2>&1; then
            runtime=podman
        else
            echo "Neither mvn, docker nor podman found; install one of them." >&2
            exit 1
        fi
    fi
    # Share the cache a native mvn would use.
    cache="${MAVEN_CACHE_DIR:-$HOME/.m2}"
    mkdir -p "$cache"

    # Run as the invoking user, or target/ comes out root-owned. Rootless
    # podman already maps the container root to this user, so it must NOT
    # get the flag.
    as_user=()
    if [ "$runtime" = docker ]; then
        as_user=(--user "$(id -u):$(id -g)")
    fi

    # A non-root user has no writable /root, so Maven's home moves with it.
    "$runtime" run --rm \
        "${as_user[@]}" \
        -v "$here":/work:Z \
        -v "$cache":/var/maven/.m2:Z \
        -e HOME=/var/maven \
        -e MAVEN_CONFIG=/var/maven/.m2 \
        -w /work \
        maven:3.9-eclipse-temurin-21 mvn -B -Duser.home=/var/maven package "$@"
fi

echo "Built $jar"

if [ -n "${PROVIDERS_DIR:-}" ]; then
    cp "$jar" "$PROVIDERS_DIR/"
    echo "Installed into $PROVIDERS_DIR"
fi
