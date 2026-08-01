#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Build the usnmp_exporter docker image and publish it to Docker Hub.
#
# The tag is taken from appVersion in usnmp_exporter.go, so bump it there before
# releasing. Both <version> and latest are pushed.
#
# Usage:
#   ./docker-publish.sh              build and push nuclearcat/usnmp_exporter
#   ./docker-publish.sh --build-only build locally, do not push
#   IMAGE=me/usnmp ./docker-publish.sh
#   PLATFORMS=linux/amd64,linux/arm64 ./docker-publish.sh   (needs docker buildx)

set -eu

IMAGE="${IMAGE:-nuclearcat/usnmp_exporter}"
PLATFORMS="${PLATFORMS:-}"
PUSH=1

for arg in "$@"; do
	case "$arg" in
	--build-only) PUSH=0 ;;
	-h | --help)
		sed -n '2,15p' "$0"
		exit 0
		;;
	*)
		echo "unknown option: $arg" >&2
		exit 1
		;;
	esac
done

cd "$(dirname "$0")"

VERSION="${VERSION:-$(sed -n 's/^const appVersion = "\(.*\)"$/\1/p' usnmp_exporter.go)}"
if [ -z "$VERSION" ]; then
	echo "cannot determine version from usnmp_exporter.go" >&2
	exit 1
fi

echo "Building $IMAGE:$VERSION"

if [ -n "$PLATFORMS" ]; then
	# Multi-arch images cannot be kept in the local docker image store, buildx
	# has to push them straight to the registry.
	if [ "$PUSH" -eq 0 ]; then
		echo "--build-only is not supported together with PLATFORMS" >&2
		exit 1
	fi
	docker buildx build \
		--platform "$PLATFORMS" \
		-t "$IMAGE:$VERSION" \
		-t "$IMAGE:latest" \
		--push .
	echo "Pushed $IMAGE:$VERSION and $IMAGE:latest for $PLATFORMS"
	exit 0
fi

docker build -t "$IMAGE:$VERSION" -t "$IMAGE:latest" .

if [ "$PUSH" -eq 0 ]; then
	echo "Built $IMAGE:$VERSION and $IMAGE:latest (not pushed)"
	exit 0
fi

docker push "$IMAGE:$VERSION"
docker push "$IMAGE:latest"
echo "Pushed $IMAGE:$VERSION and $IMAGE:latest"
