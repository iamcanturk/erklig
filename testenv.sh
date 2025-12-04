#!/bin/bash

# ERKLIG Test Environment Manager
# Creates and manages a Docker container with planted malware for testing

set -e

CONTAINER_NAME="erklig-testbed"
IMAGE_NAME="erklig-testbed:latest"

case "$1" in
    build)
        echo "🔨 Building test environment..."
        docker build -t $IMAGE_NAME ./testenv
        echo "✅ Build complete!"
        ;;
    start)
        echo "🚀 Starting test environment..."
        docker run -d --name $CONTAINER_NAME -p 8888:80 $IMAGE_NAME
        echo "✅ Test environment running at http://localhost:8888"
        echo ""
        echo "To scan the container, run:"
        echo "  docker exec -it $CONTAINER_NAME /bin/bash"
        echo "  # Then copy erklig binary and run it"
        echo ""
        echo "Or mount the container filesystem:"
        echo "  docker cp $CONTAINER_NAME:/var/www/html ./testbed_mount"
        echo "  ./erklig ./testbed_mount"
        ;;
    stop)
        echo "🛑 Stopping test environment..."
        docker stop $CONTAINER_NAME 2>/dev/null || true
        docker rm $CONTAINER_NAME 2>/dev/null || true
        echo "✅ Test environment stopped."
        ;;
    scan)
        echo "🔍 Scanning test environment..."
        TEMP_DIR=$(mktemp -d)
        docker cp $CONTAINER_NAME:/var/www/html $TEMP_DIR
        ./erklig "$TEMP_DIR/html"
        rm -rf $TEMP_DIR
        ;;
    shell)
        echo "🐚 Opening shell in test environment..."
        docker exec -it $CONTAINER_NAME /bin/bash
        ;;
    *)
        echo "ERKLIG Test Environment Manager"
        echo ""
        echo "Usage: $0 {build|start|stop|scan|shell}"
        echo ""
        echo "Commands:"
        echo "  build  - Build the Docker image with test malware"
        echo "  start  - Start the test container"
        echo "  stop   - Stop and remove the test container"
        echo "  scan   - Run ERKLIG scan on the container"
        echo "  shell  - Open a shell in the container"
        ;;
esac
