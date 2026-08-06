include ../../common.mk

.PHONY: all
all: build

.PHONY: build
build:
	${DOCKER_RUN} go build -o ./watcher ../../cmd/multinet-monitor
