FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        can-utils \
        iproute2 \
        kmod \
        python3 \
        python3-pip \
        python3-venv \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work
COPY . /work

# Bringing up vcan loads a kernel module, which needs host privileges, so run the
# container with --privileged (or --cap-add=NET_ADMIN) and then:
#   docker/setup-vcan.sh vcan0
CMD ["/bin/bash"]
