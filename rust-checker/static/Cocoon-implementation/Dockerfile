# syntax=docker/dockerfile:1

FROM ubuntu:20.04

# Install dependencies.
ENV DEBIAN_FRONTEND noninteractive 
RUN apt-get update &&                   \
    apt-get install -y                  \
        build-essential                 \
        curl                            \
        gawk                            \
        git                             \
        jq                              \
        libssl-dev                      \
        m4                              \
        pkg-config                      \
        python3                         \
        python3-pip                     \
        time

RUN python3 -m pip install pandas==1.5.1 scipy==1.9.3

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Set up rust
WORKDIR /usr/src/
ADD rust-toolchain.toml .
RUN rustup toolchain install .

COPY . .

# Run evaluation script
CMD ["/bin/bash"]
