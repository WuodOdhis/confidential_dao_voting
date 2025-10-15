FROM debian:12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake pkg-config libsodium-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . .
RUN cmake -S . -B build && cmake --build build -j
ENTRYPOINT ["/app/build/tee-app"]



