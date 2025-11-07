FROM debian AS base
RUN apt update && apt install -y build-essential cmake libssl-dev nlohmann-json3-dev libboost-dev libboost-test-dev

FROM base AS builder
WORKDIR /app
COPY . .
RUN mkdir build
WORKDIR /app/build
RUN cmake ..
RUN cmake --build  .

FROM base AS runner
WORKDIR /app
COPY --from=builder /app/build/self_cert_lib.so /usr/lib/
COPY --from=builder /app/build/self-cert .

