FROM --platform=linux/amd64 ubuntu:22.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential clang

COPY . /repo
WORKDIR /repo
RUN ./configure --prefix=/install
RUN make -j8
RUN make install
RUN clang /repo/mayhem/fuzz_strtolower.cpp -fsanitize=fuzzer,address -L /repo/ -lsyscom -o /fuzz

FROM ubuntu:22.04 as package
COPY --from=builder /install /install
COPY --from=builder /fuzz /fuzz_strtolower
