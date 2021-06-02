FROM ubuntu:18.04

RUN apt-get update && apt-get -q install -y curl \
  iperf3 \
  gcc \
  pkg-config \
  zip \
  unzip \
  g++ \
  zlib1g-dev \
  python3 \
  wget \
  libtool \
  cmake \
  clang-format-8 \
  automake \
  autoconf \
  make \
  ninja-build \
  curl \
  virtualenv \
  golang-go \
  git

RUN go get -u github.com/bazelbuild/buildtools/buildifier

RUN echo "deb [arch=amd64] https://storage.googleapis.com/bazel-apt stable jdk1.8" | tee /etc/apt/sources.list.d/bazel.list
RUN curl https://bazel.build/bazel-release.pub.gpg | apt-key add -

RUN apt-get update && apt-get -q install -y bazel

RUN cd /usr/local/share && git clone https://github.com/envoyproxy/envoy.git
RuN cd /usr/local/share/envoy && git checkout v1.11.0
RUN cd /usr/local/share/envoy && \
  bazel --bazelrc=/dev/null build --define boringssl=fips -c opt //source/exe:envoy-static.stripped
RUN ln -s /usr/local/share/envoy/bazel-bin/source/exe/envoy-static /usr/local/bin/envoy
