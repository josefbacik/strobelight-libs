#!/bin/sh

sudo apt-get install -y linux-tools-common libelf-dev linux-libc-dev \
    clang libbpf-dev make pkg-config libfmt-dev libre2-dev libcap-dev \
    --no-install-recommends

git submodule update --init --recursive
if [ $? -ne 0 ]
then
  echo "submodule update failed"
  exit 1
fi

make -C strobelight/bpf_lib/python
if [ $? -ne 0 ]
then
  echo "library build failed"
  exit 1
fi

make INSTALL_DIR=`pwd`/foo -C strobelight/bpf_lib/python install
if [ $? -ne 0 ]
then
  echo "library install failed"
  exit 1
fi

if [ `ls -l foo/pystacks.bpf.o foo/libpystacks.a | wc -l` -ne 2 ]
then
  echo "install did not place files where expected"
  exit 1
fi

make -C strobelight/bpf_lib/samples/pystacks/
if [ $? -ne 0 ]
then
  echo "sample build failed"
  exit 1
fi

if [ "`strobelight/bpf_lib/samples/pystacks/.output/pystacks_sample`" != "Usage: strobelight/bpf_lib/samples/pystacks/.output/pystacks_sample <PID>" ]
then
  echo "sample run failed"
  exit 1
fi
