# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
# Copyright (c) Meta Platforms, Inc. and affiliates.

OUTPUT ?= $(abspath .output)
CLANG ?= clang
LIBBPF_SRC := $(abspath ../../../../libbpf/src)
BPFTOOL_SRC := $(abspath ../../../../bpftool/src)
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
UAPI_REL_PATH ?= bpf/uapi
VMLINUX_OUTPUT := $(abspath $(OUTPUT)/bpf/vmlinux)
BPFTOOL_OUTPUT ?= $(abspath $(OUTPUT)/bpftool)
BPFTOOL ?= $(BPFTOOL_OUTPUT)/bootstrap/bpftool
ARCH ?= $(shell uname -m)

CXX_VERSION ?= -std=c++20

INCLUDES := -I$(OUTPUT) -I$(OUTPUT)/$(UAPI_REL_PATH) -I ../../../..
CFLAGS := -g -Wall $(CXX_VERSION)
ALL_LDFLAGS := $(LDFLAGS) $(EXTRA_LDFLAGS) -lstdc++

LIBS := python_discovery

ALL_LDFLAGS += -lelf -lz -lcap

ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n'					\
		      "$(1)"						\
		      "$(patsubst $(abspath $(OUTPUT))/%,%,$(2))"	\
		      "$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory
endif

define allow-override
  $(if $(or $(findstring environment,$(origin $(1))),\
            $(findstring command line,$(origin $(1)))),,\
    $(eval $(1) = $(2)))
endef

$(call allow-override,CC,$(CROSS_COMPILE)cc)
$(call allow-override,LD,$(CROSS_COMPILE)ld)

.PHONY: all
all: $(LIBS)

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT)

$(OUTPUT) $(OUTPUT)/libbpf $(BPFTOOL_OUTPUT) $(VMLINUX_OUTPUT) $(OUTPUT)/$(UAPI_REL_PATH):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

vmlinux:| $(BPFTOOL) $(VMLINUX_OUTPUT)
	$(Q)$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_OUTPUT)/vmlinux.h
.PHONY: vmlinux

# Build libbpf
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf $(OUTPUT)/$(UAPI_REL_PATH)
	$(call msg,LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1		      \
		    OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)		      \
		    INCLUDEDIR= LIBDIR= UAPIDIR=$(UAPI_REL_PATH) \
		    install install_uapi_headers

# Build bpftool
$(BPFTOOL): | $(BPFTOOL_OUTPUT)
	$(call msg,BPFTOOL,$@)
	$(Q)$(MAKE) ARCH= CROSS_COMPILE= OUTPUT=$(BPFTOOL_OUTPUT)/ -C $(BPFTOOL_SRC) bootstrap

SRCS := $(shell find $(SRC_DIRS) -name '*.cpp' -or -name '*.c' -or -name '*.s')
OBJS := $(SRCS:%=$(OUTPUT)/%.o)

$(OUTPUT)/%.cpp.o: %.cpp | $(LIBBPF_OBJ) $(BPFTOOL) vmlinux
	$(call msg,CLANG,$@)
	$(CLANG) $(INCLUDES) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

python_discovery: $(OBJS) | $(LIBBPF_OBJ)
	$(CLANG) -v $(OBJS) -o $(OUTPUT)/$@.a $(ALL_LDFLAGS) --emit-static-lib

# delete failed targets
.DELETE_ON_ERROR:

# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY:
