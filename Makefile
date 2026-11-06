# Copyright (c) The slhdsa-c project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT

.PHONY: test func

CSRC	=	$(wildcard *.c)
OBJS	= 	$(CSRC:.c=.o)

XTEST	?=	xfips205
XTESTC	?=	test/xfips205.c

XFUNC	?=	test_slhdsa
XFUNCC	=	test/src/test_slhdsa.c test/notrandombytes/notrandombytes.c

CROSS_PREFIX ?=
CC      ?= gcc
CC      := $(CROSS_PREFIX)$(CC)
CFLAGS  :=	-Wall \
		-Wextra \
		-Werror=unused-result \
		-Wpedantic \
		-Werror \
		-Wmissing-prototypes \
		-Wshadow \
		-Wpointer-arith \
		-Wredundant-decls \
		-Wno-long-long \
		-Wno-unknown-pragmas \
		-O3 \
		-fomit-frame-pointer \
		-std=c99 \
		-pedantic \
		$(CFLAGS)

LDLIBS	+=

$(XTEST):	$(OBJS)
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $(OBJS) $(XTESTC) $(LDLIBS)

$(XFUNC):	$(OBJS) $(XFUNCC)
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $(OBJS) $(XFUNCC) $(LDLIBS)

%.o:	%.[cS]
	$(CC) $(CFLAGS) -c $^ -o $@

test: $(XTEST)
	EXEC_WRAPPER="$(EXEC_WRAPPER)" python3 test/acvp_client.py

func: $(XFUNC)
	$(EXEC_WRAPPER) ./$(XFUNC)

clean:
	$(RM) -rf $(XTEST) $(XFUNC) $(OBJS) *.rsp *.req *.log
	cd test && $(MAKE) clean
