# Copyright (c) The slhdsa-c project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT

.PHONY: test

CSRC	=	$(wildcard *.c)
OBJS	= 	$(CSRC:.c=.o)

XTEST	?=	xfips205
XTESTC	?=	test/xfips205.c

CC 		=	gcc
CFLAGS	:=	-Wall \
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
		-pedantic

LDLIBS	+=

$(XTEST):	$(OBJS)
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $(OBJS) $(XTESTC) $(LDLIBS)

%.o:	%.[cS]
	$(CC) $(CFLAGS) -c $^ -o $@

# without gnu parallel: bash test/acvp_cases.sh | tee test.log
test:	$(XTEST) test/acvp_cases.sh
	cat test/acvp_cases.sh | parallel --pipe bash | tee test.log
	@echo "=== test summary ==="
	@echo "PASS:" `grep -c PASS test.log`
	@echo "SKIP:" `grep -c SKIP test.log`
	@echo "FAIL:" `grep -c FAIL test.log`

test/acvp_cases.sh:
	cd test && $(MAKE) acvp_cases.sh

clean:
	$(RM) -rf $(XTEST) $(OBJS) *.rsp *.req *.log
	cd test && $(MAKE) clean
