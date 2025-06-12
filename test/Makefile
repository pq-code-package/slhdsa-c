# Copyright (c) The slhdsa-c project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT

acvp_cases.sh: ACVP-Server/gen-val/json-files
	python3 test_slhdsa.py > acvp_cases.sh

ACVP-Server/gen-val/json-files:
	git submodule update --init ACVP-Server

clean:
	$(RM) acvp_cases.sh
	$(RM) -f *.pyc *.cprof */*.pyc *.rsp *.log
	$(RM) -rf __pycache__ */__pycache__

