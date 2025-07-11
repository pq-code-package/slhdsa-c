#!/usr/bin/env python3
# Copyright (c) The slhdsa-c project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT

"""SLH-DSA ACVP client."""

import argparse
import json
import os
import subprocess
import sys
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# === ACVP file downloading ===

def download_acvp_files(version="v1.1.0.40"):
    """Download ACVP test files for the specified version if not present."""
    base_url = f"https://raw.githubusercontent.com/usnistgov/ACVP-Server/{version}/gen-val/json-files"

    # Files we need to download
    files_to_download = [
        "SLH-DSA-keyGen-FIPS205/prompt.json",
        "SLH-DSA-keyGen-FIPS205/expectedResults.json",
        "SLH-DSA-sigGen-FIPS205/prompt.json",
        "SLH-DSA-sigGen-FIPS205/expectedResults.json",
        "SLH-DSA-sigVer-FIPS205/prompt.json",
        "SLH-DSA-sigVer-FIPS205/expectedResults.json",
        "SLH-DSA-sigVer-FIPS205/internalProjection.json"
    ]

    # Create directory structure
    data_dir = Path(f"test/.acvp-data/{version}/files")
    data_dir.mkdir(parents=True, exist_ok=True)

    for file_path in files_to_download:
        local_file = data_dir / file_path
        local_file.parent.mkdir(parents=True, exist_ok=True)

        if not local_file.exists():
            url = f"{base_url}/{file_path}"
            print(f"Downloading {file_path}...", file=sys.stderr)
            try:
                urllib.request.urlretrieve(url, local_file)
                # Verify the file is valid JSON
                with open(local_file, 'r') as f:
                    json.load(f)
            except json.JSONDecodeError as e:
                print(f"Error: Downloaded file {file_path} is not valid JSON: {e}", file=sys.stderr)
                local_file.unlink(missing_ok=True)  # Remove corrupted file
                return False
            except Exception as e:
                print(f"Error downloading {file_path}: {e}", file=sys.stderr)
                local_file.unlink(missing_ok=True)  # Remove partial file
                return False

    return True

# === JSON parsing functions  ===

def slhdsa_load_keygen(req_fn, res_fn):
    with open(req_fn) as f:
        keygen_req = json.load(f)
    with open(res_fn) as f:
        keygen_res = json.load(f)

    keygen_kat = []
    for qtg in keygen_req['testGroups']:
        alg = qtg['parameterSet']
        tgid = qtg['tgId']

        rtg = None
        for tg in keygen_res['testGroups']:
            if tg['tgId'] == tgid:
                rtg = tg['tests']
                break

        for qt in qtg['tests']:
            tcid = qt['tcId']
            for t in rtg:
                if t['tcId'] == tcid:
                    qt.update(t)
            qt['parameterSet'] = alg
            keygen_kat += [qt]
    return keygen_kat

def slhdsa_load_siggen(req_fn, res_fn):
    with open(req_fn) as f:
        siggen_req = json.load(f)
    with open(res_fn) as f:
        siggen_res = json.load(f)

    siggen_kat = []
    for qtg in siggen_req['testGroups']:
        alg = qtg['parameterSet']
        det = qtg['deterministic']
        pre = False
        if 'preHash' in qtg and qtg['preHash'] == 'preHash':
                pre = True
        ifc = None
        if 'signatureInterface' in qtg:
            ifc = qtg['signatureInterface']
        tgid = qtg['tgId']

        rtg = None
        for tg in siggen_res['testGroups']:
            if tg['tgId'] == tgid:
                rtg = tg['tests']
                break

        for qt in qtg['tests']:
            tcid = qt['tcId']
            for t in rtg:
                if t['tcId'] == tcid:
                    qt.update(t)
            qt['parameterSet'] = alg
            qt['deterministic'] = det
            if 'preHash' not in qt:
                qt['preHash'] = pre
            if 'context' not in qt:
                qt['context'] = ''
            qt['signatureInterface'] = ifc
            siggen_kat += [qt]
    return siggen_kat

def slhdsa_load_sigver(req_fn, res_fn, int_fn):
    with open(req_fn) as f:
        sigver_req = json.load(f)
    with open(res_fn) as f:
        sigver_res = json.load(f)
    with open(int_fn) as f:
        sigver_int = json.load(f)

    sigver_kat = []
    for qtg in sigver_req['testGroups']:
        alg = qtg['parameterSet']
        tgid = qtg['tgId']
        pre = False
        if 'preHash' in qtg and qtg['preHash'] == 'preHash':
                pre = True
        ifc = None
        if 'signatureInterface' in qtg:
            ifc = qtg['signatureInterface']

        rtg = None
        for tg in sigver_res['testGroups']:
            if tg['tgId'] == tgid:
                rtg = tg['tests']
                break

        itg = None
        for tg in sigver_int['testGroups']:
            if tg['tgId'] == tgid:
                itg = tg['tests']
                break

        for qt in qtg['tests']:
            pk   = qt['pk']
            tcid = qt['tcId']
            for t in rtg:
                if t['tcId'] == tcid:
                    qt.update(t)
            # message, signature in this file overrides prompts
            for t in itg:
                if t['tcId'] == tcid:
                    qt.update(t)
            qt['parameterSet'] = alg
            qt['pk'] = pk
            if 'preHash' not in qt:
                qt['preHash'] = pre
            qt['signatureInterface'] = ifc
            sigver_kat += [qt]
    return sigver_kat

# === Test execution ===

def run_command(cmd):
    """Run a single test command and return result."""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return (result.returncode, result.stdout, result.stderr)
    except Exception as e:
        return (-1, "", str(e))

def run_test_kat(test_type, kat, jobs, xbin='./xfips205'):
    """Run test KAT in parallel."""
    passed = 0
    failed = 0

    def build_command(x):
        s = xbin
        for t in x:
            if x[t] != "":
                s += f' -{t} "{x[t]}"'
        s += f' {test_type}'
        return s

    # Run tests in parallel
    with ThreadPoolExecutor(max_workers=jobs) as executor:
        futures = [executor.submit(run_command, build_command(x)) for x in kat]

        for future in as_completed(futures):
            returncode, stdout, stderr = future.result()

            if returncode == 0:
                passed += 1
                if "PASS" in stdout:
                    print(stdout.strip())
            else:
                failed += 1
                if stderr:
                    print(f"Error: {stderr}")

    return passed, failed

def main():
    parser = argparse.ArgumentParser(description="SLH-DSA ACVP test runner")
    parser.add_argument("--jobs", "-j", type=int, default=os.cpu_count() or 4,
                       help="Number of parallel jobs (default: auto-detect CPU cores)")
    parser.add_argument("--version", "-v", default="v1.1.0.40",
                       help="ACVP test vector version (default: v1.1.0.40)")

    args = parser.parse_args()

    print(f"Using ACVP test vectors version {args.version}", file=sys.stderr)

    # Download files if needed
    if not download_acvp_files(args.version):
        print("Failed to download ACVP test files", file=sys.stderr)
        return 1

    try:
        json_path = f"test/.acvp-data/{args.version}/files/"

        keygen_kat = slhdsa_load_keygen(
            json_path + 'SLH-DSA-keyGen-FIPS205/prompt.json',
            json_path + 'SLH-DSA-keyGen-FIPS205/expectedResults.json')

        siggen_kat = slhdsa_load_siggen(
            json_path + 'SLH-DSA-sigGen-FIPS205/prompt.json',
            json_path + 'SLH-DSA-sigGen-FIPS205/expectedResults.json')

        sigver_kat = slhdsa_load_sigver(
            json_path + 'SLH-DSA-sigVer-FIPS205/prompt.json',
            json_path + 'SLH-DSA-sigVer-FIPS205/expectedResults.json',
            json_path + 'SLH-DSA-sigVer-FIPS205/internalProjection.json')

    except FileNotFoundError as e:
        print(f"Error: Could not find ACVP JSON files: {e}", file=sys.stderr)
        return 1

    total_tests = len(keygen_kat) + len(siggen_kat) + len(sigver_kat)
    print(f"Running {total_tests} tests with {args.jobs} parallel jobs", file=sys.stderr)

    total_passed = 0
    total_failed = 0

    # Run each test type
    passed, failed = run_test_kat('keyGen', keygen_kat, args.jobs)
    total_passed += passed
    total_failed += failed

    passed, failed = run_test_kat('sigGen', siggen_kat, args.jobs)
    total_passed += passed
    total_failed += failed

    passed, failed = run_test_kat('sigVer', sigver_kat, args.jobs)
    total_passed += passed
    total_failed += failed

    print(f"\n=== test summary ===")
    print(f"PASS: {total_passed}")
    print(f"FAIL: {total_failed}")

    if total_failed == 0:
        print("ALL GOOD!")
        return 0
    else:
        return 1

if __name__ == "__main__":
    sys.exit(main())
