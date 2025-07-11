/*
 * Copyright (c) The slhdsa-c project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/* === ACVP Test wrapper for slhdsa-c */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../slh_dsa.h"
#include "../slh_prehash.h"
#include "../slh_var.h"

static void kat_hex(FILE *fh, const char *label, const uint8_t *x, size_t xlen)
{
  size_t i;

  fprintf(fh, "%s = ", label);
  for (i = 0; i < xlen; i++)
  {
    fprintf(fh, "%02X", x[i]);
  }
  fprintf(fh, "\n");
}

/* test targets */

static const slh_param_t *test_iut[] = {&slh_dsa_shake_128s,
                                        &slh_dsa_shake_128f,
                                        &slh_dsa_shake_192s,
                                        &slh_dsa_shake_192f,
                                        &slh_dsa_shake_256s,
                                        &slh_dsa_shake_256f,
                                        &slh_dsa_sha2_128s,
                                        &slh_dsa_sha2_128f,
                                        &slh_dsa_sha2_192s,
                                        &slh_dsa_sha2_192f,
                                        &slh_dsa_sha2_256s,
                                        &slh_dsa_sha2_256f,
                                        NULL};

/* parsed data args */
char *data_args[][2] = {
    {"additionalRandomness", NULL},
    {"context", NULL},
    {"deferred", NULL},
    {"deterministic", NULL},
    {"hashAlg", NULL},
    {"message", NULL},
    {"parameterSet", NULL},
    {"pk", NULL},
    {"pkSeed", NULL},
    {"preHash", NULL},
    {"reason", NULL},
    {"signature", NULL},
    {"signatureInterface", NULL},
    {"sk", NULL},
    {"skPrf", NULL},
    {"skSeed", NULL},
    {"tcId", NULL},
    {"testPassed", NULL},
    {NULL, NULL},
};

static const char *find_par(const char *name)
{
  int i;

  for (i = 0; data_args[i][0] != NULL; i++)
  {
    if (strcmp(data_args[i][0], name) == 0)
    {
      return data_args[i][1];
    }
  }
  return NULL;
}

static int hex_digit(int ch)
{
  if (ch >= '0' && ch <= '9')
  {
    return ch - '0';
  }
  if (ch >= 'a' && ch <= 'f')
  {
    return ch - 'a' + 10;
  }
  if (ch >= 'A' && ch <= 'F')
  {
    return ch - 'A' + 10;
  }
  return -1;
}

/* parse a pure hex string into bytes. return nonzero on error */
/* buffer needs to be freed by the caller */

static uint8_t *hex_data(size_t *data_sz, const char *hex)
{
  int ch, cl;
  size_t i, l;
  uint8_t *buf;

  if (hex == NULL || data_sz == NULL)
  {
    return NULL;
  }

  *data_sz = 0;

  l = strlen(hex);

  /* need even number of digits */
  if (l % 2 != 0)
  {
    return NULL;
  }
  l /= 2;

  buf = malloc(l);
  if (buf == NULL)
  {
    perror("malloc()");
    exit(-1);
  }

  for (i = 0; i < l; i++)
  {
    ch = hex_digit(hex[2 * i]);
    cl = hex_digit(hex[2 * i + 1]);

    if (ch < 0 || cl < 0)
    {
      free(buf);
      return NULL;
    }
    buf[i] = (ch << 4) | cl;
  }
  *data_sz = l;

  return buf;
}

const char usage[] = "xfips205 -<acvp inputs> [ keyGen | sigGen | sigVer ]\n";
const char *valid_cmds[] = {"keyGen", "sigGen", "sigVer", NULL};

int main(int argc, char **argv)
{
  int fail = 0;
  int skip = 0;

  int i, j;
  int arg_ok = 0;
  const char *cmd = NULL;
  const char *slh_name = NULL;
  const slh_param_t *prm = NULL;
  const char *tcid = NULL;

  char test_id[256] = "(no test id)";
  char test_func[256] = "(no function)";

  if (argc < 2)
  {
    fprintf(stderr, "%s", usage);
    exit(1);
  }

  /* parse arguments */
  for (i = 1; i < argc; i++)
  {
    arg_ok = 0;

    if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0)
    {
      printf("%s\nACVP inputs:", usage);
      for (j = 0; data_args[j][0] != NULL; j++)
      {
        printf(" -%s", data_args[j][0]);
      }
      printf("\n");
      exit(0);
    }

    if (argv[i][0] == '-')
    {
      /* parameters */
      for (j = 0; data_args[j][0] != NULL; j++)
      {
        if (strcmp(data_args[j][0], &argv[i][1]) == 0)
        {
          if (data_args[j][1] != NULL)
          {
            fprintf(stderr, "%s: %s set twice.\n", argv[0], argv[i]);
            exit(1);
          }
          if (i + 1 >= argc)
          {
            fprintf(stderr, "%s: %s parameter missing.\n", argv[0], argv[i]);
            exit(1);
          }
          i++;
          data_args[j][1] = argv[i];

          arg_ok = 1;
          break;
        }
      }
    }
    else
    {
      /* commands */
      for (j = 0; valid_cmds[j] != NULL; j++)
      {
        if (strcmp(argv[i], valid_cmds[j]) == 0)
        {
          if (cmd != NULL)
          {
            fprintf(stderr, "%s: %s; command set twice.\n", argv[0], argv[i]);
            exit(1);
          }
          cmd = valid_cmds[j];
          arg_ok = 1;
          break;
        }
      }
    }

    if (!arg_ok)
    {
      fprintf(stderr, "%s: unknown argument %s\n", argv[0], argv[i]);
      exit(1);
    }
  }

  /* === find the parameter set */
  slh_name = find_par("parameterSet");
  if (slh_name == NULL)
  {
    fprintf(stderr, "%s: parameterSet is not specified\n", argv[0]);
    exit(-1);
  }
  prm = NULL;
  for (i = 0; test_iut[i] != NULL; i++)
  {
    if (strcmp(slh_name, test_iut[i]->alg_id) == 0)
    {
      prm = test_iut[i];
      break;
    }
  }
  if (prm == NULL)
  {
    fprintf(stderr, "%s: unsupported parameterSet %s\n", argv[0], slh_name);
    exit(-1);
  }

  /* test identifier sring */
  tcid = find_par("tcId");
  if (tcid == NULL)
  {
    sprintf(test_id, "%s %s", cmd, prm->alg_id);
  }
  else
  {
    sprintf(test_id, "%s %s [%s]", cmd, prm->alg_id, tcid);
  }

  /* === keyGen */
  if (strcmp(cmd, "keyGen") == 0)
  {
    uint8_t pk_out[2 * SLH_MAX_N] = {0};
    uint8_t sk_out[4 * SLH_MAX_N] = {0};

    uint8_t *sk_seed = NULL;
    size_t sk_seed_sz = 0;
    uint8_t *sk_prf = NULL;
    size_t sk_prf_sz = 0;
    uint8_t *pk_seed = NULL;
    size_t pk_seed_sz = 0;

    uint8_t *pk = NULL;
    size_t pk_sz = 0;
    uint8_t *sk = NULL;
    size_t sk_sz = 0;

    /* mandatory inputs */
    sk_seed = hex_data(&sk_seed_sz, find_par("skSeed"));
    if (sk_seed == NULL || sk_seed_sz != prm->n)
    {
      fprintf(stderr, "keyGen: invalid/missing skSeed\n");
      exit(-1);
    }

    sk_prf = hex_data(&sk_prf_sz, find_par("skPrf"));
    if (sk_prf == NULL || sk_prf_sz != prm->n)
    {
      fprintf(stderr, "keyGen: invalid/missing skPrf\n");
      exit(-1);
    }

    pk_seed = hex_data(&pk_seed_sz, find_par("pkSeed"));
    if (pk_seed == NULL || pk_seed_sz != prm->n)
    {
      fprintf(stderr, "keyGen: invalid/missing pkSeed\n");
      exit(-1);
    }

    /* reference for comparisons (if present) */
    if (find_par("sk") != NULL)
    {
      sk = hex_data(&sk_sz, find_par("sk"));
      if (sk == NULL || sk_sz != slh_sk_sz(prm))
      {
        fprintf(stderr, "keyGen: invalid sk input\n");
        exit(-1);
      }
    }
    if (find_par("pk") != NULL)
    {
      pk = hex_data(&pk_sz, find_par("pk"));
      if (pk == NULL || pk_sz != slh_pk_sz(prm))
      {
        fprintf(stderr, "keyGen: invalid pk input\n");
        exit(-1);
      }
    }

    sprintf(test_func, "slh_keygen_internal()");

    /* run key generation */
    slh_keygen_internal(sk_out, pk_out, sk_seed, sk_prf, pk_seed, prm);


    /* compare outputs (or print if no reference value is given) */
    if (pk == NULL)
    {
      kat_hex(stdout, "pk", pk_out, slh_pk_sz(prm));
    }
    else
    {
      if (memcmp(pk, pk_out, pk_sz) != 0)
      {
        fail++;
      }
    }

    if (sk == NULL)
    {
      kat_hex(stdout, "sk", sk_out, slh_sk_sz(prm));
    }
    else
    {
      if (memcmp(sk, sk_out, sk_sz) != 0)
      {
        fail++;
      }
    }

    /* about to drop local stuff */
    free(sk_seed);
    free(sk_prf);
    free(pk_seed);

    if (pk != NULL)
    {
      free(pk);
    }
    if (sk != NULL)
    {
      free(sk);
    }

    arg_ok = 1;
  }
  else if (strcmp(cmd, "sigGen") == 0)
  {
    /* === sigGen */

    const char *iface = NULL;
    const char *prehash = NULL;
    const char *hashalg = NULL;

    /* mandatory parameters */
    uint8_t *msg = NULL;
    size_t msg_sz = 0;
    uint8_t *sk = NULL;
    size_t sk_sz = 0;
    uint8_t *addrnd = NULL;
    size_t addrnd_sz = 0;
    uint8_t *sig = NULL;
    size_t sig_sz = 0;
    uint8_t *ctx = NULL;
    size_t ctx_sz = 0;
    uint8_t *sig_out = NULL;
    size_t sig_out_sz = 0;

    /* flags */
    int pure = 1;

    prehash = find_par("preHash");
    if (prehash != NULL)
    {
      pure = strcmp(prehash, "False") == 0;
    }

    /* mandatory inputs */
    msg = hex_data(&msg_sz, find_par("message"));
    if (msg == NULL)
    {
      fprintf(stderr, "sigGen: missing/invalid message\n");
      exit(-1);
    }

    sk = hex_data(&sk_sz, find_par("sk"));
    if (sk == NULL || sk_sz != slh_sk_sz(prm))
    {
      fprintf(stderr, "sigGen: missing/invalid sk\n");
      exit(-1);
    }

    /* optional inputs */
    ctx = hex_data(&ctx_sz, find_par("context"));

    sig = hex_data(&sig_sz, find_par("signature"));
    if (sig != NULL && sig_sz != slh_sig_sz(prm))
    {
      fprintf(stderr, "sigGen: invalid signature\n");
      exit(-1);
    }

    addrnd = hex_data(&addrnd_sz, find_par("additionalRandomness"));
    if (addrnd != NULL && addrnd_sz != prm->n)
    {
      fprintf(stderr, "sigGen: invalid additionalRandomness\n");
      exit(-1);
    }

    /* output buffer */
    sig_out = calloc(1, slh_sig_sz(prm));
    if (sig_out == NULL)
    {
      perror("malloc()");
      exit(-1);
    }

    iface = find_par("signatureInterface");
    if (iface != NULL && strcmp(iface, "internal") == 0)
    {
      sprintf(test_func, "slh_sign_internal()");

      /* Algorithm 19: slh_sign_internal(M, SK, addrnd) */
      sig_out_sz = slh_sign_internal(sig_out, msg, msg_sz, sk, addrnd, prm);
    }
    else if (strcmp(iface, "external") == 0)
    {
      if (pure)
      {
        sprintf(test_func, "slh_sign()");

        /* Algorithm 22: slh_sign(M, ctx, SK) */
        sig_out_sz =
            slh_sign(sig_out, msg, msg_sz, ctx, ctx_sz, sk, addrnd, prm);
      }
      else
      {
        hashalg = find_par("hashAlg");
        if (hashalg == NULL)
        {
          fprintf(stderr, "sigGen: missing hashAlg\n");
          exit(-1);
        }
        sprintf(test_func, "hash_slh_sign(%s)", hashalg);

        /* Algorithm 23:  hash_slh_sign(M, ctx, PH, SK) */
        sig_out_sz = hash_slh_sign(sig_out, msg, msg_sz, ctx, ctx_sz, hashalg,
                                   sk, addrnd, prm);
      }
    }
    else
    {
      /* not sure if this ever invoked */
      skip++;
    }

    if (sig == NULL)
    {
      if (sig_out_sz > 0)
      {
        kat_hex(stdout, "sig", sig_out, sig_out_sz);
      }
      else
      {
        skip++;
      }
    }
    else
    {
      if (sig_out_sz == 0)
      {
        skip++;
      }
      else
      {
        if (sig_sz != sig_out_sz || memcmp(sig, sig_out, sig_out_sz) != 0)
        {
          fail++;
        }
      }
    }

    /* free local buffers */
    free(msg);
    free(sk);
    if (addrnd != NULL)
    {
      free(addrnd);
    }
    if (sig != NULL)
    {
      free(sig);
    }
    if (ctx != NULL)
    {
      free(ctx);
    }
    if (sig_out != NULL)
    {
      free(sig_out);
    }
    arg_ok = 1;

    /* === sigVer */
  }
  else if (strcmp(cmd, "sigVer") == 0)
  {
    const char *iface = NULL;
    const char *reason = NULL;
    const char *passed = NULL;
    const char *prehash = NULL;
    const char *hashalg = NULL;

    uint8_t *msg = NULL;
    size_t msg_sz = 0;
    uint8_t *sig = NULL;
    size_t sig_sz = 0;
    uint8_t *pk = NULL;
    size_t pk_sz = 0;
    uint8_t *ctx = NULL;
    size_t ctx_sz = 0;

    int res = 0;
    int exp_res = 1;
    int pure = 1;

    iface = find_par("signatureInterface");
    passed = find_par("testPassed");
    prehash = find_par("preHash");
    reason = find_par("reason");
    prehash = find_par("preHash");

    if (prehash != NULL)
    {
      pure = strcmp(prehash, "False") == 0;
    }

    /* expected result */
    if (passed == NULL)
    {
      printf("[WARN] %s: assuming testPassed == True\n", test_id);
      exp_res = 1;
    }
    else
    {
      exp_res = strcmp(passed, "True") == 0;
    }

    if (iface == NULL)
    {
      printf("[WARN] %s: assuming signatureInterface == internal\n", test_id);
      iface = "internal";
    }

    /* mandatory inputs */
    msg = hex_data(&msg_sz, find_par("message"));
    if (msg == NULL)
    {
      fprintf(stderr, "sigVer: missing/invalid message\n");
      exit(-1);
    }

    pk = hex_data(&pk_sz, find_par("pk"));
    if (pk == NULL || pk_sz != slh_pk_sz(prm))
    {
      fprintf(stderr, "sigVer: missing/invalid pk\n");
      exit(-1);
    }

    sig = hex_data(&sig_sz, find_par("signature"));
    if (sig == NULL)
    {
      fprintf(stderr, "sigVer: missing signature\n");
      exit(-1);
    }

    /* optional */
    ctx = hex_data(&ctx_sz, find_par("context"));

    /* optional inputs */

    if (strcmp(iface, "internal") == 0)
    {
      sprintf(test_func, "slh_verify_internal()");

      /* Algorithm 20: slh_verify_internal(M, SIG, PK) */
      res = slh_verify_internal(msg, msg_sz, sig, sig_sz, pk, prm);
    }
    else if (strcmp(iface, "external") == 0)
    {
      if (pure)
      {
        sprintf(test_func, "slh_verify()");

        /* Algorithm 24 slh_verify(M, SIG, var, PK) */
        res = slh_verify(msg, msg_sz, sig, sig_sz, ctx, ctx_sz, pk, prm);
      }
      else
      {
        hashalg = find_par("hashAlg");
        if (hashalg == NULL)
        {
          fprintf(stderr, "sigVer: missing hashAlg\n");
          exit(-1);
        }
        sprintf(test_func, "hash_slh_verify(%s)", hashalg);

        /* Algorithm 25: hash_slh_verify(M, SIG, ctx, PH, PK) */
        res = hash_slh_verify(msg, msg_sz, sig, sig_sz, ctx, ctx_sz, hashalg,
                              pk, prm);
      }
    }
    else
    {
      skip++;
    }

    /* check for expected result */
    if (skip == 0 && res != exp_res)
    {
      fail++;
      if (reason != NULL)
      {
        printf("[INFO] %s: %s\n", test_id, reason);
      }
    }

    /* free local buffers */
    free(msg);
    free(sig);
    free(pk);
    if (ctx != NULL)
    {
      free(ctx);
    }
  }
  else
  {
    /* turns out some command is disabled? */
    skip++;
  }

  if (fail > 0)
  {
    printf("[FAIL] %s %s\n", test_id, test_func);
  }
  else if (skip > 0)
  {
    printf("[SKIP] %s %s\n", test_id, test_func);
  }
  else
  {
    printf("[PASS] %s %s\n", test_id, test_func);
  }

  return fail;
}
