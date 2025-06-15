/*
 * Copyright (c) The slhdsa-c project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */
 
/* === private tests and benchmarks */

#include "my_dbg.h"
#include <stdio.h>

/* loop (instead of a table) to save code size; this is for test vectors */

static inline uint32_t crc32byte(uint32_t x, const uint8_t c)
{
  x ^= ((uint32_t)c) << 24;

  for (int i = 0; i < 8; i++)
  {
    x = (x << 1) ^ ((-(x >> 31)) & 0x04C11DB7);
  }

  return x;
}

void dbg_chk(const char *label, const void *data, size_t data_sz)
{
  size_t i;
  uint32_t x = 0;
  uint64_t l;
  const uint8_t *vu8 = (const uint8_t *)data;

  /* compatible with cksum(1) */
  for (i = 0; i < data_sz; i++)
  {
    x = crc32byte(x, vu8[i]);
  }
  l = data_sz;
  while (l != 0)
  {
    x = crc32byte(x, l & 0xFF);
    l >>= 8;
  }
  x = ~x;

  printf("%s: %08X (%zu)\n", label, x, data_sz);
  fflush(stdout);
}

/* [debug] dump a hex string */

void dbg_hex(const char *label, const void *data, size_t data_sz)
{
  size_t i;
  const uint8_t *vu8 = (const uint8_t *)data;

  printf("%s[%zu] = ", label, data_sz);
  for (i = 0; i < data_sz; i++)
  {
    printf("%02X", vu8[i]);
  }
  printf("\n");
  fflush(stdout);
}

/* [debug] dump a hex string in kat format */

void dbg_kat(const char *label, const void *data, size_t data_sz)
{
  size_t i;
  const uint8_t *vu8 = (const uint8_t *)data;

  printf("%s = ", label);
  for (i = 0; i < data_sz; i++)
  {
    printf("%02X", vu8[i]);
  }
  printf("\n");
  fflush(stdout);
}

/* [debug] dump a hex in indexed format (suitable for comparison) */

void dbg_dump(const char *label, const void *data, size_t data_sz)
{
  size_t i;
  const uint8_t *vu8 = (const uint8_t *)data;

  printf("%s = (%zu)", label, data_sz);
  for (i = 0; i < data_sz; i++)
  {
    if ((i & 0x1F) == 0)
    {
      printf("\n%s[%06zx]: ", label, i);
    }
    printf("%02x", vu8[i]);
  }
  printf("\n");
  fflush(stdout);
}
