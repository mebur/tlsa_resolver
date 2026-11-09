/*
 * Exercises the native shim on its own, built with AddressSanitizer and
 * UndefinedBehaviorSanitizer (see the README). Needs the system resolver.
 *
 *   cc -std=gnu11 -Wall -Wextra -Werror -g -fno-omit-frame-pointer \
 *      -fsanitize=address,undefined -Isrc src/tlsa_resolver.c \
 *      test/native/shim_test.c -lresolv -o build/shim_test && build/shim_test
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tlsa_resolver.h"

static int failures = 0;

#define CHECK(cond, ...)                      \
  do {                                        \
    if (!(cond)) {                            \
      fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
      fprintf(stderr, __VA_ARGS__);           \
      fprintf(stderr, "\n");                  \
      failures++;                             \
    }                                         \
  } while (0)

// Builds a query with RD, CD and an EDNS0 OPT record with DO, like the Dart
// side does. Returns its length.
static int build_query(uint8_t *out, const char *name, uint16_t type) {
  const uint8_t header[] = {0x12, 0x34, 0x01, 0x10, 0, 1, 0, 0, 0, 0, 0, 1};
  int n = 0;
  memcpy(out, header, sizeof(header));
  n += (int)sizeof(header);
  const char *p = name;
  while (*p) {
    const char *dot = strchr(p, '.');
    size_t len = dot ? (size_t)(dot - p) : strlen(p);
    out[n++] = (uint8_t)len;
    memcpy(out + n, p, len);
    n += (int)len;
    p += len;
    if (*p == '.') p++;
  }
  out[n++] = 0;
  out[n++] = (uint8_t)(type >> 8);
  out[n++] = (uint8_t)type;
  out[n++] = 0;
  out[n++] = 1;  // class IN
  const uint8_t opt[] = {0, 0, 41, 0x10, 0x00, 0, 0, 0x80, 0x00, 0, 0};
  memcpy(out + n, opt, sizeof(opt));
  return n + (int)sizeof(opt);
}

int main(void) {
  uint8_t query[512];
  int qlen = build_query(query, "ietf.org", 48 /* DNSKEY */);

  // Invalid arguments are refused before anything is sent.
  uint8_t small[16];
  CHECK(tlsa_resolver_send(NULL, qlen, small, 16, 1000) == -TLSA_ERR_ARGUMENT, "null query");
  CHECK(tlsa_resolver_send(query, qlen, NULL, 16, 1000) == -TLSA_ERR_ARGUMENT, "null answer");
  CHECK(tlsa_resolver_send(query, 0, small, 16, 1000) == -TLSA_ERR_ARGUMENT, "empty query");
  CHECK(tlsa_resolver_send(query, -1, small, 16, 1000) == -TLSA_ERR_ARGUMENT, "negative length");
  CHECK(tlsa_resolver_send(query, qlen, small, -1, 1000) == -TLSA_ERR_ARGUMENT, "negative capacity");
  CHECK(tlsa_resolver_send(query, qlen, small, 16, 0) == -TLSA_ERR_ARGUMENT, "zero timeout");
  CHECK(tlsa_resolver_send(query, qlen, small, 16, -5) == -TLSA_ERR_ARGUMENT, "negative timeout");

  // A buffer exactly as large as claimed, so AddressSanitizer catches any
  // write past it. A DNSKEY answer with signatures does not fit in 64 bytes.
  uint8_t *tight = malloc(64);
  int n = tlsa_resolver_send(query, qlen, tight, 64, 5000);
  CHECK(n == -TLSA_ERR_TRUNCATED || n == -TLSA_ERR_SEND || (n > 0 && n <= 64),
        "small buffer gave %d", n);
  free(tight);

  // A normal lookup: the answer carries our ID and the DNSKEY records.
  const int cap = 65535;
  uint8_t *answer = malloc(cap);
  n = tlsa_resolver_send(query, qlen, answer, cap, 5000);
  CHECK(n > 12 && n <= cap, "lookup gave %d", n);
  if (n > 12) {
    CHECK(answer[0] == 0x12 && answer[1] == 0x34, "answer ID %02x%02x", answer[0], answer[1]);
    CHECK((answer[2] & 0x80) != 0, "not a response");
    CHECK(((answer[6] << 8) | answer[7]) > 0, "no answer records");
  }
  free(answer);

  if (failures) {
    fprintf(stderr, "%d failure(s)\n", failures);
    return 1;
  }
  printf("shim_test: all checks passed\n");
  return 0;
}
