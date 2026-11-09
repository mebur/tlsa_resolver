#ifndef TLSA_RESOLVER_H
#define TLSA_RESOLVER_H

#include <stdint.h>

#if _WIN32
#define TLSA_EXPORT __declspec(dllexport)
#else
#define TLSA_EXPORT __attribute__((visibility("default")))
#endif

// Error codes returned (negated) by tlsa_resolver_send.
#define TLSA_ERR_UNSUPPORTED 1  // No system resolver API on this platform/OS version.
#define TLSA_ERR_INIT 2         // The resolver could not be initialised.
#define TLSA_ERR_SEND 3         // The query could not be sent or no server answered.
#define TLSA_ERR_TIMEOUT 4      // No answer within the timeout.
#define TLSA_ERR_TRUNCATED 5    // The answer did not fit in the buffer.

// Sends a complete DNS query message (wire format, as built by the Dart side,
// including the EDNS0 OPT record with the DO bit) to the operating system's
// configured resolver and copies the raw answer message into `answer`.
//
// Returns the answer length, or a negative TLSA_ERR_* code.
//
// Blocks the calling thread for up to about `timeout_ms`; call it off the UI
// isolate.
TLSA_EXPORT int32_t tlsa_resolver_send(const uint8_t *query, int32_t query_len,
                                       uint8_t *answer, int32_t answer_cap,
                                       int32_t timeout_ms);

#endif
