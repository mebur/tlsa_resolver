#include "tlsa_resolver.h"

#include <string.h>

// Rejects arguments the platform APIs would misread: negative sizes turn
// into huge size_t values, and a negative poll() timeout waits forever.
static int bad_arguments(const uint8_t *query, int32_t query_len,
                         const uint8_t *answer, int32_t answer_cap,
                         int32_t timeout_ms) {
  return query == NULL || answer == NULL || query_len <= 0 ||
         answer_cap <= 0 || timeout_ms <= 0;
}

#if defined(__ANDROID__)

// Android 10 (API 29) added android_res_nsend, which hands a raw query to the
// system resolver (netd) for the default network, honouring Private DNS. It is
// looked up at run time so the library still loads on older devices.
#include <dlfcn.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>

typedef int (*nsend_fn)(uint64_t network, const uint8_t *msg, size_t msglen,
                        uint32_t flags);
typedef int (*nresult_fn)(int fd, int *rcode, uint8_t *answer, size_t anslen);
typedef void (*cancel_fn)(int fd);

static nsend_fn nsend;
static nresult_fn nresult;
static cancel_fn cancel;
static pthread_once_t load_once = PTHREAD_ONCE_INIT;

static void load_api(void) {
  void *lib = dlopen("libandroid.so", RTLD_NOW);
  if (!lib) return;
  nsend = (nsend_fn)dlsym(lib, "android_res_nsend");
  nresult = (nresult_fn)dlsym(lib, "android_res_nresult");
  cancel = (cancel_fn)dlsym(lib, "android_res_cancel");
}

int32_t tlsa_resolver_send(const uint8_t *query, int32_t query_len,
                           uint8_t *answer, int32_t answer_cap,
                           int32_t timeout_ms) {
  if (bad_arguments(query, query_len, answer, answer_cap, timeout_ms)) {
    return -TLSA_ERR_ARGUMENT;
  }
  pthread_once(&load_once, load_api);
  if (!nsend || !nresult || !cancel) return -TLSA_ERR_UNSUPPORTED;

  // NETWORK_UNSPECIFIED (0) is the app's default network. Flags 0: use the
  // resolver cache and normal retry behaviour.
  int fd = nsend(0, query, (size_t)query_len, 0);
  if (fd < 0) return -TLSA_ERR_SEND;

  struct pollfd pfd = {.fd = fd, .events = POLLIN};
  int ready;
  do {
    ready = poll(&pfd, 1, timeout_ms);
  } while (ready < 0 && errno == EINTR);
  if (ready <= 0) {
    cancel(fd);  // Also closes fd.
    return -TLSA_ERR_TIMEOUT;
  }

  int rcode = 0;
  int n = nresult(fd, &rcode, answer, (size_t)answer_cap);  // Closes fd.
  if (n < 0) return n == -EMSGSIZE ? -TLSA_ERR_TRUNCATED : -TLSA_ERR_SEND;
  return n;
}

#elif defined(__APPLE__) || defined(__linux__)

// libresolv: res_nsend sends the message to the servers from the system
// configuration and retries over TCP when the UDP answer is truncated.
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

int32_t tlsa_resolver_send(const uint8_t *query, int32_t query_len,
                           uint8_t *answer, int32_t answer_cap,
                           int32_t timeout_ms) {
  if (bad_arguments(query, query_len, answer, answer_cap, timeout_ms)) {
    return -TLSA_ERR_ARGUMENT;
  }
  struct __res_state state;
  memset(&state, 0, sizeof(state));
  if (res_ninit(&state) != 0) return -TLSA_ERR_INIT;

  // res_nsend waits `retrans` seconds per server per attempt.
  int seconds = timeout_ms / 1000;
  int servers = state.nscount > 0 ? state.nscount : 1;
  state.retry = 2;
  state.retrans = seconds / (state.retry * servers);
  if (state.retrans < 1) state.retrans = 1;

  int n = res_nsend(&state, query, query_len, answer, answer_cap);
#if defined(__APPLE__)
  res_ndestroy(&state);
#else
  res_nclose(&state);
#endif
  if (n < 0) return -TLSA_ERR_SEND;
  if (n > answer_cap) return -TLSA_ERR_TRUNCATED;
  return n;
}

#else

int32_t tlsa_resolver_send(const uint8_t *query, int32_t query_len,
                           uint8_t *answer, int32_t answer_cap,
                           int32_t timeout_ms) {
  (void)query;
  (void)query_len;
  (void)answer;
  (void)answer_cap;
  (void)timeout_ms;
  return -TLSA_ERR_UNSUPPORTED;
}

#endif
