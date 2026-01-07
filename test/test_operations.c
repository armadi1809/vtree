
// We need to define _GNU_SOURCE before
// _any_ headers files are imported to get
// the usage statistics of a thread (i.e. have RUSAGE_THREAD) on GNU/Linux
// https://manpages.courier-mta.org/htmlman2/getrusage.2.html
#ifndef _GNU_SOURCE // Avoid possible double-definition warning.
#define _GNU_SOURCE
#endif

#ifdef __clang__
#pragma clang diagnostic ignored "-Wunused-function"
#pragma clang diagnostic ignored "-Wunused-variable"
#pragma clang diagnostic ignored "-Wunused-const-variable"
#pragma clang diagnostic ignored "-Wparentheses"
#pragma clang diagnostic ignored "-Wunused-label"
#pragma clang diagnostic ignored "-Wunused-but-set-variable"
#elif __GNUC__
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wunused-const-variable"
#pragma GCC diagnostic ignored "-Wparentheses"
#pragma GCC diagnostic ignored "-Wunused-label"
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
#endif

// Headers
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <float.h>

#ifdef __cplusplus
extern "C" {
#endif

// Initialisation
struct futhark_context_config;
struct futhark_context_config *futhark_context_config_new(void);
void futhark_context_config_free(struct futhark_context_config *cfg);
int futhark_context_config_set_tuning_param(struct futhark_context_config *cfg, const char *param_name, size_t new_value);
struct futhark_context;
struct futhark_context *futhark_context_new(struct futhark_context_config *cfg);
void futhark_context_free(struct futhark_context *ctx);
void futhark_context_config_set_debugging(struct futhark_context_config *cfg, int flag);
void futhark_context_config_set_profiling(struct futhark_context_config *cfg, int flag);
void futhark_context_config_set_logging(struct futhark_context_config *cfg, int flag);
int futhark_get_tuning_param_count(void);
const char *futhark_get_tuning_param_name(int);
const char *futhark_get_tuning_param_class(int);

// Arrays


// Opaque values



// Entry points
int futhark_entry_test_delete_vertices(struct futhark_context *ctx, bool *out0);
int futhark_entry_test_merge_tree(struct futhark_context *ctx, bool *out0);
int futhark_entry_test_split(struct futhark_context *ctx, bool *out0);
int futhark_entry_test_split_at_leaf(struct futhark_context *ctx, bool *out0);
int futhark_entry_test_split_multiple(struct futhark_context *ctx, bool *out0);
int futhark_entry_test_split_none(struct futhark_context *ctx, bool *out0);

// Miscellaneous
int futhark_context_sync(struct futhark_context *ctx);
void futhark_context_config_set_cache_file(struct futhark_context_config *cfg, const char *f);
char *futhark_context_get_error(struct futhark_context *ctx);
void futhark_context_set_logging_file(struct futhark_context *ctx, FILE *f);
void futhark_context_pause_profiling(struct futhark_context *ctx);
void futhark_context_unpause_profiling(struct futhark_context *ctx);
char *futhark_context_report(struct futhark_context *ctx);
int futhark_context_clear_caches(struct futhark_context *ctx);
#define FUTHARK_BACKEND_c
#define FUTHARK_SUCCESS 0
#define FUTHARK_PROGRAM_ERROR 2
#define FUTHARK_OUT_OF_MEMORY 3

#ifdef __cplusplus
}
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <math.h>
#include <stdint.h>
// If NDEBUG is set, the assert() macro will do nothing. Since Futhark
// (unfortunately) makes use of assert() for error detection (and even some
// side effects), we want to avoid that.
#undef NDEBUG
#include <assert.h>
#include <stdarg.h>
#define SCALAR_FUN_ATTR static inline
// Start of util.h.
//
// Various helper functions that are useful in all generated C code.

#include <errno.h>
#include <string.h>

static const char *fut_progname = "(embedded Futhark)";

static void futhark_panic(int eval, const char *fmt, ...) __attribute__((noreturn));
static char* msgprintf(const char *s, ...);
static void* slurp_file(const char *filename, size_t *size);
static int dump_file(const char *file, const void *buf, size_t n);
struct str_builder;
static void str_builder_init(struct str_builder *b);
static void str_builder(struct str_builder *b, const char *s, ...);
static char *strclone(const char *str);

static void futhark_panic(int eval, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  fprintf(stderr, "%s: ", fut_progname);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
  exit(eval);
}

// For generating arbitrary-sized error messages.  It is the callers
// responsibility to free the buffer at some point.
static char* msgprintf(const char *s, ...) {
  va_list vl;
  va_start(vl, s);
  size_t needed = 1 + (size_t)vsnprintf(NULL, 0, s, vl);
  char *buffer = (char*) malloc(needed);
  va_start(vl, s); // Must re-init.
  vsnprintf(buffer, needed, s, vl);
  return buffer;
}

static inline void check_err(int errval, int sets_errno, const char *fun, int line,
                             const char *msg, ...) {
  if (errval) {
    char errnum[10];

    va_list vl;
    va_start(vl, msg);

    fprintf(stderr, "ERROR: ");
    vfprintf(stderr, msg, vl);
    fprintf(stderr, " in %s() at line %d with error code %s\n",
            fun, line,
            sets_errno ? strerror(errno) : errnum);
    exit(errval);
  }
}

#define CHECK_ERR(err, ...) check_err(err, 0, __func__, __LINE__, __VA_ARGS__)
#define CHECK_ERRNO(err, ...) check_err(err, 1, __func__, __LINE__, __VA_ARGS__)

// Read the rest of an open file into a NUL-terminated string; returns
// NULL on error.
static void* fslurp_file(FILE *f, size_t *size) {
  long start = ftell(f);
  fseek(f, 0, SEEK_END);
  long src_size = ftell(f)-start;
  fseek(f, start, SEEK_SET);
  unsigned char *s = (unsigned char*) malloc((size_t)src_size + 1);
  if (fread(s, 1, (size_t)src_size, f) != (size_t)src_size) {
    free(s);
    s = NULL;
  } else {
    s[src_size] = '\0';
  }

  if (size) {
    *size = (size_t)src_size;
  }

  return s;
}

// Read a file into a NUL-terminated string; returns NULL on error.
static void* slurp_file(const char *filename, size_t *size) {
  FILE *f = fopen(filename, "rb"); // To avoid Windows messing with linebreaks.
  if (f == NULL) return NULL;
  unsigned char *s = fslurp_file(f, size);
  fclose(f);
  return s;
}

// Dump 'n' bytes from 'buf' into the file at the designated location.
// Returns 0 on success.
static int dump_file(const char *file, const void *buf, size_t n) {
  FILE *f = fopen(file, "w");

  if (f == NULL) {
    return 1;
  }

  if (fwrite(buf, sizeof(char), n, f) != n) {
    return 1;
  }

  if (fclose(f) != 0) {
    return 1;
  }

  return 0;
}

struct str_builder {
  char *str;
  size_t capacity; // Size of buffer.
  size_t used; // Bytes used, *not* including final zero.
};

static void str_builder_init(struct str_builder *b) {
  b->capacity = 10;
  b->used = 0;
  b->str = malloc(b->capacity);
  b->str[0] = 0;
}

static void str_builder(struct str_builder *b, const char *s, ...) {
  va_list vl;
  va_start(vl, s);
  size_t needed = (size_t)vsnprintf(NULL, 0, s, vl);

  while (b->capacity < b->used + needed + 1) {
    b->capacity *= 2;
    b->str = realloc(b->str, b->capacity);
  }

  va_start(vl, s); // Must re-init.
  vsnprintf(b->str+b->used, b->capacity-b->used, s, vl);
  b->used += needed;
}

static void str_builder_str(struct str_builder *b, const char *s) {
  size_t needed = strlen(s);
  if (b->capacity < b->used + needed + 1) {
    b->capacity *= 2;
    b->str = realloc(b->str, b->capacity);
  }
  strcpy(b->str+b->used, s);
  b->used += needed;
}

static void str_builder_char(struct str_builder *b, char c) {
  size_t needed = 1;
  if (b->capacity < b->used + needed + 1) {
    b->capacity *= 2;
    b->str = realloc(b->str, b->capacity);
  }
  b->str[b->used] = c;
  b->str[b->used+1] = 0;
  b->used += needed;
}

static void str_builder_json_str(struct str_builder* sb, const char* s) {
  str_builder_char(sb, '"');
  for (int j = 0; s[j]; j++) {
    char c = s[j];
    switch (c) {
    case '\n':
      str_builder_str(sb, "\\n");
      break;
    case '"':
      str_builder_str(sb, "\\\"");
      break;
    default:
      str_builder_char(sb, c);
    }
  }
  str_builder_char(sb, '"');
}

static char *strclone(const char *str) {
  size_t size = strlen(str) + 1;
  char *copy = (char*) malloc(size);
  if (copy == NULL) {
    return NULL;
  }

  memcpy(copy, str, size);
  return copy;
}

// Assumes NULL-terminated.
static char *strconcat(const char *src_fragments[]) {
  size_t src_len = 0;
  const char **p;

  for (p = src_fragments; *p; p++) {
    src_len += strlen(*p);
  }

  char *src = (char*) malloc(src_len + 1);
  size_t n = 0;
  for (p = src_fragments; *p; p++) {
    strcpy(src + n, *p);
    n += strlen(*p);
  }

  return src;
}

// End of util.h.
// Start of cache.h

#define CACHE_HASH_SIZE 8 // In 32-bit words.

struct cache_hash {
  uint32_t hash[CACHE_HASH_SIZE];
};

// Initialise a blank cache.
static void cache_hash_init(struct cache_hash *c);

// Hash some bytes and add them to the accumulated hash.
static void cache_hash(struct cache_hash *out, const char *in, size_t n);

// Try to restore cache contents from a file with the given name.
// Assumes the cache is invalid if it contains the given hash.
// Allocates memory and reads the cache conents, which is returned in
// *buf with size *buflen.  If the cache is successfully loaded, this
// function returns 0.  Otherwise it returns nonzero.  Errno is set if
// the failure to load the cache is due to anything except invalid
// cache conents.  Note that failing to restore the cache is not
// necessarily a problem: it might just be invalid or not created yet.
static int cache_restore(const char *fname, const struct cache_hash *hash,
                         unsigned char **buf, size_t *buflen);

// Store cache contents in the given file, with the given hash.
static int cache_store(const char *fname, const struct cache_hash *hash,
                       const unsigned char *buf, size_t buflen);

// Now for the implementation.

static void cache_hash_init(struct cache_hash *c) {
  memset(c->hash, 0, CACHE_HASH_SIZE * sizeof(uint32_t));
}

static void cache_hash(struct cache_hash *out, const char *in, size_t n) {
  // Adaptation of djb2 for larger output size by storing intermediate
  // states.
  uint32_t hash = 5381;
  for (size_t i = 0; i < n; i++) {
    hash = ((hash << 5) + hash) + in[i];
    out->hash[i % CACHE_HASH_SIZE] ^= hash;
  }
}

#define CACHE_HEADER_SIZE 8
static const char cache_header[CACHE_HEADER_SIZE] = "FUTHARK\0";

static int cache_restore(const char *fname, const struct cache_hash *hash,
                         unsigned char **buf, size_t *buflen) {
  FILE *f = fopen(fname, "rb");

  if (f == NULL) {
    return 1;
  }

  char f_header[CACHE_HEADER_SIZE];

  if (fread(f_header, sizeof(char), CACHE_HEADER_SIZE, f) != CACHE_HEADER_SIZE) {
    goto error;
  }

  if (memcmp(f_header, cache_header, CACHE_HEADER_SIZE) != 0) {
    goto error;
  }

  if (fseek(f, 0, SEEK_END) != 0) {
    goto error;
  }
  int64_t f_size = (int64_t)ftell(f);
  if (fseek(f, CACHE_HEADER_SIZE, SEEK_SET) != 0) {
    goto error;
  }

  int64_t expected_size;

  if (fread(&expected_size, sizeof(int64_t), 1, f) != 1) {
    goto error;
  }

  if (f_size != expected_size) {
    errno = 0;
    goto error;
  }

  int32_t f_hash[CACHE_HASH_SIZE];

  if (fread(f_hash, sizeof(int32_t), CACHE_HASH_SIZE, f) != CACHE_HASH_SIZE) {
    goto error;
  }

  if (memcmp(f_hash, hash->hash, CACHE_HASH_SIZE) != 0) {
    errno = 0;
    goto error;
  }

  *buflen = f_size - CACHE_HEADER_SIZE - sizeof(int64_t) - CACHE_HASH_SIZE*sizeof(int32_t);
  *buf = malloc(*buflen);
  if (fread(*buf, sizeof(char), *buflen, f) != *buflen) {
    free(*buf);
    goto error;
  }

  fclose(f);

  return 0;

 error:
  fclose(f);
  return 1;
}

static int cache_store(const char *fname, const struct cache_hash *hash,
                       const unsigned char *buf, size_t buflen) {
  FILE *f = fopen(fname, "wb");

  if (f == NULL) {
    return 1;
  }

  if (fwrite(cache_header, CACHE_HEADER_SIZE, 1, f) != 1) {
    goto error;
  }

  int64_t size = CACHE_HEADER_SIZE + sizeof(int64_t) + CACHE_HASH_SIZE*sizeof(int32_t) + buflen;

  if (fwrite(&size, sizeof(size), 1, f) != 1) {
    goto error;
  }

  if (fwrite(hash->hash, sizeof(int32_t), CACHE_HASH_SIZE, f) != CACHE_HASH_SIZE) {
    goto error;
  }

  if (fwrite(buf, sizeof(unsigned char), buflen, f) != buflen) {
    goto error;
  }

  fclose(f);

  return 0;

 error:
  fclose(f);
  return 1;
}

// End of cache.h
// Start of half.h.

// Conversion functions are from http://half.sourceforge.net/, but
// translated to C.
//
// Copyright (c) 2012-2021 Christian Rau
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#ifndef __OPENCL_VERSION__
#define __constant
#endif

__constant static const uint16_t base_table[512] = {
  0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
  0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
  0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
  0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
  0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
  0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
  0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001, 0x0002, 0x0004, 0x0008, 0x0010, 0x0020, 0x0040, 0x0080, 0x0100,
  0x0200, 0x0400, 0x0800, 0x0C00, 0x1000, 0x1400, 0x1800, 0x1C00, 0x2000, 0x2400, 0x2800, 0x2C00, 0x3000, 0x3400, 0x3800, 0x3C00,
  0x4000, 0x4400, 0x4800, 0x4C00, 0x5000, 0x5400, 0x5800, 0x5C00, 0x6000, 0x6400, 0x6800, 0x6C00, 0x7000, 0x7400, 0x7800, 0x7C00,
  0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00,
  0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00,
  0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00,
  0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00,
  0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00,
  0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00,
  0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00, 0x7C00,
  0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000,
  0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000,
  0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000,
  0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000,
  0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000,
  0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000,
  0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8001, 0x8002, 0x8004, 0x8008, 0x8010, 0x8020, 0x8040, 0x8080, 0x8100,
  0x8200, 0x8400, 0x8800, 0x8C00, 0x9000, 0x9400, 0x9800, 0x9C00, 0xA000, 0xA400, 0xA800, 0xAC00, 0xB000, 0xB400, 0xB800, 0xBC00,
  0xC000, 0xC400, 0xC800, 0xCC00, 0xD000, 0xD400, 0xD800, 0xDC00, 0xE000, 0xE400, 0xE800, 0xEC00, 0xF000, 0xF400, 0xF800, 0xFC00,
  0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00,
  0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00,
  0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00,
  0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00,
  0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00,
  0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00,
  0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00, 0xFC00 };

__constant static const unsigned char shift_table[512] = {
  24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
  24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
  24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
  24, 24, 24, 24, 24, 24, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
  13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
  24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
  24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
  24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 13,
  24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
  24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
  24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
  24, 24, 24, 24, 24, 24, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
  13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
  24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
  24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
  24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 13 };

__constant static const uint32_t mantissa_table[2048] = {
  0x00000000, 0x33800000, 0x34000000, 0x34400000, 0x34800000, 0x34A00000, 0x34C00000, 0x34E00000, 0x35000000, 0x35100000, 0x35200000, 0x35300000, 0x35400000, 0x35500000, 0x35600000, 0x35700000,
  0x35800000, 0x35880000, 0x35900000, 0x35980000, 0x35A00000, 0x35A80000, 0x35B00000, 0x35B80000, 0x35C00000, 0x35C80000, 0x35D00000, 0x35D80000, 0x35E00000, 0x35E80000, 0x35F00000, 0x35F80000,
  0x36000000, 0x36040000, 0x36080000, 0x360C0000, 0x36100000, 0x36140000, 0x36180000, 0x361C0000, 0x36200000, 0x36240000, 0x36280000, 0x362C0000, 0x36300000, 0x36340000, 0x36380000, 0x363C0000,
  0x36400000, 0x36440000, 0x36480000, 0x364C0000, 0x36500000, 0x36540000, 0x36580000, 0x365C0000, 0x36600000, 0x36640000, 0x36680000, 0x366C0000, 0x36700000, 0x36740000, 0x36780000, 0x367C0000,
  0x36800000, 0x36820000, 0x36840000, 0x36860000, 0x36880000, 0x368A0000, 0x368C0000, 0x368E0000, 0x36900000, 0x36920000, 0x36940000, 0x36960000, 0x36980000, 0x369A0000, 0x369C0000, 0x369E0000,
  0x36A00000, 0x36A20000, 0x36A40000, 0x36A60000, 0x36A80000, 0x36AA0000, 0x36AC0000, 0x36AE0000, 0x36B00000, 0x36B20000, 0x36B40000, 0x36B60000, 0x36B80000, 0x36BA0000, 0x36BC0000, 0x36BE0000,
  0x36C00000, 0x36C20000, 0x36C40000, 0x36C60000, 0x36C80000, 0x36CA0000, 0x36CC0000, 0x36CE0000, 0x36D00000, 0x36D20000, 0x36D40000, 0x36D60000, 0x36D80000, 0x36DA0000, 0x36DC0000, 0x36DE0000,
  0x36E00000, 0x36E20000, 0x36E40000, 0x36E60000, 0x36E80000, 0x36EA0000, 0x36EC0000, 0x36EE0000, 0x36F00000, 0x36F20000, 0x36F40000, 0x36F60000, 0x36F80000, 0x36FA0000, 0x36FC0000, 0x36FE0000,
  0x37000000, 0x37010000, 0x37020000, 0x37030000, 0x37040000, 0x37050000, 0x37060000, 0x37070000, 0x37080000, 0x37090000, 0x370A0000, 0x370B0000, 0x370C0000, 0x370D0000, 0x370E0000, 0x370F0000,
  0x37100000, 0x37110000, 0x37120000, 0x37130000, 0x37140000, 0x37150000, 0x37160000, 0x37170000, 0x37180000, 0x37190000, 0x371A0000, 0x371B0000, 0x371C0000, 0x371D0000, 0x371E0000, 0x371F0000,
  0x37200000, 0x37210000, 0x37220000, 0x37230000, 0x37240000, 0x37250000, 0x37260000, 0x37270000, 0x37280000, 0x37290000, 0x372A0000, 0x372B0000, 0x372C0000, 0x372D0000, 0x372E0000, 0x372F0000,
  0x37300000, 0x37310000, 0x37320000, 0x37330000, 0x37340000, 0x37350000, 0x37360000, 0x37370000, 0x37380000, 0x37390000, 0x373A0000, 0x373B0000, 0x373C0000, 0x373D0000, 0x373E0000, 0x373F0000,
  0x37400000, 0x37410000, 0x37420000, 0x37430000, 0x37440000, 0x37450000, 0x37460000, 0x37470000, 0x37480000, 0x37490000, 0x374A0000, 0x374B0000, 0x374C0000, 0x374D0000, 0x374E0000, 0x374F0000,
  0x37500000, 0x37510000, 0x37520000, 0x37530000, 0x37540000, 0x37550000, 0x37560000, 0x37570000, 0x37580000, 0x37590000, 0x375A0000, 0x375B0000, 0x375C0000, 0x375D0000, 0x375E0000, 0x375F0000,
  0x37600000, 0x37610000, 0x37620000, 0x37630000, 0x37640000, 0x37650000, 0x37660000, 0x37670000, 0x37680000, 0x37690000, 0x376A0000, 0x376B0000, 0x376C0000, 0x376D0000, 0x376E0000, 0x376F0000,
  0x37700000, 0x37710000, 0x37720000, 0x37730000, 0x37740000, 0x37750000, 0x37760000, 0x37770000, 0x37780000, 0x37790000, 0x377A0000, 0x377B0000, 0x377C0000, 0x377D0000, 0x377E0000, 0x377F0000,
  0x37800000, 0x37808000, 0x37810000, 0x37818000, 0x37820000, 0x37828000, 0x37830000, 0x37838000, 0x37840000, 0x37848000, 0x37850000, 0x37858000, 0x37860000, 0x37868000, 0x37870000, 0x37878000,
  0x37880000, 0x37888000, 0x37890000, 0x37898000, 0x378A0000, 0x378A8000, 0x378B0000, 0x378B8000, 0x378C0000, 0x378C8000, 0x378D0000, 0x378D8000, 0x378E0000, 0x378E8000, 0x378F0000, 0x378F8000,
  0x37900000, 0x37908000, 0x37910000, 0x37918000, 0x37920000, 0x37928000, 0x37930000, 0x37938000, 0x37940000, 0x37948000, 0x37950000, 0x37958000, 0x37960000, 0x37968000, 0x37970000, 0x37978000,
  0x37980000, 0x37988000, 0x37990000, 0x37998000, 0x379A0000, 0x379A8000, 0x379B0000, 0x379B8000, 0x379C0000, 0x379C8000, 0x379D0000, 0x379D8000, 0x379E0000, 0x379E8000, 0x379F0000, 0x379F8000,
  0x37A00000, 0x37A08000, 0x37A10000, 0x37A18000, 0x37A20000, 0x37A28000, 0x37A30000, 0x37A38000, 0x37A40000, 0x37A48000, 0x37A50000, 0x37A58000, 0x37A60000, 0x37A68000, 0x37A70000, 0x37A78000,
  0x37A80000, 0x37A88000, 0x37A90000, 0x37A98000, 0x37AA0000, 0x37AA8000, 0x37AB0000, 0x37AB8000, 0x37AC0000, 0x37AC8000, 0x37AD0000, 0x37AD8000, 0x37AE0000, 0x37AE8000, 0x37AF0000, 0x37AF8000,
  0x37B00000, 0x37B08000, 0x37B10000, 0x37B18000, 0x37B20000, 0x37B28000, 0x37B30000, 0x37B38000, 0x37B40000, 0x37B48000, 0x37B50000, 0x37B58000, 0x37B60000, 0x37B68000, 0x37B70000, 0x37B78000,
  0x37B80000, 0x37B88000, 0x37B90000, 0x37B98000, 0x37BA0000, 0x37BA8000, 0x37BB0000, 0x37BB8000, 0x37BC0000, 0x37BC8000, 0x37BD0000, 0x37BD8000, 0x37BE0000, 0x37BE8000, 0x37BF0000, 0x37BF8000,
  0x37C00000, 0x37C08000, 0x37C10000, 0x37C18000, 0x37C20000, 0x37C28000, 0x37C30000, 0x37C38000, 0x37C40000, 0x37C48000, 0x37C50000, 0x37C58000, 0x37C60000, 0x37C68000, 0x37C70000, 0x37C78000,
  0x37C80000, 0x37C88000, 0x37C90000, 0x37C98000, 0x37CA0000, 0x37CA8000, 0x37CB0000, 0x37CB8000, 0x37CC0000, 0x37CC8000, 0x37CD0000, 0x37CD8000, 0x37CE0000, 0x37CE8000, 0x37CF0000, 0x37CF8000,
  0x37D00000, 0x37D08000, 0x37D10000, 0x37D18000, 0x37D20000, 0x37D28000, 0x37D30000, 0x37D38000, 0x37D40000, 0x37D48000, 0x37D50000, 0x37D58000, 0x37D60000, 0x37D68000, 0x37D70000, 0x37D78000,
  0x37D80000, 0x37D88000, 0x37D90000, 0x37D98000, 0x37DA0000, 0x37DA8000, 0x37DB0000, 0x37DB8000, 0x37DC0000, 0x37DC8000, 0x37DD0000, 0x37DD8000, 0x37DE0000, 0x37DE8000, 0x37DF0000, 0x37DF8000,
  0x37E00000, 0x37E08000, 0x37E10000, 0x37E18000, 0x37E20000, 0x37E28000, 0x37E30000, 0x37E38000, 0x37E40000, 0x37E48000, 0x37E50000, 0x37E58000, 0x37E60000, 0x37E68000, 0x37E70000, 0x37E78000,
  0x37E80000, 0x37E88000, 0x37E90000, 0x37E98000, 0x37EA0000, 0x37EA8000, 0x37EB0000, 0x37EB8000, 0x37EC0000, 0x37EC8000, 0x37ED0000, 0x37ED8000, 0x37EE0000, 0x37EE8000, 0x37EF0000, 0x37EF8000,
  0x37F00000, 0x37F08000, 0x37F10000, 0x37F18000, 0x37F20000, 0x37F28000, 0x37F30000, 0x37F38000, 0x37F40000, 0x37F48000, 0x37F50000, 0x37F58000, 0x37F60000, 0x37F68000, 0x37F70000, 0x37F78000,
  0x37F80000, 0x37F88000, 0x37F90000, 0x37F98000, 0x37FA0000, 0x37FA8000, 0x37FB0000, 0x37FB8000, 0x37FC0000, 0x37FC8000, 0x37FD0000, 0x37FD8000, 0x37FE0000, 0x37FE8000, 0x37FF0000, 0x37FF8000,
  0x38000000, 0x38004000, 0x38008000, 0x3800C000, 0x38010000, 0x38014000, 0x38018000, 0x3801C000, 0x38020000, 0x38024000, 0x38028000, 0x3802C000, 0x38030000, 0x38034000, 0x38038000, 0x3803C000,
  0x38040000, 0x38044000, 0x38048000, 0x3804C000, 0x38050000, 0x38054000, 0x38058000, 0x3805C000, 0x38060000, 0x38064000, 0x38068000, 0x3806C000, 0x38070000, 0x38074000, 0x38078000, 0x3807C000,
  0x38080000, 0x38084000, 0x38088000, 0x3808C000, 0x38090000, 0x38094000, 0x38098000, 0x3809C000, 0x380A0000, 0x380A4000, 0x380A8000, 0x380AC000, 0x380B0000, 0x380B4000, 0x380B8000, 0x380BC000,
  0x380C0000, 0x380C4000, 0x380C8000, 0x380CC000, 0x380D0000, 0x380D4000, 0x380D8000, 0x380DC000, 0x380E0000, 0x380E4000, 0x380E8000, 0x380EC000, 0x380F0000, 0x380F4000, 0x380F8000, 0x380FC000,
  0x38100000, 0x38104000, 0x38108000, 0x3810C000, 0x38110000, 0x38114000, 0x38118000, 0x3811C000, 0x38120000, 0x38124000, 0x38128000, 0x3812C000, 0x38130000, 0x38134000, 0x38138000, 0x3813C000,
  0x38140000, 0x38144000, 0x38148000, 0x3814C000, 0x38150000, 0x38154000, 0x38158000, 0x3815C000, 0x38160000, 0x38164000, 0x38168000, 0x3816C000, 0x38170000, 0x38174000, 0x38178000, 0x3817C000,
  0x38180000, 0x38184000, 0x38188000, 0x3818C000, 0x38190000, 0x38194000, 0x38198000, 0x3819C000, 0x381A0000, 0x381A4000, 0x381A8000, 0x381AC000, 0x381B0000, 0x381B4000, 0x381B8000, 0x381BC000,
  0x381C0000, 0x381C4000, 0x381C8000, 0x381CC000, 0x381D0000, 0x381D4000, 0x381D8000, 0x381DC000, 0x381E0000, 0x381E4000, 0x381E8000, 0x381EC000, 0x381F0000, 0x381F4000, 0x381F8000, 0x381FC000,
  0x38200000, 0x38204000, 0x38208000, 0x3820C000, 0x38210000, 0x38214000, 0x38218000, 0x3821C000, 0x38220000, 0x38224000, 0x38228000, 0x3822C000, 0x38230000, 0x38234000, 0x38238000, 0x3823C000,
  0x38240000, 0x38244000, 0x38248000, 0x3824C000, 0x38250000, 0x38254000, 0x38258000, 0x3825C000, 0x38260000, 0x38264000, 0x38268000, 0x3826C000, 0x38270000, 0x38274000, 0x38278000, 0x3827C000,
  0x38280000, 0x38284000, 0x38288000, 0x3828C000, 0x38290000, 0x38294000, 0x38298000, 0x3829C000, 0x382A0000, 0x382A4000, 0x382A8000, 0x382AC000, 0x382B0000, 0x382B4000, 0x382B8000, 0x382BC000,
  0x382C0000, 0x382C4000, 0x382C8000, 0x382CC000, 0x382D0000, 0x382D4000, 0x382D8000, 0x382DC000, 0x382E0000, 0x382E4000, 0x382E8000, 0x382EC000, 0x382F0000, 0x382F4000, 0x382F8000, 0x382FC000,
  0x38300000, 0x38304000, 0x38308000, 0x3830C000, 0x38310000, 0x38314000, 0x38318000, 0x3831C000, 0x38320000, 0x38324000, 0x38328000, 0x3832C000, 0x38330000, 0x38334000, 0x38338000, 0x3833C000,
  0x38340000, 0x38344000, 0x38348000, 0x3834C000, 0x38350000, 0x38354000, 0x38358000, 0x3835C000, 0x38360000, 0x38364000, 0x38368000, 0x3836C000, 0x38370000, 0x38374000, 0x38378000, 0x3837C000,
  0x38380000, 0x38384000, 0x38388000, 0x3838C000, 0x38390000, 0x38394000, 0x38398000, 0x3839C000, 0x383A0000, 0x383A4000, 0x383A8000, 0x383AC000, 0x383B0000, 0x383B4000, 0x383B8000, 0x383BC000,
  0x383C0000, 0x383C4000, 0x383C8000, 0x383CC000, 0x383D0000, 0x383D4000, 0x383D8000, 0x383DC000, 0x383E0000, 0x383E4000, 0x383E8000, 0x383EC000, 0x383F0000, 0x383F4000, 0x383F8000, 0x383FC000,
  0x38400000, 0x38404000, 0x38408000, 0x3840C000, 0x38410000, 0x38414000, 0x38418000, 0x3841C000, 0x38420000, 0x38424000, 0x38428000, 0x3842C000, 0x38430000, 0x38434000, 0x38438000, 0x3843C000,
  0x38440000, 0x38444000, 0x38448000, 0x3844C000, 0x38450000, 0x38454000, 0x38458000, 0x3845C000, 0x38460000, 0x38464000, 0x38468000, 0x3846C000, 0x38470000, 0x38474000, 0x38478000, 0x3847C000,
  0x38480000, 0x38484000, 0x38488000, 0x3848C000, 0x38490000, 0x38494000, 0x38498000, 0x3849C000, 0x384A0000, 0x384A4000, 0x384A8000, 0x384AC000, 0x384B0000, 0x384B4000, 0x384B8000, 0x384BC000,
  0x384C0000, 0x384C4000, 0x384C8000, 0x384CC000, 0x384D0000, 0x384D4000, 0x384D8000, 0x384DC000, 0x384E0000, 0x384E4000, 0x384E8000, 0x384EC000, 0x384F0000, 0x384F4000, 0x384F8000, 0x384FC000,
  0x38500000, 0x38504000, 0x38508000, 0x3850C000, 0x38510000, 0x38514000, 0x38518000, 0x3851C000, 0x38520000, 0x38524000, 0x38528000, 0x3852C000, 0x38530000, 0x38534000, 0x38538000, 0x3853C000,
  0x38540000, 0x38544000, 0x38548000, 0x3854C000, 0x38550000, 0x38554000, 0x38558000, 0x3855C000, 0x38560000, 0x38564000, 0x38568000, 0x3856C000, 0x38570000, 0x38574000, 0x38578000, 0x3857C000,
  0x38580000, 0x38584000, 0x38588000, 0x3858C000, 0x38590000, 0x38594000, 0x38598000, 0x3859C000, 0x385A0000, 0x385A4000, 0x385A8000, 0x385AC000, 0x385B0000, 0x385B4000, 0x385B8000, 0x385BC000,
  0x385C0000, 0x385C4000, 0x385C8000, 0x385CC000, 0x385D0000, 0x385D4000, 0x385D8000, 0x385DC000, 0x385E0000, 0x385E4000, 0x385E8000, 0x385EC000, 0x385F0000, 0x385F4000, 0x385F8000, 0x385FC000,
  0x38600000, 0x38604000, 0x38608000, 0x3860C000, 0x38610000, 0x38614000, 0x38618000, 0x3861C000, 0x38620000, 0x38624000, 0x38628000, 0x3862C000, 0x38630000, 0x38634000, 0x38638000, 0x3863C000,
  0x38640000, 0x38644000, 0x38648000, 0x3864C000, 0x38650000, 0x38654000, 0x38658000, 0x3865C000, 0x38660000, 0x38664000, 0x38668000, 0x3866C000, 0x38670000, 0x38674000, 0x38678000, 0x3867C000,
  0x38680000, 0x38684000, 0x38688000, 0x3868C000, 0x38690000, 0x38694000, 0x38698000, 0x3869C000, 0x386A0000, 0x386A4000, 0x386A8000, 0x386AC000, 0x386B0000, 0x386B4000, 0x386B8000, 0x386BC000,
  0x386C0000, 0x386C4000, 0x386C8000, 0x386CC000, 0x386D0000, 0x386D4000, 0x386D8000, 0x386DC000, 0x386E0000, 0x386E4000, 0x386E8000, 0x386EC000, 0x386F0000, 0x386F4000, 0x386F8000, 0x386FC000,
  0x38700000, 0x38704000, 0x38708000, 0x3870C000, 0x38710000, 0x38714000, 0x38718000, 0x3871C000, 0x38720000, 0x38724000, 0x38728000, 0x3872C000, 0x38730000, 0x38734000, 0x38738000, 0x3873C000,
  0x38740000, 0x38744000, 0x38748000, 0x3874C000, 0x38750000, 0x38754000, 0x38758000, 0x3875C000, 0x38760000, 0x38764000, 0x38768000, 0x3876C000, 0x38770000, 0x38774000, 0x38778000, 0x3877C000,
  0x38780000, 0x38784000, 0x38788000, 0x3878C000, 0x38790000, 0x38794000, 0x38798000, 0x3879C000, 0x387A0000, 0x387A4000, 0x387A8000, 0x387AC000, 0x387B0000, 0x387B4000, 0x387B8000, 0x387BC000,
  0x387C0000, 0x387C4000, 0x387C8000, 0x387CC000, 0x387D0000, 0x387D4000, 0x387D8000, 0x387DC000, 0x387E0000, 0x387E4000, 0x387E8000, 0x387EC000, 0x387F0000, 0x387F4000, 0x387F8000, 0x387FC000,
  0x38000000, 0x38002000, 0x38004000, 0x38006000, 0x38008000, 0x3800A000, 0x3800C000, 0x3800E000, 0x38010000, 0x38012000, 0x38014000, 0x38016000, 0x38018000, 0x3801A000, 0x3801C000, 0x3801E000,
  0x38020000, 0x38022000, 0x38024000, 0x38026000, 0x38028000, 0x3802A000, 0x3802C000, 0x3802E000, 0x38030000, 0x38032000, 0x38034000, 0x38036000, 0x38038000, 0x3803A000, 0x3803C000, 0x3803E000,
  0x38040000, 0x38042000, 0x38044000, 0x38046000, 0x38048000, 0x3804A000, 0x3804C000, 0x3804E000, 0x38050000, 0x38052000, 0x38054000, 0x38056000, 0x38058000, 0x3805A000, 0x3805C000, 0x3805E000,
  0x38060000, 0x38062000, 0x38064000, 0x38066000, 0x38068000, 0x3806A000, 0x3806C000, 0x3806E000, 0x38070000, 0x38072000, 0x38074000, 0x38076000, 0x38078000, 0x3807A000, 0x3807C000, 0x3807E000,
  0x38080000, 0x38082000, 0x38084000, 0x38086000, 0x38088000, 0x3808A000, 0x3808C000, 0x3808E000, 0x38090000, 0x38092000, 0x38094000, 0x38096000, 0x38098000, 0x3809A000, 0x3809C000, 0x3809E000,
  0x380A0000, 0x380A2000, 0x380A4000, 0x380A6000, 0x380A8000, 0x380AA000, 0x380AC000, 0x380AE000, 0x380B0000, 0x380B2000, 0x380B4000, 0x380B6000, 0x380B8000, 0x380BA000, 0x380BC000, 0x380BE000,
  0x380C0000, 0x380C2000, 0x380C4000, 0x380C6000, 0x380C8000, 0x380CA000, 0x380CC000, 0x380CE000, 0x380D0000, 0x380D2000, 0x380D4000, 0x380D6000, 0x380D8000, 0x380DA000, 0x380DC000, 0x380DE000,
  0x380E0000, 0x380E2000, 0x380E4000, 0x380E6000, 0x380E8000, 0x380EA000, 0x380EC000, 0x380EE000, 0x380F0000, 0x380F2000, 0x380F4000, 0x380F6000, 0x380F8000, 0x380FA000, 0x380FC000, 0x380FE000,
  0x38100000, 0x38102000, 0x38104000, 0x38106000, 0x38108000, 0x3810A000, 0x3810C000, 0x3810E000, 0x38110000, 0x38112000, 0x38114000, 0x38116000, 0x38118000, 0x3811A000, 0x3811C000, 0x3811E000,
  0x38120000, 0x38122000, 0x38124000, 0x38126000, 0x38128000, 0x3812A000, 0x3812C000, 0x3812E000, 0x38130000, 0x38132000, 0x38134000, 0x38136000, 0x38138000, 0x3813A000, 0x3813C000, 0x3813E000,
  0x38140000, 0x38142000, 0x38144000, 0x38146000, 0x38148000, 0x3814A000, 0x3814C000, 0x3814E000, 0x38150000, 0x38152000, 0x38154000, 0x38156000, 0x38158000, 0x3815A000, 0x3815C000, 0x3815E000,
  0x38160000, 0x38162000, 0x38164000, 0x38166000, 0x38168000, 0x3816A000, 0x3816C000, 0x3816E000, 0x38170000, 0x38172000, 0x38174000, 0x38176000, 0x38178000, 0x3817A000, 0x3817C000, 0x3817E000,
  0x38180000, 0x38182000, 0x38184000, 0x38186000, 0x38188000, 0x3818A000, 0x3818C000, 0x3818E000, 0x38190000, 0x38192000, 0x38194000, 0x38196000, 0x38198000, 0x3819A000, 0x3819C000, 0x3819E000,
  0x381A0000, 0x381A2000, 0x381A4000, 0x381A6000, 0x381A8000, 0x381AA000, 0x381AC000, 0x381AE000, 0x381B0000, 0x381B2000, 0x381B4000, 0x381B6000, 0x381B8000, 0x381BA000, 0x381BC000, 0x381BE000,
  0x381C0000, 0x381C2000, 0x381C4000, 0x381C6000, 0x381C8000, 0x381CA000, 0x381CC000, 0x381CE000, 0x381D0000, 0x381D2000, 0x381D4000, 0x381D6000, 0x381D8000, 0x381DA000, 0x381DC000, 0x381DE000,
  0x381E0000, 0x381E2000, 0x381E4000, 0x381E6000, 0x381E8000, 0x381EA000, 0x381EC000, 0x381EE000, 0x381F0000, 0x381F2000, 0x381F4000, 0x381F6000, 0x381F8000, 0x381FA000, 0x381FC000, 0x381FE000,
  0x38200000, 0x38202000, 0x38204000, 0x38206000, 0x38208000, 0x3820A000, 0x3820C000, 0x3820E000, 0x38210000, 0x38212000, 0x38214000, 0x38216000, 0x38218000, 0x3821A000, 0x3821C000, 0x3821E000,
  0x38220000, 0x38222000, 0x38224000, 0x38226000, 0x38228000, 0x3822A000, 0x3822C000, 0x3822E000, 0x38230000, 0x38232000, 0x38234000, 0x38236000, 0x38238000, 0x3823A000, 0x3823C000, 0x3823E000,
  0x38240000, 0x38242000, 0x38244000, 0x38246000, 0x38248000, 0x3824A000, 0x3824C000, 0x3824E000, 0x38250000, 0x38252000, 0x38254000, 0x38256000, 0x38258000, 0x3825A000, 0x3825C000, 0x3825E000,
  0x38260000, 0x38262000, 0x38264000, 0x38266000, 0x38268000, 0x3826A000, 0x3826C000, 0x3826E000, 0x38270000, 0x38272000, 0x38274000, 0x38276000, 0x38278000, 0x3827A000, 0x3827C000, 0x3827E000,
  0x38280000, 0x38282000, 0x38284000, 0x38286000, 0x38288000, 0x3828A000, 0x3828C000, 0x3828E000, 0x38290000, 0x38292000, 0x38294000, 0x38296000, 0x38298000, 0x3829A000, 0x3829C000, 0x3829E000,
  0x382A0000, 0x382A2000, 0x382A4000, 0x382A6000, 0x382A8000, 0x382AA000, 0x382AC000, 0x382AE000, 0x382B0000, 0x382B2000, 0x382B4000, 0x382B6000, 0x382B8000, 0x382BA000, 0x382BC000, 0x382BE000,
  0x382C0000, 0x382C2000, 0x382C4000, 0x382C6000, 0x382C8000, 0x382CA000, 0x382CC000, 0x382CE000, 0x382D0000, 0x382D2000, 0x382D4000, 0x382D6000, 0x382D8000, 0x382DA000, 0x382DC000, 0x382DE000,
  0x382E0000, 0x382E2000, 0x382E4000, 0x382E6000, 0x382E8000, 0x382EA000, 0x382EC000, 0x382EE000, 0x382F0000, 0x382F2000, 0x382F4000, 0x382F6000, 0x382F8000, 0x382FA000, 0x382FC000, 0x382FE000,
  0x38300000, 0x38302000, 0x38304000, 0x38306000, 0x38308000, 0x3830A000, 0x3830C000, 0x3830E000, 0x38310000, 0x38312000, 0x38314000, 0x38316000, 0x38318000, 0x3831A000, 0x3831C000, 0x3831E000,
  0x38320000, 0x38322000, 0x38324000, 0x38326000, 0x38328000, 0x3832A000, 0x3832C000, 0x3832E000, 0x38330000, 0x38332000, 0x38334000, 0x38336000, 0x38338000, 0x3833A000, 0x3833C000, 0x3833E000,
  0x38340000, 0x38342000, 0x38344000, 0x38346000, 0x38348000, 0x3834A000, 0x3834C000, 0x3834E000, 0x38350000, 0x38352000, 0x38354000, 0x38356000, 0x38358000, 0x3835A000, 0x3835C000, 0x3835E000,
  0x38360000, 0x38362000, 0x38364000, 0x38366000, 0x38368000, 0x3836A000, 0x3836C000, 0x3836E000, 0x38370000, 0x38372000, 0x38374000, 0x38376000, 0x38378000, 0x3837A000, 0x3837C000, 0x3837E000,
  0x38380000, 0x38382000, 0x38384000, 0x38386000, 0x38388000, 0x3838A000, 0x3838C000, 0x3838E000, 0x38390000, 0x38392000, 0x38394000, 0x38396000, 0x38398000, 0x3839A000, 0x3839C000, 0x3839E000,
  0x383A0000, 0x383A2000, 0x383A4000, 0x383A6000, 0x383A8000, 0x383AA000, 0x383AC000, 0x383AE000, 0x383B0000, 0x383B2000, 0x383B4000, 0x383B6000, 0x383B8000, 0x383BA000, 0x383BC000, 0x383BE000,
  0x383C0000, 0x383C2000, 0x383C4000, 0x383C6000, 0x383C8000, 0x383CA000, 0x383CC000, 0x383CE000, 0x383D0000, 0x383D2000, 0x383D4000, 0x383D6000, 0x383D8000, 0x383DA000, 0x383DC000, 0x383DE000,
  0x383E0000, 0x383E2000, 0x383E4000, 0x383E6000, 0x383E8000, 0x383EA000, 0x383EC000, 0x383EE000, 0x383F0000, 0x383F2000, 0x383F4000, 0x383F6000, 0x383F8000, 0x383FA000, 0x383FC000, 0x383FE000,
  0x38400000, 0x38402000, 0x38404000, 0x38406000, 0x38408000, 0x3840A000, 0x3840C000, 0x3840E000, 0x38410000, 0x38412000, 0x38414000, 0x38416000, 0x38418000, 0x3841A000, 0x3841C000, 0x3841E000,
  0x38420000, 0x38422000, 0x38424000, 0x38426000, 0x38428000, 0x3842A000, 0x3842C000, 0x3842E000, 0x38430000, 0x38432000, 0x38434000, 0x38436000, 0x38438000, 0x3843A000, 0x3843C000, 0x3843E000,
  0x38440000, 0x38442000, 0x38444000, 0x38446000, 0x38448000, 0x3844A000, 0x3844C000, 0x3844E000, 0x38450000, 0x38452000, 0x38454000, 0x38456000, 0x38458000, 0x3845A000, 0x3845C000, 0x3845E000,
  0x38460000, 0x38462000, 0x38464000, 0x38466000, 0x38468000, 0x3846A000, 0x3846C000, 0x3846E000, 0x38470000, 0x38472000, 0x38474000, 0x38476000, 0x38478000, 0x3847A000, 0x3847C000, 0x3847E000,
  0x38480000, 0x38482000, 0x38484000, 0x38486000, 0x38488000, 0x3848A000, 0x3848C000, 0x3848E000, 0x38490000, 0x38492000, 0x38494000, 0x38496000, 0x38498000, 0x3849A000, 0x3849C000, 0x3849E000,
  0x384A0000, 0x384A2000, 0x384A4000, 0x384A6000, 0x384A8000, 0x384AA000, 0x384AC000, 0x384AE000, 0x384B0000, 0x384B2000, 0x384B4000, 0x384B6000, 0x384B8000, 0x384BA000, 0x384BC000, 0x384BE000,
  0x384C0000, 0x384C2000, 0x384C4000, 0x384C6000, 0x384C8000, 0x384CA000, 0x384CC000, 0x384CE000, 0x384D0000, 0x384D2000, 0x384D4000, 0x384D6000, 0x384D8000, 0x384DA000, 0x384DC000, 0x384DE000,
  0x384E0000, 0x384E2000, 0x384E4000, 0x384E6000, 0x384E8000, 0x384EA000, 0x384EC000, 0x384EE000, 0x384F0000, 0x384F2000, 0x384F4000, 0x384F6000, 0x384F8000, 0x384FA000, 0x384FC000, 0x384FE000,
  0x38500000, 0x38502000, 0x38504000, 0x38506000, 0x38508000, 0x3850A000, 0x3850C000, 0x3850E000, 0x38510000, 0x38512000, 0x38514000, 0x38516000, 0x38518000, 0x3851A000, 0x3851C000, 0x3851E000,
  0x38520000, 0x38522000, 0x38524000, 0x38526000, 0x38528000, 0x3852A000, 0x3852C000, 0x3852E000, 0x38530000, 0x38532000, 0x38534000, 0x38536000, 0x38538000, 0x3853A000, 0x3853C000, 0x3853E000,
  0x38540000, 0x38542000, 0x38544000, 0x38546000, 0x38548000, 0x3854A000, 0x3854C000, 0x3854E000, 0x38550000, 0x38552000, 0x38554000, 0x38556000, 0x38558000, 0x3855A000, 0x3855C000, 0x3855E000,
  0x38560000, 0x38562000, 0x38564000, 0x38566000, 0x38568000, 0x3856A000, 0x3856C000, 0x3856E000, 0x38570000, 0x38572000, 0x38574000, 0x38576000, 0x38578000, 0x3857A000, 0x3857C000, 0x3857E000,
  0x38580000, 0x38582000, 0x38584000, 0x38586000, 0x38588000, 0x3858A000, 0x3858C000, 0x3858E000, 0x38590000, 0x38592000, 0x38594000, 0x38596000, 0x38598000, 0x3859A000, 0x3859C000, 0x3859E000,
  0x385A0000, 0x385A2000, 0x385A4000, 0x385A6000, 0x385A8000, 0x385AA000, 0x385AC000, 0x385AE000, 0x385B0000, 0x385B2000, 0x385B4000, 0x385B6000, 0x385B8000, 0x385BA000, 0x385BC000, 0x385BE000,
  0x385C0000, 0x385C2000, 0x385C4000, 0x385C6000, 0x385C8000, 0x385CA000, 0x385CC000, 0x385CE000, 0x385D0000, 0x385D2000, 0x385D4000, 0x385D6000, 0x385D8000, 0x385DA000, 0x385DC000, 0x385DE000,
  0x385E0000, 0x385E2000, 0x385E4000, 0x385E6000, 0x385E8000, 0x385EA000, 0x385EC000, 0x385EE000, 0x385F0000, 0x385F2000, 0x385F4000, 0x385F6000, 0x385F8000, 0x385FA000, 0x385FC000, 0x385FE000,
  0x38600000, 0x38602000, 0x38604000, 0x38606000, 0x38608000, 0x3860A000, 0x3860C000, 0x3860E000, 0x38610000, 0x38612000, 0x38614000, 0x38616000, 0x38618000, 0x3861A000, 0x3861C000, 0x3861E000,
  0x38620000, 0x38622000, 0x38624000, 0x38626000, 0x38628000, 0x3862A000, 0x3862C000, 0x3862E000, 0x38630000, 0x38632000, 0x38634000, 0x38636000, 0x38638000, 0x3863A000, 0x3863C000, 0x3863E000,
  0x38640000, 0x38642000, 0x38644000, 0x38646000, 0x38648000, 0x3864A000, 0x3864C000, 0x3864E000, 0x38650000, 0x38652000, 0x38654000, 0x38656000, 0x38658000, 0x3865A000, 0x3865C000, 0x3865E000,
  0x38660000, 0x38662000, 0x38664000, 0x38666000, 0x38668000, 0x3866A000, 0x3866C000, 0x3866E000, 0x38670000, 0x38672000, 0x38674000, 0x38676000, 0x38678000, 0x3867A000, 0x3867C000, 0x3867E000,
  0x38680000, 0x38682000, 0x38684000, 0x38686000, 0x38688000, 0x3868A000, 0x3868C000, 0x3868E000, 0x38690000, 0x38692000, 0x38694000, 0x38696000, 0x38698000, 0x3869A000, 0x3869C000, 0x3869E000,
  0x386A0000, 0x386A2000, 0x386A4000, 0x386A6000, 0x386A8000, 0x386AA000, 0x386AC000, 0x386AE000, 0x386B0000, 0x386B2000, 0x386B4000, 0x386B6000, 0x386B8000, 0x386BA000, 0x386BC000, 0x386BE000,
  0x386C0000, 0x386C2000, 0x386C4000, 0x386C6000, 0x386C8000, 0x386CA000, 0x386CC000, 0x386CE000, 0x386D0000, 0x386D2000, 0x386D4000, 0x386D6000, 0x386D8000, 0x386DA000, 0x386DC000, 0x386DE000,
  0x386E0000, 0x386E2000, 0x386E4000, 0x386E6000, 0x386E8000, 0x386EA000, 0x386EC000, 0x386EE000, 0x386F0000, 0x386F2000, 0x386F4000, 0x386F6000, 0x386F8000, 0x386FA000, 0x386FC000, 0x386FE000,
  0x38700000, 0x38702000, 0x38704000, 0x38706000, 0x38708000, 0x3870A000, 0x3870C000, 0x3870E000, 0x38710000, 0x38712000, 0x38714000, 0x38716000, 0x38718000, 0x3871A000, 0x3871C000, 0x3871E000,
  0x38720000, 0x38722000, 0x38724000, 0x38726000, 0x38728000, 0x3872A000, 0x3872C000, 0x3872E000, 0x38730000, 0x38732000, 0x38734000, 0x38736000, 0x38738000, 0x3873A000, 0x3873C000, 0x3873E000,
  0x38740000, 0x38742000, 0x38744000, 0x38746000, 0x38748000, 0x3874A000, 0x3874C000, 0x3874E000, 0x38750000, 0x38752000, 0x38754000, 0x38756000, 0x38758000, 0x3875A000, 0x3875C000, 0x3875E000,
  0x38760000, 0x38762000, 0x38764000, 0x38766000, 0x38768000, 0x3876A000, 0x3876C000, 0x3876E000, 0x38770000, 0x38772000, 0x38774000, 0x38776000, 0x38778000, 0x3877A000, 0x3877C000, 0x3877E000,
  0x38780000, 0x38782000, 0x38784000, 0x38786000, 0x38788000, 0x3878A000, 0x3878C000, 0x3878E000, 0x38790000, 0x38792000, 0x38794000, 0x38796000, 0x38798000, 0x3879A000, 0x3879C000, 0x3879E000,
  0x387A0000, 0x387A2000, 0x387A4000, 0x387A6000, 0x387A8000, 0x387AA000, 0x387AC000, 0x387AE000, 0x387B0000, 0x387B2000, 0x387B4000, 0x387B6000, 0x387B8000, 0x387BA000, 0x387BC000, 0x387BE000,
  0x387C0000, 0x387C2000, 0x387C4000, 0x387C6000, 0x387C8000, 0x387CA000, 0x387CC000, 0x387CE000, 0x387D0000, 0x387D2000, 0x387D4000, 0x387D6000, 0x387D8000, 0x387DA000, 0x387DC000, 0x387DE000,
  0x387E0000, 0x387E2000, 0x387E4000, 0x387E6000, 0x387E8000, 0x387EA000, 0x387EC000, 0x387EE000, 0x387F0000, 0x387F2000, 0x387F4000, 0x387F6000, 0x387F8000, 0x387FA000, 0x387FC000, 0x387FE000 };
__constant static const uint32_t exponent_table[64] = {
  0x00000000, 0x00800000, 0x01000000, 0x01800000, 0x02000000, 0x02800000, 0x03000000, 0x03800000, 0x04000000, 0x04800000, 0x05000000, 0x05800000, 0x06000000, 0x06800000, 0x07000000, 0x07800000,
  0x08000000, 0x08800000, 0x09000000, 0x09800000, 0x0A000000, 0x0A800000, 0x0B000000, 0x0B800000, 0x0C000000, 0x0C800000, 0x0D000000, 0x0D800000, 0x0E000000, 0x0E800000, 0x0F000000, 0x47800000,
  0x80000000, 0x80800000, 0x81000000, 0x81800000, 0x82000000, 0x82800000, 0x83000000, 0x83800000, 0x84000000, 0x84800000, 0x85000000, 0x85800000, 0x86000000, 0x86800000, 0x87000000, 0x87800000,
  0x88000000, 0x88800000, 0x89000000, 0x89800000, 0x8A000000, 0x8A800000, 0x8B000000, 0x8B800000, 0x8C000000, 0x8C800000, 0x8D000000, 0x8D800000, 0x8E000000, 0x8E800000, 0x8F000000, 0xC7800000 };
__constant static const unsigned short offset_table[64] = {
  0, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024,
  0, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024 };

SCALAR_FUN_ATTR uint16_t float2halfbits(float value) {
  union { float x; uint32_t y; } u;
  u.x = value;
  uint32_t bits = u.y;

  uint16_t hbits = base_table[bits>>23] + (uint16_t)((bits&0x7FFFFF)>>shift_table[bits>>23]);;

  return hbits;
}

SCALAR_FUN_ATTR float halfbits2float(uint16_t value) {
  uint32_t bits = mantissa_table[offset_table[value>>10]+(value&0x3FF)] + exponent_table[value>>10];

  union { uint32_t x; float y; } u;
  u.x = bits;
  return u.y;
}

SCALAR_FUN_ATTR uint16_t halfbitsnextafter(uint16_t from, uint16_t to) {
  int fabs = from & 0x7FFF, tabs = to & 0x7FFF;
  if(fabs > 0x7C00 || tabs > 0x7C00) {
    return ((from&0x7FFF)>0x7C00) ? (from|0x200) : (to|0x200);
  }
  if(from == to || !(fabs|tabs)) {
    return to;
  }
  if(!fabs) {
    return (to&0x8000)+1;
  }
  unsigned int out =
    from +
    (((from>>15)^(unsigned int)((from^(0x8000|(0x8000-(from>>15))))<(to^(0x8000|(0x8000-(to>>15))))))<<1)
    - 1;
  return out;
}

// End of half.h.
// Start of timing.h.

// The function get_wall_time() returns the wall time in microseconds
// (with an unspecified offset).

#ifdef _WIN32

#include <windows.h>

static int64_t get_wall_time(void) {
  LARGE_INTEGER time,freq;
  assert(QueryPerformanceFrequency(&freq));
  assert(QueryPerformanceCounter(&time));
  return ((double)time.QuadPart / freq.QuadPart) * 1000000;
}

static int64_t get_wall_time_ns(void) {
  return get_wall_time() * 1000;
}

#else
// Assuming POSIX

#include <time.h>
#include <sys/time.h>

static int64_t get_wall_time_ns(void) {
  struct timespec time;
  assert(clock_gettime(CLOCK_MONOTONIC, &time) == 0);
  return time.tv_sec * 1000000000 + time.tv_nsec;
}

static int64_t get_wall_time(void) {
  return get_wall_time_ns() / 1000;
}


#endif

// End of timing.h.
// Start of lock.h.

// A very simple cross-platform implementation of locks.  Uses
// pthreads on Unix and some Windows thing there.  Futhark's
// host-level code is not multithreaded, but user code may be, so we
// need some mechanism for ensuring atomic access to API functions.
// This is that mechanism.  It is not exposed to user code at all, so
// we do not have to worry about name collisions.

#ifdef _WIN32

typedef HANDLE lock_t;

static void create_lock(lock_t *lock) {
  *lock = CreateMutex(NULL,  // Default security attributes.
                      FALSE, // Initially unlocked.
                      NULL); // Unnamed.
}

static void lock_lock(lock_t *lock) {
  assert(WaitForSingleObject(*lock, INFINITE) == WAIT_OBJECT_0);
}

static void lock_unlock(lock_t *lock) {
  assert(ReleaseMutex(*lock));
}

static void free_lock(lock_t *lock) {
  CloseHandle(*lock);
}

#else
// Assuming POSIX

#include <pthread.h>

typedef pthread_mutex_t lock_t;

static void create_lock(lock_t *lock) {
  int r = pthread_mutex_init(lock, NULL);
  assert(r == 0);
}

static void lock_lock(lock_t *lock) {
  int r = pthread_mutex_lock(lock);
  assert(r == 0);
}

static void lock_unlock(lock_t *lock) {
  int r = pthread_mutex_unlock(lock);
  assert(r == 0);
}

static void free_lock(lock_t *lock) {
  // Nothing to do for pthreads.
  (void)lock;
}

#endif

// End of lock.h.
// Start of free_list.h.

typedef uintptr_t fl_mem;

// An entry in the free list.  May be invalid, to avoid having to
// deallocate entries as soon as they are removed.  There is also a
// tag, to help with memory reuse.
struct free_list_entry {
  size_t size;
  fl_mem mem;
  const char *tag;
  unsigned char valid;
};

struct free_list {
  struct free_list_entry *entries; // Pointer to entries.
  int capacity;                    // Number of entries.
  int used;                        // Number of valid entries.
  lock_t lock;                     // Thread safety.
};

static void free_list_init(struct free_list *l) {
  l->capacity = 30; // Picked arbitrarily.
  l->used = 0;
  l->entries = (struct free_list_entry*) malloc(sizeof(struct free_list_entry) * l->capacity);
  for (int i = 0; i < l->capacity; i++) {
    l->entries[i].valid = 0;
  }
  create_lock(&l->lock);
}

// Remove invalid entries from the free list.
static void free_list_pack(struct free_list *l) {
  lock_lock(&l->lock);
  int p = 0;
  for (int i = 0; i < l->capacity; i++) {
    if (l->entries[i].valid) {
      l->entries[p] = l->entries[i];
      if (i > p) {
        l->entries[i].valid = 0;
      }
      p++;
    }
  }

  // Now p is the number of used elements.  We don't want it to go
  // less than the default capacity (although in practice it's OK as
  // long as it doesn't become 1).
  if (p < 30) {
    p = 30;
  }
  l->entries = realloc(l->entries, p * sizeof(struct free_list_entry));
  l->capacity = p;
  lock_unlock(&l->lock);
}

static void free_list_destroy(struct free_list *l) {
  assert(l->used == 0);
  free(l->entries);
  free_lock(&l->lock);
}

// Not part of the interface, so no locking.
static int free_list_find_invalid(struct free_list *l) {
  int i;
  for (i = 0; i < l->capacity; i++) {
    if (!l->entries[i].valid) {
      break;
    }
  }
  return i;
}

static void free_list_insert(struct free_list *l, size_t size, fl_mem mem, const char *tag) {
  lock_lock(&l->lock);
  int i = free_list_find_invalid(l);

  if (i == l->capacity) {
    // List is full; so we have to grow it.
    int new_capacity = l->capacity * 2 * sizeof(struct free_list_entry);
    l->entries = realloc(l->entries, new_capacity);
    for (int j = 0; j < l->capacity; j++) {
      l->entries[j+l->capacity].valid = 0;
    }
    l->capacity *= 2;
  }

  // Now 'i' points to the first invalid entry.
  l->entries[i].valid = 1;
  l->entries[i].size = size;
  l->entries[i].mem = mem;
  l->entries[i].tag = tag;

  l->used++;
  lock_unlock(&l->lock);
}

// Determine whether this entry in the free list is acceptable for
// satisfying the request.  Not public, so no locking.
static bool free_list_acceptable(size_t size, const char* tag, struct free_list_entry *entry) {
  // We check not just the hard requirement (is the entry acceptable
  // and big enough?) but also put a cap on how much wasted space
  // (internal fragmentation) we allow.  This is necessarily a
  // heuristic, and a crude one.

  if (!entry->valid) {
    return false;
  }

  if (size > entry->size) {
    return false;
  }

  // We know the block fits.  Now the question is whether it is too
  // big.  Our policy is as follows:
  //
  // 1) We don't care about wasted space below 4096 bytes (to avoid
  // churn in tiny allocations).
  //
  // 2) If the tag matches, we allow _any_ amount of wasted space.
  //
  // 3) Otherwise we allow up to 50% wasted space.

  if (entry->size < 4096) {
    return true;
  }

  if (entry->tag == tag) {
    return true;
  }

  if (entry->size < size * 2) {
    return true;
  }

  return false;
}

// Find and remove a memory block of the indicated tag, or if that
// does not exist, another memory block with exactly the desired size.
// Returns 0 on success.
static int free_list_find(struct free_list *l, size_t size, const char *tag,
                          size_t *size_out, fl_mem *mem_out) {
  lock_lock(&l->lock);
  int size_match = -1;
  int i;
  int ret = 1;
  for (i = 0; i < l->capacity; i++) {
    if (free_list_acceptable(size, tag, &l->entries[i]) &&
        (size_match < 0 || l->entries[i].size < l->entries[size_match].size)) {
      // If this entry is valid, has sufficient size, and is smaller than the
      // best entry found so far, use this entry.
      size_match = i;
    }
  }

  if (size_match >= 0) {
    l->entries[size_match].valid = 0;
    *size_out = l->entries[size_match].size;
    *mem_out = l->entries[size_match].mem;
    l->used--;
    ret = 0;
  }
  lock_unlock(&l->lock);
  return ret;
}

// Remove the first block in the free list.  Returns 0 if a block was
// removed, and nonzero if the free list was already empty.
static int free_list_first(struct free_list *l, fl_mem *mem_out) {
  lock_lock(&l->lock);
  int ret = 1;
  for (int i = 0; i < l->capacity; i++) {
    if (l->entries[i].valid) {
      l->entries[i].valid = 0;
      *mem_out = l->entries[i].mem;
      l->used--;
      ret = 0;
      break;
    }
  }
  lock_unlock(&l->lock);
  return ret;
}

// End of free_list.h.
// Start of event_list.h

typedef int (*event_report_fn)(struct str_builder*, void*);

// A collection of key-value associations. Used to associate extra data with
// events.
struct kvs {
  // A buffer that contains all value data. Must be freed when the struct kvs is
  // no longer used.
  char *buf;

  // Size of buf in bytes.
  size_t buf_size;

  // Number of bytes used in buf.
  size_t buf_used;

  // Number of associations stored.
  size_t n;

  // Capacity of vals.
  size_t vals_capacity;

  // An array of keys.
  const char* *keys;

  // Indexes into 'buf' that contains the values as zero-terminated strings.
  size_t *vals;
};

static const size_t KVS_INIT_BUF_SIZE = 128;
static const size_t KVS_INIT_NUMKEYS = 8;

void kvs_init(struct kvs* kvs) {
  kvs->buf = malloc(KVS_INIT_BUF_SIZE);
  kvs->buf_size = KVS_INIT_BUF_SIZE;
  kvs->buf_used = 0;
  kvs->vals_capacity = KVS_INIT_NUMKEYS;
  kvs->keys = calloc(kvs->vals_capacity, sizeof(const char*));
  kvs->vals = calloc(kvs->vals_capacity, sizeof(size_t));
  kvs->n = 0;
}

struct kvs* kvs_new(void) {
  struct kvs *kvs = malloc(sizeof(struct kvs));
  kvs_init(kvs);
  return kvs;
}

void kvs_printf(struct kvs* kvs, const char* key, const char* fmt, ...) {
  va_list vl;
  va_start(vl, fmt);

  size_t needed = 1 + (size_t)vsnprintf(NULL, 0, fmt, vl);

  while (kvs->buf_used+needed > kvs->buf_size) {
    kvs->buf_size *= 2;
    kvs->buf = realloc(kvs->buf, kvs->buf_size * sizeof(const char*));
  }

  if (kvs->n == kvs->vals_capacity) {
    kvs->vals_capacity *= 2;
    kvs->vals = realloc(kvs->vals, kvs->vals_capacity * sizeof(size_t));
    kvs->keys = realloc(kvs->keys, kvs->vals_capacity * sizeof(char*));
  }

  kvs->keys[kvs->n] = key;
  kvs->vals[kvs->n] = kvs->buf_used;
  kvs->buf_used += needed;

  va_start(vl, fmt); // Must re-init.
  vsnprintf(&kvs->buf[kvs->vals[kvs->n]], needed, fmt, vl);

  kvs->n++;
}

void kvs_free(struct kvs* kvs) {
  free(kvs->vals);
  free(kvs->keys);
  free(kvs->buf);
}

// Assumes all of the values are valid JSON objects.
void kvs_json(const struct kvs* kvs, struct str_builder *sb) {
  str_builder_char(sb, '{');
  for (size_t i = 0; i < kvs->n; i++) {
    if (i != 0) {
      str_builder_str(sb, ",");
    }
    str_builder_json_str(sb, kvs->keys[i]);
    str_builder_str(sb, ":");
    str_builder_str(sb, &kvs->buf[kvs->vals[i]]);
  }
  str_builder_char(sb, '}');
}

void kvs_log(const struct kvs* kvs, const char* prefix, FILE* f) {
  for (size_t i = 0; i < kvs->n; i++) {
    fprintf(f, "%s%s: %s\n",
            prefix,
            kvs->keys[i],
            &kvs->buf[kvs->vals[i]]);
  }
}

struct event {
  void* data;
  event_report_fn f;
  const char* name;
  const char *provenance;
  // Key-value information that is also to be printed.
  struct kvs *kvs;
};

struct event_list {
  struct event *events;
  int num_events;
  int capacity;
};

static void event_list_init(struct event_list *l) {
  l->capacity = 100;
  l->num_events = 0;
  l->events = calloc(l->capacity, sizeof(struct event));
}

static void event_list_free(struct event_list *l) {
  free(l->events);
}

static void add_event_to_list(struct event_list *l,
                              const char* name,
                              const char* provenance,
                              struct kvs *kvs,
                              void* data,
                              event_report_fn f) {
  if (l->num_events == l->capacity) {
    l->capacity *= 2;
    l->events = realloc(l->events, l->capacity * sizeof(struct event));
  }
  l->events[l->num_events].name = name;
  l->events[l->num_events].provenance =
    provenance ? provenance : "unknown";
  l->events[l->num_events].kvs = kvs;
  l->events[l->num_events].data = data;
  l->events[l->num_events].f = f;
  l->num_events++;
}

static int report_events_in_list(struct event_list *l,
                                 struct str_builder* sb) {
  int ret = 0;
  for (int i = 0; i < l->num_events; i++) {
    if (i != 0) {
      str_builder_str(sb, ",");
    }
    str_builder_str(sb, "{\"name\":");
    str_builder_json_str(sb, l->events[i].name);
    str_builder_str(sb, ",\"provenance\":");
    str_builder_json_str(sb, l->events[i].provenance);
    if (l->events[i].f(sb, l->events[i].data) != 0) {
      ret = 1;
      break;
    }

    str_builder_str(sb, ",\"details\":");
    if (l->events[i].kvs) {
      kvs_json(l->events[i].kvs, sb);
      kvs_free(l->events[i].kvs);
    } else {
      str_builder_str(sb, "{}");
    }

    str_builder(sb, "}");
  }
  event_list_free(l);
  event_list_init(l);
  return ret;
}

// End of event_list.h
#include <getopt.h>
#include <ctype.h>
#include <inttypes.h>
static const char *entry_point = "main";
// Start of values.h.

//// Text I/O

typedef int (*writer)(FILE*, const void*);
typedef int (*bin_reader)(void*);
typedef int (*str_reader)(const char *, void*);

struct array_reader {
  char* elems;
  int64_t n_elems_space;
  int64_t elem_size;
  int64_t n_elems_used;
  int64_t *shape;
  str_reader elem_reader;
};

static void skipspaces(FILE *f) {
  int c;
  do {
    c = getc(f);
  } while (isspace(c));

  if (c != EOF) {
    ungetc(c, f);
  }
}

static int constituent(char c) {
  return isalnum(c) || c == '.' || c == '-' || c == '+' || c == '_';
}

// Produces an empty token only on EOF.
static void next_token(FILE *f, char *buf, int bufsize) {
 start:
  skipspaces(f);

  int i = 0;
  while (i < bufsize) {
    int c = getc(f);
    buf[i] = (char)c;

    if (c == EOF) {
      buf[i] = 0;
      return;
    } else if (c == '-' && i == 1 && buf[0] == '-') {
      // Line comment, so skip to end of line and start over.
      for (; c != '\n' && c != EOF; c = getc(f));
      goto start;
    } else if (!constituent((char)c)) {
      if (i == 0) {
        // We permit single-character tokens that are not
        // constituents; this lets things like ']' and ',' be
        // tokens.
        buf[i+1] = 0;
        return;
      } else {
        ungetc(c, f);
        buf[i] = 0;
        return;
      }
    }

    i++;
  }

  buf[bufsize-1] = 0;
}

static int next_token_is(FILE *f, char *buf, int bufsize, const char* expected) {
  next_token(f, buf, bufsize);
  return strcmp(buf, expected) == 0;
}

static void remove_underscores(char *buf) {
  char *w = buf;

  for (char *r = buf; *r; r++) {
    if (*r != '_') {
      *w++ = *r;
    }
  }

  *w++ = 0;
}

static int read_str_elem(char *buf, struct array_reader *reader) {
  int ret;
  if (reader->n_elems_used == reader->n_elems_space) {
    reader->n_elems_space *= 2;
    reader->elems = (char*) realloc(reader->elems,
                                    (size_t)(reader->n_elems_space * reader->elem_size));
  }

  ret = reader->elem_reader(buf, reader->elems + reader->n_elems_used * reader->elem_size);

  if (ret == 0) {
    reader->n_elems_used++;
  }

  return ret;
}

static int read_str_array_elems(FILE *f,
                                char *buf, int bufsize,
                                struct array_reader *reader, int64_t dims) {
  int ret = 1;
  int expect_elem = 1;
  char *knows_dimsize = (char*) calloc((size_t)dims, sizeof(char));
  int cur_dim = (int)dims-1;
  int64_t *elems_read_in_dim = (int64_t*) calloc((size_t)dims, sizeof(int64_t));

  while (1) {
    next_token(f, buf, bufsize);
    if (strcmp(buf, "]") == 0) {
      expect_elem = 0;
      if (knows_dimsize[cur_dim]) {
        if (reader->shape[cur_dim] != elems_read_in_dim[cur_dim]) {
          ret = 1;
          break;
        }
      } else {
        knows_dimsize[cur_dim] = 1;
        reader->shape[cur_dim] = elems_read_in_dim[cur_dim];
      }
      if (cur_dim == 0) {
        ret = 0;
        break;
      } else {
        cur_dim--;
        elems_read_in_dim[cur_dim]++;
      }
    } else if (!expect_elem && strcmp(buf, ",") == 0) {
      expect_elem = 1;
    } else if (expect_elem) {
      if (strcmp(buf, "[") == 0) {
        if (cur_dim == dims - 1) {
          ret = 1;
          break;
        }
        cur_dim++;
        elems_read_in_dim[cur_dim] = 0;
      } else if (cur_dim == dims - 1) {
        ret = read_str_elem(buf, reader);
        if (ret != 0) {
          break;
        }
        expect_elem = 0;
        elems_read_in_dim[cur_dim]++;
      } else {
        ret = 1;
        break;
      }
    } else {
      ret = 1;
      break;
    }
  }

  free(knows_dimsize);
  free(elems_read_in_dim);
  return ret;
}

static int read_str_empty_array(FILE *f, char *buf, int bufsize,
                                const char *type_name, int64_t *shape, int64_t dims) {
  if (strlen(buf) == 0) {
    // EOF
    return 1;
  }

  if (strcmp(buf, "empty") != 0) {
    return 1;
  }

  if (!next_token_is(f, buf, bufsize, "(")) {
    return 1;
  }

  for (int i = 0; i < dims; i++) {
    if (!next_token_is(f, buf, bufsize, "[")) {
      return 1;
    }

    next_token(f, buf, bufsize);

    if (sscanf(buf, "%"SCNu64, (uint64_t*)&shape[i]) != 1) {
      return 1;
    }

    if (!next_token_is(f, buf, bufsize, "]")) {
      return 1;
    }
  }

  if (!next_token_is(f, buf, bufsize, type_name)) {
    return 1;
  }


  if (!next_token_is(f, buf, bufsize, ")")) {
    return 1;
  }

  // Check whether the array really is empty.
  for (int i = 0; i < dims; i++) {
    if (shape[i] == 0) {
      return 0;
    }
  }

  // Not an empty array!
  return 1;
}

static int read_str_array(FILE *f,
                          int64_t elem_size, str_reader elem_reader,
                          const char *type_name,
                          void **data, int64_t *shape, int64_t dims) {
  int ret;
  struct array_reader reader;
  char buf[100];

  int dims_seen;
  for (dims_seen = 0; dims_seen < dims; dims_seen++) {
    if (!next_token_is(f, buf, sizeof(buf), "[")) {
      break;
    }
  }

  if (dims_seen == 0) {
    return read_str_empty_array(f, buf, sizeof(buf), type_name, shape, dims);
  }

  if (dims_seen != dims) {
    return 1;
  }

  reader.shape = shape;
  reader.n_elems_used = 0;
  reader.elem_size = elem_size;
  reader.n_elems_space = 16;
  reader.elems = (char*) realloc(*data, (size_t)(elem_size*reader.n_elems_space));
  reader.elem_reader = elem_reader;

  ret = read_str_array_elems(f, buf, sizeof(buf), &reader, dims);

  *data = reader.elems;

  return ret;
}

#define READ_STR(MACRO, PTR, SUFFIX)                                   \
  remove_underscores(buf);                                              \
  int j;                                                                \
  if (sscanf(buf, "%"MACRO"%n", (PTR*)dest, &j) == 1) {                 \
    return !(strcmp(buf+j, "") == 0 || strcmp(buf+j, SUFFIX) == 0);     \
  } else {                                                              \
    return 1;                                                           \
  }

static int read_str_i8(char *buf, void* dest) {
  // Some platforms (WINDOWS) does not support scanf %hhd or its
  // cousin, %SCNi8.  Read into int first to avoid corrupting
  // memory.
  //
  // https://gcc.gnu.org/bugzilla/show_bug.cgi?id=63417
  remove_underscores(buf);
  int j, x;
  if (sscanf(buf, "%i%n", &x, &j) == 1) {
    *(int8_t*)dest = (int8_t)x;
    return !(strcmp(buf+j, "") == 0 || strcmp(buf+j, "i8") == 0);
  } else {
    return 1;
  }
}

static int read_str_u8(char *buf, void* dest) {
  // Some platforms (WINDOWS) does not support scanf %hhd or its
  // cousin, %SCNu8.  Read into int first to avoid corrupting
  // memory.
  //
  // https://gcc.gnu.org/bugzilla/show_bug.cgi?id=63417
  remove_underscores(buf);
  int j, x;
  if (sscanf(buf, "%i%n", &x, &j) == 1) {
    *(uint8_t*)dest = (uint8_t)x;
    return !(strcmp(buf+j, "") == 0 || strcmp(buf+j, "u8") == 0);
  } else {
    return 1;
  }
}

static int read_str_i16(char *buf, void* dest) {
  READ_STR(SCNi16, int16_t, "i16");
}

static int read_str_u16(char *buf, void* dest) {
  READ_STR(SCNi16, int16_t, "u16");
}

static int read_str_i32(char *buf, void* dest) {
  READ_STR(SCNi32, int32_t, "i32");
}

static int read_str_u32(char *buf, void* dest) {
  READ_STR(SCNi32, int32_t, "u32");
}

static int read_str_i64(char *buf, void* dest) {
  READ_STR(SCNi64, int64_t, "i64");
}

static int read_str_u64(char *buf, void* dest) {
  // FIXME: This is not correct, as SCNu64 only permits decimal
  // literals.  However, SCNi64 does not handle very large numbers
  // correctly (it's really for signed numbers, so that's fair).
  READ_STR(SCNu64, uint64_t, "u64");
}

static int read_str_f16(char *buf, void* dest) {
  remove_underscores(buf);
  if (strcmp(buf, "f16.nan") == 0) {
    *(uint16_t*)dest = float2halfbits(NAN);
    return 0;
  } else if (strcmp(buf, "f16.inf") == 0) {
    *(uint16_t*)dest = float2halfbits(INFINITY);
    return 0;
  } else if (strcmp(buf, "-f16.inf") == 0) {
    *(uint16_t*)dest = float2halfbits(-INFINITY);
    return 0;
  } else {
    int j;
    float x;
    if (sscanf(buf, "%f%n", &x, &j) == 1) {
      if (strcmp(buf+j, "") == 0 || strcmp(buf+j, "f16") == 0) {
        *(uint16_t*)dest = float2halfbits(x);
        return 0;
      }
    }
    return 1;
  }
}

static int read_str_f32(char *buf, void* dest) {
  remove_underscores(buf);
  if (strcmp(buf, "f32.nan") == 0) {
    *(float*)dest = (float)NAN;
    return 0;
  } else if (strcmp(buf, "f32.inf") == 0) {
    *(float*)dest = (float)INFINITY;
    return 0;
  } else if (strcmp(buf, "-f32.inf") == 0) {
    *(float*)dest = (float)-INFINITY;
    return 0;
  } else {
    READ_STR("f", float, "f32");
  }
}

static int read_str_f64(char *buf, void* dest) {
  remove_underscores(buf);
  if (strcmp(buf, "f64.nan") == 0) {
    *(double*)dest = (double)NAN;
    return 0;
  } else if (strcmp(buf, "f64.inf") == 0) {
    *(double*)dest = (double)INFINITY;
    return 0;
  } else if (strcmp(buf, "-f64.inf") == 0) {
    *(double*)dest = (double)-INFINITY;
    return 0;
  } else {
    READ_STR("lf", double, "f64");
  }
}

static int read_str_bool(char *buf, void* dest) {
  if (strcmp(buf, "true") == 0) {
    *(char*)dest = 1;
    return 0;
  } else if (strcmp(buf, "false") == 0) {
    *(char*)dest = 0;
    return 0;
  } else {
    return 1;
  }
}

static int write_str_i8(FILE *out, int8_t *src) {
  return fprintf(out, "%hhdi8", *src);
}

static int write_str_u8(FILE *out, uint8_t *src) {
  return fprintf(out, "%hhuu8", *src);
}

static int write_str_i16(FILE *out, int16_t *src) {
  return fprintf(out, "%hdi16", *src);
}

static int write_str_u16(FILE *out, uint16_t *src) {
  return fprintf(out, "%huu16", *src);
}

static int write_str_i32(FILE *out, int32_t *src) {
  return fprintf(out, "%di32", *src);
}

static int write_str_u32(FILE *out, uint32_t *src) {
  return fprintf(out, "%uu32", *src);
}

static int write_str_i64(FILE *out, int64_t *src) {
  return fprintf(out, "%"PRIi64"i64", *src);
}

static int write_str_u64(FILE *out, uint64_t *src) {
  return fprintf(out, "%"PRIu64"u64", *src);
}

static int write_str_f16(FILE *out, uint16_t *src) {
  float x = halfbits2float(*src);
  if (isnan(x)) {
    return fprintf(out, "f16.nan");
  } else if (isinf(x) && x >= 0) {
    return fprintf(out, "f16.inf");
  } else if (isinf(x)) {
    return fprintf(out, "-f16.inf");
  } else {
    return fprintf(out, "%.*ff16", FLT_DIG, x);
  }
}

static int write_str_f32(FILE *out, float *src) {
  float x = *src;
  if (isnan(x)) {
    return fprintf(out, "f32.nan");
  } else if (isinf(x) && x >= 0) {
    return fprintf(out, "f32.inf");
  } else if (isinf(x)) {
    return fprintf(out, "-f32.inf");
  } else {
    return fprintf(out, "%.*ff32", FLT_DIG, x);
  }
}

static int write_str_f64(FILE *out, double *src) {
  double x = *src;
  if (isnan(x)) {
    return fprintf(out, "f64.nan");
  } else if (isinf(x) && x >= 0) {
    return fprintf(out, "f64.inf");
  } else if (isinf(x)) {
    return fprintf(out, "-f64.inf");
  } else {
    return fprintf(out, "%.*ff64", DBL_DIG, x);
  }
}

static int write_str_bool(FILE *out, void *src) {
  return fprintf(out, *(char*)src ? "true" : "false");
}

//// Binary I/O

#define BINARY_FORMAT_VERSION 2
#define IS_BIG_ENDIAN (!*(unsigned char *)&(uint16_t){1})

static void flip_bytes(size_t elem_size, unsigned char *elem) {
  for (size_t j=0; j<elem_size/2; j++) {
    unsigned char head = elem[j];
    size_t tail_index = elem_size-1-j;
    elem[j] = elem[tail_index];
    elem[tail_index] = head;
  }
}

// On Windows we need to explicitly set the file mode to not mangle
// newline characters.  On *nix there is no difference.
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
static void set_binary_mode(FILE *f) {
  setmode(fileno(f), O_BINARY);
}
#else
static void set_binary_mode(FILE *f) {
  (void)f;
}
#endif

static int read_byte(FILE *f, void* dest) {
  size_t num_elems_read = fread(dest, 1, 1, f);
  return num_elems_read == 1 ? 0 : 1;
}

//// Types

struct primtype_info_t {
  const char binname[4]; // Used for parsing binary data.
  const char* type_name; // Same name as in Futhark.
  const int64_t size; // in bytes
  const writer write_str; // Write in text format.
  const str_reader read_str; // Read in text format.
};

static const struct primtype_info_t i8_info =
  {.binname = "  i8", .type_name = "i8",   .size = 1,
   .write_str = (writer)write_str_i8, .read_str = (str_reader)read_str_i8};
static const struct primtype_info_t i16_info =
  {.binname = " i16", .type_name = "i16",  .size = 2,
   .write_str = (writer)write_str_i16, .read_str = (str_reader)read_str_i16};
static const struct primtype_info_t i32_info =
  {.binname = " i32", .type_name = "i32",  .size = 4,
   .write_str = (writer)write_str_i32, .read_str = (str_reader)read_str_i32};
static const struct primtype_info_t i64_info =
  {.binname = " i64", .type_name = "i64",  .size = 8,
   .write_str = (writer)write_str_i64, .read_str = (str_reader)read_str_i64};
static const struct primtype_info_t u8_info =
  {.binname = "  u8", .type_name = "u8",   .size = 1,
   .write_str = (writer)write_str_u8, .read_str = (str_reader)read_str_u8};
static const struct primtype_info_t u16_info =
  {.binname = " u16", .type_name = "u16",  .size = 2,
   .write_str = (writer)write_str_u16, .read_str = (str_reader)read_str_u16};
static const struct primtype_info_t u32_info =
  {.binname = " u32", .type_name = "u32",  .size = 4,
   .write_str = (writer)write_str_u32, .read_str = (str_reader)read_str_u32};
static const struct primtype_info_t u64_info =
  {.binname = " u64", .type_name = "u64",  .size = 8,
   .write_str = (writer)write_str_u64, .read_str = (str_reader)read_str_u64};
static const struct primtype_info_t f16_info =
  {.binname = " f16", .type_name = "f16",  .size = 2,
   .write_str = (writer)write_str_f16, .read_str = (str_reader)read_str_f16};
static const struct primtype_info_t f32_info =
  {.binname = " f32", .type_name = "f32",  .size = 4,
   .write_str = (writer)write_str_f32, .read_str = (str_reader)read_str_f32};
static const struct primtype_info_t f64_info =
  {.binname = " f64", .type_name = "f64",  .size = 8,
   .write_str = (writer)write_str_f64, .read_str = (str_reader)read_str_f64};
static const struct primtype_info_t bool_info =
  {.binname = "bool", .type_name = "bool", .size = 1,
   .write_str = (writer)write_str_bool, .read_str = (str_reader)read_str_bool};

static const struct primtype_info_t* primtypes[] = {
  &i8_info, &i16_info, &i32_info, &i64_info,
  &u8_info, &u16_info, &u32_info, &u64_info,
  &f16_info, &f32_info, &f64_info,
  &bool_info,
  NULL // NULL-terminated
};

// General value interface.  All endian business taken care of at
// lower layers.

static int read_is_binary(FILE *f) {
  skipspaces(f);
  int c = getc(f);
  if (c == 'b') {
    int8_t bin_version;
    int ret = read_byte(f, &bin_version);

    if (ret != 0) { futhark_panic(1, "binary-input: could not read version.\n"); }

    if (bin_version != BINARY_FORMAT_VERSION) {
      futhark_panic(1, "binary-input: File uses version %i, but I only understand version %i.\n",
            bin_version, BINARY_FORMAT_VERSION);
    }

    return 1;
  }
  ungetc(c, f);
  return 0;
}

static const struct primtype_info_t* read_bin_read_type_enum(FILE *f) {
  char read_binname[4];

  int num_matched = fscanf(f, "%4c", read_binname);
  if (num_matched != 1) { futhark_panic(1, "binary-input: Couldn't read element type.\n"); }

  const struct primtype_info_t **type = primtypes;

  for (; *type != NULL; type++) {
    // I compare the 4 characters manually instead of using strncmp because
    // this allows any value to be used, also NULL bytes
    if (memcmp(read_binname, (*type)->binname, 4) == 0) {
      return *type;
    }
  }
  futhark_panic(1, "binary-input: Did not recognize the type '%s'.\n", read_binname);
  return NULL;
}

static void read_bin_ensure_scalar(FILE *f, const struct primtype_info_t *expected_type) {
  int8_t bin_dims;
  int ret = read_byte(f, &bin_dims);
  if (ret != 0) { futhark_panic(1, "binary-input: Couldn't get dims.\n"); }

  if (bin_dims != 0) {
    futhark_panic(1, "binary-input: Expected scalar (0 dimensions), but got array with %i dimensions.\n",
          bin_dims);
  }

  const struct primtype_info_t *bin_type = read_bin_read_type_enum(f);
  if (bin_type != expected_type) {
    futhark_panic(1, "binary-input: Expected scalar of type %s but got scalar of type %s.\n",
          expected_type->type_name,
          bin_type->type_name);
  }
}

//// High-level interface

static int read_bin_array(FILE *f,
                          const struct primtype_info_t *expected_type, void **data, int64_t *shape, int64_t dims) {
  int ret;

  int8_t bin_dims;
  ret = read_byte(f, &bin_dims);
  if (ret != 0) { futhark_panic(1, "binary-input: Couldn't get dims.\n"); }

  if (bin_dims != dims) {
    futhark_panic(1, "binary-input: Expected %i dimensions, but got array with %i dimensions.\n",
          dims, bin_dims);
  }

  const struct primtype_info_t *bin_primtype = read_bin_read_type_enum(f);
  if (expected_type != bin_primtype) {
    futhark_panic(1, "binary-input: Expected %iD-array with element type '%s' but got %iD-array with element type '%s'.\n",
          dims, expected_type->type_name, dims, bin_primtype->type_name);
  }

  int64_t elem_count = 1;
  for (int i=0; i<dims; i++) {
    int64_t bin_shape;
    ret = (int)fread(&bin_shape, sizeof(bin_shape), 1, f);
    if (ret != 1) {
      futhark_panic(1, "binary-input: Couldn't read size for dimension %i of array.\n", i);
    }
    if (IS_BIG_ENDIAN) {
      flip_bytes(sizeof(bin_shape), (unsigned char*) &bin_shape);
    }
    elem_count *= bin_shape;
    shape[i] = bin_shape;
  }

  int64_t elem_size = expected_type->size;
  void* tmp = realloc(*data, (size_t)(elem_count * elem_size));
  if (tmp == NULL) {
    futhark_panic(1, "binary-input: Failed to allocate array of size %i.\n",
          elem_count * elem_size);
  }
  *data = tmp;

  int64_t num_elems_read = (int64_t)fread(*data, (size_t)elem_size, (size_t)elem_count, f);
  if (num_elems_read != elem_count) {
    futhark_panic(1, "binary-input: tried to read %i elements of an array, but only got %i elements.\n",
          elem_count, num_elems_read);
  }

  // If we're on big endian platform we must change all multibyte elements
  // from using little endian to big endian
  if (IS_BIG_ENDIAN && elem_size != 1) {
    flip_bytes((size_t)elem_size, (unsigned char*) *data);
  }

  return 0;
}

static int read_array(FILE *f, const struct primtype_info_t *expected_type, void **data, int64_t *shape, int64_t dims) {
  if (!read_is_binary(f)) {
    return read_str_array(f, expected_type->size, (str_reader)expected_type->read_str, expected_type->type_name, data, shape, dims);
  } else {
    return read_bin_array(f, expected_type, data, shape, dims);
  }
}

static int end_of_input(FILE *f) {
  skipspaces(f);
  char token[2];
  next_token(f, token, sizeof(token));
  if (strcmp(token, "") == 0) {
    return 0;
  } else {
    return 1;
  }
}

static int write_str_array(FILE *out,
                           const struct primtype_info_t *elem_type,
                           const unsigned char *data,
                           const int64_t *shape,
                           int8_t rank) {
  if (rank==0) {
    elem_type->write_str(out, (const void*)data);
  } else {
    int64_t len = (int64_t)shape[0];
    int64_t slice_size = 1;

    int64_t elem_size = elem_type->size;
    for (int8_t i = 1; i < rank; i++) {
      slice_size *= shape[i];
    }

    if (len*slice_size == 0) {
      fprintf(out, "empty(");
      for (int64_t i = 0; i < rank; i++) {
        fprintf(out, "[%"PRIi64"]", shape[i]);
      }
      fprintf(out, "%s", elem_type->type_name);
      fprintf(out, ")");
    } else if (rank==1) {
      fputc('[', out);
      for (int64_t i = 0; i < len; i++) {
        elem_type->write_str(out, (const void*) (data + i * elem_size));
        if (i != len-1) {
          fprintf(out, ", ");
        }
      }
      fputc(']', out);
    } else {
      fputc('[', out);
      for (int64_t i = 0; i < len; i++) {
        write_str_array(out, elem_type, data + i * slice_size * elem_size, shape+1, rank-1);
        if (i != len-1) {
          fprintf(out, ", ");
        }
      }
      fputc(']', out);
    }
  }
  return 0;
}

static int write_bin_array(FILE *out,
                           const struct primtype_info_t *elem_type,
                           const unsigned char *data,
                           const int64_t *shape,
                           int8_t rank) {
  int64_t num_elems = 1;
  for (int64_t i = 0; i < rank; i++) {
    num_elems *= shape[i];
  }

  fputc('b', out);
  fputc((char)BINARY_FORMAT_VERSION, out);
  fwrite(&rank, sizeof(int8_t), 1, out);
  fwrite(elem_type->binname, 4, 1, out);
  if (shape != NULL) {
    fwrite(shape, sizeof(int64_t), (size_t)rank, out);
  }

  if (IS_BIG_ENDIAN) {
    for (int64_t i = 0; i < num_elems; i++) {
      const unsigned char *elem = data+i*elem_type->size;
      for (int64_t j = 0; j < elem_type->size; j++) {
        fwrite(&elem[elem_type->size-j], 1, 1, out);
      }
    }
  } else {
    fwrite(data, (size_t)elem_type->size, (size_t)num_elems, out);
  }

  return 0;
}

static int write_array(FILE *out, int write_binary,
                       const struct primtype_info_t *elem_type,
                       const void *data,
                       const int64_t *shape,
                       const int8_t rank) {
  if (write_binary) {
    return write_bin_array(out, elem_type, data, shape, rank);
  } else {
    return write_str_array(out, elem_type, data, shape, rank);
  }
}

static int read_scalar(FILE *f,
                       const struct primtype_info_t *expected_type, void *dest) {
  if (!read_is_binary(f)) {
    char buf[100];
    next_token(f, buf, sizeof(buf));
    return expected_type->read_str(buf, dest);
  } else {
    read_bin_ensure_scalar(f, expected_type);
    size_t elem_size = (size_t)expected_type->size;
    size_t num_elems_read = fread(dest, elem_size, 1, f);
    if (IS_BIG_ENDIAN) {
      flip_bytes(elem_size, (unsigned char*) dest);
    }
    return num_elems_read == 1 ? 0 : 1;
  }
}

static int write_scalar(FILE *out, int write_binary, const struct primtype_info_t *type, void *src) {
  if (write_binary) {
    return write_bin_array(out, type, src, NULL, 0);
  } else {
    return type->write_str(out, src);
  }
}

// End of values.h.

// Start of server.h.

// Forward declarations of things that we technically don't know until
// the application header file is included, but which we need.
struct futhark_context_config;
struct futhark_context;
char *futhark_context_get_error(struct futhark_context *ctx);
int futhark_context_sync(struct futhark_context *ctx);
int futhark_context_clear_caches(struct futhark_context *ctx);
int futhark_context_config_set_tuning_param(struct futhark_context_config *cfg,
                                            const char *param_name,
                                            size_t new_value);
int futhark_get_tuning_param_count(void);
const char* futhark_get_tuning_param_name(int i);
const char* futhark_get_tuning_param_class(int i);

typedef int (*restore_fn)(const void*, FILE *, struct futhark_context*, void*);
typedef void (*store_fn)(const void*, FILE *, struct futhark_context*, void*);
typedef int (*free_fn)(const void*, struct futhark_context*, void*);
typedef int (*project_fn)(struct futhark_context*, void*, const void*);
typedef int (*new_fn)(struct futhark_context*, void**, const void*[]);

struct field {
  const char *name;
  const struct type *type;
  project_fn project;
};

struct record {
  int num_fields;
  const struct field* fields;
  new_fn new;
};

struct type {
  const char *name;
  restore_fn restore;
  store_fn store;
  free_fn free;
  const void *aux;
  const struct record *record;
};

int free_scalar(const void *aux, struct futhark_context *ctx, void *p) {
  (void)aux;
  (void)ctx;
  (void)p;
  // Nothing to do.
  return 0;
}

#define DEF_SCALAR_TYPE(T)                                      \
  int restore_##T(const void *aux, FILE *f,                     \
                  struct futhark_context *ctx, void *p) {       \
    (void)aux;                                                  \
    (void)ctx;                                                  \
    return read_scalar(f, &T##_info, p);                        \
  }                                                             \
                                                                \
  void store_##T(const void *aux, FILE *f,                      \
                 struct futhark_context *ctx, void *p) {        \
    (void)aux;                                                  \
    (void)ctx;                                                  \
    write_scalar(f, 1, &T##_info, p);                           \
  }                                                             \
                                                                \
  struct type type_##T =                                        \
    { .name = #T,                                               \
      .restore = restore_##T,                                   \
      .store = store_##T,                                       \
      .free = free_scalar                                       \
    }                                                           \

DEF_SCALAR_TYPE(i8);
DEF_SCALAR_TYPE(i16);
DEF_SCALAR_TYPE(i32);
DEF_SCALAR_TYPE(i64);
DEF_SCALAR_TYPE(u8);
DEF_SCALAR_TYPE(u16);
DEF_SCALAR_TYPE(u32);
DEF_SCALAR_TYPE(u64);
DEF_SCALAR_TYPE(f16);
DEF_SCALAR_TYPE(f32);
DEF_SCALAR_TYPE(f64);
DEF_SCALAR_TYPE(bool);

struct value {
  const struct type *type;
  union {
    void *v_ptr;
    int8_t  v_i8;
    int16_t v_i16;
    int32_t v_i32;
    int64_t v_i64;

    uint8_t  v_u8;
    uint16_t v_u16;
    uint32_t v_u32;
    uint64_t v_u64;

    uint16_t v_f16;
    float v_f32;
    double v_f64;

    bool v_bool;
  } value;
};

void* value_ptr(struct value *v) {
  if (v->type == &type_i8) {
    return &v->value.v_i8;
  }
  if (v->type == &type_i16) {
    return &v->value.v_i16;
  }
  if (v->type == &type_i32) {
    return &v->value.v_i32;
  }
  if (v->type == &type_i64) {
    return &v->value.v_i64;
  }
  if (v->type == &type_u8) {
    return &v->value.v_u8;
  }
  if (v->type == &type_u16) {
    return &v->value.v_u16;
  }
  if (v->type == &type_u32) {
    return &v->value.v_u32;
  }
  if (v->type == &type_u64) {
    return &v->value.v_u64;
  }
  if (v->type == &type_f16) {
    return &v->value.v_f16;
  }
  if (v->type == &type_f32) {
    return &v->value.v_f32;
  }
  if (v->type == &type_f64) {
    return &v->value.v_f64;
  }
  if (v->type == &type_bool) {
    return &v->value.v_bool;
  }
  return &v->value.v_ptr;
}

struct variable {
  // NULL name indicates free slot.  Name is owned by this struct.
  char *name;
  struct value value;
};

typedef int (*entry_point_fn)(struct futhark_context*, void**, void**);

struct entry_point {
  const char *name;
  entry_point_fn f;
  const char** tuning_params;
  const struct type **out_types;
  bool *out_unique;
  const struct type **in_types;
  bool *in_unique;
};

int entry_num_ins(struct entry_point *e) {
  int count = 0;
  while (e->in_types[count]) {
    count++;
  }
  return count;
}

int entry_num_outs(struct entry_point *e) {
  int count = 0;
  while (e->out_types[count]) {
    count++;
  }
  return count;
}

struct futhark_prog {
  // Last entry point identified by NULL name.
  struct entry_point *entry_points;
  // Last type identified by NULL name.
  const struct type **types;
};

struct server_state {
  struct futhark_prog prog;
  struct futhark_context_config *cfg;
  struct futhark_context *ctx;
  int variables_capacity;
  struct variable *variables;
};

struct variable* get_variable(struct server_state *s,
                              const char *name) {
  for (int i = 0; i < s->variables_capacity; i++) {
    if (s->variables[i].name != NULL &&
        strcmp(s->variables[i].name, name) == 0) {
      return &s->variables[i];
    }
  }

  return NULL;
}

struct variable* create_variable(struct server_state *s,
                                 const char *name,
                                 const struct type *type) {
  int found = -1;
  for (int i = 0; i < s->variables_capacity; i++) {
    if (found == -1 && s->variables[i].name == NULL) {
      found = i;
    } else if (s->variables[i].name != NULL &&
               strcmp(s->variables[i].name, name) == 0) {
      return NULL;
    }
  }

  if (found != -1) {
    // Found a free spot.
    s->variables[found].name = strdup(name);
    s->variables[found].value.type = type;
    return &s->variables[found];
  }

  // Need to grow the buffer.
  found = s->variables_capacity;
  s->variables_capacity *= 2;
  s->variables = realloc(s->variables,
                         s->variables_capacity * sizeof(struct variable));

  s->variables[found].name = strdup(name);
  s->variables[found].value.type = type;

  for (int i = found+1; i < s->variables_capacity; i++) {
    s->variables[i].name = NULL;
  }

  return &s->variables[found];
}

void drop_variable(struct variable *v) {
  free(v->name);
  v->name = NULL;
}

int arg_exists(const char *args[], int i) {
  return args[i] != NULL;
}

const char* get_arg(const char *args[], int i) {
  if (!arg_exists(args, i)) {
    futhark_panic(1, "Insufficient command args.\n");
  }
  return args[i];
}

const struct type* get_type(struct server_state *s, const char *name) {
  for (int i = 0; s->prog.types[i]; i++) {
    if (strcmp(s->prog.types[i]->name, name) == 0) {
      return s->prog.types[i];
    }
  }

  futhark_panic(1, "Unknown type %s\n", name);
  return NULL;
}

struct entry_point* get_entry_point(struct server_state *s, const char *name) {
  for (int i = 0; s->prog.entry_points[i].name; i++) {
    if (strcmp(s->prog.entry_points[i].name, name) == 0) {
      return &s->prog.entry_points[i];
    }
  }

  return NULL;
}

// Print the command-done marker, indicating that we are ready for
// more input.
void ok(void) {
  printf("%%%%%% OK\n");
  fflush(stdout);
}

// Print the failure marker.  Output is now an error message until the
// next ok().
void failure(void) {
  printf("%%%%%% FAILURE\n");
}

void error_check(struct server_state *s, int err) {
  if (err != 0) {
    failure();
    char *error = futhark_context_get_error(s->ctx);
    if (error != NULL) {
      puts(error);
    }
    free(error);
  }
}

void cmd_call(struct server_state *s, const char *args[]) {
  const char *name = get_arg(args, 0);

  struct entry_point *e = get_entry_point(s, name);

  if (e == NULL) {
    failure();
    printf("Unknown entry point: %s\n", name);
    return;
  }

  int num_outs = entry_num_outs(e);
  int num_ins = entry_num_ins(e);
  // +1 to avoid zero-size arrays, which is UB.
  void* outs[num_outs+1];
  void* ins[num_ins+1];

  for (int i = 0; i < num_ins; i++) {
    const char *in_name = get_arg(args, 1+num_outs+i);
    struct variable *v = get_variable(s, in_name);
    if (v == NULL) {
      failure();
      printf("Unknown variable: %s\n", in_name);
      return;
    }
    if (v->value.type != e->in_types[i]) {
      failure();
      printf("Wrong input type.  Expected %s, got %s.\n",
             e->in_types[i]->name, v->value.type->name);
      return;
    }
    ins[i] = value_ptr(&v->value);
  }

  for (int i = 0; i < num_outs; i++) {
    const char *out_name = get_arg(args, 1+i);
    struct variable *v = create_variable(s, out_name, e->out_types[i]);
    if (v == NULL) {
      failure();
      printf("Variable already exists: %s\n", out_name);
      return;
    }
    outs[i] = value_ptr(&v->value);
  }

  int64_t t_start = get_wall_time();
  int err = e->f(s->ctx, outs, ins);
  err |= futhark_context_sync(s->ctx);
  int64_t t_end = get_wall_time();
  long long int elapsed_usec = t_end - t_start;
  printf("runtime: %lld\n", elapsed_usec);

  error_check(s, err);
  if (err != 0) {
    // Need to uncreate the output variables, which would otherwise be left
    // in an uninitialised state.
    for (int i = 0; i < num_outs; i++) {
      const char *out_name = get_arg(args, 1+i);
      struct variable *v = get_variable(s, out_name);
      if (v) {
        drop_variable(v);
      }
    }
  }
}

void cmd_restore(struct server_state *s, const char *args[]) {
  const char *fname = get_arg(args, 0);

  FILE *f = fopen(fname, "rb");
  if (f == NULL) {
    failure();
    printf("Failed to open %s: %s\n", fname, strerror(errno));
    return;
  }

  int bad = 0;
  int values = 0;
  for (int i = 1; arg_exists(args, i); i+=2, values++) {
    const char *vname = get_arg(args, i);
    const char *type = get_arg(args, i+1);

    const struct type *t = get_type(s, type);
    struct variable *v = create_variable(s, vname, t);

    if (v == NULL) {
      bad = 1;
      failure();
      printf("Variable already exists: %s\n", vname);
      break;
    }

    errno = 0;
    if (t->restore(t->aux, f, s->ctx, value_ptr(&v->value)) != 0) {
      bad = 1;
      failure();
      printf("Failed to restore variable %s.\n"
             "Possibly malformed data in %s (errno: %s)\n",
             vname, fname, strerror(errno));
      drop_variable(v);
      break;
    }
  }

  if (!bad && end_of_input(f) != 0) {
    failure();
    printf("Expected EOF after reading %d values from %s\n",
           values, fname);
  }

  fclose(f);

  if (!bad) {
    int err = futhark_context_sync(s->ctx);
    error_check(s, err);
  }
}

void cmd_store(struct server_state *s, const char *args[]) {
  const char *fname = get_arg(args, 0);

  FILE *f = fopen(fname, "wb");
  if (f == NULL) {
    failure();
    printf("Failed to open %s: %s\n", fname, strerror(errno));
  } else {
    for (int i = 1; arg_exists(args, i); i++) {
      const char *vname = get_arg(args, i);
      struct variable *v = get_variable(s, vname);

      if (v == NULL) {
        failure();
        printf("Unknown variable: %s\n", vname);
        return;
      }

      const struct type *t = v->value.type;
      t->store(t->aux, f, s->ctx, value_ptr(&v->value));
    }
    fclose(f);
  }
}

void cmd_free(struct server_state *s, const char *args[]) {
  for (int i = 0; arg_exists(args, i); i++) {
    const char *name = get_arg(args, i);
    struct variable *v = get_variable(s, name);

    if (v == NULL) {
      failure();
      printf("Unknown variable: %s\n", name);
      return;
    }

    const struct type *t = v->value.type;

    int err = t->free(t->aux, s->ctx, value_ptr(&v->value));
    error_check(s, err);
    drop_variable(v);
  }
}

void cmd_rename(struct server_state *s, const char *args[]) {
  const char *oldname = get_arg(args, 0);
  const char *newname = get_arg(args, 1);
  struct variable *old = get_variable(s, oldname);
  struct variable *new = get_variable(s, newname);

  if (old == NULL) {
    failure();
    printf("Unknown variable: %s\n", oldname);
    return;
  }

  if (new != NULL) {
    failure();
    printf("Variable already exists: %s\n", newname);
    return;
  }

  free(old->name);
  old->name = strdup(newname);
}

void cmd_inputs(struct server_state *s, const char *args[]) {
  const char *name = get_arg(args, 0);
  struct entry_point *e = get_entry_point(s, name);

  if (e == NULL) {
    failure();
    printf("Unknown entry point: %s\n", name);
    return;
  }

  int num_ins = entry_num_ins(e);
  for (int i = 0; i < num_ins; i++) {
    if (e->in_unique[i]) {
      putchar('*');
    }
    puts(e->in_types[i]->name);
  }
}

void cmd_outputs(struct server_state *s, const char *args[]) {
  const char *name = get_arg(args, 0);
  struct entry_point *e = get_entry_point(s, name);

  if (e == NULL) {
    failure();
    printf("Unknown entry point: %s\n", name);
    return;
  }

  int num_outs = entry_num_outs(e);
  for (int i = 0; i < num_outs; i++) {
    if (e->out_unique[i]) {
      putchar('*');
    }
    puts(e->out_types[i]->name);
  }
}

void cmd_clear(struct server_state *s, const char *args[]) {
  (void)args;
  int err = 0;
  for (int i = 0; i < s->variables_capacity; i++) {
    struct variable *v = &s->variables[i];
    if (v->name != NULL) {
      err |= v->value.type->free(v->value.type->aux, s->ctx, value_ptr(&v->value));
      drop_variable(v);
    }
  }
  err |= futhark_context_clear_caches(s->ctx);
  error_check(s, err);
}

void cmd_pause_profiling(struct server_state *s, const char *args[]) {
  (void)args;
  futhark_context_pause_profiling(s->ctx);
}

void cmd_unpause_profiling(struct server_state *s, const char *args[]) {
  (void)args;
  futhark_context_unpause_profiling(s->ctx);
}

void cmd_report(struct server_state *s, const char *args[]) {
  (void)args;
  char *report = futhark_context_report(s->ctx);
  if (report) {
    puts(report);
  } else {
    failure();
    report = futhark_context_get_error(s->ctx);
    if (report) {
      puts(report);
    } else {
      puts("Failed to produce profiling report.\n");
    }
  }
  free(report);
}

void cmd_set_tuning_param(struct server_state *s, const char *args[]) {
  const char *param = get_arg(args, 0);
  const char *val_s = get_arg(args, 1);
  size_t val = atol(val_s);
  int err = futhark_context_config_set_tuning_param(s->cfg, param, val);

  error_check(s, err);

  if (err != 0) {
    printf("Failed to set tuning parameter %s to %ld\n", param, (long)val);
  }
}

void cmd_tuning_params(struct server_state *s, const char *args[]) {
  const char *name = get_arg(args, 0);
  struct entry_point *e = get_entry_point(s, name);

  if (e == NULL) {
    failure();
    printf("Unknown entry point: %s\n", name);
    return;
  }

  const char **params = e->tuning_params;
  for (int i = 0; params[i] != NULL; i++) {
    printf("%s\n", params[i]);
  }
}

void cmd_tuning_param_class(struct server_state *s, const char *args[]) {
  (void)s;
  const char *param = get_arg(args, 0);

  int n = futhark_get_tuning_param_count();

  for (int i = 0; i < n; i++) {
    if (strcmp(futhark_get_tuning_param_name(i), param) == 0) {
      printf("%s\n", futhark_get_tuning_param_class(i));
      return;
    }
  }

  failure();
  printf("Unknown tuning parameter: %s\n", param);
}

void cmd_fields(struct server_state *s, const char *args[]) {
  const char *type = get_arg(args, 0);
  const struct type *t = get_type(s, type);
  const struct record *r = t->record;

  if (r == NULL) {
    failure();
    printf("Not a record type\n");
    return;
  }

  for (int i = 0; i < r->num_fields; i++) {
    const struct field f = r->fields[i];
    printf("%s %s\n", f.name, f.type->name);
  }
}

void cmd_project(struct server_state *s, const char *args[]) {
  const char *to_name = get_arg(args, 0);
  const char *from_name = get_arg(args, 1);
  const char *field_name = get_arg(args, 2);

  struct variable *from = get_variable(s, from_name);

  if (from == NULL) {
    failure();
    printf("Unknown variable: %s\n", from_name);
    return;
  }

  const struct type *from_type = from->value.type;
  const struct record *r = from_type->record;

  if (r == NULL) {
    failure();
    printf("Not a record type\n");
    return;
  }

  const struct field *field = NULL;
  for (int i = 0; i < r->num_fields; i++) {
    if (strcmp(r->fields[i].name, field_name) == 0) {
      field = &r->fields[i];
      break;
    }
  }

  if (field == NULL) {
    failure();
    printf("No such field\n");
  }

  struct variable *to = create_variable(s, to_name, field->type);

  if (to == NULL) {
    failure();
    printf("Variable already exists: %s\n", to_name);
    return;
  }

  field->project(s->ctx, value_ptr(&to->value), from->value.value.v_ptr);
}

void cmd_new(struct server_state *s, const char *args[]) {
  const char *to_name = get_arg(args, 0);
  const char *type_name = get_arg(args, 1);
  const struct type *type = get_type(s, type_name);
  struct variable *to = create_variable(s, to_name, type);

  if (to == NULL) {
    failure();
    printf("Variable already exists: %s\n", to_name);
    return;
  }

  const struct record* r = type->record;

  if (r == NULL) {
    failure();
    printf("Not a record type\n");
    return;
  }

  int num_args = 0;
  for (int i = 2; arg_exists(args, i); i++) {
    num_args++;
  }

  if (num_args != r->num_fields) {
    failure();
    printf("%d fields expected but %d values provided.\n", num_args, r->num_fields);
    return;
  }

  const void** value_ptrs = alloca(num_args * sizeof(void*));

  for (int i = 0; i < num_args; i++) {
    struct variable* v = get_variable(s, args[2+i]);

    if (v == NULL) {
      failure();
      printf("Unknown variable: %s\n", args[2+i]);
      return;
    }

    if (strcmp(v->value.type->name, r->fields[i].type->name) != 0) {
      failure();
      printf("Field %s mismatch: expected type %s, got %s\n",
             r->fields[i].name, r->fields[i].type->name, v->value.type->name);
      return;
    }

    value_ptrs[i] = value_ptr(&v->value);
  }

  r->new(s->ctx, value_ptr(&to->value), value_ptrs);
}

void cmd_entry_points(struct server_state *s, const char *args[]) {
  (void)args;
  for (int i = 0; s->prog.entry_points[i].name; i++) {
    puts(s->prog.entry_points[i].name);
  }
}

void cmd_types(struct server_state *s, const char *args[]) {
  (void)args;
  for (int i = 0; s->prog.types[i] != NULL; i++) {
    puts(s->prog.types[i]->name);
  }
}

char *next_word(char **line) {
  char *p = *line;

  while (isspace(*p)) {
    p++;
  }

  if (*p == 0) {
    return NULL;
  }

  if (*p == '"') {
    char *save = p+1;
    // Skip ahead till closing quote.
    p++;

    while (*p && *p != '"') {
      p++;
    }

    if (*p == '"') {
      *p = 0;
      *line = p+1;
      return save;
    } else {
      return NULL;
    }
  } else {
    char *save = p;
    // Skip ahead till next whitespace.

    while (*p && !isspace(*p)) {
      p++;
    }

    if (*p) {
      *p = 0;
      *line = p+1;
    } else {
      *line = p;
    }
    return save;
  }
}

void process_line(struct server_state *s, char *line) {
  int max_num_tokens = 1000;
  const char* tokens[max_num_tokens];
  int num_tokens = 0;

  while ((tokens[num_tokens] = next_word(&line)) != NULL) {
    num_tokens++;
    if (num_tokens == max_num_tokens) {
      futhark_panic(1, "Line too long.\n");
    }
  }

  const char *command = tokens[0];

  if (command == NULL) {
    failure();
    printf("Empty line\n");
  } else if (strcmp(command, "call") == 0) {
    cmd_call(s, tokens+1);
  } else if (strcmp(command, "restore") == 0) {
    cmd_restore(s, tokens+1);
  } else if (strcmp(command, "store") == 0) {
    cmd_store(s, tokens+1);
  } else if (strcmp(command, "free") == 0) {
    cmd_free(s, tokens+1);
  } else if (strcmp(command, "rename") == 0) {
    cmd_rename(s, tokens+1);
  } else if (strcmp(command, "inputs") == 0) {
    cmd_inputs(s, tokens+1);
  } else if (strcmp(command, "outputs") == 0) {
    cmd_outputs(s, tokens+1);
  } else if (strcmp(command, "clear") == 0) {
    cmd_clear(s, tokens+1);
  } else if (strcmp(command, "pause_profiling") == 0) {
    cmd_pause_profiling(s, tokens+1);
  } else if (strcmp(command, "unpause_profiling") == 0) {
    cmd_unpause_profiling(s, tokens+1);
  } else if (strcmp(command, "report") == 0) {
    cmd_report(s, tokens+1);
  } else if (strcmp(command, "set_tuning_param") == 0) {
    cmd_set_tuning_param(s, tokens+1);
  } else if (strcmp(command, "tuning_params") == 0) {
    cmd_tuning_params(s, tokens+1);
  } else if (strcmp(command, "tuning_param_class") == 0) {
    cmd_tuning_param_class(s, tokens+1);
  } else if (strcmp(command, "fields") == 0) {
    cmd_fields(s, tokens+1);
  } else if (strcmp(command, "new") == 0) {
    cmd_new(s, tokens+1);
  } else if (strcmp(command, "project") == 0) {
    cmd_project(s, tokens+1);
  } else if (strcmp(command, "entry_points") == 0) {
    cmd_entry_points(s, tokens+1);
  } else if (strcmp(command, "types") == 0) {
    cmd_types(s, tokens+1);
  } else {
    futhark_panic(1, "Unknown command: %s\n", command);
  }
}

void run_server(struct futhark_prog *prog,
                struct futhark_context_config *cfg,
                struct futhark_context *ctx) {
  char *line = NULL;
  size_t buflen = 0;
  ssize_t linelen;

  struct server_state s = {
    .cfg = cfg,
    .ctx = ctx,
    .variables_capacity = 100,
    .prog = *prog
  };

  s.variables = malloc(s.variables_capacity * sizeof(struct variable));

  for (int i = 0; i < s.variables_capacity; i++) {
    s.variables[i].name = NULL;
  }

  ok();
  while ((linelen = getline(&line, &buflen, stdin)) > 0) {
    process_line(&s, line);
    ok();
  }

  free(s.variables);
  free(line);
}

// The aux struct lets us write generic method implementations without
// code duplication.

typedef void* (*array_new_fn)(struct futhark_context *, const void*, const int64_t*);
typedef const int64_t* (*array_shape_fn)(struct futhark_context*, void*);
typedef int (*array_values_fn)(struct futhark_context*, void*, void*);
typedef int (*array_free_fn)(struct futhark_context*, void*);

struct array_aux {
  int rank;
  const struct primtype_info_t* info;
  const char *name;
  array_new_fn new;
  array_shape_fn shape;
  array_values_fn values;
  array_free_fn free;
};

int restore_array(const struct array_aux *aux, FILE *f,
                  struct futhark_context *ctx, void *p) {
  void *data = NULL;
  int64_t shape[aux->rank];
  if (read_array(f, aux->info, &data, shape, aux->rank) != 0) {
    return 1;
  }

  void *arr = aux->new(ctx, data, shape);
  if (arr == NULL) {
    return 1;
  }
  int err = futhark_context_sync(ctx);
  *(void**)p = arr;
  free(data);
  return err;
}

void store_array(const struct array_aux *aux, FILE *f,
                 struct futhark_context *ctx, void *p) {
  void *arr = *(void**)p;
  const int64_t *shape = aux->shape(ctx, arr);
  int64_t size = sizeof(aux->info->size);
  for (int i = 0; i < aux->rank; i++) {
    size *= shape[i];
  }
  int32_t *data = malloc(size);
  assert(aux->values(ctx, arr, data) == 0);
  assert(futhark_context_sync(ctx) == 0);
  assert(write_array(f, 1, aux->info, data, shape, aux->rank) == 0);
  free(data);
}

int free_array(const struct array_aux *aux,
               struct futhark_context *ctx, void *p) {
  void *arr = *(void**)p;
  return aux->free(ctx, arr);
}

typedef void* (*opaque_restore_fn)(struct futhark_context*, void*);
typedef int (*opaque_store_fn)(struct futhark_context*, const void*, void **, size_t *);
typedef int (*opaque_free_fn)(struct futhark_context*, void*);

struct opaque_aux {
  opaque_restore_fn restore;
  opaque_store_fn store;
  opaque_free_fn free;
};

int restore_opaque(const struct opaque_aux *aux, FILE *f,
                   struct futhark_context *ctx, void *p) {
  // We have a problem: we need to load data from 'f', since the
  // restore function takes a pointer, but we don't know how much we
  // need (and cannot possibly).  So we do something hacky: we read
  // *all* of the file, pass all of the data to the restore function
  // (which doesn't care if there's extra at the end), then we compute
  // how much space the the object actually takes in serialised form
  // and rewind the file to that position.  The only downside is more IO.
  size_t start = ftell(f);
  size_t size;
  char *bytes = fslurp_file(f, &size);
  void *obj = aux->restore(ctx, bytes);
  free(bytes);
  if (obj != NULL) {
    *(void**)p = obj;
    size_t obj_size;
    (void)aux->store(ctx, obj, NULL, &obj_size);
    fseek(f, start+obj_size, SEEK_SET);
    return 0;
  } else {
    fseek(f, start, SEEK_SET);
    return 1;
  }
}

void store_opaque(const struct opaque_aux *aux, FILE *f,
                  struct futhark_context *ctx, void *p) {
  void *obj = *(void**)p;
  size_t obj_size;
  void *data = NULL;
  (void)aux->store(ctx, obj, &data, &obj_size);
  assert(futhark_context_sync(ctx) == 0);
  fwrite(data, sizeof(char), obj_size, f);
  free(data);
}

int free_opaque(const struct opaque_aux *aux,
                struct futhark_context *ctx, void *p) {
  void *obj = *(void**)p;
  return aux->free(ctx, obj);
}

// End of server.h.

// Start of tuning.h.


int is_blank_line_or_comment(const char *s) {
  size_t i = strspn(s, " \t\n");
  return s[i] == '\0' || // Line is blank.
         strncmp(s + i, "--", 2) == 0; // Line is comment.
}

static char* load_tuning_file(const char *fname,
                              void *cfg,
                              int (*set_tuning_param)(void*, const char*, size_t)) {
  const int max_line_len = 1024;
  char* line = (char*) malloc(max_line_len);

  FILE *f = fopen(fname, "r");

  if (f == NULL) {
    snprintf(line, max_line_len, "Cannot open file: %s", strerror(errno));
    return line;
  }

  int lineno = 0;
  while (fgets(line, max_line_len, f) != NULL) {
    lineno++;
    if (is_blank_line_or_comment(line)) {
      continue;
    }
    char *eql = strstr(line, "=");
    if (eql) {
      *eql = 0;
      char *endptr;
      int value = strtol(eql+1, &endptr, 10);
      if (*endptr && *endptr != '\n') {
        snprintf(line, max_line_len, "Invalid line %d (must be of form 'name=int').",
                 lineno);
        return line;
      }
      if (set_tuning_param(cfg, line, (size_t)value) != 0) {
        char* err = (char*) malloc(max_line_len + 50);
        snprintf(err, max_line_len + 50, "Unknown name '%s' on line %d.", line, lineno);
        free(line);
        return err;
      }
    } else {
      snprintf(line, max_line_len, "Invalid line %d (must be of form 'name=int').",
               lineno);
      return line;
    }
  }

  free(line);

  return NULL;
}

// End of tuning.h.

const struct type *test_delete_vertices_out_types[] = {&type_bool, NULL};
bool test_delete_vertices_out_unique[] = {false};
const struct type *test_delete_vertices_in_types[] = {NULL};
bool test_delete_vertices_in_unique[] = {};
const char *test_delete_vertices_tuning_params[] = {NULL};
int call_test_delete_vertices(struct futhark_context *ctx, void **outs, void **ins)
{
    bool *out0 = outs[0];
    
    (void) ins;
    return futhark_entry_test_delete_vertices(ctx, out0);
}
const struct type *test_merge_tree_out_types[] = {&type_bool, NULL};
bool test_merge_tree_out_unique[] = {false};
const struct type *test_merge_tree_in_types[] = {NULL};
bool test_merge_tree_in_unique[] = {};
const char *test_merge_tree_tuning_params[] = {NULL};
int call_test_merge_tree(struct futhark_context *ctx, void **outs, void **ins)
{
    bool *out0 = outs[0];
    
    (void) ins;
    return futhark_entry_test_merge_tree(ctx, out0);
}
const struct type *test_split_out_types[] = {&type_bool, NULL};
bool test_split_out_unique[] = {false};
const struct type *test_split_in_types[] = {NULL};
bool test_split_in_unique[] = {};
const char *test_split_tuning_params[] = {NULL};
int call_test_split(struct futhark_context *ctx, void **outs, void **ins)
{
    bool *out0 = outs[0];
    
    (void) ins;
    return futhark_entry_test_split(ctx, out0);
}
const struct type *test_split_at_leaf_out_types[] = {&type_bool, NULL};
bool test_split_at_leaf_out_unique[] = {false};
const struct type *test_split_at_leaf_in_types[] = {NULL};
bool test_split_at_leaf_in_unique[] = {};
const char *test_split_at_leaf_tuning_params[] = {NULL};
int call_test_split_at_leaf(struct futhark_context *ctx, void **outs, void **ins)
{
    bool *out0 = outs[0];
    
    (void) ins;
    return futhark_entry_test_split_at_leaf(ctx, out0);
}
const struct type *test_split_multiple_out_types[] = {&type_bool, NULL};
bool test_split_multiple_out_unique[] = {false};
const struct type *test_split_multiple_in_types[] = {NULL};
bool test_split_multiple_in_unique[] = {};
const char *test_split_multiple_tuning_params[] = {NULL};
int call_test_split_multiple(struct futhark_context *ctx, void **outs, void **ins)
{
    bool *out0 = outs[0];
    
    (void) ins;
    return futhark_entry_test_split_multiple(ctx, out0);
}
const struct type *test_split_none_out_types[] = {&type_bool, NULL};
bool test_split_none_out_unique[] = {false};
const struct type *test_split_none_in_types[] = {NULL};
bool test_split_none_in_unique[] = {};
const char *test_split_none_tuning_params[] = {NULL};
int call_test_split_none(struct futhark_context *ctx, void **outs, void **ins)
{
    bool *out0 = outs[0];
    
    (void) ins;
    return futhark_entry_test_split_none(ctx, out0);
}
const struct type *types[] = {&type_i8, &type_i16, &type_i32, &type_i64, &type_u8, &type_u16, &type_u32, &type_u64, &type_f16, &type_f32, &type_f64, &type_bool, NULL};
struct entry_point entry_points[] = {{.name ="test_delete_vertices", .f =call_test_delete_vertices, .tuning_params =test_delete_vertices_tuning_params, .in_types =test_delete_vertices_in_types, .out_types =test_delete_vertices_out_types, .in_unique =test_delete_vertices_in_unique, .out_unique =test_delete_vertices_out_unique}, {.name ="test_merge_tree", .f =call_test_merge_tree, .tuning_params =test_merge_tree_tuning_params, .in_types =test_merge_tree_in_types, .out_types =test_merge_tree_out_types, .in_unique =test_merge_tree_in_unique, .out_unique =test_merge_tree_out_unique}, {.name ="test_split", .f =call_test_split, .tuning_params =test_split_tuning_params, .in_types =test_split_in_types, .out_types =test_split_out_types, .in_unique =test_split_in_unique, .out_unique =test_split_out_unique}, {.name ="test_split_at_leaf", .f =call_test_split_at_leaf, .tuning_params =test_split_at_leaf_tuning_params, .in_types =test_split_at_leaf_in_types, .out_types =test_split_at_leaf_out_types, .in_unique =test_split_at_leaf_in_unique, .out_unique =test_split_at_leaf_out_unique}, {.name ="test_split_multiple", .f =call_test_split_multiple, .tuning_params =test_split_multiple_tuning_params, .in_types =test_split_multiple_in_types, .out_types =test_split_multiple_out_types, .in_unique =test_split_multiple_in_unique, .out_unique =test_split_multiple_out_unique}, {.name ="test_split_none", .f =call_test_split_none, .tuning_params =test_split_none_tuning_params, .in_types =test_split_none_in_types, .out_types =test_split_none_out_types, .in_unique =test_split_none_in_unique, .out_unique =test_split_none_out_unique}, {.name =NULL}};
struct futhark_prog prog = {.types =types, .entry_points =entry_points};
int parse_options(struct futhark_context_config *cfg, int argc, char *const argv[])
{
    int ch;
    static struct option long_options[] = {{"debugging", no_argument, NULL, 1}, {"log", no_argument, NULL, 2}, {"profile", no_argument, NULL, 3}, {"help", no_argument, NULL, 4}, {"print-params", no_argument, NULL, 5}, {"param", required_argument, NULL, 6}, {"tuning", required_argument, NULL, 7}, {"cache-file", required_argument, NULL, 8}, {0, 0, 0, 0}};
    static char *option_descriptions = "  -D/--debugging     Perform possibly expensive internal correctness checks and verbose logging.\n  -L/--log           Print various low-overhead logging information while running.\n  -P/--profile       Enable the collection of profiling information.\n  -h/--help          Print help information and exit.\n  --print-params     Print all tuning parameters that can be set with --param or --tuning.\n  --param ASSIGNMENT Set a tuning parameter to the given value.\n  --tuning FILE      Read size=value assignments from the given file.\n  --cache-file FILE  Store program cache here.\n";
    
    while ((ch = getopt_long(argc, argv, ":DLPh", long_options, NULL)) != -1) {
        if (ch == 1 || ch == 'D')
            futhark_context_config_set_debugging(cfg, 1);
        if (ch == 2 || ch == 'L')
            futhark_context_config_set_logging(cfg, 1);
        if (ch == 3 || ch == 'P')
            futhark_context_config_set_profiling(cfg, 1);
        if (ch == 4 || ch == 'h') {
            printf("Usage: %s [OPTIONS]...\nOptions:\n\n%s\nFor more information, consult the Futhark User's Guide or the man pages.\n", fut_progname, option_descriptions);
            exit(0);
        }
        if (ch == 5) {
            int n = futhark_get_tuning_param_count();
            
            for (int i = 0; i < n; i++)
                printf("%s (%s)\n", futhark_get_tuning_param_name(i), futhark_get_tuning_param_class(i));
            exit(0);
        }
        if (ch == 6) {
            char *name = optarg;
            char *equals = strstr(optarg, "=");
            char *value_str = equals != NULL ? equals + 1 : optarg;
            int value = atoi(value_str);
            
            if (equals != NULL) {
                *equals = 0;
                if (futhark_context_config_set_tuning_param(cfg, name, value) != 0)
                    futhark_panic(1, "Unknown size: %s\n", name);
            } else
                futhark_panic(1, "Invalid argument for size option: %s\n", optarg);
        }
        if (ch == 7) {
            char *ret = load_tuning_file(optarg, cfg, (int (*)(void *, const char *, size_t)) futhark_context_config_set_tuning_param);
            
            if (ret != NULL)
                futhark_panic(1, "When loading tuning file '%s': %s\n", optarg, ret);
        }
        if (ch == 8)
            futhark_context_config_set_cache_file(cfg, optarg);
        if (ch == ':')
            futhark_panic(-1, "Missing argument for option %s\n", argv[optind - 1]);
        if (ch == '?') {
            fprintf(stderr, "Usage: %s [OPTIONS]...\nOptions:\n\n%s\n", fut_progname, "  -D/--debugging     Perform possibly expensive internal correctness checks and verbose logging.\n  -L/--log           Print various low-overhead logging information while running.\n  -P/--profile       Enable the collection of profiling information.\n  -h/--help          Print help information and exit.\n  --print-params     Print all tuning parameters that can be set with --param or --tuning.\n  --param ASSIGNMENT Set a tuning parameter to the given value.\n  --tuning FILE      Read size=value assignments from the given file.\n  --cache-file FILE  Store program cache here.\n");
            futhark_panic(1, "Unknown option: %s\n", argv[optind - 1]);
        }
    }
    return optind;
}
int main(int argc, char **argv)
{
    fut_progname = argv[0];
    
    struct futhark_context_config *cfg = futhark_context_config_new();
    
    assert(cfg != NULL);
    
    int parsed_options = parse_options(cfg, argc, argv);
    
    argc -= parsed_options;
    argv += parsed_options;
    if (argc != 0)
        futhark_panic(1, "Excess non-option: %s\n", argv[0]);
    
    struct futhark_context *ctx = futhark_context_new(cfg);
    
    assert(ctx != NULL);
    futhark_context_set_logging_file(ctx, stdout);
    
    char *error = futhark_context_get_error(ctx);
    
    if (error != NULL)
        futhark_panic(1, "Error during context initialisation:\n%s", error);
    if (entry_point != NULL)
        run_server(&prog, cfg, ctx);
    futhark_context_free(ctx);
    futhark_context_config_free(cfg);
}

#ifdef _MSC_VER
#define inline __inline
#endif
#include <string.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <ctype.h>



#define FUTHARK_F64_ENABLED

// Start of scalar.h.

// Implementation of the primitive scalar operations.  Very
// repetitive.  This code is inserted directly into both CUDA and
// OpenCL programs, as well as the CPU code, so it has some #ifdefs to
// work everywhere.  Some operations are defined as macros because
// this allows us to use them as constant expressions in things like
// array sizes and static initialisers.

// Some of the #ifdefs are because OpenCL uses type-generic functions
// for some operations (e.g. sqrt), while C and CUDA sensibly use
// distinct functions for different precisions (e.g. sqrtf() and
// sqrt()).  This is quite annoying.  Due to C's unfortunate casting
// rules, it is also really easy to accidentally implement
// floating-point functions in the wrong precision, so be careful.

// Double-precision definitions are only included if the preprocessor
// macro FUTHARK_F64_ENABLED is set.

#ifndef M_PI
#define M_PI 3.141592653589793
#endif

SCALAR_FUN_ATTR int32_t fptobits_f32_i32(float x);
SCALAR_FUN_ATTR float bitstofp_i32_f32(int32_t x);

SCALAR_FUN_ATTR uint8_t   add8(uint8_t x, uint8_t y)   { return x + y; }
SCALAR_FUN_ATTR uint16_t add16(uint16_t x, uint16_t y) { return x + y; }
SCALAR_FUN_ATTR uint32_t add32(uint32_t x, uint32_t y) { return x + y; }
SCALAR_FUN_ATTR uint64_t add64(uint64_t x, uint64_t y) { return x + y; }

SCALAR_FUN_ATTR uint8_t   sub8(uint8_t x, uint8_t y)   { return x - y; }
SCALAR_FUN_ATTR uint16_t sub16(uint16_t x, uint16_t y) { return x - y; }
SCALAR_FUN_ATTR uint32_t sub32(uint32_t x, uint32_t y) { return x - y; }
SCALAR_FUN_ATTR uint64_t sub64(uint64_t x, uint64_t y) { return x - y; }

SCALAR_FUN_ATTR uint8_t   mul8(uint8_t x, uint8_t y)   { return x * y; }
SCALAR_FUN_ATTR uint16_t mul16(uint16_t x, uint16_t y) { return x * y; }
SCALAR_FUN_ATTR uint32_t mul32(uint32_t x, uint32_t y) { return x * y; }
SCALAR_FUN_ATTR uint64_t mul64(uint64_t x, uint64_t y) { return x * y; }

#if defined(ISPC)

SCALAR_FUN_ATTR uint8_t udiv8(uint8_t x, uint8_t y) {
  // This strange pattern is used to prevent the ISPC compiler from
  // causing SIGFPEs and bogus results on divisions where inactive lanes
  // have 0-valued divisors. It ensures that any inactive lane instead
  // has a divisor of 1. https://github.com/ispc/ispc/issues/2292
  uint8_t ys = 1;
  foreach_active(i) { ys = y; }
  return x / ys;
}

SCALAR_FUN_ATTR uint16_t udiv16(uint16_t x, uint16_t y) {
  uint16_t ys = 1;
  foreach_active(i) { ys = y; }
  return x / ys;
}

SCALAR_FUN_ATTR uint32_t udiv32(uint32_t x, uint32_t y) {
  uint32_t ys = 1;
  foreach_active(i) { ys = y; }
  return x / ys;
}

SCALAR_FUN_ATTR uint64_t udiv64(uint64_t x, uint64_t y) {
  uint64_t ys = 1;
  foreach_active(i) { ys = y; }
  return x / ys;
}

SCALAR_FUN_ATTR uint8_t udiv_up8(uint8_t x, uint8_t y) {
  uint8_t ys = 1;
  foreach_active(i) { ys = y; }
  return (x + y - 1) / ys;
}

SCALAR_FUN_ATTR uint16_t udiv_up16(uint16_t x, uint16_t y) {
  uint16_t ys = 1;
  foreach_active(i) { ys = y; }
  return (x + y - 1) / ys;
}

SCALAR_FUN_ATTR uint32_t udiv_up32(uint32_t x, uint32_t y) {
  uint32_t ys = 1;
  foreach_active(i) { ys = y; }
  return (x + y - 1) / ys;
}

SCALAR_FUN_ATTR uint64_t udiv_up64(uint64_t x, uint64_t y) {
  uint64_t ys = 1;
  foreach_active(i) { ys = y; }
  return (x + y - 1) / ys;
}

SCALAR_FUN_ATTR uint8_t umod8(uint8_t x, uint8_t y) {
  uint8_t ys = 1;
  foreach_active(i) { ys = y; }
  return x % ys;
}

SCALAR_FUN_ATTR uint16_t umod16(uint16_t x, uint16_t y) {
  uint16_t ys = 1;
  foreach_active(i) { ys = y; }
  return x % ys;
}

SCALAR_FUN_ATTR uint32_t umod32(uint32_t x, uint32_t y) {
  uint32_t ys = 1;
  foreach_active(i) { ys = y; }
  return x % ys;
}

SCALAR_FUN_ATTR uint64_t umod64(uint64_t x, uint64_t y) {
  uint64_t ys = 1;
  foreach_active(i) { ys = y; }
  return x % ys;
}

SCALAR_FUN_ATTR uint8_t udiv_safe8(uint8_t x, uint8_t y) {
  uint8_t ys = 1;
  foreach_active(i) { ys = y; }
  return y == 0 ? 0 : x / ys;
}

SCALAR_FUN_ATTR uint16_t udiv_safe16(uint16_t x, uint16_t y) {
  uint16_t ys = 1;
  foreach_active(i) { ys = y; }
  return y == 0 ? 0 : x / ys;
}

SCALAR_FUN_ATTR uint32_t udiv_safe32(uint32_t x, uint32_t y) {
  uint32_t ys = 1;
  foreach_active(i) { ys = y; }
  return y == 0 ? 0 : x / ys;
}

SCALAR_FUN_ATTR uint64_t udiv_safe64(uint64_t x, uint64_t y) {
  uint64_t ys = 1;
  foreach_active(i) { ys = y; }
  return y == 0 ? 0 : x / ys;
}

SCALAR_FUN_ATTR uint8_t udiv_up_safe8(uint8_t x, uint8_t y) {
  uint8_t ys = 1;
  foreach_active(i) { ys = y; }
  return y == 0 ? 0 : (x + y - 1) / ys;
}

SCALAR_FUN_ATTR uint16_t udiv_up_safe16(uint16_t x, uint16_t y) {
  uint16_t ys = 1;
  foreach_active(i) { ys = y; }
  return y == 0 ? 0 : (x + y - 1) / ys;
}

SCALAR_FUN_ATTR uint32_t udiv_up_safe32(uint32_t x, uint32_t y) {
  uint32_t ys = 1;
  foreach_active(i) { ys = y; }
  return y == 0 ? 0 : (x + y - 1) / ys;
}

SCALAR_FUN_ATTR uint64_t udiv_up_safe64(uint64_t x, uint64_t y) {
  uint64_t ys = 1;
  foreach_active(i) { ys = y; }
  return y == 0 ? 0 : (x + y - 1) / ys;
}

SCALAR_FUN_ATTR uint8_t umod_safe8(uint8_t x, uint8_t y) {
  uint8_t ys = 1;
  foreach_active(i) { ys = y; }
  return y == 0 ? 0 : x % ys;
}

SCALAR_FUN_ATTR uint16_t umod_safe16(uint16_t x, uint16_t y) {
  uint16_t ys = 1;
  foreach_active(i) { ys = y; }
  return y == 0 ? 0 : x % ys;
}

SCALAR_FUN_ATTR uint32_t umod_safe32(uint32_t x, uint32_t y) {
  uint32_t ys = 1;
  foreach_active(i) { ys = y; }
  return y == 0 ? 0 : x % ys;
}

SCALAR_FUN_ATTR uint64_t umod_safe64(uint64_t x, uint64_t y) {
  uint64_t ys = 1;
  foreach_active(i) { ys = y; }
  return y == 0 ? 0 : x % ys;
}

SCALAR_FUN_ATTR int8_t sdiv8(int8_t x, int8_t y) {
  int8_t ys = 1;
  foreach_active(i) { ys = y; }
  int8_t q = x / ys;
  int8_t r = x % ys;
  return q - ((r != 0 && r < 0 != y < 0) ? 1 : 0);
}

SCALAR_FUN_ATTR int16_t sdiv16(int16_t x, int16_t y) {
  int16_t ys = 1;
  foreach_active(i) { ys = y; }
  int16_t q = x / ys;
  int16_t r = x % ys;
  return q - ((r != 0 && r < 0 != y < 0) ? 1 : 0);
}

SCALAR_FUN_ATTR int32_t sdiv32(int32_t x, int32_t y) {
  int32_t ys = 1;
  foreach_active(i) { ys = y; }
  int32_t q = x / ys;
  int32_t r = x % ys;
  return q - ((r != 0 && r < 0 != y < 0) ? 1 : 0);
}

SCALAR_FUN_ATTR int64_t sdiv64(int64_t x, int64_t y) {
  int64_t ys = 1;
  foreach_active(i) { ys = y; }
  int64_t q = x / ys;
  int64_t r = x % ys;
  return q - ((r != 0 && r < 0 != y < 0) ? 1 : 0);
}

SCALAR_FUN_ATTR int8_t sdiv_up8(int8_t x, int8_t y) { return sdiv8(x + y - 1, y); }
SCALAR_FUN_ATTR int16_t sdiv_up16(int16_t x, int16_t y) { return sdiv16(x + y - 1, y); }
SCALAR_FUN_ATTR int32_t sdiv_up32(int32_t x, int32_t y) { return sdiv32(x + y - 1, y); }
SCALAR_FUN_ATTR int64_t sdiv_up64(int64_t x, int64_t y) { return sdiv64(x + y - 1, y); }

SCALAR_FUN_ATTR int8_t smod8(int8_t x, int8_t y) {
  int8_t ys = 1;
  foreach_active(i) { ys = y; }
  int8_t r = x % ys;
  return r + (r == 0 || (x > 0 && y > 0) || (x < 0 && y < 0) ? 0 : y);
}

SCALAR_FUN_ATTR int16_t smod16(int16_t x, int16_t y) {
  int16_t ys = 1;
  foreach_active(i) { ys = y; }
  int16_t r = x % ys;
  return r + (r == 0 || (x > 0 && y > 0) || (x < 0 && y < 0) ? 0 : y);
}

SCALAR_FUN_ATTR int32_t smod32(int32_t x, int32_t y) {
  int32_t ys = 1;
  foreach_active(i) { ys = y; }
  int32_t r = x % ys;
  return r + (r == 0 || (x > 0 && y > 0) || (x < 0 && y < 0) ? 0 : y);
}

SCALAR_FUN_ATTR int64_t smod64(int64_t x, int64_t y) {
  int64_t ys = 1;
  foreach_active(i) { ys = y; }
  int64_t r = x % ys;
  return r + (r == 0 || (x > 0 && y > 0) || (x < 0 && y < 0) ? 0 : y);
}

SCALAR_FUN_ATTR int8_t   sdiv_safe8(int8_t x, int8_t y)   { return y == 0 ? 0 : sdiv8(x, y); }
SCALAR_FUN_ATTR int16_t sdiv_safe16(int16_t x, int16_t y) { return y == 0 ? 0 : sdiv16(x, y); }
SCALAR_FUN_ATTR int32_t sdiv_safe32(int32_t x, int32_t y) { return y == 0 ? 0 : sdiv32(x, y); }
SCALAR_FUN_ATTR int64_t sdiv_safe64(int64_t x, int64_t y) { return y == 0 ? 0 : sdiv64(x, y); }

SCALAR_FUN_ATTR int8_t sdiv_up_safe8(int8_t x, int8_t y)     { return sdiv_safe8(x + y - 1, y); }
SCALAR_FUN_ATTR int16_t sdiv_up_safe16(int16_t x, int16_t y) { return sdiv_safe16(x + y - 1, y); }
SCALAR_FUN_ATTR int32_t sdiv_up_safe32(int32_t x, int32_t y) { return sdiv_safe32(x + y - 1, y); }
SCALAR_FUN_ATTR int64_t sdiv_up_safe64(int64_t x, int64_t y) { return sdiv_safe64(x + y - 1, y); }

SCALAR_FUN_ATTR int8_t   smod_safe8(int8_t x, int8_t y)   { return y == 0 ? 0 : smod8(x, y); }
SCALAR_FUN_ATTR int16_t smod_safe16(int16_t x, int16_t y) { return y == 0 ? 0 : smod16(x, y); }
SCALAR_FUN_ATTR int32_t smod_safe32(int32_t x, int32_t y) { return y == 0 ? 0 : smod32(x, y); }
SCALAR_FUN_ATTR int64_t smod_safe64(int64_t x, int64_t y) { return y == 0 ? 0 : smod64(x, y); }

SCALAR_FUN_ATTR int8_t squot8(int8_t x, int8_t y) {
  int8_t ys = 1;
  foreach_active(i) { ys = y; }
  return x / ys;
}

SCALAR_FUN_ATTR int16_t squot16(int16_t x, int16_t y) {
  int16_t ys = 1;
  foreach_active(i) { ys = y; }
  return x / ys;
}

SCALAR_FUN_ATTR int32_t squot32(int32_t x, int32_t y) {
  int32_t ys = 1;
  foreach_active(i) { ys = y; }
  return x / ys;
}

SCALAR_FUN_ATTR int64_t squot64(int64_t x, int64_t y) {
  int64_t ys = 1;
  foreach_active(i) { ys = y; }
  return x / ys;
}

SCALAR_FUN_ATTR int8_t srem8(int8_t x, int8_t y) {
  int8_t ys = 1;
  foreach_active(i) { ys = y; }
  return x % ys;
}

SCALAR_FUN_ATTR int16_t srem16(int16_t x, int16_t y) {
  int16_t ys = 1;
  foreach_active(i) { ys = y; }
  return x % ys;
}

SCALAR_FUN_ATTR int32_t srem32(int32_t x, int32_t y) {
  int32_t ys = 1;
  foreach_active(i) { ys = y; }
  return x % ys;
}

SCALAR_FUN_ATTR int64_t srem64(int64_t x, int64_t y) {
  int8_t ys = 1;
  foreach_active(i) { ys = y; }
  return x % ys;
}

SCALAR_FUN_ATTR int8_t squot_safe8(int8_t x, int8_t y) {
  int8_t ys = 1;
  foreach_active(i) { ys = y; }
  return y == 0 ? 0 : x / ys;
}

SCALAR_FUN_ATTR int16_t squot_safe16(int16_t x, int16_t y) {
  int16_t ys = 1;
  foreach_active(i) { ys = y; }
  return y == 0 ? 0 : x / ys;
}

SCALAR_FUN_ATTR int32_t squot_safe32(int32_t x, int32_t y) {
  int32_t ys = 1;
  foreach_active(i) { ys = y; }
  return y == 0 ? 0 : x / ys;
}

SCALAR_FUN_ATTR int64_t squot_safe64(int64_t x, int64_t y) {
  int64_t ys = 1;
  foreach_active(i) { ys = y; }
  return y == 0 ? 0 : x / ys;
}

SCALAR_FUN_ATTR int8_t srem_safe8(int8_t x, int8_t y) {
  int8_t ys = 1;
  foreach_active(i) { ys = y; }
  return y == 0 ? 0 : x % ys;
}

SCALAR_FUN_ATTR int16_t srem_safe16(int16_t x, int16_t y) {
  int16_t ys = 1;
  foreach_active(i) { ys = y; }
  return y == 0 ? 0 : x % ys;
}

SCALAR_FUN_ATTR int32_t srem_safe32(int32_t x, int32_t y) {
  int32_t ys = 1;
  foreach_active(i) { ys = y; }
  return y == 0 ? 0 : x % ys;
}

SCALAR_FUN_ATTR int64_t srem_safe64(int64_t x, int64_t y) {
  int64_t ys = 1;
  foreach_active(i) { ys = y; }
  return y == 0 ? 0 : x % ys;
}

#else

SCALAR_FUN_ATTR uint8_t   udiv8(uint8_t x, uint8_t y)   { return x / y; }
SCALAR_FUN_ATTR uint16_t udiv16(uint16_t x, uint16_t y) { return x / y; }
SCALAR_FUN_ATTR uint32_t udiv32(uint32_t x, uint32_t y) { return x / y; }
SCALAR_FUN_ATTR uint64_t udiv64(uint64_t x, uint64_t y) { return x / y; }

SCALAR_FUN_ATTR uint8_t   udiv_up8(uint8_t x, uint8_t y)   { return (x + y - 1) / y; }
SCALAR_FUN_ATTR uint16_t udiv_up16(uint16_t x, uint16_t y) { return (x + y - 1) / y; }
SCALAR_FUN_ATTR uint32_t udiv_up32(uint32_t x, uint32_t y) { return (x + y - 1) / y; }
SCALAR_FUN_ATTR uint64_t udiv_up64(uint64_t x, uint64_t y) { return (x + y - 1) / y; }

SCALAR_FUN_ATTR uint8_t   umod8(uint8_t x, uint8_t y)   { return x % y; }
SCALAR_FUN_ATTR uint16_t umod16(uint16_t x, uint16_t y) { return x % y; }
SCALAR_FUN_ATTR uint32_t umod32(uint32_t x, uint32_t y) { return x % y; }
SCALAR_FUN_ATTR uint64_t umod64(uint64_t x, uint64_t y) { return x % y; }

SCALAR_FUN_ATTR uint8_t   udiv_safe8(uint8_t x, uint8_t y)   { return y == 0 ? 0 : x / y; }
SCALAR_FUN_ATTR uint16_t udiv_safe16(uint16_t x, uint16_t y) { return y == 0 ? 0 : x / y; }
SCALAR_FUN_ATTR uint32_t udiv_safe32(uint32_t x, uint32_t y) { return y == 0 ? 0 : x / y; }
SCALAR_FUN_ATTR uint64_t udiv_safe64(uint64_t x, uint64_t y) { return y == 0 ? 0 : x / y; }

SCALAR_FUN_ATTR uint8_t   udiv_up_safe8(uint8_t x, uint8_t y)   { return y == 0 ? 0 : (x + y - 1) / y; }
SCALAR_FUN_ATTR uint16_t udiv_up_safe16(uint16_t x, uint16_t y) { return y == 0 ? 0 : (x + y - 1) / y; }
SCALAR_FUN_ATTR uint32_t udiv_up_safe32(uint32_t x, uint32_t y) { return y == 0 ? 0 : (x + y - 1) / y; }
SCALAR_FUN_ATTR uint64_t udiv_up_safe64(uint64_t x, uint64_t y) { return y == 0 ? 0 : (x + y - 1) / y; }

SCALAR_FUN_ATTR uint8_t   umod_safe8(uint8_t x, uint8_t y)   { return y == 0 ? 0 : x % y; }
SCALAR_FUN_ATTR uint16_t umod_safe16(uint16_t x, uint16_t y) { return y == 0 ? 0 : x % y; }
SCALAR_FUN_ATTR uint32_t umod_safe32(uint32_t x, uint32_t y) { return y == 0 ? 0 : x % y; }
SCALAR_FUN_ATTR uint64_t umod_safe64(uint64_t x, uint64_t y) { return y == 0 ? 0 : x % y; }

SCALAR_FUN_ATTR int8_t sdiv8(int8_t x, int8_t y) {
  int8_t q = x / y;
  int8_t r = x % y;
  return q - ((r != 0 && r < 0 != y < 0) ? 1 : 0);
}

SCALAR_FUN_ATTR int16_t sdiv16(int16_t x, int16_t y) {
  int16_t q = x / y;
  int16_t r = x % y;
  return q - ((r != 0 && r < 0 != y < 0) ? 1 : 0);
}

SCALAR_FUN_ATTR int32_t sdiv32(int32_t x, int32_t y) {
  int32_t q = x / y;
  int32_t r = x % y;
  return q - ((r != 0 && r < 0 != y < 0) ? 1 : 0);
}

SCALAR_FUN_ATTR int64_t sdiv64(int64_t x, int64_t y) {
  int64_t q = x / y;
  int64_t r = x % y;
  return q - ((r != 0 && r < 0 != y < 0) ? 1 : 0);
}

SCALAR_FUN_ATTR int8_t   sdiv_up8(int8_t x, int8_t y)   { return sdiv8(x + y - 1, y); }
SCALAR_FUN_ATTR int16_t sdiv_up16(int16_t x, int16_t y) { return sdiv16(x + y - 1, y); }
SCALAR_FUN_ATTR int32_t sdiv_up32(int32_t x, int32_t y) { return sdiv32(x + y - 1, y); }
SCALAR_FUN_ATTR int64_t sdiv_up64(int64_t x, int64_t y) { return sdiv64(x + y - 1, y); }

SCALAR_FUN_ATTR int8_t smod8(int8_t x, int8_t y) {
  int8_t r = x % y;
  return r + (r == 0 || (x > 0 && y > 0) || (x < 0 && y < 0) ? 0 : y);
}

SCALAR_FUN_ATTR int16_t smod16(int16_t x, int16_t y) {
  int16_t r = x % y;
  return r + (r == 0 || (x > 0 && y > 0) || (x < 0 && y < 0) ? 0 : y);
}

SCALAR_FUN_ATTR int32_t smod32(int32_t x, int32_t y) {
  int32_t r = x % y;
  return r + (r == 0 || (x > 0 && y > 0) || (x < 0 && y < 0) ? 0 : y);
}

SCALAR_FUN_ATTR int64_t smod64(int64_t x, int64_t y) {
  int64_t r = x % y;
  return r + (r == 0 || (x > 0 && y > 0) || (x < 0 && y < 0) ? 0 : y);
}

SCALAR_FUN_ATTR int8_t   sdiv_safe8(int8_t x, int8_t y)   { return y == 0 ? 0 : sdiv8(x, y); }
SCALAR_FUN_ATTR int16_t sdiv_safe16(int16_t x, int16_t y) { return y == 0 ? 0 : sdiv16(x, y); }
SCALAR_FUN_ATTR int32_t sdiv_safe32(int32_t x, int32_t y) { return y == 0 ? 0 : sdiv32(x, y); }
SCALAR_FUN_ATTR int64_t sdiv_safe64(int64_t x, int64_t y) { return y == 0 ? 0 : sdiv64(x, y); }

SCALAR_FUN_ATTR int8_t   sdiv_up_safe8(int8_t x, int8_t y)   { return sdiv_safe8(x + y - 1, y);}
SCALAR_FUN_ATTR int16_t sdiv_up_safe16(int16_t x, int16_t y) { return sdiv_safe16(x + y - 1, y); }
SCALAR_FUN_ATTR int32_t sdiv_up_safe32(int32_t x, int32_t y) { return sdiv_safe32(x + y - 1, y); }
SCALAR_FUN_ATTR int64_t sdiv_up_safe64(int64_t x, int64_t y) { return sdiv_safe64(x + y - 1, y); }

SCALAR_FUN_ATTR int8_t   smod_safe8(int8_t x, int8_t y)   { return y == 0 ? 0 : smod8(x, y); }
SCALAR_FUN_ATTR int16_t smod_safe16(int16_t x, int16_t y) { return y == 0 ? 0 : smod16(x, y); }
SCALAR_FUN_ATTR int32_t smod_safe32(int32_t x, int32_t y) { return y == 0 ? 0 : smod32(x, y); }
SCALAR_FUN_ATTR int64_t smod_safe64(int64_t x, int64_t y) { return y == 0 ? 0 : smod64(x, y); }

SCALAR_FUN_ATTR int8_t   squot8(int8_t x, int8_t y)   { return x / y; }
SCALAR_FUN_ATTR int16_t squot16(int16_t x, int16_t y) { return x / y; }
SCALAR_FUN_ATTR int32_t squot32(int32_t x, int32_t y) { return x / y; }
SCALAR_FUN_ATTR int64_t squot64(int64_t x, int64_t y) { return x / y; }

SCALAR_FUN_ATTR int8_t   srem8(int8_t x, int8_t y)   { return x % y; }
SCALAR_FUN_ATTR int16_t srem16(int16_t x, int16_t y) { return x % y; }
SCALAR_FUN_ATTR int32_t srem32(int32_t x, int32_t y) { return x % y; }
SCALAR_FUN_ATTR int64_t srem64(int64_t x, int64_t y) { return x % y; }

SCALAR_FUN_ATTR int8_t   squot_safe8(int8_t x, int8_t y)   { return y == 0 ? 0 : x / y; }
SCALAR_FUN_ATTR int16_t squot_safe16(int16_t x, int16_t y) { return y == 0 ? 0 : x / y; }
SCALAR_FUN_ATTR int32_t squot_safe32(int32_t x, int32_t y) { return y == 0 ? 0 : x / y; }
SCALAR_FUN_ATTR int64_t squot_safe64(int64_t x, int64_t y) { return y == 0 ? 0 : x / y; }

SCALAR_FUN_ATTR int8_t   srem_safe8(int8_t x, int8_t y)   { return y == 0 ? 0 : x % y; }
SCALAR_FUN_ATTR int16_t srem_safe16(int16_t x, int16_t y) { return y == 0 ? 0 : x % y; }
SCALAR_FUN_ATTR int32_t srem_safe32(int32_t x, int32_t y) { return y == 0 ? 0 : x % y; }
SCALAR_FUN_ATTR int64_t srem_safe64(int64_t x, int64_t y) { return y == 0 ? 0 : x % y; }

#endif

SCALAR_FUN_ATTR int8_t   smin8(int8_t x, int8_t y)   { return x < y ? x : y; }
SCALAR_FUN_ATTR int16_t smin16(int16_t x, int16_t y) { return x < y ? x : y; }
SCALAR_FUN_ATTR int32_t smin32(int32_t x, int32_t y) { return x < y ? x : y; }
SCALAR_FUN_ATTR int64_t smin64(int64_t x, int64_t y) { return x < y ? x : y; }

SCALAR_FUN_ATTR uint8_t   umin8(uint8_t x, uint8_t y)   { return x < y ? x : y; }
SCALAR_FUN_ATTR uint16_t umin16(uint16_t x, uint16_t y) { return x < y ? x : y; }
SCALAR_FUN_ATTR uint32_t umin32(uint32_t x, uint32_t y) { return x < y ? x : y; }
SCALAR_FUN_ATTR uint64_t umin64(uint64_t x, uint64_t y) { return x < y ? x : y; }

SCALAR_FUN_ATTR int8_t  smax8(int8_t x, int8_t y)    { return x < y ? y : x; }
SCALAR_FUN_ATTR int16_t smax16(int16_t x, int16_t y) { return x < y ? y : x; }
SCALAR_FUN_ATTR int32_t smax32(int32_t x, int32_t y) { return x < y ? y : x; }
SCALAR_FUN_ATTR int64_t smax64(int64_t x, int64_t y) { return x < y ? y : x; }

SCALAR_FUN_ATTR uint8_t   umax8(uint8_t x, uint8_t y)   { return x < y ? y : x; }
SCALAR_FUN_ATTR uint16_t umax16(uint16_t x, uint16_t y) { return x < y ? y : x; }
SCALAR_FUN_ATTR uint32_t umax32(uint32_t x, uint32_t y) { return x < y ? y : x; }
SCALAR_FUN_ATTR uint64_t umax64(uint64_t x, uint64_t y) { return x < y ? y : x; }

SCALAR_FUN_ATTR uint8_t   shl8(uint8_t x, uint8_t y)   { return (uint8_t)(x << y); }
SCALAR_FUN_ATTR uint16_t shl16(uint16_t x, uint16_t y) { return (uint16_t)(x << y); }
SCALAR_FUN_ATTR uint32_t shl32(uint32_t x, uint32_t y) { return x << y; }
SCALAR_FUN_ATTR uint64_t shl64(uint64_t x, uint64_t y) { return x << y; }

SCALAR_FUN_ATTR uint8_t   lshr8(uint8_t x, uint8_t y)   { return x >> y; }
SCALAR_FUN_ATTR uint16_t lshr16(uint16_t x, uint16_t y) { return x >> y; }
SCALAR_FUN_ATTR uint32_t lshr32(uint32_t x, uint32_t y) { return x >> y; }
SCALAR_FUN_ATTR uint64_t lshr64(uint64_t x, uint64_t y) { return x >> y; }

SCALAR_FUN_ATTR int8_t   ashr8(int8_t x, int8_t y)   { return x >> y; }
SCALAR_FUN_ATTR int16_t ashr16(int16_t x, int16_t y) { return x >> y; }
SCALAR_FUN_ATTR int32_t ashr32(int32_t x, int32_t y) { return x >> y; }
SCALAR_FUN_ATTR int64_t ashr64(int64_t x, int64_t y) { return x >> y; }

SCALAR_FUN_ATTR uint8_t   and8(uint8_t x, uint8_t y)   { return x & y; }
SCALAR_FUN_ATTR uint16_t and16(uint16_t x, uint16_t y) { return x & y; }
SCALAR_FUN_ATTR uint32_t and32(uint32_t x, uint32_t y) { return x & y; }
SCALAR_FUN_ATTR uint64_t and64(uint64_t x, uint64_t y) { return x & y; }

SCALAR_FUN_ATTR uint8_t    or8(uint8_t x, uint8_t y)  { return x | y; }
SCALAR_FUN_ATTR uint16_t or16(uint16_t x, uint16_t y) { return x | y; }
SCALAR_FUN_ATTR uint32_t or32(uint32_t x, uint32_t y) { return x | y; }
SCALAR_FUN_ATTR uint64_t or64(uint64_t x, uint64_t y) { return x | y; }

SCALAR_FUN_ATTR uint8_t   xor8(uint8_t x, uint8_t y)   { return x ^ y; }
SCALAR_FUN_ATTR uint16_t xor16(uint16_t x, uint16_t y) { return x ^ y; }
SCALAR_FUN_ATTR uint32_t xor32(uint32_t x, uint32_t y) { return x ^ y; }
SCALAR_FUN_ATTR uint64_t xor64(uint64_t x, uint64_t y) { return x ^ y; }

SCALAR_FUN_ATTR bool ult8(uint8_t x, uint8_t y)    { return x < y; }
SCALAR_FUN_ATTR bool ult16(uint16_t x, uint16_t y) { return x < y; }
SCALAR_FUN_ATTR bool ult32(uint32_t x, uint32_t y) { return x < y; }
SCALAR_FUN_ATTR bool ult64(uint64_t x, uint64_t y) { return x < y; }

SCALAR_FUN_ATTR bool ule8(uint8_t x, uint8_t y)    { return x <= y; }
SCALAR_FUN_ATTR bool ule16(uint16_t x, uint16_t y) { return x <= y; }
SCALAR_FUN_ATTR bool ule32(uint32_t x, uint32_t y) { return x <= y; }
SCALAR_FUN_ATTR bool ule64(uint64_t x, uint64_t y) { return x <= y; }

SCALAR_FUN_ATTR bool  slt8(int8_t x, int8_t y)   { return x < y; }
SCALAR_FUN_ATTR bool slt16(int16_t x, int16_t y) { return x < y; }
SCALAR_FUN_ATTR bool slt32(int32_t x, int32_t y) { return x < y; }
SCALAR_FUN_ATTR bool slt64(int64_t x, int64_t y) { return x < y; }

SCALAR_FUN_ATTR bool  sle8(int8_t x, int8_t y)   { return x <= y; }
SCALAR_FUN_ATTR bool sle16(int16_t x, int16_t y) { return x <= y; }
SCALAR_FUN_ATTR bool sle32(int32_t x, int32_t y) { return x <= y; }
SCALAR_FUN_ATTR bool sle64(int64_t x, int64_t y) { return x <= y; }

SCALAR_FUN_ATTR uint8_t pow8(uint8_t x, uint8_t y) {
  uint8_t res = 1, rem = y;
  while (rem != 0) {
    if (rem & 1)
      res *= x;
    rem >>= 1;
    x *= x;
  }
  return res;
}

SCALAR_FUN_ATTR uint16_t pow16(uint16_t x, uint16_t y) {
  uint16_t res = 1, rem = y;
  while (rem != 0) {
    if (rem & 1)
      res *= x;
    rem >>= 1;
    x *= x;
  }
  return res;
}

SCALAR_FUN_ATTR uint32_t pow32(uint32_t x, uint32_t y) {
  uint32_t res = 1, rem = y;
  while (rem != 0) {
    if (rem & 1)
      res *= x;
    rem >>= 1;
    x *= x;
  }
  return res;
}

SCALAR_FUN_ATTR uint64_t pow64(uint64_t x, uint64_t y) {
  uint64_t res = 1, rem = y;
  while (rem != 0) {
    if (rem & 1)
      res *= x;
    rem >>= 1;
    x *= x;
  }
  return res;
}

SCALAR_FUN_ATTR bool  itob_i8_bool(int8_t x)  { return x != 0; }
SCALAR_FUN_ATTR bool itob_i16_bool(int16_t x) { return x != 0; }
SCALAR_FUN_ATTR bool itob_i32_bool(int32_t x) { return x != 0; }
SCALAR_FUN_ATTR bool itob_i64_bool(int64_t x) { return x != 0; }

SCALAR_FUN_ATTR int8_t btoi_bool_i8(bool x)   { return x; }
SCALAR_FUN_ATTR int16_t btoi_bool_i16(bool x) { return x; }
SCALAR_FUN_ATTR int32_t btoi_bool_i32(bool x) { return x; }
SCALAR_FUN_ATTR int64_t btoi_bool_i64(bool x) { return x; }

#define sext_i8_i8(x) ((int8_t) (int8_t) (x))
#define sext_i8_i16(x) ((int16_t) (int8_t) (x))
#define sext_i8_i32(x) ((int32_t) (int8_t) (x))
#define sext_i8_i64(x) ((int64_t) (int8_t) (x))
#define sext_i16_i8(x) ((int8_t) (int16_t) (x))
#define sext_i16_i16(x) ((int16_t) (int16_t) (x))
#define sext_i16_i32(x) ((int32_t) (int16_t) (x))
#define sext_i16_i64(x) ((int64_t) (int16_t) (x))
#define sext_i32_i8(x) ((int8_t) (int32_t) (x))
#define sext_i32_i16(x) ((int16_t) (int32_t) (x))
#define sext_i32_i32(x) ((int32_t) (int32_t) (x))
#define sext_i32_i64(x) ((int64_t) (int32_t) (x))
#define sext_i64_i8(x) ((int8_t) (int64_t) (x))
#define sext_i64_i16(x) ((int16_t) (int64_t) (x))
#define sext_i64_i32(x) ((int32_t) (int64_t) (x))
#define sext_i64_i64(x) ((int64_t) (int64_t) (x))
#define zext_i8_i8(x) ((int8_t) (uint8_t) (x))
#define zext_i8_i16(x) ((int16_t) (uint8_t) (x))
#define zext_i8_i32(x) ((int32_t) (uint8_t) (x))
#define zext_i8_i64(x) ((int64_t) (uint8_t) (x))
#define zext_i16_i8(x) ((int8_t) (uint16_t) (x))
#define zext_i16_i16(x) ((int16_t) (uint16_t) (x))
#define zext_i16_i32(x) ((int32_t) (uint16_t) (x))
#define zext_i16_i64(x) ((int64_t) (uint16_t) (x))
#define zext_i32_i8(x) ((int8_t) (uint32_t) (x))
#define zext_i32_i16(x) ((int16_t) (uint32_t) (x))
#define zext_i32_i32(x) ((int32_t) (uint32_t) (x))
#define zext_i32_i64(x) ((int64_t) (uint32_t) (x))
#define zext_i64_i8(x) ((int8_t) (uint64_t) (x))
#define zext_i64_i16(x) ((int16_t) (uint64_t) (x))
#define zext_i64_i32(x) ((int32_t) (uint64_t) (x))
#define zext_i64_i64(x) ((int64_t) (uint64_t) (x))

SCALAR_FUN_ATTR int8_t   abs8(int8_t x)  { return (int8_t)abs(x); }
SCALAR_FUN_ATTR int16_t abs16(int16_t x) { return (int16_t)abs(x); }
SCALAR_FUN_ATTR int32_t abs32(int32_t x) { return abs(x); }
SCALAR_FUN_ATTR int64_t abs64(int64_t x) {
#if defined(__OPENCL_VERSION__) || defined(ISPC)
  return abs(x);
#else
  return llabs(x);
#endif
}

#if defined(__OPENCL_VERSION__)

SCALAR_FUN_ATTR int32_t  futrts_popc8(int8_t x)  { return popcount(x); }
SCALAR_FUN_ATTR int32_t futrts_popc16(int16_t x) { return popcount(x); }
SCALAR_FUN_ATTR int32_t futrts_popc32(int32_t x) { return popcount(x); }
SCALAR_FUN_ATTR int32_t futrts_popc64(int64_t x) { return popcount(x); }

#elif defined(__CUDA_ARCH__)

SCALAR_FUN_ATTR int32_t  futrts_popc8(int8_t x)  { return __popc(zext_i8_i32(x)); }
SCALAR_FUN_ATTR int32_t futrts_popc16(int16_t x) { return __popc(zext_i16_i32(x)); }
SCALAR_FUN_ATTR int32_t futrts_popc32(int32_t x) { return __popc(x); }
SCALAR_FUN_ATTR int32_t futrts_popc64(int64_t x) { return __popcll(x); }

#else // Not OpenCL or CUDA, but plain C.

SCALAR_FUN_ATTR int32_t futrts_popc8(uint8_t x) {
  int c = 0;
  for (; x; ++c) { x &= x - 1; }
  return c;
}

SCALAR_FUN_ATTR int32_t futrts_popc16(uint16_t x) {
  int c = 0;
  for (; x; ++c) { x &= x - 1; }
  return c;
}

SCALAR_FUN_ATTR int32_t futrts_popc32(uint32_t x) {
  int c = 0;
  for (; x; ++c) { x &= x - 1; }
  return c;
}

SCALAR_FUN_ATTR int32_t futrts_popc64(uint64_t x) {
  int c = 0;
  for (; x; ++c) { x &= x - 1; }
  return c;
}
#endif

#if defined(__OPENCL_VERSION__)
SCALAR_FUN_ATTR uint8_t  futrts_umul_hi8 ( uint8_t a,  uint8_t b) { return mul_hi(a, b); }
SCALAR_FUN_ATTR uint16_t futrts_umul_hi16(uint16_t a, uint16_t b) { return mul_hi(a, b); }
SCALAR_FUN_ATTR uint32_t futrts_umul_hi32(uint32_t a, uint32_t b) { return mul_hi(a, b); }
SCALAR_FUN_ATTR uint64_t futrts_umul_hi64(uint64_t a, uint64_t b) { return mul_hi(a, b); }
SCALAR_FUN_ATTR uint8_t  futrts_smul_hi8 ( int8_t a,  int8_t b) { return mul_hi(a, b); }
SCALAR_FUN_ATTR uint16_t futrts_smul_hi16(int16_t a, int16_t b) { return mul_hi(a, b); }
SCALAR_FUN_ATTR uint32_t futrts_smul_hi32(int32_t a, int32_t b) { return mul_hi(a, b); }
SCALAR_FUN_ATTR uint64_t futrts_smul_hi64(int64_t a, int64_t b) { return mul_hi(a, b); }
#elif defined(__CUDA_ARCH__)
SCALAR_FUN_ATTR  uint8_t futrts_umul_hi8(uint8_t a, uint8_t b) { return ((uint16_t)a) * ((uint16_t)b) >> 8; }
SCALAR_FUN_ATTR uint16_t futrts_umul_hi16(uint16_t a, uint16_t b) { return ((uint32_t)a) * ((uint32_t)b) >> 16; }
SCALAR_FUN_ATTR uint32_t futrts_umul_hi32(uint32_t a, uint32_t b) { return __umulhi(a, b); }
SCALAR_FUN_ATTR uint64_t futrts_umul_hi64(uint64_t a, uint64_t b) { return __umul64hi(a, b); }
SCALAR_FUN_ATTR  uint8_t futrts_smul_hi8 ( int8_t a, int8_t b) { return ((int16_t)a) * ((int16_t)b) >> 8; }
SCALAR_FUN_ATTR uint16_t futrts_smul_hi16(int16_t a, int16_t b) { return ((int32_t)a) * ((int32_t)b) >> 16; }
SCALAR_FUN_ATTR uint32_t futrts_smul_hi32(int32_t a, int32_t b) { return __mulhi(a, b); }
SCALAR_FUN_ATTR uint64_t futrts_smul_hi64(int64_t a, int64_t b) { return __mul64hi(a, b); }
#elif defined(ISPC)
SCALAR_FUN_ATTR uint8_t futrts_umul_hi8(uint8_t a, uint8_t b) { return ((uint16_t)a) * ((uint16_t)b) >> 8; }
SCALAR_FUN_ATTR uint16_t futrts_umul_hi16(uint16_t a, uint16_t b) { return ((uint32_t)a) * ((uint32_t)b) >> 16; }
SCALAR_FUN_ATTR uint32_t futrts_umul_hi32(uint32_t a, uint32_t b) { return ((uint64_t)a) * ((uint64_t)b) >> 32; }
SCALAR_FUN_ATTR uint64_t futrts_umul_hi64(uint64_t a, uint64_t b) {
  uint64_t ah = a >> 32;
  uint64_t al = a & 0xffffffff;
  uint64_t bh = b >> 32;
  uint64_t bl = b & 0xffffffff;

  uint64_t p1 = al * bl;
  uint64_t p2 = al * bh;
  uint64_t p3 = ah * bl;
  uint64_t p4 = ah * bh;

  uint64_t p1h = p1 >> 32;
  uint64_t p2h = p2 >> 32;
  uint64_t p3h = p3 >> 32;
  uint64_t p2l = p2 & 0xffffffff;
  uint64_t p3l = p3 & 0xffffffff;

  uint64_t l = p1h + p2l + p3l;
  uint64_t m = (p2 >> 32) + (p3 >> 32);
  uint64_t h = (l >> 32) + m + p4;

  return h;
}
SCALAR_FUN_ATTR  int8_t futrts_smul_hi8 ( int8_t a,  int8_t b) { return ((uint16_t)a) * ((uint16_t)b) >> 8; }
SCALAR_FUN_ATTR int16_t futrts_smul_hi16(int16_t a, int16_t b) { return ((uint32_t)a) * ((uint32_t)b) >> 16; }
SCALAR_FUN_ATTR int32_t futrts_smul_hi32(int32_t a, int32_t b) { return ((uint64_t)a) * ((uint64_t)b) >> 32; }
SCALAR_FUN_ATTR int64_t futrts_smul_hi64(int64_t a, int64_t b) {
  uint64_t ah = a >> 32;
  uint64_t al = a & 0xffffffff;
  uint64_t bh = b >> 32;
  uint64_t bl = b & 0xffffffff;

  uint64_t p1 =  al * bl;
  int64_t  p2 = al * bh;
  int64_t  p3 = ah * bl;
  uint64_t p4 =  ah * bh;

  uint64_t p1h = p1 >> 32;
  uint64_t p2h = p2 >> 32;
  uint64_t p3h = p3 >> 32;
  uint64_t p2l = p2 & 0xffffffff;
  uint64_t p3l = p3 & 0xffffffff;

  uint64_t l = p1h + p2l + p3l;
  uint64_t m = (p2 >> 32) + (p3 >> 32);
  uint64_t h = (l >> 32) + m + p4;

  return h;
}

#else // Not OpenCL, ISPC, or CUDA, but plain C.
SCALAR_FUN_ATTR uint8_t futrts_umul_hi8(uint8_t a, uint8_t b) { return ((uint16_t)a) * ((uint16_t)b) >> 8; }
SCALAR_FUN_ATTR uint16_t futrts_umul_hi16(uint16_t a, uint16_t b) { return ((uint32_t)a) * ((uint32_t)b) >> 16; }
SCALAR_FUN_ATTR uint32_t futrts_umul_hi32(uint32_t a, uint32_t b) { return ((uint64_t)a) * ((uint64_t)b) >> 32; }
SCALAR_FUN_ATTR uint64_t futrts_umul_hi64(uint64_t a, uint64_t b) { return ((__uint128_t)a) * ((__uint128_t)b) >> 64; }
SCALAR_FUN_ATTR int8_t futrts_smul_hi8(int8_t a, int8_t b) { return ((int16_t)a) * ((int16_t)b) >> 8; }
SCALAR_FUN_ATTR int16_t futrts_smul_hi16(int16_t a, int16_t b) { return ((int32_t)a) * ((int32_t)b) >> 16; }
SCALAR_FUN_ATTR int32_t futrts_smul_hi32(int32_t a, int32_t b) { return ((int64_t)a) * ((int64_t)b) >> 32; }
SCALAR_FUN_ATTR int64_t futrts_smul_hi64(int64_t a, int64_t b) { return ((__int128_t)a) * ((__int128_t)b) >> 64; }
#endif

#if defined(__OPENCL_VERSION__)
SCALAR_FUN_ATTR  uint8_t futrts_umad_hi8 ( uint8_t a,  uint8_t b,  uint8_t c) { return mad_hi(a, b, c); }
SCALAR_FUN_ATTR uint16_t futrts_umad_hi16(uint16_t a, uint16_t b, uint16_t c) { return mad_hi(a, b, c); }
SCALAR_FUN_ATTR uint32_t futrts_umad_hi32(uint32_t a, uint32_t b, uint32_t c) { return mad_hi(a, b, c); }
SCALAR_FUN_ATTR uint64_t futrts_umad_hi64(uint64_t a, uint64_t b, uint64_t c) { return mad_hi(a, b, c); }
SCALAR_FUN_ATTR  uint8_t futrts_smad_hi8( int8_t a,  int8_t b,   int8_t c) { return mad_hi(a, b, c); }
SCALAR_FUN_ATTR uint16_t futrts_smad_hi16(int16_t a, int16_t b, int16_t c) { return mad_hi(a, b, c); }
SCALAR_FUN_ATTR uint32_t futrts_smad_hi32(int32_t a, int32_t b, int32_t c) { return mad_hi(a, b, c); }
SCALAR_FUN_ATTR uint64_t futrts_smad_hi64(int64_t a, int64_t b, int64_t c) { return mad_hi(a, b, c); }
#else // Not OpenCL

SCALAR_FUN_ATTR  uint8_t futrts_umad_hi8( uint8_t a,  uint8_t b,  uint8_t c) { return futrts_umul_hi8(a, b) + c; }
SCALAR_FUN_ATTR uint16_t futrts_umad_hi16(uint16_t a, uint16_t b, uint16_t c) { return futrts_umul_hi16(a, b) + c; }
SCALAR_FUN_ATTR uint32_t futrts_umad_hi32(uint32_t a, uint32_t b, uint32_t c) { return futrts_umul_hi32(a, b) + c; }
SCALAR_FUN_ATTR uint64_t futrts_umad_hi64(uint64_t a, uint64_t b, uint64_t c) { return futrts_umul_hi64(a, b) + c; }
SCALAR_FUN_ATTR  uint8_t futrts_smad_hi8 ( int8_t a,  int8_t b,  int8_t c) { return futrts_smul_hi8(a, b) + c; }
SCALAR_FUN_ATTR uint16_t futrts_smad_hi16(int16_t a, int16_t b, int16_t c) { return futrts_smul_hi16(a, b) + c; }
SCALAR_FUN_ATTR uint32_t futrts_smad_hi32(int32_t a, int32_t b, int32_t c) { return futrts_smul_hi32(a, b) + c; }
SCALAR_FUN_ATTR uint64_t futrts_smad_hi64(int64_t a, int64_t b, int64_t c) { return futrts_smul_hi64(a, b) + c; }
#endif

#if defined(__OPENCL_VERSION__)
SCALAR_FUN_ATTR int32_t  futrts_clzz8(int8_t x)  { return clz(x); }
SCALAR_FUN_ATTR int32_t futrts_clzz16(int16_t x) { return clz(x); }
SCALAR_FUN_ATTR int32_t futrts_clzz32(int32_t x) { return clz(x); }
SCALAR_FUN_ATTR int32_t futrts_clzz64(int64_t x) { return clz(x); }

#elif defined(__CUDA_ARCH__)

SCALAR_FUN_ATTR int32_t  futrts_clzz8(int8_t x)  { return __clz(zext_i8_i32(x)) - 24; }
SCALAR_FUN_ATTR int32_t futrts_clzz16(int16_t x) { return __clz(zext_i16_i32(x)) - 16; }
SCALAR_FUN_ATTR int32_t futrts_clzz32(int32_t x) { return __clz(x); }
SCALAR_FUN_ATTR int32_t futrts_clzz64(int64_t x) { return __clzll(x); }

#elif defined(ISPC)

SCALAR_FUN_ATTR int32_t  futrts_clzz8(int8_t x)  { return count_leading_zeros((int32_t)(uint8_t)x)-24; }
SCALAR_FUN_ATTR int32_t futrts_clzz16(int16_t x) { return count_leading_zeros((int32_t)(uint16_t)x)-16; }
SCALAR_FUN_ATTR int32_t futrts_clzz32(int32_t x) { return count_leading_zeros(x); }
SCALAR_FUN_ATTR int32_t futrts_clzz64(int64_t x) { return count_leading_zeros(x); }

#else // Not OpenCL, ISPC or CUDA, but plain C.

SCALAR_FUN_ATTR int32_t futrts_clzz8(int8_t x)
{ return x == 0 ? 8 : __builtin_clz((uint32_t)zext_i8_i32(x)) - 24; }
SCALAR_FUN_ATTR int32_t futrts_clzz16(int16_t x)
{ return x == 0 ? 16 : __builtin_clz((uint32_t)zext_i16_i32(x)) - 16; }
SCALAR_FUN_ATTR int32_t futrts_clzz32(int32_t x)
{ return x == 0 ? 32 : __builtin_clz((uint32_t)x); }
SCALAR_FUN_ATTR int32_t futrts_clzz64(int64_t x)
{ return x == 0 ? 64 : __builtin_clzll((uint64_t)x); }
#endif

#if defined(__OPENCL_VERSION__)
SCALAR_FUN_ATTR int32_t futrts_ctzz8(int8_t x) {
  int i = 0;
  for (; i < 8 && (x & 1) == 0; i++, x >>= 1) ;
  return i;
}

SCALAR_FUN_ATTR int32_t futrts_ctzz16(int16_t x) {
  int i = 0;
  for (; i < 16 && (x & 1) == 0; i++, x >>= 1) ;
  return i;
}

SCALAR_FUN_ATTR int32_t futrts_ctzz32(int32_t x) {
  int i = 0;
  for (; i < 32 && (x & 1) == 0; i++, x >>= 1) ;
  return i;
}

SCALAR_FUN_ATTR int32_t futrts_ctzz64(int64_t x) {
  int i = 0;
  for (; i < 64 && (x & 1) == 0; i++, x >>= 1) ;
  return i;
}

#elif defined(__CUDA_ARCH__)

SCALAR_FUN_ATTR int32_t futrts_ctzz8(int8_t x) {
  int y = __ffs(x);
  return y == 0 ? 8 : y - 1;
}

SCALAR_FUN_ATTR int32_t futrts_ctzz16(int16_t x) {
  int y = __ffs(x);
  return y == 0 ? 16 : y - 1;
}

SCALAR_FUN_ATTR int32_t futrts_ctzz32(int32_t x) {
  int y = __ffs(x);
  return y == 0 ? 32 : y - 1;
}

SCALAR_FUN_ATTR int32_t futrts_ctzz64(int64_t x) {
  int y = __ffsll(x);
  return y == 0 ? 64 : y - 1;
}

#elif defined(ISPC)

SCALAR_FUN_ATTR int32_t futrts_ctzz8(int8_t x) { return x == 0 ? 8 : count_trailing_zeros((int32_t)x); }
SCALAR_FUN_ATTR int32_t futrts_ctzz16(int16_t x) { return x == 0 ? 16 : count_trailing_zeros((int32_t)x); }
SCALAR_FUN_ATTR int32_t futrts_ctzz32(int32_t x) { return count_trailing_zeros(x); }
SCALAR_FUN_ATTR int32_t futrts_ctzz64(int64_t x) { return count_trailing_zeros(x); }

#else // Not OpenCL or CUDA, but plain C.

SCALAR_FUN_ATTR int32_t  futrts_ctzz8(int8_t x)  { return x == 0 ? 8 : __builtin_ctz((uint32_t)x); }
SCALAR_FUN_ATTR int32_t futrts_ctzz16(int16_t x) { return x == 0 ? 16 : __builtin_ctz((uint32_t)x); }
SCALAR_FUN_ATTR int32_t futrts_ctzz32(int32_t x) { return x == 0 ? 32 : __builtin_ctz((uint32_t)x); }
SCALAR_FUN_ATTR int32_t futrts_ctzz64(int64_t x) { return x == 0 ? 64 : __builtin_ctzll((uint64_t)x); }
#endif

SCALAR_FUN_ATTR float fdiv32(float x, float y) { return x / y; }
SCALAR_FUN_ATTR float fadd32(float x, float y) { return x + y; }
SCALAR_FUN_ATTR float fsub32(float x, float y) { return x - y; }
SCALAR_FUN_ATTR float fmul32(float x, float y) { return x * y; }
SCALAR_FUN_ATTR bool cmplt32(float x, float y) { return x < y; }
SCALAR_FUN_ATTR bool cmple32(float x, float y) { return x <= y; }
SCALAR_FUN_ATTR float sitofp_i8_f32(int8_t x)  { return (float) x; }

SCALAR_FUN_ATTR float sitofp_i16_f32(int16_t x) { return (float) x; }
SCALAR_FUN_ATTR float sitofp_i32_f32(int32_t x) { return (float) x; }
SCALAR_FUN_ATTR float sitofp_i64_f32(int64_t x) { return (float) x; }
SCALAR_FUN_ATTR float  uitofp_i8_f32(uint8_t x)  { return (float) x; }
SCALAR_FUN_ATTR float uitofp_i16_f32(uint16_t x) { return (float) x; }
SCALAR_FUN_ATTR float uitofp_i32_f32(uint32_t x) { return (float) x; }
SCALAR_FUN_ATTR float uitofp_i64_f32(uint64_t x) { return (float) x; }

#ifdef __OPENCL_VERSION__
SCALAR_FUN_ATTR float fabs32(float x)          { return fabs(x); }
SCALAR_FUN_ATTR float fmax32(float x, float y) { return fmax(x, y); }
SCALAR_FUN_ATTR float fmin32(float x, float y) { return fmin(x, y); }
SCALAR_FUN_ATTR float fpow32(float x, float y) { return pow(x, y); }

#elif defined(ISPC)

SCALAR_FUN_ATTR float fabs32(float x) { return abs(x); }
SCALAR_FUN_ATTR float fmax32(float x, float y) { return isnan(x) ? y : isnan(y) ? x : max(x, y); }
SCALAR_FUN_ATTR float fmin32(float x, float y) { return isnan(x) ? y : isnan(y) ? x : min(x, y); }
SCALAR_FUN_ATTR float fpow32(float a, float b) {
  float ret;
  foreach_active (i) {
      uniform float r = pow(extract(a, i), extract(b, i));
      ret = insert(ret, i, r);
  }
  return ret;
}

#else // Not OpenCL, but CUDA or plain C.

SCALAR_FUN_ATTR float fabs32(float x)          { return fabsf(x); }
SCALAR_FUN_ATTR float fmax32(float x, float y) { return fmaxf(x, y); }
SCALAR_FUN_ATTR float fmin32(float x, float y) { return fminf(x, y); }
SCALAR_FUN_ATTR float fpow32(float x, float y) { return powf(x, y); }
#endif

SCALAR_FUN_ATTR bool futrts_isnan32(float x) { return isnan(x); }

#if defined(ISPC)

SCALAR_FUN_ATTR bool futrts_isinf32(float x) { return !isnan(x) && isnan(x - x); }

SCALAR_FUN_ATTR bool futrts_isfinite32(float x) { return !isnan(x) && !futrts_isinf32(x); }

#else

SCALAR_FUN_ATTR bool futrts_isinf32(float x) { return isinf(x); }

#endif

SCALAR_FUN_ATTR int8_t fptosi_f32_i8(float x) {
  if (futrts_isnan32(x) || futrts_isinf32(x)) {
    return 0;
  } else {
    return (int8_t) x;
  }
}

SCALAR_FUN_ATTR int16_t fptosi_f32_i16(float x) {
  if (futrts_isnan32(x) || futrts_isinf32(x)) {
    return 0;
  } else {
    return (int16_t) x;
  }
}

SCALAR_FUN_ATTR int32_t fptosi_f32_i32(float x) {
  if (futrts_isnan32(x) || futrts_isinf32(x)) {
    return 0;
  } else {
    return (int32_t) x;
  }
}

SCALAR_FUN_ATTR int64_t fptosi_f32_i64(float x) {
  if (futrts_isnan32(x) || futrts_isinf32(x)) {
    return 0;
  } else {
    return (int64_t) x;
  };
}

SCALAR_FUN_ATTR uint8_t fptoui_f32_i8(float x) {
  if (futrts_isnan32(x) || futrts_isinf32(x)) {
    return 0;
  } else {
    return (uint8_t) (int8_t) x;
  }
}

SCALAR_FUN_ATTR uint16_t fptoui_f32_i16(float x) {
  if (futrts_isnan32(x) || futrts_isinf32(x)) {
    return 0;
  } else {
    return (uint16_t) (int16_t) x;
  }
}

SCALAR_FUN_ATTR uint32_t fptoui_f32_i32(float x) {
  if (futrts_isnan32(x) || futrts_isinf32(x)) {
    return 0;
  } else {
    return (uint32_t) (int32_t) x;
  }
}

SCALAR_FUN_ATTR uint64_t fptoui_f32_i64(float x) {
  if (futrts_isnan32(x) || futrts_isinf32(x)) {
    return 0;
  } else {
    return (uint64_t) (int64_t) x;
  }
}

SCALAR_FUN_ATTR bool ftob_f32_bool(float x) { return x != 0; }
SCALAR_FUN_ATTR float btof_bool_f32(bool x) { return x ? 1 : 0; }

#ifdef __OPENCL_VERSION__
SCALAR_FUN_ATTR float futrts_log32(float x) { return log(x); }
SCALAR_FUN_ATTR float futrts_log2_32(float x) { return log2(x); }
SCALAR_FUN_ATTR float futrts_log10_32(float x) { return log10(x); }
SCALAR_FUN_ATTR float futrts_log1p_32(float x) { return log1p(x); }
SCALAR_FUN_ATTR float futrts_sqrt32(float x) { return sqrt(x); }
SCALAR_FUN_ATTR float futrts_rsqrt32(float x) { return rsqrt(x); }
SCALAR_FUN_ATTR float futrts_cbrt32(float x) { return cbrt(x); }
SCALAR_FUN_ATTR float futrts_exp32(float x) { return exp(x); }
SCALAR_FUN_ATTR float futrts_cos32(float x) { return cos(x); }
SCALAR_FUN_ATTR float futrts_cospi32(float x) { return cospi(x); }
SCALAR_FUN_ATTR float futrts_sin32(float x) { return sin(x); }
SCALAR_FUN_ATTR float futrts_sinpi32(float x) { return sinpi(x); }
SCALAR_FUN_ATTR float futrts_tan32(float x) { return tan(x); }
SCALAR_FUN_ATTR float futrts_tanpi32(float x) { return tanpi(x); }
SCALAR_FUN_ATTR float futrts_acos32(float x) { return acos(x); }
SCALAR_FUN_ATTR float futrts_acospi32(float x) { return acospi(x); }
SCALAR_FUN_ATTR float futrts_asin32(float x) { return asin(x); }
SCALAR_FUN_ATTR float futrts_asinpi32(float x) { return asinpi(x); }
SCALAR_FUN_ATTR float futrts_atan32(float x) { return atan(x); }
SCALAR_FUN_ATTR float futrts_atanpi32(float x) { return atanpi(x); }
SCALAR_FUN_ATTR float futrts_cosh32(float x) { return cosh(x); }
SCALAR_FUN_ATTR float futrts_sinh32(float x) { return sinh(x); }
SCALAR_FUN_ATTR float futrts_tanh32(float x) { return tanh(x); }
SCALAR_FUN_ATTR float futrts_acosh32(float x) { return acosh(x); }
SCALAR_FUN_ATTR float futrts_asinh32(float x) { return asinh(x); }
SCALAR_FUN_ATTR float futrts_atanh32(float x) { return atanh(x); }
SCALAR_FUN_ATTR float futrts_atan2_32(float x, float y) { return atan2(x, y); }
SCALAR_FUN_ATTR float futrts_atan2pi_32(float x, float y) { return atan2pi(x, y); }
SCALAR_FUN_ATTR float futrts_hypot32(float x, float y) { return hypot(x, y); }
SCALAR_FUN_ATTR float futrts_gamma32(float x) { return tgamma(x); }
SCALAR_FUN_ATTR float futrts_lgamma32(float x) { return lgamma(x); }
SCALAR_FUN_ATTR float futrts_erf32(float x) { return erf(x); }
SCALAR_FUN_ATTR float futrts_erfc32(float x) { return erfc(x); }
SCALAR_FUN_ATTR float fmod32(float x, float y) { return fmod(x, y); }
SCALAR_FUN_ATTR float futrts_round32(float x) { return rint(x); }
SCALAR_FUN_ATTR float futrts_floor32(float x) { return floor(x); }
SCALAR_FUN_ATTR float futrts_ceil32(float x) { return ceil(x); }
SCALAR_FUN_ATTR float futrts_nextafter32(float x, float y) { return nextafter(x, y); }
SCALAR_FUN_ATTR float futrts_lerp32(float v0, float v1, float t) { return mix(v0, v1, t); }
SCALAR_FUN_ATTR float futrts_ldexp32(float x, int32_t y) { return ldexp(x, y); }
SCALAR_FUN_ATTR float futrts_copysign32(float x, float y) { return copysign(x, y); }
SCALAR_FUN_ATTR float futrts_mad32(float a, float b, float c) { return mad(a, b, c); }
SCALAR_FUN_ATTR float futrts_fma32(float a, float b, float c) { return fma(a, b, c); }

#elif defined(ISPC)

SCALAR_FUN_ATTR float futrts_log32(float x) { return futrts_isfinite32(x) || (futrts_isinf32(x) && x < 0)? log(x) : x; }
SCALAR_FUN_ATTR float futrts_log2_32(float x) { return futrts_log32(x) / log(2.0f); }
SCALAR_FUN_ATTR float futrts_log10_32(float x) { return futrts_log32(x) / log(10.0f); }

SCALAR_FUN_ATTR float futrts_log1p_32(float x) {
  if(x == -1.0f || (futrts_isinf32(x) && x > 0.0f)) return x / 0.0f;
  float y = 1.0f + x;
  float z = y - 1.0f;
  return log(y) - (z-x)/y;
}

SCALAR_FUN_ATTR float futrts_sqrt32(float x) { return sqrt(x); }
SCALAR_FUN_ATTR float futrts_rsqrt32(float x) { return 1/sqrt(x); }

extern "C" unmasked uniform float cbrtf(uniform float);
SCALAR_FUN_ATTR float futrts_cbrt32(float x) {
  float res;
  foreach_active (i) {
    uniform float r = cbrtf(extract(x, i));
    res = insert(res, i, r);
  }
  return res;
}

SCALAR_FUN_ATTR float futrts_exp32(float x) { return exp(x); }
SCALAR_FUN_ATTR float futrts_cos32(float x) { return cos(x); }
SCALAR_FUN_ATTR float futrts_cospi32(float x) { return cos((float)M_PI*x); }
SCALAR_FUN_ATTR float futrts_sin32(float x) { return sin(x); }
SCALAR_FUN_ATTR float futrts_sinpi32(float x) { return sin(M_PI*x); }
SCALAR_FUN_ATTR float futrts_tan32(float x) { return tan(x); }
SCALAR_FUN_ATTR float futrts_tanpi32(float x) { return tan((float)M_PI*x); }
SCALAR_FUN_ATTR float futrts_acos32(float x) { return acos(x); }
SCALAR_FUN_ATTR float futrts_acospi32(float x) { return acos(x)/(float)M_PI; }
SCALAR_FUN_ATTR float futrts_asin32(float x) { return asin(x); }
SCALAR_FUN_ATTR float futrts_asinpi32(float x) { return asin(x)/(float)M_PI; }
SCALAR_FUN_ATTR float futrts_atan32(float x) { return atan(x); }
SCALAR_FUN_ATTR float futrts_atanpi32(float x) { return atan(x)/(float)M_PI; }
SCALAR_FUN_ATTR float futrts_cosh32(float x) { return (exp(x)+exp(-x)) / 2.0f; }
SCALAR_FUN_ATTR float futrts_sinh32(float x) { return (exp(x)-exp(-x)) / 2.0f; }
SCALAR_FUN_ATTR float futrts_tanh32(float x) { return futrts_sinh32(x)/futrts_cosh32(x); }

SCALAR_FUN_ATTR float futrts_acosh32(float x) {
  float f = x+sqrt(x*x-1);
  if (futrts_isfinite32(f)) return log(f);
  return f;
}

SCALAR_FUN_ATTR float futrts_asinh32(float x) {
  float f = x+sqrt(x*x+1);
  if (futrts_isfinite32(f)) return log(f);
  return f;
}

SCALAR_FUN_ATTR float futrts_atanh32(float x) {
  float f = (1+x)/(1-x);
  if (futrts_isfinite32(f)) return log(f)/2.0f;
  return f;
}

SCALAR_FUN_ATTR float futrts_atan2_32(float x, float y)
{ return (x == 0.0f && y == 0.0f) ? 0.0f : atan2(x, y); }
SCALAR_FUN_ATTR float futrts_atan2pi_32(float x, float y)
{ return (x == 0.0f && y == 0.0f) ? 0.0f : atan2(x, y) / (float)M_PI; }

SCALAR_FUN_ATTR float futrts_hypot32(float x, float y) {
  if (futrts_isfinite32(x) && futrts_isfinite32(y)) {
    x = abs(x);
    y = abs(y);
    float a;
    float b;
    if (x >= y){
        a = x;
        b = y;
    } else {
        a = y;
        b = x;
    }
    if(b == 0){
      return a;
    }

    int e;
    float an;
    float bn;
    an = frexp (a, &e);
    bn = ldexp (b, - e);
    float cn;
    cn = sqrt (an * an + bn * bn);
    return ldexp (cn, e);
  } else {
    if (futrts_isinf32(x) || futrts_isinf32(y)) return INFINITY;
    else return x + y;
  }

}

extern "C" unmasked uniform float tgammaf(uniform float x);
SCALAR_FUN_ATTR float futrts_gamma32(float x) {
  float res;
  foreach_active (i) {
    uniform float r = tgammaf(extract(x, i));
    res = insert(res, i, r);
  }
  return res;
}

extern "C" unmasked uniform float lgammaf(uniform float x);
SCALAR_FUN_ATTR float futrts_lgamma32(float x) {
  float res;
  foreach_active (i) {
    uniform float r = lgammaf(extract(x, i));
    res = insert(res, i, r);
  }
  return res;
}

extern "C" unmasked uniform float erff(uniform float x);
SCALAR_FUN_ATTR float futrts_erf32(float x) {
  float res;
  foreach_active (i) {
    uniform float r = erff(extract(x, i));
    res = insert(res, i, r);
  }
  return res;
}

extern "C" unmasked uniform float erfcf(uniform float x);
SCALAR_FUN_ATTR float futrts_erfc32(float x) {
  float res;
  foreach_active (i) {
    uniform float r = erfcf(extract(x, i));
    res = insert(res, i, r);
  }
  return res;
}

SCALAR_FUN_ATTR float fmod32(float x, float y) { return x - y * trunc(x/y); }
SCALAR_FUN_ATTR float futrts_round32(float x) { return round(x); }
SCALAR_FUN_ATTR float futrts_floor32(float x) { return floor(x); }
SCALAR_FUN_ATTR float futrts_ceil32(float x) { return ceil(x); }

extern "C" unmasked uniform float nextafterf(uniform float x, uniform float y);
SCALAR_FUN_ATTR float futrts_nextafter32(float x, float y) {
  float res;
  foreach_active (i) {
    uniform float r = nextafterf(extract(x, i), extract(y, i));
    res = insert(res, i, r);
  }
  return res;
}

SCALAR_FUN_ATTR float futrts_lerp32(float v0, float v1, float t) {
  return v0 + (v1 - v0) * t;
}

SCALAR_FUN_ATTR float futrts_ldexp32(float x, int32_t y) {
  return x * pow((uniform float)2.0, (float)y);
}

SCALAR_FUN_ATTR float futrts_copysign32(float x, float y) {
  int32_t xb = fptobits_f32_i32(x);
  int32_t yb = fptobits_f32_i32(y);
  return bitstofp_i32_f32((xb & ~(1<<31)) | (yb & (1<<31)));
}

SCALAR_FUN_ATTR float futrts_mad32(float a, float b, float c) {
  return a * b + c;
}

SCALAR_FUN_ATTR float futrts_fma32(float a, float b, float c) {
  return a * b + c;
}

#else // Not OpenCL or ISPC, but CUDA or plain C.

SCALAR_FUN_ATTR float futrts_log32(float x) { return logf(x); }
SCALAR_FUN_ATTR float futrts_log2_32(float x) { return log2f(x); }
SCALAR_FUN_ATTR float futrts_log10_32(float x) { return log10f(x); }
SCALAR_FUN_ATTR float futrts_log1p_32(float x) { return log1pf(x); }
SCALAR_FUN_ATTR float futrts_sqrt32(float x) { return sqrtf(x); }
SCALAR_FUN_ATTR float futrts_rsqrt32(float x) { return 1/sqrtf(x); }
SCALAR_FUN_ATTR float futrts_cbrt32(float x) { return cbrtf(x); }
SCALAR_FUN_ATTR float futrts_exp32(float x) { return expf(x); }
SCALAR_FUN_ATTR float futrts_cos32(float x) { return cosf(x); }

SCALAR_FUN_ATTR float futrts_cospi32(float x) {
#if defined(__CUDA_ARCH__)
  return cospif(x);
#else
  return cosf(((float)M_PI)*x);
#endif
}
SCALAR_FUN_ATTR float futrts_sin32(float x) { return sinf(x); }

SCALAR_FUN_ATTR float futrts_sinpi32(float x) {
#if defined(__CUDA_ARCH__)
  return sinpif(x);
#else
  return sinf((float)M_PI*x);
#endif
}

SCALAR_FUN_ATTR float futrts_tan32(float x) { return tanf(x); }
SCALAR_FUN_ATTR float futrts_tanpi32(float x) { return tanf((float)M_PI*x); }
SCALAR_FUN_ATTR float futrts_acos32(float x) { return acosf(x); }
SCALAR_FUN_ATTR float futrts_acospi32(float x) { return acosf(x)/(float)M_PI; }
SCALAR_FUN_ATTR float futrts_asin32(float x) { return asinf(x); }
SCALAR_FUN_ATTR float futrts_asinpi32(float x) { return asinf(x)/(float)M_PI; }
SCALAR_FUN_ATTR float futrts_atan32(float x) { return atanf(x); }
SCALAR_FUN_ATTR float futrts_atanpi32(float x) { return atanf(x)/(float)M_PI; }
SCALAR_FUN_ATTR float futrts_cosh32(float x) { return coshf(x); }
SCALAR_FUN_ATTR float futrts_sinh32(float x) { return sinhf(x); }
SCALAR_FUN_ATTR float futrts_tanh32(float x) { return tanhf(x); }
SCALAR_FUN_ATTR float futrts_acosh32(float x) { return acoshf(x); }
SCALAR_FUN_ATTR float futrts_asinh32(float x) { return asinhf(x); }
SCALAR_FUN_ATTR float futrts_atanh32(float x) { return atanhf(x); }
SCALAR_FUN_ATTR float futrts_atan2_32(float x, float y) { return atan2f(x, y); }
SCALAR_FUN_ATTR float futrts_atan2pi_32(float x, float y) { return atan2f(x, y) / (float)M_PI; }
SCALAR_FUN_ATTR float futrts_hypot32(float x, float y) { return hypotf(x, y); }
SCALAR_FUN_ATTR float futrts_gamma32(float x) { return tgammaf(x); }
SCALAR_FUN_ATTR float futrts_lgamma32(float x) { return lgammaf(x); }
SCALAR_FUN_ATTR float futrts_erf32(float x) { return erff(x); }
SCALAR_FUN_ATTR float futrts_erfc32(float x) { return erfcf(x); }
SCALAR_FUN_ATTR float fmod32(float x, float y) { return fmodf(x, y); }
SCALAR_FUN_ATTR float futrts_round32(float x) { return rintf(x); }
SCALAR_FUN_ATTR float futrts_floor32(float x) { return floorf(x); }
SCALAR_FUN_ATTR float futrts_ceil32(float x) { return ceilf(x); }
SCALAR_FUN_ATTR float futrts_nextafter32(float x, float y) { return nextafterf(x, y); }
SCALAR_FUN_ATTR float futrts_lerp32(float v0, float v1, float t) { return v0 + (v1 - v0) * t; }
SCALAR_FUN_ATTR float futrts_ldexp32(float x, int32_t y) { return ldexpf(x, y); }
SCALAR_FUN_ATTR float futrts_copysign32(float x, float y) { return copysignf(x, y); }
SCALAR_FUN_ATTR float futrts_mad32(float a, float b, float c) { return a * b + c; }
SCALAR_FUN_ATTR float futrts_fma32(float a, float b, float c) { return fmaf(a, b, c); }

#endif

#if defined(ISPC)

SCALAR_FUN_ATTR int32_t fptobits_f32_i32(float x) { return intbits(x); }
SCALAR_FUN_ATTR float bitstofp_i32_f32(int32_t x) { return floatbits(x); }
SCALAR_FUN_ATTR uniform int32_t fptobits_f32_i32(uniform float x) { return intbits(x); }
SCALAR_FUN_ATTR uniform float bitstofp_i32_f32(uniform int32_t x) { return floatbits(x); }

#else

SCALAR_FUN_ATTR int32_t fptobits_f32_i32(float x) {
  union {
    float f;
    int32_t t;
  } p;

  p.f = x;
  return p.t;
}

SCALAR_FUN_ATTR float bitstofp_i32_f32(int32_t x) {
  union {
    int32_t f;
    float t;
  } p;

  p.f = x;
  return p.t;
}
#endif

SCALAR_FUN_ATTR float fsignum32(float x) {
  return futrts_isnan32(x) ? x : (x > 0 ? 1 : 0) - (x < 0 ? 1 : 0);
}

#ifdef FUTHARK_F64_ENABLED

SCALAR_FUN_ATTR double bitstofp_i64_f64(int64_t x);
SCALAR_FUN_ATTR int64_t fptobits_f64_i64(double x);

#if defined(ISPC)

SCALAR_FUN_ATTR bool futrts_isinf64(float x) { return !isnan(x) && isnan(x - x); }
SCALAR_FUN_ATTR bool futrts_isfinite64(float x) { return !isnan(x) && !futrts_isinf64(x); }
SCALAR_FUN_ATTR double fdiv64(double x, double y) { return x / y; }
SCALAR_FUN_ATTR double fadd64(double x, double y) { return x + y; }
SCALAR_FUN_ATTR double fsub64(double x, double y) { return x - y; }
SCALAR_FUN_ATTR double fmul64(double x, double y) { return x * y; }
SCALAR_FUN_ATTR bool cmplt64(double x, double y) { return x < y; }
SCALAR_FUN_ATTR bool cmple64(double x, double y) { return x <= y; }
SCALAR_FUN_ATTR double sitofp_i8_f64(int8_t x) { return (double) x; }
SCALAR_FUN_ATTR double sitofp_i16_f64(int16_t x) { return (double) x; }
SCALAR_FUN_ATTR double sitofp_i32_f64(int32_t x) { return (double) x; }
SCALAR_FUN_ATTR double sitofp_i64_f64(int64_t x) { return (double) x; }
SCALAR_FUN_ATTR double uitofp_i8_f64(uint8_t x) { return (double) x; }
SCALAR_FUN_ATTR double uitofp_i16_f64(uint16_t x) { return (double) x; }
SCALAR_FUN_ATTR double uitofp_i32_f64(uint32_t x) { return (double) x; }
SCALAR_FUN_ATTR double uitofp_i64_f64(uint64_t x) { return (double) x; }
SCALAR_FUN_ATTR double fabs64(double x) { return abs(x); }
SCALAR_FUN_ATTR double fmax64(double x, double y) { return isnan(x) ? y : isnan(y) ? x : max(x, y); }
SCALAR_FUN_ATTR double fmin64(double x, double y) { return isnan(x) ? y : isnan(y) ? x : min(x, y); }

SCALAR_FUN_ATTR double fpow64(double a, double b) {
  float ret;
  foreach_active (i) {
      uniform float r = pow(extract(a, i), extract(b, i));
      ret = insert(ret, i, r);
  }
  return ret;
}
SCALAR_FUN_ATTR double futrts_log64(double x) { return futrts_isfinite64(x) || (futrts_isinf64(x) && x < 0)? log(x) : x; }
SCALAR_FUN_ATTR double futrts_log2_64(double x) { return futrts_log64(x)/log(2.0d); }
SCALAR_FUN_ATTR double futrts_log10_64(double x) { return futrts_log64(x)/log(10.0d); }

SCALAR_FUN_ATTR double futrts_log1p_64(double x) {
  if(x == -1.0d || (futrts_isinf64(x) && x > 0.0d)) return x / 0.0d;
  double y = 1.0d + x;
  double z = y - 1.0d;
  return log(y) - (z-x)/y;
}

SCALAR_FUN_ATTR double futrts_sqrt64(double x) { return sqrt(x); }
SCALAR_FUN_ATTR double futrts_rsqrt64(double x) { return 1/sqrt(x); }

SCALAR_FUN_ATTR double futrts_cbrt64(double x) {
  double res;
  foreach_active (i) {
    uniform double r = cbrtf(extract(x, i));
    res = insert(res, i, r);
  }
  return res;
}
SCALAR_FUN_ATTR double futrts_exp64(double x) { return exp(x); }
SCALAR_FUN_ATTR double futrts_cos64(double x) { return cos(x); }
SCALAR_FUN_ATTR double futrts_cospi64(double x) { return cos(M_PI*x); }
SCALAR_FUN_ATTR double futrts_sin64(double x) { return sin(x); }
SCALAR_FUN_ATTR double futrts_sinpi64(double x) { return sin(M_PI*x); }
SCALAR_FUN_ATTR double futrts_tan64(double x) { return tan(x); }
SCALAR_FUN_ATTR double futrts_tanpi64(double x) { return tan(M_PI*x); }
SCALAR_FUN_ATTR double futrts_acos64(double x) { return acos(x); }
SCALAR_FUN_ATTR double futrts_acospi64(double x) { return acos(x)/M_PI; }
SCALAR_FUN_ATTR double futrts_asin64(double x) { return asin(x); }
SCALAR_FUN_ATTR double futrts_asinpi64(double x) { return asin(x)/M_PI; }
SCALAR_FUN_ATTR double futrts_atan64(double x) { return atan(x); }
SCALAR_FUN_ATTR double futrts_atanpi64(double x) { return atan(x)/M_PI; }
SCALAR_FUN_ATTR double futrts_cosh64(double x) { return (exp(x)+exp(-x)) / 2.0d; }
SCALAR_FUN_ATTR double futrts_sinh64(double x) { return (exp(x)-exp(-x)) / 2.0d; }
SCALAR_FUN_ATTR double futrts_tanh64(double x) { return futrts_sinh64(x)/futrts_cosh64(x); }

SCALAR_FUN_ATTR double futrts_acosh64(double x) {
  double f = x+sqrt(x*x-1.0d);
  if(futrts_isfinite64(f)) return log(f);
  return f;
}

SCALAR_FUN_ATTR double futrts_asinh64(double x) {
  double f = x+sqrt(x*x+1.0d);
  if(futrts_isfinite64(f)) return log(f);
  return f;
}

SCALAR_FUN_ATTR double futrts_atanh64(double x) {
  double f = (1.0d+x)/(1.0d-x);
  if(futrts_isfinite64(f)) return log(f)/2.0d;
  return f;
}
SCALAR_FUN_ATTR double futrts_atan2_64(double x, double y) { return atan2(x, y); }

SCALAR_FUN_ATTR double futrts_atan2pi_64(double x, double y) { return atan2(x, y) / M_PI; }

extern "C" unmasked uniform double hypot(uniform double x, uniform double y);
SCALAR_FUN_ATTR double futrts_hypot64(double x, double y) {
  double res;
  foreach_active (i) {
    uniform double r = hypot(extract(x, i), extract(y, i));
    res = insert(res, i, r);
  }
  return res;
}

extern "C" unmasked uniform double tgamma(uniform double x);
SCALAR_FUN_ATTR double futrts_gamma64(double x) {
  double res;
  foreach_active (i) {
    uniform double r = tgamma(extract(x, i));
    res = insert(res, i, r);
  }
  return res;
}

extern "C" unmasked uniform double lgamma(uniform double x);
SCALAR_FUN_ATTR double futrts_lgamma64(double x) {
  double res;
  foreach_active (i) {
    uniform double r = lgamma(extract(x, i));
    res = insert(res, i, r);
  }
  return res;
}

extern "C" unmasked uniform double erf(uniform double x);
SCALAR_FUN_ATTR double futrts_erf64(double x) {
  double res;
  foreach_active (i) {
    uniform double r = erf(extract(x, i));
    res = insert(res, i, r);
  }
  return res;
}

extern "C" unmasked uniform double erfc(uniform double x);
SCALAR_FUN_ATTR double futrts_erfc64(double x) {
  double res;
  foreach_active (i) {
    uniform double r = erfc(extract(x, i));
    res = insert(res, i, r);
  }
  return res;
}

SCALAR_FUN_ATTR double futrts_fma64(double a, double b, double c) { return a * b + c; }
SCALAR_FUN_ATTR double futrts_round64(double x) { return round(x); }
SCALAR_FUN_ATTR double futrts_ceil64(double x) { return ceil(x); }

extern "C" unmasked uniform double nextafter(uniform float x, uniform double y);
SCALAR_FUN_ATTR float futrts_nextafter64(double x, double y) {
  double res;
  foreach_active (i) {
    uniform double r = nextafter(extract(x, i), extract(y, i));
    res = insert(res, i, r);
  }
  return res;
}

SCALAR_FUN_ATTR double futrts_floor64(double x) { return floor(x); }
SCALAR_FUN_ATTR bool futrts_isnan64(double x) { return isnan(x); }

SCALAR_FUN_ATTR int8_t fptosi_f64_i8(double x) {
  if (futrts_isnan64(x) || futrts_isinf64(x)) {
    return 0;
  } else {
    return (int8_t) x;
  }
}

SCALAR_FUN_ATTR int16_t fptosi_f64_i16(double x) {
  if (futrts_isnan64(x) || futrts_isinf64(x)) {
    return 0;
  } else {
    return (int16_t) x;
  }
}

SCALAR_FUN_ATTR int32_t fptosi_f64_i32(double x) {
  if (futrts_isnan64(x) || futrts_isinf64(x)) {
    return 0;
  } else {
    return (int32_t) x;
  }
}

SCALAR_FUN_ATTR int64_t fptosi_f64_i64(double x) {
  if (futrts_isnan64(x) || futrts_isinf64(x)) {
    return 0;
  } else {
    return (int64_t) x;
  }
}

SCALAR_FUN_ATTR uint8_t fptoui_f64_i8(double x) {
  if (futrts_isnan64(x) || futrts_isinf64(x)) {
    return 0;
  } else {
    return (uint8_t) (int8_t) x;
  }
}

SCALAR_FUN_ATTR uint16_t fptoui_f64_i16(double x) {
  if (futrts_isnan64(x) || futrts_isinf64(x)) {
    return 0;
  } else {
    return (uint16_t) (int16_t) x;
  }
}

SCALAR_FUN_ATTR uint32_t fptoui_f64_i32(double x) {
  if (futrts_isnan64(x) || futrts_isinf64(x)) {
    return 0;
  } else {
    return (uint32_t) (int32_t) x;
  }
}

SCALAR_FUN_ATTR uint64_t fptoui_f64_i64(double x) {
  if (futrts_isnan64(x) || futrts_isinf64(x)) {
    return 0;
  } else {
    return (uint64_t) (int64_t) x;
  }
}

SCALAR_FUN_ATTR bool ftob_f64_bool(double x) { return x != 0.0; }
SCALAR_FUN_ATTR double btof_bool_f64(bool x) { return x ? 1.0 : 0.0; }

SCALAR_FUN_ATTR int64_t fptobits_f64_i64(double x) {
  int64_t res;
  foreach_active (i) {
    uniform double tmp = extract(x, i);
    uniform int64_t r = *((uniform int64_t* uniform)&tmp);
    res = insert(res, i, r);
  }
  return res;
}

SCALAR_FUN_ATTR double bitstofp_i64_f64(int64_t x) {
  double res;
  foreach_active (i) {
    uniform int64_t tmp = extract(x, i);
    uniform double r = *((uniform double* uniform)&tmp);
    res = insert(res, i, r);
  }
  return res;
}

SCALAR_FUN_ATTR uniform int64_t fptobits_f64_i64(uniform double x) {
  return intbits(x);
}

SCALAR_FUN_ATTR uniform double bitstofp_i64_f64(uniform int64_t x) {
  return doublebits(x);
}

SCALAR_FUN_ATTR double fmod64(double x, double y) {
  return x - y * trunc(x/y);
}

SCALAR_FUN_ATTR double fsignum64(double x) {
  return futrts_isnan64(x) ? x : (x > 0 ? 1.0d : 0.0d) - (x < 0 ? 1.0d : 0.0d);
}

SCALAR_FUN_ATTR double futrts_lerp64(double v0, double v1, double t) {
  return v0 + (v1 - v0) * t;
}

SCALAR_FUN_ATTR double futrts_ldexp64(double x, int32_t y) {
  return x * pow((uniform double)2.0, (double)y);
}

SCALAR_FUN_ATTR double futrts_copysign64(double x, double y) {
  int64_t xb = fptobits_f64_i64(x);
  int64_t yb = fptobits_f64_i64(y);
  return bitstofp_i64_f64((xb & ~(((int64_t)1)<<63)) | (yb & (((int64_t)1)<<63)));
}

SCALAR_FUN_ATTR double futrts_mad64(double a, double b, double c) { return a * b + c; }
SCALAR_FUN_ATTR float fpconv_f32_f32(float x) { return (float) x; }
SCALAR_FUN_ATTR double fpconv_f32_f64(float x) { return (double) x; }
SCALAR_FUN_ATTR float fpconv_f64_f32(double x) { return (float) x; }
SCALAR_FUN_ATTR double fpconv_f64_f64(double x) { return (double) x; }

#else

SCALAR_FUN_ATTR double fdiv64(double x, double y) { return x / y; }
SCALAR_FUN_ATTR double fadd64(double x, double y) { return x + y; }
SCALAR_FUN_ATTR double fsub64(double x, double y) { return x - y; }
SCALAR_FUN_ATTR double fmul64(double x, double y) { return x * y; }
SCALAR_FUN_ATTR bool cmplt64(double x, double y) { return x < y; }
SCALAR_FUN_ATTR bool cmple64(double x, double y) { return x <= y; }
SCALAR_FUN_ATTR double sitofp_i8_f64(int8_t x) { return (double) x; }
SCALAR_FUN_ATTR double sitofp_i16_f64(int16_t x) { return (double) x; }
SCALAR_FUN_ATTR double sitofp_i32_f64(int32_t x) { return (double) x; }
SCALAR_FUN_ATTR double sitofp_i64_f64(int64_t x) { return (double) x; }
SCALAR_FUN_ATTR double uitofp_i8_f64(uint8_t x) { return (double) x; }
SCALAR_FUN_ATTR double uitofp_i16_f64(uint16_t x) { return (double) x; }
SCALAR_FUN_ATTR double uitofp_i32_f64(uint32_t x) { return (double) x; }
SCALAR_FUN_ATTR double uitofp_i64_f64(uint64_t x) { return (double) x; }
SCALAR_FUN_ATTR double fabs64(double x) { return fabs(x); }
SCALAR_FUN_ATTR double fmax64(double x, double y) { return fmax(x, y); }
SCALAR_FUN_ATTR double fmin64(double x, double y) { return fmin(x, y); }
SCALAR_FUN_ATTR double fpow64(double x, double y) { return pow(x, y); }
SCALAR_FUN_ATTR double futrts_log64(double x) { return log(x); }
SCALAR_FUN_ATTR double futrts_log2_64(double x) { return log2(x); }
SCALAR_FUN_ATTR double futrts_log10_64(double x) { return log10(x); }
SCALAR_FUN_ATTR double futrts_log1p_64(double x) { return log1p(x); }
SCALAR_FUN_ATTR double futrts_sqrt64(double x) { return sqrt(x); }
SCALAR_FUN_ATTR double futrts_rsqrt64(double x) { return 1/sqrt(x); }
SCALAR_FUN_ATTR double futrts_cbrt64(double x) { return cbrt(x); }
SCALAR_FUN_ATTR double futrts_exp64(double x) { return exp(x); }
SCALAR_FUN_ATTR double futrts_cos64(double x) { return cos(x); }

SCALAR_FUN_ATTR double futrts_cospi64(double x) {
#ifdef __OPENCL_VERSION__
  return cospi(x);
#elif defined(__CUDA_ARCH__)
  return cospi(x);
#else
  return cos(M_PI*x);
#endif
}

SCALAR_FUN_ATTR double futrts_sin64(double x) {
  return sin(x);
}

SCALAR_FUN_ATTR double futrts_sinpi64(double x) {
#ifdef __OPENCL_VERSION__
  return sinpi(x);
#elif defined(__CUDA_ARCH__)
  return sinpi(x);
#else
  return sin(M_PI*x);
#endif
}

SCALAR_FUN_ATTR double futrts_tan64(double x) {
  return tan(x);
}

SCALAR_FUN_ATTR double futrts_tanpi64(double x) {
#ifdef __OPENCL_VERSION__
  return tanpi(x);
#else
  return tan(M_PI*x);
#endif
}

SCALAR_FUN_ATTR double futrts_acos64(double x) {
  return acos(x);
}

SCALAR_FUN_ATTR double futrts_acospi64(double x) {
#ifdef __OPENCL_VERSION__
  return acospi(x);
#else
  return acos(x) / M_PI;
#endif
}

SCALAR_FUN_ATTR double futrts_asin64(double x) {
  return asin(x);
}

SCALAR_FUN_ATTR double futrts_asinpi64(double x) {
#ifdef __OPENCL_VERSION__
  return asinpi(x);
#else
  return asin(x) / M_PI;
#endif
}

SCALAR_FUN_ATTR double futrts_atan64(double x) {
  return atan(x);
}

SCALAR_FUN_ATTR double futrts_atanpi64(double x) {
#ifdef __OPENCL_VERSION__
  return atanpi(x);
#else
  return atan(x) / M_PI;
#endif
}

SCALAR_FUN_ATTR double futrts_cosh64(double x) { return cosh(x); }
SCALAR_FUN_ATTR double futrts_sinh64(double x) { return sinh(x); }
SCALAR_FUN_ATTR double futrts_tanh64(double x) { return tanh(x); }
SCALAR_FUN_ATTR double futrts_acosh64(double x) { return acosh(x); }
SCALAR_FUN_ATTR double futrts_asinh64(double x) { return asinh(x); }
SCALAR_FUN_ATTR double futrts_atanh64(double x) { return atanh(x); }
SCALAR_FUN_ATTR double futrts_atan2_64(double x, double y) { return atan2(x, y); }

SCALAR_FUN_ATTR double futrts_atan2pi_64(double x, double y) {
#ifdef __OPENCL_VERSION__
  return atan2pi(x, y);
#else
  return atan2(x, y) / M_PI;
#endif
}

SCALAR_FUN_ATTR double futrts_hypot64(double x, double y) { return hypot(x, y); }
SCALAR_FUN_ATTR double futrts_gamma64(double x) { return tgamma(x); }
SCALAR_FUN_ATTR double futrts_lgamma64(double x) { return lgamma(x); }
SCALAR_FUN_ATTR double futrts_erf64(double x) { return erf(x); }
SCALAR_FUN_ATTR double futrts_erfc64(double x) { return erfc(x); }
SCALAR_FUN_ATTR double futrts_fma64(double a, double b, double c) { return fma(a, b, c); }
SCALAR_FUN_ATTR double futrts_round64(double x) { return rint(x); }
SCALAR_FUN_ATTR double futrts_ceil64(double x) { return ceil(x); }
SCALAR_FUN_ATTR float futrts_nextafter64(float x, float y) { return nextafter(x, y); }
SCALAR_FUN_ATTR double futrts_floor64(double x) { return floor(x); }
SCALAR_FUN_ATTR bool futrts_isnan64(double x) { return isnan(x); }
SCALAR_FUN_ATTR bool futrts_isinf64(double x) { return isinf(x); }

SCALAR_FUN_ATTR int8_t fptosi_f64_i8(double x) {
  if (futrts_isnan64(x) || futrts_isinf64(x)) {
    return 0;
  } else {
    return (int8_t) x;
  }
}

SCALAR_FUN_ATTR int16_t fptosi_f64_i16(double x) {
  if (futrts_isnan64(x) || futrts_isinf64(x)) {
    return 0;
  } else {
    return (int16_t) x;
  }
}

SCALAR_FUN_ATTR int32_t fptosi_f64_i32(double x) {
  if (futrts_isnan64(x) || futrts_isinf64(x)) {
    return 0;
  } else {
    return (int32_t) x;
  }
}

SCALAR_FUN_ATTR int64_t fptosi_f64_i64(double x) {
  if (futrts_isnan64(x) || futrts_isinf64(x)) {
    return 0;
  } else {
    return (int64_t) x;
  }
}

SCALAR_FUN_ATTR uint8_t fptoui_f64_i8(double x) {
  if (futrts_isnan64(x) || futrts_isinf64(x)) {
    return 0;
  } else {
    return (uint8_t) (int8_t) x;
  }
}

SCALAR_FUN_ATTR uint16_t fptoui_f64_i16(double x) {
  if (futrts_isnan64(x) || futrts_isinf64(x)) {
    return 0;
  } else {
    return (uint16_t) (int16_t) x;
  }
}

SCALAR_FUN_ATTR uint32_t fptoui_f64_i32(double x) {
  if (futrts_isnan64(x) || futrts_isinf64(x)) {
    return 0;
  } else {
    return (uint32_t) (int32_t) x;
  }
}

SCALAR_FUN_ATTR uint64_t fptoui_f64_i64(double x) {
  if (futrts_isnan64(x) || futrts_isinf64(x)) {
    return 0;
  } else {
    return (uint64_t) (int64_t) x;
  }
}

SCALAR_FUN_ATTR bool ftob_f64_bool(double x) { return x != 0; }
SCALAR_FUN_ATTR double btof_bool_f64(bool x) { return x ? 1 : 0; }

SCALAR_FUN_ATTR int64_t fptobits_f64_i64(double x) {
  union {
    double f;
    int64_t t;
  } p;

  p.f = x;
  return p.t;
}

SCALAR_FUN_ATTR double bitstofp_i64_f64(int64_t x) {
  union {
    int64_t f;
    double t;
  } p;

  p.f = x;
  return p.t;
}

SCALAR_FUN_ATTR double fmod64(double x, double y) {
  return fmod(x, y);
}

SCALAR_FUN_ATTR double fsignum64(double x) {
  return futrts_isnan64(x) ? x : (x > 0) - (x < 0);
}

SCALAR_FUN_ATTR double futrts_lerp64(double v0, double v1, double t) {
#ifdef __OPENCL_VERSION__
  return mix(v0, v1, t);
#else
  return v0 + (v1 - v0) * t;
#endif
}

SCALAR_FUN_ATTR double futrts_ldexp64(double x, int32_t y) {
  return ldexp(x, y);
}

SCALAR_FUN_ATTR float futrts_copysign64(double x, double y) {
  return copysign(x, y);
}

SCALAR_FUN_ATTR double futrts_mad64(double a, double b, double c) {
#ifdef __OPENCL_VERSION__
  return mad(a, b, c);
#else
  return a * b + c;
#endif
}

SCALAR_FUN_ATTR float fpconv_f32_f32(float x) { return (float) x; }
SCALAR_FUN_ATTR double fpconv_f32_f64(float x) { return (double) x; }
SCALAR_FUN_ATTR float fpconv_f64_f32(double x) { return (float) x; }
SCALAR_FUN_ATTR double fpconv_f64_f64(double x) { return (double) x; }

#endif

#endif

#define futrts_cond_f16(x,y,z) ((x) ? (y) : (z))
#define futrts_cond_f32(x,y,z) ((x) ? (y) : (z))
#define futrts_cond_f64(x,y,z) ((x) ? (y) : (z))

#define futrts_cond_i8(x,y,z) ((x) ? (y) : (z))
#define futrts_cond_i16(x,y,z) ((x) ? (y) : (z))
#define futrts_cond_i32(x,y,z) ((x) ? (y) : (z))
#define futrts_cond_i64(x,y,z) ((x) ? (y) : (z))

#define futrts_cond_bool(x,y,z) ((x) ? (y) : (z))
#define futrts_cond_unit(x,y,z) ((x) ? (y) : (z))

// End of scalar.h.
// Start of scalar_f16.h.

// Half-precision is emulated if needed (e.g. in straight C) with the
// native type used if possible.  The emulation works by typedef'ing
// 'float' to 'f16', and then implementing all operations on single
// precision.  To cut down on duplication, we use the same code for
// those Futhark functions that require just operators or casts.  The
// in-memory representation for arrays will still be 16 bits even
// under emulation, so the compiler will have to be careful when
// generating reads or writes.

#if !defined(cl_khr_fp16) && !(defined(__CUDA_ARCH__) && __CUDA_ARCH__ >= 600) && !(defined(ISPC))
#define EMULATE_F16
#endif

#if !defined(EMULATE_F16) && defined(__OPENCL_VERSION__)
#pragma OPENCL EXTENSION cl_khr_fp16 : enable
#endif

#ifdef EMULATE_F16

// Note that the half-precision storage format is still 16 bits - the
// compiler will have to be real careful!
typedef float f16;

#elif defined(ISPC)
typedef float16 f16;

#else

#ifdef __CUDA_ARCH__
#include <cuda_fp16.h>
#endif

typedef half f16;

#endif

// Some of these functions convert to single precision because half
// precision versions are not available.
SCALAR_FUN_ATTR f16 fadd16(f16 x, f16 y) { return x + y; }
SCALAR_FUN_ATTR f16 fsub16(f16 x, f16 y) { return x - y; }
SCALAR_FUN_ATTR f16 fmul16(f16 x, f16 y) { return x * y; }
SCALAR_FUN_ATTR bool cmplt16(f16 x, f16 y) { return x < y; }
SCALAR_FUN_ATTR bool cmple16(f16 x, f16 y) { return x <= y; }
SCALAR_FUN_ATTR f16 sitofp_i8_f16(int8_t x) { return (f16) x; }
SCALAR_FUN_ATTR f16 sitofp_i16_f16(int16_t x) { return (f16) x; }
SCALAR_FUN_ATTR f16 sitofp_i32_f16(int32_t x) { return (f16) x; }
SCALAR_FUN_ATTR f16 sitofp_i64_f16(int64_t x) { return (f16) x; }
SCALAR_FUN_ATTR f16 uitofp_i8_f16(uint8_t x) { return (f16) x; }
SCALAR_FUN_ATTR f16 uitofp_i16_f16(uint16_t x) { return (f16) x; }
SCALAR_FUN_ATTR f16 uitofp_i32_f16(uint32_t x) { return (f16) x; }
SCALAR_FUN_ATTR f16 uitofp_i64_f16(uint64_t x) { return (f16) x; }
SCALAR_FUN_ATTR int8_t fptosi_f16_i8(f16 x) { return (int8_t) (float) x; }
SCALAR_FUN_ATTR int16_t fptosi_f16_i16(f16 x) { return (int16_t) x; }
SCALAR_FUN_ATTR int32_t fptosi_f16_i32(f16 x) { return (int32_t) x; }
SCALAR_FUN_ATTR int64_t fptosi_f16_i64(f16 x) { return (int64_t) x; }
SCALAR_FUN_ATTR uint8_t fptoui_f16_i8(f16 x) { return (uint8_t) (float) x; }
SCALAR_FUN_ATTR uint16_t fptoui_f16_i16(f16 x) { return (uint16_t) x; }
SCALAR_FUN_ATTR uint32_t fptoui_f16_i32(f16 x) { return (uint32_t) x; }
SCALAR_FUN_ATTR uint64_t fptoui_f16_i64(f16 x) { return (uint64_t) x; }
SCALAR_FUN_ATTR bool ftob_f16_bool(f16 x) { return x != (f16)0; }
SCALAR_FUN_ATTR f16 btof_bool_f16(bool x) { return x ? 1 : 0; }

#ifndef EMULATE_F16

SCALAR_FUN_ATTR bool futrts_isnan16(f16 x) { return isnan((float)x); }

#ifdef __OPENCL_VERSION__

SCALAR_FUN_ATTR f16 fabs16(f16 x) { return fabs(x); }
SCALAR_FUN_ATTR f16 fmax16(f16 x, f16 y) { return fmax(x, y); }
SCALAR_FUN_ATTR f16 fmin16(f16 x, f16 y) { return fmin(x, y); }
SCALAR_FUN_ATTR f16 fpow16(f16 x, f16 y) { return pow(x, y); }

#elif defined(ISPC)

SCALAR_FUN_ATTR f16 fabs16(f16 x) { return abs(x); }
SCALAR_FUN_ATTR f16 fmax16(f16 x, f16 y) { return futrts_isnan16(x) ? y : futrts_isnan16(y) ? x : max(x, y); }
SCALAR_FUN_ATTR f16 fmin16(f16 x, f16 y) { return futrts_isnan16(x) ? y : futrts_isnan16(y) ? x : min(x, y); }
SCALAR_FUN_ATTR f16 fpow16(f16 x, f16 y) { return pow(x, y); }

#else // Assuming CUDA.

SCALAR_FUN_ATTR f16 fabs16(f16 x) { return fabsf(x); }
SCALAR_FUN_ATTR f16 fmax16(f16 x, f16 y) { return fmaxf(x, y); }
SCALAR_FUN_ATTR f16 fmin16(f16 x, f16 y) { return fminf(x, y); }
SCALAR_FUN_ATTR f16 fpow16(f16 x, f16 y) { return powf(x, y); }

#endif

#if defined(ISPC)
SCALAR_FUN_ATTR bool futrts_isinf16(float x) { return !futrts_isnan16(x) && futrts_isnan16(x - x); }
SCALAR_FUN_ATTR bool futrts_isfinite16(float x) { return !futrts_isnan16(x) && !futrts_isinf16(x); }
#else
SCALAR_FUN_ATTR bool futrts_isinf16(f16 x) { return isinf((float)x); }
#endif

#ifdef __OPENCL_VERSION__
SCALAR_FUN_ATTR f16 futrts_log16(f16 x) { return log(x); }
SCALAR_FUN_ATTR f16 futrts_log2_16(f16 x) { return log2(x); }
SCALAR_FUN_ATTR f16 futrts_log10_16(f16 x) { return log10(x); }
SCALAR_FUN_ATTR f16 futrts_log1p_16(f16 x) { return log1p(x); }
SCALAR_FUN_ATTR f16 futrts_sqrt16(f16 x) { return sqrt(x); }
SCALAR_FUN_ATTR f16 futrts_rsqrt16(f16 x) { return rsqrt(x); }
SCALAR_FUN_ATTR f16 futrts_cbrt16(f16 x) { return cbrt(x); }
SCALAR_FUN_ATTR f16 futrts_exp16(f16 x) { return exp(x); }
SCALAR_FUN_ATTR f16 futrts_cos16(f16 x) { return cos(x); }
SCALAR_FUN_ATTR f16 futrts_cospi16(f16 x) { return cospi(x); }
SCALAR_FUN_ATTR f16 futrts_sin16(f16 x) { return sin(x); }
SCALAR_FUN_ATTR f16 futrts_sinpi16(f16 x) { return sinpi(x); }
SCALAR_FUN_ATTR f16 futrts_tan16(f16 x) { return tan(x); }
SCALAR_FUN_ATTR f16 futrts_tanpi16(f16 x) { return tanpi(x); }
SCALAR_FUN_ATTR f16 futrts_acos16(f16 x) { return acos(x); }
SCALAR_FUN_ATTR f16 futrts_acospi16(f16 x) { return acospi(x); }
SCALAR_FUN_ATTR f16 futrts_asin16(f16 x) { return asin(x); }
SCALAR_FUN_ATTR f16 futrts_asinpi16(f16 x) { return asinpi(x); }
SCALAR_FUN_ATTR f16 futrts_atan16(f16 x) { return atan(x); }
SCALAR_FUN_ATTR f16 futrts_atanpi16(f16 x) { return atanpi(x); }
SCALAR_FUN_ATTR f16 futrts_cosh16(f16 x) { return cosh(x); }
SCALAR_FUN_ATTR f16 futrts_sinh16(f16 x) { return sinh(x); }
SCALAR_FUN_ATTR f16 futrts_tanh16(f16 x) { return tanh(x); }
SCALAR_FUN_ATTR f16 futrts_acosh16(f16 x) { return acosh(x); }
SCALAR_FUN_ATTR f16 futrts_asinh16(f16 x) { return asinh(x); }
SCALAR_FUN_ATTR f16 futrts_atanh16(f16 x) { return atanh(x); }
SCALAR_FUN_ATTR f16 futrts_atan2_16(f16 x, f16 y) { return atan2(x, y); }
SCALAR_FUN_ATTR f16 futrts_atan2pi_16(f16 x, f16 y) { return atan2pi(x, y); }
SCALAR_FUN_ATTR f16 futrts_hypot16(f16 x, f16 y) { return hypot(x, y); }
SCALAR_FUN_ATTR f16 futrts_gamma16(f16 x) { return tgamma(x); }
SCALAR_FUN_ATTR f16 futrts_lgamma16(f16 x) { return lgamma(x); }
SCALAR_FUN_ATTR f16 futrts_erf16(f16 x) { return erf(x); }
SCALAR_FUN_ATTR f16 futrts_erfc16(f16 x) { return erfc(x); }
SCALAR_FUN_ATTR f16 fmod16(f16 x, f16 y) { return fmod(x, y); }
SCALAR_FUN_ATTR f16 futrts_round16(f16 x) { return rint(x); }
SCALAR_FUN_ATTR f16 futrts_floor16(f16 x) { return floor(x); }
SCALAR_FUN_ATTR f16 futrts_ceil16(f16 x) { return ceil(x); }
SCALAR_FUN_ATTR f16 futrts_nextafter16(f16 x, f16 y) { return nextafter(x, y); }
SCALAR_FUN_ATTR f16 futrts_lerp16(f16 v0, f16 v1, f16 t) { return mix(v0, v1, t); }
SCALAR_FUN_ATTR f16 futrts_ldexp16(f16 x, int32_t y) { return ldexp(x, y); }
SCALAR_FUN_ATTR f16 futrts_copysign16(f16 x, f16 y) { return copysign(x, y); }
SCALAR_FUN_ATTR f16 futrts_mad16(f16 a, f16 b, f16 c) { return mad(a, b, c); }
SCALAR_FUN_ATTR f16 futrts_fma16(f16 a, f16 b, f16 c) { return fma(a, b, c); }

#elif defined(ISPC)

SCALAR_FUN_ATTR f16 futrts_log16(f16 x) { return futrts_isfinite16(x) || (futrts_isinf16(x) && x < 0) ? log(x) : x; }
SCALAR_FUN_ATTR f16 futrts_log2_16(f16 x) { return futrts_log16(x) / log(2.0f16); }
SCALAR_FUN_ATTR f16 futrts_log10_16(f16 x) { return futrts_log16(x) / log(10.0f16); }
SCALAR_FUN_ATTR f16 futrts_log1p_16(f16 x) {
  if(x == -1.0f16 || (futrts_isinf16(x) && x > 0.0f16)) return x / 0.0f16;
  f16 y = 1.0f16 + x;
  f16 z = y - 1.0f16;
  return log(y) - (z-x)/y;
}
SCALAR_FUN_ATTR f16 futrts_sqrt16(f16 x) { return (float16)sqrt((float)x); }
SCALAR_FUN_ATTR f16 futrts_rsqrt16(f16 x) { return (float16)1/sqrt((float)x); }
SCALAR_FUN_ATTR f16 futrts_exp16(f16 x) { return exp(x); }
SCALAR_FUN_ATTR f16 futrts_cos16(f16 x) { return (float16)cos((float)x); }
SCALAR_FUN_ATTR f16 futrts_cospi16(f16 x) { return (float16)cos((float)M_PI*(float)x); }
SCALAR_FUN_ATTR f16 futrts_sin16(f16 x) { return (float16)sin((float)x); }
SCALAR_FUN_ATTR f16 futrts_sinpi16(f16 x) { return (float16)sin((float)M_PI*(float)x); }
SCALAR_FUN_ATTR f16 futrts_tan16(f16 x) { return (float16)tan((float)x); }
SCALAR_FUN_ATTR f16 futrts_tanpi16(f16 x) { return (float16)(tan((float)M_PI*(float)x)); }
SCALAR_FUN_ATTR f16 futrts_acos16(f16 x) { return (float16)acos((float)x); }
SCALAR_FUN_ATTR f16 futrts_acospi16(f16 x) { return (float16)(acos((float)x)/(float)M_PI); }
SCALAR_FUN_ATTR f16 futrts_asin16(f16 x) { return (float16)asin((float)x); }
SCALAR_FUN_ATTR f16 futrts_asinpi16(f16 x) { return (float16)(asin((float)x)/(float)M_PI); }
SCALAR_FUN_ATTR f16 futrts_atan16(f16 x) { return (float16)atan((float)x); }
SCALAR_FUN_ATTR f16 futrts_atanpi16(f16 x) { return (float16)(atan((float)x)/(float)M_PI); }
SCALAR_FUN_ATTR f16 futrts_cosh16(f16 x) { return (exp(x)+exp(-x)) / 2.0f16; }
SCALAR_FUN_ATTR f16 futrts_sinh16(f16 x) { return (exp(x)-exp(-x)) / 2.0f16; }
SCALAR_FUN_ATTR f16 futrts_tanh16(f16 x) { return futrts_sinh16(x)/futrts_cosh16(x); }
SCALAR_FUN_ATTR f16 futrts_acosh16(f16 x) {
  float16 f = x+(float16)sqrt((float)(x*x-1));
  if(futrts_isfinite16(f)) return log(f);
  return f;
}
SCALAR_FUN_ATTR f16 futrts_asinh16(f16 x) {
  float16 f = x+(float16)sqrt((float)(x*x+1));
  if(futrts_isfinite16(f)) return log(f);
  return f;
}
SCALAR_FUN_ATTR f16 futrts_atanh16(f16 x) {
  float16 f = (1+x)/(1-x);
  if(futrts_isfinite16(f)) return log(f)/2.0f16;
  return f;
}
SCALAR_FUN_ATTR f16 futrts_atan2_16(f16 x, f16 y) { return (float16)atan2((float)x, (float)y); }
SCALAR_FUN_ATTR f16 futrts_atan2pi_16(f16 x, f16 y) { return (float16)(atan2((float)x, (float)y)/(float)M_PI); }
SCALAR_FUN_ATTR f16 futrts_hypot16(f16 x, f16 y) { return (float16)futrts_hypot32((float)x, (float)y); }

extern "C" unmasked uniform float tgammaf(uniform float x);
SCALAR_FUN_ATTR f16 futrts_gamma16(f16 x) {
  f16 res;
  foreach_active (i) {
    uniform f16 r = (f16)tgammaf(extract((float)x, i));
    res = insert(res, i, r);
  }
  return res;
}

extern "C" unmasked uniform float lgammaf(uniform float x);
SCALAR_FUN_ATTR f16 futrts_lgamma16(f16 x) {
  f16 res;
  foreach_active (i) {
    uniform f16 r = (f16)lgammaf(extract((float)x, i));
    res = insert(res, i, r);
  }
  return res;
}
SCALAR_FUN_ATTR f16 futrts_cbrt16(f16 x) { return (f16)futrts_cbrt32((float)x); }
SCALAR_FUN_ATTR f16 futrts_erf16(f16 x) { return (f16)futrts_erf32((float)x); }
SCALAR_FUN_ATTR f16 futrts_erfc16(f16 x) { return (f16)futrts_erfc32((float)x); }
SCALAR_FUN_ATTR f16 fmod16(f16 x, f16 y) { return x - y * (float16)trunc((float) (x/y)); }
SCALAR_FUN_ATTR f16 futrts_round16(f16 x) { return (float16)round((float)x); }
SCALAR_FUN_ATTR f16 futrts_floor16(f16 x) { return (float16)floor((float)x); }
SCALAR_FUN_ATTR f16 futrts_ceil16(f16 x) { return (float16)ceil((float)x); }
SCALAR_FUN_ATTR f16 futrts_nextafter16(f16 x, f16 y) { return (float16)futrts_nextafter32((float)x, (float) y); }
SCALAR_FUN_ATTR f16 futrts_lerp16(f16 v0, f16 v1, f16 t) { return v0 + (v1 - v0) * t; }
SCALAR_FUN_ATTR f16 futrts_ldexp16(f16 x, int32_t y) { return futrts_ldexp32((float)x, y); }
SCALAR_FUN_ATTR f16 futrts_copysign16(f16 x, f16 y) { return futrts_copysign32((float)x, y); }
SCALAR_FUN_ATTR f16 futrts_mad16(f16 a, f16 b, f16 c) { return a * b + c; }
SCALAR_FUN_ATTR f16 futrts_fma16(f16 a, f16 b, f16 c) { return a * b + c; }

#else // Assume CUDA.

SCALAR_FUN_ATTR f16 futrts_log16(f16 x) { return hlog(x); }
SCALAR_FUN_ATTR f16 futrts_log2_16(f16 x) { return hlog2(x); }
SCALAR_FUN_ATTR f16 futrts_log10_16(f16 x) { return hlog10(x); }
SCALAR_FUN_ATTR f16 futrts_log1p_16(f16 x) { return (f16)log1pf((float)x); }
SCALAR_FUN_ATTR f16 futrts_sqrt16(f16 x) { return hsqrt(x); }
SCALAR_FUN_ATTR f16 futrts_rsqrt16(f16 x) { return hrsqrt(x); }
SCALAR_FUN_ATTR f16 futrts_cbrt16(f16 x) { return cbrtf(x); }
SCALAR_FUN_ATTR f16 futrts_exp16(f16 x) { return hexp(x); }
SCALAR_FUN_ATTR f16 futrts_cos16(f16 x) { return hcos(x); }
SCALAR_FUN_ATTR f16 futrts_cospi16(f16 x) { return hcos((f16)M_PI*x); }
SCALAR_FUN_ATTR f16 futrts_sin16(f16 x) { return hsin(x); }
SCALAR_FUN_ATTR f16 futrts_sinpi16(f16 x) { return hsin((f16)M_PI*x); }
SCALAR_FUN_ATTR f16 futrts_tan16(f16 x) { return tanf(x); }
SCALAR_FUN_ATTR f16 futrts_tanpi16(f16 x) { return tanf((f16)M_PI*x); }
SCALAR_FUN_ATTR f16 futrts_acos16(f16 x) { return acosf(x); }
SCALAR_FUN_ATTR f16 futrts_acospi16(f16 x) { return (f16)acosf(x)/(f16)M_PI; }
SCALAR_FUN_ATTR f16 futrts_asin16(f16 x) { return asinf(x); }
SCALAR_FUN_ATTR f16 futrts_asinpi16(f16 x) { return (f16)asinf(x)/(f16)M_PI; }
SCALAR_FUN_ATTR f16 futrts_atan16(f16 x) { return (f16)atanf(x); }
SCALAR_FUN_ATTR f16 futrts_atanpi16(f16 x) { return (f16)atanf(x)/(f16)M_PI; }
SCALAR_FUN_ATTR f16 futrts_cosh16(f16 x) { return coshf(x); }
SCALAR_FUN_ATTR f16 futrts_sinh16(f16 x) { return sinhf(x); }
SCALAR_FUN_ATTR f16 futrts_tanh16(f16 x) { return tanhf(x); }
SCALAR_FUN_ATTR f16 futrts_acosh16(f16 x) { return acoshf(x); }
SCALAR_FUN_ATTR f16 futrts_asinh16(f16 x) { return asinhf(x); }
SCALAR_FUN_ATTR f16 futrts_atanh16(f16 x) { return atanhf(x); }
SCALAR_FUN_ATTR f16 futrts_atan2_16(f16 x, f16 y) { return (f16)atan2f(x, y); }
SCALAR_FUN_ATTR f16 futrts_atan2pi_16(f16 x, f16 y) { return (f16)atan2f(x, y)/(f16)M_PI; }
SCALAR_FUN_ATTR f16 futrts_hypot16(f16 x, f16 y) { return hypotf(x, y); }
SCALAR_FUN_ATTR f16 futrts_gamma16(f16 x) { return tgammaf(x); }
SCALAR_FUN_ATTR f16 futrts_lgamma16(f16 x) { return lgammaf(x); }
SCALAR_FUN_ATTR f16 futrts_erf16(f16 x) { return erff(x); }
SCALAR_FUN_ATTR f16 futrts_erfc16(f16 x) { return erfcf(x); }
SCALAR_FUN_ATTR f16 fmod16(f16 x, f16 y) { return fmodf(x, y); }
SCALAR_FUN_ATTR f16 futrts_round16(f16 x) { return rintf(x); }
SCALAR_FUN_ATTR f16 futrts_floor16(f16 x) { return hfloor(x); }
SCALAR_FUN_ATTR f16 futrts_ceil16(f16 x) { return hceil(x); }
SCALAR_FUN_ATTR f16 futrts_nextafter16(f16 x, f16 y) { return __ushort_as_half(halfbitsnextafter(__half_as_ushort(x), __half_as_ushort(y))); }
SCALAR_FUN_ATTR f16 futrts_lerp16(f16 v0, f16 v1, f16 t) { return v0 + (v1 - v0) * t; }
SCALAR_FUN_ATTR f16 futrts_ldexp16(f16 x, int32_t y) { return futrts_ldexp32((float)x, y); }
SCALAR_FUN_ATTR f16 futrts_copysign16(f16 x, f16 y) { return futrts_copysign32((float)x, y); }
SCALAR_FUN_ATTR f16 futrts_mad16(f16 a, f16 b, f16 c) { return a * b + c; }
SCALAR_FUN_ATTR f16 futrts_fma16(f16 a, f16 b, f16 c) { return fmaf(a, b, c); }

#endif

// The CUDA __half type cannot be put in unions for some reason, so we
// use bespoke conversion functions instead.
#ifdef __CUDA_ARCH__
SCALAR_FUN_ATTR int16_t fptobits_f16_i16(f16 x) { return __half_as_ushort(x); }
SCALAR_FUN_ATTR f16 bitstofp_i16_f16(int16_t x) { return __ushort_as_half(x); }
#elif defined(ISPC)
SCALAR_FUN_ATTR int16_t fptobits_f16_i16(f16 x) { varying int16_t y = *((varying int16_t * uniform)&x); return y;
}
SCALAR_FUN_ATTR f16 bitstofp_i16_f16(int16_t x) { varying f16 y = *((varying f16 * uniform)&x); return y; }
#else
SCALAR_FUN_ATTR int16_t fptobits_f16_i16(f16 x) {
  union {
    f16 f;
    int16_t t;
  } p;

  p.f = x;
  return p.t;
}

SCALAR_FUN_ATTR f16 bitstofp_i16_f16(int16_t x) {
  union {
    int16_t f;
    f16 t;
  } p;

  p.f = x;
  return p.t;
}
#endif

#else // No native f16 - emulate.

SCALAR_FUN_ATTR f16 fabs16(f16 x) { return fabs32(x); }
SCALAR_FUN_ATTR f16 fmax16(f16 x, f16 y) { return fmax32(x, y); }
SCALAR_FUN_ATTR f16 fmin16(f16 x, f16 y) { return fmin32(x, y); }
SCALAR_FUN_ATTR f16 fpow16(f16 x, f16 y) { return fpow32(x, y); }
SCALAR_FUN_ATTR bool futrts_isnan16(f16 x) { return futrts_isnan32(x); }
SCALAR_FUN_ATTR bool futrts_isinf16(f16 x) { return futrts_isinf32(x); }
SCALAR_FUN_ATTR f16 futrts_log16(f16 x) { return futrts_log32(x); }
SCALAR_FUN_ATTR f16 futrts_log2_16(f16 x) { return futrts_log2_32(x); }
SCALAR_FUN_ATTR f16 futrts_log10_16(f16 x) { return futrts_log10_32(x); }
SCALAR_FUN_ATTR f16 futrts_log1p_16(f16 x) { return futrts_log1p_32(x); }
SCALAR_FUN_ATTR f16 futrts_sqrt16(f16 x) { return futrts_sqrt32(x); }
SCALAR_FUN_ATTR f16 futrts_rsqrt16(f16 x) { return futrts_rsqrt32(x); }
SCALAR_FUN_ATTR f16 futrts_cbrt16(f16 x) { return futrts_cbrt32(x); }
SCALAR_FUN_ATTR f16 futrts_exp16(f16 x) { return futrts_exp32(x); }
SCALAR_FUN_ATTR f16 futrts_cos16(f16 x) { return futrts_cos32(x); }
SCALAR_FUN_ATTR f16 futrts_cospi16(f16 x) { return futrts_cospi32(x); }
SCALAR_FUN_ATTR f16 futrts_sin16(f16 x) { return futrts_sin32(x); }
SCALAR_FUN_ATTR f16 futrts_sinpi16(f16 x) { return futrts_sinpi32(x); }
SCALAR_FUN_ATTR f16 futrts_tan16(f16 x) { return futrts_tan32(x); }
SCALAR_FUN_ATTR f16 futrts_tanpi16(f16 x) { return futrts_tanpi32(x); }
SCALAR_FUN_ATTR f16 futrts_acos16(f16 x) { return futrts_acos32(x); }
SCALAR_FUN_ATTR f16 futrts_acospi16(f16 x) { return futrts_acospi32(x); }
SCALAR_FUN_ATTR f16 futrts_asin16(f16 x) { return futrts_asin32(x); }
SCALAR_FUN_ATTR f16 futrts_asinpi16(f16 x) { return futrts_asinpi32(x); }
SCALAR_FUN_ATTR f16 futrts_atan16(f16 x) { return futrts_atan32(x); }
SCALAR_FUN_ATTR f16 futrts_atanpi16(f16 x) { return futrts_atanpi32(x); }
SCALAR_FUN_ATTR f16 futrts_cosh16(f16 x) { return futrts_cosh32(x); }
SCALAR_FUN_ATTR f16 futrts_sinh16(f16 x) { return futrts_sinh32(x); }
SCALAR_FUN_ATTR f16 futrts_tanh16(f16 x) { return futrts_tanh32(x); }
SCALAR_FUN_ATTR f16 futrts_acosh16(f16 x) { return futrts_acosh32(x); }
SCALAR_FUN_ATTR f16 futrts_asinh16(f16 x) { return futrts_asinh32(x); }
SCALAR_FUN_ATTR f16 futrts_atanh16(f16 x) { return futrts_atanh32(x); }
SCALAR_FUN_ATTR f16 futrts_atan2_16(f16 x, f16 y) { return futrts_atan2_32(x, y); }
SCALAR_FUN_ATTR f16 futrts_atan2pi_16(f16 x, f16 y) { return futrts_atan2pi_32(x, y); }
SCALAR_FUN_ATTR f16 futrts_hypot16(f16 x, f16 y) { return futrts_hypot32(x, y); }
SCALAR_FUN_ATTR f16 futrts_gamma16(f16 x) { return futrts_gamma32(x); }
SCALAR_FUN_ATTR f16 futrts_lgamma16(f16 x) { return futrts_lgamma32(x); }
SCALAR_FUN_ATTR f16 futrts_erf16(f16 x) { return futrts_erf32(x); }
SCALAR_FUN_ATTR f16 futrts_erfc16(f16 x) { return futrts_erfc32(x); }
SCALAR_FUN_ATTR f16 fmod16(f16 x, f16 y) { return fmod32(x, y); }
SCALAR_FUN_ATTR f16 futrts_round16(f16 x) { return futrts_round32(x); }
SCALAR_FUN_ATTR f16 futrts_floor16(f16 x) { return futrts_floor32(x); }
SCALAR_FUN_ATTR f16 futrts_ceil16(f16 x) { return futrts_ceil32(x); }
SCALAR_FUN_ATTR f16 futrts_nextafter16(f16 x, f16 y) { return halfbits2float(halfbitsnextafter(float2halfbits(x), float2halfbits(y))); }
SCALAR_FUN_ATTR f16 futrts_lerp16(f16 v0, f16 v1, f16 t) { return futrts_lerp32(v0, v1, t); }
SCALAR_FUN_ATTR f16 futrts_ldexp16(f16 x, int32_t y) { return futrts_ldexp32(x, y); }
SCALAR_FUN_ATTR f16 futrts_copysign16(f16 x, f16 y) { return futrts_copysign32((float)x, y); }
SCALAR_FUN_ATTR f16 futrts_mad16(f16 a, f16 b, f16 c) { return futrts_mad32(a, b, c); }
SCALAR_FUN_ATTR f16 futrts_fma16(f16 a, f16 b, f16 c) { return futrts_fma32(a, b, c); }

// Even when we are using an OpenCL that does not support cl_khr_fp16,
// it must still support vload_half for actually creating a
// half-precision number, which can then be efficiently converted to a
// float.  Similarly for vstore_half.
#ifdef __OPENCL_VERSION__

SCALAR_FUN_ATTR int16_t fptobits_f16_i16(f16 x) {
  int16_t y;
  // Violating strict aliasing here.
  vstore_half((float)x, 0, (half*)&y);
  return y;
}

SCALAR_FUN_ATTR f16 bitstofp_i16_f16(int16_t x) {
  return (f16)vload_half(0, (half*)&x);
}

#else
SCALAR_FUN_ATTR int16_t fptobits_f16_i16(f16 x) { return (int16_t)float2halfbits(x); }
SCALAR_FUN_ATTR f16 bitstofp_i16_f16(int16_t x) { return halfbits2float((uint16_t)x); }
SCALAR_FUN_ATTR f16 fsignum16(f16 x) { return futrts_isnan16(x) ? x : (x > 0 ? 1 : 0) - (x < 0 ? 1 : 0); }

#endif

#endif

SCALAR_FUN_ATTR float fpconv_f16_f16(f16 x) { return x; }
SCALAR_FUN_ATTR float fpconv_f16_f32(f16 x) { return x; }
SCALAR_FUN_ATTR f16 fpconv_f32_f16(float x) { return (f16) x; }

#ifdef FUTHARK_F64_ENABLED
SCALAR_FUN_ATTR double fpconv_f16_f64(f16 x) { return (double) x; }
#if defined(ISPC)
SCALAR_FUN_ATTR f16 fpconv_f64_f16(double x) { return (f16) ((float)x); }
#else
SCALAR_FUN_ATTR f16 fpconv_f64_f16(double x) { return (f16) x; }
#endif
#endif

// End of scalar_f16.h.

// Start of context_prototypes.h
//
// Prototypes for the functions in context.h, or that will be called
// from those functions, that need to be available very early.

struct futhark_context_config;
struct futhark_context;

static void set_error(struct futhark_context* ctx, char *error);

// These are called in context/config new/free functions and contain
// shared setup.  They are generated by the compiler itself.
static int init_constants(struct futhark_context*);
static int free_constants(struct futhark_context*);
static void setup_program(struct futhark_context* ctx);
static void teardown_program(struct futhark_context *ctx);

// Allocate host memory.  Must be freed with host_free().
static void host_alloc(struct futhark_context* ctx, size_t size, const char* tag, size_t* size_out, void** mem_out);
// Allocate memory allocated with host_alloc().
static void host_free(struct futhark_context* ctx, size_t size, const char* tag, void* mem);

// Log that a copy has occurred. The provenance may be NULL, if we do not know
// where this came from.
static void log_copy(struct futhark_context* ctx,
                     const char *kind, const char *provenance,
                     int r,
                     int64_t dst_offset, int64_t dst_strides[r],
                     int64_t src_offset, int64_t src_strides[r],
                     int64_t shape[r]);

static void log_transpose(struct futhark_context* ctx,
                          int64_t k, int64_t m, int64_t n);

static bool lmad_map_tr(int64_t *num_arrays_out, int64_t *n_out, int64_t *m_out,
                        int r,
                        const int64_t dst_strides[r],
                        const int64_t src_strides[r],
                        const int64_t shape[r]);

static bool lmad_contiguous(int r, int64_t strides[r], int64_t shape[r]);

static bool lmad_memcpyable(int r,
                            int64_t dst_strides[r], int64_t src_strides[r], int64_t shape[r]);

static void add_event(struct futhark_context* ctx,
                      const char* name,
                      const char* provenance,
                      struct kvs *kvs,
                      void* data,
                      event_report_fn f);

// Functions that must be defined by the backend.
static void backend_context_config_setup(struct futhark_context_config* cfg);
static void backend_context_config_teardown(struct futhark_context_config* cfg);
static int backend_context_setup(struct futhark_context *ctx);
static void backend_context_teardown(struct futhark_context *ctx);

// End of of context_prototypes.h

struct memblock {
    int *references;
    unsigned char *mem;
    int64_t size;
    const char *desc;
};
struct constants {
    int dummy;
    bool ok_11754;
    bool ok_11838;
    bool x_16121;
    bool x_16124;
    bool x_16130;
    bool x_16136;
};
static int64_t static_array_realtype_22784[6] = { (int64_t) 0,(int64_t) 1,(int64_t) 2,(int64_t) 4,(int64_t) 6,(int64_t) 9};
static int64_t static_array_realtype_22785[6] = { (int64_t) 11,(int64_t) 8,(int64_t) 3,(int64_t) 5,(int64_t) 7,(int64_t) 10};
static bool static_array_realtype_22786[6] = { 0,1,0,0,0,0};
static int64_t static_array_realtype_22787[4] = { (int64_t) 1,(int64_t) 2,(int64_t) 3,(int64_t) 4};
static int64_t static_array_realtype_22788[4] = { (int64_t) 0,(int64_t) 1,(int64_t) 3,(int64_t) 5};
static int64_t static_array_realtype_22789[4] = { (int64_t) 7,(int64_t) 2,(int64_t) 4,(int64_t) 6};
static int64_t static_array_realtype_22790[1] = { (int64_t) 0};
static int64_t static_array_realtype_22791[2] = { (int64_t) 0,(int64_t) 5};
static int64_t static_array_realtype_22792[2] = { (int64_t) 0,(int64_t) 1};
static int64_t static_array_realtype_22793[2] = { (int64_t) 3,(int64_t) 2};
static bool static_array_realtype_22794[6] = { 0,0,1,0,0,0};
static bool static_array_realtype_22795[6] = { 0,1,0,0,0,1};
static int64_t static_array_realtype_22796[2] = { (int64_t) 0,(int64_t) 4};
static bool static_array_realtype_22797[6] = { 0,0,0,0,0,0};
static bool static_array_realtype_22798[6] = { 1,1,0,0,0,1};
static int64_t static_array_realtype_22799[3] = { (int64_t) 0,(int64_t) 1,(int64_t) 5};
static int64_t static_array_realtype_22800[4] = { (int64_t) 0,(int64_t) 1,(int64_t) 3,(int64_t) 4};
static int64_t static_array_realtype_22801[4] = { (int64_t) 7,(int64_t) 2,(int64_t) 6,(int64_t) 5};
static int64_t static_array_realtype_22802[4] = { (int64_t) 0,(int64_t) 1,(int64_t) 2,(int64_t) 3};
static int64_t static_array_realtype_22803[5] = { (int64_t) 0,(int64_t) 1,(int64_t) 0,(int64_t) 1,(int64_t) 3};
static int64_t static_array_realtype_22804[5] = { (int64_t) 3,(int64_t) 2,(int64_t) 5,(int64_t) 2,(int64_t) 4};
static int64_t static_array_realtype_22805[5] = { (int64_t) 4,(int64_t) 5,(int64_t) 6,(int64_t) 7,(int64_t) 8};
static int64_t static_array_realtype_22806[2] = { (int64_t) 0,(int64_t) 2};
static int64_t static_array_realtype_22807[4] = { (int64_t) 0,(int64_t) 1,(int64_t) 0,(int64_t) -1};
static int64_t static_array_realtype_22808[11] = { (int64_t) 0,(int64_t) 1,(int64_t) 2,(int64_t) 5,(int64_t) 6,(int64_t) 7,(int64_t) 9,(int64_t) 13,(int64_t) 14,(int64_t) 15,(int64_t) 18};
static int64_t static_array_realtype_22809[11] = { (int64_t) 21,(int64_t) 4,(int64_t) 3,(int64_t) 12,(int64_t) 11,(int64_t) 8,(int64_t) 10,(int64_t) 20,(int64_t) 17,(int64_t) 16,(int64_t) 19};
static int64_t static_array_realtype_22810[11] = { (int64_t) 0,(int64_t) 4,(int64_t) 5,(int64_t) 2,(int64_t) 6,(int64_t) 7,(int64_t) 8,(int64_t) 2,(int64_t) 4,(int64_t) 5,(int64_t) 3};
struct tuning_params {
    int dummy;
};
static const int num_tuning_params = 0;
static const char *tuning_param_names[] = {NULL};
static const char *tuning_param_vars[] = {NULL};
static const char *tuning_param_classes[] = {NULL};
static int64_t tuning_param_defaults[] = {0};
// Start of backends/c.h

struct futhark_context_config {
  int in_use;
  int debugging;
  int profiling;
  int logging;
  char *cache_fname;
  int num_tuning_params;
  int64_t *tuning_params;
  const char** tuning_param_names;
  const char** tuning_param_vars;
  const char** tuning_param_classes;
};

static void backend_context_config_setup(struct futhark_context_config* cfg) {
  (void)cfg;
}

static void backend_context_config_teardown(struct futhark_context_config* cfg) {
  (void)cfg;
}

int futhark_context_config_set_tuning_param(struct futhark_context_config* cfg, const char *param_name, size_t param_value) {
  (void)cfg; (void)param_name; (void)param_value;
  return 1;
}

struct futhark_context {
  struct futhark_context_config* cfg;
  int detail_memory;
  int debugging;
  int profiling;
  int profiling_paused;
  int logging;
  lock_t lock;
  char *error;
  lock_t error_lock;
  FILE *log;
  struct constants *constants;
  struct free_list free_list;
  struct event_list event_list;
  int64_t peak_mem_usage_default;
  int64_t cur_mem_usage_default;
  struct program* program;
  bool program_initialised;
};

int backend_context_setup(struct futhark_context* ctx) {
  (void)ctx;
  return 0;
}

void backend_context_teardown(struct futhark_context* ctx) {
  (void)ctx;
}

int futhark_context_sync(struct futhark_context* ctx) {
  (void)ctx;
  return 0;
}

// End of backends/c.h

struct program {
    int dummy;
};
static void setup_program(struct futhark_context *ctx)
{
    (void) ctx;
    
    int error = 0;
    
    (void) error;
    ctx->program = malloc(sizeof(struct program));
}
static void teardown_program(struct futhark_context *ctx)
{
    (void) ctx;
    
    int error = 0;
    
    (void) error;
    free(ctx->program);
}
static void set_tuning_params(struct futhark_context *ctx)
{
    (void) ctx;
}
int memblock_unref(struct futhark_context *ctx, struct memblock *block, const char *desc)
{
    if (block->references != NULL) {
        *block->references -= 1;
        if (ctx->detail_memory)
            fprintf(ctx->log, "Unreferencing block %s (allocated as %s) in %s: %d references remaining.\n", desc, block->desc, "default space", *block->references);
        if (*block->references == 0) {
            ctx->cur_mem_usage_default -= block->size;
            host_free(ctx, (size_t) block->size, desc, (void *) block->mem);
            free(block->references);
            if (ctx->detail_memory)
                fprintf(ctx->log, "%lld bytes freed (now allocated: %lld bytes)\n", (long long) block->size, (long long) ctx->cur_mem_usage_default);
        }
        block->references = NULL;
    }
    return 0;
}
int memblock_alloc(struct futhark_context *ctx, struct memblock *block, int64_t size, const char *desc)
{
    if (size < 0)
        futhark_panic(1, "Negative allocation of %lld bytes attempted for %s in %s.\n", (long long) size, desc, "default space", ctx->cur_mem_usage_default);
    
    int ret = memblock_unref(ctx, block, desc);
    
    if (ret != FUTHARK_SUCCESS)
        return ret;
    if (ctx->detail_memory)
        fprintf(ctx->log, "Allocating %lld bytes for %s in %s (currently allocated: %lld bytes).\n", (long long) size, desc, "default space", (long long) ctx->cur_mem_usage_default);
    host_alloc(ctx, (size_t) size, desc, (size_t *) &size, (void *) &block->mem);
    if (ctx->error == NULL) {
        block->references = (int *) malloc(sizeof(int));
        *block->references = 1;
        block->size = size;
        block->desc = desc;
        
        long long new_usage = ctx->cur_mem_usage_default + size;
        
        if (ctx->detail_memory)
            fprintf(ctx->log, "Received block of %lld bytes; now allocated: %lld bytes", (long long) block->size, new_usage);
        ctx->cur_mem_usage_default = new_usage;
        if (new_usage > ctx->peak_mem_usage_default) {
            ctx->peak_mem_usage_default = new_usage;
            if (ctx->detail_memory)
                fprintf(ctx->log, " (new peak).\n");
        } else if (ctx->detail_memory)
            fprintf(ctx->log, ".\n");
        return FUTHARK_SUCCESS;
    } else {
        // We are naively assuming that any memory allocation error is due to OOM.
        lock_lock(&ctx->error_lock);
        
        char *old_error = ctx->error;
        
        ctx->error = msgprintf("Failed to allocate memory in %s.\nAttempted allocation: %12lld bytes\nCurrently allocated:  %12lld bytes\n%s", "default space", (long long) size, (long long) ctx->cur_mem_usage_default, old_error);
        free(old_error);
        lock_unlock(&ctx->error_lock);
        return FUTHARK_OUT_OF_MEMORY;
    }
}
int memblock_set(struct futhark_context *ctx, struct memblock *lhs, struct memblock *rhs, const char *lhs_desc)
{
    int ret = memblock_unref(ctx, lhs, lhs_desc);
    
    if (rhs->references != NULL)
        (*rhs->references)++;
    *lhs = *rhs;
    return ret;
}
char *futhark_context_report(struct futhark_context *ctx)
{
    if (futhark_context_sync(ctx) != 0)
        return NULL;
    
    struct str_builder builder;
    
    str_builder_init(&builder);
    str_builder_char(&builder, '{');
    str_builder_str(&builder, "\"memory\":{");
    str_builder(&builder, "\"default space\": %lld", (long long) ctx->peak_mem_usage_default);
    str_builder_str(&builder, "},\"events\":[");
    if (report_events_in_list(&ctx->event_list, &builder) != 0) {
        free(builder.str);
        return NULL;
    } else {
        str_builder_str(&builder, "]}");
        return builder.str;
    }
}
int futhark_context_clear_caches(struct futhark_context *ctx)
{
    lock_lock(&ctx->lock);
    ctx->peak_mem_usage_default = 0;
    lock_unlock(&ctx->lock);
    return ctx->error != NULL;
}

// Start of context.h

// Internal functions.

static void set_error(struct futhark_context* ctx, char *error) {
  lock_lock(&ctx->error_lock);
  if (ctx->error == NULL) {
    ctx->error = error;
  } else {
    free(error);
  }
  lock_unlock(&ctx->error_lock);
}

// XXX: should be static, but used in ispc_util.h
void lexical_realloc_error(struct futhark_context* ctx, size_t new_size) {
  set_error(ctx,
            msgprintf("Failed to allocate memory.\nAttempted allocation: %12lld bytes\n",
                      (long long) new_size));
}

static int lexical_realloc(struct futhark_context *ctx,
                           unsigned char **ptr,
                           int64_t *old_size,
                           int64_t new_size) {
  unsigned char *new = realloc(*ptr, (size_t)new_size);
  if (new == NULL) {
    lexical_realloc_error(ctx, new_size);
    return FUTHARK_OUT_OF_MEMORY;
  } else {
    *ptr = new;
    *old_size = new_size;
    return FUTHARK_SUCCESS;
  }
}

static void free_all_in_free_list(struct futhark_context* ctx) {
  fl_mem mem;
  free_list_pack(&ctx->free_list);
  while (free_list_first(&ctx->free_list, (fl_mem*)&mem) == 0) {
    free((void*)mem);
  }
}

static int is_small_alloc(size_t size) {
  return size < 1024*1024;
}

static void host_alloc(struct futhark_context* ctx,
                       size_t size, const char* tag, size_t* size_out, void** mem_out) {
  if (is_small_alloc(size) || free_list_find(&ctx->free_list, size, tag, size_out, (fl_mem*)mem_out) != 0) {
    *size_out = size;
    *mem_out = malloc(size);
  }
}

static void host_free(struct futhark_context* ctx,
                      size_t size, const char* tag, void* mem) {
  // Small allocations are handled by malloc()s own free list.  The
  // threshold here is kind of arbitrary, but seems to work OK.
  // Larger allocations are mmap()ed/munmapped() every time, which is
  // very slow, and Futhark programs tend to use a few very large
  // allocations.
  if (is_small_alloc(size)) {
    free(mem);
  } else {
    free_list_insert(&ctx->free_list, size, (fl_mem)mem, tag);
  }
}

static void add_event(struct futhark_context* ctx,
                      const char* name,
                      const char* provenance,
                      struct kvs *kvs,
                      void* data,
                      event_report_fn f) {
  if (provenance == NULL) {
    provenance = "unknown";
  }
  if (ctx->logging) {
    fprintf(ctx->log, "Event: %s\n  at: %s\n", name, provenance);
    if (kvs) {
      kvs_log(kvs, "  ", ctx->log);
    }
  }
  add_event_to_list(&ctx->event_list, name, provenance, kvs, data, f);
}

char *futhark_context_get_error(struct futhark_context *ctx) {
  char *error = ctx->error;
  ctx->error = NULL;
  return error;
}

void futhark_context_config_set_debugging(struct futhark_context_config *cfg, int flag) {
    cfg->profiling = cfg->logging = cfg->debugging = flag;
}

void futhark_context_config_set_profiling(struct futhark_context_config *cfg, int flag) {
    cfg->profiling = flag;
}

void futhark_context_config_set_logging(struct futhark_context_config *cfg, int flag) {
    cfg->logging = flag;
}

void futhark_context_config_set_cache_file(struct futhark_context_config *cfg, const char *f) {
  cfg->cache_fname = strdup(f);
}

int futhark_get_tuning_param_count(void) {
  return num_tuning_params;
}

const char *futhark_get_tuning_param_name(int i) {
  return tuning_param_names[i];
}

const char *futhark_get_tuning_param_class(int i) {
    return tuning_param_classes[i];
}

void futhark_context_set_logging_file(struct futhark_context *ctx, FILE *f){
  ctx->log = f;
}

void futhark_context_pause_profiling(struct futhark_context *ctx) {
  ctx->profiling_paused = 1;
}

void futhark_context_unpause_profiling(struct futhark_context *ctx) {
  ctx->profiling_paused = 0;
}

struct futhark_context_config* futhark_context_config_new(void) {
  struct futhark_context_config* cfg = malloc(sizeof(struct futhark_context_config));
  if (cfg == NULL) {
    return NULL;
  }
  cfg->in_use = 0;
  cfg->debugging = 0;
  cfg->profiling = 0;
  cfg->logging = 0;
  cfg->cache_fname = NULL;
  cfg->num_tuning_params = num_tuning_params;
  cfg->tuning_params = malloc(cfg->num_tuning_params * sizeof(int64_t));
  memcpy(cfg->tuning_params, tuning_param_defaults,
         cfg->num_tuning_params * sizeof(int64_t));
  cfg->tuning_param_names = tuning_param_names;
  cfg->tuning_param_vars = tuning_param_vars;
  cfg->tuning_param_classes = tuning_param_classes;
  backend_context_config_setup(cfg);
  return cfg;
}

void futhark_context_config_free(struct futhark_context_config* cfg) {
  assert(!cfg->in_use);
  backend_context_config_teardown(cfg);
  free(cfg->cache_fname);
  free(cfg->tuning_params);
  free(cfg);
}

struct futhark_context* futhark_context_new(struct futhark_context_config* cfg) {
  struct futhark_context* ctx = malloc(sizeof(struct futhark_context));
  if (ctx == NULL) {
    return NULL;
  }
  assert(!cfg->in_use);
  ctx->cfg = cfg;
  ctx->cfg->in_use = 1;
  ctx->program_initialised = false;
  create_lock(&ctx->error_lock);
  create_lock(&ctx->lock);
  free_list_init(&ctx->free_list);
  event_list_init(&ctx->event_list);
  ctx->peak_mem_usage_default = 0;
  ctx->cur_mem_usage_default = 0;
  ctx->constants = malloc(sizeof(struct constants));
  ctx->debugging = cfg->debugging;
  ctx->logging = cfg->logging;
  ctx->detail_memory = cfg->logging;
  ctx->profiling = cfg->profiling;
  ctx->profiling_paused = 0;
  ctx->error = NULL;
  ctx->log = stderr;
  set_tuning_params(ctx);
  if (backend_context_setup(ctx) == 0) {
    setup_program(ctx);
    init_constants(ctx);
    ctx->program_initialised = true;
    (void)futhark_context_clear_caches(ctx);
    (void)futhark_context_sync(ctx);
  }
  return ctx;
}

void futhark_context_free(struct futhark_context* ctx) {
  if (ctx->program_initialised) {
    free_constants(ctx);
    teardown_program(ctx);
  }
  backend_context_teardown(ctx);
  free_all_in_free_list(ctx);
  free_list_destroy(&ctx->free_list);
  event_list_free(&ctx->event_list);
  free(ctx->constants);
  free(ctx->error);
  free_lock(&ctx->lock);
  free_lock(&ctx->error_lock);
  ctx->cfg->in_use = 0;
  free(ctx);
}

// End of context.h

// Start of copy.h

// Cache-oblivious map-transpose function.
#define GEN_MAP_TRANSPOSE(NAME, ELEM_TYPE)                              \
  static void map_transpose_##NAME                                      \
  (ELEM_TYPE* dst, ELEM_TYPE* src,                                      \
   int64_t k, int64_t m, int64_t n,                                     \
   int64_t cb, int64_t ce, int64_t rb, int64_t re)                      \
  {                                                                     \
  int32_t r = re - rb;                                                  \
  int32_t c = ce - cb;                                                  \
  if (k == 1) {                                                         \
    if (r <= 64 && c <= 64) {                                           \
      for (int64_t j = 0; j < c; j++) {                                 \
        for (int64_t i = 0; i < r; i++) {                               \
          dst[(j + cb) * n + (i + rb)] = src[(i + rb) * m + (j + cb)];  \
        }                                                               \
      }                                                                 \
    } else if (c <= r) {                                                \
      map_transpose_##NAME(dst, src, k, m, n, cb, ce, rb, rb + r/2);    \
      map_transpose_##NAME(dst, src, k, m, n, cb, ce, rb + r/2, re);    \
    } else {                                                            \
      map_transpose_##NAME(dst, src, k, m, n, cb, cb + c/2, rb, re);    \
      map_transpose_##NAME(dst, src, k, m, n, cb + c/2, ce, rb, re);    \
    }                                                                   \
  } else {                                                              \
  for (int64_t i = 0; i < k; i++) {                                     \
    map_transpose_##NAME(dst + i * m * n, src + i * m * n, 1, m, n, cb, ce, rb, re); \
  }\
} \
}

// Straightforward LMAD copy function.
#define GEN_LMAD_COPY_ELEMENTS(NAME, ELEM_TYPE)                         \
  static void lmad_copy_elements_##NAME(int r,                          \
                                        ELEM_TYPE* dst, int64_t dst_strides[r], \
                                        ELEM_TYPE *src, int64_t src_strides[r], \
                                        int64_t shape[r]) {             \
    if (r == 1) {                                                       \
      for (int i = 0; i < shape[0]; i++) {                              \
        dst[i*dst_strides[0]] = src[i*src_strides[0]];                  \
      }                                                                 \
    } else if (r > 1) {                                                 \
      for (int i = 0; i < shape[0]; i++) {                              \
        lmad_copy_elements_##NAME(r-1,                                  \
                                  dst+i*dst_strides[0], dst_strides+1,  \
                                  src+i*src_strides[0], src_strides+1,  \
                                  shape+1);                             \
      }                                                                 \
    }                                                                   \
  }                                                                     \

// Check whether this LMAD can be seen as a transposed 2D array.  This
// is done by checking every possible splitting point.
static bool lmad_is_tr(int64_t *n_out, int64_t *m_out,
                       int r,
                       const int64_t strides[r],
                       const int64_t shape[r]) {
  for (int i = 1; i < r; i++) {
    int n = 1, m = 1;
    bool ok = true;
    int64_t expected = 1;
    // Check strides before 'i'.
    for (int j = i-1; j >= 0; j--) {
      ok = ok && strides[j] == expected;
      expected *= shape[j];
      n *= shape[j];
    }
    // Check strides after 'i'.
    for (int j = r-1; j >= i; j--) {
      ok = ok && strides[j] == expected;
      expected *= shape[j];
      m *= shape[j];
    }
    if (ok) {
      *n_out = n;
      *m_out = m;
      return true;
    }
  }
  return false;
}

// This function determines whether the a 'dst' LMAD is row-major and
// 'src' LMAD is column-major.  Both LMADs are for arrays of the same
// shape.  Both LMADs are allowed to have additional dimensions "on
// top".  Essentially, this function determines whether a copy from
// 'src' to 'dst' is a "map(transpose)" that we know how to implement
// efficiently.  The LMADs can have arbitrary rank, and the main
// challenge here is checking whether the src LMAD actually
// corresponds to a 2D column-major layout by morally collapsing
// dimensions.  There is a lot of looping here, but the actual trip
// count is going to be very low in practice.
//
// Returns true if this is indeed a map(transpose), and writes the
// number of arrays, and moral array size to appropriate output
// parameters.
static bool lmad_map_tr(int64_t *num_arrays_out, int64_t *n_out, int64_t *m_out,
                        int r,
                        const int64_t dst_strides[r],
                        const int64_t src_strides[r],
                        const int64_t shape[r]) {
  int64_t rowmajor_strides[r];
  rowmajor_strides[r-1] = 1;

  for (int i = r-2; i >= 0; i--) {
    rowmajor_strides[i] = rowmajor_strides[i+1] * shape[i+1];
  }

  // map_r will be the number of mapped dimensions on top.
  int map_r = 0;
  int64_t num_arrays = 1;
  for (int i = 0; i < r; i++) {
    if (dst_strides[i] != rowmajor_strides[i] ||
        src_strides[i] != rowmajor_strides[i]) {
      break;
    } else {
      num_arrays *= shape[i];
      map_r++;
    }
  }

  *num_arrays_out = num_arrays;

  if (r==map_r) {
    return false;
  }

  if (memcmp(&rowmajor_strides[map_r],
             &dst_strides[map_r],
             sizeof(int64_t)*(r-map_r)) == 0) {
    return lmad_is_tr(n_out, m_out, r-map_r, src_strides+map_r, shape+map_r);
  } else if (memcmp(&rowmajor_strides[map_r],
                    &src_strides[map_r],
                    sizeof(int64_t)*(r-map_r)) == 0) {
    return lmad_is_tr(m_out, n_out, r-map_r, dst_strides+map_r, shape+map_r);
  }
  return false;
}

// Check if the strides correspond to row-major strides of *any*
// permutation of the shape.  This is done by recursive search with
// backtracking.  This is worst-case exponential, but hopefully the
// arrays we encounter do not have that many dimensions.
static bool lmad_contiguous_search(int checked, int64_t expected,
                                   int r,
                                   int64_t strides[r], int64_t shape[r], bool used[r]) {
  for (int i = 0; i < r; i++) {
    for (int j = 0; j < r; j++) {
      if (!used[j] && strides[j] == expected && strides[j] >= 0) {
        used[j] = true;
        if (checked+1 == r ||
            lmad_contiguous_search(checked+1, expected * shape[j], r, strides, shape, used)) {
          return true;
        }
        used[j] = false;
      }
    }
  }
  return false;
}

// Does this LMAD correspond to an array with positive strides and no
// holes?
static bool lmad_contiguous(int r, int64_t strides[r], int64_t shape[r]) {
  bool used[r];
  for (int i = 0; i < r; i++) {
    used[i] = false;
  }
  return lmad_contiguous_search(0, 1, r, strides, shape, used);
}

// Does this copy correspond to something that could be done with a
// memcpy()-like operation?  I.e. do the LMADs actually represent the
// same in-memory layout and are they contiguous?
static bool lmad_memcpyable(int r,
                            int64_t dst_strides[r], int64_t src_strides[r], int64_t shape[r]) {
  if (!lmad_contiguous(r, dst_strides, shape)) {
    return false;
  }
  for (int i = 0; i < r; i++) {
    if (dst_strides[i] != src_strides[i] && shape[i] != 1) {
      return false;
    }
  }
  return true;
}


static void log_copy(struct futhark_context* ctx,
                     const char *kind, const char *provenance,
                     int r,
                     int64_t dst_offset, int64_t dst_strides[r],
                     int64_t src_offset, int64_t src_strides[r],
                     int64_t shape[r]) {
  if (ctx->logging) {
    fprintf(ctx->log, "\n# Copy %s\n", kind);
    if (provenance) { fprintf(ctx->log, "At: %s\n", provenance); }
    fprintf(ctx->log, "Shape: ");
    for (int i = 0; i < r; i++) { fprintf(ctx->log, "[%ld]", (long int)shape[i]); }
    fprintf(ctx->log, "\n");
    fprintf(ctx->log, "Dst offset: %ld\n", (long int)dst_offset);
    fprintf(ctx->log, "Dst strides:");
    for (int i = 0; i < r; i++) { fprintf(ctx->log, " %ld", (long int)dst_strides[i]); }
    fprintf(ctx->log, "\n");
    fprintf(ctx->log, "Src offset: %ld\n", (long int)src_offset);
    fprintf(ctx->log, "Src strides:");
    for (int i = 0; i < r; i++) { fprintf(ctx->log, " %ld", (long int)src_strides[i]); }
    fprintf(ctx->log, "\n");
  }
}

static void log_transpose(struct futhark_context* ctx,
                          int64_t k, int64_t n, int64_t m) {
  if (ctx->logging) {
    fprintf(ctx->log, "## Transpose\n");
    fprintf(ctx->log, "Arrays     : %ld\n", (long int)k);
    fprintf(ctx->log, "X elements : %ld\n", (long int)m);
    fprintf(ctx->log, "Y elements : %ld\n", (long int)n);
    fprintf(ctx->log, "\n");
  }
}

#define GEN_LMAD_COPY(NAME, ELEM_TYPE)                                  \
  static void lmad_copy_##NAME                                          \
  (struct futhark_context *ctx, int r,                                  \
   ELEM_TYPE* dst, int64_t dst_offset, int64_t dst_strides[r],          \
   ELEM_TYPE *src, int64_t src_offset, int64_t src_strides[r],          \
   int64_t shape[r]) {                                                  \
    log_copy(ctx, "CPU to CPU", NULL, r, dst_offset, dst_strides,       \
             src_offset, src_strides, shape);                           \
    int64_t size = 1;                                                   \
    for (int i = 0; i < r; i++) { size *= shape[i]; }                   \
    if (size == 0) { return; }                                          \
    int64_t k, n, m;                                                    \
    if (lmad_map_tr(&k, &n, &m,                                         \
                    r, dst_strides, src_strides, shape)) {              \
      log_transpose(ctx, k, n, m);                                      \
      map_transpose_##NAME                                              \
        (dst+dst_offset, src+src_offset, k, n, m, 0, n, 0, m);          \
    } else if (lmad_memcpyable(r, dst_strides, src_strides, shape)) {   \
      if (ctx->logging) {fprintf(ctx->log, "## Flat copy\n\n");}          \
      memcpy(dst+dst_offset, src+src_offset, size*sizeof(*dst));        \
    } else {                                                            \
      if (ctx->logging) {fprintf(ctx->log, "## General copy\n\n");}       \
      lmad_copy_elements_##NAME                                         \
        (r,                                                             \
         dst+dst_offset, dst_strides,                                   \
         src+src_offset, src_strides, shape);                           \
    }                                                                   \
  }

GEN_MAP_TRANSPOSE(1b, uint8_t)
GEN_MAP_TRANSPOSE(2b, uint16_t)
GEN_MAP_TRANSPOSE(4b, uint32_t)
GEN_MAP_TRANSPOSE(8b, uint64_t)

GEN_LMAD_COPY_ELEMENTS(1b, uint8_t)
GEN_LMAD_COPY_ELEMENTS(2b, uint16_t)
GEN_LMAD_COPY_ELEMENTS(4b, uint32_t)
GEN_LMAD_COPY_ELEMENTS(8b, uint64_t)

GEN_LMAD_COPY(1b, uint8_t)
GEN_LMAD_COPY(2b, uint16_t)
GEN_LMAD_COPY(4b, uint32_t)
GEN_LMAD_COPY(8b, uint64_t)

// End of copy.h

#define FUTHARK_FUN_ATTR static

FUTHARK_FUN_ATTR int futrts_deleteVertices_7461(struct futhark_context *ctx, struct memblock *mem_out_p_22811, struct memblock *mem_out_p_22812, struct memblock *mem_out_p_22813, int64_t *out_prim_out_22814, struct memblock data_mem_22551, struct memblock lp_mem_22552, struct memblock rp_mem_22553, struct memblock keep_mem_22554, int64_t n_12702);
FUTHARK_FUN_ATTR int futrts_entry_test_delete_vertices(struct futhark_context *ctx, bool *out_prim_out_22826);
FUTHARK_FUN_ATTR int futrts_entry_test_merge_tree(struct futhark_context *ctx, bool *out_prim_out_22827);
FUTHARK_FUN_ATTR int futrts_entry_test_split(struct futhark_context *ctx, bool *out_prim_out_22828);
FUTHARK_FUN_ATTR int futrts_entry_test_split_at_leaf(struct futhark_context *ctx, bool *out_prim_out_22829);
FUTHARK_FUN_ATTR int futrts_entry_test_split_multiple(struct futhark_context *ctx, bool *out_prim_out_22830);
FUTHARK_FUN_ATTR int futrts_entry_test_split_none(struct futhark_context *ctx, bool *out_prim_out_22831);
FUTHARK_FUN_ATTR int futrts_split_7462(struct futhark_context *ctx, struct memblock *mem_out_p_22832, struct memblock *mem_out_p_22833, struct memblock *mem_out_p_22834, struct memblock *mem_out_p_22835, struct memblock *mem_out_p_22836, struct memblock *mem_out_p_22837, struct memblock *mem_out_p_22838, int64_t *out_prim_out_22839, int64_t *out_prim_out_22840, int64_t *out_prim_out_22841, struct memblock data_mem_22551, struct memblock lp_mem_22552, struct memblock rp_mem_22553, struct memblock splits_mem_22554, int64_t n_13611);

static int init_constants(struct futhark_context *ctx)
{
    (void) ctx;
    
    int err = 0;
    
    #define ok_11754 (ctx->constants->ok_11754)
    #define ok_11838 (ctx->constants->ok_11838)
    #define x_16121 (ctx->constants->x_16121)
    #define x_16124 (ctx->constants->x_16124)
    #define x_16130 (ctx->constants->x_16130)
    #define x_16136 (ctx->constants->x_16136)
    
    struct memblock mem_22544;
    
    mem_22544.references = NULL;
    
    struct memblock mem_22530;
    
    mem_22530.references = NULL;
    
    struct memblock mem_22516;
    
    mem_22516.references = NULL;
    
    struct memblock mem_22508;
    
    mem_22508.references = NULL;
    
    struct memblock mem_22495;
    
    mem_22495.references = NULL;
    
    struct memblock mem_22487;
    
    mem_22487.references = NULL;
    
    struct memblock mem_22480;
    
    mem_22480.references = NULL;
    
    struct memblock mem_22479;
    
    mem_22479.references = NULL;
    
    struct memblock mem_22461;
    
    mem_22461.references = NULL;
    
    struct memblock mem_22459;
    
    mem_22459.references = NULL;
    
    struct memblock mem_22477;
    
    mem_22477.references = NULL;
    
    struct memblock mem_22475;
    
    mem_22475.references = NULL;
    
    struct memblock mem_22457;
    
    mem_22457.references = NULL;
    
    struct memblock mem_22443;
    
    mem_22443.references = NULL;
    
    struct memblock mem_22441;
    
    mem_22441.references = NULL;
    
    struct memblock mem_22439;
    
    mem_22439.references = NULL;
    
    struct memblock mem_22437;
    
    mem_22437.references = NULL;
    
    struct memblock mem_22435;
    
    mem_22435.references = NULL;
    
    struct memblock mem_22433;
    
    mem_22433.references = NULL;
    
    struct memblock mem_22432;
    
    mem_22432.references = NULL;
    
    struct memblock mem_22430;
    
    mem_22430.references = NULL;
    
    struct memblock mem_22428;
    
    mem_22428.references = NULL;
    
    struct memblock mem_22427;
    
    mem_22427.references = NULL;
    
    struct memblock mem_22420;
    
    mem_22420.references = NULL;
    
    struct memblock mem_22413;
    
    mem_22413.references = NULL;
    
    struct memblock mem_22388;
    
    mem_22388.references = NULL;
    
    struct memblock mem_22387;
    
    mem_22387.references = NULL;
    
    struct memblock mem_22386;
    
    mem_22386.references = NULL;
    
    struct memblock mem_22385;
    
    mem_22385.references = NULL;
    
    struct memblock mem_22378;
    
    mem_22378.references = NULL;
    
    struct memblock mem_22371;
    
    mem_22371.references = NULL;
    
    struct memblock mem_22370;
    
    mem_22370.references = NULL;
    
    struct memblock mem_22369;
    
    mem_22369.references = NULL;
    
    struct memblock mem_22368;
    
    mem_22368.references = NULL;
    
    struct memblock mem_22367;
    
    mem_22367.references = NULL;
    
    struct memblock mem_22366;
    
    mem_22366.references = NULL;
    
    struct memblock mem_22365;
    
    mem_22365.references = NULL;
    
    struct memblock mem_22364;
    
    mem_22364.references = NULL;
    
    struct memblock mem_22363;
    
    mem_22363.references = NULL;
    
    struct memblock mem_22362;
    
    mem_22362.references = NULL;
    
    struct memblock mem_22361;
    
    mem_22361.references = NULL;
    
    struct memblock mem_22360;
    
    mem_22360.references = NULL;
    
    struct memblock mem_22359;
    
    mem_22359.references = NULL;
    
    struct memblock ext_mem_22356;
    
    ext_mem_22356.references = NULL;
    
    struct memblock ext_mem_22357;
    
    ext_mem_22357.references = NULL;
    
    struct memblock ext_mem_22358;
    
    ext_mem_22358.references = NULL;
    
    struct memblock mem_22355;
    
    mem_22355.references = NULL;
    
    struct memblock ext_mem_22348;
    
    ext_mem_22348.references = NULL;
    
    struct memblock ext_mem_22349;
    
    ext_mem_22349.references = NULL;
    
    struct memblock ext_mem_22350;
    
    ext_mem_22350.references = NULL;
    
    struct memblock ext_mem_22351;
    
    ext_mem_22351.references = NULL;
    
    struct memblock ext_mem_22352;
    
    ext_mem_22352.references = NULL;
    
    struct memblock ext_mem_22353;
    
    ext_mem_22353.references = NULL;
    
    struct memblock ext_mem_22354;
    
    ext_mem_22354.references = NULL;
    
    struct memblock mem_22347;
    
    mem_22347.references = NULL;
    
    struct memblock mem_22346;
    
    mem_22346.references = NULL;
    
    struct memblock ext_mem_22339;
    
    ext_mem_22339.references = NULL;
    
    struct memblock ext_mem_22340;
    
    ext_mem_22340.references = NULL;
    
    struct memblock ext_mem_22341;
    
    ext_mem_22341.references = NULL;
    
    struct memblock ext_mem_22342;
    
    ext_mem_22342.references = NULL;
    
    struct memblock ext_mem_22343;
    
    ext_mem_22343.references = NULL;
    
    struct memblock ext_mem_22344;
    
    ext_mem_22344.references = NULL;
    
    struct memblock ext_mem_22345;
    
    ext_mem_22345.references = NULL;
    
    struct memblock mem_22338;
    
    mem_22338.references = NULL;
    
    struct memblock ext_mem_22331;
    
    ext_mem_22331.references = NULL;
    
    struct memblock ext_mem_22332;
    
    ext_mem_22332.references = NULL;
    
    struct memblock ext_mem_22333;
    
    ext_mem_22333.references = NULL;
    
    struct memblock ext_mem_22334;
    
    ext_mem_22334.references = NULL;
    
    struct memblock ext_mem_22335;
    
    ext_mem_22335.references = NULL;
    
    struct memblock ext_mem_22336;
    
    ext_mem_22336.references = NULL;
    
    struct memblock ext_mem_22337;
    
    ext_mem_22337.references = NULL;
    
    struct memblock mem_22330;
    
    mem_22330.references = NULL;
    
    struct memblock mem_22329;
    
    mem_22329.references = NULL;
    
    struct memblock mem_22328;
    
    mem_22328.references = NULL;
    
    struct memblock mem_22327;
    
    mem_22327.references = NULL;
    
    struct memblock mem_22326;
    
    mem_22326.references = NULL;
    
    struct memblock mem_22325;
    
    mem_22325.references = NULL;
    
    struct memblock mem_22324;
    
    mem_22324.references = NULL;
    
    struct memblock mem_22323;
    
    mem_22323.references = NULL;
    
    struct memblock ext_mem_22316;
    
    ext_mem_22316.references = NULL;
    
    struct memblock ext_mem_22317;
    
    ext_mem_22317.references = NULL;
    
    struct memblock ext_mem_22318;
    
    ext_mem_22318.references = NULL;
    
    struct memblock ext_mem_22319;
    
    ext_mem_22319.references = NULL;
    
    struct memblock ext_mem_22320;
    
    ext_mem_22320.references = NULL;
    
    struct memblock ext_mem_22321;
    
    ext_mem_22321.references = NULL;
    
    struct memblock ext_mem_22322;
    
    ext_mem_22322.references = NULL;
    
    struct memblock mem_22315;
    
    mem_22315.references = NULL;
    
    struct memblock mem_22314;
    
    mem_22314.references = NULL;
    
    struct memblock mem_22313;
    
    mem_22313.references = NULL;
    
    struct memblock mem_22312;
    
    mem_22312.references = NULL;
    // test_operations.fut:9:21-27
    if (memblock_alloc(ctx, &mem_22312, (int64_t) 48, "mem_22312")) {
        err = 1;
        goto cleanup;
    }
    // test_operations.fut:9:21-27
    for (int64_t i_22682 = 0; i_22682 < (int64_t) 6; i_22682++) {
        int64_t x_22683 = (int64_t) 0 + i_22682 * (int64_t) 1;
        
        ((int64_t *) mem_22312.mem)[i_22682] = x_22683;
    }
    // test_operations.fut:7:5-10:13
    if (memblock_alloc(ctx, &mem_22313, (int64_t) 48, "mem_22313")) {
        err = 1;
        goto cleanup;
    }
    // test_operations.fut:7:5-10:13
    
    struct memblock static_array_22684 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_22784, 0, "static_array_22684"};
    
    // test_operations.fut:7:5-10:13
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_22313.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_22684.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 6});
    // test_operations.fut:7:5-10:13
    if (memblock_alloc(ctx, &mem_22314, (int64_t) 48, "mem_22314")) {
        err = 1;
        goto cleanup;
    }
    // test_operations.fut:7:5-10:13
    
    struct memblock static_array_22685 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_22785, 0, "static_array_22685"};
    
    // test_operations.fut:7:5-10:13
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_22314.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_22685.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 6});
    // test_operations.fut:11:16-57
    if (memblock_alloc(ctx, &mem_22315, (int64_t) 6, "mem_22315")) {
        err = 1;
        goto cleanup;
    }
    // test_operations.fut:11:16-57
    
    struct memblock static_array_22686 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_22786, 0, "static_array_22686"};
    
    // test_operations.fut:11:16-57
    lmad_copy_1b(ctx, 1, (uint8_t *) mem_22315.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint8_t *) static_array_22686.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 6});
    // test_operations.fut:6:7-12:50
    
    int64_t test_split_res_11393;
    int64_t test_split_res_11394;
    int64_t test_split_res_11395;
    
    if (futrts_split_7462(ctx, &ext_mem_22322, &ext_mem_22321, &ext_mem_22320, &ext_mem_22319, &ext_mem_22318, &ext_mem_22317, &ext_mem_22316, &test_split_res_11393, &test_split_res_11394, &test_split_res_11395, mem_22312, mem_22313, mem_22314, mem_22315, (int64_t) 6) != 0) {
        err = 1;
        goto cleanup;
    }
    if (memblock_unref(ctx, &mem_22315, "mem_22315") != 0)
        return 1;
    // test_operations.fut:16:5-19:63
    
    bool cond_11424 = test_split_res_11394 == (int64_t) 4;
    
    // test_operations.fut:17:13-61
    if (memblock_alloc(ctx, &mem_22323, (int64_t) 32, "mem_22323")) {
        err = 1;
        goto cleanup;
    }
    // test_operations.fut:17:13-61
    
    struct memblock static_array_22687 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_22787, 0, "static_array_22687"};
    
    // test_operations.fut:17:13-61
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_22323.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_22687.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 4});
    // test_operations.fut:16:5-19:63
    
    bool cond_11425;
    
    if (cond_11424) {
        // test_operations.fut:17:24-47
        
        bool dim_match_20811 = (int64_t) 4 == test_split_res_11394;
        
        // test_operations.fut:17:24-47
        
        bool empty_or_match_cert_20812;
        
        if (!dim_match_20811) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (desugared) shape [", (long long) test_split_res_11394, "] cannot match shape of type \"[", (long long) (int64_t) 4, "]i64\".", "-> #0  test_operations.fut:17:24-47\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        // test_operations.fut:17:8-61
        
        bool defunc_0_reduce_res_20814;
        bool redout_21855 = 1;
        
        for (int64_t i_21856 = 0; i_21856 < (int64_t) 4; i_21856++) {
            int64_t eta_p_20815 = ((int64_t *) ext_mem_22321.mem)[i_21856];
            int64_t eta_p_20816 = ((int64_t *) mem_22323.mem)[i_21856];
            
            // test_operations.fut:17:18-22
            
            bool defunc_0_f_res_20817 = eta_p_20815 == eta_p_20816;
            
            // test_operations.fut:17:8-61
            
            bool x_20820 = defunc_0_f_res_20817 && redout_21855;
            bool redout_tmp_22688 = x_20820;
            
            redout_21855 = redout_tmp_22688;
        }
        defunc_0_reduce_res_20814 = redout_21855;
        cond_11425 = defunc_0_reduce_res_20814;
    } else {
        cond_11425 = 0;
    }
    if (memblock_unref(ctx, &ext_mem_22321, "ext_mem_22321") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22323, "mem_22323") != 0)
        return 1;
    // test_operations.fut:18:13-62
    if (memblock_alloc(ctx, &mem_22324, (int64_t) 32, "mem_22324")) {
        err = 1;
        goto cleanup;
    }
    // test_operations.fut:18:13-62
    
    struct memblock static_array_22689 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_22788, 0, "static_array_22689"};
    
    // test_operations.fut:18:13-62
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_22324.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_22689.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 4});
    // test_operations.fut:16:5-19:63
    
    bool cond_11435;
    
    if (cond_11425) {
        // test_operations.fut:18:24-45
        
        bool dim_match_20825 = (int64_t) 4 == test_split_res_11394;
        
        // test_operations.fut:18:24-45
        
        bool empty_or_match_cert_20826;
        
        if (!dim_match_20825) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (desugared) shape [", (long long) test_split_res_11394, "] cannot match shape of type \"[", (long long) (int64_t) 4, "]i64\".", "-> #0  test_operations.fut:18:24-45\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        // test_operations.fut:18:8-62
        
        bool defunc_0_reduce_res_20828;
        bool redout_21857 = 1;
        
        for (int64_t i_21858 = 0; i_21858 < (int64_t) 4; i_21858++) {
            int64_t eta_p_20829 = ((int64_t *) ext_mem_22320.mem)[i_21858];
            int64_t eta_p_20830 = ((int64_t *) mem_22324.mem)[i_21858];
            
            // test_operations.fut:18:18-22
            
            bool defunc_0_f_res_20831 = eta_p_20829 == eta_p_20830;
            
            // test_operations.fut:18:8-62
            
            bool x_20834 = defunc_0_f_res_20831 && redout_21857;
            bool redout_tmp_22690 = x_20834;
            
            redout_21857 = redout_tmp_22690;
        }
        defunc_0_reduce_res_20828 = redout_21857;
        cond_11435 = defunc_0_reduce_res_20828;
    } else {
        cond_11435 = 0;
    }
    if (memblock_unref(ctx, &ext_mem_22320, "ext_mem_22320") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22324, "mem_22324") != 0)
        return 1;
    // test_operations.fut:19:13-62
    if (memblock_alloc(ctx, &mem_22325, (int64_t) 32, "mem_22325")) {
        err = 1;
        goto cleanup;
    }
    // test_operations.fut:19:13-62
    
    struct memblock static_array_22691 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_22789, 0, "static_array_22691"};
    
    // test_operations.fut:19:13-62
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_22325.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_22691.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 4});
    // test_operations.fut:16:5-19:63
    
    bool subtrees_ok_11445;
    
    if (cond_11435) {
        // test_operations.fut:19:24-45
        
        bool dim_match_20839 = (int64_t) 4 == test_split_res_11394;
        
        // test_operations.fut:19:24-45
        
        bool empty_or_match_cert_20840;
        
        if (!dim_match_20839) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (desugared) shape [", (long long) test_split_res_11394, "] cannot match shape of type \"[", (long long) (int64_t) 4, "]i64\".", "-> #0  test_operations.fut:19:24-45\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        // test_operations.fut:19:8-62
        
        bool defunc_0_reduce_res_20842;
        bool redout_21859 = 1;
        
        for (int64_t i_21860 = 0; i_21860 < (int64_t) 4; i_21860++) {
            int64_t eta_p_20843 = ((int64_t *) ext_mem_22319.mem)[i_21860];
            int64_t eta_p_20844 = ((int64_t *) mem_22325.mem)[i_21860];
            
            // test_operations.fut:19:18-22
            
            bool defunc_0_f_res_20845 = eta_p_20843 == eta_p_20844;
            
            // test_operations.fut:19:8-62
            
            bool x_20848 = defunc_0_f_res_20845 && redout_21859;
            bool redout_tmp_22692 = x_20848;
            
            redout_21859 = redout_tmp_22692;
        }
        defunc_0_reduce_res_20842 = redout_21859;
        subtrees_ok_11445 = defunc_0_reduce_res_20842;
    } else {
        subtrees_ok_11445 = 0;
    }
    if (memblock_unref(ctx, &ext_mem_22319, "ext_mem_22319") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22325, "mem_22325") != 0)
        return 1;
    // test_operations.fut:22:5-23:62
    
    bool cond_11458 = test_split_res_11393 == (int64_t) 1;
    
    // test_operations.fut:22:5-23:62
    
    bool offsets_ok_11459;
    
    if (cond_11458) {
        // test_operations.fut:23:24-53
        
        bool dim_match_20851 = (int64_t) 1 == test_split_res_11393;
        
        // test_operations.fut:23:24-53
        
        bool empty_or_match_cert_20852;
        
        if (!dim_match_20851) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (desugared) shape [", (long long) test_split_res_11393, "] cannot match shape of type \"[", (long long) (int64_t) 1, "]i64\".", "-> #0  test_operations.fut:23:24-53\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        // test_operations.fut:23:13-61
        if (memblock_alloc(ctx, &mem_22326, (int64_t) 8, "mem_22326")) {
            err = 1;
            goto cleanup;
        }
        // test_operations.fut:23:13-61
        
        struct memblock static_array_22693 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_22790, 0, "static_array_22693"};
        
        // test_operations.fut:23:13-61
        lmad_copy_8b(ctx, 1, (uint64_t *) mem_22326.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_22693.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 1});
        
        int64_t eta_p_20854 = ((int64_t *) ext_mem_22322.mem)[(int64_t) 0];
        int64_t eta_p_20855 = ((int64_t *) mem_22326.mem)[(int64_t) 0];
        
        if (memblock_unref(ctx, &mem_22326, "mem_22326") != 0)
            return 1;
        // test_operations.fut:23:18-22
        
        bool defunc_0_f_res_20856 = eta_p_20854 == eta_p_20855;
        
        offsets_ok_11459 = defunc_0_f_res_20856;
    } else {
        offsets_ok_11459 = 0;
    }
    if (memblock_unref(ctx, &ext_mem_22322, "ext_mem_22322") != 0)
        return 1;
    // test_operations.fut:27:5-30:52
    
    bool cond_11478 = test_split_res_11395 == (int64_t) 2;
    
    // test_operations.fut:28:13-50
    if (memblock_alloc(ctx, &mem_22327, (int64_t) 16, "mem_22327")) {
        err = 1;
        goto cleanup;
    }
    // test_operations.fut:28:13-50
    
    struct memblock static_array_22694 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_22791, 0, "static_array_22694"};
    
    // test_operations.fut:28:13-50
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_22327.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_22694.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 2});
    // test_operations.fut:27:5-30:52
    
    bool cond_11479;
    
    if (cond_11478) {
        // test_operations.fut:28:24-42
        
        bool dim_match_20859 = (int64_t) 2 == test_split_res_11395;
        
        // test_operations.fut:28:24-42
        
        bool empty_or_match_cert_20860;
        
        if (!dim_match_20859) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (desugared) shape [", (long long) test_split_res_11395, "] cannot match shape of type \"[", (long long) (int64_t) 2, "]i64\".", "-> #0  test_operations.fut:28:24-42\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        // test_operations.fut:28:8-50
        
        bool defunc_0_reduce_res_20862;
        bool redout_21861 = 1;
        
        for (int64_t i_21862 = 0; i_21862 < (int64_t) 2; i_21862++) {
            int64_t eta_p_20863 = ((int64_t *) ext_mem_22318.mem)[i_21862];
            int64_t eta_p_20864 = ((int64_t *) mem_22327.mem)[i_21862];
            
            // test_operations.fut:28:18-22
            
            bool defunc_0_f_res_20865 = eta_p_20863 == eta_p_20864;
            
            // test_operations.fut:28:8-50
            
            bool x_20868 = defunc_0_f_res_20865 && redout_21861;
            bool redout_tmp_22695 = x_20868;
            
            redout_21861 = redout_tmp_22695;
        }
        defunc_0_reduce_res_20862 = redout_21861;
        cond_11479 = defunc_0_reduce_res_20862;
    } else {
        cond_11479 = 0;
    }
    if (memblock_unref(ctx, &ext_mem_22318, "ext_mem_22318") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22327, "mem_22327") != 0)
        return 1;
    // test_operations.fut:29:13-51
    if (memblock_alloc(ctx, &mem_22328, (int64_t) 16, "mem_22328")) {
        err = 1;
        goto cleanup;
    }
    // test_operations.fut:29:13-51
    
    struct memblock static_array_22696 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_22792, 0, "static_array_22696"};
    
    // test_operations.fut:29:13-51
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_22328.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_22696.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 2});
    // test_operations.fut:27:5-30:52
    
    bool cond_11489;
    
    if (cond_11479) {
        // test_operations.fut:29:24-40
        
        bool dim_match_20873 = (int64_t) 2 == test_split_res_11395;
        
        // test_operations.fut:29:24-40
        
        bool empty_or_match_cert_20874;
        
        if (!dim_match_20873) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (desugared) shape [", (long long) test_split_res_11395, "] cannot match shape of type \"[", (long long) (int64_t) 2, "]i64\".", "-> #0  test_operations.fut:29:24-40\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        // test_operations.fut:29:8-51
        
        bool defunc_0_reduce_res_20876;
        bool redout_21863 = 1;
        
        for (int64_t i_21864 = 0; i_21864 < (int64_t) 2; i_21864++) {
            int64_t eta_p_20877 = ((int64_t *) ext_mem_22317.mem)[i_21864];
            int64_t eta_p_20878 = ((int64_t *) mem_22328.mem)[i_21864];
            
            // test_operations.fut:29:18-22
            
            bool defunc_0_f_res_20879 = eta_p_20877 == eta_p_20878;
            
            // test_operations.fut:29:8-51
            
            bool x_20882 = defunc_0_f_res_20879 && redout_21863;
            bool redout_tmp_22697 = x_20882;
            
            redout_21863 = redout_tmp_22697;
        }
        defunc_0_reduce_res_20876 = redout_21863;
        cond_11489 = defunc_0_reduce_res_20876;
    } else {
        cond_11489 = 0;
    }
    if (memblock_unref(ctx, &ext_mem_22317, "ext_mem_22317") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22328, "mem_22328") != 0)
        return 1;
    // test_operations.fut:30:13-51
    if (memblock_alloc(ctx, &mem_22329, (int64_t) 16, "mem_22329")) {
        err = 1;
        goto cleanup;
    }
    // test_operations.fut:30:13-51
    
    struct memblock static_array_22698 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_22793, 0, "static_array_22698"};
    
    // test_operations.fut:30:13-51
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_22329.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_22698.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 2});
    // test_operations.fut:27:5-30:52
    
    bool remainder_ok_11499;
    
    if (cond_11489) {
        // test_operations.fut:30:24-40
        
        bool dim_match_20887 = (int64_t) 2 == test_split_res_11395;
        
        // test_operations.fut:30:24-40
        
        bool empty_or_match_cert_20888;
        
        if (!dim_match_20887) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (desugared) shape [", (long long) test_split_res_11395, "] cannot match shape of type \"[", (long long) (int64_t) 2, "]i64\".", "-> #0  test_operations.fut:30:24-40\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        // test_operations.fut:30:8-51
        
        bool defunc_0_reduce_res_20890;
        bool redout_21865 = 1;
        
        for (int64_t i_21866 = 0; i_21866 < (int64_t) 2; i_21866++) {
            int64_t eta_p_20891 = ((int64_t *) ext_mem_22316.mem)[i_21866];
            int64_t eta_p_20892 = ((int64_t *) mem_22329.mem)[i_21866];
            
            // test_operations.fut:30:18-22
            
            bool defunc_0_f_res_20893 = eta_p_20891 == eta_p_20892;
            
            // test_operations.fut:30:8-51
            
            bool x_20896 = defunc_0_f_res_20893 && redout_21865;
            bool redout_tmp_22699 = x_20896;
            
            redout_21865 = redout_tmp_22699;
        }
        defunc_0_reduce_res_20890 = redout_21865;
        remainder_ok_11499 = defunc_0_reduce_res_20890;
    } else {
        remainder_ok_11499 = 0;
    }
    if (memblock_unref(ctx, &ext_mem_22316, "ext_mem_22316") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22329, "mem_22329") != 0)
        return 1;
    
    bool x_16118 = subtrees_ok_11445 && offsets_ok_11459;
    
    x_16121 = remainder_ok_11499 && x_16118;
    // test_operations.fut:55:16-57
    if (memblock_alloc(ctx, &mem_22330, (int64_t) 6, "mem_22330")) {
        err = 1;
        goto cleanup;
    }
    // test_operations.fut:55:16-57
    
    struct memblock static_array_22700 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_22794, 0, "static_array_22700"};
    
    // test_operations.fut:55:16-57
    lmad_copy_1b(ctx, 1, (uint8_t *) mem_22330.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint8_t *) static_array_22700.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 6});
    // test_operations.fut:49:7-56:50
    
    int64_t test_split_at_leaf_res_11525;
    int64_t test_split_at_leaf_res_11526;
    int64_t test_split_at_leaf_res_11527;
    
    if (futrts_split_7462(ctx, &ext_mem_22337, &ext_mem_22336, &ext_mem_22335, &ext_mem_22334, &ext_mem_22333, &ext_mem_22332, &ext_mem_22331, &test_split_at_leaf_res_11525, &test_split_at_leaf_res_11526, &test_split_at_leaf_res_11527, mem_22312, mem_22313, mem_22314, mem_22330, (int64_t) 6) != 0) {
        err = 1;
        goto cleanup;
    }
    if (memblock_unref(ctx, &mem_22330, "mem_22330") != 0)
        return 1;
    // test_operations.fut:61:5-62:53
    
    bool cond_11562 = test_split_at_leaf_res_11526 == (int64_t) 1;
    
    // test_operations.fut:61:5-62:53
    
    bool subtrees_ok_11563;
    
    if (cond_11562) {
        // test_operations.fut:62:24-47
        
        bool dim_match_20899 = (int64_t) 1 == test_split_at_leaf_res_11526;
        
        // test_operations.fut:62:24-47
        
        bool empty_or_match_cert_20900;
        
        if (!dim_match_20899) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (desugared) shape [", (long long) test_split_at_leaf_res_11526, "] cannot match shape of type \"[", (long long) (int64_t) 1, "]i64\".", "-> #0  test_operations.fut:62:24-47\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        
        int64_t eta_p_20901 = ((int64_t *) ext_mem_22336.mem)[(int64_t) 0];
        
        // test_operations.fut:62:18-22
        
        bool defunc_0_f_res_20902 = eta_p_20901 == (int64_t) 2;
        
        subtrees_ok_11563 = defunc_0_f_res_20902;
    } else {
        subtrees_ok_11563 = 0;
    }
    if (memblock_unref(ctx, &ext_mem_22336, "ext_mem_22336") != 0)
        return 1;
    // test_operations.fut:64:38-42
    
    bool remainder_ok_11576 = test_split_at_leaf_res_11527 == (int64_t) 5;
    
    x_16124 = subtrees_ok_11563 && remainder_ok_11576;
    // test_operations.fut:74:16-56
    if (memblock_alloc(ctx, &mem_22338, (int64_t) 6, "mem_22338")) {
        err = 1;
        goto cleanup;
    }
    // test_operations.fut:74:16-56
    
    struct memblock static_array_22701 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_22795, 0, "static_array_22701"};
    
    // test_operations.fut:74:16-56
    lmad_copy_1b(ctx, 1, (uint8_t *) mem_22338.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint8_t *) static_array_22701.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 6});
    // test_operations.fut:68:7-75:50
    
    int64_t test_split_multiple_res_11592;
    int64_t test_split_multiple_res_11593;
    int64_t test_split_multiple_res_11594;
    
    if (futrts_split_7462(ctx, &ext_mem_22345, &ext_mem_22344, &ext_mem_22343, &ext_mem_22342, &ext_mem_22341, &ext_mem_22340, &ext_mem_22339, &test_split_multiple_res_11592, &test_split_multiple_res_11593, &test_split_multiple_res_11594, mem_22312, mem_22313, mem_22314, mem_22338, (int64_t) 6) != 0) {
        err = 1;
        goto cleanup;
    }
    if (memblock_unref(ctx, &mem_22338, "mem_22338") != 0)
        return 1;
    // test_operations.fut:79:42-46
    
    bool subtrees_ok_11629 = test_split_multiple_res_11593 == (int64_t) 5;
    
    // test_operations.fut:82:5-83:65
    
    bool cond_11633 = test_split_multiple_res_11592 == (int64_t) 2;
    
    // test_operations.fut:83:13-64
    if (memblock_alloc(ctx, &mem_22346, (int64_t) 16, "mem_22346")) {
        err = 1;
        goto cleanup;
    }
    // test_operations.fut:83:13-64
    
    struct memblock static_array_22702 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_22796, 0, "static_array_22702"};
    
    // test_operations.fut:83:13-64
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_22346.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_22702.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 2});
    // test_operations.fut:82:5-83:65
    
    bool offsets_ok_11634;
    
    if (cond_11633) {
        // test_operations.fut:83:24-53
        
        bool dim_match_20905 = (int64_t) 2 == test_split_multiple_res_11592;
        
        // test_operations.fut:83:24-53
        
        bool empty_or_match_cert_20906;
        
        if (!dim_match_20905) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (desugared) shape [", (long long) test_split_multiple_res_11592, "] cannot match shape of type \"[", (long long) (int64_t) 2, "]i64\".", "-> #0  test_operations.fut:83:24-53\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        // test_operations.fut:83:8-64
        
        bool defunc_0_reduce_res_20908;
        bool redout_21867 = 1;
        
        for (int64_t i_21868 = 0; i_21868 < (int64_t) 2; i_21868++) {
            int64_t eta_p_20909 = ((int64_t *) ext_mem_22345.mem)[i_21868];
            int64_t eta_p_20910 = ((int64_t *) mem_22346.mem)[i_21868];
            
            // test_operations.fut:83:18-22
            
            bool defunc_0_f_res_20911 = eta_p_20909 == eta_p_20910;
            
            // test_operations.fut:83:8-64
            
            bool x_20914 = defunc_0_f_res_20911 && redout_21867;
            bool redout_tmp_22703 = x_20914;
            
            redout_21867 = redout_tmp_22703;
        }
        defunc_0_reduce_res_20908 = redout_21867;
        offsets_ok_11634 = defunc_0_reduce_res_20908;
    } else {
        offsets_ok_11634 = 0;
    }
    if (memblock_unref(ctx, &ext_mem_22345, "ext_mem_22345") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22346, "mem_22346") != 0)
        return 1;
    // test_operations.fut:86:5-87:48
    
    bool cond_11647 = test_split_multiple_res_11594 == (int64_t) 1;
    
    // test_operations.fut:86:5-87:48
    
    bool remainder_ok_11648;
    
    if (cond_11647) {
        // test_operations.fut:87:24-42
        
        bool dim_match_20917 = (int64_t) 1 == test_split_multiple_res_11594;
        
        // test_operations.fut:87:24-42
        
        bool empty_or_match_cert_20918;
        
        if (!dim_match_20917) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (desugared) shape [", (long long) test_split_multiple_res_11594, "] cannot match shape of type \"[", (long long) (int64_t) 1, "]i64\".", "-> #0  test_operations.fut:87:24-42\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        
        int64_t eta_p_20919 = ((int64_t *) ext_mem_22341.mem)[(int64_t) 0];
        
        // test_operations.fut:87:18-22
        
        bool defunc_0_f_res_20920 = eta_p_20919 == (int64_t) 0;
        
        remainder_ok_11648 = defunc_0_f_res_20920;
    } else {
        remainder_ok_11648 = 0;
    }
    if (memblock_unref(ctx, &ext_mem_22341, "ext_mem_22341") != 0)
        return 1;
    
    bool x_16127 = subtrees_ok_11629 && offsets_ok_11634;
    
    x_16130 = remainder_ok_11648 && x_16127;
    // test_operations.fut:96:16-58
    if (memblock_alloc(ctx, &mem_22347, (int64_t) 6, "mem_22347")) {
        err = 1;
        goto cleanup;
    }
    // test_operations.fut:96:16-58
    
    struct memblock static_array_22704 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_22797, 0, "static_array_22704"};
    
    // test_operations.fut:96:16-58
    lmad_copy_1b(ctx, 1, (uint8_t *) mem_22347.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint8_t *) static_array_22704.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 6});
    // test_operations.fut:91:7-97:50
    
    int64_t test_split_none_res_11674;
    int64_t test_split_none_res_11675;
    int64_t test_split_none_res_11676;
    
    if (futrts_split_7462(ctx, &ext_mem_22354, &ext_mem_22353, &ext_mem_22352, &ext_mem_22351, &ext_mem_22350, &ext_mem_22349, &ext_mem_22348, &test_split_none_res_11674, &test_split_none_res_11675, &test_split_none_res_11676, mem_22312, mem_22313, mem_22314, mem_22347, (int64_t) 6) != 0) {
        err = 1;
        goto cleanup;
    }
    if (memblock_unref(ctx, &mem_22347, "mem_22347") != 0)
        return 1;
    // test_operations.fut:101:42-46
    
    bool subtrees_ok_11711 = test_split_none_res_11675 == (int64_t) 0;
    
    // test_operations.fut:102:47-51
    
    bool offsets_ok_11715 = test_split_none_res_11674 == (int64_t) 0;
    
    // test_operations.fut:104:38-42
    
    bool remainder_ok_11719 = test_split_none_res_11676 == (int64_t) 6;
    bool x_16133 = subtrees_ok_11711 && offsets_ok_11715;
    
    x_16136 = remainder_ok_11719 && x_16133;
    // test_operations.fut:114:14-53
    if (memblock_alloc(ctx, &mem_22355, (int64_t) 6, "mem_22355")) {
        err = 1;
        goto cleanup;
    }
    // test_operations.fut:114:14-53
    
    struct memblock static_array_22705 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_22798, 0, "static_array_22705"};
    
    // test_operations.fut:114:14-53
    lmad_copy_1b(ctx, 1, (uint8_t *) mem_22355.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint8_t *) static_array_22705.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 6});
    // test_operations.fut:108:7-115:39
    
    int64_t test_delete_vertices_res_11736;
    
    if (futrts_deleteVertices_7461(ctx, &ext_mem_22358, &ext_mem_22357, &ext_mem_22356, &test_delete_vertices_res_11736, mem_22312, mem_22313, mem_22314, mem_22355, (int64_t) 6) != 0) {
        err = 1;
        goto cleanup;
    }
    if (memblock_unref(ctx, &mem_22312, "mem_22312") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22313, "mem_22313") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22314, "mem_22314") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22355, "mem_22355") != 0)
        return 1;
    // test_operations.fut:118:5-119:54
    
    bool cond_11753 = test_delete_vertices_res_11736 == (int64_t) 3;
    
    // test_operations.fut:119:13-53
    if (memblock_alloc(ctx, &mem_22359, (int64_t) 24, "mem_22359")) {
        err = 1;
        goto cleanup;
    }
    // test_operations.fut:119:13-53
    
    struct memblock static_array_22706 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_22799, 0, "static_array_22706"};
    
    // test_operations.fut:119:13-53
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_22359.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_22706.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 3});
    // test_operations.fut:118:5-119:54
    if (cond_11753) {
        // test_operations.fut:119:24-42
        
        bool dim_match_20923 = (int64_t) 3 == test_delete_vertices_res_11736;
        
        // test_operations.fut:119:24-42
        
        bool empty_or_match_cert_20924;
        
        if (!dim_match_20923) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (desugared) shape [", (long long) test_delete_vertices_res_11736, "] cannot match shape of type \"[", (long long) (int64_t) 3, "]i64\".", "-> #0  test_operations.fut:119:24-42\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        // test_operations.fut:119:8-53
        
        bool defunc_0_reduce_res_20926;
        bool redout_21869 = 1;
        
        for (int64_t i_21870 = 0; i_21870 < (int64_t) 3; i_21870++) {
            int64_t eta_p_20927 = ((int64_t *) ext_mem_22358.mem)[i_21870];
            int64_t eta_p_20928 = ((int64_t *) mem_22359.mem)[i_21870];
            
            // test_operations.fut:119:18-22
            
            bool defunc_0_f_res_20929 = eta_p_20927 == eta_p_20928;
            
            // test_operations.fut:119:8-53
            
            bool x_20932 = defunc_0_f_res_20929 && redout_21869;
            bool redout_tmp_22707 = x_20932;
            
            redout_21869 = redout_tmp_22707;
        }
        defunc_0_reduce_res_20926 = redout_21869;
        ok_11754 = defunc_0_reduce_res_20926;
    } else {
        ok_11754 = 0;
    }
    if (memblock_unref(ctx, &ext_mem_22358, "ext_mem_22358") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22359, "mem_22359") != 0)
        return 1;
    // test_operations.fut:124:5-128:4
    if (memblock_alloc(ctx, &mem_22360, (int64_t) 32, "mem_22360")) {
        err = 1;
        goto cleanup;
    }
    // test_operations.fut:124:5-128:4
    
    struct memblock static_array_22708 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_22800, 0, "static_array_22708"};
    
    // test_operations.fut:124:5-128:4
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_22360.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_22708.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 4});
    // test_operations.fut:124:5-128:4
    if (memblock_alloc(ctx, &mem_22361, (int64_t) 32, "mem_22361")) {
        err = 1;
        goto cleanup;
    }
    // test_operations.fut:124:5-128:4
    
    struct memblock static_array_22709 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_22801, 0, "static_array_22709"};
    
    // test_operations.fut:124:5-128:4
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_22361.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_22709.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 4});
    // test_operations.fut:124:5-128:4
    if (memblock_alloc(ctx, &mem_22362, (int64_t) 32, "mem_22362")) {
        err = 1;
        goto cleanup;
    }
    // test_operations.fut:124:5-128:4
    
    struct memblock static_array_22710 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_22802, 0, "static_array_22710"};
    
    // test_operations.fut:124:5-128:4
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_22362.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_22710.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 4});
    // test_operations.fut:130:5-134:6
    if (memblock_alloc(ctx, &mem_22363, (int64_t) 40, "mem_22363")) {
        err = 1;
        goto cleanup;
    }
    // test_operations.fut:130:5-134:6
    
    struct memblock static_array_22711 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_22803, 0, "static_array_22711"};
    
    // test_operations.fut:130:5-134:6
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_22363.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_22711.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 5});
    // test_operations.fut:130:5-134:6
    if (memblock_alloc(ctx, &mem_22364, (int64_t) 40, "mem_22364")) {
        err = 1;
        goto cleanup;
    }
    // test_operations.fut:130:5-134:6
    
    struct memblock static_array_22712 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_22804, 0, "static_array_22712"};
    
    // test_operations.fut:130:5-134:6
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_22364.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_22712.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 5});
    // test_operations.fut:130:5-134:6
    if (memblock_alloc(ctx, &mem_22365, (int64_t) 40, "mem_22365")) {
        err = 1;
        goto cleanup;
    }
    // test_operations.fut:130:5-134:6
    
    struct memblock static_array_22713 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_22805, 0, "static_array_22713"};
    
    // test_operations.fut:130:5-134:6
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_22365.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_22713.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 5});
    if (memblock_alloc(ctx, &mem_22366, (int64_t) 16, "mem_22366")) {
        err = 1;
        goto cleanup;
    }
    
    struct memblock static_array_22714 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_22806, 0, "static_array_22714"};
    
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_22366.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_22714.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 2});
    if (memblock_alloc(ctx, &mem_22367, (int64_t) 32, "mem_22367")) {
        err = 1;
        goto cleanup;
    }
    
    struct memblock static_array_22715 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_22807, 0, "static_array_22715"};
    
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_22367.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_22715.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 4});
    if (memblock_alloc(ctx, &mem_22368, (int64_t) 88, "mem_22368")) {
        err = 1;
        goto cleanup;
    }
    
    struct memblock static_array_22716 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_22808, 0, "static_array_22716"};
    
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_22368.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_22716.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 11});
    if (memblock_alloc(ctx, &mem_22369, (int64_t) 88, "mem_22369")) {
        err = 1;
        goto cleanup;
    }
    
    struct memblock static_array_22717 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_22809, 0, "static_array_22717"};
    
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_22369.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_22717.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 11});
    if (memblock_alloc(ctx, &mem_22370, (int64_t) 88, "mem_22370")) {
        err = 1;
        goto cleanup;
    }
    
    struct memblock static_array_22718 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_22810, 0, "static_array_22718"};
    
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_22370.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_22718.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 11});
    // ../lib/github.com/diku-dk/vtree/vtree.fut:300:21-93
    if (memblock_alloc(ctx, &mem_22371, (int64_t) 16, "mem_22371")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:300:21-93
    for (int64_t i_21873 = 0; i_21873 < (int64_t) 2; i_21873++) {
        // ../lib/github.com/diku-dk/vtree/vtree.fut:300:33-70
        
        bool cond_17682 = slt64(i_21873, (int64_t) 1);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:300:33-70
        
        int64_t zm_lhs_17683;
        
        if (cond_17682) {
            // ../lib/github.com/diku-dk/vtree/vtree.fut:300:60-62
            
            int64_t tmp_20935 = add64((int64_t) 1, i_21873);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:300:51-63
            
            bool x_20936 = sle64((int64_t) 0, tmp_20935);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:300:51-63
            
            bool y_20937 = slt64(tmp_20935, (int64_t) 2);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:300:51-63
            
            bool bounds_check_20938 = x_20936 && y_20937;
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:300:51-63
            
            bool index_certs_20939;
            
            if (!bounds_check_20938) {
                set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) tmp_20935, "] out of bounds for array of shape [", (long long) (int64_t) 2, "].", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:300:51-63\n   #1  test_operations.fut:123:7-142:98\n"));
                err = FUTHARK_PROGRAM_ERROR;
                goto cleanup;
            }
            // ../lib/github.com/diku-dk/vtree/vtree.fut:300:51-63
            
            int64_t zm_lhs_t_res_20940 = ((int64_t *) mem_22366.mem)[tmp_20935];
            
            zm_lhs_17683 = zm_lhs_t_res_20940;
        } else {
            zm_lhs_17683 = (int64_t) 2;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:300:74-84
        
        int64_t zm_rhs_17694 = ((int64_t *) mem_22366.mem)[i_21873];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:300:72-84
        
        int64_t lifted_lambda_res_17695 = sub64(zm_lhs_17683, zm_rhs_17694);
        
        ((int64_t *) mem_22371.mem)[i_21873] = lifted_lambda_res_17695;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:300:98-103
    // Trace: trace
    fprintf(ctx->log, "%s", "trace: ");
    for (int64_t nest_i_22720 = 0; nest_i_22720 < (int64_t) 2; nest_i_22720++) {
        int64_t arr_elem_22721 = ((int64_t *) mem_22371.mem)[nest_i_22720];
        
        fprintf(ctx->log, "%lld%s", (long long) arr_elem_22721, " ");
    }
    fprintf(ctx->log, "%s", "\n");
    // ../lib/github.com/diku-dk/vtree/vtree.fut:301:23-85
    if (memblock_alloc(ctx, &mem_22378, (int64_t) 32, "mem_22378")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:301:23-85
    for (int64_t i_21877 = 0; i_21877 < (int64_t) 4; i_21877++) {
        int64_t eta_p_17698 = ((int64_t *) mem_22367.mem)[i_21877];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:301:34-68
        
        bool cond_17699 = sle64((int64_t) 0, eta_p_17698);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:301:34-68
        
        int64_t lifted_lambda_res_17700;
        
        if (cond_17699) {
            // ../lib/github.com/diku-dk/vtree/vtree.fut:301:49-61
            
            bool y_20941 = slt64(eta_p_17698, (int64_t) 2);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:301:49-61
            
            bool bounds_check_20942 = cond_17699 && y_20941;
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:301:49-61
            
            bool index_certs_20943;
            
            if (!bounds_check_20942) {
                set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) eta_p_17698, "] out of bounds for array of shape [", (long long) (int64_t) 2, "].", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:301:49-61\n   #1  test_operations.fut:123:7-142:98\n"));
                err = FUTHARK_PROGRAM_ERROR;
                goto cleanup;
            }
            // ../lib/github.com/diku-dk/vtree/vtree.fut:301:49-61
            
            int64_t lifted_lambda_res_t_res_20944 = ((int64_t *) mem_22371.mem)[eta_p_17698];
            
            lifted_lambda_res_17700 = lifted_lambda_res_t_res_20944;
        } else {
            lifted_lambda_res_17700 = (int64_t) 0;
        }
        ((int64_t *) mem_22378.mem)[i_21877] = lifted_lambda_res_17700;
    }
    if (memblock_unref(ctx, &mem_22371, "mem_22371") != 0)
        return 1;
    // ../lib/github.com/diku-dk/vtree/vtree.fut:301:89-94
    // Trace: trace
    fprintf(ctx->log, "%s", "trace: ");
    for (int64_t nest_i_22723 = 0; nest_i_22723 < (int64_t) 4; nest_i_22723++) {
        int64_t arr_elem_22724 = ((int64_t *) mem_22378.mem)[nest_i_22723];
        
        fprintf(ctx->log, "%lld%s", (long long) arr_elem_22724, " ");
    }
    fprintf(ctx->log, "%s", "\n");
    // ../lib/github.com/diku-dk/vtree/vtree.fut:327:16-31
    if (memblock_alloc(ctx, &mem_22385, (int64_t) 32, "mem_22385")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:327:16-31
    if (memblock_alloc(ctx, &mem_22386, (int64_t) 32, "mem_22386")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:327:16-31
    if (memblock_alloc(ctx, &mem_22387, (int64_t) 32, "mem_22387")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:327:16-31
    if (memblock_alloc(ctx, &mem_22388, (int64_t) 32, "mem_22388")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:327:16-31
    
    int64_t discard_21896;
    int64_t discard_21897;
    int64_t discard_21898;
    int64_t defunc_0_reduce_res_21103;
    int64_t scanacc_21883;
    int64_t scanacc_21884;
    int64_t scanacc_21885;
    int64_t redout_21889;
    
    scanacc_21883 = (int64_t) 0;
    scanacc_21884 = (int64_t) 0;
    scanacc_21885 = (int64_t) 0;
    redout_21889 = (int64_t) 0;
    for (int64_t i_21891 = 0; i_21891 < (int64_t) 4; i_21891++) {
        int64_t x_20306 = ((int64_t *) mem_22378.mem)[i_21891];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:302:31-35
        
        int64_t lifted_lambda_res_20311 = add64((int64_t) 1, x_20306);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:352:28-32
        
        int64_t lifted_lambda_res_20315 = mul64((int64_t) 2, x_20306);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:327:21-24
        
        int64_t defunc_0_op_res_17845 = add64(x_20306, scanacc_21883);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:353:36-39
        
        int64_t defunc_0_op_res_17942 = add64(lifted_lambda_res_20315, scanacc_21884);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:327:21-24
        
        int64_t defunc_0_op_res_17974 = add64(x_20306, scanacc_21885);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:305:34-37
        
        int64_t defunc_0_op_res_17731 = add64(x_20306, redout_21889);
        
        ((int64_t *) mem_22385.mem)[i_21891] = defunc_0_op_res_17845;
        ((int64_t *) mem_22386.mem)[i_21891] = defunc_0_op_res_17942;
        ((int64_t *) mem_22387.mem)[i_21891] = defunc_0_op_res_17974;
        ((int64_t *) mem_22388.mem)[i_21891] = lifted_lambda_res_20311;
        
        int64_t scanacc_tmp_22725 = defunc_0_op_res_17845;
        int64_t scanacc_tmp_22726 = defunc_0_op_res_17942;
        int64_t scanacc_tmp_22727 = defunc_0_op_res_17974;
        int64_t redout_tmp_22731 = defunc_0_op_res_17731;
        
        scanacc_21883 = scanacc_tmp_22725;
        scanacc_21884 = scanacc_tmp_22726;
        scanacc_21885 = scanacc_tmp_22727;
        redout_21889 = redout_tmp_22731;
    }
    discard_21896 = scanacc_21883;
    discard_21897 = scanacc_21884;
    discard_21898 = scanacc_21885;
    defunc_0_reduce_res_21103 = redout_21889;
    // ../lib/github.com/diku-dk/vtree/vtree.fut:302:51-56
    // Trace: trace
    fprintf(ctx->log, "%s", "trace: ");
    for (int64_t nest_i_22733 = 0; nest_i_22733 < (int64_t) 4; nest_i_22733++) {
        int64_t arr_elem_22734 = ((int64_t *) mem_22388.mem)[nest_i_22733];
        
        fprintf(ctx->log, "%lld%s", (long long) arr_elem_22734, " ");
    }
    fprintf(ctx->log, "%s", "\n");
    // ../lib/github.com/diku-dk/vtree/vtree.fut:132:24-36
    if (memblock_alloc(ctx, &mem_22413, (int64_t) 32, "mem_22413")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:132:24-36
    
    int64_t discard_21904;
    int64_t scanacc_21900 = (int64_t) 0;
    
    for (int64_t i_21902 = 0; i_21902 < (int64_t) 4; i_21902++) {
        int64_t x_17711 = ((int64_t *) mem_22388.mem)[i_21902];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:303:28-31
        
        int64_t defunc_0_op_res_17714 = add64(x_17711, scanacc_21900);
        
        ((int64_t *) mem_22413.mem)[i_21902] = defunc_0_op_res_17714;
        
        int64_t scanacc_tmp_22735 = defunc_0_op_res_17714;
        
        scanacc_21900 = scanacc_tmp_22735;
    }
    discard_21904 = scanacc_21900;
    if (memblock_unref(ctx, &mem_22388, "mem_22388") != 0)
        return 1;
    // ../lib/github.com/diku-dk/vtree/vtree.fut:130:5-132:37
    if (memblock_alloc(ctx, &mem_22420, (int64_t) 32, "mem_22420")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:130:5-132:37
    for (int64_t i_21907 = 0; i_21907 < (int64_t) 4; i_21907++) {
        // ../lib/github.com/diku-dk/vtree/vtree.fut:132:11-36
        
        int64_t zv_lhs_20270 = add64((int64_t) -1, i_21907);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:132:11-36
        
        int64_t tmp_20271 = smod64(zv_lhs_20270, (int64_t) 4);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:132:11-36
        
        int64_t lifted_lambda_res_20272 = ((int64_t *) mem_22413.mem)[tmp_20271];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:130:19-43
        
        bool cond_20274 = i_21907 == (int64_t) 0;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:130:19-43
        
        int64_t lifted_lambda_res_20275;
        
        if (cond_20274) {
            lifted_lambda_res_20275 = (int64_t) 0;
        } else {
            lifted_lambda_res_20275 = lifted_lambda_res_20272;
        }
        ((int64_t *) mem_22420.mem)[i_21907] = lifted_lambda_res_20275;
    }
    if (memblock_unref(ctx, &mem_22413, "mem_22413") != 0)
        return 1;
    // ../lib/github.com/diku-dk/vtree/vtree.fut:303:53-58
    // Trace: trace
    fprintf(ctx->log, "%s", "trace: ");
    for (int64_t nest_i_22738 = 0; nest_i_22738 < (int64_t) 4; nest_i_22738++) {
        int64_t arr_elem_22739 = ((int64_t *) mem_22420.mem)[nest_i_22738];
        
        fprintf(ctx->log, "%lld%s", (long long) arr_elem_22739, " ");
    }
    fprintf(ctx->log, "%s", "\n");
    // ../lib/github.com/diku-dk/vtree/vtree.fut:306:25-42
    
    int64_t result_sizze_17732 = add64((int64_t) 4, defunc_0_reduce_res_21103);
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:310:24-50
    if (memblock_alloc(ctx, &mem_22427, result_sizze_17732, "mem_22427")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:310:24-50
    for (int64_t nest_i_22740 = 0; nest_i_22740 < result_sizze_17732; nest_i_22740++) {
        ((bool *) mem_22427.mem)[nest_i_22740] = 1;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:220:13-33
    if (memblock_alloc(ctx, &mem_22428, (int64_t) 64, "mem_22428")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:220:13-33
    for (int64_t nest_i_22741 = 0; nest_i_22741 < (int64_t) 8; nest_i_22741++) {
        ((int64_t *) mem_22428.mem)[nest_i_22741] = (int64_t) 0;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:329:26-53
    
    int64_t bytes_22429 = (int64_t) 8 * defunc_0_reduce_res_21103;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:329:26-53
    if (memblock_alloc(ctx, &mem_22430, bytes_22429, "mem_22430")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:329:26-53
    for (int64_t nest_i_22742 = 0; nest_i_22742 < defunc_0_reduce_res_21103; nest_i_22742++) {
        ((int64_t *) mem_22430.mem)[nest_i_22742] = (int64_t) 0;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:329:26-53
    if (memblock_alloc(ctx, &mem_22432, bytes_22429, "mem_22432")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:329:26-53
    for (int64_t nest_i_22743 = 0; nest_i_22743 < defunc_0_reduce_res_21103; nest_i_22743++) {
        ((int64_t *) mem_22432.mem)[nest_i_22743] = (int64_t) 0;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:343:28-59
    if (memblock_alloc(ctx, &mem_22433, defunc_0_reduce_res_21103, "mem_22433")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:343:28-59
    for (int64_t nest_i_22744 = 0; nest_i_22744 < defunc_0_reduce_res_21103; nest_i_22744++) {
        ((bool *) mem_22433.mem)[nest_i_22744] = 0;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:316:41-82
    
    int64_t bytes_22434 = (int64_t) 8 * result_sizze_17732;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:316:41-82
    if (memblock_alloc(ctx, &mem_22435, bytes_22434, "mem_22435")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:316:41-82
    for (int64_t nest_i_22745 = 0; nest_i_22745 < result_sizze_17732; nest_i_22745++) {
        ((int64_t *) mem_22435.mem)[nest_i_22745] = (int64_t) 0;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:315:39-65
    if (memblock_alloc(ctx, &mem_22437, bytes_22434, "mem_22437")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:315:39-65
    for (int64_t nest_i_22746 = 0; nest_i_22746 < result_sizze_17732; nest_i_22746++) {
        ((int64_t *) mem_22437.mem)[nest_i_22746] = (int64_t) 0;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:314:39-65
    if (memblock_alloc(ctx, &mem_22439, bytes_22434, "mem_22439")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:314:39-65
    for (int64_t nest_i_22747 = 0; nest_i_22747 < result_sizze_17732; nest_i_22747++) {
        ((int64_t *) mem_22439.mem)[nest_i_22747] = (int64_t) 0;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:221:13-30
    
    bool acc_cert_17735;
    bool acc_cert_17790;
    bool acc_cert_17799;
    bool acc_cert_17811;
    bool acc_cert_17820;
    bool acc_cert_18027;
    bool acc_cert_18379;
    bool acc_cert_19272;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:221:13-30
    for (int64_t i_21914 = 0; i_21914 < (int64_t) 4; i_21914++) {
        int64_t v_20603 = ((int64_t *) mem_22360.mem)[i_21914];
        int64_t v_20604 = ((int64_t *) mem_22378.mem)[i_21914];
        int64_t v_20606 = ((int64_t *) mem_22420.mem)[i_21914];
        int64_t v_20607 = ((int64_t *) mem_22362.mem)[i_21914];
        int64_t v_20609 = ((int64_t *) mem_22361.mem)[i_21914];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:311:24-71
        // UpdateAcc
        if (sle64((int64_t) 0, v_20606) && slt64(v_20606, result_sizze_17732)) {
            ((bool *) mem_22427.mem)[v_20606] = 0;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:314:30-91
        // UpdateAcc
        if (sle64((int64_t) 0, v_20606) && slt64(v_20606, result_sizze_17732)) {
            ((int64_t *) mem_22439.mem)[v_20606] = v_20603;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:315:30-91
        // UpdateAcc
        if (sle64((int64_t) 0, v_20606) && slt64(v_20606, result_sizze_17732)) {
            ((int64_t *) mem_22437.mem)[v_20606] = v_20609;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:316:32-110
        // UpdateAcc
        if (sle64((int64_t) 0, v_20606) && slt64(v_20606, result_sizze_17732)) {
            ((int64_t *) mem_22435.mem)[v_20606] = v_20607;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:221:13-30
        // UpdateAcc
        if (sle64((int64_t) 0, v_20603) && slt64(v_20603, (int64_t) 8)) {
            ((int64_t *) mem_22428.mem)[v_20603] = v_20604;
        }
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:343:19-86
    for (int64_t i_21916 = 0; i_21916 < (int64_t) 2; i_21916++) {
        int64_t v_17824 = ((int64_t *) mem_22366.mem)[i_21916];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:343:19-86
        // UpdateAcc
        if (sle64((int64_t) 0, v_17824) && slt64(v_17824, defunc_0_reduce_res_21103)) {
            ((bool *) mem_22433.mem)[v_17824] = 1;
        }
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:328:16-329:65
    for (int64_t i_21919 = 0; i_21919 < (int64_t) 4; i_21919++) {
        // ../lib/github.com/diku-dk/vtree/vtree.fut:328:27-54
        
        bool cond_20578 = i_21919 == (int64_t) 0;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:328:27-54
        
        int64_t lifted_lambda_res_20579;
        
        if (cond_20578) {
            lifted_lambda_res_20579 = (int64_t) 0;
        } else {
            // ../lib/github.com/diku-dk/vtree/vtree.fut:328:51-53
            
            int64_t tmp_20580 = sub64(i_21919, (int64_t) 1);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:328:47-54
            
            bool x_20581 = sle64((int64_t) 0, tmp_20580);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:328:47-54
            
            bool y_20582 = slt64(tmp_20580, (int64_t) 4);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:328:47-54
            
            bool bounds_check_20583 = x_20581 && y_20582;
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:328:47-54
            
            bool index_certs_20584;
            
            if (!bounds_check_20583) {
                set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) tmp_20580, "] out of bounds for array of shape [", (long long) (int64_t) 4, "].", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:328:47-54\n   #1  ../lib/github.com/diku-dk/vtree/vtree.fut:334:34-38\n   #2  ../lib/github.com/diku-dk/vtree/vtree.fut:345:46-73\n   #3  test_operations.fut:123:7-142:98\n"));
                err = FUTHARK_PROGRAM_ERROR;
                goto cleanup;
            }
            // ../lib/github.com/diku-dk/vtree/vtree.fut:328:47-54
            
            int64_t lifted_lambda_res_f_res_20585 = ((int64_t *) mem_22385.mem)[tmp_20580];
            
            lifted_lambda_res_20579 = lifted_lambda_res_f_res_20585;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:329:17-65
        // UpdateAcc
        if (sle64((int64_t) 0, lifted_lambda_res_20579) && slt64(lifted_lambda_res_20579, defunc_0_reduce_res_21103)) {
            ((int64_t *) mem_22432.mem)[lifted_lambda_res_20579] = i_21919;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:328:27-54
        
        int64_t lifted_lambda_res_20590;
        
        if (cond_20578) {
            lifted_lambda_res_20590 = (int64_t) 0;
        } else {
            // ../lib/github.com/diku-dk/vtree/vtree.fut:328:51-53
            
            int64_t tmp_20591 = sub64(i_21919, (int64_t) 1);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:328:47-54
            
            bool x_20592 = sle64((int64_t) 0, tmp_20591);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:328:47-54
            
            bool y_20593 = slt64(tmp_20591, (int64_t) 4);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:328:47-54
            
            bool bounds_check_20594 = x_20592 && y_20593;
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:328:47-54
            
            bool index_certs_20595;
            
            if (!bounds_check_20594) {
                set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) tmp_20591, "] out of bounds for array of shape [", (long long) (int64_t) 4, "].", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:328:47-54\n   #1  ../lib/github.com/diku-dk/vtree/vtree.fut:334:34-38\n   #2  ../lib/github.com/diku-dk/vtree/vtree.fut:356:48-76\n   #3  test_operations.fut:123:7-142:98\n"));
                err = FUTHARK_PROGRAM_ERROR;
                goto cleanup;
            }
            // ../lib/github.com/diku-dk/vtree/vtree.fut:328:47-54
            
            int64_t lifted_lambda_res_f_res_20596 = ((int64_t *) mem_22387.mem)[tmp_20591];
            
            lifted_lambda_res_20590 = lifted_lambda_res_f_res_20596;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:329:17-65
        // UpdateAcc
        if (sle64((int64_t) 0, lifted_lambda_res_20590) && slt64(lifted_lambda_res_20590, defunc_0_reduce_res_21103)) {
            ((int64_t *) mem_22430.mem)[lifted_lambda_res_20590] = i_21919;
        }
    }
    if (memblock_unref(ctx, &mem_22362, "mem_22362") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22366, "mem_22366") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22385, "mem_22385") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22387, "mem_22387") != 0)
        return 1;
    // ../lib/github.com/diku-dk/vtree/vtree.fut:312:10-56
    if (memblock_alloc(ctx, &mem_22441, bytes_22434, "mem_22441")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:312:10-56
    if (memblock_alloc(ctx, &mem_22443, bytes_22434, "mem_22443")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:312:10-56
    
    int64_t discard_21928;
    int64_t scanacc_21922 = (int64_t) 0;
    
    for (int64_t i_21925 = 0; i_21925 < result_sizze_17732; i_21925++) {
        // ../lib/github.com/diku-dk/vtree/vtree.fut:312:24-37
        
        bool lifted_lambda_res_20264 = ((bool *) mem_22427.mem)[i_21925];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:312:10-56
        
        int64_t defunc_0_f_res_20265 = btoi_bool_i64(lifted_lambda_res_20264);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:312:10-56
        
        int64_t defunc_0_op_res_17754 = add64(defunc_0_f_res_20265, scanacc_21922);
        
        ((int64_t *) mem_22441.mem)[i_21925] = defunc_0_op_res_17754;
        ((int64_t *) mem_22443.mem)[i_21925] = defunc_0_f_res_20265;
        
        int64_t scanacc_tmp_22756 = defunc_0_op_res_17754;
        
        scanacc_21922 = scanacc_tmp_22756;
    }
    discard_21928 = scanacc_21922;
    if (memblock_unref(ctx, &mem_22427, "mem_22427") != 0)
        return 1;
    // ../lib/github.com/diku-dk/vtree/vtree.fut:312:10-56
    
    bool cond_17755 = result_sizze_17732 == (int64_t) 0;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:312:10-56
    
    bool x_17756 = !cond_17755;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:312:10-56
    
    int64_t tmp_17757 = sub64(result_sizze_17732, (int64_t) 1);
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:312:10-56
    
    bool x_17758 = sle64((int64_t) 0, tmp_17757);
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:312:10-56
    
    bool y_17759 = slt64(tmp_17757, result_sizze_17732);
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:312:10-56
    
    bool bounds_check_17760 = x_17758 && y_17759;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:312:10-56
    
    bool protect_assert_disj_17761 = cond_17755 || bounds_check_17760;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:312:10-56
    
    bool index_certs_17762;
    
    if (!protect_assert_disj_17761) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) tmp_17757, "] out of bounds for array of shape [", (long long) result_sizze_17732, "].", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:312:10-56\n   #1  test_operations.fut:123:7-142:98\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:312:10-56
    
    int64_t m_f_res_17763;
    
    if (x_17756) {
        // ../lib/github.com/diku-dk/vtree/vtree.fut:312:10-56
        
        int64_t x_20955 = ((int64_t *) mem_22441.mem)[tmp_17757];
        
        m_f_res_17763 = x_20955;
    } else {
        m_f_res_17763 = (int64_t) 0;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:312:10-56
    
    int64_t m_17765;
    
    if (cond_17755) {
        m_17765 = (int64_t) 0;
    } else {
        m_17765 = m_f_res_17763;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:312:10-56
    
    int64_t bytes_22456 = (int64_t) 8 * m_17765;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:312:10-56
    if (memblock_alloc(ctx, &mem_22457, bytes_22456, "mem_22457")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:312:10-56
    
    bool acc_cert_20230;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:312:10-56
    for (int64_t i_21930 = 0; i_21930 < result_sizze_17732; i_21930++) {
        int64_t eta_p_20245 = ((int64_t *) mem_22443.mem)[i_21930];
        int64_t eta_p_20246 = ((int64_t *) mem_22441.mem)[i_21930];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:312:10-56
        
        bool cond_20249 = eta_p_20245 == (int64_t) 1;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:312:10-56
        
        int64_t lifted_lambda_res_20250;
        
        if (cond_20249) {
            // ../lib/github.com/diku-dk/vtree/vtree.fut:312:10-56
            
            int64_t lifted_lambda_res_t_res_20956 = sub64(eta_p_20246, (int64_t) 1);
            
            lifted_lambda_res_20250 = lifted_lambda_res_t_res_20956;
        } else {
            lifted_lambda_res_20250 = (int64_t) -1;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:312:10-56
        // UpdateAcc
        if (sle64((int64_t) 0, lifted_lambda_res_20250) && slt64(lifted_lambda_res_20250, m_17765)) {
            ((int64_t *) mem_22457.mem)[lifted_lambda_res_20250] = i_21930;
        }
    }
    if (memblock_unref(ctx, &mem_22441, "mem_22441") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22443, "mem_22443") != 0)
        return 1;
    // test_operations.fut:123:7-142:98
    
    bool eq_x_y_17781 = defunc_0_reduce_res_21103 == (int64_t) 0;
    
    // test_operations.fut:123:7-142:98
    
    bool eq_x_zz_17782 = defunc_0_reduce_res_21103 == m_f_res_17763;
    
    // test_operations.fut:123:7-142:98
    
    bool p_and_eq_x_y_17783 = cond_17755 && eq_x_y_17781;
    
    // test_operations.fut:123:7-142:98
    
    bool p_and_eq_x_y_17784 = x_17756 && eq_x_zz_17782;
    
    // test_operations.fut:123:7-142:98
    
    bool dim_match_17785 = p_and_eq_x_y_17783 || p_and_eq_x_y_17784;
    
    // test_operations.fut:123:7-142:98
    
    bool empty_or_match_cert_17786;
    
    if (!dim_match_17785) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (desugared) shape [", (long long) m_17765, "] cannot match shape of type \"[", (long long) defunc_0_reduce_res_21103, "]i64\".", "-> #0  test_operations.fut:123:7-142:98\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:348:28-103
    if (memblock_alloc(ctx, &mem_22475, bytes_22429, "mem_22475")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:348:28-103
    if (memblock_alloc(ctx, &mem_22477, bytes_22429, "mem_22477")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:346:10-350:109
    if (memblock_alloc(ctx, &mem_22459, bytes_22429, "mem_22459")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:346:10-350:109
    if (memblock_alloc(ctx, &mem_22461, bytes_22429, "mem_22461")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:348:28-103
    
    bool acc_cert_19629;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:346:10-350:109
    
    int64_t inpacc_20975;
    int64_t inpacc_20977;
    int64_t inpacc_19784;
    int64_t inpacc_19786;
    
    inpacc_19784 = (int64_t) 0;
    inpacc_19786 = (int64_t) 0;
    for (int64_t i_22011 = 0; i_22011 < defunc_0_reduce_res_21103; i_22011++) {
        bool x_22208 = ((bool *) mem_22433.mem)[i_22011];
        int64_t eta_p_22224 = ((int64_t *) mem_22432.mem)[i_22011];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:330:23-27
        
        bool lifted_lambda_res_22225 = slt64((int64_t) 0, eta_p_22224);
        int64_t v_22253 = ((int64_t *) mem_22457.mem)[i_22011];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:321:35-61
        
        int64_t v_22255;
        
        if (x_22208) {
            v_22255 = (int64_t) 1;
        } else {
            // ../lib/github.com/diku-dk/vtree/vtree.fut:338:34-37
            
            int64_t defunc_0_g_res_22256 = add64((int64_t) 1, inpacc_19784);
            
            v_22255 = defunc_0_g_res_22256;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:339:22-24
        
        int64_t lifted_lambda_res_22257 = sub64(v_22255, (int64_t) 1);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:321:35-61
        
        int64_t v_22259;
        
        if (lifted_lambda_res_22225) {
            v_22259 = eta_p_22224;
        } else {
            // ../lib/github.com/diku-dk/vtree/vtree.fut:331:25-28
            
            int64_t defunc_0_g_res_22260 = add64(inpacc_19786, eta_p_22224);
            
            v_22259 = defunc_0_g_res_22260;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:335:21-26
        
        bool x_22261 = sle64((int64_t) 0, v_22259);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:335:21-26
        
        bool y_22262 = slt64(v_22259, (int64_t) 4);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:335:21-26
        
        bool bounds_check_22263 = x_22261 && y_22262;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:335:21-26
        
        bool index_certs_22264;
        
        if (!bounds_check_22263) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) v_22259, "] out of bounds for array of shape [", (long long) (int64_t) 4, "].", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:335:21-26\n   #1  ../lib/github.com/diku-dk/vtree/vtree.fut:345:46-73\n   #2  test_operations.fut:123:7-142:98\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:335:21-26
        
        int64_t lifted_lambda_res_22265 = ((int64_t *) mem_22367.mem)[v_22259];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:346:15-18
        
        int64_t defunc_0_f_res_22266 = add64(lifted_lambda_res_22257, lifted_lambda_res_22265);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:348:76-90
        
        bool x_22267 = sle64((int64_t) 0, defunc_0_f_res_22266);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:348:76-90
        
        bool y_22268 = slt64(defunc_0_f_res_22266, (int64_t) 5);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:348:76-90
        
        bool bounds_check_22269 = x_22267 && y_22268;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:348:76-90
        
        bool index_certs_22270;
        
        if (!bounds_check_22269) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) defunc_0_f_res_22266, "] out of bounds for array of shape [", (long long) (int64_t) 5, "].", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:348:76-90\n   #1  test_operations.fut:123:7-142:98\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:348:76-90
        
        int64_t lifted_lambda_res_22271 = ((int64_t *) mem_22363.mem)[defunc_0_f_res_22266];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:348:28-103
        // UpdateAcc
        if (sle64((int64_t) 0, v_22253) && slt64(v_22253, result_sizze_17732)) {
            ((int64_t *) mem_22439.mem)[v_22253] = lifted_lambda_res_22271;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:350:80-96
        
        int64_t lifted_lambda_res_22273 = ((int64_t *) mem_22365.mem)[defunc_0_f_res_22266];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:349:76-90
        
        int64_t lifted_lambda_res_22274 = ((int64_t *) mem_22364.mem)[defunc_0_f_res_22266];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:321:35-61
        
        int64_t v_19824;
        
        if (x_22208) {
            v_19824 = (int64_t) 1;
        } else {
            // ../lib/github.com/diku-dk/vtree/vtree.fut:338:34-37
            
            int64_t defunc_0_g_res_19825 = add64((int64_t) 1, inpacc_19784);
            
            v_19824 = defunc_0_g_res_19825;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:321:35-61
        
        int64_t v_19887;
        
        if (lifted_lambda_res_22225) {
            v_19887 = eta_p_22224;
        } else {
            // ../lib/github.com/diku-dk/vtree/vtree.fut:331:25-28
            
            int64_t defunc_0_g_res_19888 = add64(inpacc_19786, eta_p_22224);
            
            v_19887 = defunc_0_g_res_19888;
        }
        ((int64_t *) mem_22459.mem)[i_22011] = lifted_lambda_res_22274;
        ((int64_t *) mem_22461.mem)[i_22011] = lifted_lambda_res_22273;
        
        int64_t inpacc_tmp_22760 = v_19824;
        int64_t inpacc_tmp_22761 = v_19887;
        
        inpacc_19784 = inpacc_tmp_22760;
        inpacc_19786 = inpacc_tmp_22761;
    }
    inpacc_20975 = inpacc_19784;
    inpacc_20977 = inpacc_19786;
    // ../lib/github.com/diku-dk/vtree/vtree.fut:348:28-103
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_22475.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) mem_22461.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {defunc_0_reduce_res_21103});
    // ../lib/github.com/diku-dk/vtree/vtree.fut:348:28-103
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_22477.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) mem_22459.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {defunc_0_reduce_res_21103});
    if (memblock_unref(ctx, &mem_22363, "mem_22363") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22364, "mem_22364") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22365, "mem_22365") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22367, "mem_22367") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22432, "mem_22432") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22433, "mem_22433") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22459, "mem_22459") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22461, "mem_22461") != 0)
        return 1;
    // test_operations.fut:144:5-147:59
    
    bool cond_11819 = result_sizze_17732 == (int64_t) 11;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:367:39-65
    if (memblock_alloc(ctx, &mem_22479, bytes_22434, "mem_22479")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:367:39-65
    for (int64_t nest_i_22765 = 0; nest_i_22765 < result_sizze_17732; nest_i_22765++) {
        ((int64_t *) mem_22479.mem)[nest_i_22765] = (int64_t) 0;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:132:24-36
    if (memblock_alloc(ctx, &mem_22480, (int64_t) 64, "mem_22480")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:132:24-36
    
    int64_t discard_22028;
    int64_t scanacc_22024 = (int64_t) 0;
    
    for (int64_t i_22026 = 0; i_22026 < (int64_t) 8; i_22026++) {
        int64_t x_18035 = ((int64_t *) mem_22428.mem)[i_22026];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:364:33-36
        
        int64_t defunc_0_op_res_18038 = add64(x_18035, scanacc_22024);
        
        ((int64_t *) mem_22480.mem)[i_22026] = defunc_0_op_res_18038;
        
        int64_t scanacc_tmp_22766 = defunc_0_op_res_18038;
        
        scanacc_22024 = scanacc_tmp_22766;
    }
    discard_22028 = scanacc_22024;
    if (memblock_unref(ctx, &mem_22428, "mem_22428") != 0)
        return 1;
    // ../lib/github.com/diku-dk/vtree/vtree.fut:130:5-132:37
    if (memblock_alloc(ctx, &mem_22487, (int64_t) 64, "mem_22487")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:130:5-132:37
    for (int64_t i_22031 = 0; i_22031 < (int64_t) 8; i_22031++) {
        // ../lib/github.com/diku-dk/vtree/vtree.fut:132:11-36
        
        int64_t zv_lhs_18190 = add64((int64_t) -1, i_22031);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:132:11-36
        
        int64_t tmp_18191 = smod64(zv_lhs_18190, (int64_t) 8);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:132:11-36
        
        int64_t lifted_lambda_res_18192 = ((int64_t *) mem_22480.mem)[tmp_18191];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:130:19-43
        
        bool cond_18194 = i_22031 == (int64_t) 0;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:130:19-43
        
        int64_t lifted_lambda_res_18195;
        
        if (cond_18194) {
            lifted_lambda_res_18195 = (int64_t) 0;
        } else {
            lifted_lambda_res_18195 = lifted_lambda_res_18192;
        }
        ((int64_t *) mem_22487.mem)[i_22031] = lifted_lambda_res_18195;
    }
    if (memblock_unref(ctx, &mem_22480, "mem_22480") != 0)
        return 1;
    // ../lib/github.com/diku-dk/vtree/vtree.fut:354:39-65
    if (memblock_alloc(ctx, &mem_22495, bytes_22434, "mem_22495")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:354:39-65
    for (int64_t nest_i_22769 = 0; nest_i_22769 < result_sizze_17732; nest_i_22769++) {
        ((int64_t *) mem_22495.mem)[nest_i_22769] = (int64_t) 0;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:354:22-367:100
    for (int64_t iter_22033 = 0; iter_22033 < (int64_t) 4; iter_22033++) {
        int64_t pixel_22036 = ((int64_t *) mem_22378.mem)[iter_22033];
        int64_t pixel_22037 = ((int64_t *) mem_22361.mem)[iter_22033];
        int64_t pixel_22038 = ((int64_t *) mem_22360.mem)[iter_22033];
        int64_t pixel_22039 = ((int64_t *) mem_22420.mem)[iter_22033];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:132:11-36
        
        int64_t zv_lhs_20326 = add64((int64_t) -1, iter_22033);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:132:11-36
        
        int64_t tmp_20327 = smod64(zv_lhs_20326, (int64_t) 4);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:132:11-36
        
        int64_t lifted_lambda_res_20328 = ((int64_t *) mem_22386.mem)[tmp_20327];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:130:19-43
        
        bool cond_20330 = iter_22033 == (int64_t) 0;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:130:19-43
        
        int64_t lifted_lambda_res_20331;
        
        if (cond_20330) {
            lifted_lambda_res_20331 = (int64_t) 0;
        } else {
            lifted_lambda_res_20331 = lifted_lambda_res_20328;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:364:37-44
        
        int64_t neg_res_20333 = -pixel_22036;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:223:25-29
        
        bool x_20335 = sle64((int64_t) 0, pixel_22037);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:223:25-29
        
        bool y_20336 = slt64(pixel_22037, (int64_t) 8);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:223:25-29
        
        bool bounds_check_20337 = x_20335 && y_20336;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:223:25-29
        
        bool index_certs_20338;
        
        if (!bounds_check_20337) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) pixel_22037, "] out of bounds for array of shape [", (long long) (int64_t) 8, "].", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:223:25-29\n   #1  ../lib/github.com/diku-dk/vtree/vtree.fut:227:63-228:22\n   #2  ../lib/github.com/diku-dk/vtree/vtree.fut:359:9-364:32\n   #3  test_operations.fut:123:7-142:98\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:223:25-29
        
        int64_t lifted_lambda_res_20339 = ((int64_t *) mem_22487.mem)[pixel_22037];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:224:30-34
        
        bool x_20341 = sle64((int64_t) 0, pixel_22038);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:224:30-34
        
        bool y_20342 = slt64(pixel_22038, (int64_t) 8);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:224:30-34
        
        bool bounds_check_20343 = x_20341 && y_20342;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:224:30-34
        
        bool index_certs_20344;
        
        if (!bounds_check_20343) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) pixel_22038, "] out of bounds for array of shape [", (long long) (int64_t) 8, "].", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:224:30-34\n   #1  ../lib/github.com/diku-dk/vtree/vtree.fut:227:63-228:22\n   #2  ../lib/github.com/diku-dk/vtree/vtree.fut:359:9-364:32\n   #3  test_operations.fut:123:7-142:98\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:224:30-34
        
        int64_t inv_arg0_20345 = ((int64_t *) mem_22487.mem)[pixel_22038];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:364:37-44
        
        int64_t neg_res_20346 = -inv_arg0_20345;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:364:33-36
        
        int64_t defunc_0_f_res_20348 = add64(lifted_lambda_res_20339, neg_res_20346);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:364:33-36
        
        int64_t defunc_0_f_res_20350 = add64(neg_res_20333, defunc_0_f_res_20348);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:365:34-37
        
        int64_t defunc_0_f_res_20353 = add64(defunc_0_f_res_20350, pixel_22039);
        bool less_than_zzero_22042 = slt64(pixel_22039, (int64_t) 0);
        bool greater_than_sizze_22043 = sle64(result_sizze_17732, pixel_22039);
        bool outside_bounds_dim_22044 = less_than_zzero_22042 || greater_than_sizze_22043;
        
        if (!outside_bounds_dim_22044) {
            int64_t read_hist_22046 = ((int64_t *) mem_22479.mem)[pixel_22039];
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:367:67-70
            
            int64_t defunc_0_f_res_18081 = add64(defunc_0_f_res_20353, read_hist_22046);
            
            ((int64_t *) mem_22479.mem)[pixel_22039] = defunc_0_f_res_18081;
        }
        if (!outside_bounds_dim_22044) {
            int64_t read_hist_22053 = ((int64_t *) mem_22495.mem)[pixel_22039];
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:354:67-70
            
            int64_t defunc_0_f_res_17957 = add64(lifted_lambda_res_20331, read_hist_22053);
            
            ((int64_t *) mem_22495.mem)[pixel_22039] = defunc_0_f_res_17957;
        }
    }
    if (memblock_unref(ctx, &mem_22360, "mem_22360") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22361, "mem_22361") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22378, "mem_22378") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22386, "mem_22386") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22487, "mem_22487") != 0)
        return 1;
    // ../lib/github.com/diku-dk/vtree/vtree.fut:355:28-89
    if (memblock_alloc(ctx, &mem_22508, (int64_t) 32, "mem_22508")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:355:28-89
    for (int64_t i_22058 = 0; i_22058 < (int64_t) 4; i_22058++) {
        int64_t eta_p_17961 = ((int64_t *) mem_22420.mem)[i_22058];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:355:39-58
        
        bool x_17962 = sle64((int64_t) 0, eta_p_17961);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:355:39-58
        
        bool y_17963 = slt64(eta_p_17961, result_sizze_17732);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:355:39-58
        
        bool bounds_check_17964 = x_17962 && y_17963;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:355:39-58
        
        bool index_certs_17965;
        
        if (!bounds_check_17964) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) eta_p_17961, "] out of bounds for array of shape [", (long long) result_sizze_17732, "].", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:355:39-58\n   #1  test_operations.fut:123:7-142:98\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:355:39-58
        
        int64_t zp_lhs_17966 = ((int64_t *) mem_22439.mem)[eta_p_17961];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:355:61-74
        
        int64_t zp_rhs_17967 = ((int64_t *) mem_22495.mem)[eta_p_17961];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:355:59-74
        
        int64_t zp_lhs_17968 = add64(zp_lhs_17966, zp_rhs_17967);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:355:75-78
        
        int64_t lifted_lambda_res_17969 = add64((int64_t) 1, zp_lhs_17968);
        
        ((int64_t *) mem_22508.mem)[i_22058] = lifted_lambda_res_17969;
    }
    if (memblock_unref(ctx, &mem_22420, "mem_22420") != 0)
        return 1;
    // ../lib/github.com/diku-dk/vtree/vtree.fut:335:10-32
    if (memblock_alloc(ctx, &mem_22516, bytes_22429, "mem_22516")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:335:10-32
    
    int64_t inpacc_21114;
    int64_t inpacc_18328 = (int64_t) 0;
    
    for (int64_t i_22077 = 0; i_22077 < defunc_0_reduce_res_21103; i_22077++) {
        int64_t eta_p_22175 = ((int64_t *) mem_22430.mem)[i_22077];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:330:23-27
        
        bool lifted_lambda_res_22176 = slt64((int64_t) 0, eta_p_22175);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:321:35-61
        
        int64_t v_22190;
        
        if (lifted_lambda_res_22176) {
            v_22190 = eta_p_22175;
        } else {
            // ../lib/github.com/diku-dk/vtree/vtree.fut:331:25-28
            
            int64_t defunc_0_g_res_22191 = add64(inpacc_18328, eta_p_22175);
            
            v_22190 = defunc_0_g_res_22191;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:335:21-26
        
        bool x_22192 = sle64((int64_t) 0, v_22190);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:335:21-26
        
        bool y_22193 = slt64(v_22190, (int64_t) 4);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:335:21-26
        
        bool bounds_check_22194 = x_22192 && y_22193;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:335:21-26
        
        bool index_certs_22195;
        
        if (!bounds_check_22194) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) v_22190, "] out of bounds for array of shape [", (long long) (int64_t) 4, "].", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:335:21-26\n   #1  ../lib/github.com/diku-dk/vtree/vtree.fut:356:48-76\n   #2  test_operations.fut:123:7-142:98\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:335:21-26
        
        int64_t lifted_lambda_res_22196 = ((int64_t *) mem_22508.mem)[v_22190];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:321:35-61
        
        int64_t v_18367;
        
        if (lifted_lambda_res_22176) {
            v_18367 = eta_p_22175;
        } else {
            // ../lib/github.com/diku-dk/vtree/vtree.fut:331:25-28
            
            int64_t defunc_0_g_res_18368 = add64(inpacc_18328, eta_p_22175);
            
            v_18367 = defunc_0_g_res_18368;
        }
        ((int64_t *) mem_22516.mem)[i_22077] = lifted_lambda_res_22196;
        
        int64_t inpacc_tmp_22773 = v_18367;
        
        inpacc_18328 = inpacc_tmp_22773;
    }
    inpacc_21114 = inpacc_18328;
    if (memblock_unref(ctx, &mem_22430, "mem_22430") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22508, "mem_22508") != 0)
        return 1;
    // test_operations.fut:144:5-147:59
    
    bool cond_11820;
    
    if (cond_11819) {
        // ../lib/github.com/diku-dk/vtree/vtree.fut:357:22-80
        for (int64_t iter_22079 = 0; iter_22079 < defunc_0_reduce_res_21103; iter_22079++) {
            int64_t pixel_22081 = ((int64_t *) mem_22457.mem)[iter_22079];
            int64_t pixel_22082 = ((int64_t *) mem_22516.mem)[iter_22079];
            bool less_than_zzero_22083 = slt64(pixel_22081, (int64_t) 0);
            bool greater_than_sizze_22084 = sle64(result_sizze_17732, pixel_22081);
            bool outside_bounds_dim_22085 = less_than_zzero_22083 || greater_than_sizze_22084;
            
            if (!outside_bounds_dim_22085) {
                int64_t read_hist_22087 = ((int64_t *) mem_22495.mem)[pixel_22081];
                
                // ../lib/github.com/diku-dk/vtree/vtree.fut:357:49-52
                
                int64_t defunc_0_f_res_21071 = add64(pixel_22082, read_hist_22087);
                
                ((int64_t *) mem_22495.mem)[pixel_22081] = defunc_0_f_res_21071;
            }
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:370:18-54
        if (memblock_alloc(ctx, &mem_22530, bytes_22434, "mem_22530")) {
            err = 1;
            goto cleanup;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:370:18-54
        for (int64_t i_22092 = 0; i_22092 < result_sizze_17732; i_22092++) {
            int64_t eta_p_21078 = ((int64_t *) mem_22439.mem)[i_22092];
            int64_t eta_p_21079 = ((int64_t *) mem_22495.mem)[i_22092];
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:370:23-26
            
            int64_t defunc_0_f_res_21080 = add64(eta_p_21078, eta_p_21079);
            
            ((int64_t *) mem_22530.mem)[i_22092] = defunc_0_f_res_21080;
        }
        // test_operations.fut:145:21-41
        
        bool dim_match_21084 = (int64_t) 11 == result_sizze_17732;
        
        // test_operations.fut:145:21-41
        
        bool empty_or_match_cert_21085;
        
        if (!dim_match_21084) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (desugared) shape [", (long long) result_sizze_17732, "] cannot match shape of type \"[", (long long) (int64_t) 11, "]i64\".", "-> #0  test_operations.fut:145:21-41\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        // test_operations.fut:145:5-54
        
        bool defunc_0_reduce_res_21087;
        bool redout_22094 = 1;
        
        for (int64_t i_22095 = 0; i_22095 < (int64_t) 11; i_22095++) {
            int64_t eta_p_21088 = ((int64_t *) mem_22530.mem)[i_22095];
            int64_t eta_p_21089 = ((int64_t *) mem_22368.mem)[i_22095];
            
            // test_operations.fut:145:15-19
            
            bool defunc_0_f_res_21090 = eta_p_21088 == eta_p_21089;
            
            // test_operations.fut:145:5-54
            
            bool x_21093 = defunc_0_f_res_21090 && redout_22094;
            bool redout_tmp_22777 = x_21093;
            
            redout_22094 = redout_tmp_22777;
        }
        defunc_0_reduce_res_21087 = redout_22094;
        if (memblock_unref(ctx, &mem_22530, "mem_22530") != 0)
            return 1;
        cond_11820 = defunc_0_reduce_res_21087;
    } else {
        cond_11820 = 0;
    }
    if (memblock_unref(ctx, &mem_22368, "mem_22368") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22439, "mem_22439") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22495, "mem_22495") != 0)
        return 1;
    // test_operations.fut:144:5-147:59
    
    bool cond_11829;
    
    if (cond_11820) {
        // ../lib/github.com/diku-dk/vtree/vtree.fut:349:28-103
        
        bool acc_cert_20997;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:349:28-103
        for (int64_t i_22097 = 0; i_22097 < defunc_0_reduce_res_21103; i_22097++) {
            int64_t v_21001 = ((int64_t *) mem_22457.mem)[i_22097];
            int64_t v_21002 = ((int64_t *) mem_22477.mem)[i_22097];
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:349:28-103
            // UpdateAcc
            if (sle64((int64_t) 0, v_21001) && slt64(v_21001, result_sizze_17732)) {
                ((int64_t *) mem_22437.mem)[v_21001] = v_21002;
            }
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:368:22-80
        for (int64_t iter_22098 = 0; iter_22098 < defunc_0_reduce_res_21103; iter_22098++) {
            int64_t pixel_22100 = ((int64_t *) mem_22457.mem)[iter_22098];
            int64_t pixel_22101 = ((int64_t *) mem_22516.mem)[iter_22098];
            bool less_than_zzero_22102 = slt64(pixel_22100, (int64_t) 0);
            bool greater_than_sizze_22103 = sle64(result_sizze_17732, pixel_22100);
            bool outside_bounds_dim_22104 = less_than_zzero_22102 || greater_than_sizze_22103;
            
            if (!outside_bounds_dim_22104) {
                int64_t read_hist_22106 = ((int64_t *) mem_22479.mem)[pixel_22100];
                
                // ../lib/github.com/diku-dk/vtree/vtree.fut:368:49-52
                
                int64_t defunc_0_f_res_21008 = add64(pixel_22101, read_hist_22106);
                
                ((int64_t *) mem_22479.mem)[pixel_22100] = defunc_0_f_res_21008;
            }
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:371:18-54
        if (memblock_alloc(ctx, &mem_22544, bytes_22434, "mem_22544")) {
            err = 1;
            goto cleanup;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:371:18-54
        for (int64_t i_22111 = 0; i_22111 < result_sizze_17732; i_22111++) {
            int64_t eta_p_21015 = ((int64_t *) mem_22437.mem)[i_22111];
            int64_t eta_p_21016 = ((int64_t *) mem_22479.mem)[i_22111];
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:371:23-26
            
            int64_t defunc_0_f_res_21017 = add64(eta_p_21015, eta_p_21016);
            
            ((int64_t *) mem_22544.mem)[i_22111] = defunc_0_f_res_21017;
        }
        // test_operations.fut:146:21-41
        
        bool dim_match_21021 = (int64_t) 11 == result_sizze_17732;
        
        // test_operations.fut:146:21-41
        
        bool empty_or_match_cert_21022;
        
        if (!dim_match_21021) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (desugared) shape [", (long long) result_sizze_17732, "] cannot match shape of type \"[", (long long) (int64_t) 11, "]i64\".", "-> #0  test_operations.fut:146:21-41\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        // test_operations.fut:146:5-54
        
        bool defunc_0_reduce_res_21024;
        bool redout_22113 = 1;
        
        for (int64_t i_22114 = 0; i_22114 < (int64_t) 11; i_22114++) {
            int64_t eta_p_21025 = ((int64_t *) mem_22544.mem)[i_22114];
            int64_t eta_p_21026 = ((int64_t *) mem_22369.mem)[i_22114];
            
            // test_operations.fut:146:15-19
            
            bool defunc_0_f_res_21027 = eta_p_21025 == eta_p_21026;
            
            // test_operations.fut:146:5-54
            
            bool x_21030 = defunc_0_f_res_21027 && redout_22113;
            bool redout_tmp_22781 = x_21030;
            
            redout_22113 = redout_tmp_22781;
        }
        defunc_0_reduce_res_21024 = redout_22113;
        if (memblock_unref(ctx, &mem_22544, "mem_22544") != 0)
            return 1;
        cond_11829 = defunc_0_reduce_res_21024;
    } else {
        cond_11829 = 0;
    }
    if (memblock_unref(ctx, &mem_22369, "mem_22369") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22437, "mem_22437") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22477, "mem_22477") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22479, "mem_22479") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22516, "mem_22516") != 0)
        return 1;
    // test_operations.fut:144:5-147:59
    if (cond_11829) {
        // ../lib/github.com/diku-dk/vtree/vtree.fut:350:30-109
        
        bool acc_cert_21040;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:350:30-109
        for (int64_t i_22116 = 0; i_22116 < defunc_0_reduce_res_21103; i_22116++) {
            int64_t v_21044 = ((int64_t *) mem_22457.mem)[i_22116];
            int64_t v_21045 = ((int64_t *) mem_22475.mem)[i_22116];
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:350:30-109
            // UpdateAcc
            if (sle64((int64_t) 0, v_21044) && slt64(v_21044, result_sizze_17732)) {
                ((int64_t *) mem_22435.mem)[v_21044] = v_21045;
            }
        }
        // test_operations.fut:147:21-43
        
        bool dim_match_21048 = (int64_t) 11 == result_sizze_17732;
        
        // test_operations.fut:147:21-43
        
        bool empty_or_match_cert_21049;
        
        if (!dim_match_21048) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (desugared) shape [", (long long) result_sizze_17732, "] cannot match shape of type \"[", (long long) (int64_t) 11, "]i64\".", "-> #0  test_operations.fut:147:21-43\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        // test_operations.fut:147:5-58
        
        bool defunc_0_reduce_res_21051;
        bool redout_22117 = 1;
        
        for (int64_t i_22118 = 0; i_22118 < (int64_t) 11; i_22118++) {
            int64_t eta_p_21052 = ((int64_t *) mem_22435.mem)[i_22118];
            int64_t eta_p_21053 = ((int64_t *) mem_22370.mem)[i_22118];
            
            // test_operations.fut:147:15-19
            
            bool defunc_0_f_res_21054 = eta_p_21052 == eta_p_21053;
            
            // test_operations.fut:147:5-58
            
            bool x_21057 = defunc_0_f_res_21054 && redout_22117;
            bool redout_tmp_22783 = x_21057;
            
            redout_22117 = redout_tmp_22783;
        }
        defunc_0_reduce_res_21051 = redout_22117;
        ok_11838 = defunc_0_reduce_res_21051;
    } else {
        ok_11838 = 0;
    }
    if (memblock_unref(ctx, &mem_22370, "mem_22370") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22435, "mem_22435") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22457, "mem_22457") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22475, "mem_22475") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22544, "mem_22544") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22530, "mem_22530") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22516, "mem_22516") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22508, "mem_22508") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22495, "mem_22495") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22487, "mem_22487") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22480, "mem_22480") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22479, "mem_22479") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22461, "mem_22461") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22459, "mem_22459") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22477, "mem_22477") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22475, "mem_22475") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22457, "mem_22457") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22443, "mem_22443") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22441, "mem_22441") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22439, "mem_22439") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22437, "mem_22437") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22435, "mem_22435") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22433, "mem_22433") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22432, "mem_22432") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22430, "mem_22430") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22428, "mem_22428") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22427, "mem_22427") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22420, "mem_22420") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22413, "mem_22413") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22388, "mem_22388") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22387, "mem_22387") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22386, "mem_22386") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22385, "mem_22385") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22378, "mem_22378") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22371, "mem_22371") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22370, "mem_22370") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22369, "mem_22369") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22368, "mem_22368") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22367, "mem_22367") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22366, "mem_22366") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22365, "mem_22365") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22364, "mem_22364") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22363, "mem_22363") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22362, "mem_22362") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22361, "mem_22361") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22360, "mem_22360") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22359, "mem_22359") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_22356, "ext_mem_22356") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_22357, "ext_mem_22357") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_22358, "ext_mem_22358") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22355, "mem_22355") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_22348, "ext_mem_22348") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_22349, "ext_mem_22349") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_22350, "ext_mem_22350") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_22351, "ext_mem_22351") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_22352, "ext_mem_22352") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_22353, "ext_mem_22353") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_22354, "ext_mem_22354") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22347, "mem_22347") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22346, "mem_22346") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_22339, "ext_mem_22339") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_22340, "ext_mem_22340") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_22341, "ext_mem_22341") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_22342, "ext_mem_22342") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_22343, "ext_mem_22343") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_22344, "ext_mem_22344") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_22345, "ext_mem_22345") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22338, "mem_22338") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_22331, "ext_mem_22331") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_22332, "ext_mem_22332") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_22333, "ext_mem_22333") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_22334, "ext_mem_22334") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_22335, "ext_mem_22335") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_22336, "ext_mem_22336") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_22337, "ext_mem_22337") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22330, "mem_22330") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22329, "mem_22329") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22328, "mem_22328") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22327, "mem_22327") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22326, "mem_22326") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22325, "mem_22325") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22324, "mem_22324") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22323, "mem_22323") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_22316, "ext_mem_22316") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_22317, "ext_mem_22317") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_22318, "ext_mem_22318") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_22319, "ext_mem_22319") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_22320, "ext_mem_22320") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_22321, "ext_mem_22321") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_22322, "ext_mem_22322") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22315, "mem_22315") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22314, "mem_22314") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22313, "mem_22313") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_22312, "mem_22312") != 0)
        return 1;
    #undef ok_11754
    #undef ok_11838
    #undef x_16121
    #undef x_16124
    #undef x_16130
    #undef x_16136
    
  cleanup:
    return err;
}
static int free_constants(struct futhark_context *ctx)
{
    (void) ctx;
    return 0;
}

FUTHARK_FUN_ATTR int futrts_deleteVertices_7461(struct futhark_context *ctx, struct memblock *mem_out_p_22811, struct memblock *mem_out_p_22812, struct memblock *mem_out_p_22813, int64_t *out_prim_out_22814, struct memblock data_mem_22551, struct memblock lp_mem_22552, struct memblock rp_mem_22553, struct memblock keep_mem_22554, int64_t n_12702)
{
    (void) ctx;
    
    int err = 0;
    int64_t mem_22556_cached_sizze_22815 = 0;
    unsigned char *mem_22556 = NULL;
    int64_t mem_22558_cached_sizze_22816 = 0;
    unsigned char *mem_22558 = NULL;
    int64_t mem_22560_cached_sizze_22817 = 0;
    unsigned char *mem_22560 = NULL;
    int64_t mem_22562_cached_sizze_22818 = 0;
    unsigned char *mem_22562 = NULL;
    int64_t mem_22564_cached_sizze_22819 = 0;
    unsigned char *mem_22564 = NULL;
    int64_t mem_22566_cached_sizze_22820 = 0;
    unsigned char *mem_22566 = NULL;
    int64_t mem_22603_cached_sizze_22821 = 0;
    unsigned char *mem_22603 = NULL;
    int64_t mem_22605_cached_sizze_22822 = 0;
    unsigned char *mem_22605 = NULL;
    int64_t mem_22607_cached_sizze_22823 = 0;
    unsigned char *mem_22607 = NULL;
    int64_t mem_22615_cached_sizze_22824 = 0;
    unsigned char *mem_22615 = NULL;
    int64_t mem_22617_cached_sizze_22825 = 0;
    unsigned char *mem_22617 = NULL;
    struct memblock mem_22623;
    
    mem_22623.references = NULL;
    
    struct memblock mem_22621;
    
    mem_22621.references = NULL;
    
    struct memblock mem_22619;
    
    mem_22619.references = NULL;
    
    struct memblock mem_out_22653;
    
    mem_out_22653.references = NULL;
    
    struct memblock mem_out_22652;
    
    mem_out_22652.references = NULL;
    
    struct memblock mem_out_22651;
    
    mem_out_22651.references = NULL;
    
    bool ok_11754 = ctx->constants->ok_11754;
    bool ok_11838 = ctx->constants->ok_11838;
    bool x_16121 = ctx->constants->x_16121;
    bool x_16124 = ctx->constants->x_16124;
    bool x_16130 = ctx->constants->x_16130;
    bool x_16136 = ctx->constants->x_16136;
    int64_t prim_out_22654;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:242:27-32
    
    int64_t dzlz7bUZLztZRz20U2z20Unz7dUzg_12707 = mul64((int64_t) 2, n_12702);
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    
    int64_t bytes_22555 = (int64_t) 8 * n_12702;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    if (mem_22556_cached_sizze_22815 < bytes_22555) {
        err = lexical_realloc(ctx, &mem_22556, &mem_22556_cached_sizze_22815, bytes_22555);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    if (mem_22558_cached_sizze_22816 < bytes_22555) {
        err = lexical_realloc(ctx, &mem_22558, &mem_22558_cached_sizze_22816, bytes_22555);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    if (mem_22560_cached_sizze_22817 < bytes_22555) {
        err = lexical_realloc(ctx, &mem_22560, &mem_22560_cached_sizze_22817, bytes_22555);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    if (mem_22562_cached_sizze_22818 < bytes_22555) {
        err = lexical_realloc(ctx, &mem_22562, &mem_22562_cached_sizze_22818, bytes_22555);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    if (mem_22564_cached_sizze_22819 < bytes_22555) {
        err = lexical_realloc(ctx, &mem_22564, &mem_22564_cached_sizze_22819, bytes_22555);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    if (mem_22566_cached_sizze_22820 < bytes_22555) {
        err = lexical_realloc(ctx, &mem_22566, &mem_22566_cached_sizze_22820, bytes_22555);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    
    int64_t discard_22142;
    int64_t discard_22143;
    int64_t discard_22144;
    int64_t defunc_res_21683;
    int64_t scanacc_22125;
    int64_t scanacc_22126;
    int64_t scanacc_22127;
    int64_t redout_22131;
    
    scanacc_22125 = (int64_t) 0;
    scanacc_22126 = (int64_t) 0;
    scanacc_22127 = (int64_t) 0;
    redout_22131 = (int64_t) 0;
    for (int64_t i_22135 = 0; i_22135 < n_12702; i_22135++) {
        bool eta_p_21549 = ((bool *) keep_mem_22554.mem)[i_22135];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:240:22-57
        
        int64_t lifted_lambda_res_21553 = btoi_bool_i64(eta_p_21549);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
        
        int64_t defunc_0_op_res_17465 = add64(lifted_lambda_res_21553, scanacc_22125);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
        
        int64_t defunc_0_op_res_17515 = add64(lifted_lambda_res_21553, scanacc_22126);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
        
        int64_t defunc_0_op_res_17565 = add64(lifted_lambda_res_21553, scanacc_22127);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:240:13-57
        
        int64_t zp_res_17020 = add64(lifted_lambda_res_21553, redout_22131);
        
        ((int64_t *) mem_22556)[i_22135] = defunc_0_op_res_17465;
        ((int64_t *) mem_22558)[i_22135] = defunc_0_op_res_17515;
        ((int64_t *) mem_22560)[i_22135] = defunc_0_op_res_17565;
        ((int64_t *) mem_22562)[i_22135] = lifted_lambda_res_21553;
        ((int64_t *) mem_22564)[i_22135] = lifted_lambda_res_21553;
        ((int64_t *) mem_22566)[i_22135] = lifted_lambda_res_21553;
        
        int64_t scanacc_tmp_22655 = defunc_0_op_res_17465;
        int64_t scanacc_tmp_22656 = defunc_0_op_res_17515;
        int64_t scanacc_tmp_22657 = defunc_0_op_res_17565;
        int64_t redout_tmp_22661 = zp_res_17020;
        
        scanacc_22125 = scanacc_tmp_22655;
        scanacc_22126 = scanacc_tmp_22656;
        scanacc_22127 = scanacc_tmp_22657;
        redout_22131 = redout_tmp_22661;
    }
    discard_22142 = scanacc_22125;
    discard_22143 = scanacc_22126;
    discard_22144 = scanacc_22127;
    defunc_res_21683 = redout_22131;
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    
    int64_t tmp_17468 = sub64(n_12702, (int64_t) 1);
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    
    bool y_17470 = slt64(tmp_17468, n_12702);
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    
    bool x_17469 = sle64((int64_t) 0, tmp_17468);
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    
    bool bounds_check_17471 = x_17469 && y_17470;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    
    bool cond_17466 = n_12702 == (int64_t) 0;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    
    bool protect_assert_disj_17472 = cond_17466 || bounds_check_17471;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    
    bool index_certs_17473;
    
    if (!protect_assert_disj_17472) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) tmp_17468, "] out of bounds for array of shape [", (long long) n_12702, "].", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40\n   #1  ../lib/github.com/diku-dk/vtree/vtree.fut:252:14-32\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    
    bool x_17467 = !cond_17466;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    
    int64_t m_f_res_17574;
    
    if (x_17467) {
        // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
        
        int64_t x_21679 = ((int64_t *) mem_22560)[tmp_17468];
        
        m_f_res_17574 = x_21679;
    } else {
        m_f_res_17574 = (int64_t) 0;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    
    int64_t m_17576;
    
    if (cond_17466) {
        m_17576 = (int64_t) 0;
    } else {
        m_17576 = m_f_res_17574;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    
    int64_t bytes_22604 = (int64_t) 8 * m_17576;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:231:16-234:25
    
    int64_t bytes_22606 = (int64_t) 16 * n_12702;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    
    int64_t m_f_res_17524;
    
    if (x_17467) {
        // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
        
        int64_t x_21678 = ((int64_t *) mem_22558)[tmp_17468];
        
        m_f_res_17524 = x_21678;
    } else {
        m_f_res_17524 = (int64_t) 0;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    
    int64_t m_17526;
    
    if (cond_17466) {
        m_17526 = (int64_t) 0;
    } else {
        m_17526 = m_f_res_17524;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    
    int64_t bytes_22614 = (int64_t) 8 * m_17526;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    
    int64_t m_f_res_17474;
    
    if (x_17467) {
        // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
        
        int64_t x_21677 = ((int64_t *) mem_22556)[tmp_17468];
        
        m_f_res_17474 = x_21677;
    } else {
        m_f_res_17474 = (int64_t) 0;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    
    int64_t m_17476;
    
    if (cond_17466) {
        m_17476 = (int64_t) 0;
    } else {
        m_17476 = m_f_res_17474;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    
    int64_t bytes_22616 = (int64_t) 8 * m_17476;
    bool eq_x_y_18098 = defunc_res_21683 == (int64_t) 0;
    bool eq_x_zz_18099 = defunc_res_21683 == m_f_res_17474;
    bool p_and_eq_x_y_18100 = cond_17466 && eq_x_y_18098;
    bool p_and_eq_x_y_18102 = x_17467 && eq_x_zz_18099;
    bool dim_match_12764 = p_and_eq_x_y_18100 || p_and_eq_x_y_18102;
    bool empty_or_match_cert_12765;
    
    if (!dim_match_12764) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (desugared) shape [", (long long) m_17476, "] cannot match shape of type \"[", (long long) defunc_res_21683, "]i64\".", "-> #0  unknown location\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    int64_t bytes_22618 = (int64_t) 8 * defunc_res_21683;
    bool eq_x_zz_18105 = defunc_res_21683 == m_f_res_17524;
    bool p_and_eq_x_y_18108 = x_17467 && eq_x_zz_18105;
    bool dim_match_12773 = p_and_eq_x_y_18100 || p_and_eq_x_y_18108;
    bool empty_or_match_cert_12774;
    
    if (!dim_match_12773) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (desugared) shape [", (long long) m_17526, "] cannot match shape of type \"[", (long long) defunc_res_21683, "]i64\".", "-> #0  unknown location\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    bool eq_x_zz_18111 = defunc_res_21683 == m_f_res_17574;
    bool p_and_eq_x_y_18114 = x_17467 && eq_x_zz_18111;
    bool dim_match_12782 = p_and_eq_x_y_18100 || p_and_eq_x_y_18114;
    bool empty_or_match_cert_12783;
    
    if (!dim_match_12782) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (desugared) shape [", (long long) m_17576, "] cannot match shape of type \"[", (long long) defunc_res_21683, "]i64\".", "-> #0  unknown location\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:242:16-39
    if (mem_22603_cached_sizze_22821 < dzlz7bUZLztZRz20U2z20Unz7dUzg_12707) {
        err = lexical_realloc(ctx, &mem_22603, &mem_22603_cached_sizze_22821, dzlz7bUZLztZRz20U2z20Unz7dUzg_12707);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:242:16-39
    for (int64_t nest_i_22665 = 0; nest_i_22665 < dzlz7bUZLztZRz20U2z20Unz7dUzg_12707; nest_i_22665++) {
        ((bool *) mem_22603)[nest_i_22665] = 0;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    if (mem_22605_cached_sizze_22822 < bytes_22604) {
        err = lexical_realloc(ctx, &mem_22605, &mem_22605_cached_sizze_22822, bytes_22604);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    
    bool acc_cert_16412;
    bool acc_cert_21118;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:242:7-244:32
    for (int64_t i_22146 = 0; i_22146 < n_12702; i_22146++) {
        int64_t v_17047 = ((int64_t *) lp_mem_22552.mem)[i_22146];
        bool v_17048 = ((bool *) keep_mem_22554.mem)[i_22146];
        int64_t v_17051 = ((int64_t *) rp_mem_22553.mem)[i_22146];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:242:7-244:32
        // UpdateAcc
        if (sle64((int64_t) 0, v_17047) && slt64(v_17047, dzlz7bUZLztZRz20U2z20Unz7dUzg_12707)) {
            ((bool *) mem_22603)[v_17047] = v_17048;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:242:7-244:32
        // UpdateAcc
        if (sle64((int64_t) 0, v_17051) && slt64(v_17051, dzlz7bUZLztZRz20U2z20Unz7dUzg_12707)) {
            ((bool *) mem_22603)[v_17051] = v_17048;
        }
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    for (int64_t i_22148 = 0; i_22148 < n_12702; i_22148++) {
        int64_t eta_p_21133 = ((int64_t *) mem_22562)[i_22148];
        int64_t eta_p_21134 = ((int64_t *) mem_22560)[i_22148];
        int64_t v_21136 = ((int64_t *) data_mem_22551.mem)[i_22148];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
        
        bool cond_21137 = eta_p_21133 == (int64_t) 1;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
        
        int64_t lifted_lambda_res_21138;
        
        if (cond_21137) {
            // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
            
            int64_t lifted_lambda_res_t_res_21652 = sub64(eta_p_21134, (int64_t) 1);
            
            lifted_lambda_res_21138 = lifted_lambda_res_t_res_21652;
        } else {
            lifted_lambda_res_21138 = (int64_t) -1;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
        // UpdateAcc
        if (sle64((int64_t) 0, lifted_lambda_res_21138) && slt64(lifted_lambda_res_21138, m_17576)) {
            ((int64_t *) mem_22605)[lifted_lambda_res_21138] = v_21136;
        }
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:231:16-234:25
    if (mem_22607_cached_sizze_22823 < bytes_22606) {
        err = lexical_realloc(ctx, &mem_22607, &mem_22607_cached_sizze_22823, bytes_22606);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:231:16-234:25
    
    int64_t inpacc_21687;
    int64_t inpacc_21491 = (int64_t) 0;
    
    for (int64_t i_22161 = 0; i_22161 < dzlz7bUZLztZRz20U2z20Unz7dUzg_12707; i_22161++) {
        bool eta_p_22298 = ((bool *) mem_22603)[i_22161];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:231:16-52
        
        int64_t lifted_lambda_res_22299 = btoi_bool_i64(eta_p_22298);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:232:19-22
        
        int64_t defunc_0_op_res_22308 = add64(inpacc_21491, lifted_lambda_res_22299);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:233:24-47
        
        int64_t lifted_lambda_res_22309;
        
        if (eta_p_22298) {
            // ../lib/github.com/diku-dk/vtree/vtree.fut:233:36-39
            
            int64_t lifted_lambda_res_t_res_22310 = sub64(defunc_0_op_res_22308, (int64_t) 1);
            
            lifted_lambda_res_22309 = lifted_lambda_res_t_res_22310;
        } else {
            lifted_lambda_res_22309 = (int64_t) -1;
        }
        ((int64_t *) mem_22607)[i_22161] = lifted_lambda_res_22309;
        
        int64_t inpacc_tmp_22668 = defunc_0_op_res_22308;
        
        inpacc_21491 = inpacc_tmp_22668;
    }
    inpacc_21687 = inpacc_21491;
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    if (mem_22615_cached_sizze_22824 < bytes_22614) {
        err = lexical_realloc(ctx, &mem_22615, &mem_22615_cached_sizze_22824, bytes_22614);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    if (mem_22617_cached_sizze_22825 < bytes_22616) {
        err = lexical_realloc(ctx, &mem_22617, &mem_22617_cached_sizze_22825, bytes_22616);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    
    bool acc_cert_21219;
    bool acc_cert_21277;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    for (int64_t i_22165 = 0; i_22165 < n_12702; i_22165++) {
        bool eta_p_21586 = ((bool *) keep_mem_22554.mem)[i_22165];
        int64_t eta_p_21587 = ((int64_t *) rp_mem_22553.mem)[i_22165];
        int64_t eta_p_21588 = ((int64_t *) mem_22564)[i_22165];
        int64_t eta_p_21589 = ((int64_t *) mem_22558)[i_22165];
        int64_t eta_p_21591 = ((int64_t *) lp_mem_22552.mem)[i_22165];
        int64_t eta_p_21592 = ((int64_t *) mem_22566)[i_22165];
        int64_t eta_p_21593 = ((int64_t *) mem_22556)[i_22165];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:247:23-54
        
        int64_t lifted_lambda_res_21596;
        
        if (eta_p_21586) {
            // ../lib/github.com/diku-dk/vtree/vtree.fut:247:33-46
            
            bool x_21659 = sle64((int64_t) 0, eta_p_21591);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:247:33-46
            
            bool y_21660 = slt64(eta_p_21591, dzlz7bUZLztZRz20U2z20Unz7dUzg_12707);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:247:33-46
            
            bool bounds_check_21661 = x_21659 && y_21660;
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:247:33-46
            
            bool index_certs_21662;
            
            if (!bounds_check_21661) {
                set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) eta_p_21591, "] out of bounds for array of shape [", (long long) dzlz7bUZLztZRz20U2z20Unz7dUzg_12707, "].", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:247:33-46\n"));
                err = FUTHARK_PROGRAM_ERROR;
                goto cleanup;
            }
            // ../lib/github.com/diku-dk/vtree/vtree.fut:247:33-46
            
            int64_t lifted_lambda_res_t_res_21663 = ((int64_t *) mem_22607)[eta_p_21591];
            
            lifted_lambda_res_21596 = lifted_lambda_res_t_res_21663;
        } else {
            lifted_lambda_res_21596 = (int64_t) -1;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
        
        bool cond_21602 = eta_p_21592 == (int64_t) 1;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
        
        int64_t lifted_lambda_res_21603;
        
        if (cond_21602) {
            // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
            
            int64_t lifted_lambda_res_t_res_21664 = sub64(eta_p_21593, (int64_t) 1);
            
            lifted_lambda_res_21603 = lifted_lambda_res_t_res_21664;
        } else {
            lifted_lambda_res_21603 = (int64_t) -1;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
        // UpdateAcc
        if (sle64((int64_t) 0, lifted_lambda_res_21603) && slt64(lifted_lambda_res_21603, m_17476)) {
            ((int64_t *) mem_22617)[lifted_lambda_res_21603] = lifted_lambda_res_21596;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:250:23-54
        
        int64_t lifted_lambda_res_21609;
        
        if (eta_p_21586) {
            // ../lib/github.com/diku-dk/vtree/vtree.fut:250:33-46
            
            bool x_21665 = sle64((int64_t) 0, eta_p_21587);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:250:33-46
            
            bool y_21666 = slt64(eta_p_21587, dzlz7bUZLztZRz20U2z20Unz7dUzg_12707);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:250:33-46
            
            bool bounds_check_21667 = x_21665 && y_21666;
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:250:33-46
            
            bool index_certs_21668;
            
            if (!bounds_check_21667) {
                set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) eta_p_21587, "] out of bounds for array of shape [", (long long) dzlz7bUZLztZRz20U2z20Unz7dUzg_12707, "].", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:250:33-46\n"));
                err = FUTHARK_PROGRAM_ERROR;
                goto cleanup;
            }
            // ../lib/github.com/diku-dk/vtree/vtree.fut:250:33-46
            
            int64_t lifted_lambda_res_t_res_21669 = ((int64_t *) mem_22607)[eta_p_21587];
            
            lifted_lambda_res_21609 = lifted_lambda_res_t_res_21669;
        } else {
            lifted_lambda_res_21609 = (int64_t) -1;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
        
        bool cond_21615 = eta_p_21588 == (int64_t) 1;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
        
        int64_t lifted_lambda_res_21616;
        
        if (cond_21615) {
            // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
            
            int64_t lifted_lambda_res_t_res_21670 = sub64(eta_p_21589, (int64_t) 1);
            
            lifted_lambda_res_21616 = lifted_lambda_res_t_res_21670;
        } else {
            lifted_lambda_res_21616 = (int64_t) -1;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
        // UpdateAcc
        if (sle64((int64_t) 0, lifted_lambda_res_21616) && slt64(lifted_lambda_res_21616, m_17526)) {
            ((int64_t *) mem_22615)[lifted_lambda_res_21616] = lifted_lambda_res_21609;
        }
    }
    if (memblock_alloc(ctx, &mem_22619, bytes_22618, "mem_22619")) {
        err = 1;
        goto cleanup;
    }
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_22619.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) mem_22617, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {defunc_res_21683});
    if (memblock_alloc(ctx, &mem_22621, bytes_22618, "mem_22621")) {
        err = 1;
        goto cleanup;
    }
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_22621.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) mem_22615, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {defunc_res_21683});
    if (memblock_alloc(ctx, &mem_22623, bytes_22618, "mem_22623")) {
        err = 1;
        goto cleanup;
    }
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_22623.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) mem_22605, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {defunc_res_21683});
    if (memblock_set(ctx, &mem_out_22651, &mem_22623, "mem_22623") != 0)
        return 1;
    if (memblock_set(ctx, &mem_out_22652, &mem_22619, "mem_22619") != 0)
        return 1;
    if (memblock_set(ctx, &mem_out_22653, &mem_22621, "mem_22621") != 0)
        return 1;
    prim_out_22654 = defunc_res_21683;
    if (memblock_set(ctx, &*mem_out_p_22811, &mem_out_22651, "mem_out_22651") != 0)
        return 1;
    if (memblock_set(ctx, &*mem_out_p_22812, &mem_out_22652, "mem_out_22652") != 0)
        return 1;
    if (memblock_set(ctx, &*mem_out_p_22813, &mem_out_22653, "mem_out_22653") != 0)
        return 1;
    *out_prim_out_22814 = prim_out_22654;
    
  cleanup:
    {
        free(mem_22556);
        free(mem_22558);
        free(mem_22560);
        free(mem_22562);
        free(mem_22564);
        free(mem_22566);
        free(mem_22603);
        free(mem_22605);
        free(mem_22607);
        free(mem_22615);
        free(mem_22617);
        if (memblock_unref(ctx, &mem_22623, "mem_22623") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_22621, "mem_22621") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_22619, "mem_22619") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_out_22653, "mem_out_22653") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_out_22652, "mem_out_22652") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_out_22651, "mem_out_22651") != 0)
            return 1;
    }
    return err;
}
FUTHARK_FUN_ATTR int futrts_entry_test_delete_vertices(struct futhark_context *ctx, bool *out_prim_out_22826)
{
    (void) ctx;
    
    int err = 0;
    bool ok_11754 = ctx->constants->ok_11754;
    bool ok_11838 = ctx->constants->ok_11838;
    bool x_16121 = ctx->constants->x_16121;
    bool x_16124 = ctx->constants->x_16124;
    bool x_16130 = ctx->constants->x_16130;
    bool x_16136 = ctx->constants->x_16136;
    bool prim_out_22651;
    
    prim_out_22651 = ok_11754;
    *out_prim_out_22826 = prim_out_22651;
    
  cleanup:
    { }
    return err;
}
FUTHARK_FUN_ATTR int futrts_entry_test_merge_tree(struct futhark_context *ctx, bool *out_prim_out_22827)
{
    (void) ctx;
    
    int err = 0;
    bool ok_11754 = ctx->constants->ok_11754;
    bool ok_11838 = ctx->constants->ok_11838;
    bool x_16121 = ctx->constants->x_16121;
    bool x_16124 = ctx->constants->x_16124;
    bool x_16130 = ctx->constants->x_16130;
    bool x_16136 = ctx->constants->x_16136;
    bool prim_out_22651;
    
    prim_out_22651 = ok_11838;
    *out_prim_out_22827 = prim_out_22651;
    
  cleanup:
    { }
    return err;
}
FUTHARK_FUN_ATTR int futrts_entry_test_split(struct futhark_context *ctx, bool *out_prim_out_22828)
{
    (void) ctx;
    
    int err = 0;
    bool ok_11754 = ctx->constants->ok_11754;
    bool ok_11838 = ctx->constants->ok_11838;
    bool x_16121 = ctx->constants->x_16121;
    bool x_16124 = ctx->constants->x_16124;
    bool x_16130 = ctx->constants->x_16130;
    bool x_16136 = ctx->constants->x_16136;
    bool prim_out_22651;
    
    prim_out_22651 = x_16121;
    *out_prim_out_22828 = prim_out_22651;
    
  cleanup:
    { }
    return err;
}
FUTHARK_FUN_ATTR int futrts_entry_test_split_at_leaf(struct futhark_context *ctx, bool *out_prim_out_22829)
{
    (void) ctx;
    
    int err = 0;
    bool ok_11754 = ctx->constants->ok_11754;
    bool ok_11838 = ctx->constants->ok_11838;
    bool x_16121 = ctx->constants->x_16121;
    bool x_16124 = ctx->constants->x_16124;
    bool x_16130 = ctx->constants->x_16130;
    bool x_16136 = ctx->constants->x_16136;
    bool prim_out_22651;
    
    prim_out_22651 = x_16124;
    *out_prim_out_22829 = prim_out_22651;
    
  cleanup:
    { }
    return err;
}
FUTHARK_FUN_ATTR int futrts_entry_test_split_multiple(struct futhark_context *ctx, bool *out_prim_out_22830)
{
    (void) ctx;
    
    int err = 0;
    bool ok_11754 = ctx->constants->ok_11754;
    bool ok_11838 = ctx->constants->ok_11838;
    bool x_16121 = ctx->constants->x_16121;
    bool x_16124 = ctx->constants->x_16124;
    bool x_16130 = ctx->constants->x_16130;
    bool x_16136 = ctx->constants->x_16136;
    bool prim_out_22651;
    
    prim_out_22651 = x_16130;
    *out_prim_out_22830 = prim_out_22651;
    
  cleanup:
    { }
    return err;
}
FUTHARK_FUN_ATTR int futrts_entry_test_split_none(struct futhark_context *ctx, bool *out_prim_out_22831)
{
    (void) ctx;
    
    int err = 0;
    bool ok_11754 = ctx->constants->ok_11754;
    bool ok_11838 = ctx->constants->ok_11838;
    bool x_16121 = ctx->constants->x_16121;
    bool x_16124 = ctx->constants->x_16124;
    bool x_16130 = ctx->constants->x_16130;
    bool x_16136 = ctx->constants->x_16136;
    bool prim_out_22651;
    
    prim_out_22651 = x_16136;
    *out_prim_out_22831 = prim_out_22651;
    
  cleanup:
    { }
    return err;
}
FUTHARK_FUN_ATTR int futrts_split_7462(struct futhark_context *ctx, struct memblock *mem_out_p_22832, struct memblock *mem_out_p_22833, struct memblock *mem_out_p_22834, struct memblock *mem_out_p_22835, struct memblock *mem_out_p_22836, struct memblock *mem_out_p_22837, struct memblock *mem_out_p_22838, int64_t *out_prim_out_22839, int64_t *out_prim_out_22840, int64_t *out_prim_out_22841, struct memblock data_mem_22551, struct memblock lp_mem_22552, struct memblock rp_mem_22553, struct memblock splits_mem_22554, int64_t n_13611)
{
    (void) ctx;
    
    int err = 0;
    int64_t mem_22556_cached_sizze_22842 = 0;
    unsigned char *mem_22556 = NULL;
    int64_t mem_22558_cached_sizze_22843 = 0;
    unsigned char *mem_22558 = NULL;
    int64_t mem_22566_cached_sizze_22844 = 0;
    unsigned char *mem_22566 = NULL;
    int64_t mem_22568_cached_sizze_22845 = 0;
    unsigned char *mem_22568 = NULL;
    int64_t mem_22576_cached_sizze_22846 = 0;
    unsigned char *mem_22576 = NULL;
    int64_t mem_22584_cached_sizze_22847 = 0;
    unsigned char *mem_22584 = NULL;
    int64_t mem_22586_cached_sizze_22848 = 0;
    unsigned char *mem_22586 = NULL;
    int64_t mem_22588_cached_sizze_22849 = 0;
    unsigned char *mem_22588 = NULL;
    int64_t mem_22590_cached_sizze_22850 = 0;
    unsigned char *mem_22590 = NULL;
    int64_t mem_22591_cached_sizze_22851 = 0;
    unsigned char *mem_22591 = NULL;
    int64_t mem_22593_cached_sizze_22852 = 0;
    unsigned char *mem_22593 = NULL;
    int64_t mem_22595_cached_sizze_22853 = 0;
    unsigned char *mem_22595 = NULL;
    struct memblock ext_mem_22648;
    
    ext_mem_22648.references = NULL;
    
    struct memblock ext_mem_22649;
    
    ext_mem_22649.references = NULL;
    
    struct memblock ext_mem_22650;
    
    ext_mem_22650.references = NULL;
    
    struct memblock mem_22646;
    
    mem_22646.references = NULL;
    
    struct memblock mem_22645;
    
    mem_22645.references = NULL;
    
    struct memblock mem_22643;
    
    mem_22643.references = NULL;
    
    struct memblock mem_22641;
    
    mem_22641.references = NULL;
    
    struct memblock mem_22639;
    
    mem_22639.references = NULL;
    
    struct memblock mem_out_22657;
    
    mem_out_22657.references = NULL;
    
    struct memblock mem_out_22656;
    
    mem_out_22656.references = NULL;
    
    struct memblock mem_out_22655;
    
    mem_out_22655.references = NULL;
    
    struct memblock mem_out_22654;
    
    mem_out_22654.references = NULL;
    
    struct memblock mem_out_22653;
    
    mem_out_22653.references = NULL;
    
    struct memblock mem_out_22652;
    
    mem_out_22652.references = NULL;
    
    struct memblock mem_out_22651;
    
    mem_out_22651.references = NULL;
    
    bool ok_11754 = ctx->constants->ok_11754;
    bool ok_11838 = ctx->constants->ok_11838;
    bool x_16121 = ctx->constants->x_16121;
    bool x_16124 = ctx->constants->x_16124;
    bool x_16130 = ctx->constants->x_16130;
    bool x_16136 = ctx->constants->x_16136;
    int64_t prim_out_22658;
    int64_t prim_out_22659;
    int64_t prim_out_22660;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:210:24-29
    
    int64_t dzlz7bUZLztZRz20U2z20Unz7dUzg_17610 = mul64((int64_t) 2, n_13611);
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:210:13-33
    
    int64_t bytes_22555 = (int64_t) 16 * n_13611;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:210:13-33
    if (mem_22556_cached_sizze_22842 < bytes_22555) {
        err = lexical_realloc(ctx, &mem_22556, &mem_22556_cached_sizze_22842, bytes_22555);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:210:13-33
    for (int64_t nest_i_22661 = 0; nest_i_22661 < dzlz7bUZLztZRz20U2z20Unz7dUzg_17610; nest_i_22661++) {
        ((int64_t *) mem_22556)[nest_i_22661] = (int64_t) 0;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:211:13-30
    
    int64_t bytes_22565 = (int64_t) 8 * n_13611;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:211:13-30
    if (mem_22558_cached_sizze_22843 < bytes_22565) {
        err = lexical_realloc(ctx, &mem_22558, &mem_22558_cached_sizze_22843, bytes_22565);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:211:13-30
    if (mem_22566_cached_sizze_22844 < bytes_22565) {
        err = lexical_realloc(ctx, &mem_22566, &mem_22566_cached_sizze_22844, bytes_22565);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:211:13-30
    
    bool acc_cert_21589;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:211:13-30
    for (int64_t i_22122 = 0; i_22122 < n_13611; i_22122++) {
        bool eta_p_21602 = ((bool *) splits_mem_22554.mem)[i_22122];
        int64_t eta_p_21603 = ((int64_t *) lp_mem_22552.mem)[i_22122];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:266:25-49
        
        int64_t lifted_lambda_res_21606;
        
        if (eta_p_21602) {
            lifted_lambda_res_21606 = eta_p_21603;
        } else {
            lifted_lambda_res_21606 = (int64_t) 0;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:211:13-30
        // UpdateAcc
        if (sle64((int64_t) 0, eta_p_21603) && slt64(eta_p_21603, dzlz7bUZLztZRz20U2z20Unz7dUzg_17610)) {
            ((int64_t *) mem_22556)[eta_p_21603] = lifted_lambda_res_21606;
        }
        ((int64_t *) mem_22558)[i_22122] = lifted_lambda_res_21606;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:211:13-30
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_22566, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) mem_22558, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {n_13611});
    // ../lib/github.com/diku-dk/vtree/vtree.fut:212:13-39
    
    bool acc_cert_21544;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:212:13-39
    for (int64_t i_22125 = 0; i_22125 < n_13611; i_22125++) {
        int64_t eta_p_21556 = ((int64_t *) mem_22566)[i_22125];
        int64_t v_21558 = ((int64_t *) rp_mem_22553.mem)[i_22125];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:268:31-38
        
        int64_t neg_res_21559 = -eta_p_21556;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:212:13-39
        // UpdateAcc
        if (sle64((int64_t) 0, v_21558) && slt64(v_21558, dzlz7bUZLztZRz20U2z20Unz7dUzg_17610)) {
            ((int64_t *) mem_22556)[v_21558] = neg_res_21559;
        }
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:132:24-36
    if (mem_22568_cached_sizze_22845 < bytes_22555) {
        err = lexical_realloc(ctx, &mem_22568, &mem_22568_cached_sizze_22845, bytes_22555);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:132:24-36
    
    int64_t discard_22131;
    int64_t scanacc_22127 = (int64_t) 0;
    
    for (int64_t i_22129 = 0; i_22129 < dzlz7bUZLztZRz20U2z20Unz7dUzg_17610; i_22129++) {
        int64_t x_17632 = ((int64_t *) mem_22556)[i_22129];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:268:23-30
        
        int64_t zp_res_17635 = add64(x_17632, scanacc_22127);
        
        ((int64_t *) mem_22568)[i_22129] = zp_res_17635;
        
        int64_t scanacc_tmp_22665 = zp_res_17635;
        
        scanacc_22127 = scanacc_tmp_22665;
    }
    discard_22131 = scanacc_22127;
    // ../lib/github.com/diku-dk/vtree/vtree.fut:130:5-132:37
    if (mem_22576_cached_sizze_22846 < bytes_22555) {
        err = lexical_realloc(ctx, &mem_22576, &mem_22576_cached_sizze_22846, bytes_22555);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:130:5-132:37
    for (int64_t i_22134 = 0; i_22134 < dzlz7bUZLztZRz20U2z20Unz7dUzg_17610; i_22134++) {
        // ../lib/github.com/diku-dk/vtree/vtree.fut:132:11-36
        
        int64_t zv_lhs_21537 = add64((int64_t) -1, i_22134);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:132:11-36
        
        int64_t tmp_21538 = smod64(zv_lhs_21537, dzlz7bUZLztZRz20U2z20Unz7dUzg_17610);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:132:11-36
        
        int64_t lifted_lambda_res_21539 = ((int64_t *) mem_22568)[tmp_21538];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:130:19-43
        
        bool cond_21541 = i_22134 == (int64_t) 0;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:130:19-43
        
        int64_t lifted_lambda_res_21542;
        
        if (cond_21541) {
            lifted_lambda_res_21542 = (int64_t) 0;
        } else {
            lifted_lambda_res_21542 = lifted_lambda_res_21539;
        }
        ((int64_t *) mem_22576)[i_22134] = lifted_lambda_res_21542;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    if (mem_22584_cached_sizze_22847 < bytes_22565) {
        err = lexical_realloc(ctx, &mem_22584, &mem_22584_cached_sizze_22847, bytes_22565);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    if (mem_22586_cached_sizze_22848 < bytes_22565) {
        err = lexical_realloc(ctx, &mem_22586, &mem_22586_cached_sizze_22848, bytes_22565);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    if (mem_22588_cached_sizze_22849 < bytes_22565) {
        err = lexical_realloc(ctx, &mem_22588, &mem_22588_cached_sizze_22849, bytes_22565);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    if (mem_22590_cached_sizze_22850 < bytes_22565) {
        err = lexical_realloc(ctx, &mem_22590, &mem_22590_cached_sizze_22850, bytes_22565);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    if (mem_22591_cached_sizze_22851 < n_13611) {
        err = lexical_realloc(ctx, &mem_22591, &mem_22591_cached_sizze_22851, n_13611);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    if (mem_22593_cached_sizze_22852 < bytes_22565) {
        err = lexical_realloc(ctx, &mem_22593, &mem_22593_cached_sizze_22852, bytes_22565);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    if (mem_22595_cached_sizze_22853 < bytes_22565) {
        err = lexical_realloc(ctx, &mem_22595, &mem_22595_cached_sizze_22853, bytes_22565);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    
    int64_t discard_22161;
    int64_t discard_22162;
    int64_t discard_22163;
    int64_t scanacc_22143;
    int64_t scanacc_22144;
    int64_t scanacc_22145;
    
    scanacc_22143 = (int64_t) 0;
    scanacc_22144 = (int64_t) 0;
    scanacc_22145 = (int64_t) 0;
    for (int64_t i_22153 = 0; i_22153 < n_13611; i_22153++) {
        int64_t eta_p_21729 = ((int64_t *) lp_mem_22552.mem)[i_22153];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:214:19-23
        
        bool x_21733 = sle64((int64_t) 0, eta_p_21729);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:214:19-23
        
        bool y_21734 = slt64(eta_p_21729, dzlz7bUZLztZRz20U2z20Unz7dUzg_17610);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:214:19-23
        
        bool bounds_check_21735 = x_21733 && y_21734;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:214:19-23
        
        bool index_certs_21736;
        
        if (!bounds_check_21735) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) eta_p_21729, "] out of bounds for array of shape [", (long long) dzlz7bUZLztZRz20U2z20Unz7dUzg_17610, "].", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:214:19-23\n   #1  ../lib/github.com/diku-dk/vtree/vtree.fut:216:64-217:21\n   #2  ../lib/github.com/diku-dk/vtree/vtree.fut:267:7-268:22\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        
        bool eta_p_21728 = ((bool *) splits_mem_22554.mem)[i_22153];
        int64_t eta_p_21730 = ((int64_t *) rp_mem_22553.mem)[i_22153];
        int64_t eta_p_21731 = ((int64_t *) mem_22566)[i_22153];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:214:19-23
        
        int64_t lifted_lambda_res_21737 = ((int64_t *) mem_22576)[eta_p_21729];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:268:23-30
        
        int64_t zp_res_21738 = add64(eta_p_21731, lifted_lambda_res_21737);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:273:33-37
        
        bool lifted_lambda_res_21739 = zp_res_21738 == (int64_t) 0;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:273:33-37
        
        bool lifted_lambda_res_21740 = !lifted_lambda_res_21739;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:278:5-279:51
        
        int64_t defunc_0_f_res_21741 = btoi_bool_i64(lifted_lambda_res_21740);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:287:40-43
        
        int64_t zp_lhs_21742 = sub64(eta_p_21730, eta_p_21729);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:287:44-47
        
        int64_t zs_lhs_21743 = add64((int64_t) 1, zp_lhs_21742);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:287:49-52
        
        int64_t lifted_lambda_res_21744 = sdiv64(zs_lhs_21743, (int64_t) 2);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:288:36-55
        
        int64_t lifted_lambda_res_21745;
        
        if (eta_p_21728) {
            lifted_lambda_res_21745 = lifted_lambda_res_21744;
        } else {
            lifted_lambda_res_21745 = (int64_t) 0;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
        
        int64_t defunc_0_f_res_21749 = btoi_bool_i64(eta_p_21728);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:278:5-279:51
        
        int64_t defunc_0_op_res_17284 = add64(defunc_0_f_res_21741, scanacc_22143);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:289:37-40
        
        int64_t defunc_0_op_res_17343 = add64(lifted_lambda_res_21745, scanacc_22144);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
        
        int64_t defunc_0_op_res_17465 = add64(defunc_0_f_res_21749, scanacc_22145);
        
        ((int64_t *) mem_22584)[i_22153] = defunc_0_op_res_17284;
        ((int64_t *) mem_22586)[i_22153] = defunc_0_op_res_17343;
        ((int64_t *) mem_22588)[i_22153] = defunc_0_op_res_17465;
        ((int64_t *) mem_22590)[i_22153] = defunc_0_f_res_21749;
        ((bool *) mem_22591)[i_22153] = lifted_lambda_res_21739;
        ((int64_t *) mem_22593)[i_22153] = defunc_0_f_res_21741;
        ((int64_t *) mem_22595)[i_22153] = zp_res_21738;
        
        int64_t scanacc_tmp_22668 = defunc_0_op_res_17284;
        int64_t scanacc_tmp_22669 = defunc_0_op_res_17343;
        int64_t scanacc_tmp_22670 = defunc_0_op_res_17465;
        
        scanacc_22143 = scanacc_tmp_22668;
        scanacc_22144 = scanacc_tmp_22669;
        scanacc_22145 = scanacc_tmp_22670;
    }
    discard_22161 = scanacc_22143;
    discard_22162 = scanacc_22144;
    discard_22163 = scanacc_22145;
    // ../lib/github.com/diku-dk/vtree/vtree.fut:278:5-279:51
    
    int64_t tmp_17287 = sub64(n_13611, (int64_t) 1);
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:278:5-279:51
    
    bool y_17289 = slt64(tmp_17287, n_13611);
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:278:5-279:51
    
    bool x_17288 = sle64((int64_t) 0, tmp_17287);
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:278:5-279:51
    
    bool bounds_check_17290 = x_17288 && y_17289;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:278:5-279:51
    
    bool cond_17285 = n_13611 == (int64_t) 0;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:278:5-279:51
    
    bool protect_assert_disj_17291 = cond_17285 || bounds_check_17290;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:278:5-279:51
    
    bool index_certs_17292;
    
    if (!protect_assert_disj_17291) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) tmp_17287, "] out of bounds for array of shape [", (long long) n_13611, "].", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:278:5-279:51\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:278:5-279:51
    
    bool x_17286 = !cond_17285;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    
    int64_t m_f_res_17474;
    
    if (x_17286) {
        // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
        
        int64_t x_21845 = ((int64_t *) mem_22588)[tmp_17287];
        
        m_f_res_17474 = x_21845;
    } else {
        m_f_res_17474 = (int64_t) 0;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    
    int64_t m_17476;
    
    if (cond_17285) {
        m_17476 = (int64_t) 0;
    } else {
        m_17476 = m_f_res_17474;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    
    int64_t bytes_22638 = (int64_t) 8 * m_17476;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:278:5-279:51
    
    int64_t m_f_res_17293;
    
    if (x_17286) {
        // ../lib/github.com/diku-dk/vtree/vtree.fut:278:5-279:51
        
        int64_t x_21844 = ((int64_t *) mem_22584)[tmp_17287];
        
        m_f_res_17293 = x_21844;
    } else {
        m_f_res_17293 = (int64_t) 0;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:278:5-279:51
    
    int64_t m_17295;
    
    if (cond_17285) {
        m_17295 = (int64_t) 0;
    } else {
        m_17295 = m_f_res_17293;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:278:5-279:51
    
    int64_t bytes_22640 = (int64_t) 8 * m_17295;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    if (memblock_alloc(ctx, &mem_22639, bytes_22638, "mem_22639")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:278:5-279:51
    if (memblock_alloc(ctx, &mem_22641, bytes_22640, "mem_22641")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:278:5-279:51
    if (memblock_alloc(ctx, &mem_22643, bytes_22640, "mem_22643")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:278:5-279:51
    if (memblock_alloc(ctx, &mem_22645, bytes_22640, "mem_22645")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    
    bool acc_cert_21194;
    bool acc_cert_21438;
    bool acc_cert_21439;
    bool acc_cert_21440;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:271:17-279:51
    for (int64_t i_22167 = 0; i_22167 < n_13611; i_22167++) {
        int64_t eta_p_21475 = ((int64_t *) lp_mem_22552.mem)[i_22167];
        int64_t eta_p_21476 = ((int64_t *) mem_22595)[i_22167];
        int64_t eta_p_21477 = ((int64_t *) rp_mem_22553.mem)[i_22167];
        int64_t eta_p_21478 = ((int64_t *) mem_22593)[i_22167];
        int64_t eta_p_21479 = ((int64_t *) mem_22584)[i_22167];
        int64_t v_21483 = ((int64_t *) data_mem_22551.mem)[i_22167];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:271:22-25
        
        int64_t defunc_0_f_res_21485 = sub64(eta_p_21475, eta_p_21476);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:272:22-25
        
        int64_t defunc_0_f_res_21487 = sub64(eta_p_21477, eta_p_21476);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:278:5-279:51
        
        bool cond_21488 = eta_p_21478 == (int64_t) 1;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:278:5-279:51
        
        int64_t lifted_lambda_res_21489;
        
        if (cond_21488) {
            // ../lib/github.com/diku-dk/vtree/vtree.fut:278:5-279:51
            
            int64_t lifted_lambda_res_t_res_21832 = sub64(eta_p_21479, (int64_t) 1);
            
            lifted_lambda_res_21489 = lifted_lambda_res_t_res_21832;
        } else {
            lifted_lambda_res_21489 = (int64_t) -1;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:278:5-279:51
        // UpdateAcc
        if (sle64((int64_t) 0, lifted_lambda_res_21489) && slt64(lifted_lambda_res_21489, m_17295)) {
            ((int64_t *) mem_22645.mem)[lifted_lambda_res_21489] = defunc_0_f_res_21485;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:278:5-279:51
        // UpdateAcc
        if (sle64((int64_t) 0, lifted_lambda_res_21489) && slt64(lifted_lambda_res_21489, m_17295)) {
            ((int64_t *) mem_22643.mem)[lifted_lambda_res_21489] = defunc_0_f_res_21487;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:278:5-279:51
        // UpdateAcc
        if (sle64((int64_t) 0, lifted_lambda_res_21489) && slt64(lifted_lambda_res_21489, m_17295)) {
            ((int64_t *) mem_22641.mem)[lifted_lambda_res_21489] = v_21483;
        }
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    for (int64_t i_22169 = 0; i_22169 < n_13611; i_22169++) {
        int64_t eta_p_21220 = ((int64_t *) mem_22590)[i_22169];
        int64_t eta_p_21221 = ((int64_t *) mem_22588)[i_22169];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:132:11-36
        
        int64_t zv_lhs_21224 = add64((int64_t) -1, i_22169);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:132:11-36
        
        int64_t tmp_21225 = smod64(zv_lhs_21224, n_13611);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:132:11-36
        
        int64_t lifted_lambda_res_21226 = ((int64_t *) mem_22586)[tmp_21225];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:130:19-43
        
        bool cond_21228 = i_22169 == (int64_t) 0;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:130:19-43
        
        int64_t lifted_lambda_res_21229;
        
        if (cond_21228) {
            lifted_lambda_res_21229 = (int64_t) 0;
        } else {
            lifted_lambda_res_21229 = lifted_lambda_res_21226;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
        
        bool cond_21230 = eta_p_21220 == (int64_t) 1;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
        
        int64_t lifted_lambda_res_21231;
        
        if (cond_21230) {
            // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
            
            int64_t lifted_lambda_res_t_res_21833 = sub64(eta_p_21221, (int64_t) 1);
            
            lifted_lambda_res_21231 = lifted_lambda_res_t_res_21833;
        } else {
            lifted_lambda_res_21231 = (int64_t) -1;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
        // UpdateAcc
        if (sle64((int64_t) 0, lifted_lambda_res_21231) && slt64(lifted_lambda_res_21231, m_17476)) {
            ((int64_t *) mem_22639.mem)[lifted_lambda_res_21231] = lifted_lambda_res_21229;
        }
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:258:12-292:42
    if (memblock_alloc(ctx, &mem_22646, n_13611, "mem_22646")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:258:12-292:42
    // ../lib/github.com/diku-dk/vtree/vtree.fut:258:12-292:42
    lmad_copy_1b(ctx, 1, (uint8_t *) mem_22646.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint8_t *) mem_22591, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {n_13611});
    // ../lib/github.com/diku-dk/vtree/vtree.fut:258:12-292:42
    
    int64_t split_res_13708;
    
    if (futrts_deleteVertices_7461(ctx, &ext_mem_22650, &ext_mem_22649, &ext_mem_22648, &split_res_13708, data_mem_22551, lp_mem_22552, rp_mem_22553, mem_22646, n_13611) != 0) {
        err = 1;
        goto cleanup;
    }
    if (memblock_unref(ctx, &mem_22646, "mem_22646") != 0)
        return 1;
    if (memblock_set(ctx, &mem_out_22651, &mem_22639, "mem_22639") != 0)
        return 1;
    if (memblock_set(ctx, &mem_out_22652, &mem_22641, "mem_22641") != 0)
        return 1;
    if (memblock_set(ctx, &mem_out_22653, &mem_22645, "mem_22645") != 0)
        return 1;
    if (memblock_set(ctx, &mem_out_22654, &mem_22643, "mem_22643") != 0)
        return 1;
    if (memblock_set(ctx, &mem_out_22655, &ext_mem_22650, "ext_mem_22650") != 0)
        return 1;
    if (memblock_set(ctx, &mem_out_22656, &ext_mem_22649, "ext_mem_22649") != 0)
        return 1;
    if (memblock_set(ctx, &mem_out_22657, &ext_mem_22648, "ext_mem_22648") != 0)
        return 1;
    prim_out_22658 = m_17476;
    prim_out_22659 = m_17295;
    prim_out_22660 = split_res_13708;
    if (memblock_set(ctx, &*mem_out_p_22832, &mem_out_22651, "mem_out_22651") != 0)
        return 1;
    if (memblock_set(ctx, &*mem_out_p_22833, &mem_out_22652, "mem_out_22652") != 0)
        return 1;
    if (memblock_set(ctx, &*mem_out_p_22834, &mem_out_22653, "mem_out_22653") != 0)
        return 1;
    if (memblock_set(ctx, &*mem_out_p_22835, &mem_out_22654, "mem_out_22654") != 0)
        return 1;
    if (memblock_set(ctx, &*mem_out_p_22836, &mem_out_22655, "mem_out_22655") != 0)
        return 1;
    if (memblock_set(ctx, &*mem_out_p_22837, &mem_out_22656, "mem_out_22656") != 0)
        return 1;
    if (memblock_set(ctx, &*mem_out_p_22838, &mem_out_22657, "mem_out_22657") != 0)
        return 1;
    *out_prim_out_22839 = prim_out_22658;
    *out_prim_out_22840 = prim_out_22659;
    *out_prim_out_22841 = prim_out_22660;
    
  cleanup:
    {
        free(mem_22556);
        free(mem_22558);
        free(mem_22566);
        free(mem_22568);
        free(mem_22576);
        free(mem_22584);
        free(mem_22586);
        free(mem_22588);
        free(mem_22590);
        free(mem_22591);
        free(mem_22593);
        free(mem_22595);
        if (memblock_unref(ctx, &ext_mem_22648, "ext_mem_22648") != 0)
            return 1;
        if (memblock_unref(ctx, &ext_mem_22649, "ext_mem_22649") != 0)
            return 1;
        if (memblock_unref(ctx, &ext_mem_22650, "ext_mem_22650") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_22646, "mem_22646") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_22645, "mem_22645") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_22643, "mem_22643") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_22641, "mem_22641") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_22639, "mem_22639") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_out_22657, "mem_out_22657") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_out_22656, "mem_out_22656") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_out_22655, "mem_out_22655") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_out_22654, "mem_out_22654") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_out_22653, "mem_out_22653") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_out_22652, "mem_out_22652") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_out_22651, "mem_out_22651") != 0)
            return 1;
    }
    return err;
}

int futhark_entry_test_delete_vertices(struct futhark_context *ctx, bool *out0)
{
    bool prim_out_22651 = 0;
    int ret = 0;
    
    lock_lock(&ctx->lock);
    if (ret == 0) {
        ret = futrts_entry_test_delete_vertices(ctx, &prim_out_22651);
        if (ret == 0) {
            bool ok_11754 = ctx->constants->ok_11754;
            bool ok_11838 = ctx->constants->ok_11838;
            bool x_16121 = ctx->constants->x_16121;
            bool x_16124 = ctx->constants->x_16124;
            bool x_16130 = ctx->constants->x_16130;
            bool x_16136 = ctx->constants->x_16136;
            
            *out0 = prim_out_22651;
        }
    }
    lock_unlock(&ctx->lock);
    return ret;
}
int futhark_entry_test_merge_tree(struct futhark_context *ctx, bool *out0)
{
    bool prim_out_22651 = 0;
    int ret = 0;
    
    lock_lock(&ctx->lock);
    if (ret == 0) {
        ret = futrts_entry_test_merge_tree(ctx, &prim_out_22651);
        if (ret == 0) {
            bool ok_11754 = ctx->constants->ok_11754;
            bool ok_11838 = ctx->constants->ok_11838;
            bool x_16121 = ctx->constants->x_16121;
            bool x_16124 = ctx->constants->x_16124;
            bool x_16130 = ctx->constants->x_16130;
            bool x_16136 = ctx->constants->x_16136;
            
            *out0 = prim_out_22651;
        }
    }
    lock_unlock(&ctx->lock);
    return ret;
}
int futhark_entry_test_split(struct futhark_context *ctx, bool *out0)
{
    bool prim_out_22651 = 0;
    int ret = 0;
    
    lock_lock(&ctx->lock);
    if (ret == 0) {
        ret = futrts_entry_test_split(ctx, &prim_out_22651);
        if (ret == 0) {
            bool ok_11754 = ctx->constants->ok_11754;
            bool ok_11838 = ctx->constants->ok_11838;
            bool x_16121 = ctx->constants->x_16121;
            bool x_16124 = ctx->constants->x_16124;
            bool x_16130 = ctx->constants->x_16130;
            bool x_16136 = ctx->constants->x_16136;
            
            *out0 = prim_out_22651;
        }
    }
    lock_unlock(&ctx->lock);
    return ret;
}
int futhark_entry_test_split_at_leaf(struct futhark_context *ctx, bool *out0)
{
    bool prim_out_22651 = 0;
    int ret = 0;
    
    lock_lock(&ctx->lock);
    if (ret == 0) {
        ret = futrts_entry_test_split_at_leaf(ctx, &prim_out_22651);
        if (ret == 0) {
            bool ok_11754 = ctx->constants->ok_11754;
            bool ok_11838 = ctx->constants->ok_11838;
            bool x_16121 = ctx->constants->x_16121;
            bool x_16124 = ctx->constants->x_16124;
            bool x_16130 = ctx->constants->x_16130;
            bool x_16136 = ctx->constants->x_16136;
            
            *out0 = prim_out_22651;
        }
    }
    lock_unlock(&ctx->lock);
    return ret;
}
int futhark_entry_test_split_multiple(struct futhark_context *ctx, bool *out0)
{
    bool prim_out_22651 = 0;
    int ret = 0;
    
    lock_lock(&ctx->lock);
    if (ret == 0) {
        ret = futrts_entry_test_split_multiple(ctx, &prim_out_22651);
        if (ret == 0) {
            bool ok_11754 = ctx->constants->ok_11754;
            bool ok_11838 = ctx->constants->ok_11838;
            bool x_16121 = ctx->constants->x_16121;
            bool x_16124 = ctx->constants->x_16124;
            bool x_16130 = ctx->constants->x_16130;
            bool x_16136 = ctx->constants->x_16136;
            
            *out0 = prim_out_22651;
        }
    }
    lock_unlock(&ctx->lock);
    return ret;
}
int futhark_entry_test_split_none(struct futhark_context *ctx, bool *out0)
{
    bool prim_out_22651 = 0;
    int ret = 0;
    
    lock_lock(&ctx->lock);
    if (ret == 0) {
        ret = futrts_entry_test_split_none(ctx, &prim_out_22651);
        if (ret == 0) {
            bool ok_11754 = ctx->constants->ok_11754;
            bool ok_11838 = ctx->constants->ok_11838;
            bool x_16121 = ctx->constants->x_16121;
            bool x_16124 = ctx->constants->x_16124;
            bool x_16130 = ctx->constants->x_16130;
            bool x_16136 = ctx->constants->x_16136;
            
            *out0 = prim_out_22651;
        }
    }
    lock_unlock(&ctx->lock);
    return ret;
}
  
