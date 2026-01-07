
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

static int read_str_i8(const char *buf, void* dest) {
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

static int read_str_u8(const char *buf, void* dest) {
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

static int read_str_i16(const char *buf, void* dest) {
  READ_STR(SCNi16, int16_t, "i16");
}

static int read_str_u16(const char *buf, void* dest) {
  READ_STR(SCNi16, int16_t, "u16");
}

static int read_str_i32(const char *buf, void* dest) {
  READ_STR(SCNi32, int32_t, "i32");
}

static int read_str_u32(const char *buf, void* dest) {
  READ_STR(SCNi32, int32_t, "u32");
}

static int read_str_i64(const char *buf, void* dest) {
  READ_STR(SCNi64, int64_t, "i64");
}

static int read_str_u64(const char *buf, void* dest) {
  // FIXME: This is not correct, as SCNu64 only permits decimal
  // literals.  However, SCNi64 does not handle very large numbers
  // correctly (it's really for signed numbers, so that's fair).
  READ_STR(SCNu64, uint64_t, "u64");
}

static int read_str_f16(const char *buf, void* dest) {
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

static int read_str_f32(const char *buf, void* dest) {
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

static int read_str_f64(const char *buf, void* dest) {
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

static int read_str_bool(const char *buf, void* dest) {
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

static int write_str_i8(FILE *out, const int8_t *src) {
  return fprintf(out, "%hhdi8", *src);
}

static int write_str_u8(FILE *out, const uint8_t *src) {
  return fprintf(out, "%hhuu8", *src);
}

static int write_str_i16(FILE *out, const int16_t *src) {
  return fprintf(out, "%hdi16", *src);
}

static int write_str_u16(FILE *out, const uint16_t *src) {
  return fprintf(out, "%huu16", *src);
}

static int write_str_i32(FILE *out, const int32_t *src) {
  return fprintf(out, "%di32", *src);
}

static int write_str_u32(FILE *out, const uint32_t *src) {
  return fprintf(out, "%uu32", *src);
}

static int write_str_i64(FILE *out, const int64_t *src) {
  return fprintf(out, "%"PRIi64"i64", *src);
}

static int write_str_u64(FILE *out, const uint64_t *src) {
  return fprintf(out, "%"PRIu64"u64", *src);
}

static int write_str_f16(FILE *out, const uint16_t *src) {
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

static int write_str_f32(FILE *out, const float *src) {
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

static int write_str_f64(FILE *out, const double *src) {
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

static int write_str_bool(FILE *out, const void *src) {
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
    bool ok_11869;
    bool ok_11952;
    bool x_16338;
    bool x_16341;
    bool x_16347;
    bool x_16353;
};
static int64_t static_array_realtype_23801[6] = { (int64_t) 0,(int64_t) 1,(int64_t) 2,(int64_t) 4,(int64_t) 6,(int64_t) 9};
static int64_t static_array_realtype_23802[6] = { (int64_t) 11,(int64_t) 8,(int64_t) 3,(int64_t) 5,(int64_t) 7,(int64_t) 10};
static bool static_array_realtype_23803[6] = { 0,1,0,0,0,0};
static int64_t static_array_realtype_23804[4] = { (int64_t) 1,(int64_t) 2,(int64_t) 3,(int64_t) 4};
static int64_t static_array_realtype_23805[4] = { (int64_t) 0,(int64_t) 1,(int64_t) 3,(int64_t) 5};
static int64_t static_array_realtype_23806[4] = { (int64_t) 7,(int64_t) 2,(int64_t) 4,(int64_t) 6};
static int64_t static_array_realtype_23807[1] = { (int64_t) 0};
static int64_t static_array_realtype_23808[2] = { (int64_t) 0,(int64_t) 5};
static int64_t static_array_realtype_23809[2] = { (int64_t) 0,(int64_t) 1};
static int64_t static_array_realtype_23810[2] = { (int64_t) 3,(int64_t) 2};
static bool static_array_realtype_23811[6] = { 0,0,1,0,0,0};
static bool static_array_realtype_23812[6] = { 0,1,0,0,0,1};
static int64_t static_array_realtype_23813[2] = { (int64_t) 0,(int64_t) 4};
static bool static_array_realtype_23814[6] = { 0,0,0,0,0,0};
static bool static_array_realtype_23815[6] = { 1,1,0,0,0,1};
static int64_t static_array_realtype_23816[3] = { (int64_t) 0,(int64_t) 1,(int64_t) 5};
static int64_t static_array_realtype_23817[4] = { (int64_t) 0,(int64_t) 1,(int64_t) 3,(int64_t) 4};
static int64_t static_array_realtype_23818[4] = { (int64_t) 7,(int64_t) 2,(int64_t) 6,(int64_t) 5};
static int64_t static_array_realtype_23819[4] = { (int64_t) 0,(int64_t) 1,(int64_t) 2,(int64_t) 3};
static int64_t static_array_realtype_23820[5] = { (int64_t) 0,(int64_t) 1,(int64_t) 0,(int64_t) 1,(int64_t) 3};
static int64_t static_array_realtype_23821[5] = { (int64_t) 3,(int64_t) 2,(int64_t) 5,(int64_t) 2,(int64_t) 4};
static int64_t static_array_realtype_23822[5] = { (int64_t) 4,(int64_t) 5,(int64_t) 6,(int64_t) 7,(int64_t) 8};
static int64_t static_array_realtype_23823[2] = { (int64_t) 0,(int64_t) 2};
static int64_t static_array_realtype_23824[4] = { (int64_t) 0,(int64_t) 1,(int64_t) 0,(int64_t) -1};
static int64_t static_array_realtype_23825[11] = { (int64_t) 0,(int64_t) 1,(int64_t) 2,(int64_t) 5,(int64_t) 6,(int64_t) 7,(int64_t) 9,(int64_t) 13,(int64_t) 14,(int64_t) 15,(int64_t) 18};
static int64_t static_array_realtype_23826[11] = { (int64_t) 21,(int64_t) 4,(int64_t) 3,(int64_t) 12,(int64_t) 11,(int64_t) 8,(int64_t) 10,(int64_t) 20,(int64_t) 17,(int64_t) 16,(int64_t) 19};
static int64_t static_array_realtype_23827[11] = { (int64_t) 0,(int64_t) 4,(int64_t) 5,(int64_t) 2,(int64_t) 6,(int64_t) 7,(int64_t) 8,(int64_t) 2,(int64_t) 4,(int64_t) 5,(int64_t) 3};
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

FUTHARK_FUN_ATTR int futrts_deleteVertices_7489(struct futhark_context *ctx, struct memblock *mem_out_p_23828, struct memblock *mem_out_p_23829, struct memblock *mem_out_p_23830, int64_t *out_prim_out_23831, struct memblock data_mem_23558, struct memblock lp_mem_23559, struct memblock rp_mem_23560, struct memblock keep_mem_23561, int64_t n_12816);
FUTHARK_FUN_ATTR int futrts_entry_test_delete_vertices(struct futhark_context *ctx, bool *out_prim_out_23843);
FUTHARK_FUN_ATTR int futrts_entry_test_merge_tree(struct futhark_context *ctx, bool *out_prim_out_23844);
FUTHARK_FUN_ATTR int futrts_entry_test_split(struct futhark_context *ctx, bool *out_prim_out_23845);
FUTHARK_FUN_ATTR int futrts_entry_test_split_at_leaf(struct futhark_context *ctx, bool *out_prim_out_23846);
FUTHARK_FUN_ATTR int futrts_entry_test_split_multiple(struct futhark_context *ctx, bool *out_prim_out_23847);
FUTHARK_FUN_ATTR int futrts_entry_test_split_none(struct futhark_context *ctx, bool *out_prim_out_23848);
FUTHARK_FUN_ATTR int futrts_split_7490(struct futhark_context *ctx, struct memblock *mem_out_p_23849, struct memblock *mem_out_p_23850, struct memblock *mem_out_p_23851, struct memblock *mem_out_p_23852, struct memblock *mem_out_p_23853, struct memblock *mem_out_p_23854, struct memblock *mem_out_p_23855, int64_t *out_prim_out_23856, int64_t *out_prim_out_23857, int64_t *out_prim_out_23858, struct memblock data_mem_23558, struct memblock lp_mem_23559, struct memblock rp_mem_23560, struct memblock splits_mem_23561, int64_t n_13725);

static int init_constants(struct futhark_context *ctx)
{
    (void) ctx;
    
    int err = 0;
    
    #define ok_11869 (ctx->constants->ok_11869)
    #define ok_11952 (ctx->constants->ok_11952)
    #define x_16338 (ctx->constants->x_16338)
    #define x_16341 (ctx->constants->x_16341)
    #define x_16347 (ctx->constants->x_16347)
    #define x_16353 (ctx->constants->x_16353)
    
    struct memblock mem_23551;
    
    mem_23551.references = NULL;
    
    struct memblock mem_23543;
    
    mem_23543.references = NULL;
    
    struct memblock mem_23523;
    
    mem_23523.references = NULL;
    
    struct memblock mem_23515;
    
    mem_23515.references = NULL;
    
    struct memblock mem_23502;
    
    mem_23502.references = NULL;
    
    struct memblock mem_23500;
    
    mem_23500.references = NULL;
    
    struct memblock mem_23482;
    
    mem_23482.references = NULL;
    
    struct memblock mem_23480;
    
    mem_23480.references = NULL;
    
    struct memblock mem_23498;
    
    mem_23498.references = NULL;
    
    struct memblock mem_23496;
    
    mem_23496.references = NULL;
    
    struct memblock mem_23478;
    
    mem_23478.references = NULL;
    
    struct memblock mem_23464;
    
    mem_23464.references = NULL;
    
    struct memblock mem_23462;
    
    mem_23462.references = NULL;
    
    struct memblock mem_23446;
    
    mem_23446.references = NULL;
    
    struct memblock mem_23445;
    
    mem_23445.references = NULL;
    
    struct memblock mem_23460;
    
    mem_23460.references = NULL;
    
    struct memblock mem_23459;
    
    mem_23459.references = NULL;
    
    struct memblock mem_23444;
    
    mem_23444.references = NULL;
    
    struct memblock mem_23443;
    
    mem_23443.references = NULL;
    
    struct memblock mem_23441;
    
    mem_23441.references = NULL;
    
    struct memblock mem_23439;
    
    mem_23439.references = NULL;
    
    struct memblock mem_23437;
    
    mem_23437.references = NULL;
    
    struct memblock mem_23436;
    
    mem_23436.references = NULL;
    
    struct memblock mem_23434;
    
    mem_23434.references = NULL;
    
    struct memblock mem_23426;
    
    mem_23426.references = NULL;
    
    struct memblock mem_23419;
    
    mem_23419.references = NULL;
    
    struct memblock mem_23412;
    
    mem_23412.references = NULL;
    
    struct memblock mem_23411;
    
    mem_23411.references = NULL;
    
    struct memblock mem_23368;
    
    mem_23368.references = NULL;
    
    struct memblock mem_23367;
    
    mem_23367.references = NULL;
    
    struct memblock mem_23366;
    
    mem_23366.references = NULL;
    
    struct memblock mem_23365;
    
    mem_23365.references = NULL;
    
    struct memblock mem_23364;
    
    mem_23364.references = NULL;
    
    struct memblock mem_23363;
    
    mem_23363.references = NULL;
    
    struct memblock mem_23362;
    
    mem_23362.references = NULL;
    
    struct memblock mem_23355;
    
    mem_23355.references = NULL;
    
    struct memblock mem_23354;
    
    mem_23354.references = NULL;
    
    struct memblock mem_23353;
    
    mem_23353.references = NULL;
    
    struct memblock mem_23352;
    
    mem_23352.references = NULL;
    
    struct memblock mem_23351;
    
    mem_23351.references = NULL;
    
    struct memblock mem_23350;
    
    mem_23350.references = NULL;
    
    struct memblock mem_23349;
    
    mem_23349.references = NULL;
    
    struct memblock mem_23348;
    
    mem_23348.references = NULL;
    
    struct memblock mem_23347;
    
    mem_23347.references = NULL;
    
    struct memblock mem_23346;
    
    mem_23346.references = NULL;
    
    struct memblock mem_23345;
    
    mem_23345.references = NULL;
    
    struct memblock mem_23344;
    
    mem_23344.references = NULL;
    
    struct memblock mem_23343;
    
    mem_23343.references = NULL;
    
    struct memblock ext_mem_23340;
    
    ext_mem_23340.references = NULL;
    
    struct memblock ext_mem_23341;
    
    ext_mem_23341.references = NULL;
    
    struct memblock ext_mem_23342;
    
    ext_mem_23342.references = NULL;
    
    struct memblock mem_23339;
    
    mem_23339.references = NULL;
    
    struct memblock ext_mem_23332;
    
    ext_mem_23332.references = NULL;
    
    struct memblock ext_mem_23333;
    
    ext_mem_23333.references = NULL;
    
    struct memblock ext_mem_23334;
    
    ext_mem_23334.references = NULL;
    
    struct memblock ext_mem_23335;
    
    ext_mem_23335.references = NULL;
    
    struct memblock ext_mem_23336;
    
    ext_mem_23336.references = NULL;
    
    struct memblock ext_mem_23337;
    
    ext_mem_23337.references = NULL;
    
    struct memblock ext_mem_23338;
    
    ext_mem_23338.references = NULL;
    
    struct memblock mem_23331;
    
    mem_23331.references = NULL;
    
    struct memblock mem_23330;
    
    mem_23330.references = NULL;
    
    struct memblock ext_mem_23323;
    
    ext_mem_23323.references = NULL;
    
    struct memblock ext_mem_23324;
    
    ext_mem_23324.references = NULL;
    
    struct memblock ext_mem_23325;
    
    ext_mem_23325.references = NULL;
    
    struct memblock ext_mem_23326;
    
    ext_mem_23326.references = NULL;
    
    struct memblock ext_mem_23327;
    
    ext_mem_23327.references = NULL;
    
    struct memblock ext_mem_23328;
    
    ext_mem_23328.references = NULL;
    
    struct memblock ext_mem_23329;
    
    ext_mem_23329.references = NULL;
    
    struct memblock mem_23322;
    
    mem_23322.references = NULL;
    
    struct memblock ext_mem_23315;
    
    ext_mem_23315.references = NULL;
    
    struct memblock ext_mem_23316;
    
    ext_mem_23316.references = NULL;
    
    struct memblock ext_mem_23317;
    
    ext_mem_23317.references = NULL;
    
    struct memblock ext_mem_23318;
    
    ext_mem_23318.references = NULL;
    
    struct memblock ext_mem_23319;
    
    ext_mem_23319.references = NULL;
    
    struct memblock ext_mem_23320;
    
    ext_mem_23320.references = NULL;
    
    struct memblock ext_mem_23321;
    
    ext_mem_23321.references = NULL;
    
    struct memblock mem_23314;
    
    mem_23314.references = NULL;
    
    struct memblock mem_23313;
    
    mem_23313.references = NULL;
    
    struct memblock mem_23312;
    
    mem_23312.references = NULL;
    
    struct memblock mem_23311;
    
    mem_23311.references = NULL;
    
    struct memblock mem_23310;
    
    mem_23310.references = NULL;
    
    struct memblock mem_23309;
    
    mem_23309.references = NULL;
    
    struct memblock mem_23308;
    
    mem_23308.references = NULL;
    
    struct memblock mem_23307;
    
    mem_23307.references = NULL;
    
    struct memblock ext_mem_23300;
    
    ext_mem_23300.references = NULL;
    
    struct memblock ext_mem_23301;
    
    ext_mem_23301.references = NULL;
    
    struct memblock ext_mem_23302;
    
    ext_mem_23302.references = NULL;
    
    struct memblock ext_mem_23303;
    
    ext_mem_23303.references = NULL;
    
    struct memblock ext_mem_23304;
    
    ext_mem_23304.references = NULL;
    
    struct memblock ext_mem_23305;
    
    ext_mem_23305.references = NULL;
    
    struct memblock ext_mem_23306;
    
    ext_mem_23306.references = NULL;
    
    struct memblock mem_23299;
    
    mem_23299.references = NULL;
    
    struct memblock mem_23298;
    
    mem_23298.references = NULL;
    
    struct memblock mem_23297;
    
    mem_23297.references = NULL;
    
    struct memblock mem_23296;
    
    mem_23296.references = NULL;
    // ./test_operations.fut:9:21-27
    if (memblock_alloc(ctx, &mem_23296, (int64_t) 48, "mem_23296")) {
        err = 1;
        goto cleanup;
    }
    // ./test_operations.fut:9:21-27
    for (int64_t i_23689 = 0; i_23689 < (int64_t) 6; i_23689++) {
        int64_t x_23690 = (int64_t) 0 + i_23689 * (int64_t) 1;
        
        ((int64_t *) mem_23296.mem)[i_23689] = x_23690;
    }
    // ./test_operations.fut:7:5-10:13
    if (memblock_alloc(ctx, &mem_23297, (int64_t) 48, "mem_23297")) {
        err = 1;
        goto cleanup;
    }
    // ./test_operations.fut:7:5-10:13
    
    struct memblock static_array_23691 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_23801, 0, "static_array_23691"};
    
    // ./test_operations.fut:7:5-10:13
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_23297.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_23691.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 6});
    // ./test_operations.fut:7:5-10:13
    if (memblock_alloc(ctx, &mem_23298, (int64_t) 48, "mem_23298")) {
        err = 1;
        goto cleanup;
    }
    // ./test_operations.fut:7:5-10:13
    
    struct memblock static_array_23692 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_23802, 0, "static_array_23692"};
    
    // ./test_operations.fut:7:5-10:13
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_23298.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_23692.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 6});
    // ./test_operations.fut:11:16-57
    if (memblock_alloc(ctx, &mem_23299, (int64_t) 6, "mem_23299")) {
        err = 1;
        goto cleanup;
    }
    // ./test_operations.fut:11:16-57
    
    struct memblock static_array_23693 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_23803, 0, "static_array_23693"};
    
    // ./test_operations.fut:11:16-57
    lmad_copy_1b(ctx, 1, (uint8_t *) mem_23299.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint8_t *) static_array_23693.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 6});
    // ./test_operations.fut:6:7-12:50
    
    int64_t test_split_res_11508;
    int64_t test_split_res_11509;
    int64_t test_split_res_11510;
    
    if (futrts_split_7490(ctx, &ext_mem_23306, &ext_mem_23305, &ext_mem_23304, &ext_mem_23303, &ext_mem_23302, &ext_mem_23301, &ext_mem_23300, &test_split_res_11508, &test_split_res_11509, &test_split_res_11510, mem_23296, mem_23297, mem_23298, mem_23299, (int64_t) 6) != 0) {
        err = 1;
        goto cleanup;
    }
    if (memblock_unref(ctx, &mem_23299, "mem_23299") != 0)
        return 1;
    // ./test_operations.fut:16:5-19:63
    
    bool cond_11539 = test_split_res_11509 == (int64_t) 4;
    
    // ./test_operations.fut:17:13-61
    if (memblock_alloc(ctx, &mem_23307, (int64_t) 32, "mem_23307")) {
        err = 1;
        goto cleanup;
    }
    // ./test_operations.fut:17:13-61
    
    struct memblock static_array_23694 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_23804, 0, "static_array_23694"};
    
    // ./test_operations.fut:17:13-61
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_23307.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_23694.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 4});
    // ./test_operations.fut:16:5-19:63
    
    bool cond_11540;
    
    if (cond_11539) {
        // ./test_operations.fut:17:24-47
        
        bool dim_match_21795 = (int64_t) 4 == test_split_res_11509;
        
        // ./test_operations.fut:17:24-47
        
        bool empty_or_match_cert_21796;
        
        if (!dim_match_21795) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (desugared) shape [", (long long) test_split_res_11509, "] cannot match shape of type \"[", (long long) (int64_t) 4, "]i64\".", "-> #0  ./test_operations.fut:17:24-47\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        // ./test_operations.fut:17:8-61
        
        bool defunc_0_reduce_res_21798;
        bool redout_22835 = 1;
        
        for (int64_t i_22836 = 0; i_22836 < (int64_t) 4; i_22836++) {
            int64_t eta_p_21799 = ((int64_t *) ext_mem_23305.mem)[i_22836];
            int64_t eta_p_21800 = ((int64_t *) mem_23307.mem)[i_22836];
            
            // ./test_operations.fut:17:18-22
            
            bool defunc_0_f_res_21801 = eta_p_21799 == eta_p_21800;
            
            // ./test_operations.fut:17:8-61
            
            bool x_21804 = defunc_0_f_res_21801 && redout_22835;
            bool redout_tmp_23695 = x_21804;
            
            redout_22835 = redout_tmp_23695;
        }
        defunc_0_reduce_res_21798 = redout_22835;
        cond_11540 = defunc_0_reduce_res_21798;
    } else {
        cond_11540 = 0;
    }
    if (memblock_unref(ctx, &ext_mem_23305, "ext_mem_23305") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23307, "mem_23307") != 0)
        return 1;
    // ./test_operations.fut:18:13-62
    if (memblock_alloc(ctx, &mem_23308, (int64_t) 32, "mem_23308")) {
        err = 1;
        goto cleanup;
    }
    // ./test_operations.fut:18:13-62
    
    struct memblock static_array_23696 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_23805, 0, "static_array_23696"};
    
    // ./test_operations.fut:18:13-62
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_23308.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_23696.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 4});
    // ./test_operations.fut:16:5-19:63
    
    bool cond_11550;
    
    if (cond_11540) {
        // ./test_operations.fut:18:24-45
        
        bool dim_match_21809 = (int64_t) 4 == test_split_res_11509;
        
        // ./test_operations.fut:18:24-45
        
        bool empty_or_match_cert_21810;
        
        if (!dim_match_21809) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (desugared) shape [", (long long) test_split_res_11509, "] cannot match shape of type \"[", (long long) (int64_t) 4, "]i64\".", "-> #0  ./test_operations.fut:18:24-45\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        // ./test_operations.fut:18:8-62
        
        bool defunc_0_reduce_res_21812;
        bool redout_22837 = 1;
        
        for (int64_t i_22838 = 0; i_22838 < (int64_t) 4; i_22838++) {
            int64_t eta_p_21813 = ((int64_t *) ext_mem_23304.mem)[i_22838];
            int64_t eta_p_21814 = ((int64_t *) mem_23308.mem)[i_22838];
            
            // ./test_operations.fut:18:18-22
            
            bool defunc_0_f_res_21815 = eta_p_21813 == eta_p_21814;
            
            // ./test_operations.fut:18:8-62
            
            bool x_21818 = defunc_0_f_res_21815 && redout_22837;
            bool redout_tmp_23697 = x_21818;
            
            redout_22837 = redout_tmp_23697;
        }
        defunc_0_reduce_res_21812 = redout_22837;
        cond_11550 = defunc_0_reduce_res_21812;
    } else {
        cond_11550 = 0;
    }
    if (memblock_unref(ctx, &ext_mem_23304, "ext_mem_23304") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23308, "mem_23308") != 0)
        return 1;
    // ./test_operations.fut:19:13-62
    if (memblock_alloc(ctx, &mem_23309, (int64_t) 32, "mem_23309")) {
        err = 1;
        goto cleanup;
    }
    // ./test_operations.fut:19:13-62
    
    struct memblock static_array_23698 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_23806, 0, "static_array_23698"};
    
    // ./test_operations.fut:19:13-62
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_23309.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_23698.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 4});
    // ./test_operations.fut:16:5-19:63
    
    bool subtrees_ok_11560;
    
    if (cond_11550) {
        // ./test_operations.fut:19:24-45
        
        bool dim_match_21823 = (int64_t) 4 == test_split_res_11509;
        
        // ./test_operations.fut:19:24-45
        
        bool empty_or_match_cert_21824;
        
        if (!dim_match_21823) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (desugared) shape [", (long long) test_split_res_11509, "] cannot match shape of type \"[", (long long) (int64_t) 4, "]i64\".", "-> #0  ./test_operations.fut:19:24-45\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        // ./test_operations.fut:19:8-62
        
        bool defunc_0_reduce_res_21826;
        bool redout_22839 = 1;
        
        for (int64_t i_22840 = 0; i_22840 < (int64_t) 4; i_22840++) {
            int64_t eta_p_21827 = ((int64_t *) ext_mem_23303.mem)[i_22840];
            int64_t eta_p_21828 = ((int64_t *) mem_23309.mem)[i_22840];
            
            // ./test_operations.fut:19:18-22
            
            bool defunc_0_f_res_21829 = eta_p_21827 == eta_p_21828;
            
            // ./test_operations.fut:19:8-62
            
            bool x_21832 = defunc_0_f_res_21829 && redout_22839;
            bool redout_tmp_23699 = x_21832;
            
            redout_22839 = redout_tmp_23699;
        }
        defunc_0_reduce_res_21826 = redout_22839;
        subtrees_ok_11560 = defunc_0_reduce_res_21826;
    } else {
        subtrees_ok_11560 = 0;
    }
    if (memblock_unref(ctx, &ext_mem_23303, "ext_mem_23303") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23309, "mem_23309") != 0)
        return 1;
    // ./test_operations.fut:22:5-23:62
    
    bool cond_11573 = test_split_res_11508 == (int64_t) 1;
    
    // ./test_operations.fut:22:5-23:62
    
    bool offsets_ok_11574;
    
    if (cond_11573) {
        // ./test_operations.fut:23:24-53
        
        bool dim_match_21835 = (int64_t) 1 == test_split_res_11508;
        
        // ./test_operations.fut:23:24-53
        
        bool empty_or_match_cert_21836;
        
        if (!dim_match_21835) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (desugared) shape [", (long long) test_split_res_11508, "] cannot match shape of type \"[", (long long) (int64_t) 1, "]i64\".", "-> #0  ./test_operations.fut:23:24-53\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        // ./test_operations.fut:23:13-61
        if (memblock_alloc(ctx, &mem_23310, (int64_t) 8, "mem_23310")) {
            err = 1;
            goto cleanup;
        }
        // ./test_operations.fut:23:13-61
        
        struct memblock static_array_23700 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_23807, 0, "static_array_23700"};
        
        // ./test_operations.fut:23:13-61
        lmad_copy_8b(ctx, 1, (uint64_t *) mem_23310.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_23700.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 1});
        
        int64_t eta_p_21838 = ((int64_t *) ext_mem_23306.mem)[(int64_t) 0];
        int64_t eta_p_21839 = ((int64_t *) mem_23310.mem)[(int64_t) 0];
        
        if (memblock_unref(ctx, &mem_23310, "mem_23310") != 0)
            return 1;
        // ./test_operations.fut:23:18-22
        
        bool defunc_0_f_res_21840 = eta_p_21838 == eta_p_21839;
        
        offsets_ok_11574 = defunc_0_f_res_21840;
    } else {
        offsets_ok_11574 = 0;
    }
    if (memblock_unref(ctx, &ext_mem_23306, "ext_mem_23306") != 0)
        return 1;
    // ./test_operations.fut:27:5-30:52
    
    bool cond_11593 = test_split_res_11510 == (int64_t) 2;
    
    // ./test_operations.fut:28:13-50
    if (memblock_alloc(ctx, &mem_23311, (int64_t) 16, "mem_23311")) {
        err = 1;
        goto cleanup;
    }
    // ./test_operations.fut:28:13-50
    
    struct memblock static_array_23701 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_23808, 0, "static_array_23701"};
    
    // ./test_operations.fut:28:13-50
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_23311.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_23701.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 2});
    // ./test_operations.fut:27:5-30:52
    
    bool cond_11594;
    
    if (cond_11593) {
        // ./test_operations.fut:28:24-42
        
        bool dim_match_21843 = (int64_t) 2 == test_split_res_11510;
        
        // ./test_operations.fut:28:24-42
        
        bool empty_or_match_cert_21844;
        
        if (!dim_match_21843) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (desugared) shape [", (long long) test_split_res_11510, "] cannot match shape of type \"[", (long long) (int64_t) 2, "]i64\".", "-> #0  ./test_operations.fut:28:24-42\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        // ./test_operations.fut:28:8-50
        
        bool defunc_0_reduce_res_21846;
        bool redout_22841 = 1;
        
        for (int64_t i_22842 = 0; i_22842 < (int64_t) 2; i_22842++) {
            int64_t eta_p_21847 = ((int64_t *) ext_mem_23302.mem)[i_22842];
            int64_t eta_p_21848 = ((int64_t *) mem_23311.mem)[i_22842];
            
            // ./test_operations.fut:28:18-22
            
            bool defunc_0_f_res_21849 = eta_p_21847 == eta_p_21848;
            
            // ./test_operations.fut:28:8-50
            
            bool x_21852 = defunc_0_f_res_21849 && redout_22841;
            bool redout_tmp_23702 = x_21852;
            
            redout_22841 = redout_tmp_23702;
        }
        defunc_0_reduce_res_21846 = redout_22841;
        cond_11594 = defunc_0_reduce_res_21846;
    } else {
        cond_11594 = 0;
    }
    if (memblock_unref(ctx, &ext_mem_23302, "ext_mem_23302") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23311, "mem_23311") != 0)
        return 1;
    // ./test_operations.fut:29:13-51
    if (memblock_alloc(ctx, &mem_23312, (int64_t) 16, "mem_23312")) {
        err = 1;
        goto cleanup;
    }
    // ./test_operations.fut:29:13-51
    
    struct memblock static_array_23703 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_23809, 0, "static_array_23703"};
    
    // ./test_operations.fut:29:13-51
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_23312.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_23703.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 2});
    // ./test_operations.fut:27:5-30:52
    
    bool cond_11604;
    
    if (cond_11594) {
        // ./test_operations.fut:29:24-40
        
        bool dim_match_21857 = (int64_t) 2 == test_split_res_11510;
        
        // ./test_operations.fut:29:24-40
        
        bool empty_or_match_cert_21858;
        
        if (!dim_match_21857) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (desugared) shape [", (long long) test_split_res_11510, "] cannot match shape of type \"[", (long long) (int64_t) 2, "]i64\".", "-> #0  ./test_operations.fut:29:24-40\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        // ./test_operations.fut:29:8-51
        
        bool defunc_0_reduce_res_21860;
        bool redout_22843 = 1;
        
        for (int64_t i_22844 = 0; i_22844 < (int64_t) 2; i_22844++) {
            int64_t eta_p_21861 = ((int64_t *) ext_mem_23301.mem)[i_22844];
            int64_t eta_p_21862 = ((int64_t *) mem_23312.mem)[i_22844];
            
            // ./test_operations.fut:29:18-22
            
            bool defunc_0_f_res_21863 = eta_p_21861 == eta_p_21862;
            
            // ./test_operations.fut:29:8-51
            
            bool x_21866 = defunc_0_f_res_21863 && redout_22843;
            bool redout_tmp_23704 = x_21866;
            
            redout_22843 = redout_tmp_23704;
        }
        defunc_0_reduce_res_21860 = redout_22843;
        cond_11604 = defunc_0_reduce_res_21860;
    } else {
        cond_11604 = 0;
    }
    if (memblock_unref(ctx, &ext_mem_23301, "ext_mem_23301") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23312, "mem_23312") != 0)
        return 1;
    // ./test_operations.fut:30:13-51
    if (memblock_alloc(ctx, &mem_23313, (int64_t) 16, "mem_23313")) {
        err = 1;
        goto cleanup;
    }
    // ./test_operations.fut:30:13-51
    
    struct memblock static_array_23705 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_23810, 0, "static_array_23705"};
    
    // ./test_operations.fut:30:13-51
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_23313.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_23705.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 2});
    // ./test_operations.fut:27:5-30:52
    
    bool remainder_ok_11614;
    
    if (cond_11604) {
        // ./test_operations.fut:30:24-40
        
        bool dim_match_21871 = (int64_t) 2 == test_split_res_11510;
        
        // ./test_operations.fut:30:24-40
        
        bool empty_or_match_cert_21872;
        
        if (!dim_match_21871) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (desugared) shape [", (long long) test_split_res_11510, "] cannot match shape of type \"[", (long long) (int64_t) 2, "]i64\".", "-> #0  ./test_operations.fut:30:24-40\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        // ./test_operations.fut:30:8-51
        
        bool defunc_0_reduce_res_21874;
        bool redout_22845 = 1;
        
        for (int64_t i_22846 = 0; i_22846 < (int64_t) 2; i_22846++) {
            int64_t eta_p_21875 = ((int64_t *) ext_mem_23300.mem)[i_22846];
            int64_t eta_p_21876 = ((int64_t *) mem_23313.mem)[i_22846];
            
            // ./test_operations.fut:30:18-22
            
            bool defunc_0_f_res_21877 = eta_p_21875 == eta_p_21876;
            
            // ./test_operations.fut:30:8-51
            
            bool x_21880 = defunc_0_f_res_21877 && redout_22845;
            bool redout_tmp_23706 = x_21880;
            
            redout_22845 = redout_tmp_23706;
        }
        defunc_0_reduce_res_21874 = redout_22845;
        remainder_ok_11614 = defunc_0_reduce_res_21874;
    } else {
        remainder_ok_11614 = 0;
    }
    if (memblock_unref(ctx, &ext_mem_23300, "ext_mem_23300") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23313, "mem_23313") != 0)
        return 1;
    
    bool x_16335 = subtrees_ok_11560 && offsets_ok_11574;
    
    x_16338 = remainder_ok_11614 && x_16335;
    // ./test_operations.fut:55:16-57
    if (memblock_alloc(ctx, &mem_23314, (int64_t) 6, "mem_23314")) {
        err = 1;
        goto cleanup;
    }
    // ./test_operations.fut:55:16-57
    
    struct memblock static_array_23707 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_23811, 0, "static_array_23707"};
    
    // ./test_operations.fut:55:16-57
    lmad_copy_1b(ctx, 1, (uint8_t *) mem_23314.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint8_t *) static_array_23707.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 6});
    // ./test_operations.fut:49:7-56:50
    
    int64_t test_split_at_leaf_res_11640;
    int64_t test_split_at_leaf_res_11641;
    int64_t test_split_at_leaf_res_11642;
    
    if (futrts_split_7490(ctx, &ext_mem_23321, &ext_mem_23320, &ext_mem_23319, &ext_mem_23318, &ext_mem_23317, &ext_mem_23316, &ext_mem_23315, &test_split_at_leaf_res_11640, &test_split_at_leaf_res_11641, &test_split_at_leaf_res_11642, mem_23296, mem_23297, mem_23298, mem_23314, (int64_t) 6) != 0) {
        err = 1;
        goto cleanup;
    }
    if (memblock_unref(ctx, &mem_23314, "mem_23314") != 0)
        return 1;
    // ./test_operations.fut:61:5-62:53
    
    bool cond_11677 = test_split_at_leaf_res_11641 == (int64_t) 1;
    
    // ./test_operations.fut:61:5-62:53
    
    bool subtrees_ok_11678;
    
    if (cond_11677) {
        // ./test_operations.fut:62:24-47
        
        bool dim_match_21883 = (int64_t) 1 == test_split_at_leaf_res_11641;
        
        // ./test_operations.fut:62:24-47
        
        bool empty_or_match_cert_21884;
        
        if (!dim_match_21883) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (desugared) shape [", (long long) test_split_at_leaf_res_11641, "] cannot match shape of type \"[", (long long) (int64_t) 1, "]i64\".", "-> #0  ./test_operations.fut:62:24-47\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        
        int64_t eta_p_21885 = ((int64_t *) ext_mem_23320.mem)[(int64_t) 0];
        
        // ./test_operations.fut:62:18-22
        
        bool defunc_0_f_res_21886 = eta_p_21885 == (int64_t) 2;
        
        subtrees_ok_11678 = defunc_0_f_res_21886;
    } else {
        subtrees_ok_11678 = 0;
    }
    if (memblock_unref(ctx, &ext_mem_23320, "ext_mem_23320") != 0)
        return 1;
    // ./test_operations.fut:64:38-42
    
    bool remainder_ok_11691 = test_split_at_leaf_res_11642 == (int64_t) 5;
    
    x_16341 = subtrees_ok_11678 && remainder_ok_11691;
    // ./test_operations.fut:74:16-56
    if (memblock_alloc(ctx, &mem_23322, (int64_t) 6, "mem_23322")) {
        err = 1;
        goto cleanup;
    }
    // ./test_operations.fut:74:16-56
    
    struct memblock static_array_23708 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_23812, 0, "static_array_23708"};
    
    // ./test_operations.fut:74:16-56
    lmad_copy_1b(ctx, 1, (uint8_t *) mem_23322.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint8_t *) static_array_23708.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 6});
    // ./test_operations.fut:68:7-75:50
    
    int64_t test_split_multiple_res_11707;
    int64_t test_split_multiple_res_11708;
    int64_t test_split_multiple_res_11709;
    
    if (futrts_split_7490(ctx, &ext_mem_23329, &ext_mem_23328, &ext_mem_23327, &ext_mem_23326, &ext_mem_23325, &ext_mem_23324, &ext_mem_23323, &test_split_multiple_res_11707, &test_split_multiple_res_11708, &test_split_multiple_res_11709, mem_23296, mem_23297, mem_23298, mem_23322, (int64_t) 6) != 0) {
        err = 1;
        goto cleanup;
    }
    if (memblock_unref(ctx, &mem_23322, "mem_23322") != 0)
        return 1;
    // ./test_operations.fut:79:42-46
    
    bool subtrees_ok_11744 = test_split_multiple_res_11708 == (int64_t) 5;
    
    // ./test_operations.fut:82:5-83:65
    
    bool cond_11748 = test_split_multiple_res_11707 == (int64_t) 2;
    
    // ./test_operations.fut:83:13-64
    if (memblock_alloc(ctx, &mem_23330, (int64_t) 16, "mem_23330")) {
        err = 1;
        goto cleanup;
    }
    // ./test_operations.fut:83:13-64
    
    struct memblock static_array_23709 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_23813, 0, "static_array_23709"};
    
    // ./test_operations.fut:83:13-64
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_23330.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_23709.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 2});
    // ./test_operations.fut:82:5-83:65
    
    bool offsets_ok_11749;
    
    if (cond_11748) {
        // ./test_operations.fut:83:24-53
        
        bool dim_match_21889 = (int64_t) 2 == test_split_multiple_res_11707;
        
        // ./test_operations.fut:83:24-53
        
        bool empty_or_match_cert_21890;
        
        if (!dim_match_21889) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (desugared) shape [", (long long) test_split_multiple_res_11707, "] cannot match shape of type \"[", (long long) (int64_t) 2, "]i64\".", "-> #0  ./test_operations.fut:83:24-53\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        // ./test_operations.fut:83:8-64
        
        bool defunc_0_reduce_res_21892;
        bool redout_22847 = 1;
        
        for (int64_t i_22848 = 0; i_22848 < (int64_t) 2; i_22848++) {
            int64_t eta_p_21893 = ((int64_t *) ext_mem_23329.mem)[i_22848];
            int64_t eta_p_21894 = ((int64_t *) mem_23330.mem)[i_22848];
            
            // ./test_operations.fut:83:18-22
            
            bool defunc_0_f_res_21895 = eta_p_21893 == eta_p_21894;
            
            // ./test_operations.fut:83:8-64
            
            bool x_21898 = defunc_0_f_res_21895 && redout_22847;
            bool redout_tmp_23710 = x_21898;
            
            redout_22847 = redout_tmp_23710;
        }
        defunc_0_reduce_res_21892 = redout_22847;
        offsets_ok_11749 = defunc_0_reduce_res_21892;
    } else {
        offsets_ok_11749 = 0;
    }
    if (memblock_unref(ctx, &ext_mem_23329, "ext_mem_23329") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23330, "mem_23330") != 0)
        return 1;
    // ./test_operations.fut:86:5-87:48
    
    bool cond_11762 = test_split_multiple_res_11709 == (int64_t) 1;
    
    // ./test_operations.fut:86:5-87:48
    
    bool remainder_ok_11763;
    
    if (cond_11762) {
        // ./test_operations.fut:87:24-42
        
        bool dim_match_21901 = (int64_t) 1 == test_split_multiple_res_11709;
        
        // ./test_operations.fut:87:24-42
        
        bool empty_or_match_cert_21902;
        
        if (!dim_match_21901) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (desugared) shape [", (long long) test_split_multiple_res_11709, "] cannot match shape of type \"[", (long long) (int64_t) 1, "]i64\".", "-> #0  ./test_operations.fut:87:24-42\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        
        int64_t eta_p_21903 = ((int64_t *) ext_mem_23325.mem)[(int64_t) 0];
        
        // ./test_operations.fut:87:18-22
        
        bool defunc_0_f_res_21904 = eta_p_21903 == (int64_t) 0;
        
        remainder_ok_11763 = defunc_0_f_res_21904;
    } else {
        remainder_ok_11763 = 0;
    }
    if (memblock_unref(ctx, &ext_mem_23325, "ext_mem_23325") != 0)
        return 1;
    
    bool x_16344 = subtrees_ok_11744 && offsets_ok_11749;
    
    x_16347 = remainder_ok_11763 && x_16344;
    // ./test_operations.fut:96:16-58
    if (memblock_alloc(ctx, &mem_23331, (int64_t) 6, "mem_23331")) {
        err = 1;
        goto cleanup;
    }
    // ./test_operations.fut:96:16-58
    
    struct memblock static_array_23711 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_23814, 0, "static_array_23711"};
    
    // ./test_operations.fut:96:16-58
    lmad_copy_1b(ctx, 1, (uint8_t *) mem_23331.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint8_t *) static_array_23711.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 6});
    // ./test_operations.fut:91:7-97:50
    
    int64_t test_split_none_res_11789;
    int64_t test_split_none_res_11790;
    int64_t test_split_none_res_11791;
    
    if (futrts_split_7490(ctx, &ext_mem_23338, &ext_mem_23337, &ext_mem_23336, &ext_mem_23335, &ext_mem_23334, &ext_mem_23333, &ext_mem_23332, &test_split_none_res_11789, &test_split_none_res_11790, &test_split_none_res_11791, mem_23296, mem_23297, mem_23298, mem_23331, (int64_t) 6) != 0) {
        err = 1;
        goto cleanup;
    }
    if (memblock_unref(ctx, &mem_23331, "mem_23331") != 0)
        return 1;
    // ./test_operations.fut:101:42-46
    
    bool subtrees_ok_11826 = test_split_none_res_11790 == (int64_t) 0;
    
    // ./test_operations.fut:102:47-51
    
    bool offsets_ok_11830 = test_split_none_res_11789 == (int64_t) 0;
    
    // ./test_operations.fut:104:38-42
    
    bool remainder_ok_11834 = test_split_none_res_11791 == (int64_t) 6;
    bool x_16350 = subtrees_ok_11826 && offsets_ok_11830;
    
    x_16353 = remainder_ok_11834 && x_16350;
    // ./test_operations.fut:114:14-53
    if (memblock_alloc(ctx, &mem_23339, (int64_t) 6, "mem_23339")) {
        err = 1;
        goto cleanup;
    }
    // ./test_operations.fut:114:14-53
    
    struct memblock static_array_23712 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_23815, 0, "static_array_23712"};
    
    // ./test_operations.fut:114:14-53
    lmad_copy_1b(ctx, 1, (uint8_t *) mem_23339.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint8_t *) static_array_23712.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 6});
    // ./test_operations.fut:108:7-115:39
    
    int64_t test_delete_vertices_res_11851;
    
    if (futrts_deleteVertices_7489(ctx, &ext_mem_23342, &ext_mem_23341, &ext_mem_23340, &test_delete_vertices_res_11851, mem_23296, mem_23297, mem_23298, mem_23339, (int64_t) 6) != 0) {
        err = 1;
        goto cleanup;
    }
    if (memblock_unref(ctx, &mem_23296, "mem_23296") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23297, "mem_23297") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23298, "mem_23298") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23339, "mem_23339") != 0)
        return 1;
    // ./test_operations.fut:118:5-119:54
    
    bool cond_11868 = test_delete_vertices_res_11851 == (int64_t) 3;
    
    // ./test_operations.fut:119:13-53
    if (memblock_alloc(ctx, &mem_23343, (int64_t) 24, "mem_23343")) {
        err = 1;
        goto cleanup;
    }
    // ./test_operations.fut:119:13-53
    
    struct memblock static_array_23713 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_23816, 0, "static_array_23713"};
    
    // ./test_operations.fut:119:13-53
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_23343.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_23713.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 3});
    // ./test_operations.fut:118:5-119:54
    if (cond_11868) {
        // ./test_operations.fut:119:24-42
        
        bool dim_match_21907 = (int64_t) 3 == test_delete_vertices_res_11851;
        
        // ./test_operations.fut:119:24-42
        
        bool empty_or_match_cert_21908;
        
        if (!dim_match_21907) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (desugared) shape [", (long long) test_delete_vertices_res_11851, "] cannot match shape of type \"[", (long long) (int64_t) 3, "]i64\".", "-> #0  ./test_operations.fut:119:24-42\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        // ./test_operations.fut:119:8-53
        
        bool defunc_0_reduce_res_21910;
        bool redout_22849 = 1;
        
        for (int64_t i_22850 = 0; i_22850 < (int64_t) 3; i_22850++) {
            int64_t eta_p_21911 = ((int64_t *) ext_mem_23342.mem)[i_22850];
            int64_t eta_p_21912 = ((int64_t *) mem_23343.mem)[i_22850];
            
            // ./test_operations.fut:119:18-22
            
            bool defunc_0_f_res_21913 = eta_p_21911 == eta_p_21912;
            
            // ./test_operations.fut:119:8-53
            
            bool x_21916 = defunc_0_f_res_21913 && redout_22849;
            bool redout_tmp_23714 = x_21916;
            
            redout_22849 = redout_tmp_23714;
        }
        defunc_0_reduce_res_21910 = redout_22849;
        ok_11869 = defunc_0_reduce_res_21910;
    } else {
        ok_11869 = 0;
    }
    if (memblock_unref(ctx, &ext_mem_23342, "ext_mem_23342") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23343, "mem_23343") != 0)
        return 1;
    // ./test_operations.fut:124:5-128:4
    if (memblock_alloc(ctx, &mem_23344, (int64_t) 32, "mem_23344")) {
        err = 1;
        goto cleanup;
    }
    // ./test_operations.fut:124:5-128:4
    
    struct memblock static_array_23715 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_23817, 0, "static_array_23715"};
    
    // ./test_operations.fut:124:5-128:4
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_23344.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_23715.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 4});
    // ./test_operations.fut:124:5-128:4
    if (memblock_alloc(ctx, &mem_23345, (int64_t) 32, "mem_23345")) {
        err = 1;
        goto cleanup;
    }
    // ./test_operations.fut:124:5-128:4
    
    struct memblock static_array_23716 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_23818, 0, "static_array_23716"};
    
    // ./test_operations.fut:124:5-128:4
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_23345.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_23716.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 4});
    // ./test_operations.fut:124:5-128:4
    if (memblock_alloc(ctx, &mem_23346, (int64_t) 32, "mem_23346")) {
        err = 1;
        goto cleanup;
    }
    // ./test_operations.fut:124:5-128:4
    
    struct memblock static_array_23717 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_23819, 0, "static_array_23717"};
    
    // ./test_operations.fut:124:5-128:4
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_23346.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_23717.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 4});
    // ./test_operations.fut:130:5-134:6
    if (memblock_alloc(ctx, &mem_23347, (int64_t) 40, "mem_23347")) {
        err = 1;
        goto cleanup;
    }
    // ./test_operations.fut:130:5-134:6
    
    struct memblock static_array_23718 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_23820, 0, "static_array_23718"};
    
    // ./test_operations.fut:130:5-134:6
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_23347.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_23718.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 5});
    // ./test_operations.fut:130:5-134:6
    if (memblock_alloc(ctx, &mem_23348, (int64_t) 40, "mem_23348")) {
        err = 1;
        goto cleanup;
    }
    // ./test_operations.fut:130:5-134:6
    
    struct memblock static_array_23719 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_23821, 0, "static_array_23719"};
    
    // ./test_operations.fut:130:5-134:6
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_23348.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_23719.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 5});
    // ./test_operations.fut:130:5-134:6
    if (memblock_alloc(ctx, &mem_23349, (int64_t) 40, "mem_23349")) {
        err = 1;
        goto cleanup;
    }
    // ./test_operations.fut:130:5-134:6
    
    struct memblock static_array_23720 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_23822, 0, "static_array_23720"};
    
    // ./test_operations.fut:130:5-134:6
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_23349.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_23720.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 5});
    // ./test_operations.fut:135:17-28
    if (memblock_alloc(ctx, &mem_23350, (int64_t) 16, "mem_23350")) {
        err = 1;
        goto cleanup;
    }
    // ./test_operations.fut:135:17-28
    
    struct memblock static_array_23721 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_23823, 0, "static_array_23721"};
    
    // ./test_operations.fut:135:17-28
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_23350.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_23721.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 2});
    if (memblock_alloc(ctx, &mem_23351, (int64_t) 32, "mem_23351")) {
        err = 1;
        goto cleanup;
    }
    
    struct memblock static_array_23722 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_23824, 0, "static_array_23722"};
    
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_23351.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_23722.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 4});
    if (memblock_alloc(ctx, &mem_23352, (int64_t) 88, "mem_23352")) {
        err = 1;
        goto cleanup;
    }
    
    struct memblock static_array_23723 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_23825, 0, "static_array_23723"};
    
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_23352.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_23723.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 11});
    if (memblock_alloc(ctx, &mem_23353, (int64_t) 88, "mem_23353")) {
        err = 1;
        goto cleanup;
    }
    
    struct memblock static_array_23724 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_23826, 0, "static_array_23724"};
    
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_23353.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_23724.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 11});
    if (memblock_alloc(ctx, &mem_23354, (int64_t) 88, "mem_23354")) {
        err = 1;
        goto cleanup;
    }
    
    struct memblock static_array_23725 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_23827, 0, "static_array_23725"};
    
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_23354.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_23725.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 11});
    // ../lib/github.com/diku-dk/vtree/vtree.fut:300:21-93
    if (memblock_alloc(ctx, &mem_23355, (int64_t) 16, "mem_23355")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:300:21-93
    for (int64_t i_22853 = 0; i_22853 < (int64_t) 2; i_22853++) {
        // ../lib/github.com/diku-dk/vtree/vtree.fut:300:33-70
        
        bool cond_17915 = slt64(i_22853, (int64_t) 1);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:300:33-70
        
        int64_t zm_lhs_17916;
        
        if (cond_17915) {
            // ../lib/github.com/diku-dk/vtree/vtree.fut:300:60-62
            
            int64_t tmp_21919 = add64((int64_t) 1, i_22853);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:300:51-63
            
            bool x_21920 = sle64((int64_t) 0, tmp_21919);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:300:51-63
            
            bool y_21921 = slt64(tmp_21919, (int64_t) 2);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:300:51-63
            
            bool bounds_check_21922 = x_21920 && y_21921;
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:300:51-63
            
            bool index_certs_21923;
            
            if (!bounds_check_21922) {
                set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) tmp_21919, "] out of bounds for array of shape [", (long long) (int64_t) 2, "].", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:300:51-63\n   #1  ./test_operations.fut:123:7-142:103\n"));
                err = FUTHARK_PROGRAM_ERROR;
                goto cleanup;
            }
            // ../lib/github.com/diku-dk/vtree/vtree.fut:300:51-63
            
            int64_t zm_lhs_t_res_21924 = ((int64_t *) mem_23350.mem)[tmp_21919];
            
            zm_lhs_17916 = zm_lhs_t_res_21924;
        } else {
            zm_lhs_17916 = (int64_t) 5;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:300:74-84
        
        int64_t zm_rhs_17927 = ((int64_t *) mem_23350.mem)[i_22853];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:300:72-84
        
        int64_t lifted_lambda_res_17928 = sub64(zm_lhs_17916, zm_rhs_17927);
        
        ((int64_t *) mem_23355.mem)[i_22853] = lifted_lambda_res_17928;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:346:28-90
    if (memblock_alloc(ctx, &mem_23362, (int64_t) 32, "mem_23362")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:346:28-90
    if (memblock_alloc(ctx, &mem_23363, (int64_t) 32, "mem_23363")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:346:28-90
    if (memblock_alloc(ctx, &mem_23364, (int64_t) 32, "mem_23364")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:346:28-90
    if (memblock_alloc(ctx, &mem_23365, (int64_t) 32, "mem_23365")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:346:28-90
    if (memblock_alloc(ctx, &mem_23366, (int64_t) 32, "mem_23366")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:346:28-90
    if (memblock_alloc(ctx, &mem_23367, (int64_t) 32, "mem_23367")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:346:28-90
    if (memblock_alloc(ctx, &mem_23368, (int64_t) 32, "mem_23368")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:346:28-90
    
    int64_t discard_22883;
    int64_t discard_22884;
    int64_t discard_22885;
    int64_t discard_22886;
    int64_t discard_22887;
    int64_t defunc_0_reduce_res_22082;
    int64_t scanacc_22862;
    int64_t scanacc_22863;
    int64_t scanacc_22864;
    int64_t scanacc_22865;
    int64_t scanacc_22866;
    int64_t redout_22872;
    
    scanacc_22862 = (int64_t) 0;
    scanacc_22863 = (int64_t) 0;
    scanacc_22864 = (int64_t) 0;
    scanacc_22865 = (int64_t) 0;
    scanacc_22866 = (int64_t) 0;
    redout_22872 = (int64_t) 0;
    for (int64_t i_22875 = 0; i_22875 < (int64_t) 4; i_22875++) {
        int64_t eta_p_21220 = ((int64_t *) mem_23351.mem)[i_22875];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:301:34-68
        
        bool cond_21222 = sle64((int64_t) 0, eta_p_21220);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:301:34-68
        
        int64_t lifted_lambda_res_21223;
        
        if (cond_21222) {
            // ../lib/github.com/diku-dk/vtree/vtree.fut:301:49-61
            
            bool y_21925 = slt64(eta_p_21220, (int64_t) 2);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:301:49-61
            
            bool bounds_check_21926 = cond_21222 && y_21925;
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:301:49-61
            
            bool index_certs_21927;
            
            if (!bounds_check_21926) {
                set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) eta_p_21220, "] out of bounds for array of shape [", (long long) (int64_t) 2, "].", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:301:49-61\n   #1  ./test_operations.fut:123:7-142:103\n"));
                err = FUTHARK_PROGRAM_ERROR;
                goto cleanup;
            }
            // ../lib/github.com/diku-dk/vtree/vtree.fut:301:49-61
            
            int64_t lifted_lambda_res_t_res_21928 = ((int64_t *) mem_23355.mem)[eta_p_21220];
            
            lifted_lambda_res_21223 = lifted_lambda_res_t_res_21928;
        } else {
            lifted_lambda_res_21223 = (int64_t) 0;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:303:31-35
        
        int64_t lifted_lambda_res_21229 = add64((int64_t) 1, lifted_lambda_res_21223);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:354:28-32
        
        int64_t lifted_lambda_res_21232 = mul64((int64_t) 2, lifted_lambda_res_21223);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:346:39-73
        
        bool cond_21239 = eta_p_21220 == (int64_t) -1;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:346:39-73
        
        int64_t lifted_lambda_res_21240;
        
        if (cond_21239) {
            lifted_lambda_res_21240 = (int64_t) -1;
        } else {
            // ../lib/github.com/diku-dk/vtree/vtree.fut:346:63-73
            
            bool y_21242 = slt64(eta_p_21220, (int64_t) 2);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:346:63-73
            
            bool bounds_check_21243 = cond_21222 && y_21242;
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:346:63-73
            
            bool index_certs_21244;
            
            if (!bounds_check_21243) {
                set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) eta_p_21220, "] out of bounds for array of shape [", (long long) (int64_t) 2, "].", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:346:63-73\n   #1  ./test_operations.fut:123:7-142:103\n"));
                err = FUTHARK_PROGRAM_ERROR;
                goto cleanup;
            }
            // ../lib/github.com/diku-dk/vtree/vtree.fut:346:63-73
            
            int64_t lifted_lambda_res_f_res_21245 = ((int64_t *) mem_23350.mem)[eta_p_21220];
            
            lifted_lambda_res_21240 = lifted_lambda_res_f_res_21245;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:304:28-31
        
        int64_t defunc_0_op_res_17960 = add64(lifted_lambda_res_21229, scanacc_22862);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:355:36-39
        
        int64_t defunc_0_op_res_18193 = add64(lifted_lambda_res_21232, scanacc_22863);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:328:21-24
        
        int64_t defunc_0_op_res_18226 = add64(lifted_lambda_res_21223, scanacc_22864);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:328:21-24
        
        int64_t defunc_0_op_res_18095 = add64(lifted_lambda_res_21223, scanacc_22865);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:302:40-43
        
        int64_t defunc_0_op_res_17941 = add64(lifted_lambda_res_21223, scanacc_22866);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:306:34-37
        
        int64_t defunc_0_op_res_17976 = add64(lifted_lambda_res_21223, redout_22872);
        
        ((int64_t *) mem_23362.mem)[i_22875] = defunc_0_op_res_17960;
        ((int64_t *) mem_23363.mem)[i_22875] = defunc_0_op_res_18193;
        ((int64_t *) mem_23364.mem)[i_22875] = defunc_0_op_res_18226;
        ((int64_t *) mem_23365.mem)[i_22875] = defunc_0_op_res_18095;
        ((int64_t *) mem_23366.mem)[i_22875] = defunc_0_op_res_17941;
        ((int64_t *) mem_23367.mem)[i_22875] = lifted_lambda_res_21240;
        ((int64_t *) mem_23368.mem)[i_22875] = lifted_lambda_res_21223;
        
        int64_t scanacc_tmp_23727 = defunc_0_op_res_17960;
        int64_t scanacc_tmp_23728 = defunc_0_op_res_18193;
        int64_t scanacc_tmp_23729 = defunc_0_op_res_18226;
        int64_t scanacc_tmp_23730 = defunc_0_op_res_18095;
        int64_t scanacc_tmp_23731 = defunc_0_op_res_17941;
        int64_t redout_tmp_23737 = defunc_0_op_res_17976;
        
        scanacc_22862 = scanacc_tmp_23727;
        scanacc_22863 = scanacc_tmp_23728;
        scanacc_22864 = scanacc_tmp_23729;
        scanacc_22865 = scanacc_tmp_23730;
        scanacc_22866 = scanacc_tmp_23731;
        redout_22872 = redout_tmp_23737;
    }
    discard_22883 = scanacc_22862;
    discard_22884 = scanacc_22863;
    discard_22885 = scanacc_22864;
    discard_22886 = scanacc_22865;
    discard_22887 = scanacc_22866;
    defunc_0_reduce_res_22082 = redout_22872;
    if (memblock_unref(ctx, &mem_23350, "mem_23350") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23351, "mem_23351") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23355, "mem_23355") != 0)
        return 1;
    // ../lib/github.com/diku-dk/vtree/vtree.fut:220:13-33
    if (memblock_alloc(ctx, &mem_23411, (int64_t) 64, "mem_23411")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:220:13-33
    for (int64_t nest_i_23740 = 0; nest_i_23740 < (int64_t) 8; nest_i_23740++) {
        ((int64_t *) mem_23411.mem)[nest_i_23740] = (int64_t) 0;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:365:10-15
    // Trace: trace
    fprintf(ctx->log, "%s", "trace: ");
    for (int64_t nest_i_23741 = 0; nest_i_23741 < (int64_t) 4; nest_i_23741++) {
        int64_t arr_elem_23742 = ((int64_t *) mem_23344.mem)[nest_i_23741];
        
        fprintf(ctx->log, "%lld%s", (long long) arr_elem_23742, " ");
    }
    fprintf(ctx->log, "%s", "\n");
    // ../lib/github.com/diku-dk/vtree/vtree.fut:365:10-15
    // Trace: trace
    fprintf(ctx->log, "%s", "trace: ");
    for (int64_t nest_i_23743 = 0; nest_i_23743 < (int64_t) 4; nest_i_23743++) {
        int64_t arr_elem_23744 = ((int64_t *) mem_23368.mem)[nest_i_23743];
        
        fprintf(ctx->log, "%lld%s", (long long) arr_elem_23744, " ");
    }
    fprintf(ctx->log, "%s", "\n");
    // ../lib/github.com/diku-dk/vtree/vtree.fut:221:13-30
    
    bool acc_cert_18280;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:221:13-30
    for (int64_t i_22889 = 0; i_22889 < (int64_t) 4; i_22889++) {
        int64_t v_18284 = ((int64_t *) mem_23344.mem)[i_22889];
        int64_t v_18285 = ((int64_t *) mem_23368.mem)[i_22889];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:221:13-30
        // UpdateAcc
        if (sle64((int64_t) 0, v_18284) && slt64(v_18284, (int64_t) 8)) {
            ((int64_t *) mem_23411.mem)[v_18284] = v_18285;
        }
    }
    if (memblock_unref(ctx, &mem_23368, "mem_23368") != 0)
        return 1;
    // ../lib/github.com/diku-dk/vtree/vtree.fut:132:24-36
    if (memblock_alloc(ctx, &mem_23412, (int64_t) 64, "mem_23412")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:132:24-36
    
    int64_t discard_22895;
    int64_t scanacc_22891 = (int64_t) 0;
    
    for (int64_t i_22893 = 0; i_22893 < (int64_t) 8; i_22893++) {
        int64_t x_18288 = ((int64_t *) mem_23411.mem)[i_22893];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:366:34-37
        
        int64_t defunc_0_op_res_18291 = add64(x_18288, scanacc_22891);
        
        ((int64_t *) mem_23412.mem)[i_22893] = defunc_0_op_res_18291;
        
        int64_t scanacc_tmp_23746 = defunc_0_op_res_18291;
        
        scanacc_22891 = scanacc_tmp_23746;
    }
    discard_22895 = scanacc_22891;
    if (memblock_unref(ctx, &mem_23411, "mem_23411") != 0)
        return 1;
    // ../lib/github.com/diku-dk/vtree/vtree.fut:130:5-132:37
    if (memblock_alloc(ctx, &mem_23419, (int64_t) 64, "mem_23419")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:130:5-132:37
    for (int64_t i_22898 = 0; i_22898 < (int64_t) 8; i_22898++) {
        // ../lib/github.com/diku-dk/vtree/vtree.fut:132:11-36
        
        int64_t zv_lhs_18468 = add64((int64_t) -1, i_22898);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:132:11-36
        
        int64_t tmp_18469 = smod64(zv_lhs_18468, (int64_t) 8);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:132:11-36
        
        int64_t lifted_lambda_res_18470 = ((int64_t *) mem_23412.mem)[tmp_18469];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:130:19-43
        
        bool cond_18472 = i_22898 == (int64_t) 0;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:130:19-43
        
        int64_t lifted_lambda_res_18473;
        
        if (cond_18472) {
            lifted_lambda_res_18473 = (int64_t) 0;
        } else {
            lifted_lambda_res_18473 = lifted_lambda_res_18470;
        }
        ((int64_t *) mem_23419.mem)[i_22898] = lifted_lambda_res_18473;
    }
    if (memblock_unref(ctx, &mem_23412, "mem_23412") != 0)
        return 1;
    // ../lib/github.com/diku-dk/vtree/vtree.fut:365:10-15
    // Trace: trace
    fprintf(ctx->log, "%s", "trace: ");
    for (int64_t nest_i_23749 = 0; nest_i_23749 < (int64_t) 4; nest_i_23749++) {
        int64_t arr_elem_23750 = ((int64_t *) mem_23345.mem)[nest_i_23749];
        
        fprintf(ctx->log, "%lld%s", (long long) arr_elem_23750, " ");
    }
    fprintf(ctx->log, "%s", "\n");
    // ../lib/github.com/diku-dk/vtree/vtree.fut:223:14-225:21
    if (memblock_alloc(ctx, &mem_23426, (int64_t) 32, "mem_23426")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:223:14-225:21
    for (int64_t i_22902 = 0; i_22902 < (int64_t) 4; i_22902++) {
        int64_t eta_p_18449 = ((int64_t *) mem_23345.mem)[i_22902];
        int64_t eta_p_18450 = ((int64_t *) mem_23344.mem)[i_22902];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:223:25-29
        
        bool x_18451 = sle64((int64_t) 0, eta_p_18449);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:223:25-29
        
        bool y_18452 = slt64(eta_p_18449, (int64_t) 8);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:223:25-29
        
        bool bounds_check_18453 = x_18451 && y_18452;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:223:25-29
        
        bool index_certs_18454;
        
        if (!bounds_check_18453) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) eta_p_18449, "] out of bounds for array of shape [", (long long) (int64_t) 8, "].", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:223:25-29\n   #1  ../lib/github.com/diku-dk/vtree/vtree.fut:361:9-366:33\n   #2  ./test_operations.fut:123:7-142:103\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:223:25-29
        
        int64_t lifted_lambda_res_18455 = ((int64_t *) mem_23419.mem)[eta_p_18449];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:224:30-34
        
        bool x_18457 = sle64((int64_t) 0, eta_p_18450);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:224:30-34
        
        bool y_18458 = slt64(eta_p_18450, (int64_t) 8);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:224:30-34
        
        bool bounds_check_18459 = x_18457 && y_18458;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:224:30-34
        
        bool index_certs_18460;
        
        if (!bounds_check_18459) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) eta_p_18450, "] out of bounds for array of shape [", (long long) (int64_t) 8, "].", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:224:30-34\n   #1  ../lib/github.com/diku-dk/vtree/vtree.fut:361:9-366:33\n   #2  ./test_operations.fut:123:7-142:103\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:224:30-34
        
        int64_t inv_arg0_18461 = ((int64_t *) mem_23419.mem)[eta_p_18450];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:366:38-45
        
        int64_t neg_res_18462 = -inv_arg0_18461;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:366:34-37
        
        int64_t defunc_0_f_res_18464 = add64(lifted_lambda_res_18455, neg_res_18462);
        
        ((int64_t *) mem_23426.mem)[i_22902] = defunc_0_f_res_18464;
    }
    if (memblock_unref(ctx, &mem_23419, "mem_23419") != 0)
        return 1;
    // ../lib/github.com/diku-dk/vtree/vtree.fut:366:84-89
    // Trace: trace
    fprintf(ctx->log, "%s", "trace: ");
    for (int64_t nest_i_23752 = 0; nest_i_23752 < (int64_t) 4; nest_i_23752++) {
        int64_t arr_elem_23753 = ((int64_t *) mem_23426.mem)[nest_i_23752];
        
        fprintf(ctx->log, "%lld%s", (long long) arr_elem_23753, " ");
    }
    fprintf(ctx->log, "%s", "\n");
    // ../lib/github.com/diku-dk/vtree/vtree.fut:330:26-53
    
    int64_t bytes_23433 = (int64_t) 8 * defunc_0_reduce_res_22082;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:330:26-53
    if (memblock_alloc(ctx, &mem_23434, bytes_23433, "mem_23434")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:330:26-53
    for (int64_t nest_i_23754 = 0; nest_i_23754 < defunc_0_reduce_res_22082; nest_i_23754++) {
        ((int64_t *) mem_23434.mem)[nest_i_23754] = (int64_t) 0;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:330:26-53
    if (memblock_alloc(ctx, &mem_23436, bytes_23433, "mem_23436")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:330:26-53
    for (int64_t nest_i_23755 = 0; nest_i_23755 < defunc_0_reduce_res_22082; nest_i_23755++) {
        ((int64_t *) mem_23436.mem)[nest_i_23755] = (int64_t) 0;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:344:28-59
    if (memblock_alloc(ctx, &mem_23437, defunc_0_reduce_res_22082, "mem_23437")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:344:28-59
    for (int64_t nest_i_23756 = 0; nest_i_23756 < defunc_0_reduce_res_22082; nest_i_23756++) {
        ((bool *) mem_23437.mem)[nest_i_23756] = 0;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:307:25-42
    
    int64_t result_sizze_17977 = add64((int64_t) 4, defunc_0_reduce_res_22082);
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:317:41-82
    
    int64_t bytes_23438 = (int64_t) 8 * result_sizze_17977;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:317:41-82
    if (memblock_alloc(ctx, &mem_23439, bytes_23438, "mem_23439")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:317:41-82
    for (int64_t nest_i_23757 = 0; nest_i_23757 < result_sizze_17977; nest_i_23757++) {
        ((int64_t *) mem_23439.mem)[nest_i_23757] = (int64_t) 0;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:316:39-65
    if (memblock_alloc(ctx, &mem_23441, bytes_23438, "mem_23441")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:316:39-65
    for (int64_t nest_i_23758 = 0; nest_i_23758 < result_sizze_17977; nest_i_23758++) {
        ((int64_t *) mem_23441.mem)[nest_i_23758] = (int64_t) 0;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:315:39-65
    if (memblock_alloc(ctx, &mem_23443, bytes_23438, "mem_23443")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:315:39-65
    for (int64_t nest_i_23759 = 0; nest_i_23759 < result_sizze_17977; nest_i_23759++) {
        ((int64_t *) mem_23443.mem)[nest_i_23759] = (int64_t) 0;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:311:24-50
    if (memblock_alloc(ctx, &mem_23444, result_sizze_17977, "mem_23444")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:311:24-50
    for (int64_t nest_i_23760 = 0; nest_i_23760 < result_sizze_17977; nest_i_23760++) {
        ((bool *) mem_23444.mem)[nest_i_23760] = 1;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:330:17-65
    if (memblock_alloc(ctx, &mem_23459, (int64_t) 32, "mem_23459")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:330:17-65
    if (memblock_alloc(ctx, &mem_23460, (int64_t) 32, "mem_23460")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:329:16-330:65
    if (memblock_alloc(ctx, &mem_23445, (int64_t) 32, "mem_23445")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:329:16-330:65
    if (memblock_alloc(ctx, &mem_23446, (int64_t) 32, "mem_23446")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:330:17-65
    
    bool acc_cert_18630;
    bool acc_cert_19523;
    bool acc_cert_20869;
    bool acc_cert_20870;
    bool acc_cert_20871;
    bool acc_cert_20872;
    bool acc_cert_21035;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:329:16-330:65
    for (int64_t i_22915 = 0; i_22915 < (int64_t) 4; i_22915++) {
        int64_t v_21542 = ((int64_t *) mem_23346.mem)[i_22915];
        int64_t v_21544 = ((int64_t *) mem_23345.mem)[i_22915];
        int64_t v_21546 = ((int64_t *) mem_23344.mem)[i_22915];
        int64_t eta_p_21548 = ((int64_t *) mem_23426.mem)[i_22915];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:132:11-36
        
        int64_t zv_lhs_21553 = add64((int64_t) -1, i_22915);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:132:11-36
        
        int64_t tmp_21554 = smod64(zv_lhs_21553, (int64_t) 4);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:132:11-36
        
        int64_t lifted_lambda_res_21555 = ((int64_t *) mem_23366.mem)[tmp_21554];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:130:19-43
        
        bool cond_21556 = i_22915 == (int64_t) 0;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:130:19-43
        
        int64_t lifted_lambda_res_21557;
        
        if (cond_21556) {
            lifted_lambda_res_21557 = (int64_t) 0;
        } else {
            lifted_lambda_res_21557 = lifted_lambda_res_21555;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:367:44-47
        
        int64_t defunc_0_f_res_21558 = add64(eta_p_21548, lifted_lambda_res_21557);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:344:19-100
        // UpdateAcc
        if (sle64((int64_t) 0, lifted_lambda_res_21557) && slt64(lifted_lambda_res_21557, defunc_0_reduce_res_22082)) {
            ((bool *) mem_23437.mem)[lifted_lambda_res_21557] = 1;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:132:11-36
        
        int64_t lifted_lambda_res_21566 = ((int64_t *) mem_23362.mem)[tmp_21554];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:130:19-43
        
        int64_t lifted_lambda_res_21568;
        
        if (cond_21556) {
            lifted_lambda_res_21568 = (int64_t) 0;
        } else {
            lifted_lambda_res_21568 = lifted_lambda_res_21566;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:317:32-110
        // UpdateAcc
        if (sle64((int64_t) 0, lifted_lambda_res_21568) && slt64(lifted_lambda_res_21568, result_sizze_17977)) {
            ((int64_t *) mem_23439.mem)[lifted_lambda_res_21568] = v_21542;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:316:30-91
        // UpdateAcc
        if (sle64((int64_t) 0, lifted_lambda_res_21568) && slt64(lifted_lambda_res_21568, result_sizze_17977)) {
            ((int64_t *) mem_23441.mem)[lifted_lambda_res_21568] = v_21544;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:315:30-91
        // UpdateAcc
        if (sle64((int64_t) 0, lifted_lambda_res_21568) && slt64(lifted_lambda_res_21568, result_sizze_17977)) {
            ((int64_t *) mem_23443.mem)[lifted_lambda_res_21568] = v_21546;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:312:24-71
        // UpdateAcc
        if (sle64((int64_t) 0, lifted_lambda_res_21568) && slt64(lifted_lambda_res_21568, result_sizze_17977)) {
            ((bool *) mem_23444.mem)[lifted_lambda_res_21568] = 0;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:329:27-54
        
        int64_t lifted_lambda_res_21584;
        
        if (cond_21556) {
            lifted_lambda_res_21584 = (int64_t) 0;
        } else {
            // ../lib/github.com/diku-dk/vtree/vtree.fut:329:51-53
            
            int64_t tmp_21585 = sub64(i_22915, (int64_t) 1);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:329:47-54
            
            bool x_21586 = sle64((int64_t) 0, tmp_21585);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:329:47-54
            
            bool y_21587 = slt64(tmp_21585, (int64_t) 4);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:329:47-54
            
            bool bounds_check_21588 = x_21586 && y_21587;
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:329:47-54
            
            bool index_certs_21589;
            
            if (!bounds_check_21588) {
                set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) tmp_21585, "] out of bounds for array of shape [", (long long) (int64_t) 4, "].", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:329:47-54\n   #1  ../lib/github.com/diku-dk/vtree/vtree.fut:335:34-38\n   #2  ../lib/github.com/diku-dk/vtree/vtree.fut:347:46-72\n   #3  ./test_operations.fut:123:7-142:103\n"));
                err = FUTHARK_PROGRAM_ERROR;
                goto cleanup;
            }
            // ../lib/github.com/diku-dk/vtree/vtree.fut:329:47-54
            
            int64_t lifted_lambda_res_f_res_21590 = ((int64_t *) mem_23365.mem)[tmp_21585];
            
            lifted_lambda_res_21584 = lifted_lambda_res_f_res_21590;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:330:17-65
        // UpdateAcc
        if (sle64((int64_t) 0, lifted_lambda_res_21584) && slt64(lifted_lambda_res_21584, defunc_0_reduce_res_22082)) {
            ((int64_t *) mem_23436.mem)[lifted_lambda_res_21584] = i_22915;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:329:27-54
        
        int64_t lifted_lambda_res_21605;
        
        if (cond_21556) {
            lifted_lambda_res_21605 = (int64_t) 0;
        } else {
            // ../lib/github.com/diku-dk/vtree/vtree.fut:329:51-53
            
            int64_t tmp_21606 = sub64(i_22915, (int64_t) 1);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:329:47-54
            
            bool x_21607 = sle64((int64_t) 0, tmp_21606);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:329:47-54
            
            bool y_21608 = slt64(tmp_21606, (int64_t) 4);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:329:47-54
            
            bool bounds_check_21609 = x_21607 && y_21608;
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:329:47-54
            
            bool index_certs_21610;
            
            if (!bounds_check_21609) {
                set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) tmp_21606, "] out of bounds for array of shape [", (long long) (int64_t) 4, "].", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:329:47-54\n   #1  ../lib/github.com/diku-dk/vtree/vtree.fut:335:34-38\n   #2  ../lib/github.com/diku-dk/vtree/vtree.fut:358:48-76\n   #3  ./test_operations.fut:123:7-142:103\n"));
                err = FUTHARK_PROGRAM_ERROR;
                goto cleanup;
            }
            // ../lib/github.com/diku-dk/vtree/vtree.fut:329:47-54
            
            int64_t lifted_lambda_res_f_res_21611 = ((int64_t *) mem_23364.mem)[tmp_21606];
            
            lifted_lambda_res_21605 = lifted_lambda_res_f_res_21611;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:330:17-65
        // UpdateAcc
        if (sle64((int64_t) 0, lifted_lambda_res_21605) && slt64(lifted_lambda_res_21605, defunc_0_reduce_res_22082)) {
            ((int64_t *) mem_23434.mem)[lifted_lambda_res_21605] = i_22915;
        }
        ((int64_t *) mem_23445.mem)[i_22915] = lifted_lambda_res_21568;
        ((int64_t *) mem_23446.mem)[i_22915] = defunc_0_f_res_21558;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:330:17-65
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_23459.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) mem_23446.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 4});
    // ../lib/github.com/diku-dk/vtree/vtree.fut:330:17-65
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_23460.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) mem_23445.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 4});
    if (memblock_unref(ctx, &mem_23344, "mem_23344") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23345, "mem_23345") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23346, "mem_23346") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23362, "mem_23362") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23364, "mem_23364") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23365, "mem_23365") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23366, "mem_23366") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23426, "mem_23426") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23445, "mem_23445") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23446, "mem_23446") != 0)
        return 1;
    // ../lib/github.com/diku-dk/vtree/vtree.fut:313:10-56
    if (memblock_alloc(ctx, &mem_23462, bytes_23438, "mem_23462")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:313:10-56
    if (memblock_alloc(ctx, &mem_23464, bytes_23438, "mem_23464")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:313:10-56
    
    int64_t discard_22926;
    int64_t scanacc_22920 = (int64_t) 0;
    
    for (int64_t i_22923 = 0; i_22923 < result_sizze_17977; i_22923++) {
        // ../lib/github.com/diku-dk/vtree/vtree.fut:313:24-37
        
        bool lifted_lambda_res_20670 = ((bool *) mem_23444.mem)[i_22923];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:313:10-56
        
        int64_t defunc_0_f_res_20671 = btoi_bool_i64(lifted_lambda_res_20670);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:313:10-56
        
        int64_t defunc_0_op_res_17999 = add64(defunc_0_f_res_20671, scanacc_22920);
        
        ((int64_t *) mem_23462.mem)[i_22923] = defunc_0_op_res_17999;
        ((int64_t *) mem_23464.mem)[i_22923] = defunc_0_f_res_20671;
        
        int64_t scanacc_tmp_23770 = defunc_0_op_res_17999;
        
        scanacc_22920 = scanacc_tmp_23770;
    }
    discard_22926 = scanacc_22920;
    if (memblock_unref(ctx, &mem_23444, "mem_23444") != 0)
        return 1;
    // ../lib/github.com/diku-dk/vtree/vtree.fut:313:10-56
    
    bool cond_18000 = result_sizze_17977 == (int64_t) 0;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:313:10-56
    
    bool x_18001 = !cond_18000;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:313:10-56
    
    int64_t tmp_18002 = sub64(result_sizze_17977, (int64_t) 1);
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:313:10-56
    
    bool x_18003 = sle64((int64_t) 0, tmp_18002);
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:313:10-56
    
    bool y_18004 = slt64(tmp_18002, result_sizze_17977);
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:313:10-56
    
    bool bounds_check_18005 = x_18003 && y_18004;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:313:10-56
    
    bool protect_assert_disj_18006 = cond_18000 || bounds_check_18005;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:313:10-56
    
    bool index_certs_18007;
    
    if (!protect_assert_disj_18006) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) tmp_18002, "] out of bounds for array of shape [", (long long) result_sizze_17977, "].", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:313:10-56\n   #1  ./test_operations.fut:123:7-142:103\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:313:10-56
    
    int64_t m_f_res_18008;
    
    if (x_18001) {
        // ../lib/github.com/diku-dk/vtree/vtree.fut:313:10-56
        
        int64_t x_21943 = ((int64_t *) mem_23462.mem)[tmp_18002];
        
        m_f_res_18008 = x_21943;
    } else {
        m_f_res_18008 = (int64_t) 0;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:313:10-56
    
    int64_t m_18010;
    
    if (cond_18000) {
        m_18010 = (int64_t) 0;
    } else {
        m_18010 = m_f_res_18008;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:313:10-56
    
    int64_t bytes_23477 = (int64_t) 8 * m_18010;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:313:10-56
    if (memblock_alloc(ctx, &mem_23478, bytes_23477, "mem_23478")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:313:10-56
    
    bool acc_cert_20636;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:313:10-56
    for (int64_t i_22928 = 0; i_22928 < result_sizze_17977; i_22928++) {
        int64_t eta_p_20651 = ((int64_t *) mem_23464.mem)[i_22928];
        int64_t eta_p_20652 = ((int64_t *) mem_23462.mem)[i_22928];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:313:10-56
        
        bool cond_20655 = eta_p_20651 == (int64_t) 1;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:313:10-56
        
        int64_t lifted_lambda_res_20656;
        
        if (cond_20655) {
            // ../lib/github.com/diku-dk/vtree/vtree.fut:313:10-56
            
            int64_t lifted_lambda_res_t_res_21944 = sub64(eta_p_20652, (int64_t) 1);
            
            lifted_lambda_res_20656 = lifted_lambda_res_t_res_21944;
        } else {
            lifted_lambda_res_20656 = (int64_t) -1;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:313:10-56
        // UpdateAcc
        if (sle64((int64_t) 0, lifted_lambda_res_20656) && slt64(lifted_lambda_res_20656, m_18010)) {
            ((int64_t *) mem_23478.mem)[lifted_lambda_res_20656] = i_22928;
        }
    }
    if (memblock_unref(ctx, &mem_23462, "mem_23462") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23464, "mem_23464") != 0)
        return 1;
    
    bool eq_x_y_18354 = defunc_0_reduce_res_22082 == (int64_t) 0;
    bool eq_x_zz_18355 = defunc_0_reduce_res_22082 == m_f_res_18008;
    bool p_and_eq_x_y_18356 = cond_18000 && eq_x_y_18354;
    bool p_and_eq_x_y_18358 = x_18001 && eq_x_zz_18355;
    bool dim_match_18026 = p_and_eq_x_y_18356 || p_and_eq_x_y_18358;
    
    // ./test_operations.fut:123:7-142:103
    
    bool empty_or_match_cert_18027;
    
    if (!dim_match_18026) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (desugared) shape [", (long long) m_18010, "] cannot match shape of type \"[", (long long) defunc_0_reduce_res_22082, "]i64\".", "-> #0  ./test_operations.fut:123:7-142:103\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:350:28-103
    if (memblock_alloc(ctx, &mem_23496, bytes_23433, "mem_23496")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:350:28-103
    if (memblock_alloc(ctx, &mem_23498, bytes_23433, "mem_23498")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:348:10-352:109
    if (memblock_alloc(ctx, &mem_23480, bytes_23433, "mem_23480")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:348:10-352:109
    if (memblock_alloc(ctx, &mem_23482, bytes_23433, "mem_23482")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:350:28-103
    
    bool acc_cert_20035;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:348:10-352:109
    
    int64_t inpacc_21963;
    int64_t inpacc_21965;
    int64_t inpacc_20190;
    int64_t inpacc_20192;
    
    inpacc_20190 = (int64_t) 0;
    inpacc_20192 = (int64_t) 0;
    for (int64_t i_23009 = 0; i_23009 < defunc_0_reduce_res_22082; i_23009++) {
        bool x_23192 = ((bool *) mem_23437.mem)[i_23009];
        int64_t eta_p_23208 = ((int64_t *) mem_23436.mem)[i_23009];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:331:23-27
        
        bool lifted_lambda_res_23209 = slt64((int64_t) 0, eta_p_23208);
        int64_t v_23237 = ((int64_t *) mem_23478.mem)[i_23009];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:322:35-61
        
        int64_t v_23239;
        
        if (x_23192) {
            v_23239 = (int64_t) 1;
        } else {
            // ../lib/github.com/diku-dk/vtree/vtree.fut:339:34-37
            
            int64_t defunc_0_g_res_23240 = add64((int64_t) 1, inpacc_20190);
            
            v_23239 = defunc_0_g_res_23240;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:340:22-24
        
        int64_t lifted_lambda_res_23241 = sub64(v_23239, (int64_t) 1);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:322:35-61
        
        int64_t v_23243;
        
        if (lifted_lambda_res_23209) {
            v_23243 = eta_p_23208;
        } else {
            // ../lib/github.com/diku-dk/vtree/vtree.fut:332:25-28
            
            int64_t defunc_0_g_res_23244 = add64(inpacc_20192, eta_p_23208);
            
            v_23243 = defunc_0_g_res_23244;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:336:21-26
        
        bool x_23245 = sle64((int64_t) 0, v_23243);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:336:21-26
        
        bool y_23246 = slt64(v_23243, (int64_t) 4);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:336:21-26
        
        bool bounds_check_23247 = x_23245 && y_23246;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:336:21-26
        
        bool index_certs_23248;
        
        if (!bounds_check_23247) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) v_23243, "] out of bounds for array of shape [", (long long) (int64_t) 4, "].", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:336:21-26\n   #1  ../lib/github.com/diku-dk/vtree/vtree.fut:347:46-72\n   #2  ./test_operations.fut:123:7-142:103\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:336:21-26
        
        int64_t lifted_lambda_res_23249 = ((int64_t *) mem_23367.mem)[v_23243];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:348:15-18
        
        int64_t defunc_0_f_res_23250 = add64(lifted_lambda_res_23241, lifted_lambda_res_23249);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:350:76-90
        
        bool x_23251 = sle64((int64_t) 0, defunc_0_f_res_23250);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:350:76-90
        
        bool y_23252 = slt64(defunc_0_f_res_23250, (int64_t) 5);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:350:76-90
        
        bool bounds_check_23253 = x_23251 && y_23252;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:350:76-90
        
        bool index_certs_23254;
        
        if (!bounds_check_23253) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) defunc_0_f_res_23250, "] out of bounds for array of shape [", (long long) (int64_t) 5, "].", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:350:76-90\n   #1  ./test_operations.fut:123:7-142:103\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:350:76-90
        
        int64_t lifted_lambda_res_23255 = ((int64_t *) mem_23347.mem)[defunc_0_f_res_23250];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:350:28-103
        // UpdateAcc
        if (sle64((int64_t) 0, v_23237) && slt64(v_23237, result_sizze_17977)) {
            ((int64_t *) mem_23443.mem)[v_23237] = lifted_lambda_res_23255;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:352:80-96
        
        int64_t lifted_lambda_res_23257 = ((int64_t *) mem_23349.mem)[defunc_0_f_res_23250];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:351:76-90
        
        int64_t lifted_lambda_res_23258 = ((int64_t *) mem_23348.mem)[defunc_0_f_res_23250];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:322:35-61
        
        int64_t v_20230;
        
        if (x_23192) {
            v_20230 = (int64_t) 1;
        } else {
            // ../lib/github.com/diku-dk/vtree/vtree.fut:339:34-37
            
            int64_t defunc_0_g_res_20231 = add64((int64_t) 1, inpacc_20190);
            
            v_20230 = defunc_0_g_res_20231;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:322:35-61
        
        int64_t v_20293;
        
        if (lifted_lambda_res_23209) {
            v_20293 = eta_p_23208;
        } else {
            // ../lib/github.com/diku-dk/vtree/vtree.fut:332:25-28
            
            int64_t defunc_0_g_res_20294 = add64(inpacc_20192, eta_p_23208);
            
            v_20293 = defunc_0_g_res_20294;
        }
        ((int64_t *) mem_23480.mem)[i_23009] = lifted_lambda_res_23258;
        ((int64_t *) mem_23482.mem)[i_23009] = lifted_lambda_res_23257;
        
        int64_t inpacc_tmp_23774 = v_20230;
        int64_t inpacc_tmp_23775 = v_20293;
        
        inpacc_20190 = inpacc_tmp_23774;
        inpacc_20192 = inpacc_tmp_23775;
    }
    inpacc_21963 = inpacc_20190;
    inpacc_21965 = inpacc_20192;
    // ../lib/github.com/diku-dk/vtree/vtree.fut:350:28-103
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_23496.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) mem_23482.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {defunc_0_reduce_res_22082});
    // ../lib/github.com/diku-dk/vtree/vtree.fut:350:28-103
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_23498.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) mem_23480.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {defunc_0_reduce_res_22082});
    if (memblock_unref(ctx, &mem_23347, "mem_23347") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23348, "mem_23348") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23349, "mem_23349") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23367, "mem_23367") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23436, "mem_23436") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23437, "mem_23437") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23480, "mem_23480") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23482, "mem_23482") != 0)
        return 1;
    // ../lib/github.com/diku-dk/vtree/vtree.fut:369:39-65
    if (memblock_alloc(ctx, &mem_23500, bytes_23438, "mem_23500")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:369:39-65
    for (int64_t nest_i_23779 = 0; nest_i_23779 < result_sizze_17977; nest_i_23779++) {
        ((int64_t *) mem_23500.mem)[nest_i_23779] = (int64_t) 0;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:367:87-92
    // Trace: trace
    fprintf(ctx->log, "%s", "trace: ");
    for (int64_t nest_i_23780 = 0; nest_i_23780 < (int64_t) 4; nest_i_23780++) {
        int64_t arr_elem_23781 = ((int64_t *) mem_23459.mem)[nest_i_23780];
        
        fprintf(ctx->log, "%lld%s", (long long) arr_elem_23781, " ");
    }
    fprintf(ctx->log, "%s", "\n");
    // ../lib/github.com/diku-dk/vtree/vtree.fut:356:39-65
    if (memblock_alloc(ctx, &mem_23502, bytes_23438, "mem_23502")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:356:39-65
    for (int64_t nest_i_23782 = 0; nest_i_23782 < result_sizze_17977; nest_i_23782++) {
        ((int64_t *) mem_23502.mem)[nest_i_23782] = (int64_t) 0;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:356:22-369:100
    for (int64_t iter_23021 = 0; iter_23021 < (int64_t) 4; iter_23021++) {
        int64_t pixel_23024 = ((int64_t *) mem_23459.mem)[iter_23021];
        int64_t pixel_23025 = ((int64_t *) mem_23460.mem)[iter_23021];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:132:11-36
        
        int64_t zv_lhs_21252 = add64((int64_t) -1, iter_23021);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:132:11-36
        
        int64_t tmp_21253 = smod64(zv_lhs_21252, (int64_t) 4);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:132:11-36
        
        int64_t lifted_lambda_res_21254 = ((int64_t *) mem_23363.mem)[tmp_21253];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:130:19-43
        
        bool cond_21256 = iter_23021 == (int64_t) 0;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:130:19-43
        
        int64_t lifted_lambda_res_21257;
        
        if (cond_21256) {
            lifted_lambda_res_21257 = (int64_t) 0;
        } else {
            lifted_lambda_res_21257 = lifted_lambda_res_21254;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:367:33-37
        
        int64_t lifted_lambda_res_21259 = mul64((int64_t) 2, pixel_23024);
        bool less_than_zzero_23028 = slt64(pixel_23025, (int64_t) 0);
        bool greater_than_sizze_23029 = sle64(result_sizze_17977, pixel_23025);
        bool outside_bounds_dim_23030 = less_than_zzero_23028 || greater_than_sizze_23029;
        
        if (!outside_bounds_dim_23030) {
            int64_t read_hist_23032 = ((int64_t *) mem_23500.mem)[pixel_23025];
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:369:67-70
            
            int64_t defunc_0_f_res_18335 = add64(lifted_lambda_res_21259, read_hist_23032);
            
            ((int64_t *) mem_23500.mem)[pixel_23025] = defunc_0_f_res_18335;
        }
        if (!outside_bounds_dim_23030) {
            int64_t read_hist_23039 = ((int64_t *) mem_23502.mem)[pixel_23025];
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:356:67-70
            
            int64_t defunc_0_f_res_18209 = add64(lifted_lambda_res_21257, read_hist_23039);
            
            ((int64_t *) mem_23502.mem)[pixel_23025] = defunc_0_f_res_18209;
        }
    }
    if (memblock_unref(ctx, &mem_23363, "mem_23363") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23459, "mem_23459") != 0)
        return 1;
    // ../lib/github.com/diku-dk/vtree/vtree.fut:369:104-109
    // Trace: trace
    fprintf(ctx->log, "%s", "trace: ");
    for (int64_t nest_i_23785 = 0; nest_i_23785 < result_sizze_17977; nest_i_23785++) {
        int64_t arr_elem_23786 = ((int64_t *) mem_23500.mem)[nest_i_23785];
        
        fprintf(ctx->log, "%lld%s", (long long) arr_elem_23786, " ");
    }
    fprintf(ctx->log, "%s", "\n");
    // ../lib/github.com/diku-dk/vtree/vtree.fut:357:28-89
    if (memblock_alloc(ctx, &mem_23515, (int64_t) 32, "mem_23515")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:357:28-89
    for (int64_t i_23044 = 0; i_23044 < (int64_t) 4; i_23044++) {
        int64_t eta_p_18213 = ((int64_t *) mem_23460.mem)[i_23044];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:357:39-58
        
        bool x_18214 = sle64((int64_t) 0, eta_p_18213);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:357:39-58
        
        bool y_18215 = slt64(eta_p_18213, result_sizze_17977);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:357:39-58
        
        bool bounds_check_18216 = x_18214 && y_18215;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:357:39-58
        
        bool index_certs_18217;
        
        if (!bounds_check_18216) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) eta_p_18213, "] out of bounds for array of shape [", (long long) result_sizze_17977, "].", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:357:39-58\n   #1  ./test_operations.fut:123:7-142:103\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:357:39-58
        
        int64_t zp_lhs_18218 = ((int64_t *) mem_23443.mem)[eta_p_18213];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:357:61-74
        
        int64_t zp_rhs_18219 = ((int64_t *) mem_23502.mem)[eta_p_18213];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:357:59-74
        
        int64_t zp_lhs_18220 = add64(zp_lhs_18218, zp_rhs_18219);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:357:75-78
        
        int64_t lifted_lambda_res_18221 = add64((int64_t) 1, zp_lhs_18220);
        
        ((int64_t *) mem_23515.mem)[i_23044] = lifted_lambda_res_18221;
    }
    if (memblock_unref(ctx, &mem_23460, "mem_23460") != 0)
        return 1;
    // ../lib/github.com/diku-dk/vtree/vtree.fut:336:10-32
    if (memblock_alloc(ctx, &mem_23523, bytes_23433, "mem_23523")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:336:10-32
    
    int64_t inpacc_22093;
    int64_t inpacc_18579 = (int64_t) 0;
    
    for (int64_t i_23063 = 0; i_23063 < defunc_0_reduce_res_22082; i_23063++) {
        int64_t eta_p_23161 = ((int64_t *) mem_23434.mem)[i_23063];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:331:23-27
        
        bool lifted_lambda_res_23162 = slt64((int64_t) 0, eta_p_23161);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:322:35-61
        
        int64_t v_23176;
        
        if (lifted_lambda_res_23162) {
            v_23176 = eta_p_23161;
        } else {
            // ../lib/github.com/diku-dk/vtree/vtree.fut:332:25-28
            
            int64_t defunc_0_g_res_23177 = add64(inpacc_18579, eta_p_23161);
            
            v_23176 = defunc_0_g_res_23177;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:336:21-26
        
        bool x_23178 = sle64((int64_t) 0, v_23176);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:336:21-26
        
        bool y_23179 = slt64(v_23176, (int64_t) 4);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:336:21-26
        
        bool bounds_check_23180 = x_23178 && y_23179;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:336:21-26
        
        bool index_certs_23181;
        
        if (!bounds_check_23180) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) v_23176, "] out of bounds for array of shape [", (long long) (int64_t) 4, "].", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:336:21-26\n   #1  ../lib/github.com/diku-dk/vtree/vtree.fut:358:48-76\n   #2  ./test_operations.fut:123:7-142:103\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:336:21-26
        
        int64_t lifted_lambda_res_23182 = ((int64_t *) mem_23515.mem)[v_23176];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:322:35-61
        
        int64_t v_18618;
        
        if (lifted_lambda_res_23162) {
            v_18618 = eta_p_23161;
        } else {
            // ../lib/github.com/diku-dk/vtree/vtree.fut:332:25-28
            
            int64_t defunc_0_g_res_18619 = add64(inpacc_18579, eta_p_23161);
            
            v_18618 = defunc_0_g_res_18619;
        }
        ((int64_t *) mem_23523.mem)[i_23063] = lifted_lambda_res_23182;
        
        int64_t inpacc_tmp_23788 = v_18618;
        
        inpacc_18579 = inpacc_tmp_23788;
    }
    inpacc_22093 = inpacc_18579;
    if (memblock_unref(ctx, &mem_23434, "mem_23434") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23515, "mem_23515") != 0)
        return 1;
    // ../lib/github.com/diku-dk/vtree/vtree.fut:370:22-80
    for (int64_t iter_23065 = 0; iter_23065 < defunc_0_reduce_res_22082; iter_23065++) {
        int64_t pixel_23067 = ((int64_t *) mem_23478.mem)[iter_23065];
        int64_t pixel_23068 = ((int64_t *) mem_23523.mem)[iter_23065];
        bool less_than_zzero_23069 = slt64(pixel_23067, (int64_t) 0);
        bool greater_than_sizze_23070 = sle64(result_sizze_17977, pixel_23067);
        bool outside_bounds_dim_23071 = less_than_zzero_23069 || greater_than_sizze_23070;
        
        if (!outside_bounds_dim_23071) {
            int64_t read_hist_23073 = ((int64_t *) mem_23500.mem)[pixel_23067];
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:370:49-52
            
            int64_t defunc_0_f_res_18342 = add64(pixel_23068, read_hist_23073);
            
            ((int64_t *) mem_23500.mem)[pixel_23067] = defunc_0_f_res_18342;
        }
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:370:84-89
    // Trace: trace
    fprintf(ctx->log, "%s", "trace: ");
    for (int64_t nest_i_23791 = 0; nest_i_23791 < result_sizze_17977; nest_i_23791++) {
        int64_t arr_elem_23792 = ((int64_t *) mem_23500.mem)[nest_i_23791];
        
        fprintf(ctx->log, "%lld%s", (long long) arr_elem_23792, " ");
    }
    fprintf(ctx->log, "%s", "\n");
    // ./test_operations.fut:144:5-147:62
    
    bool cond_11933 = result_sizze_17977 == (int64_t) 11;
    
    // ./test_operations.fut:144:5-147:62
    
    bool cond_11934;
    
    if (cond_11933) {
        // ../lib/github.com/diku-dk/vtree/vtree.fut:359:22-80
        for (int64_t iter_23076 = 0; iter_23076 < defunc_0_reduce_res_22082; iter_23076++) {
            int64_t pixel_23078 = ((int64_t *) mem_23478.mem)[iter_23076];
            int64_t pixel_23079 = ((int64_t *) mem_23523.mem)[iter_23076];
            bool less_than_zzero_23080 = slt64(pixel_23078, (int64_t) 0);
            bool greater_than_sizze_23081 = sle64(result_sizze_17977, pixel_23078);
            bool outside_bounds_dim_23082 = less_than_zzero_23080 || greater_than_sizze_23081;
            
            if (!outside_bounds_dim_23082) {
                int64_t read_hist_23084 = ((int64_t *) mem_23502.mem)[pixel_23078];
                
                // ../lib/github.com/diku-dk/vtree/vtree.fut:359:49-52
                
                int64_t defunc_0_f_res_22048 = add64(pixel_23079, read_hist_23084);
                
                ((int64_t *) mem_23502.mem)[pixel_23078] = defunc_0_f_res_22048;
            }
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:372:18-54
        if (memblock_alloc(ctx, &mem_23543, bytes_23438, "mem_23543")) {
            err = 1;
            goto cleanup;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:372:18-54
        for (int64_t i_23089 = 0; i_23089 < result_sizze_17977; i_23089++) {
            int64_t eta_p_22055 = ((int64_t *) mem_23443.mem)[i_23089];
            int64_t eta_p_22056 = ((int64_t *) mem_23502.mem)[i_23089];
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:372:23-26
            
            int64_t defunc_0_f_res_22057 = add64(eta_p_22055, eta_p_22056);
            
            ((int64_t *) mem_23543.mem)[i_23089] = defunc_0_f_res_22057;
        }
        // ./test_operations.fut:145:24-44
        
        bool dim_match_22061 = (int64_t) 11 == result_sizze_17977;
        
        // ./test_operations.fut:145:24-44
        
        bool empty_or_match_cert_22062;
        
        if (!dim_match_22061) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (desugared) shape [", (long long) result_sizze_17977, "] cannot match shape of type \"[", (long long) (int64_t) 11, "]i64\".", "-> #0  ./test_operations.fut:145:24-44\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        // ./test_operations.fut:145:8-57
        
        bool defunc_0_reduce_res_22064;
        bool redout_23091 = 1;
        
        for (int64_t i_23092 = 0; i_23092 < (int64_t) 11; i_23092++) {
            int64_t eta_p_22065 = ((int64_t *) mem_23543.mem)[i_23092];
            int64_t eta_p_22066 = ((int64_t *) mem_23352.mem)[i_23092];
            
            // ./test_operations.fut:145:18-22
            
            bool defunc_0_f_res_22067 = eta_p_22065 == eta_p_22066;
            
            // ./test_operations.fut:145:8-57
            
            bool x_22070 = defunc_0_f_res_22067 && redout_23091;
            bool redout_tmp_23795 = x_22070;
            
            redout_23091 = redout_tmp_23795;
        }
        defunc_0_reduce_res_22064 = redout_23091;
        if (memblock_unref(ctx, &mem_23543, "mem_23543") != 0)
            return 1;
        cond_11934 = defunc_0_reduce_res_22064;
    } else {
        cond_11934 = 0;
    }
    if (memblock_unref(ctx, &mem_23352, "mem_23352") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23443, "mem_23443") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23502, "mem_23502") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23523, "mem_23523") != 0)
        return 1;
    // ./test_operations.fut:144:5-147:62
    
    bool cond_11943;
    
    if (cond_11934) {
        // ../lib/github.com/diku-dk/vtree/vtree.fut:351:28-103
        
        bool acc_cert_21984;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:351:28-103
        for (int64_t i_23094 = 0; i_23094 < defunc_0_reduce_res_22082; i_23094++) {
            int64_t v_21988 = ((int64_t *) mem_23478.mem)[i_23094];
            int64_t v_21989 = ((int64_t *) mem_23498.mem)[i_23094];
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:351:28-103
            // UpdateAcc
            if (sle64((int64_t) 0, v_21988) && slt64(v_21988, result_sizze_17977)) {
                ((int64_t *) mem_23441.mem)[v_21988] = v_21989;
            }
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:373:18-54
        if (memblock_alloc(ctx, &mem_23551, bytes_23438, "mem_23551")) {
            err = 1;
            goto cleanup;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:373:18-54
        for (int64_t i_23097 = 0; i_23097 < result_sizze_17977; i_23097++) {
            int64_t eta_p_21993 = ((int64_t *) mem_23441.mem)[i_23097];
            int64_t eta_p_21994 = ((int64_t *) mem_23500.mem)[i_23097];
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:373:23-26
            
            int64_t defunc_0_f_res_21995 = add64(eta_p_21993, eta_p_21994);
            
            ((int64_t *) mem_23551.mem)[i_23097] = defunc_0_f_res_21995;
        }
        // ./test_operations.fut:146:24-44
        
        bool dim_match_21999 = (int64_t) 11 == result_sizze_17977;
        
        // ./test_operations.fut:146:24-44
        
        bool empty_or_match_cert_22000;
        
        if (!dim_match_21999) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (desugared) shape [", (long long) result_sizze_17977, "] cannot match shape of type \"[", (long long) (int64_t) 11, "]i64\".", "-> #0  ./test_operations.fut:146:24-44\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        // ./test_operations.fut:146:8-57
        
        bool defunc_0_reduce_res_22002;
        bool redout_23099 = 1;
        
        for (int64_t i_23100 = 0; i_23100 < (int64_t) 11; i_23100++) {
            int64_t eta_p_22003 = ((int64_t *) mem_23551.mem)[i_23100];
            int64_t eta_p_22004 = ((int64_t *) mem_23353.mem)[i_23100];
            
            // ./test_operations.fut:146:18-22
            
            bool defunc_0_f_res_22005 = eta_p_22003 == eta_p_22004;
            
            // ./test_operations.fut:146:8-57
            
            bool x_22008 = defunc_0_f_res_22005 && redout_23099;
            bool redout_tmp_23798 = x_22008;
            
            redout_23099 = redout_tmp_23798;
        }
        defunc_0_reduce_res_22002 = redout_23099;
        if (memblock_unref(ctx, &mem_23551, "mem_23551") != 0)
            return 1;
        cond_11943 = defunc_0_reduce_res_22002;
    } else {
        cond_11943 = 0;
    }
    if (memblock_unref(ctx, &mem_23353, "mem_23353") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23441, "mem_23441") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23498, "mem_23498") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23500, "mem_23500") != 0)
        return 1;
    // ./test_operations.fut:144:5-147:62
    if (cond_11943) {
        // ../lib/github.com/diku-dk/vtree/vtree.fut:352:30-109
        
        bool acc_cert_22017;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:352:30-109
        for (int64_t i_23102 = 0; i_23102 < defunc_0_reduce_res_22082; i_23102++) {
            int64_t v_22021 = ((int64_t *) mem_23478.mem)[i_23102];
            int64_t v_22022 = ((int64_t *) mem_23496.mem)[i_23102];
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:352:30-109
            // UpdateAcc
            if (sle64((int64_t) 0, v_22021) && slt64(v_22021, result_sizze_17977)) {
                ((int64_t *) mem_23439.mem)[v_22021] = v_22022;
            }
        }
        // ./test_operations.fut:147:24-46
        
        bool dim_match_22025 = (int64_t) 11 == result_sizze_17977;
        
        // ./test_operations.fut:147:24-46
        
        bool empty_or_match_cert_22026;
        
        if (!dim_match_22025) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (desugared) shape [", (long long) result_sizze_17977, "] cannot match shape of type \"[", (long long) (int64_t) 11, "]i64\".", "-> #0  ./test_operations.fut:147:24-46\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        // ./test_operations.fut:147:8-61
        
        bool defunc_0_reduce_res_22028;
        bool redout_23103 = 1;
        
        for (int64_t i_23104 = 0; i_23104 < (int64_t) 11; i_23104++) {
            int64_t eta_p_22029 = ((int64_t *) mem_23439.mem)[i_23104];
            int64_t eta_p_22030 = ((int64_t *) mem_23354.mem)[i_23104];
            
            // ./test_operations.fut:147:18-22
            
            bool defunc_0_f_res_22031 = eta_p_22029 == eta_p_22030;
            
            // ./test_operations.fut:147:8-61
            
            bool x_22034 = defunc_0_f_res_22031 && redout_23103;
            bool redout_tmp_23800 = x_22034;
            
            redout_23103 = redout_tmp_23800;
        }
        defunc_0_reduce_res_22028 = redout_23103;
        ok_11952 = defunc_0_reduce_res_22028;
    } else {
        ok_11952 = 0;
    }
    if (memblock_unref(ctx, &mem_23354, "mem_23354") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23439, "mem_23439") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23478, "mem_23478") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23496, "mem_23496") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23551, "mem_23551") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23543, "mem_23543") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23523, "mem_23523") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23515, "mem_23515") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23502, "mem_23502") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23500, "mem_23500") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23482, "mem_23482") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23480, "mem_23480") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23498, "mem_23498") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23496, "mem_23496") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23478, "mem_23478") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23464, "mem_23464") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23462, "mem_23462") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23446, "mem_23446") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23445, "mem_23445") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23460, "mem_23460") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23459, "mem_23459") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23444, "mem_23444") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23443, "mem_23443") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23441, "mem_23441") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23439, "mem_23439") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23437, "mem_23437") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23436, "mem_23436") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23434, "mem_23434") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23426, "mem_23426") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23419, "mem_23419") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23412, "mem_23412") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23411, "mem_23411") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23368, "mem_23368") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23367, "mem_23367") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23366, "mem_23366") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23365, "mem_23365") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23364, "mem_23364") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23363, "mem_23363") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23362, "mem_23362") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23355, "mem_23355") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23354, "mem_23354") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23353, "mem_23353") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23352, "mem_23352") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23351, "mem_23351") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23350, "mem_23350") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23349, "mem_23349") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23348, "mem_23348") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23347, "mem_23347") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23346, "mem_23346") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23345, "mem_23345") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23344, "mem_23344") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23343, "mem_23343") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_23340, "ext_mem_23340") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_23341, "ext_mem_23341") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_23342, "ext_mem_23342") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23339, "mem_23339") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_23332, "ext_mem_23332") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_23333, "ext_mem_23333") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_23334, "ext_mem_23334") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_23335, "ext_mem_23335") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_23336, "ext_mem_23336") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_23337, "ext_mem_23337") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_23338, "ext_mem_23338") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23331, "mem_23331") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23330, "mem_23330") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_23323, "ext_mem_23323") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_23324, "ext_mem_23324") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_23325, "ext_mem_23325") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_23326, "ext_mem_23326") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_23327, "ext_mem_23327") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_23328, "ext_mem_23328") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_23329, "ext_mem_23329") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23322, "mem_23322") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_23315, "ext_mem_23315") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_23316, "ext_mem_23316") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_23317, "ext_mem_23317") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_23318, "ext_mem_23318") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_23319, "ext_mem_23319") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_23320, "ext_mem_23320") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_23321, "ext_mem_23321") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23314, "mem_23314") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23313, "mem_23313") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23312, "mem_23312") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23311, "mem_23311") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23310, "mem_23310") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23309, "mem_23309") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23308, "mem_23308") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23307, "mem_23307") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_23300, "ext_mem_23300") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_23301, "ext_mem_23301") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_23302, "ext_mem_23302") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_23303, "ext_mem_23303") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_23304, "ext_mem_23304") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_23305, "ext_mem_23305") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_23306, "ext_mem_23306") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23299, "mem_23299") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23298, "mem_23298") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23297, "mem_23297") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_23296, "mem_23296") != 0)
        return 1;
    #undef ok_11869
    #undef ok_11952
    #undef x_16338
    #undef x_16341
    #undef x_16347
    #undef x_16353
    
  cleanup:
    return err;
}
static int free_constants(struct futhark_context *ctx)
{
    (void) ctx;
    return 0;
}

FUTHARK_FUN_ATTR int futrts_deleteVertices_7489(struct futhark_context *ctx, struct memblock *mem_out_p_23828, struct memblock *mem_out_p_23829, struct memblock *mem_out_p_23830, int64_t *out_prim_out_23831, struct memblock data_mem_23558, struct memblock lp_mem_23559, struct memblock rp_mem_23560, struct memblock keep_mem_23561, int64_t n_12816)
{
    (void) ctx;
    
    int err = 0;
    int64_t mem_23563_cached_sizze_23832 = 0;
    unsigned char *mem_23563 = NULL;
    int64_t mem_23565_cached_sizze_23833 = 0;
    unsigned char *mem_23565 = NULL;
    int64_t mem_23567_cached_sizze_23834 = 0;
    unsigned char *mem_23567 = NULL;
    int64_t mem_23569_cached_sizze_23835 = 0;
    unsigned char *mem_23569 = NULL;
    int64_t mem_23571_cached_sizze_23836 = 0;
    unsigned char *mem_23571 = NULL;
    int64_t mem_23573_cached_sizze_23837 = 0;
    unsigned char *mem_23573 = NULL;
    int64_t mem_23610_cached_sizze_23838 = 0;
    unsigned char *mem_23610 = NULL;
    int64_t mem_23612_cached_sizze_23839 = 0;
    unsigned char *mem_23612 = NULL;
    int64_t mem_23614_cached_sizze_23840 = 0;
    unsigned char *mem_23614 = NULL;
    int64_t mem_23622_cached_sizze_23841 = 0;
    unsigned char *mem_23622 = NULL;
    int64_t mem_23624_cached_sizze_23842 = 0;
    unsigned char *mem_23624 = NULL;
    struct memblock mem_23630;
    
    mem_23630.references = NULL;
    
    struct memblock mem_23628;
    
    mem_23628.references = NULL;
    
    struct memblock mem_23626;
    
    mem_23626.references = NULL;
    
    struct memblock mem_out_23660;
    
    mem_out_23660.references = NULL;
    
    struct memblock mem_out_23659;
    
    mem_out_23659.references = NULL;
    
    struct memblock mem_out_23658;
    
    mem_out_23658.references = NULL;
    
    bool ok_11869 = ctx->constants->ok_11869;
    bool ok_11952 = ctx->constants->ok_11952;
    bool x_16338 = ctx->constants->x_16338;
    bool x_16341 = ctx->constants->x_16341;
    bool x_16347 = ctx->constants->x_16347;
    bool x_16353 = ctx->constants->x_16353;
    int64_t prim_out_23661;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:242:27-32
    
    int64_t dzlz7bUZLztZRz20U2z20Unz7dUzg_12821 = mul64((int64_t) 2, n_12816);
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    
    int64_t bytes_23562 = (int64_t) 8 * n_12816;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    if (mem_23563_cached_sizze_23832 < bytes_23562) {
        err = lexical_realloc(ctx, &mem_23563, &mem_23563_cached_sizze_23832, bytes_23562);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    if (mem_23565_cached_sizze_23833 < bytes_23562) {
        err = lexical_realloc(ctx, &mem_23565, &mem_23565_cached_sizze_23833, bytes_23562);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    if (mem_23567_cached_sizze_23834 < bytes_23562) {
        err = lexical_realloc(ctx, &mem_23567, &mem_23567_cached_sizze_23834, bytes_23562);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    if (mem_23569_cached_sizze_23835 < bytes_23562) {
        err = lexical_realloc(ctx, &mem_23569, &mem_23569_cached_sizze_23835, bytes_23562);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    if (mem_23571_cached_sizze_23836 < bytes_23562) {
        err = lexical_realloc(ctx, &mem_23571, &mem_23571_cached_sizze_23836, bytes_23562);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    if (mem_23573_cached_sizze_23837 < bytes_23562) {
        err = lexical_realloc(ctx, &mem_23573, &mem_23573_cached_sizze_23837, bytes_23562);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    
    int64_t discard_23128;
    int64_t discard_23129;
    int64_t discard_23130;
    int64_t defunc_res_22663;
    int64_t scanacc_23111;
    int64_t scanacc_23112;
    int64_t scanacc_23113;
    int64_t redout_23117;
    
    scanacc_23111 = (int64_t) 0;
    scanacc_23112 = (int64_t) 0;
    scanacc_23113 = (int64_t) 0;
    redout_23117 = (int64_t) 0;
    for (int64_t i_23121 = 0; i_23121 < n_12816; i_23121++) {
        bool eta_p_22529 = ((bool *) keep_mem_23561.mem)[i_23121];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:240:22-57
        
        int64_t lifted_lambda_res_22533 = btoi_bool_i64(eta_p_22529);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
        
        int64_t defunc_0_op_res_17762 = add64(lifted_lambda_res_22533, scanacc_23111);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
        
        int64_t defunc_0_op_res_17812 = add64(lifted_lambda_res_22533, scanacc_23112);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
        
        int64_t defunc_0_op_res_17862 = add64(lifted_lambda_res_22533, scanacc_23113);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:240:13-57
        
        int64_t zp_res_17297 = add64(lifted_lambda_res_22533, redout_23117);
        
        ((int64_t *) mem_23563)[i_23121] = defunc_0_op_res_17762;
        ((int64_t *) mem_23565)[i_23121] = defunc_0_op_res_17812;
        ((int64_t *) mem_23567)[i_23121] = defunc_0_op_res_17862;
        ((int64_t *) mem_23569)[i_23121] = lifted_lambda_res_22533;
        ((int64_t *) mem_23571)[i_23121] = lifted_lambda_res_22533;
        ((int64_t *) mem_23573)[i_23121] = lifted_lambda_res_22533;
        
        int64_t scanacc_tmp_23662 = defunc_0_op_res_17762;
        int64_t scanacc_tmp_23663 = defunc_0_op_res_17812;
        int64_t scanacc_tmp_23664 = defunc_0_op_res_17862;
        int64_t redout_tmp_23668 = zp_res_17297;
        
        scanacc_23111 = scanacc_tmp_23662;
        scanacc_23112 = scanacc_tmp_23663;
        scanacc_23113 = scanacc_tmp_23664;
        redout_23117 = redout_tmp_23668;
    }
    discard_23128 = scanacc_23111;
    discard_23129 = scanacc_23112;
    discard_23130 = scanacc_23113;
    defunc_res_22663 = redout_23117;
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    
    int64_t tmp_17765 = sub64(n_12816, (int64_t) 1);
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    
    bool y_17767 = slt64(tmp_17765, n_12816);
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    
    bool x_17766 = sle64((int64_t) 0, tmp_17765);
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    
    bool bounds_check_17768 = x_17766 && y_17767;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    
    bool cond_17763 = n_12816 == (int64_t) 0;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    
    bool protect_assert_disj_17769 = cond_17763 || bounds_check_17768;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    
    bool index_certs_17770;
    
    if (!protect_assert_disj_17769) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) tmp_17765, "] out of bounds for array of shape [", (long long) n_12816, "].", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40\n   #1  ../lib/github.com/diku-dk/vtree/vtree.fut:252:14-32\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    
    bool x_17764 = !cond_17763;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    
    int64_t m_f_res_17871;
    
    if (x_17764) {
        // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
        
        int64_t x_22659 = ((int64_t *) mem_23567)[tmp_17765];
        
        m_f_res_17871 = x_22659;
    } else {
        m_f_res_17871 = (int64_t) 0;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    
    int64_t m_17873;
    
    if (cond_17763) {
        m_17873 = (int64_t) 0;
    } else {
        m_17873 = m_f_res_17871;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    
    int64_t bytes_23611 = (int64_t) 8 * m_17873;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:231:16-234:25
    
    int64_t bytes_23613 = (int64_t) 16 * n_12816;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    
    int64_t m_f_res_17821;
    
    if (x_17764) {
        // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
        
        int64_t x_22658 = ((int64_t *) mem_23565)[tmp_17765];
        
        m_f_res_17821 = x_22658;
    } else {
        m_f_res_17821 = (int64_t) 0;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    
    int64_t m_17823;
    
    if (cond_17763) {
        m_17823 = (int64_t) 0;
    } else {
        m_17823 = m_f_res_17821;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    
    int64_t bytes_23621 = (int64_t) 8 * m_17823;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    
    int64_t m_f_res_17771;
    
    if (x_17764) {
        // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
        
        int64_t x_22657 = ((int64_t *) mem_23563)[tmp_17765];
        
        m_f_res_17771 = x_22657;
    } else {
        m_f_res_17771 = (int64_t) 0;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    
    int64_t m_17773;
    
    if (cond_17763) {
        m_17773 = (int64_t) 0;
    } else {
        m_17773 = m_f_res_17771;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    
    int64_t bytes_23623 = (int64_t) 8 * m_17773;
    bool eq_x_y_18414 = defunc_res_22663 == (int64_t) 0;
    bool eq_x_zz_18415 = defunc_res_22663 == m_f_res_17771;
    bool p_and_eq_x_y_18416 = cond_17763 && eq_x_y_18414;
    bool p_and_eq_x_y_18418 = x_17764 && eq_x_zz_18415;
    bool dim_match_12878 = p_and_eq_x_y_18416 || p_and_eq_x_y_18418;
    bool empty_or_match_cert_12879;
    
    if (!dim_match_12878) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (desugared) shape [", (long long) m_17773, "] cannot match shape of type \"[", (long long) defunc_res_22663, "]i64\".", "-> #0  unknown location\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    int64_t bytes_23625 = (int64_t) 8 * defunc_res_22663;
    bool eq_x_zz_18421 = defunc_res_22663 == m_f_res_17821;
    bool p_and_eq_x_y_18424 = x_17764 && eq_x_zz_18421;
    bool dim_match_12887 = p_and_eq_x_y_18416 || p_and_eq_x_y_18424;
    bool empty_or_match_cert_12888;
    
    if (!dim_match_12887) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (desugared) shape [", (long long) m_17823, "] cannot match shape of type \"[", (long long) defunc_res_22663, "]i64\".", "-> #0  unknown location\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    bool eq_x_zz_18427 = defunc_res_22663 == m_f_res_17871;
    bool p_and_eq_x_y_18430 = x_17764 && eq_x_zz_18427;
    bool dim_match_12896 = p_and_eq_x_y_18416 || p_and_eq_x_y_18430;
    bool empty_or_match_cert_12897;
    
    if (!dim_match_12896) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (desugared) shape [", (long long) m_17873, "] cannot match shape of type \"[", (long long) defunc_res_22663, "]i64\".", "-> #0  unknown location\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:242:16-39
    if (mem_23610_cached_sizze_23838 < dzlz7bUZLztZRz20U2z20Unz7dUzg_12821) {
        err = lexical_realloc(ctx, &mem_23610, &mem_23610_cached_sizze_23838, dzlz7bUZLztZRz20U2z20Unz7dUzg_12821);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:242:16-39
    for (int64_t nest_i_23672 = 0; nest_i_23672 < dzlz7bUZLztZRz20U2z20Unz7dUzg_12821; nest_i_23672++) {
        ((bool *) mem_23610)[nest_i_23672] = 0;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    if (mem_23612_cached_sizze_23839 < bytes_23611) {
        err = lexical_realloc(ctx, &mem_23612, &mem_23612_cached_sizze_23839, bytes_23611);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    
    bool acc_cert_16629;
    bool acc_cert_22098;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:242:7-244:32
    for (int64_t i_23132 = 0; i_23132 < n_12816; i_23132++) {
        int64_t v_17324 = ((int64_t *) lp_mem_23559.mem)[i_23132];
        bool v_17325 = ((bool *) keep_mem_23561.mem)[i_23132];
        int64_t v_17328 = ((int64_t *) rp_mem_23560.mem)[i_23132];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:242:7-244:32
        // UpdateAcc
        if (sle64((int64_t) 0, v_17324) && slt64(v_17324, dzlz7bUZLztZRz20U2z20Unz7dUzg_12821)) {
            ((bool *) mem_23610)[v_17324] = v_17325;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:242:7-244:32
        // UpdateAcc
        if (sle64((int64_t) 0, v_17328) && slt64(v_17328, dzlz7bUZLztZRz20U2z20Unz7dUzg_12821)) {
            ((bool *) mem_23610)[v_17328] = v_17325;
        }
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    for (int64_t i_23134 = 0; i_23134 < n_12816; i_23134++) {
        int64_t eta_p_22113 = ((int64_t *) mem_23569)[i_23134];
        int64_t eta_p_22114 = ((int64_t *) mem_23567)[i_23134];
        int64_t v_22116 = ((int64_t *) data_mem_23558.mem)[i_23134];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
        
        bool cond_22117 = eta_p_22113 == (int64_t) 1;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
        
        int64_t lifted_lambda_res_22118;
        
        if (cond_22117) {
            // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
            
            int64_t lifted_lambda_res_t_res_22632 = sub64(eta_p_22114, (int64_t) 1);
            
            lifted_lambda_res_22118 = lifted_lambda_res_t_res_22632;
        } else {
            lifted_lambda_res_22118 = (int64_t) -1;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
        // UpdateAcc
        if (sle64((int64_t) 0, lifted_lambda_res_22118) && slt64(lifted_lambda_res_22118, m_17873)) {
            ((int64_t *) mem_23612)[lifted_lambda_res_22118] = v_22116;
        }
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:231:16-234:25
    if (mem_23614_cached_sizze_23840 < bytes_23613) {
        err = lexical_realloc(ctx, &mem_23614, &mem_23614_cached_sizze_23840, bytes_23613);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:231:16-234:25
    
    int64_t inpacc_22667;
    int64_t inpacc_22471 = (int64_t) 0;
    
    for (int64_t i_23147 = 0; i_23147 < dzlz7bUZLztZRz20U2z20Unz7dUzg_12821; i_23147++) {
        bool eta_p_23282 = ((bool *) mem_23610)[i_23147];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:231:16-52
        
        int64_t lifted_lambda_res_23283 = btoi_bool_i64(eta_p_23282);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:232:19-22
        
        int64_t defunc_0_op_res_23292 = add64(inpacc_22471, lifted_lambda_res_23283);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:233:24-47
        
        int64_t lifted_lambda_res_23293;
        
        if (eta_p_23282) {
            // ../lib/github.com/diku-dk/vtree/vtree.fut:233:36-39
            
            int64_t lifted_lambda_res_t_res_23294 = sub64(defunc_0_op_res_23292, (int64_t) 1);
            
            lifted_lambda_res_23293 = lifted_lambda_res_t_res_23294;
        } else {
            lifted_lambda_res_23293 = (int64_t) -1;
        }
        ((int64_t *) mem_23614)[i_23147] = lifted_lambda_res_23293;
        
        int64_t inpacc_tmp_23675 = defunc_0_op_res_23292;
        
        inpacc_22471 = inpacc_tmp_23675;
    }
    inpacc_22667 = inpacc_22471;
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    if (mem_23622_cached_sizze_23841 < bytes_23621) {
        err = lexical_realloc(ctx, &mem_23622, &mem_23622_cached_sizze_23841, bytes_23621);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    if (mem_23624_cached_sizze_23842 < bytes_23623) {
        err = lexical_realloc(ctx, &mem_23624, &mem_23624_cached_sizze_23842, bytes_23623);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    
    bool acc_cert_22199;
    bool acc_cert_22257;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    for (int64_t i_23151 = 0; i_23151 < n_12816; i_23151++) {
        bool eta_p_22566 = ((bool *) keep_mem_23561.mem)[i_23151];
        int64_t eta_p_22567 = ((int64_t *) rp_mem_23560.mem)[i_23151];
        int64_t eta_p_22568 = ((int64_t *) mem_23571)[i_23151];
        int64_t eta_p_22569 = ((int64_t *) mem_23565)[i_23151];
        int64_t eta_p_22571 = ((int64_t *) lp_mem_23559.mem)[i_23151];
        int64_t eta_p_22572 = ((int64_t *) mem_23573)[i_23151];
        int64_t eta_p_22573 = ((int64_t *) mem_23563)[i_23151];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:247:23-54
        
        int64_t lifted_lambda_res_22576;
        
        if (eta_p_22566) {
            // ../lib/github.com/diku-dk/vtree/vtree.fut:247:33-46
            
            bool x_22639 = sle64((int64_t) 0, eta_p_22571);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:247:33-46
            
            bool y_22640 = slt64(eta_p_22571, dzlz7bUZLztZRz20U2z20Unz7dUzg_12821);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:247:33-46
            
            bool bounds_check_22641 = x_22639 && y_22640;
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:247:33-46
            
            bool index_certs_22642;
            
            if (!bounds_check_22641) {
                set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) eta_p_22571, "] out of bounds for array of shape [", (long long) dzlz7bUZLztZRz20U2z20Unz7dUzg_12821, "].", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:247:33-46\n"));
                err = FUTHARK_PROGRAM_ERROR;
                goto cleanup;
            }
            // ../lib/github.com/diku-dk/vtree/vtree.fut:247:33-46
            
            int64_t lifted_lambda_res_t_res_22643 = ((int64_t *) mem_23614)[eta_p_22571];
            
            lifted_lambda_res_22576 = lifted_lambda_res_t_res_22643;
        } else {
            lifted_lambda_res_22576 = (int64_t) -1;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
        
        bool cond_22582 = eta_p_22572 == (int64_t) 1;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
        
        int64_t lifted_lambda_res_22583;
        
        if (cond_22582) {
            // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
            
            int64_t lifted_lambda_res_t_res_22644 = sub64(eta_p_22573, (int64_t) 1);
            
            lifted_lambda_res_22583 = lifted_lambda_res_t_res_22644;
        } else {
            lifted_lambda_res_22583 = (int64_t) -1;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
        // UpdateAcc
        if (sle64((int64_t) 0, lifted_lambda_res_22583) && slt64(lifted_lambda_res_22583, m_17773)) {
            ((int64_t *) mem_23624)[lifted_lambda_res_22583] = lifted_lambda_res_22576;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:250:23-54
        
        int64_t lifted_lambda_res_22589;
        
        if (eta_p_22566) {
            // ../lib/github.com/diku-dk/vtree/vtree.fut:250:33-46
            
            bool x_22645 = sle64((int64_t) 0, eta_p_22567);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:250:33-46
            
            bool y_22646 = slt64(eta_p_22567, dzlz7bUZLztZRz20U2z20Unz7dUzg_12821);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:250:33-46
            
            bool bounds_check_22647 = x_22645 && y_22646;
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:250:33-46
            
            bool index_certs_22648;
            
            if (!bounds_check_22647) {
                set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) eta_p_22567, "] out of bounds for array of shape [", (long long) dzlz7bUZLztZRz20U2z20Unz7dUzg_12821, "].", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:250:33-46\n"));
                err = FUTHARK_PROGRAM_ERROR;
                goto cleanup;
            }
            // ../lib/github.com/diku-dk/vtree/vtree.fut:250:33-46
            
            int64_t lifted_lambda_res_t_res_22649 = ((int64_t *) mem_23614)[eta_p_22567];
            
            lifted_lambda_res_22589 = lifted_lambda_res_t_res_22649;
        } else {
            lifted_lambda_res_22589 = (int64_t) -1;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
        
        bool cond_22595 = eta_p_22568 == (int64_t) 1;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
        
        int64_t lifted_lambda_res_22596;
        
        if (cond_22595) {
            // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
            
            int64_t lifted_lambda_res_t_res_22650 = sub64(eta_p_22569, (int64_t) 1);
            
            lifted_lambda_res_22596 = lifted_lambda_res_t_res_22650;
        } else {
            lifted_lambda_res_22596 = (int64_t) -1;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
        // UpdateAcc
        if (sle64((int64_t) 0, lifted_lambda_res_22596) && slt64(lifted_lambda_res_22596, m_17823)) {
            ((int64_t *) mem_23622)[lifted_lambda_res_22596] = lifted_lambda_res_22589;
        }
    }
    if (memblock_alloc(ctx, &mem_23626, bytes_23625, "mem_23626")) {
        err = 1;
        goto cleanup;
    }
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_23626.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) mem_23624, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {defunc_res_22663});
    if (memblock_alloc(ctx, &mem_23628, bytes_23625, "mem_23628")) {
        err = 1;
        goto cleanup;
    }
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_23628.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) mem_23622, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {defunc_res_22663});
    if (memblock_alloc(ctx, &mem_23630, bytes_23625, "mem_23630")) {
        err = 1;
        goto cleanup;
    }
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_23630.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) mem_23612, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {defunc_res_22663});
    if (memblock_set(ctx, &mem_out_23658, &mem_23630, "mem_23630") != 0)
        return 1;
    if (memblock_set(ctx, &mem_out_23659, &mem_23626, "mem_23626") != 0)
        return 1;
    if (memblock_set(ctx, &mem_out_23660, &mem_23628, "mem_23628") != 0)
        return 1;
    prim_out_23661 = defunc_res_22663;
    if (memblock_set(ctx, &*mem_out_p_23828, &mem_out_23658, "mem_out_23658") != 0)
        return 1;
    if (memblock_set(ctx, &*mem_out_p_23829, &mem_out_23659, "mem_out_23659") != 0)
        return 1;
    if (memblock_set(ctx, &*mem_out_p_23830, &mem_out_23660, "mem_out_23660") != 0)
        return 1;
    *out_prim_out_23831 = prim_out_23661;
    
  cleanup:
    {
        free(mem_23563);
        free(mem_23565);
        free(mem_23567);
        free(mem_23569);
        free(mem_23571);
        free(mem_23573);
        free(mem_23610);
        free(mem_23612);
        free(mem_23614);
        free(mem_23622);
        free(mem_23624);
        if (memblock_unref(ctx, &mem_23630, "mem_23630") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_23628, "mem_23628") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_23626, "mem_23626") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_out_23660, "mem_out_23660") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_out_23659, "mem_out_23659") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_out_23658, "mem_out_23658") != 0)
            return 1;
    }
    return err;
}
FUTHARK_FUN_ATTR int futrts_entry_test_delete_vertices(struct futhark_context *ctx, bool *out_prim_out_23843)
{
    (void) ctx;
    
    int err = 0;
    bool ok_11869 = ctx->constants->ok_11869;
    bool ok_11952 = ctx->constants->ok_11952;
    bool x_16338 = ctx->constants->x_16338;
    bool x_16341 = ctx->constants->x_16341;
    bool x_16347 = ctx->constants->x_16347;
    bool x_16353 = ctx->constants->x_16353;
    bool prim_out_23658;
    
    prim_out_23658 = ok_11869;
    *out_prim_out_23843 = prim_out_23658;
    
  cleanup:
    { }
    return err;
}
FUTHARK_FUN_ATTR int futrts_entry_test_merge_tree(struct futhark_context *ctx, bool *out_prim_out_23844)
{
    (void) ctx;
    
    int err = 0;
    bool ok_11869 = ctx->constants->ok_11869;
    bool ok_11952 = ctx->constants->ok_11952;
    bool x_16338 = ctx->constants->x_16338;
    bool x_16341 = ctx->constants->x_16341;
    bool x_16347 = ctx->constants->x_16347;
    bool x_16353 = ctx->constants->x_16353;
    bool prim_out_23658;
    
    prim_out_23658 = ok_11952;
    *out_prim_out_23844 = prim_out_23658;
    
  cleanup:
    { }
    return err;
}
FUTHARK_FUN_ATTR int futrts_entry_test_split(struct futhark_context *ctx, bool *out_prim_out_23845)
{
    (void) ctx;
    
    int err = 0;
    bool ok_11869 = ctx->constants->ok_11869;
    bool ok_11952 = ctx->constants->ok_11952;
    bool x_16338 = ctx->constants->x_16338;
    bool x_16341 = ctx->constants->x_16341;
    bool x_16347 = ctx->constants->x_16347;
    bool x_16353 = ctx->constants->x_16353;
    bool prim_out_23658;
    
    prim_out_23658 = x_16338;
    *out_prim_out_23845 = prim_out_23658;
    
  cleanup:
    { }
    return err;
}
FUTHARK_FUN_ATTR int futrts_entry_test_split_at_leaf(struct futhark_context *ctx, bool *out_prim_out_23846)
{
    (void) ctx;
    
    int err = 0;
    bool ok_11869 = ctx->constants->ok_11869;
    bool ok_11952 = ctx->constants->ok_11952;
    bool x_16338 = ctx->constants->x_16338;
    bool x_16341 = ctx->constants->x_16341;
    bool x_16347 = ctx->constants->x_16347;
    bool x_16353 = ctx->constants->x_16353;
    bool prim_out_23658;
    
    prim_out_23658 = x_16341;
    *out_prim_out_23846 = prim_out_23658;
    
  cleanup:
    { }
    return err;
}
FUTHARK_FUN_ATTR int futrts_entry_test_split_multiple(struct futhark_context *ctx, bool *out_prim_out_23847)
{
    (void) ctx;
    
    int err = 0;
    bool ok_11869 = ctx->constants->ok_11869;
    bool ok_11952 = ctx->constants->ok_11952;
    bool x_16338 = ctx->constants->x_16338;
    bool x_16341 = ctx->constants->x_16341;
    bool x_16347 = ctx->constants->x_16347;
    bool x_16353 = ctx->constants->x_16353;
    bool prim_out_23658;
    
    prim_out_23658 = x_16347;
    *out_prim_out_23847 = prim_out_23658;
    
  cleanup:
    { }
    return err;
}
FUTHARK_FUN_ATTR int futrts_entry_test_split_none(struct futhark_context *ctx, bool *out_prim_out_23848)
{
    (void) ctx;
    
    int err = 0;
    bool ok_11869 = ctx->constants->ok_11869;
    bool ok_11952 = ctx->constants->ok_11952;
    bool x_16338 = ctx->constants->x_16338;
    bool x_16341 = ctx->constants->x_16341;
    bool x_16347 = ctx->constants->x_16347;
    bool x_16353 = ctx->constants->x_16353;
    bool prim_out_23658;
    
    prim_out_23658 = x_16353;
    *out_prim_out_23848 = prim_out_23658;
    
  cleanup:
    { }
    return err;
}
FUTHARK_FUN_ATTR int futrts_split_7490(struct futhark_context *ctx, struct memblock *mem_out_p_23849, struct memblock *mem_out_p_23850, struct memblock *mem_out_p_23851, struct memblock *mem_out_p_23852, struct memblock *mem_out_p_23853, struct memblock *mem_out_p_23854, struct memblock *mem_out_p_23855, int64_t *out_prim_out_23856, int64_t *out_prim_out_23857, int64_t *out_prim_out_23858, struct memblock data_mem_23558, struct memblock lp_mem_23559, struct memblock rp_mem_23560, struct memblock splits_mem_23561, int64_t n_13725)
{
    (void) ctx;
    
    int err = 0;
    int64_t mem_23563_cached_sizze_23859 = 0;
    unsigned char *mem_23563 = NULL;
    int64_t mem_23565_cached_sizze_23860 = 0;
    unsigned char *mem_23565 = NULL;
    int64_t mem_23573_cached_sizze_23861 = 0;
    unsigned char *mem_23573 = NULL;
    int64_t mem_23575_cached_sizze_23862 = 0;
    unsigned char *mem_23575 = NULL;
    int64_t mem_23583_cached_sizze_23863 = 0;
    unsigned char *mem_23583 = NULL;
    int64_t mem_23591_cached_sizze_23864 = 0;
    unsigned char *mem_23591 = NULL;
    int64_t mem_23593_cached_sizze_23865 = 0;
    unsigned char *mem_23593 = NULL;
    int64_t mem_23595_cached_sizze_23866 = 0;
    unsigned char *mem_23595 = NULL;
    int64_t mem_23597_cached_sizze_23867 = 0;
    unsigned char *mem_23597 = NULL;
    int64_t mem_23598_cached_sizze_23868 = 0;
    unsigned char *mem_23598 = NULL;
    int64_t mem_23600_cached_sizze_23869 = 0;
    unsigned char *mem_23600 = NULL;
    int64_t mem_23602_cached_sizze_23870 = 0;
    unsigned char *mem_23602 = NULL;
    struct memblock ext_mem_23655;
    
    ext_mem_23655.references = NULL;
    
    struct memblock ext_mem_23656;
    
    ext_mem_23656.references = NULL;
    
    struct memblock ext_mem_23657;
    
    ext_mem_23657.references = NULL;
    
    struct memblock mem_23653;
    
    mem_23653.references = NULL;
    
    struct memblock mem_23652;
    
    mem_23652.references = NULL;
    
    struct memblock mem_23650;
    
    mem_23650.references = NULL;
    
    struct memblock mem_23648;
    
    mem_23648.references = NULL;
    
    struct memblock mem_23646;
    
    mem_23646.references = NULL;
    
    struct memblock mem_out_23664;
    
    mem_out_23664.references = NULL;
    
    struct memblock mem_out_23663;
    
    mem_out_23663.references = NULL;
    
    struct memblock mem_out_23662;
    
    mem_out_23662.references = NULL;
    
    struct memblock mem_out_23661;
    
    mem_out_23661.references = NULL;
    
    struct memblock mem_out_23660;
    
    mem_out_23660.references = NULL;
    
    struct memblock mem_out_23659;
    
    mem_out_23659.references = NULL;
    
    struct memblock mem_out_23658;
    
    mem_out_23658.references = NULL;
    
    bool ok_11869 = ctx->constants->ok_11869;
    bool ok_11952 = ctx->constants->ok_11952;
    bool x_16338 = ctx->constants->x_16338;
    bool x_16341 = ctx->constants->x_16341;
    bool x_16347 = ctx->constants->x_16347;
    bool x_16353 = ctx->constants->x_16353;
    int64_t prim_out_23665;
    int64_t prim_out_23666;
    int64_t prim_out_23667;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:210:24-29
    
    int64_t dzlz7bUZLztZRz20U2z20Unz7dUzg_18366 = mul64((int64_t) 2, n_13725);
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:210:13-33
    
    int64_t bytes_23562 = (int64_t) 16 * n_13725;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:210:13-33
    if (mem_23563_cached_sizze_23859 < bytes_23562) {
        err = lexical_realloc(ctx, &mem_23563, &mem_23563_cached_sizze_23859, bytes_23562);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:210:13-33
    for (int64_t nest_i_23668 = 0; nest_i_23668 < dzlz7bUZLztZRz20U2z20Unz7dUzg_18366; nest_i_23668++) {
        ((int64_t *) mem_23563)[nest_i_23668] = (int64_t) 0;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:211:13-30
    
    int64_t bytes_23572 = (int64_t) 8 * n_13725;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:211:13-30
    if (mem_23565_cached_sizze_23860 < bytes_23572) {
        err = lexical_realloc(ctx, &mem_23565, &mem_23565_cached_sizze_23860, bytes_23572);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:211:13-30
    if (mem_23573_cached_sizze_23861 < bytes_23572) {
        err = lexical_realloc(ctx, &mem_23573, &mem_23573_cached_sizze_23861, bytes_23572);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:211:13-30
    
    bool acc_cert_22569;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:211:13-30
    for (int64_t i_23108 = 0; i_23108 < n_13725; i_23108++) {
        bool eta_p_22582 = ((bool *) splits_mem_23561.mem)[i_23108];
        int64_t eta_p_22583 = ((int64_t *) lp_mem_23559.mem)[i_23108];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:266:25-49
        
        int64_t lifted_lambda_res_22586;
        
        if (eta_p_22582) {
            lifted_lambda_res_22586 = eta_p_22583;
        } else {
            lifted_lambda_res_22586 = (int64_t) 0;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:211:13-30
        // UpdateAcc
        if (sle64((int64_t) 0, eta_p_22583) && slt64(eta_p_22583, dzlz7bUZLztZRz20U2z20Unz7dUzg_18366)) {
            ((int64_t *) mem_23563)[eta_p_22583] = lifted_lambda_res_22586;
        }
        ((int64_t *) mem_23565)[i_23108] = lifted_lambda_res_22586;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:211:13-30
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_23573, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) mem_23565, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {n_13725});
    // ../lib/github.com/diku-dk/vtree/vtree.fut:212:13-39
    
    bool acc_cert_22524;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:212:13-39
    for (int64_t i_23111 = 0; i_23111 < n_13725; i_23111++) {
        int64_t eta_p_22536 = ((int64_t *) mem_23573)[i_23111];
        int64_t v_22538 = ((int64_t *) rp_mem_23560.mem)[i_23111];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:268:31-38
        
        int64_t neg_res_22539 = -eta_p_22536;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:212:13-39
        // UpdateAcc
        if (sle64((int64_t) 0, v_22538) && slt64(v_22538, dzlz7bUZLztZRz20U2z20Unz7dUzg_18366)) {
            ((int64_t *) mem_23563)[v_22538] = neg_res_22539;
        }
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:132:24-36
    if (mem_23575_cached_sizze_23862 < bytes_23562) {
        err = lexical_realloc(ctx, &mem_23575, &mem_23575_cached_sizze_23862, bytes_23562);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:132:24-36
    
    int64_t discard_23117;
    int64_t scanacc_23113 = (int64_t) 0;
    
    for (int64_t i_23115 = 0; i_23115 < dzlz7bUZLztZRz20U2z20Unz7dUzg_18366; i_23115++) {
        int64_t x_18388 = ((int64_t *) mem_23563)[i_23115];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:268:23-30
        
        int64_t zp_res_18391 = add64(x_18388, scanacc_23113);
        
        ((int64_t *) mem_23575)[i_23115] = zp_res_18391;
        
        int64_t scanacc_tmp_23672 = zp_res_18391;
        
        scanacc_23113 = scanacc_tmp_23672;
    }
    discard_23117 = scanacc_23113;
    // ../lib/github.com/diku-dk/vtree/vtree.fut:130:5-132:37
    if (mem_23583_cached_sizze_23863 < bytes_23562) {
        err = lexical_realloc(ctx, &mem_23583, &mem_23583_cached_sizze_23863, bytes_23562);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:130:5-132:37
    for (int64_t i_23120 = 0; i_23120 < dzlz7bUZLztZRz20U2z20Unz7dUzg_18366; i_23120++) {
        // ../lib/github.com/diku-dk/vtree/vtree.fut:132:11-36
        
        int64_t zv_lhs_22517 = add64((int64_t) -1, i_23120);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:132:11-36
        
        int64_t tmp_22518 = smod64(zv_lhs_22517, dzlz7bUZLztZRz20U2z20Unz7dUzg_18366);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:132:11-36
        
        int64_t lifted_lambda_res_22519 = ((int64_t *) mem_23575)[tmp_22518];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:130:19-43
        
        bool cond_22521 = i_23120 == (int64_t) 0;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:130:19-43
        
        int64_t lifted_lambda_res_22522;
        
        if (cond_22521) {
            lifted_lambda_res_22522 = (int64_t) 0;
        } else {
            lifted_lambda_res_22522 = lifted_lambda_res_22519;
        }
        ((int64_t *) mem_23583)[i_23120] = lifted_lambda_res_22522;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    if (mem_23591_cached_sizze_23864 < bytes_23572) {
        err = lexical_realloc(ctx, &mem_23591, &mem_23591_cached_sizze_23864, bytes_23572);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    if (mem_23593_cached_sizze_23865 < bytes_23572) {
        err = lexical_realloc(ctx, &mem_23593, &mem_23593_cached_sizze_23865, bytes_23572);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    if (mem_23595_cached_sizze_23866 < bytes_23572) {
        err = lexical_realloc(ctx, &mem_23595, &mem_23595_cached_sizze_23866, bytes_23572);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    if (mem_23597_cached_sizze_23867 < bytes_23572) {
        err = lexical_realloc(ctx, &mem_23597, &mem_23597_cached_sizze_23867, bytes_23572);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    if (mem_23598_cached_sizze_23868 < n_13725) {
        err = lexical_realloc(ctx, &mem_23598, &mem_23598_cached_sizze_23868, n_13725);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    if (mem_23600_cached_sizze_23869 < bytes_23572) {
        err = lexical_realloc(ctx, &mem_23600, &mem_23600_cached_sizze_23869, bytes_23572);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    if (mem_23602_cached_sizze_23870 < bytes_23572) {
        err = lexical_realloc(ctx, &mem_23602, &mem_23602_cached_sizze_23870, bytes_23572);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    
    int64_t discard_23147;
    int64_t discard_23148;
    int64_t discard_23149;
    int64_t scanacc_23129;
    int64_t scanacc_23130;
    int64_t scanacc_23131;
    
    scanacc_23129 = (int64_t) 0;
    scanacc_23130 = (int64_t) 0;
    scanacc_23131 = (int64_t) 0;
    for (int64_t i_23139 = 0; i_23139 < n_13725; i_23139++) {
        int64_t eta_p_22709 = ((int64_t *) lp_mem_23559.mem)[i_23139];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:214:19-23
        
        bool x_22713 = sle64((int64_t) 0, eta_p_22709);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:214:19-23
        
        bool y_22714 = slt64(eta_p_22709, dzlz7bUZLztZRz20U2z20Unz7dUzg_18366);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:214:19-23
        
        bool bounds_check_22715 = x_22713 && y_22714;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:214:19-23
        
        bool index_certs_22716;
        
        if (!bounds_check_22715) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) eta_p_22709, "] out of bounds for array of shape [", (long long) dzlz7bUZLztZRz20U2z20Unz7dUzg_18366, "].", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:214:19-23\n   #1  ../lib/github.com/diku-dk/vtree/vtree.fut:216:64-217:21\n   #2  ../lib/github.com/diku-dk/vtree/vtree.fut:267:7-268:22\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        
        bool eta_p_22708 = ((bool *) splits_mem_23561.mem)[i_23139];
        int64_t eta_p_22710 = ((int64_t *) rp_mem_23560.mem)[i_23139];
        int64_t eta_p_22711 = ((int64_t *) mem_23573)[i_23139];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:214:19-23
        
        int64_t lifted_lambda_res_22717 = ((int64_t *) mem_23583)[eta_p_22709];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:268:23-30
        
        int64_t zp_res_22718 = add64(eta_p_22711, lifted_lambda_res_22717);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:273:33-37
        
        bool lifted_lambda_res_22719 = zp_res_22718 == (int64_t) 0;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:273:33-37
        
        bool lifted_lambda_res_22720 = !lifted_lambda_res_22719;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:278:5-279:51
        
        int64_t defunc_0_f_res_22721 = btoi_bool_i64(lifted_lambda_res_22720);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:287:40-43
        
        int64_t zp_lhs_22722 = sub64(eta_p_22710, eta_p_22709);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:287:44-47
        
        int64_t zs_lhs_22723 = add64((int64_t) 1, zp_lhs_22722);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:287:49-52
        
        int64_t lifted_lambda_res_22724 = sdiv64(zs_lhs_22723, (int64_t) 2);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:288:36-55
        
        int64_t lifted_lambda_res_22725;
        
        if (eta_p_22708) {
            lifted_lambda_res_22725 = lifted_lambda_res_22724;
        } else {
            lifted_lambda_res_22725 = (int64_t) 0;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
        
        int64_t defunc_0_f_res_22729 = btoi_bool_i64(eta_p_22708);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:278:5-279:51
        
        int64_t defunc_0_op_res_17561 = add64(defunc_0_f_res_22721, scanacc_23129);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:289:37-40
        
        int64_t defunc_0_op_res_17620 = add64(lifted_lambda_res_22725, scanacc_23130);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
        
        int64_t defunc_0_op_res_17762 = add64(defunc_0_f_res_22729, scanacc_23131);
        
        ((int64_t *) mem_23591)[i_23139] = defunc_0_op_res_17561;
        ((int64_t *) mem_23593)[i_23139] = defunc_0_op_res_17620;
        ((int64_t *) mem_23595)[i_23139] = defunc_0_op_res_17762;
        ((int64_t *) mem_23597)[i_23139] = defunc_0_f_res_22729;
        ((bool *) mem_23598)[i_23139] = lifted_lambda_res_22719;
        ((int64_t *) mem_23600)[i_23139] = defunc_0_f_res_22721;
        ((int64_t *) mem_23602)[i_23139] = zp_res_22718;
        
        int64_t scanacc_tmp_23675 = defunc_0_op_res_17561;
        int64_t scanacc_tmp_23676 = defunc_0_op_res_17620;
        int64_t scanacc_tmp_23677 = defunc_0_op_res_17762;
        
        scanacc_23129 = scanacc_tmp_23675;
        scanacc_23130 = scanacc_tmp_23676;
        scanacc_23131 = scanacc_tmp_23677;
    }
    discard_23147 = scanacc_23129;
    discard_23148 = scanacc_23130;
    discard_23149 = scanacc_23131;
    // ../lib/github.com/diku-dk/vtree/vtree.fut:278:5-279:51
    
    int64_t tmp_17564 = sub64(n_13725, (int64_t) 1);
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:278:5-279:51
    
    bool y_17566 = slt64(tmp_17564, n_13725);
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:278:5-279:51
    
    bool x_17565 = sle64((int64_t) 0, tmp_17564);
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:278:5-279:51
    
    bool bounds_check_17567 = x_17565 && y_17566;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:278:5-279:51
    
    bool cond_17562 = n_13725 == (int64_t) 0;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:278:5-279:51
    
    bool protect_assert_disj_17568 = cond_17562 || bounds_check_17567;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:278:5-279:51
    
    bool index_certs_17569;
    
    if (!protect_assert_disj_17568) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) tmp_17564, "] out of bounds for array of shape [", (long long) n_13725, "].", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:278:5-279:51\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:278:5-279:51
    
    bool x_17563 = !cond_17562;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    
    int64_t m_f_res_17771;
    
    if (x_17563) {
        // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
        
        int64_t x_22825 = ((int64_t *) mem_23595)[tmp_17564];
        
        m_f_res_17771 = x_22825;
    } else {
        m_f_res_17771 = (int64_t) 0;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    
    int64_t m_17773;
    
    if (cond_17562) {
        m_17773 = (int64_t) 0;
    } else {
        m_17773 = m_f_res_17771;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    
    int64_t bytes_23645 = (int64_t) 8 * m_17773;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:278:5-279:51
    
    int64_t m_f_res_17570;
    
    if (x_17563) {
        // ../lib/github.com/diku-dk/vtree/vtree.fut:278:5-279:51
        
        int64_t x_22824 = ((int64_t *) mem_23591)[tmp_17564];
        
        m_f_res_17570 = x_22824;
    } else {
        m_f_res_17570 = (int64_t) 0;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:278:5-279:51
    
    int64_t m_17572;
    
    if (cond_17562) {
        m_17572 = (int64_t) 0;
    } else {
        m_17572 = m_f_res_17570;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:278:5-279:51
    
    int64_t bytes_23647 = (int64_t) 8 * m_17572;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    if (memblock_alloc(ctx, &mem_23646, bytes_23645, "mem_23646")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:278:5-279:51
    if (memblock_alloc(ctx, &mem_23648, bytes_23647, "mem_23648")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:278:5-279:51
    if (memblock_alloc(ctx, &mem_23650, bytes_23647, "mem_23650")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:278:5-279:51
    if (memblock_alloc(ctx, &mem_23652, bytes_23647, "mem_23652")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    
    bool acc_cert_22174;
    bool acc_cert_22418;
    bool acc_cert_22419;
    bool acc_cert_22420;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:271:17-279:51
    for (int64_t i_23153 = 0; i_23153 < n_13725; i_23153++) {
        int64_t eta_p_22455 = ((int64_t *) lp_mem_23559.mem)[i_23153];
        int64_t eta_p_22456 = ((int64_t *) mem_23602)[i_23153];
        int64_t eta_p_22457 = ((int64_t *) rp_mem_23560.mem)[i_23153];
        int64_t eta_p_22458 = ((int64_t *) mem_23600)[i_23153];
        int64_t eta_p_22459 = ((int64_t *) mem_23591)[i_23153];
        int64_t v_22463 = ((int64_t *) data_mem_23558.mem)[i_23153];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:271:22-25
        
        int64_t defunc_0_f_res_22465 = sub64(eta_p_22455, eta_p_22456);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:272:22-25
        
        int64_t defunc_0_f_res_22467 = sub64(eta_p_22457, eta_p_22456);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:278:5-279:51
        
        bool cond_22468 = eta_p_22458 == (int64_t) 1;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:278:5-279:51
        
        int64_t lifted_lambda_res_22469;
        
        if (cond_22468) {
            // ../lib/github.com/diku-dk/vtree/vtree.fut:278:5-279:51
            
            int64_t lifted_lambda_res_t_res_22812 = sub64(eta_p_22459, (int64_t) 1);
            
            lifted_lambda_res_22469 = lifted_lambda_res_t_res_22812;
        } else {
            lifted_lambda_res_22469 = (int64_t) -1;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:278:5-279:51
        // UpdateAcc
        if (sle64((int64_t) 0, lifted_lambda_res_22469) && slt64(lifted_lambda_res_22469, m_17572)) {
            ((int64_t *) mem_23652.mem)[lifted_lambda_res_22469] = defunc_0_f_res_22465;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:278:5-279:51
        // UpdateAcc
        if (sle64((int64_t) 0, lifted_lambda_res_22469) && slt64(lifted_lambda_res_22469, m_17572)) {
            ((int64_t *) mem_23650.mem)[lifted_lambda_res_22469] = defunc_0_f_res_22467;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:278:5-279:51
        // UpdateAcc
        if (sle64((int64_t) 0, lifted_lambda_res_22469) && slt64(lifted_lambda_res_22469, m_17572)) {
            ((int64_t *) mem_23648.mem)[lifted_lambda_res_22469] = v_22463;
        }
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
    for (int64_t i_23155 = 0; i_23155 < n_13725; i_23155++) {
        int64_t eta_p_22200 = ((int64_t *) mem_23597)[i_23155];
        int64_t eta_p_22201 = ((int64_t *) mem_23595)[i_23155];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:132:11-36
        
        int64_t zv_lhs_22204 = add64((int64_t) -1, i_23155);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:132:11-36
        
        int64_t tmp_22205 = smod64(zv_lhs_22204, n_13725);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:132:11-36
        
        int64_t lifted_lambda_res_22206 = ((int64_t *) mem_23593)[tmp_22205];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:130:19-43
        
        bool cond_22208 = i_23155 == (int64_t) 0;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:130:19-43
        
        int64_t lifted_lambda_res_22209;
        
        if (cond_22208) {
            lifted_lambda_res_22209 = (int64_t) 0;
        } else {
            lifted_lambda_res_22209 = lifted_lambda_res_22206;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
        
        bool cond_22210 = eta_p_22200 == (int64_t) 1;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
        
        int64_t lifted_lambda_res_22211;
        
        if (cond_22210) {
            // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
            
            int64_t lifted_lambda_res_t_res_22813 = sub64(eta_p_22201, (int64_t) 1);
            
            lifted_lambda_res_22211 = lifted_lambda_res_t_res_22813;
        } else {
            lifted_lambda_res_22211 = (int64_t) -1;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:237:15-40
        // UpdateAcc
        if (sle64((int64_t) 0, lifted_lambda_res_22211) && slt64(lifted_lambda_res_22211, m_17773)) {
            ((int64_t *) mem_23646.mem)[lifted_lambda_res_22211] = lifted_lambda_res_22209;
        }
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:258:12-292:42
    if (memblock_alloc(ctx, &mem_23653, n_13725, "mem_23653")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:258:12-292:42
    // ../lib/github.com/diku-dk/vtree/vtree.fut:258:12-292:42
    lmad_copy_1b(ctx, 1, (uint8_t *) mem_23653.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint8_t *) mem_23598, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {n_13725});
    // ../lib/github.com/diku-dk/vtree/vtree.fut:258:12-292:42
    
    int64_t split_res_13822;
    
    if (futrts_deleteVertices_7489(ctx, &ext_mem_23657, &ext_mem_23656, &ext_mem_23655, &split_res_13822, data_mem_23558, lp_mem_23559, rp_mem_23560, mem_23653, n_13725) != 0) {
        err = 1;
        goto cleanup;
    }
    if (memblock_unref(ctx, &mem_23653, "mem_23653") != 0)
        return 1;
    if (memblock_set(ctx, &mem_out_23658, &mem_23646, "mem_23646") != 0)
        return 1;
    if (memblock_set(ctx, &mem_out_23659, &mem_23648, "mem_23648") != 0)
        return 1;
    if (memblock_set(ctx, &mem_out_23660, &mem_23652, "mem_23652") != 0)
        return 1;
    if (memblock_set(ctx, &mem_out_23661, &mem_23650, "mem_23650") != 0)
        return 1;
    if (memblock_set(ctx, &mem_out_23662, &ext_mem_23657, "ext_mem_23657") != 0)
        return 1;
    if (memblock_set(ctx, &mem_out_23663, &ext_mem_23656, "ext_mem_23656") != 0)
        return 1;
    if (memblock_set(ctx, &mem_out_23664, &ext_mem_23655, "ext_mem_23655") != 0)
        return 1;
    prim_out_23665 = m_17773;
    prim_out_23666 = m_17572;
    prim_out_23667 = split_res_13822;
    if (memblock_set(ctx, &*mem_out_p_23849, &mem_out_23658, "mem_out_23658") != 0)
        return 1;
    if (memblock_set(ctx, &*mem_out_p_23850, &mem_out_23659, "mem_out_23659") != 0)
        return 1;
    if (memblock_set(ctx, &*mem_out_p_23851, &mem_out_23660, "mem_out_23660") != 0)
        return 1;
    if (memblock_set(ctx, &*mem_out_p_23852, &mem_out_23661, "mem_out_23661") != 0)
        return 1;
    if (memblock_set(ctx, &*mem_out_p_23853, &mem_out_23662, "mem_out_23662") != 0)
        return 1;
    if (memblock_set(ctx, &*mem_out_p_23854, &mem_out_23663, "mem_out_23663") != 0)
        return 1;
    if (memblock_set(ctx, &*mem_out_p_23855, &mem_out_23664, "mem_out_23664") != 0)
        return 1;
    *out_prim_out_23856 = prim_out_23665;
    *out_prim_out_23857 = prim_out_23666;
    *out_prim_out_23858 = prim_out_23667;
    
  cleanup:
    {
        free(mem_23563);
        free(mem_23565);
        free(mem_23573);
        free(mem_23575);
        free(mem_23583);
        free(mem_23591);
        free(mem_23593);
        free(mem_23595);
        free(mem_23597);
        free(mem_23598);
        free(mem_23600);
        free(mem_23602);
        if (memblock_unref(ctx, &ext_mem_23655, "ext_mem_23655") != 0)
            return 1;
        if (memblock_unref(ctx, &ext_mem_23656, "ext_mem_23656") != 0)
            return 1;
        if (memblock_unref(ctx, &ext_mem_23657, "ext_mem_23657") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_23653, "mem_23653") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_23652, "mem_23652") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_23650, "mem_23650") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_23648, "mem_23648") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_23646, "mem_23646") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_out_23664, "mem_out_23664") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_out_23663, "mem_out_23663") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_out_23662, "mem_out_23662") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_out_23661, "mem_out_23661") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_out_23660, "mem_out_23660") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_out_23659, "mem_out_23659") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_out_23658, "mem_out_23658") != 0)
            return 1;
    }
    return err;
}

int futhark_entry_test_delete_vertices(struct futhark_context *ctx, bool *out0)
{
    bool prim_out_23658 = 0;
    int ret = 0;
    
    lock_lock(&ctx->lock);
    if (ret == 0) {
        ret = futrts_entry_test_delete_vertices(ctx, &prim_out_23658);
        if (ret == 0) {
            bool ok_11869 = ctx->constants->ok_11869;
            bool ok_11952 = ctx->constants->ok_11952;
            bool x_16338 = ctx->constants->x_16338;
            bool x_16341 = ctx->constants->x_16341;
            bool x_16347 = ctx->constants->x_16347;
            bool x_16353 = ctx->constants->x_16353;
            
            *out0 = prim_out_23658;
        }
    }
    lock_unlock(&ctx->lock);
    return ret;
}
int futhark_entry_test_merge_tree(struct futhark_context *ctx, bool *out0)
{
    bool prim_out_23658 = 0;
    int ret = 0;
    
    lock_lock(&ctx->lock);
    if (ret == 0) {
        ret = futrts_entry_test_merge_tree(ctx, &prim_out_23658);
        if (ret == 0) {
            bool ok_11869 = ctx->constants->ok_11869;
            bool ok_11952 = ctx->constants->ok_11952;
            bool x_16338 = ctx->constants->x_16338;
            bool x_16341 = ctx->constants->x_16341;
            bool x_16347 = ctx->constants->x_16347;
            bool x_16353 = ctx->constants->x_16353;
            
            *out0 = prim_out_23658;
        }
    }
    lock_unlock(&ctx->lock);
    return ret;
}
int futhark_entry_test_split(struct futhark_context *ctx, bool *out0)
{
    bool prim_out_23658 = 0;
    int ret = 0;
    
    lock_lock(&ctx->lock);
    if (ret == 0) {
        ret = futrts_entry_test_split(ctx, &prim_out_23658);
        if (ret == 0) {
            bool ok_11869 = ctx->constants->ok_11869;
            bool ok_11952 = ctx->constants->ok_11952;
            bool x_16338 = ctx->constants->x_16338;
            bool x_16341 = ctx->constants->x_16341;
            bool x_16347 = ctx->constants->x_16347;
            bool x_16353 = ctx->constants->x_16353;
            
            *out0 = prim_out_23658;
        }
    }
    lock_unlock(&ctx->lock);
    return ret;
}
int futhark_entry_test_split_at_leaf(struct futhark_context *ctx, bool *out0)
{
    bool prim_out_23658 = 0;
    int ret = 0;
    
    lock_lock(&ctx->lock);
    if (ret == 0) {
        ret = futrts_entry_test_split_at_leaf(ctx, &prim_out_23658);
        if (ret == 0) {
            bool ok_11869 = ctx->constants->ok_11869;
            bool ok_11952 = ctx->constants->ok_11952;
            bool x_16338 = ctx->constants->x_16338;
            bool x_16341 = ctx->constants->x_16341;
            bool x_16347 = ctx->constants->x_16347;
            bool x_16353 = ctx->constants->x_16353;
            
            *out0 = prim_out_23658;
        }
    }
    lock_unlock(&ctx->lock);
    return ret;
}
int futhark_entry_test_split_multiple(struct futhark_context *ctx, bool *out0)
{
    bool prim_out_23658 = 0;
    int ret = 0;
    
    lock_lock(&ctx->lock);
    if (ret == 0) {
        ret = futrts_entry_test_split_multiple(ctx, &prim_out_23658);
        if (ret == 0) {
            bool ok_11869 = ctx->constants->ok_11869;
            bool ok_11952 = ctx->constants->ok_11952;
            bool x_16338 = ctx->constants->x_16338;
            bool x_16341 = ctx->constants->x_16341;
            bool x_16347 = ctx->constants->x_16347;
            bool x_16353 = ctx->constants->x_16353;
            
            *out0 = prim_out_23658;
        }
    }
    lock_unlock(&ctx->lock);
    return ret;
}
int futhark_entry_test_split_none(struct futhark_context *ctx, bool *out0)
{
    bool prim_out_23658 = 0;
    int ret = 0;
    
    lock_lock(&ctx->lock);
    if (ret == 0) {
        ret = futrts_entry_test_split_none(ctx, &prim_out_23658);
        if (ret == 0) {
            bool ok_11869 = ctx->constants->ok_11869;
            bool ok_11952 = ctx->constants->ok_11952;
            bool x_16338 = ctx->constants->x_16338;
            bool x_16341 = ctx->constants->x_16341;
            bool x_16347 = ctx->constants->x_16347;
            bool x_16353 = ctx->constants->x_16353;
            
            *out0 = prim_out_23658;
        }
    }
    lock_unlock(&ctx->lock);
    return ret;
}
  
