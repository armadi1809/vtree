
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
struct futhark_i64_1d;
struct futhark_i64_1d *futhark_new_i64_1d(struct futhark_context *ctx, const int64_t *data, int64_t dim0);
struct futhark_i64_1d *futhark_new_raw_i64_1d(struct futhark_context *ctx, unsigned char *data, int64_t dim0);
int futhark_free_i64_1d(struct futhark_context *ctx, struct futhark_i64_1d *arr);
int futhark_values_i64_1d(struct futhark_context *ctx, struct futhark_i64_1d *arr, int64_t *data);
int futhark_index_i64_1d(struct futhark_context *ctx, int64_t *out, struct futhark_i64_1d *arr, int64_t i0);
unsigned char *futhark_values_raw_i64_1d(struct futhark_context *ctx, struct futhark_i64_1d *arr);
const int64_t *futhark_shape_i64_1d(struct futhark_context *ctx, struct futhark_i64_1d *arr);

// Opaque values



// Entry points
int futhark_entry_test_delete_vertices(struct futhark_context *ctx, bool *out0);
int futhark_entry_test_merge_no_subtrees(struct futhark_context *ctx, bool *out0);
int futhark_entry_test_merge_tree(struct futhark_context *ctx, bool *out0);
int futhark_entry_test_parent_chain4_root0_simple(struct futhark_context *ctx, bool *out0, const struct futhark_i64_1d *in0, const struct futhark_i64_1d *in1);
int futhark_entry_test_parent_singleton_simple(struct futhark_context *ctx, bool *out0, const struct futhark_i64_1d *in0, const struct futhark_i64_1d *in1);
int futhark_entry_test_parent_star5_root3_simple(struct futhark_context *ctx, bool *out0, const struct futhark_i64_1d *in0, const struct futhark_i64_1d *in1);
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

const struct type type_ZMZNi64;
void *futhark_new_i64_1d_wrap(struct futhark_context *ctx, const void *p, const int64_t *shape)
{
    return futhark_new_i64_1d(ctx, p, shape[0]);
}
const struct array_aux type_ZMZNi64_aux = {.name ="[]i64", .rank =1, .info =&i64_info, .new =(array_new_fn) futhark_new_i64_1d_wrap, .free =(array_free_fn) futhark_free_i64_1d, .shape =(array_shape_fn) futhark_shape_i64_1d, .values =(array_values_fn) futhark_values_i64_1d};
const struct type type_ZMZNi64 = {.name ="[]i64", .restore =(restore_fn) restore_array, .store =(store_fn) store_array, .free =(free_fn) free_array, .aux =&type_ZMZNi64_aux};
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
const struct type *test_merge_no_subtrees_out_types[] = {&type_bool, NULL};
bool test_merge_no_subtrees_out_unique[] = {false};
const struct type *test_merge_no_subtrees_in_types[] = {NULL};
bool test_merge_no_subtrees_in_unique[] = {};
const char *test_merge_no_subtrees_tuning_params[] = {NULL};
int call_test_merge_no_subtrees(struct futhark_context *ctx, void **outs, void **ins)
{
    bool *out0 = outs[0];
    
    (void) ins;
    return futhark_entry_test_merge_no_subtrees(ctx, out0);
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
const struct type *test_parent_chain4_root0_simple_out_types[] = {&type_bool, NULL};
bool test_parent_chain4_root0_simple_out_unique[] = {false};
const struct type *test_parent_chain4_root0_simple_in_types[] = {&type_ZMZNi64, &type_ZMZNi64, NULL};
bool test_parent_chain4_root0_simple_in_unique[] = {false, false};
const char *test_parent_chain4_root0_simple_tuning_params[] = {NULL};
int call_test_parent_chain4_root0_simple(struct futhark_context *ctx, void **outs, void **ins)
{
    bool *out0 = outs[0];
    struct futhark_i64_1d * in0 = *(struct futhark_i64_1d * *) ins[0];
    struct futhark_i64_1d * in1 = *(struct futhark_i64_1d * *) ins[1];
    
    return futhark_entry_test_parent_chain4_root0_simple(ctx, out0, in0, in1);
}
const struct type *test_parent_singleton_simple_out_types[] = {&type_bool, NULL};
bool test_parent_singleton_simple_out_unique[] = {false};
const struct type *test_parent_singleton_simple_in_types[] = {&type_ZMZNi64, &type_ZMZNi64, NULL};
bool test_parent_singleton_simple_in_unique[] = {false, false};
const char *test_parent_singleton_simple_tuning_params[] = {NULL};
int call_test_parent_singleton_simple(struct futhark_context *ctx, void **outs, void **ins)
{
    bool *out0 = outs[0];
    struct futhark_i64_1d * in0 = *(struct futhark_i64_1d * *) ins[0];
    struct futhark_i64_1d * in1 = *(struct futhark_i64_1d * *) ins[1];
    
    return futhark_entry_test_parent_singleton_simple(ctx, out0, in0, in1);
}
const struct type *test_parent_star5_root3_simple_out_types[] = {&type_bool, NULL};
bool test_parent_star5_root3_simple_out_unique[] = {false};
const struct type *test_parent_star5_root3_simple_in_types[] = {&type_ZMZNi64, &type_ZMZNi64, NULL};
bool test_parent_star5_root3_simple_in_unique[] = {false, false};
const char *test_parent_star5_root3_simple_tuning_params[] = {NULL};
int call_test_parent_star5_root3_simple(struct futhark_context *ctx, void **outs, void **ins)
{
    bool *out0 = outs[0];
    struct futhark_i64_1d * in0 = *(struct futhark_i64_1d * *) ins[0];
    struct futhark_i64_1d * in1 = *(struct futhark_i64_1d * *) ins[1];
    
    return futhark_entry_test_parent_star5_root3_simple(ctx, out0, in0, in1);
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
const struct type *types[] = {&type_i8, &type_i16, &type_i32, &type_i64, &type_u8, &type_u16, &type_u32, &type_u64, &type_f16, &type_f32, &type_f64, &type_bool, &type_ZMZNi64, NULL};
struct entry_point entry_points[] = {{.name ="test_delete_vertices", .f =call_test_delete_vertices, .tuning_params =test_delete_vertices_tuning_params, .in_types =test_delete_vertices_in_types, .out_types =test_delete_vertices_out_types, .in_unique =test_delete_vertices_in_unique, .out_unique =test_delete_vertices_out_unique}, {.name ="test_merge_no_subtrees", .f =call_test_merge_no_subtrees, .tuning_params =test_merge_no_subtrees_tuning_params, .in_types =test_merge_no_subtrees_in_types, .out_types =test_merge_no_subtrees_out_types, .in_unique =test_merge_no_subtrees_in_unique, .out_unique =test_merge_no_subtrees_out_unique}, {.name ="test_merge_tree", .f =call_test_merge_tree, .tuning_params =test_merge_tree_tuning_params, .in_types =test_merge_tree_in_types, .out_types =test_merge_tree_out_types, .in_unique =test_merge_tree_in_unique, .out_unique =test_merge_tree_out_unique}, {.name ="test_parent_chain4_root0_simple", .f =call_test_parent_chain4_root0_simple, .tuning_params =test_parent_chain4_root0_simple_tuning_params, .in_types =test_parent_chain4_root0_simple_in_types, .out_types =test_parent_chain4_root0_simple_out_types, .in_unique =test_parent_chain4_root0_simple_in_unique, .out_unique =test_parent_chain4_root0_simple_out_unique}, {.name ="test_parent_singleton_simple", .f =call_test_parent_singleton_simple, .tuning_params =test_parent_singleton_simple_tuning_params, .in_types =test_parent_singleton_simple_in_types, .out_types =test_parent_singleton_simple_out_types, .in_unique =test_parent_singleton_simple_in_unique, .out_unique =test_parent_singleton_simple_out_unique}, {.name ="test_parent_star5_root3_simple", .f =call_test_parent_star5_root3_simple, .tuning_params =test_parent_star5_root3_simple_tuning_params, .in_types =test_parent_star5_root3_simple_in_types, .out_types =test_parent_star5_root3_simple_out_types, .in_unique =test_parent_star5_root3_simple_in_unique, .out_unique =test_parent_star5_root3_simple_out_unique}, {.name ="test_split", .f =call_test_split, .tuning_params =test_split_tuning_params, .in_types =test_split_in_types, .out_types =test_split_out_types, .in_unique =test_split_in_unique, .out_unique =test_split_out_unique}, {.name ="test_split_at_leaf", .f =call_test_split_at_leaf, .tuning_params =test_split_at_leaf_tuning_params, .in_types =test_split_at_leaf_in_types, .out_types =test_split_at_leaf_out_types, .in_unique =test_split_at_leaf_in_unique, .out_unique =test_split_at_leaf_out_unique}, {.name ="test_split_multiple", .f =call_test_split_multiple, .tuning_params =test_split_multiple_tuning_params, .in_types =test_split_multiple_in_types, .out_types =test_split_multiple_out_types, .in_unique =test_split_multiple_in_unique, .out_unique =test_split_multiple_out_unique}, {.name ="test_split_none", .f =call_test_split_none, .tuning_params =test_split_none_tuning_params, .in_types =test_split_none_in_types, .out_types =test_split_none_out_types, .in_unique =test_split_none_in_unique, .out_unique =test_split_none_out_unique}, {.name =NULL}};
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
    bool ok_17775;
    bool ok_17859;
    bool ok_17938;
    bool x_27518;
    bool x_27521;
    bool x_27527;
    bool x_27533;
};
static int64_t static_array_realtype_39631[6] = { (int64_t) 0,(int64_t) 1,(int64_t) 2,(int64_t) 4,(int64_t) 6,(int64_t) 9};
static int64_t static_array_realtype_39632[6] = { (int64_t) 11,(int64_t) 8,(int64_t) 3,(int64_t) 5,(int64_t) 7,(int64_t) 10};
static bool static_array_realtype_39633[6] = { 0,1,0,0,0,0};
static int64_t static_array_realtype_39634[4] = { (int64_t) 1,(int64_t) 2,(int64_t) 3,(int64_t) 4};
static int64_t static_array_realtype_39635[4] = { (int64_t) 0,(int64_t) 1,(int64_t) 3,(int64_t) 5};
static int64_t static_array_realtype_39636[4] = { (int64_t) 7,(int64_t) 2,(int64_t) 4,(int64_t) 6};
static int64_t static_array_realtype_39637[1] = { (int64_t) 4};
static int64_t static_array_realtype_39638[2] = { (int64_t) 0,(int64_t) 5};
static int64_t static_array_realtype_39639[2] = { (int64_t) 0,(int64_t) 1};
static int64_t static_array_realtype_39640[2] = { (int64_t) 3,(int64_t) 2};
static bool static_array_realtype_39641[6] = { 0,0,1,0,0,0};
static bool static_array_realtype_39642[6] = { 0,1,0,0,0,1};
static int64_t static_array_realtype_39643[2] = { (int64_t) 4,(int64_t) 1};
static bool static_array_realtype_39644[6] = { 0,0,0,0,0,0};
static bool static_array_realtype_39645[6] = { 1,1,0,0,0,1};
static int64_t static_array_realtype_39646[3] = { (int64_t) 0,(int64_t) 1,(int64_t) 5};
static int64_t static_array_realtype_39647[4] = { (int64_t) 0,(int64_t) 1,(int64_t) 3,(int64_t) 4};
static int64_t static_array_realtype_39648[4] = { (int64_t) 7,(int64_t) 2,(int64_t) 6,(int64_t) 5};
static int64_t static_array_realtype_39649[4] = { (int64_t) 0,(int64_t) 1,(int64_t) 2,(int64_t) 3};
static int64_t static_array_realtype_39650[5] = { (int64_t) 0,(int64_t) 1,(int64_t) 0,(int64_t) 1,(int64_t) 3};
static int64_t static_array_realtype_39651[5] = { (int64_t) 3,(int64_t) 2,(int64_t) 5,(int64_t) 2,(int64_t) 4};
static int64_t static_array_realtype_39652[5] = { (int64_t) 4,(int64_t) 5,(int64_t) 6,(int64_t) 7,(int64_t) 8};
static int64_t static_array_realtype_39653[2] = { (int64_t) 2,(int64_t) 3};
static int64_t static_array_realtype_39654[4] = { (int64_t) 0,(int64_t) 1,(int64_t) 0,(int64_t) -1};
static int64_t static_array_realtype_39655[11] = { (int64_t) 0,(int64_t) 1,(int64_t) 2,(int64_t) 5,(int64_t) 6,(int64_t) 7,(int64_t) 9,(int64_t) 13,(int64_t) 14,(int64_t) 15,(int64_t) 18};
static int64_t static_array_realtype_39656[11] = { (int64_t) 21,(int64_t) 4,(int64_t) 3,(int64_t) 12,(int64_t) 11,(int64_t) 8,(int64_t) 10,(int64_t) 20,(int64_t) 17,(int64_t) 16,(int64_t) 19};
static int64_t static_array_realtype_39657[11] = { (int64_t) 0,(int64_t) 4,(int64_t) 5,(int64_t) 1,(int64_t) 6,(int64_t) 7,(int64_t) 8,(int64_t) 2,(int64_t) 4,(int64_t) 5,(int64_t) 3};
static int64_t test_parent_chain4_root0_simplezistatic_array_realtype_39683[4] = { (int64_t) 0,(int64_t) 1,(int64_t) 2,(int64_t) 3};
static int64_t test_parent_chain4_root0_simplezistatic_array_realtype_39684[4] = { (int64_t) 4,(int64_t) 3,(int64_t) 2,(int64_t) 1};
static int64_t test_parent_chain4_root0_simplezistatic_array_realtype_39685[4] = { (int64_t) 0,(int64_t) 5,(int64_t) 12,(int64_t) 23};
static int64_t test_parent_singleton_simplezistatic_array_realtype_39692[1] = { (int64_t) 0};
static int64_t test_parent_singleton_simplezistatic_array_realtype_39693[1] = { (int64_t) 1};
static int64_t test_parent_star5_root3_simplezistatic_array_realtype_39701[5] = { (int64_t) 1,(int64_t) 1,(int64_t) 1,(int64_t) 0,(int64_t) 1};
static int64_t test_parent_star5_root3_simplezistatic_array_realtype_39702[5] = { (int64_t) 1,(int64_t) 1,(int64_t) 1,(int64_t) 5,(int64_t) 1};
static int64_t test_parent_star5_root3_simplezistatic_array_realtype_39703[5] = { (int64_t) 40,(int64_t) 40,(int64_t) 40,(int64_t) 0,(int64_t) 40};
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

FUTHARK_FUN_ATTR int futrts_deleteVertices_9181(struct futhark_context *ctx, struct memblock *mem_out_p_39658, struct memblock *mem_out_p_39659, struct memblock *mem_out_p_39660, int64_t *out_prim_out_39661, struct memblock data_mem_39192, struct memblock lp_mem_39193, struct memblock rp_mem_39194, struct memblock keep_mem_39195, int64_t n_19236);
FUTHARK_FUN_ATTR int futrts_depth_9287(struct futhark_context *ctx, struct memblock *mem_out_p_39669, struct memblock data_mem_39192, struct memblock lp_mem_39193, struct memblock rp_mem_39194, int64_t n_26930);
FUTHARK_FUN_ATTR int futrts_entry_test_delete_vertices(struct futhark_context *ctx, bool *out_prim_out_39673);
FUTHARK_FUN_ATTR int futrts_entry_test_merge_no_subtrees(struct futhark_context *ctx, bool *out_prim_out_39674);
FUTHARK_FUN_ATTR int futrts_entry_test_merge_tree(struct futhark_context *ctx, bool *out_prim_out_39675);
FUTHARK_FUN_ATTR int futrts_entry_test_parent_chain4_root0_simple(struct futhark_context *ctx, bool *out_prim_out_39676, struct memblock parent_mem_39192, struct memblock data_mem_39193);
FUTHARK_FUN_ATTR int futrts_entry_test_parent_singleton_simple(struct futhark_context *ctx, bool *out_prim_out_39686, struct memblock parent_mem_39192, struct memblock data_mem_39193);
FUTHARK_FUN_ATTR int futrts_entry_test_parent_star5_root3_simple(struct futhark_context *ctx, bool *out_prim_out_39694, struct memblock parent_mem_39192, struct memblock data_mem_39193);
FUTHARK_FUN_ATTR int futrts_entry_test_split(struct futhark_context *ctx, bool *out_prim_out_39704);
FUTHARK_FUN_ATTR int futrts_entry_test_split_at_leaf(struct futhark_context *ctx, bool *out_prim_out_39705);
FUTHARK_FUN_ATTR int futrts_entry_test_split_multiple(struct futhark_context *ctx, bool *out_prim_out_39706);
FUTHARK_FUN_ATTR int futrts_entry_test_split_none(struct futhark_context *ctx, bool *out_prim_out_39707);
FUTHARK_FUN_ATTR int futrts_from_parent_9285(struct futhark_context *ctx, struct memblock *mem_out_p_39708, struct memblock *mem_out_p_39709, struct memblock *mem_out_p_39710, struct memblock parent_mem_39192, struct memblock data_mem_39193, int64_t n_26458);
FUTHARK_FUN_ATTR int futrts_split_9182(struct futhark_context *ctx, struct memblock *mem_out_p_39736, struct memblock *mem_out_p_39737, struct memblock *mem_out_p_39738, struct memblock *mem_out_p_39739, struct memblock *mem_out_p_39740, struct memblock *mem_out_p_39741, struct memblock *mem_out_p_39742, int64_t *out_prim_out_39743, int64_t *out_prim_out_39744, int64_t *out_prim_out_39745, struct memblock data_mem_39192, struct memblock lp_mem_39193, struct memblock rp_mem_39194, struct memblock splits_mem_39195, int64_t n_20017);
FUTHARK_FUN_ATTR int futrts_subtree_sizzes_9289(struct futhark_context *ctx, struct memblock *mem_out_p_39757, struct memblock data_mem_39192, struct memblock lp_mem_39193, struct memblock rp_mem_39194, int64_t n_27252);

static int init_constants(struct futhark_context *ctx)
{
    (void) ctx;
    
    int err = 0;
    
    #define ok_17775 (ctx->constants->ok_17775)
    #define ok_17859 (ctx->constants->ok_17859)
    #define ok_17938 (ctx->constants->ok_17938)
    #define x_27518 (ctx->constants->x_27518)
    #define x_27521 (ctx->constants->x_27521)
    #define x_27527 (ctx->constants->x_27527)
    #define x_27533 (ctx->constants->x_27533)
    
    struct memblock mem_39185;
    
    mem_39185.references = NULL;
    
    struct memblock mem_39178;
    
    mem_39178.references = NULL;
    
    struct memblock mem_39164;
    
    mem_39164.references = NULL;
    
    struct memblock mem_39150;
    
    mem_39150.references = NULL;
    
    struct memblock mem_39142;
    
    mem_39142.references = NULL;
    
    struct memblock mem_39117;
    
    mem_39117.references = NULL;
    
    struct memblock mem_39103;
    
    mem_39103.references = NULL;
    
    struct memblock mem_39102;
    
    mem_39102.references = NULL;
    
    struct memblock mem_39095;
    
    mem_39095.references = NULL;
    
    struct memblock mem_39088;
    
    mem_39088.references = NULL;
    
    struct memblock mem_39087;
    
    mem_39087.references = NULL;
    
    struct memblock mem_39085;
    
    mem_39085.references = NULL;
    
    struct memblock mem_39084;
    
    mem_39084.references = NULL;
    
    struct memblock mem_39067;
    
    mem_39067.references = NULL;
    
    struct memblock mem_39065;
    
    mem_39065.references = NULL;
    
    struct memblock mem_39083;
    
    mem_39083.references = NULL;
    
    struct memblock mem_39081;
    
    mem_39081.references = NULL;
    
    struct memblock mem_39057;
    
    mem_39057.references = NULL;
    
    struct memblock mem_39043;
    
    mem_39043.references = NULL;
    
    struct memblock mem_39041;
    
    mem_39041.references = NULL;
    
    struct memblock mem_39033;
    
    mem_39033.references = NULL;
    
    struct memblock mem_39026;
    
    mem_39026.references = NULL;
    
    struct memblock mem_39025;
    
    mem_39025.references = NULL;
    
    struct memblock mem_39011;
    
    mem_39011.references = NULL;
    
    struct memblock mem_39009;
    
    mem_39009.references = NULL;
    
    struct memblock mem_38993;
    
    mem_38993.references = NULL;
    
    struct memblock mem_38992;
    
    mem_38992.references = NULL;
    
    struct memblock mem_39007;
    
    mem_39007.references = NULL;
    
    struct memblock mem_39006;
    
    mem_39006.references = NULL;
    
    struct memblock mem_38991;
    
    mem_38991.references = NULL;
    
    struct memblock mem_38990;
    
    mem_38990.references = NULL;
    
    struct memblock mem_38988;
    
    mem_38988.references = NULL;
    
    struct memblock mem_38986;
    
    mem_38986.references = NULL;
    
    struct memblock mem_38984;
    
    mem_38984.references = NULL;
    
    struct memblock mem_38977;
    
    mem_38977.references = NULL;
    
    struct memblock mem_38970;
    
    mem_38970.references = NULL;
    
    struct memblock mem_38934;
    
    mem_38934.references = NULL;
    
    struct memblock mem_38933;
    
    mem_38933.references = NULL;
    
    struct memblock mem_38932;
    
    mem_38932.references = NULL;
    
    struct memblock mem_38931;
    
    mem_38931.references = NULL;
    
    struct memblock mem_38930;
    
    mem_38930.references = NULL;
    
    struct memblock mem_38969;
    
    mem_38969.references = NULL;
    
    struct memblock mem_38968;
    
    mem_38968.references = NULL;
    
    struct memblock mem_38967;
    
    mem_38967.references = NULL;
    
    struct memblock mem_38966;
    
    mem_38966.references = NULL;
    
    struct memblock mem_38965;
    
    mem_38965.references = NULL;
    
    struct memblock mem_38929;
    
    mem_38929.references = NULL;
    
    struct memblock mem_38922;
    
    mem_38922.references = NULL;
    
    struct memblock mem_38921;
    
    mem_38921.references = NULL;
    
    struct memblock mem_38920;
    
    mem_38920.references = NULL;
    
    struct memblock mem_38919;
    
    mem_38919.references = NULL;
    
    struct memblock mem_38918;
    
    mem_38918.references = NULL;
    
    struct memblock mem_38917;
    
    mem_38917.references = NULL;
    
    struct memblock mem_38916;
    
    mem_38916.references = NULL;
    
    struct memblock mem_38915;
    
    mem_38915.references = NULL;
    
    struct memblock mem_38914;
    
    mem_38914.references = NULL;
    
    struct memblock mem_38913;
    
    mem_38913.references = NULL;
    
    struct memblock mem_38912;
    
    mem_38912.references = NULL;
    
    struct memblock mem_38911;
    
    mem_38911.references = NULL;
    
    struct memblock mem_38910;
    
    mem_38910.references = NULL;
    
    struct memblock mem_38909;
    
    mem_38909.references = NULL;
    
    struct memblock mem_38908;
    
    mem_38908.references = NULL;
    
    struct memblock mem_38907;
    
    mem_38907.references = NULL;
    
    struct memblock mem_38906;
    
    mem_38906.references = NULL;
    
    struct memblock ext_mem_38903;
    
    ext_mem_38903.references = NULL;
    
    struct memblock ext_mem_38904;
    
    ext_mem_38904.references = NULL;
    
    struct memblock ext_mem_38905;
    
    ext_mem_38905.references = NULL;
    
    struct memblock mem_38902;
    
    mem_38902.references = NULL;
    
    struct memblock ext_mem_38895;
    
    ext_mem_38895.references = NULL;
    
    struct memblock ext_mem_38896;
    
    ext_mem_38896.references = NULL;
    
    struct memblock ext_mem_38897;
    
    ext_mem_38897.references = NULL;
    
    struct memblock ext_mem_38898;
    
    ext_mem_38898.references = NULL;
    
    struct memblock ext_mem_38899;
    
    ext_mem_38899.references = NULL;
    
    struct memblock ext_mem_38900;
    
    ext_mem_38900.references = NULL;
    
    struct memblock ext_mem_38901;
    
    ext_mem_38901.references = NULL;
    
    struct memblock mem_38894;
    
    mem_38894.references = NULL;
    
    struct memblock mem_38893;
    
    mem_38893.references = NULL;
    
    struct memblock ext_mem_38886;
    
    ext_mem_38886.references = NULL;
    
    struct memblock ext_mem_38887;
    
    ext_mem_38887.references = NULL;
    
    struct memblock ext_mem_38888;
    
    ext_mem_38888.references = NULL;
    
    struct memblock ext_mem_38889;
    
    ext_mem_38889.references = NULL;
    
    struct memblock ext_mem_38890;
    
    ext_mem_38890.references = NULL;
    
    struct memblock ext_mem_38891;
    
    ext_mem_38891.references = NULL;
    
    struct memblock ext_mem_38892;
    
    ext_mem_38892.references = NULL;
    
    struct memblock mem_38885;
    
    mem_38885.references = NULL;
    
    struct memblock ext_mem_38878;
    
    ext_mem_38878.references = NULL;
    
    struct memblock ext_mem_38879;
    
    ext_mem_38879.references = NULL;
    
    struct memblock ext_mem_38880;
    
    ext_mem_38880.references = NULL;
    
    struct memblock ext_mem_38881;
    
    ext_mem_38881.references = NULL;
    
    struct memblock ext_mem_38882;
    
    ext_mem_38882.references = NULL;
    
    struct memblock ext_mem_38883;
    
    ext_mem_38883.references = NULL;
    
    struct memblock ext_mem_38884;
    
    ext_mem_38884.references = NULL;
    
    struct memblock mem_38877;
    
    mem_38877.references = NULL;
    
    struct memblock mem_38876;
    
    mem_38876.references = NULL;
    
    struct memblock mem_38875;
    
    mem_38875.references = NULL;
    
    struct memblock mem_38874;
    
    mem_38874.references = NULL;
    
    struct memblock mem_38873;
    
    mem_38873.references = NULL;
    
    struct memblock mem_38872;
    
    mem_38872.references = NULL;
    
    struct memblock mem_38871;
    
    mem_38871.references = NULL;
    
    struct memblock mem_38870;
    
    mem_38870.references = NULL;
    
    struct memblock ext_mem_38863;
    
    ext_mem_38863.references = NULL;
    
    struct memblock ext_mem_38864;
    
    ext_mem_38864.references = NULL;
    
    struct memblock ext_mem_38865;
    
    ext_mem_38865.references = NULL;
    
    struct memblock ext_mem_38866;
    
    ext_mem_38866.references = NULL;
    
    struct memblock ext_mem_38867;
    
    ext_mem_38867.references = NULL;
    
    struct memblock ext_mem_38868;
    
    ext_mem_38868.references = NULL;
    
    struct memblock ext_mem_38869;
    
    ext_mem_38869.references = NULL;
    
    struct memblock mem_38862;
    
    mem_38862.references = NULL;
    
    struct memblock mem_38861;
    
    mem_38861.references = NULL;
    
    struct memblock mem_38860;
    
    mem_38860.references = NULL;
    
    struct memblock mem_38859;
    
    mem_38859.references = NULL;
    // test_operations.fut:9:21-27
    if (memblock_alloc(ctx, &mem_38859, (int64_t) 48, "mem_38859")) {
        err = 1;
        goto cleanup;
    }
    // test_operations.fut:9:21-27
    for (int64_t i_39510 = 0; i_39510 < (int64_t) 6; i_39510++) {
        int64_t x_39511 = (int64_t) 0 + i_39510 * (int64_t) 1;
        
        ((int64_t *) mem_38859.mem)[i_39510] = x_39511;
    }
    // test_operations.fut:7:5-10:13
    if (memblock_alloc(ctx, &mem_38860, (int64_t) 48, "mem_38860")) {
        err = 1;
        goto cleanup;
    }
    // test_operations.fut:7:5-10:13
    
    struct memblock static_array_39512 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_39631, 0, "static_array_39512"};
    
    // test_operations.fut:7:5-10:13
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_38860.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_39512.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 6});
    // test_operations.fut:7:5-10:13
    if (memblock_alloc(ctx, &mem_38861, (int64_t) 48, "mem_38861")) {
        err = 1;
        goto cleanup;
    }
    // test_operations.fut:7:5-10:13
    
    struct memblock static_array_39513 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_39632, 0, "static_array_39513"};
    
    // test_operations.fut:7:5-10:13
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_38861.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_39513.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 6});
    // test_operations.fut:11:16-57
    if (memblock_alloc(ctx, &mem_38862, (int64_t) 6, "mem_38862")) {
        err = 1;
        goto cleanup;
    }
    // test_operations.fut:11:16-57
    
    struct memblock static_array_39514 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_39633, 0, "static_array_39514"};
    
    // test_operations.fut:11:16-57
    lmad_copy_1b(ctx, 1, (uint8_t *) mem_38862.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint8_t *) static_array_39514.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 6});
    // test_operations.fut:6:7-12:50
    
    int64_t test_split_res_17414;
    int64_t test_split_res_17415;
    int64_t test_split_res_17416;
    
    if (futrts_split_9182(ctx, &ext_mem_38869, &ext_mem_38868, &ext_mem_38867, &ext_mem_38866, &ext_mem_38865, &ext_mem_38864, &ext_mem_38863, &test_split_res_17414, &test_split_res_17415, &test_split_res_17416, mem_38859, mem_38860, mem_38861, mem_38862, (int64_t) 6) != 0) {
        err = 1;
        goto cleanup;
    }
    if (memblock_unref(ctx, &mem_38862, "mem_38862") != 0)
        return 1;
    // test_operations.fut:16:5-19:63
    
    bool cond_17445 = test_split_res_17414 == (int64_t) 4;
    
    // test_operations.fut:17:13-61
    if (memblock_alloc(ctx, &mem_38870, (int64_t) 32, "mem_38870")) {
        err = 1;
        goto cleanup;
    }
    // test_operations.fut:17:13-61
    
    struct memblock static_array_39515 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_39634, 0, "static_array_39515"};
    
    // test_operations.fut:17:13-61
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_38870.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_39515.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 4});
    // test_operations.fut:16:5-19:63
    
    bool cond_17446;
    
    if (cond_17445) {
        // test_operations.fut:17:24-47
        
        bool dim_match_34969 = (int64_t) 4 == test_split_res_17414;
        
        // test_operations.fut:17:24-47
        
        bool empty_or_match_cert_34970;
        
        if (!dim_match_34969) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (desugared) shape [", (long long) test_split_res_17414, "] cannot match shape of type \"[", (long long) (int64_t) 4, "]i64\".", "-> #0  test_operations.fut:17:24-47\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        // test_operations.fut:17:8-61
        
        bool defunc_0_reduce_res_34972;
        bool redout_38151 = 1;
        
        for (int64_t i_38152 = 0; i_38152 < (int64_t) 4; i_38152++) {
            int64_t eta_p_34973 = ((int64_t *) ext_mem_38869.mem)[i_38152];
            int64_t eta_p_34974 = ((int64_t *) mem_38870.mem)[i_38152];
            
            // test_operations.fut:17:18-22
            
            bool defunc_0_f_res_34975 = eta_p_34973 == eta_p_34974;
            
            // test_operations.fut:17:8-61
            
            bool x_34978 = defunc_0_f_res_34975 && redout_38151;
            bool redout_tmp_39516 = x_34978;
            
            redout_38151 = redout_tmp_39516;
        }
        defunc_0_reduce_res_34972 = redout_38151;
        cond_17446 = defunc_0_reduce_res_34972;
    } else {
        cond_17446 = 0;
    }
    if (memblock_unref(ctx, &ext_mem_38869, "ext_mem_38869") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38870, "mem_38870") != 0)
        return 1;
    // test_operations.fut:18:13-62
    if (memblock_alloc(ctx, &mem_38871, (int64_t) 32, "mem_38871")) {
        err = 1;
        goto cleanup;
    }
    // test_operations.fut:18:13-62
    
    struct memblock static_array_39517 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_39635, 0, "static_array_39517"};
    
    // test_operations.fut:18:13-62
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_38871.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_39517.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 4});
    // test_operations.fut:16:5-19:63
    
    bool cond_17456;
    
    if (cond_17446) {
        // test_operations.fut:18:24-45
        
        bool dim_match_34984 = (int64_t) 4 == test_split_res_17414;
        
        // test_operations.fut:18:24-45
        
        bool empty_or_match_cert_34985;
        
        if (!dim_match_34984) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (desugared) shape [", (long long) test_split_res_17414, "] cannot match shape of type \"[", (long long) (int64_t) 4, "]i64\".", "-> #0  test_operations.fut:18:24-45\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        // test_operations.fut:18:8-62
        
        bool defunc_0_reduce_res_34987;
        bool redout_38153 = 1;
        
        for (int64_t i_38154 = 0; i_38154 < (int64_t) 4; i_38154++) {
            int64_t eta_p_34988 = ((int64_t *) ext_mem_38868.mem)[i_38154];
            int64_t eta_p_34989 = ((int64_t *) mem_38871.mem)[i_38154];
            
            // test_operations.fut:18:18-22
            
            bool defunc_0_f_res_34990 = eta_p_34988 == eta_p_34989;
            
            // test_operations.fut:18:8-62
            
            bool x_34993 = defunc_0_f_res_34990 && redout_38153;
            bool redout_tmp_39518 = x_34993;
            
            redout_38153 = redout_tmp_39518;
        }
        defunc_0_reduce_res_34987 = redout_38153;
        cond_17456 = defunc_0_reduce_res_34987;
    } else {
        cond_17456 = 0;
    }
    if (memblock_unref(ctx, &ext_mem_38868, "ext_mem_38868") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38871, "mem_38871") != 0)
        return 1;
    // test_operations.fut:19:13-62
    if (memblock_alloc(ctx, &mem_38872, (int64_t) 32, "mem_38872")) {
        err = 1;
        goto cleanup;
    }
    // test_operations.fut:19:13-62
    
    struct memblock static_array_39519 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_39636, 0, "static_array_39519"};
    
    // test_operations.fut:19:13-62
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_38872.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_39519.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 4});
    // test_operations.fut:16:5-19:63
    
    bool subtrees_ok_17466;
    
    if (cond_17456) {
        // test_operations.fut:19:24-45
        
        bool dim_match_34999 = (int64_t) 4 == test_split_res_17414;
        
        // test_operations.fut:19:24-45
        
        bool empty_or_match_cert_35000;
        
        if (!dim_match_34999) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (desugared) shape [", (long long) test_split_res_17414, "] cannot match shape of type \"[", (long long) (int64_t) 4, "]i64\".", "-> #0  test_operations.fut:19:24-45\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        // test_operations.fut:19:8-62
        
        bool defunc_0_reduce_res_35002;
        bool redout_38155 = 1;
        
        for (int64_t i_38156 = 0; i_38156 < (int64_t) 4; i_38156++) {
            int64_t eta_p_35003 = ((int64_t *) ext_mem_38867.mem)[i_38156];
            int64_t eta_p_35004 = ((int64_t *) mem_38872.mem)[i_38156];
            
            // test_operations.fut:19:18-22
            
            bool defunc_0_f_res_35005 = eta_p_35003 == eta_p_35004;
            
            // test_operations.fut:19:8-62
            
            bool x_35008 = defunc_0_f_res_35005 && redout_38155;
            bool redout_tmp_39520 = x_35008;
            
            redout_38155 = redout_tmp_39520;
        }
        defunc_0_reduce_res_35002 = redout_38155;
        subtrees_ok_17466 = defunc_0_reduce_res_35002;
    } else {
        subtrees_ok_17466 = 0;
    }
    if (memblock_unref(ctx, &ext_mem_38867, "ext_mem_38867") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38872, "mem_38872") != 0)
        return 1;
    // test_operations.fut:22:5-23:69
    
    bool cond_17479 = test_split_res_17415 == (int64_t) 1;
    
    // test_operations.fut:22:5-23:69
    
    bool shape_ok_17480;
    
    if (cond_17479) {
        // test_operations.fut:23:24-60
        
        bool dim_match_35012 = (int64_t) 1 == test_split_res_17415;
        
        // test_operations.fut:23:24-60
        
        bool empty_or_match_cert_35013;
        
        if (!dim_match_35012) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (desugared) shape [", (long long) test_split_res_17415, "] cannot match shape of type \"[", (long long) (int64_t) 1, "]i64\".", "-> #0  test_operations.fut:23:24-60\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        // test_operations.fut:23:13-68
        if (memblock_alloc(ctx, &mem_38873, (int64_t) 8, "mem_38873")) {
            err = 1;
            goto cleanup;
        }
        // test_operations.fut:23:13-68
        
        struct memblock static_array_39521 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_39637, 0, "static_array_39521"};
        
        // test_operations.fut:23:13-68
        lmad_copy_8b(ctx, 1, (uint64_t *) mem_38873.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_39521.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 1});
        
        int64_t eta_p_35015 = ((int64_t *) ext_mem_38866.mem)[(int64_t) 0];
        int64_t eta_p_35016 = ((int64_t *) mem_38873.mem)[(int64_t) 0];
        
        if (memblock_unref(ctx, &mem_38873, "mem_38873") != 0)
            return 1;
        // test_operations.fut:23:18-22
        
        bool defunc_0_f_res_35017 = eta_p_35015 == eta_p_35016;
        
        shape_ok_17480 = defunc_0_f_res_35017;
    } else {
        shape_ok_17480 = 0;
    }
    if (memblock_unref(ctx, &ext_mem_38866, "ext_mem_38866") != 0)
        return 1;
    // test_operations.fut:27:5-30:52
    
    bool cond_17499 = test_split_res_17416 == (int64_t) 2;
    
    // test_operations.fut:28:13-50
    if (memblock_alloc(ctx, &mem_38874, (int64_t) 16, "mem_38874")) {
        err = 1;
        goto cleanup;
    }
    // test_operations.fut:28:13-50
    
    struct memblock static_array_39522 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_39638, 0, "static_array_39522"};
    
    // test_operations.fut:28:13-50
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_38874.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_39522.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 2});
    // test_operations.fut:27:5-30:52
    
    bool cond_17500;
    
    if (cond_17499) {
        // test_operations.fut:28:24-42
        
        bool dim_match_35020 = (int64_t) 2 == test_split_res_17416;
        
        // test_operations.fut:28:24-42
        
        bool empty_or_match_cert_35021;
        
        if (!dim_match_35020) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (desugared) shape [", (long long) test_split_res_17416, "] cannot match shape of type \"[", (long long) (int64_t) 2, "]i64\".", "-> #0  test_operations.fut:28:24-42\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        // test_operations.fut:28:8-50
        
        bool defunc_0_reduce_res_35023;
        bool redout_38157 = 1;
        
        for (int64_t i_38158 = 0; i_38158 < (int64_t) 2; i_38158++) {
            int64_t eta_p_35024 = ((int64_t *) ext_mem_38865.mem)[i_38158];
            int64_t eta_p_35025 = ((int64_t *) mem_38874.mem)[i_38158];
            
            // test_operations.fut:28:18-22
            
            bool defunc_0_f_res_35026 = eta_p_35024 == eta_p_35025;
            
            // test_operations.fut:28:8-50
            
            bool x_35029 = defunc_0_f_res_35026 && redout_38157;
            bool redout_tmp_39523 = x_35029;
            
            redout_38157 = redout_tmp_39523;
        }
        defunc_0_reduce_res_35023 = redout_38157;
        cond_17500 = defunc_0_reduce_res_35023;
    } else {
        cond_17500 = 0;
    }
    if (memblock_unref(ctx, &ext_mem_38865, "ext_mem_38865") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38874, "mem_38874") != 0)
        return 1;
    // test_operations.fut:29:13-51
    if (memblock_alloc(ctx, &mem_38875, (int64_t) 16, "mem_38875")) {
        err = 1;
        goto cleanup;
    }
    // test_operations.fut:29:13-51
    
    struct memblock static_array_39524 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_39639, 0, "static_array_39524"};
    
    // test_operations.fut:29:13-51
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_38875.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_39524.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 2});
    // test_operations.fut:27:5-30:52
    
    bool cond_17510;
    
    if (cond_17500) {
        // test_operations.fut:29:24-40
        
        bool dim_match_35035 = (int64_t) 2 == test_split_res_17416;
        
        // test_operations.fut:29:24-40
        
        bool empty_or_match_cert_35036;
        
        if (!dim_match_35035) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (desugared) shape [", (long long) test_split_res_17416, "] cannot match shape of type \"[", (long long) (int64_t) 2, "]i64\".", "-> #0  test_operations.fut:29:24-40\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        // test_operations.fut:29:8-51
        
        bool defunc_0_reduce_res_35038;
        bool redout_38159 = 1;
        
        for (int64_t i_38160 = 0; i_38160 < (int64_t) 2; i_38160++) {
            int64_t eta_p_35039 = ((int64_t *) ext_mem_38864.mem)[i_38160];
            int64_t eta_p_35040 = ((int64_t *) mem_38875.mem)[i_38160];
            
            // test_operations.fut:29:18-22
            
            bool defunc_0_f_res_35041 = eta_p_35039 == eta_p_35040;
            
            // test_operations.fut:29:8-51
            
            bool x_35044 = defunc_0_f_res_35041 && redout_38159;
            bool redout_tmp_39525 = x_35044;
            
            redout_38159 = redout_tmp_39525;
        }
        defunc_0_reduce_res_35038 = redout_38159;
        cond_17510 = defunc_0_reduce_res_35038;
    } else {
        cond_17510 = 0;
    }
    if (memblock_unref(ctx, &ext_mem_38864, "ext_mem_38864") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38875, "mem_38875") != 0)
        return 1;
    // test_operations.fut:30:13-51
    if (memblock_alloc(ctx, &mem_38876, (int64_t) 16, "mem_38876")) {
        err = 1;
        goto cleanup;
    }
    // test_operations.fut:30:13-51
    
    struct memblock static_array_39526 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_39640, 0, "static_array_39526"};
    
    // test_operations.fut:30:13-51
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_38876.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_39526.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 2});
    // test_operations.fut:27:5-30:52
    
    bool remainder_ok_17520;
    
    if (cond_17510) {
        // test_operations.fut:30:24-40
        
        bool dim_match_35050 = (int64_t) 2 == test_split_res_17416;
        
        // test_operations.fut:30:24-40
        
        bool empty_or_match_cert_35051;
        
        if (!dim_match_35050) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (desugared) shape [", (long long) test_split_res_17416, "] cannot match shape of type \"[", (long long) (int64_t) 2, "]i64\".", "-> #0  test_operations.fut:30:24-40\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        // test_operations.fut:30:8-51
        
        bool defunc_0_reduce_res_35053;
        bool redout_38161 = 1;
        
        for (int64_t i_38162 = 0; i_38162 < (int64_t) 2; i_38162++) {
            int64_t eta_p_35054 = ((int64_t *) ext_mem_38863.mem)[i_38162];
            int64_t eta_p_35055 = ((int64_t *) mem_38876.mem)[i_38162];
            
            // test_operations.fut:30:18-22
            
            bool defunc_0_f_res_35056 = eta_p_35054 == eta_p_35055;
            
            // test_operations.fut:30:8-51
            
            bool x_35059 = defunc_0_f_res_35056 && redout_38161;
            bool redout_tmp_39527 = x_35059;
            
            redout_38161 = redout_tmp_39527;
        }
        defunc_0_reduce_res_35053 = redout_38161;
        remainder_ok_17520 = defunc_0_reduce_res_35053;
    } else {
        remainder_ok_17520 = 0;
    }
    if (memblock_unref(ctx, &ext_mem_38863, "ext_mem_38863") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38876, "mem_38876") != 0)
        return 1;
    
    bool x_27515 = subtrees_ok_17466 && shape_ok_17480;
    
    x_27518 = remainder_ok_17520 && x_27515;
    // test_operations.fut:55:16-57
    if (memblock_alloc(ctx, &mem_38877, (int64_t) 6, "mem_38877")) {
        err = 1;
        goto cleanup;
    }
    // test_operations.fut:55:16-57
    
    struct memblock static_array_39528 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_39641, 0, "static_array_39528"};
    
    // test_operations.fut:55:16-57
    lmad_copy_1b(ctx, 1, (uint8_t *) mem_38877.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint8_t *) static_array_39528.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 6});
    // test_operations.fut:49:7-56:50
    
    int64_t test_split_at_leaf_res_17546;
    int64_t test_split_at_leaf_res_17547;
    int64_t test_split_at_leaf_res_17548;
    
    if (futrts_split_9182(ctx, &ext_mem_38884, &ext_mem_38883, &ext_mem_38882, &ext_mem_38881, &ext_mem_38880, &ext_mem_38879, &ext_mem_38878, &test_split_at_leaf_res_17546, &test_split_at_leaf_res_17547, &test_split_at_leaf_res_17548, mem_38859, mem_38860, mem_38861, mem_38877, (int64_t) 6) != 0) {
        err = 1;
        goto cleanup;
    }
    if (memblock_unref(ctx, &mem_38877, "mem_38877") != 0)
        return 1;
    // test_operations.fut:61:5-62:53
    
    bool cond_17583 = test_split_at_leaf_res_17546 == (int64_t) 1;
    
    // test_operations.fut:61:5-62:53
    
    bool subtrees_ok_17584;
    
    if (cond_17583) {
        // test_operations.fut:62:24-47
        
        bool dim_match_35063 = (int64_t) 1 == test_split_at_leaf_res_17546;
        
        // test_operations.fut:62:24-47
        
        bool empty_or_match_cert_35064;
        
        if (!dim_match_35063) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (desugared) shape [", (long long) test_split_at_leaf_res_17546, "] cannot match shape of type \"[", (long long) (int64_t) 1, "]i64\".", "-> #0  test_operations.fut:62:24-47\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        
        int64_t eta_p_35065 = ((int64_t *) ext_mem_38884.mem)[(int64_t) 0];
        
        // test_operations.fut:62:18-22
        
        bool defunc_0_f_res_35066 = eta_p_35065 == (int64_t) 2;
        
        subtrees_ok_17584 = defunc_0_f_res_35066;
    } else {
        subtrees_ok_17584 = 0;
    }
    if (memblock_unref(ctx, &ext_mem_38884, "ext_mem_38884") != 0)
        return 1;
    // test_operations.fut:64:38-42
    
    bool remainder_ok_17597 = test_split_at_leaf_res_17548 == (int64_t) 5;
    
    x_27521 = subtrees_ok_17584 && remainder_ok_17597;
    // test_operations.fut:74:16-56
    if (memblock_alloc(ctx, &mem_38885, (int64_t) 6, "mem_38885")) {
        err = 1;
        goto cleanup;
    }
    // test_operations.fut:74:16-56
    
    struct memblock static_array_39529 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_39642, 0, "static_array_39529"};
    
    // test_operations.fut:74:16-56
    lmad_copy_1b(ctx, 1, (uint8_t *) mem_38885.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint8_t *) static_array_39529.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 6});
    // test_operations.fut:68:7-75:50
    
    int64_t test_split_multiple_res_17613;
    int64_t test_split_multiple_res_17614;
    int64_t test_split_multiple_res_17615;
    
    if (futrts_split_9182(ctx, &ext_mem_38892, &ext_mem_38891, &ext_mem_38890, &ext_mem_38889, &ext_mem_38888, &ext_mem_38887, &ext_mem_38886, &test_split_multiple_res_17613, &test_split_multiple_res_17614, &test_split_multiple_res_17615, mem_38859, mem_38860, mem_38861, mem_38885, (int64_t) 6) != 0) {
        err = 1;
        goto cleanup;
    }
    if (memblock_unref(ctx, &mem_38885, "mem_38885") != 0)
        return 1;
    // test_operations.fut:79:42-46
    
    bool subtrees_ok_17650 = test_split_multiple_res_17613 == (int64_t) 5;
    
    // test_operations.fut:82:5-83:75
    
    bool cond_17654 = test_split_multiple_res_17614 == (int64_t) 2;
    
    // test_operations.fut:82:5-83:75
    
    bool shape_ok_17655;
    
    if (cond_17654) {
        // test_operations.fut:83:24-60
        
        bool dim_match_35069 = (int64_t) 2 == test_split_multiple_res_17614;
        
        // test_operations.fut:83:24-60
        
        bool empty_or_match_cert_35070;
        
        if (!dim_match_35069) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (desugared) shape [", (long long) test_split_multiple_res_17614, "] cannot match shape of type \"[", (long long) (int64_t) 2, "]i64\".", "-> #0  test_operations.fut:83:24-60\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        // test_operations.fut:83:13-74
        if (memblock_alloc(ctx, &mem_38893, (int64_t) 16, "mem_38893")) {
            err = 1;
            goto cleanup;
        }
        // test_operations.fut:83:13-74
        
        struct memblock static_array_39530 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_39643, 0, "static_array_39530"};
        
        // test_operations.fut:83:13-74
        lmad_copy_8b(ctx, 1, (uint64_t *) mem_38893.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_39530.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 2});
        // test_operations.fut:83:8-74
        
        bool defunc_0_reduce_res_35073;
        bool redout_38163 = 1;
        
        for (int64_t i_38164 = 0; i_38164 < (int64_t) 2; i_38164++) {
            int64_t eta_p_35074 = ((int64_t *) ext_mem_38889.mem)[i_38164];
            int64_t eta_p_35075 = ((int64_t *) mem_38893.mem)[i_38164];
            
            // test_operations.fut:83:18-22
            
            bool defunc_0_f_res_35076 = eta_p_35074 == eta_p_35075;
            
            // test_operations.fut:83:8-74
            
            bool x_35079 = defunc_0_f_res_35076 && redout_38163;
            bool redout_tmp_39531 = x_35079;
            
            redout_38163 = redout_tmp_39531;
        }
        defunc_0_reduce_res_35073 = redout_38163;
        if (memblock_unref(ctx, &mem_38893, "mem_38893") != 0)
            return 1;
        shape_ok_17655 = defunc_0_reduce_res_35073;
    } else {
        shape_ok_17655 = 0;
    }
    if (memblock_unref(ctx, &ext_mem_38889, "ext_mem_38889") != 0)
        return 1;
    // test_operations.fut:86:5-87:48
    
    bool cond_17668 = test_split_multiple_res_17615 == (int64_t) 1;
    
    // test_operations.fut:86:5-87:48
    
    bool remainder_ok_17669;
    
    if (cond_17668) {
        // test_operations.fut:87:24-42
        
        bool dim_match_35083 = (int64_t) 1 == test_split_multiple_res_17615;
        
        // test_operations.fut:87:24-42
        
        bool empty_or_match_cert_35084;
        
        if (!dim_match_35083) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (desugared) shape [", (long long) test_split_multiple_res_17615, "] cannot match shape of type \"[", (long long) (int64_t) 1, "]i64\".", "-> #0  test_operations.fut:87:24-42\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        
        int64_t eta_p_35085 = ((int64_t *) ext_mem_38888.mem)[(int64_t) 0];
        
        // test_operations.fut:87:18-22
        
        bool defunc_0_f_res_35086 = eta_p_35085 == (int64_t) 0;
        
        remainder_ok_17669 = defunc_0_f_res_35086;
    } else {
        remainder_ok_17669 = 0;
    }
    if (memblock_unref(ctx, &ext_mem_38888, "ext_mem_38888") != 0)
        return 1;
    
    bool x_27524 = subtrees_ok_17650 && shape_ok_17655;
    
    x_27527 = remainder_ok_17669 && x_27524;
    // test_operations.fut:96:16-58
    if (memblock_alloc(ctx, &mem_38894, (int64_t) 6, "mem_38894")) {
        err = 1;
        goto cleanup;
    }
    // test_operations.fut:96:16-58
    
    struct memblock static_array_39532 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_39644, 0, "static_array_39532"};
    
    // test_operations.fut:96:16-58
    lmad_copy_1b(ctx, 1, (uint8_t *) mem_38894.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint8_t *) static_array_39532.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 6});
    // test_operations.fut:91:7-97:50
    
    int64_t test_split_none_res_17695;
    int64_t test_split_none_res_17696;
    int64_t test_split_none_res_17697;
    
    if (futrts_split_9182(ctx, &ext_mem_38901, &ext_mem_38900, &ext_mem_38899, &ext_mem_38898, &ext_mem_38897, &ext_mem_38896, &ext_mem_38895, &test_split_none_res_17695, &test_split_none_res_17696, &test_split_none_res_17697, mem_38859, mem_38860, mem_38861, mem_38894, (int64_t) 6) != 0) {
        err = 1;
        goto cleanup;
    }
    if (memblock_unref(ctx, &mem_38894, "mem_38894") != 0)
        return 1;
    // test_operations.fut:101:42-46
    
    bool subtrees_ok_17732 = test_split_none_res_17695 == (int64_t) 0;
    
    // test_operations.fut:102:52-56
    
    bool shape_ok_17736 = test_split_none_res_17696 == (int64_t) 0;
    
    // test_operations.fut:104:38-42
    
    bool remainder_ok_17740 = test_split_none_res_17697 == (int64_t) 6;
    bool x_27530 = subtrees_ok_17732 && shape_ok_17736;
    
    x_27533 = remainder_ok_17740 && x_27530;
    // test_operations.fut:114:14-53
    if (memblock_alloc(ctx, &mem_38902, (int64_t) 6, "mem_38902")) {
        err = 1;
        goto cleanup;
    }
    // test_operations.fut:114:14-53
    
    struct memblock static_array_39533 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_39645, 0, "static_array_39533"};
    
    // test_operations.fut:114:14-53
    lmad_copy_1b(ctx, 1, (uint8_t *) mem_38902.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint8_t *) static_array_39533.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 6});
    // test_operations.fut:108:7-115:39
    
    int64_t test_delete_vertices_res_17757;
    
    if (futrts_deleteVertices_9181(ctx, &ext_mem_38905, &ext_mem_38904, &ext_mem_38903, &test_delete_vertices_res_17757, mem_38859, mem_38860, mem_38861, mem_38902, (int64_t) 6) != 0) {
        err = 1;
        goto cleanup;
    }
    if (memblock_unref(ctx, &mem_38859, "mem_38859") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38860, "mem_38860") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38861, "mem_38861") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38902, "mem_38902") != 0)
        return 1;
    // test_operations.fut:118:5-119:54
    
    bool cond_17774 = test_delete_vertices_res_17757 == (int64_t) 3;
    
    // test_operations.fut:119:13-53
    if (memblock_alloc(ctx, &mem_38906, (int64_t) 24, "mem_38906")) {
        err = 1;
        goto cleanup;
    }
    // test_operations.fut:119:13-53
    
    struct memblock static_array_39534 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_39646, 0, "static_array_39534"};
    
    // test_operations.fut:119:13-53
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_38906.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_39534.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 3});
    // test_operations.fut:118:5-119:54
    if (cond_17774) {
        // test_operations.fut:119:24-42
        
        bool dim_match_35089 = (int64_t) 3 == test_delete_vertices_res_17757;
        
        // test_operations.fut:119:24-42
        
        bool empty_or_match_cert_35090;
        
        if (!dim_match_35089) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (desugared) shape [", (long long) test_delete_vertices_res_17757, "] cannot match shape of type \"[", (long long) (int64_t) 3, "]i64\".", "-> #0  test_operations.fut:119:24-42\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        // test_operations.fut:119:8-53
        
        bool defunc_0_reduce_res_35092;
        bool redout_38165 = 1;
        
        for (int64_t i_38166 = 0; i_38166 < (int64_t) 3; i_38166++) {
            int64_t eta_p_35093 = ((int64_t *) ext_mem_38905.mem)[i_38166];
            int64_t eta_p_35094 = ((int64_t *) mem_38906.mem)[i_38166];
            
            // test_operations.fut:119:18-22
            
            bool defunc_0_f_res_35095 = eta_p_35093 == eta_p_35094;
            
            // test_operations.fut:119:8-53
            
            bool x_35098 = defunc_0_f_res_35095 && redout_38165;
            bool redout_tmp_39535 = x_35098;
            
            redout_38165 = redout_tmp_39535;
        }
        defunc_0_reduce_res_35092 = redout_38165;
        ok_17775 = defunc_0_reduce_res_35092;
    } else {
        ok_17775 = 0;
    }
    if (memblock_unref(ctx, &ext_mem_38905, "ext_mem_38905") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38906, "mem_38906") != 0)
        return 1;
    // test_operations.fut:124:5-128:4
    if (memblock_alloc(ctx, &mem_38907, (int64_t) 32, "mem_38907")) {
        err = 1;
        goto cleanup;
    }
    // test_operations.fut:124:5-128:4
    
    struct memblock static_array_39536 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_39647, 0, "static_array_39536"};
    
    // test_operations.fut:124:5-128:4
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_38907.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_39536.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 4});
    // test_operations.fut:124:5-128:4
    if (memblock_alloc(ctx, &mem_38908, (int64_t) 32, "mem_38908")) {
        err = 1;
        goto cleanup;
    }
    // test_operations.fut:124:5-128:4
    
    struct memblock static_array_39537 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_39648, 0, "static_array_39537"};
    
    // test_operations.fut:124:5-128:4
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_38908.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_39537.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 4});
    // test_operations.fut:124:5-128:4
    if (memblock_alloc(ctx, &mem_38909, (int64_t) 32, "mem_38909")) {
        err = 1;
        goto cleanup;
    }
    // test_operations.fut:124:5-128:4
    
    struct memblock static_array_39538 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_39649, 0, "static_array_39538"};
    
    // test_operations.fut:124:5-128:4
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_38909.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_39538.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 4});
    // test_operations.fut:130:5-134:6
    if (memblock_alloc(ctx, &mem_38910, (int64_t) 40, "mem_38910")) {
        err = 1;
        goto cleanup;
    }
    // test_operations.fut:130:5-134:6
    
    struct memblock static_array_39539 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_39650, 0, "static_array_39539"};
    
    // test_operations.fut:130:5-134:6
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_38910.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_39539.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 5});
    // test_operations.fut:130:5-134:6
    if (memblock_alloc(ctx, &mem_38911, (int64_t) 40, "mem_38911")) {
        err = 1;
        goto cleanup;
    }
    // test_operations.fut:130:5-134:6
    
    struct memblock static_array_39540 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_39651, 0, "static_array_39540"};
    
    // test_operations.fut:130:5-134:6
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_38911.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_39540.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 5});
    // test_operations.fut:130:5-134:6
    if (memblock_alloc(ctx, &mem_38912, (int64_t) 40, "mem_38912")) {
        err = 1;
        goto cleanup;
    }
    // test_operations.fut:130:5-134:6
    
    struct memblock static_array_39541 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_39652, 0, "static_array_39541"};
    
    // test_operations.fut:130:5-134:6
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_38912.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_39541.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 5});
    // test_operations.fut:135:24-35
    if (memblock_alloc(ctx, &mem_38913, (int64_t) 16, "mem_38913")) {
        err = 1;
        goto cleanup;
    }
    // test_operations.fut:135:24-35
    
    struct memblock static_array_39542 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_39653, 0, "static_array_39542"};
    
    // test_operations.fut:135:24-35
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_38913.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_39542.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 2});
    if (memblock_alloc(ctx, &mem_38914, (int64_t) 32, "mem_38914")) {
        err = 1;
        goto cleanup;
    }
    
    struct memblock static_array_39543 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_39654, 0, "static_array_39543"};
    
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_38914.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_39543.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 4});
    if (memblock_alloc(ctx, &mem_38915, (int64_t) 88, "mem_38915")) {
        err = 1;
        goto cleanup;
    }
    
    struct memblock static_array_39544 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_39655, 0, "static_array_39544"};
    
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_38915.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_39544.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 11});
    if (memblock_alloc(ctx, &mem_38916, (int64_t) 88, "mem_38916")) {
        err = 1;
        goto cleanup;
    }
    
    struct memblock static_array_39545 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_39656, 0, "static_array_39545"};
    
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_38916.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_39545.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 11});
    if (memblock_alloc(ctx, &mem_38917, (int64_t) 88, "mem_38917")) {
        err = 1;
        goto cleanup;
    }
    
    struct memblock static_array_39546 = (struct memblock) {NULL, (unsigned char *) static_array_realtype_39657, 0, "static_array_39546"};
    
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_38917.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) static_array_39546.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 11});
    // ../lib/github.com/diku-dk/vtree/vtree.fut:224:13-33
    if (memblock_alloc(ctx, &mem_38918, (int64_t) 64, "mem_38918")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:224:13-33
    for (int64_t nest_i_39547 = 0; nest_i_39547 < (int64_t) 8; nest_i_39547++) {
        ((int64_t *) mem_38918.mem)[nest_i_39547] = (int64_t) 0;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:320:41-82
    if (memblock_alloc(ctx, &mem_38919, (int64_t) 32, "mem_38919")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:320:41-82
    for (int64_t nest_i_39548 = 0; nest_i_39548 < (int64_t) 4; nest_i_39548++) {
        ((int64_t *) mem_38919.mem)[nest_i_39548] = (int64_t) 0;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:319:39-65
    if (memblock_alloc(ctx, &mem_38920, (int64_t) 32, "mem_38920")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:319:39-65
    for (int64_t nest_i_39549 = 0; nest_i_39549 < (int64_t) 4; nest_i_39549++) {
        ((int64_t *) mem_38920.mem)[nest_i_39549] = (int64_t) 0;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:318:39-65
    if (memblock_alloc(ctx, &mem_38921, (int64_t) 32, "mem_38921")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:318:39-65
    for (int64_t nest_i_39550 = 0; nest_i_39550 < (int64_t) 4; nest_i_39550++) {
        ((int64_t *) mem_38921.mem)[nest_i_39550] = (int64_t) 0;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:136:24-36
    if (memblock_alloc(ctx, &mem_38922, (int64_t) 32, "mem_38922")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:136:24-36
    
    int64_t discard_38172;
    int64_t scanacc_38168 = (int64_t) 0;
    
    for (int64_t i_38170 = 0; i_38170 < (int64_t) 4; i_38170++) {
        // ../lib/github.com/diku-dk/vtree/vtree.fut:308:33-36
        
        int64_t defunc_0_op_res_29552 = add64((int64_t) 1, scanacc_38168);
        
        ((int64_t *) mem_38922.mem)[i_38170] = defunc_0_op_res_29552;
        
        int64_t scanacc_tmp_39551 = defunc_0_op_res_29552;
        
        scanacc_38168 = scanacc_tmp_39551;
    }
    discard_38172 = scanacc_38168;
    // ../lib/github.com/diku-dk/vtree/vtree.fut:224:13-33
    if (memblock_alloc(ctx, &mem_38929, (int64_t) 64, "mem_38929")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:224:13-33
    for (int64_t nest_i_39553 = 0; nest_i_39553 < (int64_t) 8; nest_i_39553++) {
        ((int64_t *) mem_38929.mem)[nest_i_39553] = (int64_t) 0;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:225:13-30
    if (memblock_alloc(ctx, &mem_38965, (int64_t) 32, "mem_38965")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:225:13-30
    if (memblock_alloc(ctx, &mem_38966, (int64_t) 32, "mem_38966")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:225:13-30
    if (memblock_alloc(ctx, &mem_38967, (int64_t) 32, "mem_38967")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:225:13-30
    if (memblock_alloc(ctx, &mem_38968, (int64_t) 32, "mem_38968")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:225:13-30
    if (memblock_alloc(ctx, &mem_38969, (int64_t) 32, "mem_38969")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:225:13-30
    if (memblock_alloc(ctx, &mem_38930, (int64_t) 32, "mem_38930")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:225:13-30
    if (memblock_alloc(ctx, &mem_38931, (int64_t) 32, "mem_38931")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:225:13-30
    if (memblock_alloc(ctx, &mem_38932, (int64_t) 32, "mem_38932")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:225:13-30
    if (memblock_alloc(ctx, &mem_38933, (int64_t) 32, "mem_38933")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:225:13-30
    if (memblock_alloc(ctx, &mem_38934, (int64_t) 32, "mem_38934")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:225:13-30
    
    int64_t defunc_res_30924;
    int64_t defunc_0_reduce_res_29178;
    bool acc_cert_29825;
    bool acc_cert_31260;
    bool acc_cert_31261;
    bool acc_cert_31262;
    bool acc_cert_33278;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:225:13-30
    
    int64_t discard_38201;
    int64_t discard_38202;
    int64_t discard_38203;
    int64_t discard_38204;
    int64_t defunc_res_35106;
    int64_t defunc_0_reduce_res_35107;
    int64_t scanacc_38178;
    int64_t scanacc_38179;
    int64_t scanacc_38180;
    int64_t scanacc_38181;
    int64_t redout_38186;
    int64_t redout_38187;
    
    scanacc_38178 = (int64_t) 0;
    scanacc_38179 = (int64_t) 0;
    scanacc_38180 = (int64_t) 0;
    scanacc_38181 = (int64_t) 0;
    redout_38186 = (int64_t) 0;
    redout_38187 = (int64_t) 0;
    for (int64_t i_38195 = 0; i_38195 < (int64_t) 4; i_38195++) {
        int64_t v_33669 = ((int64_t *) mem_38907.mem)[i_38195];
        int64_t v_33672 = ((int64_t *) mem_38909.mem)[i_38195];
        int64_t v_33674 = ((int64_t *) mem_38908.mem)[i_38195];
        int64_t eta_p_33677 = ((int64_t *) mem_38914.mem)[i_38195];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:305:55-93
        
        bool cond_33681 = slt64(eta_p_33677, (int64_t) 0);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:305:55-93
        
        int64_t lifted_lambda_res_33682;
        
        if (cond_33681) {
            lifted_lambda_res_33682 = (int64_t) 0;
        } else {
            // ../lib/github.com/diku-dk/vtree/vtree.fut:305:76-93
            
            bool x_33683 = sle64((int64_t) 0, eta_p_33677);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:305:76-93
            
            bool y_33684 = slt64(eta_p_33677, (int64_t) 2);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:305:76-93
            
            bool bounds_check_33685 = x_33683 && y_33684;
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:305:76-93
            
            bool index_certs_33686;
            
            if (!bounds_check_33685) {
                set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) eta_p_33677, "] out of bounds for array of shape [", (long long) (int64_t) 2, "].", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:305:76-93\n   #1  test_operations.fut:123:7-142:117\n"));
                err = FUTHARK_PROGRAM_ERROR;
                goto cleanup;
            }
            // ../lib/github.com/diku-dk/vtree/vtree.fut:305:76-93
            
            int64_t lifted_lambda_res_f_res_33687 = ((int64_t *) mem_38913.mem)[eta_p_33677];
            
            lifted_lambda_res_33682 = lifted_lambda_res_f_res_33687;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:307:41-45
        
        int64_t lifted_lambda_res_33688 = add64((int64_t) 1, lifted_lambda_res_33682);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:225:13-30
        // UpdateAcc
        if (sle64((int64_t) 0, v_33669) && slt64(v_33669, (int64_t) 8)) {
            ((int64_t *) mem_38929.mem)[v_33669] = lifted_lambda_res_33682;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:136:11-36
        
        int64_t zv_lhs_33692 = add64((int64_t) -1, i_38195);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:136:11-36
        
        int64_t tmp_33693 = smod64(zv_lhs_33692, (int64_t) 4);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:136:11-36
        
        int64_t lifted_lambda_res_33694 = ((int64_t *) mem_38922.mem)[tmp_33693];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:134:19-43
        
        bool cond_33695 = i_38195 == (int64_t) 0;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:134:19-43
        
        int64_t lifted_lambda_res_33696;
        
        if (cond_33695) {
            lifted_lambda_res_33696 = (int64_t) 0;
        } else {
            lifted_lambda_res_33696 = lifted_lambda_res_33694;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:320:32-115
        // UpdateAcc
        if (sle64((int64_t) 0, lifted_lambda_res_33696) && slt64(lifted_lambda_res_33696, (int64_t) 4)) {
            ((int64_t *) mem_38919.mem)[lifted_lambda_res_33696] = v_33672;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:319:30-96
        // UpdateAcc
        if (sle64((int64_t) 0, lifted_lambda_res_33696) && slt64(lifted_lambda_res_33696, (int64_t) 4)) {
            ((int64_t *) mem_38920.mem)[lifted_lambda_res_33696] = v_33674;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:318:30-96
        // UpdateAcc
        if (sle64((int64_t) 0, lifted_lambda_res_33696) && slt64(lifted_lambda_res_33696, (int64_t) 4)) {
            ((int64_t *) mem_38921.mem)[lifted_lambda_res_33696] = v_33669;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:225:13-30
        // UpdateAcc
        if (sle64((int64_t) 0, v_33669) && slt64(v_33669, (int64_t) 8)) {
            ((int64_t *) mem_38918.mem)[v_33669] = (int64_t) 0;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:308:33-36
        
        int64_t defunc_0_op_res_33301 = add64(lifted_lambda_res_33688, scanacc_38178);
        
        // ../lib/github.com/diku-dk/segmented/segmented.fut:45:22-25
        
        int64_t defunc_0_op_res_33304 = add64(lifted_lambda_res_33682, scanacc_38179);
        
        // ../lib/github.com/diku-dk/segmented/segmented.fut:45:22-25
        
        int64_t defunc_0_op_res_33307 = add64(lifted_lambda_res_33682, scanacc_38180);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:306:68-71
        
        int64_t defunc_0_op_res_33331 = add64(lifted_lambda_res_33682, scanacc_38181);
        
        // ../lib/github.com/diku-dk/segmented/segmented.fut:46:18-30
        
        int64_t zp_res_33310 = add64(lifted_lambda_res_33682, redout_38186);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:310:34-37
        
        int64_t defunc_0_op_res_33313 = add64(lifted_lambda_res_33682, redout_38187);
        
        ((int64_t *) mem_38930.mem)[i_38195] = defunc_0_op_res_33301;
        ((int64_t *) mem_38931.mem)[i_38195] = defunc_0_op_res_33304;
        ((int64_t *) mem_38932.mem)[i_38195] = defunc_0_op_res_33307;
        ((int64_t *) mem_38933.mem)[i_38195] = defunc_0_op_res_33331;
        ((int64_t *) mem_38934.mem)[i_38195] = lifted_lambda_res_33696;
        
        int64_t scanacc_tmp_39554 = defunc_0_op_res_33301;
        int64_t scanacc_tmp_39555 = defunc_0_op_res_33304;
        int64_t scanacc_tmp_39556 = defunc_0_op_res_33307;
        int64_t scanacc_tmp_39557 = defunc_0_op_res_33331;
        int64_t redout_tmp_39562 = zp_res_33310;
        int64_t redout_tmp_39563 = defunc_0_op_res_33313;
        
        scanacc_38178 = scanacc_tmp_39554;
        scanacc_38179 = scanacc_tmp_39555;
        scanacc_38180 = scanacc_tmp_39556;
        scanacc_38181 = scanacc_tmp_39557;
        redout_38186 = redout_tmp_39562;
        redout_38187 = redout_tmp_39563;
    }
    discard_38201 = scanacc_38178;
    discard_38202 = scanacc_38179;
    discard_38203 = scanacc_38180;
    discard_38204 = scanacc_38181;
    defunc_res_35106 = redout_38186;
    defunc_0_reduce_res_35107 = redout_38187;
    // ../lib/github.com/diku-dk/vtree/vtree.fut:225:13-30
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_38965.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) mem_38930.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 4});
    // ../lib/github.com/diku-dk/vtree/vtree.fut:225:13-30
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_38966.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) mem_38931.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 4});
    // ../lib/github.com/diku-dk/vtree/vtree.fut:225:13-30
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_38967.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) mem_38932.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 4});
    defunc_res_30924 = defunc_res_35106;
    defunc_0_reduce_res_29178 = defunc_0_reduce_res_35107;
    // ../lib/github.com/diku-dk/vtree/vtree.fut:225:13-30
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_38968.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) mem_38933.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 4});
    // ../lib/github.com/diku-dk/vtree/vtree.fut:225:13-30
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_38969.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) mem_38934.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 4});
    if (memblock_unref(ctx, &mem_38922, "mem_38922") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38930, "mem_38930") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38931, "mem_38931") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38932, "mem_38932") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38933, "mem_38933") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38934, "mem_38934") != 0)
        return 1;
    // ../lib/github.com/diku-dk/vtree/vtree.fut:136:24-36
    if (memblock_alloc(ctx, &mem_38970, (int64_t) 32, "mem_38970")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:136:24-36
    for (int64_t i_38208 = 0; i_38208 < (int64_t) 4; i_38208++) {
        ((int64_t *) mem_38970.mem)[i_38208] = (int64_t) 0;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:316:10-339:87
    if (memblock_alloc(ctx, &mem_38977, (int64_t) 32, "mem_38977")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:316:10-339:87
    for (int64_t i_38216 = 0; i_38216 < (int64_t) 4; i_38216++) {
        // ../lib/github.com/diku-dk/vtree/vtree.fut:136:11-36
        
        int64_t zv_lhs_33414 = add64((int64_t) -1, i_38216);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:136:11-36
        
        int64_t tmp_33415 = smod64(zv_lhs_33414, (int64_t) 4);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:136:11-36
        
        int64_t lifted_lambda_res_33416 = ((int64_t *) mem_38970.mem)[tmp_33415];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:134:19-43
        
        bool cond_33418 = i_38216 == (int64_t) 0;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:134:19-43
        
        int64_t lifted_lambda_res_33419;
        
        if (cond_33418) {
            lifted_lambda_res_33419 = (int64_t) 0;
        } else {
            lifted_lambda_res_33419 = lifted_lambda_res_33416;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:339:33-37
        
        int64_t lifted_lambda_res_33421 = mul64((int64_t) 2, lifted_lambda_res_33419);
        
        ((int64_t *) mem_38977.mem)[i_38216] = lifted_lambda_res_33421;
    }
    if (memblock_unref(ctx, &mem_38970, "mem_38970") != 0)
        return 1;
    // ../lib/github.com/diku-dk/vtree/vtree.fut:328:33-64
    if (memblock_alloc(ctx, &mem_38984, defunc_0_reduce_res_29178, "mem_38984")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:328:33-64
    for (int64_t nest_i_39572 = 0; nest_i_39572 < defunc_0_reduce_res_29178; nest_i_39572++) {
        ((bool *) mem_38984.mem)[nest_i_39572] = 0;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:311:25-42
    
    int64_t result_sizze_29183 = add64((int64_t) 4, defunc_0_reduce_res_29178);
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:320:41-82
    
    int64_t bytes_38985 = (int64_t) 8 * result_sizze_29183;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:320:41-82
    if (memblock_alloc(ctx, &mem_38986, bytes_38985, "mem_38986")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:320:41-82
    for (int64_t nest_i_39573 = 0; nest_i_39573 < result_sizze_29183; nest_i_39573++) {
        ((int64_t *) mem_38986.mem)[nest_i_39573] = (int64_t) 0;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:319:39-65
    if (memblock_alloc(ctx, &mem_38988, bytes_38985, "mem_38988")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:319:39-65
    for (int64_t nest_i_39574 = 0; nest_i_39574 < result_sizze_29183; nest_i_39574++) {
        ((int64_t *) mem_38988.mem)[nest_i_39574] = (int64_t) 0;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:318:39-65
    if (memblock_alloc(ctx, &mem_38990, bytes_38985, "mem_38990")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:318:39-65
    for (int64_t nest_i_39575 = 0; nest_i_39575 < result_sizze_29183; nest_i_39575++) {
        ((int64_t *) mem_38990.mem)[nest_i_39575] = (int64_t) 0;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:314:24-50
    if (memblock_alloc(ctx, &mem_38991, result_sizze_29183, "mem_38991")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:314:24-50
    for (int64_t nest_i_39576 = 0; nest_i_39576 < result_sizze_29183; nest_i_39576++) {
        ((bool *) mem_38991.mem)[nest_i_39576] = 1;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:335:28-112
    if (memblock_alloc(ctx, &mem_39006, (int64_t) 32, "mem_39006")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:335:28-112
    if (memblock_alloc(ctx, &mem_39007, (int64_t) 32, "mem_39007")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:315:24-339:87
    if (memblock_alloc(ctx, &mem_38992, (int64_t) 32, "mem_38992")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:315:24-339:87
    if (memblock_alloc(ctx, &mem_38993, (int64_t) 32, "mem_38993")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:335:28-112
    
    bool acc_cert_32714;
    bool acc_cert_32715;
    bool acc_cert_32716;
    bool acc_cert_32717;
    bool acc_cert_32877;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:315:24-339:87
    for (int64_t i_38229 = 0; i_38229 < (int64_t) 4; i_38229++) {
        int64_t v_33731 = ((int64_t *) mem_38909.mem)[i_38229];
        int64_t v_33733 = ((int64_t *) mem_38908.mem)[i_38229];
        int64_t v_33735 = ((int64_t *) mem_38907.mem)[i_38229];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:136:11-36
        
        int64_t zv_lhs_33739 = add64((int64_t) -1, i_38229);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:136:11-36
        
        int64_t tmp_33740 = smod64(zv_lhs_33739, (int64_t) 4);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:136:11-36
        
        int64_t lifted_lambda_res_33741 = ((int64_t *) mem_38968.mem)[tmp_33740];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:134:19-43
        
        bool cond_33742 = i_38229 == (int64_t) 0;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:134:19-43
        
        int64_t lifted_lambda_res_33743;
        
        if (cond_33742) {
            lifted_lambda_res_33743 = (int64_t) 0;
        } else {
            lifted_lambda_res_33743 = lifted_lambda_res_33741;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:339:33-37
        
        int64_t lifted_lambda_res_33744 = mul64((int64_t) 2, lifted_lambda_res_33743);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:328:24-133
        // UpdateAcc
        if (sle64((int64_t) 0, lifted_lambda_res_33743) && slt64(lifted_lambda_res_33743, defunc_0_reduce_res_29178)) {
            ((bool *) mem_38984.mem)[lifted_lambda_res_33743] = 1;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:136:11-36
        
        int64_t lifted_lambda_res_33752 = ((int64_t *) mem_38965.mem)[tmp_33740];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:134:19-43
        
        int64_t lifted_lambda_res_33754;
        
        if (cond_33742) {
            lifted_lambda_res_33754 = (int64_t) 0;
        } else {
            lifted_lambda_res_33754 = lifted_lambda_res_33752;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:320:32-115
        // UpdateAcc
        if (sle64((int64_t) 0, lifted_lambda_res_33754) && slt64(lifted_lambda_res_33754, result_sizze_29183)) {
            ((int64_t *) mem_38986.mem)[lifted_lambda_res_33754] = v_33731;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:319:30-96
        // UpdateAcc
        if (sle64((int64_t) 0, lifted_lambda_res_33754) && slt64(lifted_lambda_res_33754, result_sizze_29183)) {
            ((int64_t *) mem_38988.mem)[lifted_lambda_res_33754] = v_33733;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:318:30-96
        // UpdateAcc
        if (sle64((int64_t) 0, lifted_lambda_res_33754) && slt64(lifted_lambda_res_33754, result_sizze_29183)) {
            ((int64_t *) mem_38990.mem)[lifted_lambda_res_33754] = v_33735;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:315:24-76
        // UpdateAcc
        if (sle64((int64_t) 0, lifted_lambda_res_33754) && slt64(lifted_lambda_res_33754, result_sizze_29183)) {
            ((bool *) mem_38991.mem)[lifted_lambda_res_33754] = 0;
        }
        ((int64_t *) mem_38992.mem)[i_38229] = lifted_lambda_res_33754;
        ((int64_t *) mem_38993.mem)[i_38229] = lifted_lambda_res_33744;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:335:28-112
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_39006.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) mem_38993.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 4});
    // ../lib/github.com/diku-dk/vtree/vtree.fut:335:28-112
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_39007.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) mem_38992.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 4});
    if (memblock_unref(ctx, &mem_38965, "mem_38965") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38968, "mem_38968") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38992, "mem_38992") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38993, "mem_38993") != 0)
        return 1;
    // ../lib/github.com/diku-dk/vtree/vtree.fut:316:10-56
    if (memblock_alloc(ctx, &mem_39009, bytes_38985, "mem_39009")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:316:10-56
    if (memblock_alloc(ctx, &mem_39011, bytes_38985, "mem_39011")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:316:10-56
    
    int64_t discard_38242;
    int64_t scanacc_38236 = (int64_t) 0;
    
    for (int64_t i_38239 = 0; i_38239 < result_sizze_29183; i_38239++) {
        // ../lib/github.com/diku-dk/vtree/vtree.fut:316:24-37
        
        bool lifted_lambda_res_32515 = ((bool *) mem_38991.mem)[i_38239];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:316:10-56
        
        int64_t defunc_0_f_res_32516 = btoi_bool_i64(lifted_lambda_res_32515);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:316:10-56
        
        int64_t defunc_0_op_res_29205 = add64(defunc_0_f_res_32516, scanacc_38236);
        
        ((int64_t *) mem_39009.mem)[i_38239] = defunc_0_op_res_29205;
        ((int64_t *) mem_39011.mem)[i_38239] = defunc_0_f_res_32516;
        
        int64_t scanacc_tmp_39584 = defunc_0_op_res_29205;
        
        scanacc_38236 = scanacc_tmp_39584;
    }
    discard_38242 = scanacc_38236;
    if (memblock_unref(ctx, &mem_38991, "mem_38991") != 0)
        return 1;
    // ../lib/github.com/diku-dk/vtree/vtree.fut:316:10-56
    
    bool cond_29206 = result_sizze_29183 == (int64_t) 0;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:316:10-56
    
    bool x_29207 = !cond_29206;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:316:10-56
    
    int64_t tmp_29208 = sub64(result_sizze_29183, (int64_t) 1);
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:316:10-56
    
    bool x_29209 = sle64((int64_t) 0, tmp_29208);
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:316:10-56
    
    bool y_29210 = slt64(tmp_29208, result_sizze_29183);
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:316:10-56
    
    bool bounds_check_29211 = x_29209 && y_29210;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:316:10-56
    
    bool protect_assert_disj_29212 = cond_29206 || bounds_check_29211;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:316:10-56
    
    bool index_certs_29213;
    
    if (!protect_assert_disj_29212) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) tmp_29208, "] out of bounds for array of shape [", (long long) result_sizze_29183, "].", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:316:10-56\n   #1  test_operations.fut:123:7-142:117\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:316:10-56
    
    int64_t m_f_res_29214;
    
    if (x_29207) {
        // ../lib/github.com/diku-dk/vtree/vtree.fut:316:10-56
        
        int64_t x_35128 = ((int64_t *) mem_39009.mem)[tmp_29208];
        
        m_f_res_29214 = x_35128;
    } else {
        m_f_res_29214 = (int64_t) 0;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:316:10-56
    
    int64_t m_29216;
    
    if (cond_29206) {
        m_29216 = (int64_t) 0;
    } else {
        m_29216 = m_f_res_29214;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:316:10-56
    
    int64_t bytes_39024 = (int64_t) 8 * m_29216;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:316:10-56
    if (memblock_alloc(ctx, &mem_39025, bytes_39024, "mem_39025")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:316:10-56
    
    bool acc_cert_32481;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:316:10-56
    for (int64_t i_38244 = 0; i_38244 < result_sizze_29183; i_38244++) {
        int64_t eta_p_32496 = ((int64_t *) mem_39011.mem)[i_38244];
        int64_t eta_p_32497 = ((int64_t *) mem_39009.mem)[i_38244];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:316:10-56
        
        bool cond_32500 = eta_p_32496 == (int64_t) 1;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:316:10-56
        
        int64_t lifted_lambda_res_32501;
        
        if (cond_32500) {
            // ../lib/github.com/diku-dk/vtree/vtree.fut:316:10-56
            
            int64_t lifted_lambda_res_t_res_35129 = sub64(eta_p_32497, (int64_t) 1);
            
            lifted_lambda_res_32501 = lifted_lambda_res_t_res_35129;
        } else {
            lifted_lambda_res_32501 = (int64_t) -1;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:316:10-56
        // UpdateAcc
        if (sle64((int64_t) 0, lifted_lambda_res_32501) && slt64(lifted_lambda_res_32501, m_29216)) {
            ((int64_t *) mem_39025.mem)[lifted_lambda_res_32501] = i_38244;
        }
    }
    if (memblock_unref(ctx, &mem_39009, "mem_39009") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_39011, "mem_39011") != 0)
        return 1;
    
    bool eq_x_y_29895 = defunc_0_reduce_res_29178 == (int64_t) 0;
    bool eq_x_zz_29896 = defunc_0_reduce_res_29178 == m_f_res_29214;
    bool p_and_eq_x_y_29897 = cond_29206 && eq_x_y_29895;
    bool p_and_eq_x_y_29899 = x_29207 && eq_x_zz_29896;
    bool dim_match_29232 = p_and_eq_x_y_29897 || p_and_eq_x_y_29899;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:316:61-66
    
    bool empty_or_match_cert_29233;
    
    if (!dim_match_29232) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (desugared) shape [", (long long) m_29216, "] cannot match shape of type \"[", (long long) defunc_0_reduce_res_29178, "]i64\".", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:316:61-66\n   #1  test_operations.fut:123:7-142:117\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:136:24-36
    if (memblock_alloc(ctx, &mem_39026, (int64_t) 16, "mem_39026")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:136:24-36
    
    int64_t discard_38250;
    int64_t scanacc_38246 = (int64_t) 0;
    
    for (int64_t i_38248 = 0; i_38248 < (int64_t) 2; i_38248++) {
        int64_t x_29307 = ((int64_t *) mem_38913.mem)[i_38248];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:331:36-39
        
        int64_t defunc_0_op_res_29310 = add64(x_29307, scanacc_38246);
        
        ((int64_t *) mem_39026.mem)[i_38248] = defunc_0_op_res_29310;
        
        int64_t scanacc_tmp_39588 = defunc_0_op_res_29310;
        
        scanacc_38246 = scanacc_tmp_39588;
    }
    discard_38250 = scanacc_38246;
    if (memblock_unref(ctx, &mem_38913, "mem_38913") != 0)
        return 1;
    // ../lib/github.com/diku-dk/vtree/vtree.fut:134:5-136:37
    if (memblock_alloc(ctx, &mem_39033, (int64_t) 16, "mem_39033")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:134:5-136:37
    for (int64_t i_38253 = 0; i_38253 < (int64_t) 2; i_38253++) {
        // ../lib/github.com/diku-dk/vtree/vtree.fut:136:11-36
        
        int64_t zv_lhs_31867 = add64((int64_t) -1, i_38253);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:136:11-36
        
        int64_t tmp_31868 = smod64(zv_lhs_31867, (int64_t) 2);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:136:11-36
        
        int64_t lifted_lambda_res_31869 = ((int64_t *) mem_39026.mem)[tmp_31868];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:134:19-43
        
        bool cond_31871 = i_38253 == (int64_t) 0;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:134:19-43
        
        int64_t lifted_lambda_res_31872;
        
        if (cond_31871) {
            lifted_lambda_res_31872 = (int64_t) 0;
        } else {
            lifted_lambda_res_31872 = lifted_lambda_res_31869;
        }
        ((int64_t *) mem_39033.mem)[i_38253] = lifted_lambda_res_31872;
    }
    if (memblock_unref(ctx, &mem_39026, "mem_39026") != 0)
        return 1;
    // ../lib/github.com/diku-dk/vtree/vtree.fut:330:99-104
    
    bool dim_match_29303 = defunc_0_reduce_res_29178 == defunc_res_30924;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:330:99-104
    
    bool empty_or_match_cert_29304;
    
    if (!dim_match_29303) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (desugared) shape [", (long long) defunc_res_30924, "] cannot match shape of type \"[", (long long) defunc_0_reduce_res_29178, "]i64\".", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:330:99-104\n   #1  test_operations.fut:123:7-142:117\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/segmented/segmented.fut:46:6-54
    
    bool bounds_invalid_upwards_29281 = slt64(defunc_res_30924, (int64_t) 0);
    
    // ../lib/github.com/diku-dk/segmented/segmented.fut:46:6-54
    
    bool valid_29282 = !bounds_invalid_upwards_29281;
    
    // ../lib/github.com/diku-dk/segmented/segmented.fut:46:6-54
    
    bool range_valid_c_29283;
    
    if (!valid_29282) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s%lld%s\n\nBacktrace:\n%s", "Range ", (long long) (int64_t) 0, "..", (long long) (int64_t) 1, "..<", (long long) defunc_res_30924, " is invalid.", "-> #0  ../lib/github.com/diku-dk/segmented/segmented.fut:46:6-54\n   #1  ../lib/github.com/diku-dk/vtree/vtree.fut:323:18-38\n   #2  ../lib/github.com/diku-dk/vtree/vtree.fut:330:47-95\n   #3  test_operations.fut:123:7-142:117\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/segmented/segmented.fut:46:6-54
    
    int64_t bytes_39040 = (int64_t) 8 * defunc_res_30924;
    
    // ../lib/github.com/diku-dk/segmented/segmented.fut:46:6-54
    if (memblock_alloc(ctx, &mem_39041, bytes_39040, "mem_39041")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/segmented/segmented.fut:46:6-54
    for (int64_t nest_i_39591 = 0; nest_i_39591 < defunc_res_30924; nest_i_39591++) {
        ((int64_t *) mem_39041.mem)[nest_i_39591] = (int64_t) 0;
    }
    // ../lib/github.com/diku-dk/segmented/segmented.fut:46:6-54
    if (memblock_alloc(ctx, &mem_39043, bytes_39040, "mem_39043")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/segmented/segmented.fut:46:6-54
    for (int64_t nest_i_39592 = 0; nest_i_39592 < defunc_res_30924; nest_i_39592++) {
        ((int64_t *) mem_39043.mem)[nest_i_39592] = (int64_t) 0;
    }
    // ../lib/github.com/diku-dk/segmented/segmented.fut:46:6-54
    for (int64_t iter_38255 = 0; iter_38255 < (int64_t) 4; iter_38255++) {
        int64_t pixel_38258 = ((int64_t *) mem_38966.mem)[iter_38255];
        int64_t pixel_38260 = ((int64_t *) mem_38967.mem)[iter_38255];
        bool less_than_zzero_38262 = slt64(pixel_38258, (int64_t) 0);
        bool greater_than_sizze_38263 = sle64(defunc_res_30924, pixel_38258);
        bool outside_bounds_dim_38264 = less_than_zzero_38262 || greater_than_sizze_38263;
        
        if (!outside_bounds_dim_38264) {
            int64_t read_hist_38266 = ((int64_t *) mem_39041.mem)[pixel_38258];
            
            // ../lib/github.com/diku-dk/segmented/segmented.fut:46:11-14
            
            int64_t defunc_0_op_res_29412 = add64((int64_t) 1, read_hist_38266);
            
            ((int64_t *) mem_39041.mem)[pixel_38258] = defunc_0_op_res_29412;
        }
        
        bool less_than_zzero_38269 = slt64(pixel_38260, (int64_t) 0);
        bool greater_than_sizze_38270 = sle64(defunc_res_30924, pixel_38260);
        bool outside_bounds_dim_38271 = less_than_zzero_38269 || greater_than_sizze_38270;
        
        if (!outside_bounds_dim_38271) {
            int64_t read_hist_38273 = ((int64_t *) mem_39043.mem)[pixel_38260];
            
            // ../lib/github.com/diku-dk/segmented/segmented.fut:46:11-14
            
            int64_t defunc_0_op_res_29288 = add64((int64_t) 1, read_hist_38273);
            
            ((int64_t *) mem_39043.mem)[pixel_38260] = defunc_0_op_res_29288;
        }
    }
    if (memblock_unref(ctx, &mem_38966, "mem_38966") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38967, "mem_38967") != 0)
        return 1;
    // ../lib/github.com/diku-dk/vtree/vtree.fut:324:10-32
    if (memblock_alloc(ctx, &mem_39057, bytes_39040, "mem_39057")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:324:10-32
    
    int64_t inpacc_35345;
    int64_t inpacc_31904 = (int64_t) 0;
    
    for (int64_t i_38288 = 0; i_38288 < defunc_res_30924; i_38288++) {
        int64_t x_38748 = ((int64_t *) mem_39043.mem)[i_38288];
        
        // ../lib/github.com/diku-dk/segmented/segmented.fut:47:11-14
        
        int64_t defunc_0_op_res_38756 = add64(inpacc_31904, x_38748);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:324:21-26
        
        bool x_38757 = sle64((int64_t) 0, defunc_0_op_res_38756);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:324:21-26
        
        bool y_38758 = slt64(defunc_0_op_res_38756, (int64_t) 4);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:324:21-26
        
        bool bounds_check_38759 = x_38757 && y_38758;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:324:21-26
        
        bool index_certs_38760;
        
        if (!bounds_check_38759) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) defunc_0_op_res_38756, "] out of bounds for array of shape [", (long long) (int64_t) 4, "].", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:324:21-26\n   #1  ../lib/github.com/diku-dk/vtree/vtree.fut:330:47-95\n   #2  test_operations.fut:123:7-142:117\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:324:21-26
        
        int64_t lifted_lambda_res_38761 = ((int64_t *) mem_38914.mem)[defunc_0_op_res_38756];
        
        ((int64_t *) mem_39057.mem)[i_38288] = lifted_lambda_res_38761;
        
        int64_t inpacc_tmp_39595 = defunc_0_op_res_38756;
        
        inpacc_31904 = inpacc_tmp_39595;
    }
    inpacc_35345 = inpacc_31904;
    if (memblock_unref(ctx, &mem_38914, "mem_38914") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_39043, "mem_39043") != 0)
        return 1;
    // ../lib/github.com/diku-dk/vtree/vtree.fut:335:28-112
    
    int64_t bytes_39080 = (int64_t) 8 * defunc_0_reduce_res_29178;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:335:28-112
    if (memblock_alloc(ctx, &mem_39081, bytes_39080, "mem_39081")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:335:28-112
    if (memblock_alloc(ctx, &mem_39083, bytes_39080, "mem_39083")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:332:26-337:118
    if (memblock_alloc(ctx, &mem_39065, bytes_39080, "mem_39065")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:332:26-337:118
    if (memblock_alloc(ctx, &mem_39067, bytes_39080, "mem_39067")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:335:28-112
    
    bool acc_cert_32022;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:332:26-337:118
    
    int64_t inpacc_35144;
    int64_t inpacc_32158 = (int64_t) 0;
    
    for (int64_t i_38344 = 0; i_38344 < defunc_0_reduce_res_29178; i_38344++) {
        bool x_38693 = ((bool *) mem_38984.mem)[i_38344];
        int64_t eta_p_38716 = ((int64_t *) mem_39057.mem)[i_38344];
        int64_t v_38718 = ((int64_t *) mem_39025.mem)[i_38344];
        
        // ../lib/github.com/diku-dk/segmented/segmented.fut:11:18-48
        
        int64_t tmp_38720;
        
        if (x_38693) {
            tmp_38720 = (int64_t) 1;
        } else {
            // ../lib/github.com/diku-dk/segmented/segmented.fut:56:30-33
            
            int64_t defunc_0_op_res_38721 = add64((int64_t) 1, inpacc_32158);
            
            tmp_38720 = defunc_0_op_res_38721;
        }
        // ../lib/github.com/diku-dk/segmented/segmented.fut:57:18-20
        
        int64_t lifted_lambda_res_38722 = sub64(tmp_38720, (int64_t) 1);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:332:37-55
        
        bool x_38723 = sle64((int64_t) 0, eta_p_38716);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:332:37-55
        
        bool y_38724 = slt64(eta_p_38716, (int64_t) 2);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:332:37-55
        
        bool bounds_check_38725 = x_38723 && y_38724;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:332:37-55
        
        bool index_certs_38726;
        
        if (!bounds_check_38725) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) eta_p_38716, "] out of bounds for array of shape [", (long long) (int64_t) 2, "].", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:332:37-55\n   #1  test_operations.fut:123:7-142:117\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:332:37-55
        
        int64_t lifted_lambda_res_38727 = ((int64_t *) mem_39033.mem)[eta_p_38716];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:333:15-18
        
        int64_t defunc_0_f_res_38728 = add64(lifted_lambda_res_38722, lifted_lambda_res_38727);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:335:81-95
        
        bool x_38729 = sle64((int64_t) 0, defunc_0_f_res_38728);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:335:81-95
        
        bool y_38730 = slt64(defunc_0_f_res_38728, (int64_t) 5);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:335:81-95
        
        bool bounds_check_38731 = x_38729 && y_38730;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:335:81-95
        
        bool index_certs_38732;
        
        if (!bounds_check_38731) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) defunc_0_f_res_38728, "] out of bounds for array of shape [", (long long) (int64_t) 5, "].", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:335:81-95\n   #1  test_operations.fut:123:7-142:117\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:335:81-95
        
        int64_t lifted_lambda_res_38733 = ((int64_t *) mem_38910.mem)[defunc_0_f_res_38728];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:335:28-112
        // UpdateAcc
        if (sle64((int64_t) 0, v_38718) && slt64(v_38718, result_sizze_29183)) {
            ((int64_t *) mem_38990.mem)[v_38718] = lifted_lambda_res_38733;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:337:85-101
        
        int64_t lifted_lambda_res_38735 = ((int64_t *) mem_38912.mem)[defunc_0_f_res_38728];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:336:81-95
        
        int64_t lifted_lambda_res_38736 = ((int64_t *) mem_38911.mem)[defunc_0_f_res_38728];
        
        // ../lib/github.com/diku-dk/segmented/segmented.fut:11:18-48
        
        int64_t tmp_32195;
        
        if (x_38693) {
            tmp_32195 = (int64_t) 1;
        } else {
            // ../lib/github.com/diku-dk/segmented/segmented.fut:56:30-33
            
            int64_t defunc_0_op_res_32196 = add64((int64_t) 1, inpacc_32158);
            
            tmp_32195 = defunc_0_op_res_32196;
        }
        ((int64_t *) mem_39065.mem)[i_38344] = lifted_lambda_res_38736;
        ((int64_t *) mem_39067.mem)[i_38344] = lifted_lambda_res_38735;
        
        int64_t inpacc_tmp_39597 = tmp_32195;
        
        inpacc_32158 = inpacc_tmp_39597;
    }
    inpacc_35144 = inpacc_32158;
    // ../lib/github.com/diku-dk/vtree/vtree.fut:335:28-112
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_39081.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) mem_39067.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {defunc_0_reduce_res_29178});
    // ../lib/github.com/diku-dk/vtree/vtree.fut:335:28-112
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_39083.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) mem_39065.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {defunc_0_reduce_res_29178});
    if (memblock_unref(ctx, &mem_38910, "mem_38910") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38911, "mem_38911") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38912, "mem_38912") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38984, "mem_38984") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_39033, "mem_39033") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_39057, "mem_39057") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_39065, "mem_39065") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_39067, "mem_39067") != 0)
        return 1;
    // test_operations.fut:144:5-147:62
    
    bool cond_17840 = result_sizze_29183 == (int64_t) 11;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:353:39-65
    if (memblock_alloc(ctx, &mem_39084, (int64_t) 32, "mem_39084")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:353:39-65
    for (int64_t nest_i_39601 = 0; nest_i_39601 < (int64_t) 4; nest_i_39601++) {
        ((int64_t *) mem_39084.mem)[nest_i_39601] = (int64_t) 0;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:340:39-65
    if (memblock_alloc(ctx, &mem_39085, (int64_t) 32, "mem_39085")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:340:39-65
    for (int64_t nest_i_39602 = 0; nest_i_39602 < (int64_t) 4; nest_i_39602++) {
        ((int64_t *) mem_39085.mem)[nest_i_39602] = (int64_t) 0;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:353:39-65
    if (memblock_alloc(ctx, &mem_39087, bytes_38985, "mem_39087")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:353:39-65
    for (int64_t nest_i_39603 = 0; nest_i_39603 < result_sizze_29183; nest_i_39603++) {
        ((int64_t *) mem_39087.mem)[nest_i_39603] = (int64_t) 0;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:136:24-36
    if (memblock_alloc(ctx, &mem_39088, (int64_t) 64, "mem_39088")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:136:24-36
    
    int64_t discard_38358;
    int64_t scanacc_38354 = (int64_t) 0;
    
    for (int64_t i_38356 = 0; i_38356 < (int64_t) 8; i_38356++) {
        int64_t x_29833 = ((int64_t *) mem_38918.mem)[i_38356];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:350:67-70
        
        int64_t defunc_0_op_res_29836 = add64(x_29833, scanacc_38354);
        
        ((int64_t *) mem_39088.mem)[i_38356] = defunc_0_op_res_29836;
        
        int64_t scanacc_tmp_39604 = defunc_0_op_res_29836;
        
        scanacc_38354 = scanacc_tmp_39604;
    }
    discard_38358 = scanacc_38354;
    if (memblock_unref(ctx, &mem_38918, "mem_38918") != 0)
        return 1;
    // ../lib/github.com/diku-dk/vtree/vtree.fut:136:24-36
    if (memblock_alloc(ctx, &mem_39095, (int64_t) 64, "mem_39095")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:136:24-36
    
    int64_t discard_38364;
    int64_t scanacc_38360 = (int64_t) 0;
    
    for (int64_t i_38362 = 0; i_38362 < (int64_t) 8; i_38362++) {
        int64_t x_29447 = ((int64_t *) mem_38929.mem)[i_38362];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:350:67-70
        
        int64_t defunc_0_op_res_29450 = add64(x_29447, scanacc_38360);
        
        ((int64_t *) mem_39095.mem)[i_38362] = defunc_0_op_res_29450;
        
        int64_t scanacc_tmp_39606 = defunc_0_op_res_29450;
        
        scanacc_38360 = scanacc_tmp_39606;
    }
    discard_38364 = scanacc_38360;
    if (memblock_unref(ctx, &mem_38929, "mem_38929") != 0)
        return 1;
    // ../lib/github.com/diku-dk/vtree/vtree.fut:134:5-136:37
    if (memblock_alloc(ctx, &mem_39102, (int64_t) 64, "mem_39102")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:134:5-136:37
    if (memblock_alloc(ctx, &mem_39103, (int64_t) 64, "mem_39103")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:134:5-136:37
    for (int64_t i_38369 = 0; i_38369 < (int64_t) 8; i_38369++) {
        // ../lib/github.com/diku-dk/vtree/vtree.fut:136:11-36
        
        int64_t zv_lhs_33396 = add64((int64_t) -1, i_38369);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:136:11-36
        
        int64_t tmp_33397 = smod64(zv_lhs_33396, (int64_t) 8);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:136:11-36
        
        int64_t lifted_lambda_res_33398 = ((int64_t *) mem_39095.mem)[tmp_33397];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:134:19-43
        
        bool cond_33400 = i_38369 == (int64_t) 0;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:134:19-43
        
        int64_t lifted_lambda_res_33401;
        
        if (cond_33400) {
            lifted_lambda_res_33401 = (int64_t) 0;
        } else {
            lifted_lambda_res_33401 = lifted_lambda_res_33398;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:136:11-36
        
        int64_t lifted_lambda_res_33406 = ((int64_t *) mem_39088.mem)[tmp_33397];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:134:19-43
        
        int64_t lifted_lambda_res_33409;
        
        if (cond_33400) {
            lifted_lambda_res_33409 = (int64_t) 0;
        } else {
            lifted_lambda_res_33409 = lifted_lambda_res_33406;
        }
        ((int64_t *) mem_39102.mem)[i_38369] = lifted_lambda_res_33409;
        ((int64_t *) mem_39103.mem)[i_38369] = lifted_lambda_res_33401;
    }
    if (memblock_unref(ctx, &mem_39088, "mem_39088") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_39095, "mem_39095") != 0)
        return 1;
    // ../lib/github.com/diku-dk/vtree/vtree.fut:340:39-65
    if (memblock_alloc(ctx, &mem_39117, bytes_38985, "mem_39117")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:340:39-65
    for (int64_t nest_i_39610 = 0; nest_i_39610 < result_sizze_29183; nest_i_39610++) {
        ((int64_t *) mem_39117.mem)[nest_i_39610] = (int64_t) 0;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:340:22-353:105
    for (int64_t iter_38372 = 0; iter_38372 < (int64_t) 4; iter_38372++) {
        int64_t pixel_38377 = ((int64_t *) mem_38908.mem)[iter_38372];
        int64_t pixel_38378 = ((int64_t *) mem_38907.mem)[iter_38372];
        int64_t pixel_38379 = ((int64_t *) mem_38977.mem)[iter_38372];
        int64_t pixel_38380 = ((int64_t *) mem_38969.mem)[iter_38372];
        int64_t pixel_38385 = ((int64_t *) mem_39006.mem)[iter_38372];
        int64_t pixel_38386 = ((int64_t *) mem_39007.mem)[iter_38372];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:227:25-29
        
        bool x_34309 = sle64((int64_t) 0, pixel_38377);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:227:25-29
        
        bool y_34310 = slt64(pixel_38377, (int64_t) 8);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:227:25-29
        
        bool bounds_check_34311 = x_34309 && y_34310;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:227:25-29
        
        bool index_certs_34312;
        
        if (!bounds_check_34311) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) pixel_38377, "] out of bounds for array of shape [", (long long) (int64_t) 8, "].", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:227:25-29\n   #1  ../lib/github.com/diku-dk/vtree/vtree.fut:345:9-350:66\n   #2  test_operations.fut:123:7-142:117\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:227:25-29
        
        int64_t lifted_lambda_res_34313 = ((int64_t *) mem_39103.mem)[pixel_38377];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:228:30-34
        
        bool x_34314 = sle64((int64_t) 0, pixel_38378);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:228:30-34
        
        bool y_34315 = slt64(pixel_38378, (int64_t) 8);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:228:30-34
        
        bool bounds_check_34316 = x_34314 && y_34315;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:228:30-34
        
        bool index_certs_34317;
        
        if (!bounds_check_34316) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) pixel_38378, "] out of bounds for array of shape [", (long long) (int64_t) 8, "].", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:228:30-34\n   #1  ../lib/github.com/diku-dk/vtree/vtree.fut:345:9-350:66\n   #2  test_operations.fut:123:7-142:117\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:228:30-34
        
        int64_t inv_arg0_34318 = ((int64_t *) mem_39103.mem)[pixel_38378];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:350:71-78
        
        int64_t neg_res_34319 = -inv_arg0_34318;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:350:67-70
        
        int64_t defunc_0_f_res_34320 = add64(lifted_lambda_res_34313, neg_res_34319);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:351:61-65
        
        int64_t lifted_lambda_res_34321 = mul64((int64_t) 2, defunc_0_f_res_34320);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:351:34-37
        
        int64_t defunc_0_f_res_34322 = add64(lifted_lambda_res_34321, pixel_38385);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:227:25-29
        
        int64_t lifted_lambda_res_34327 = ((int64_t *) mem_39102.mem)[pixel_38377];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:228:30-34
        
        int64_t inv_arg0_34332 = ((int64_t *) mem_39102.mem)[pixel_38378];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:350:71-78
        
        int64_t neg_res_34333 = -inv_arg0_34332;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:350:67-70
        
        int64_t defunc_0_f_res_34334 = add64(lifted_lambda_res_34327, neg_res_34333);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:351:61-65
        
        int64_t lifted_lambda_res_34335 = mul64((int64_t) 2, defunc_0_f_res_34334);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:351:34-37
        
        int64_t defunc_0_f_res_34336 = add64(lifted_lambda_res_34335, pixel_38379);
        bool less_than_zzero_38389 = slt64(pixel_38380, (int64_t) 0);
        bool greater_than_sizze_38390 = sle64((int64_t) 4, pixel_38380);
        bool outside_bounds_dim_38391 = less_than_zzero_38389 || greater_than_sizze_38390;
        
        if (!outside_bounds_dim_38391) {
            int64_t read_hist_38393 = ((int64_t *) mem_39084.mem)[pixel_38380];
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:353:67-70
            
            int64_t defunc_0_f_res_29878 = add64(defunc_0_f_res_34336, read_hist_38393);
            
            ((int64_t *) mem_39084.mem)[pixel_38380] = defunc_0_f_res_29878;
        }
        if (!outside_bounds_dim_38391) {
            int64_t read_hist_38400 = ((int64_t *) mem_39085.mem)[pixel_38380];
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:340:67-70
            
            int64_t defunc_0_f_res_29771 = add64(pixel_38379, read_hist_38400);
            
            ((int64_t *) mem_39085.mem)[pixel_38380] = defunc_0_f_res_29771;
        }
        
        bool less_than_zzero_38403 = slt64(pixel_38386, (int64_t) 0);
        bool greater_than_sizze_38404 = sle64(result_sizze_29183, pixel_38386);
        bool outside_bounds_dim_38405 = less_than_zzero_38403 || greater_than_sizze_38404;
        
        if (!outside_bounds_dim_38405) {
            int64_t read_hist_38407 = ((int64_t *) mem_39087.mem)[pixel_38386];
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:353:67-70
            
            int64_t defunc_0_f_res_29492 = add64(defunc_0_f_res_34322, read_hist_38407);
            
            ((int64_t *) mem_39087.mem)[pixel_38386] = defunc_0_f_res_29492;
        }
        if (!outside_bounds_dim_38405) {
            int64_t read_hist_38414 = ((int64_t *) mem_39117.mem)[pixel_38386];
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:340:67-70
            
            int64_t defunc_0_f_res_29385 = add64(pixel_38385, read_hist_38414);
            
            ((int64_t *) mem_39117.mem)[pixel_38386] = defunc_0_f_res_29385;
        }
    }
    if (memblock_unref(ctx, &mem_38969, "mem_38969") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38977, "mem_38977") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_39006, "mem_39006") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_39102, "mem_39102") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_39103, "mem_39103") != 0)
        return 1;
    // ../lib/github.com/diku-dk/vtree/vtree.fut:341:35-101
    if (memblock_alloc(ctx, &mem_39142, (int64_t) 32, "mem_39142")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:341:35-101
    for (int64_t i_38419 = 0; i_38419 < (int64_t) 4; i_38419++) {
        int64_t eta_p_29389 = ((int64_t *) mem_39007.mem)[i_38419];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:341:46-65
        
        bool x_29390 = sle64((int64_t) 0, eta_p_29389);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:341:46-65
        
        bool y_29391 = slt64(eta_p_29389, result_sizze_29183);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:341:46-65
        
        bool bounds_check_29392 = x_29390 && y_29391;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:341:46-65
        
        bool index_certs_29393;
        
        if (!bounds_check_29392) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) eta_p_29389, "] out of bounds for array of shape [", (long long) result_sizze_29183, "].", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:341:46-65\n   #1  test_operations.fut:123:7-142:117\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:341:46-65
        
        int64_t zp_lhs_29394 = ((int64_t *) mem_38990.mem)[eta_p_29389];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:341:68-81
        
        int64_t zp_rhs_29395 = ((int64_t *) mem_39117.mem)[eta_p_29389];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:341:66-81
        
        int64_t zp_lhs_29396 = add64(zp_lhs_29394, zp_rhs_29395);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:341:82-85
        
        int64_t lifted_lambda_res_29397 = add64((int64_t) 1, zp_lhs_29396);
        
        ((int64_t *) mem_39142.mem)[i_38419] = lifted_lambda_res_29397;
    }
    if (memblock_unref(ctx, &mem_39007, "mem_39007") != 0)
        return 1;
    // ../lib/github.com/diku-dk/vtree/vtree.fut:324:10-32
    if (memblock_alloc(ctx, &mem_39150, bytes_39040, "mem_39150")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:324:10-32
    
    int64_t inpacc_35356;
    int64_t inpacc_31504 = (int64_t) 0;
    
    for (int64_t i_38433 = 0; i_38433 < defunc_res_30924; i_38433++) {
        int64_t x_38671 = ((int64_t *) mem_39041.mem)[i_38433];
        
        // ../lib/github.com/diku-dk/segmented/segmented.fut:47:11-14
        
        int64_t defunc_0_op_res_38679 = add64(inpacc_31504, x_38671);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:324:21-26
        
        bool x_38680 = sle64((int64_t) 0, defunc_0_op_res_38679);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:324:21-26
        
        bool y_38681 = slt64(defunc_0_op_res_38679, (int64_t) 4);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:324:21-26
        
        bool bounds_check_38682 = x_38680 && y_38681;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:324:21-26
        
        bool index_certs_38683;
        
        if (!bounds_check_38682) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) defunc_0_op_res_38679, "] out of bounds for array of shape [", (long long) (int64_t) 4, "].", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:324:21-26\n   #1  ../lib/github.com/diku-dk/vtree/vtree.fut:342:48-104\n   #2  test_operations.fut:123:7-142:117\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:324:21-26
        
        int64_t lifted_lambda_res_38684 = ((int64_t *) mem_39142.mem)[defunc_0_op_res_38679];
        
        ((int64_t *) mem_39150.mem)[i_38433] = lifted_lambda_res_38684;
        
        int64_t inpacc_tmp_39616 = defunc_0_op_res_38679;
        
        inpacc_31504 = inpacc_tmp_39616;
    }
    inpacc_35356 = inpacc_31504;
    if (memblock_unref(ctx, &mem_39041, "mem_39041") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_39142, "mem_39142") != 0)
        return 1;
    // test_operations.fut:144:5-147:62
    
    bool cond_17841;
    
    if (cond_17840) {
        // ../lib/github.com/diku-dk/vtree/vtree.fut:343:22-85
        for (int64_t iter_38435 = 0; iter_38435 < defunc_0_reduce_res_29178; iter_38435++) {
            int64_t pixel_38437 = ((int64_t *) mem_39025.mem)[iter_38435];
            int64_t pixel_38438 = ((int64_t *) mem_39150.mem)[iter_38435];
            bool less_than_zzero_38439 = slt64(pixel_38437, (int64_t) 0);
            bool greater_than_sizze_38440 = sle64(result_sizze_29183, pixel_38437);
            bool outside_bounds_dim_38441 = less_than_zzero_38439 || greater_than_sizze_38440;
            
            if (!outside_bounds_dim_38441) {
                int64_t read_hist_38443 = ((int64_t *) mem_39117.mem)[pixel_38437];
                
                // ../lib/github.com/diku-dk/vtree/vtree.fut:343:49-52
                
                int64_t defunc_0_f_res_35239 = add64(pixel_38438, read_hist_38443);
                
                ((int64_t *) mem_39117.mem)[pixel_38437] = defunc_0_f_res_35239;
            }
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:356:18-54
        if (memblock_alloc(ctx, &mem_39164, bytes_38985, "mem_39164")) {
            err = 1;
            goto cleanup;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:356:18-54
        for (int64_t i_38448 = 0; i_38448 < result_sizze_29183; i_38448++) {
            int64_t eta_p_35247 = ((int64_t *) mem_38990.mem)[i_38448];
            int64_t eta_p_35248 = ((int64_t *) mem_39117.mem)[i_38448];
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:356:23-26
            
            int64_t defunc_0_f_res_35249 = add64(eta_p_35247, eta_p_35248);
            
            ((int64_t *) mem_39164.mem)[i_38448] = defunc_0_f_res_35249;
        }
        // test_operations.fut:145:24-44
        
        bool dim_match_35254 = (int64_t) 11 == result_sizze_29183;
        
        // test_operations.fut:145:24-44
        
        bool empty_or_match_cert_35255;
        
        if (!dim_match_35254) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (desugared) shape [", (long long) result_sizze_29183, "] cannot match shape of type \"[", (long long) (int64_t) 11, "]i64\".", "-> #0  test_operations.fut:145:24-44\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        // test_operations.fut:145:8-57
        
        bool defunc_0_reduce_res_35257;
        bool redout_38450 = 1;
        
        for (int64_t i_38451 = 0; i_38451 < (int64_t) 11; i_38451++) {
            int64_t eta_p_35258 = ((int64_t *) mem_39164.mem)[i_38451];
            int64_t eta_p_35259 = ((int64_t *) mem_38915.mem)[i_38451];
            
            // test_operations.fut:145:18-22
            
            bool defunc_0_f_res_35260 = eta_p_35258 == eta_p_35259;
            
            // test_operations.fut:145:8-57
            
            bool x_35263 = defunc_0_f_res_35260 && redout_38450;
            bool redout_tmp_39620 = x_35263;
            
            redout_38450 = redout_tmp_39620;
        }
        defunc_0_reduce_res_35257 = redout_38450;
        if (memblock_unref(ctx, &mem_39164, "mem_39164") != 0)
            return 1;
        cond_17841 = defunc_0_reduce_res_35257;
    } else {
        cond_17841 = 0;
    }
    if (memblock_unref(ctx, &mem_38915, "mem_38915") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38990, "mem_38990") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_39117, "mem_39117") != 0)
        return 1;
    // test_operations.fut:144:5-147:62
    
    bool cond_17850;
    
    if (cond_17841) {
        // ../lib/github.com/diku-dk/vtree/vtree.fut:336:28-112
        
        bool acc_cert_35162;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:336:28-112
        for (int64_t i_38453 = 0; i_38453 < defunc_0_reduce_res_29178; i_38453++) {
            int64_t v_35166 = ((int64_t *) mem_39025.mem)[i_38453];
            int64_t v_35167 = ((int64_t *) mem_39083.mem)[i_38453];
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:336:28-112
            // UpdateAcc
            if (sle64((int64_t) 0, v_35166) && slt64(v_35166, result_sizze_29183)) {
                ((int64_t *) mem_38988.mem)[v_35166] = v_35167;
            }
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:354:22-85
        for (int64_t iter_38454 = 0; iter_38454 < defunc_0_reduce_res_29178; iter_38454++) {
            int64_t pixel_38456 = ((int64_t *) mem_39025.mem)[iter_38454];
            int64_t pixel_38457 = ((int64_t *) mem_39150.mem)[iter_38454];
            bool less_than_zzero_38458 = slt64(pixel_38456, (int64_t) 0);
            bool greater_than_sizze_38459 = sle64(result_sizze_29183, pixel_38456);
            bool outside_bounds_dim_38460 = less_than_zzero_38458 || greater_than_sizze_38459;
            
            if (!outside_bounds_dim_38460) {
                int64_t read_hist_38462 = ((int64_t *) mem_39087.mem)[pixel_38456];
                
                // ../lib/github.com/diku-dk/vtree/vtree.fut:354:49-52
                
                int64_t defunc_0_f_res_35173 = add64(pixel_38457, read_hist_38462);
                
                ((int64_t *) mem_39087.mem)[pixel_38456] = defunc_0_f_res_35173;
            }
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:357:18-54
        if (memblock_alloc(ctx, &mem_39178, bytes_38985, "mem_39178")) {
            err = 1;
            goto cleanup;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:357:18-54
        for (int64_t i_38467 = 0; i_38467 < result_sizze_29183; i_38467++) {
            int64_t eta_p_35181 = ((int64_t *) mem_38988.mem)[i_38467];
            int64_t eta_p_35182 = ((int64_t *) mem_39087.mem)[i_38467];
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:357:23-26
            
            int64_t defunc_0_f_res_35183 = add64(eta_p_35181, eta_p_35182);
            
            ((int64_t *) mem_39178.mem)[i_38467] = defunc_0_f_res_35183;
        }
        // test_operations.fut:146:24-44
        
        bool dim_match_35188 = (int64_t) 11 == result_sizze_29183;
        
        // test_operations.fut:146:24-44
        
        bool empty_or_match_cert_35189;
        
        if (!dim_match_35188) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (desugared) shape [", (long long) result_sizze_29183, "] cannot match shape of type \"[", (long long) (int64_t) 11, "]i64\".", "-> #0  test_operations.fut:146:24-44\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        // test_operations.fut:146:8-57
        
        bool defunc_0_reduce_res_35191;
        bool redout_38469 = 1;
        
        for (int64_t i_38470 = 0; i_38470 < (int64_t) 11; i_38470++) {
            int64_t eta_p_35192 = ((int64_t *) mem_39178.mem)[i_38470];
            int64_t eta_p_35193 = ((int64_t *) mem_38916.mem)[i_38470];
            
            // test_operations.fut:146:18-22
            
            bool defunc_0_f_res_35194 = eta_p_35192 == eta_p_35193;
            
            // test_operations.fut:146:8-57
            
            bool x_35197 = defunc_0_f_res_35194 && redout_38469;
            bool redout_tmp_39624 = x_35197;
            
            redout_38469 = redout_tmp_39624;
        }
        defunc_0_reduce_res_35191 = redout_38469;
        if (memblock_unref(ctx, &mem_39178, "mem_39178") != 0)
            return 1;
        cond_17850 = defunc_0_reduce_res_35191;
    } else {
        cond_17850 = 0;
    }
    if (memblock_unref(ctx, &mem_38916, "mem_38916") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38988, "mem_38988") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_39083, "mem_39083") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_39087, "mem_39087") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_39150, "mem_39150") != 0)
        return 1;
    // test_operations.fut:144:5-147:62
    if (cond_17850) {
        // ../lib/github.com/diku-dk/vtree/vtree.fut:337:30-118
        
        bool acc_cert_35208;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:337:30-118
        for (int64_t i_38472 = 0; i_38472 < defunc_0_reduce_res_29178; i_38472++) {
            int64_t v_35212 = ((int64_t *) mem_39025.mem)[i_38472];
            int64_t v_35213 = ((int64_t *) mem_39081.mem)[i_38472];
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:337:30-118
            // UpdateAcc
            if (sle64((int64_t) 0, v_35212) && slt64(v_35212, result_sizze_29183)) {
                ((int64_t *) mem_38986.mem)[v_35212] = v_35213;
            }
        }
        // test_operations.fut:147:24-46
        
        bool dim_match_35216 = (int64_t) 11 == result_sizze_29183;
        
        // test_operations.fut:147:24-46
        
        bool empty_or_match_cert_35217;
        
        if (!dim_match_35216) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (desugared) shape [", (long long) result_sizze_29183, "] cannot match shape of type \"[", (long long) (int64_t) 11, "]i64\".", "-> #0  test_operations.fut:147:24-46\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        // test_operations.fut:147:8-61
        
        bool defunc_0_reduce_res_35219;
        bool redout_38473 = 1;
        
        for (int64_t i_38474 = 0; i_38474 < (int64_t) 11; i_38474++) {
            int64_t eta_p_35220 = ((int64_t *) mem_38986.mem)[i_38474];
            int64_t eta_p_35221 = ((int64_t *) mem_38917.mem)[i_38474];
            
            // test_operations.fut:147:18-22
            
            bool defunc_0_f_res_35222 = eta_p_35220 == eta_p_35221;
            
            // test_operations.fut:147:8-61
            
            bool x_35225 = defunc_0_f_res_35222 && redout_38473;
            bool redout_tmp_39626 = x_35225;
            
            redout_38473 = redout_tmp_39626;
        }
        defunc_0_reduce_res_35219 = redout_38473;
        ok_17859 = defunc_0_reduce_res_35219;
    } else {
        ok_17859 = 0;
    }
    if (memblock_unref(ctx, &mem_38917, "mem_38917") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38986, "mem_38986") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_39025, "mem_39025") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_39081, "mem_39081") != 0)
        return 1;
    // test_operations.fut:169:8-56
    
    bool defunc_0_reduce_res_35359;
    bool redout_38486 = 1;
    
    for (int64_t i_38487 = 0; i_38487 < (int64_t) 4; i_38487++) {
        int64_t eta_p_30953 = ((int64_t *) mem_38921.mem)[i_38487];
        int64_t eta_p_30954 = ((int64_t *) mem_39085.mem)[i_38487];
        int64_t eta_p_30955 = ((int64_t *) mem_38907.mem)[i_38487];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:356:23-26
        
        int64_t defunc_0_f_res_30956 = add64(eta_p_30953, eta_p_30954);
        
        // test_operations.fut:169:18-22
        
        bool defunc_0_f_res_30958 = defunc_0_f_res_30956 == eta_p_30955;
        
        // test_operations.fut:169:8-56
        
        bool x_28734 = defunc_0_f_res_30958 && redout_38486;
        bool redout_tmp_39627 = x_28734;
        
        redout_38486 = redout_tmp_39627;
    }
    defunc_0_reduce_res_35359 = redout_38486;
    if (memblock_unref(ctx, &mem_38907, "mem_38907") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38921, "mem_38921") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_39085, "mem_39085") != 0)
        return 1;
    // test_operations.fut:168:5-171:61
    
    bool cond_17929;
    
    if (defunc_0_reduce_res_35359) {
        // ../lib/github.com/diku-dk/vtree/vtree.fut:357:18-54
        if (memblock_alloc(ctx, &mem_39185, (int64_t) 32, "mem_39185")) {
            err = 1;
            goto cleanup;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:357:18-54
        for (int64_t i_38503 = 0; i_38503 < (int64_t) 4; i_38503++) {
            int64_t eta_p_35293 = ((int64_t *) mem_38920.mem)[i_38503];
            int64_t eta_p_35294 = ((int64_t *) mem_39084.mem)[i_38503];
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:357:23-26
            
            int64_t defunc_0_f_res_35295 = add64(eta_p_35293, eta_p_35294);
            
            ((int64_t *) mem_39185.mem)[i_38503] = defunc_0_f_res_35295;
        }
        // test_operations.fut:170:8-56
        
        bool defunc_0_reduce_res_35300;
        bool redout_38505 = 1;
        
        for (int64_t i_38506 = 0; i_38506 < (int64_t) 4; i_38506++) {
            int64_t eta_p_35301 = ((int64_t *) mem_39185.mem)[i_38506];
            int64_t eta_p_35302 = ((int64_t *) mem_38908.mem)[i_38506];
            
            // test_operations.fut:170:18-22
            
            bool defunc_0_f_res_35303 = eta_p_35301 == eta_p_35302;
            
            // test_operations.fut:170:8-56
            
            bool x_35306 = defunc_0_f_res_35303 && redout_38505;
            bool redout_tmp_39629 = x_35306;
            
            redout_38505 = redout_tmp_39629;
        }
        defunc_0_reduce_res_35300 = redout_38505;
        if (memblock_unref(ctx, &mem_39185, "mem_39185") != 0)
            return 1;
        cond_17929 = defunc_0_reduce_res_35300;
    } else {
        cond_17929 = 0;
    }
    if (memblock_unref(ctx, &mem_38908, "mem_38908") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38920, "mem_38920") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_39084, "mem_39084") != 0)
        return 1;
    // test_operations.fut:168:5-171:61
    if (cond_17929) {
        // test_operations.fut:171:8-60
        
        bool defunc_0_reduce_res_35324;
        bool redout_38509 = 1;
        
        for (int64_t i_38510 = 0; i_38510 < (int64_t) 4; i_38510++) {
            int64_t eta_p_35325 = ((int64_t *) mem_38919.mem)[i_38510];
            int64_t eta_p_35326 = ((int64_t *) mem_38909.mem)[i_38510];
            
            // test_operations.fut:171:18-22
            
            bool defunc_0_f_res_35327 = eta_p_35325 == eta_p_35326;
            
            // test_operations.fut:171:8-60
            
            bool x_35330 = defunc_0_f_res_35327 && redout_38509;
            bool redout_tmp_39630 = x_35330;
            
            redout_38509 = redout_tmp_39630;
        }
        defunc_0_reduce_res_35324 = redout_38509;
        ok_17938 = defunc_0_reduce_res_35324;
    } else {
        ok_17938 = 0;
    }
    if (memblock_unref(ctx, &mem_38909, "mem_38909") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38919, "mem_38919") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_39185, "mem_39185") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_39178, "mem_39178") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_39164, "mem_39164") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_39150, "mem_39150") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_39142, "mem_39142") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_39117, "mem_39117") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_39103, "mem_39103") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_39102, "mem_39102") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_39095, "mem_39095") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_39088, "mem_39088") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_39087, "mem_39087") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_39085, "mem_39085") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_39084, "mem_39084") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_39067, "mem_39067") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_39065, "mem_39065") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_39083, "mem_39083") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_39081, "mem_39081") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_39057, "mem_39057") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_39043, "mem_39043") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_39041, "mem_39041") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_39033, "mem_39033") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_39026, "mem_39026") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_39025, "mem_39025") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_39011, "mem_39011") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_39009, "mem_39009") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38993, "mem_38993") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38992, "mem_38992") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_39007, "mem_39007") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_39006, "mem_39006") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38991, "mem_38991") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38990, "mem_38990") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38988, "mem_38988") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38986, "mem_38986") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38984, "mem_38984") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38977, "mem_38977") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38970, "mem_38970") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38934, "mem_38934") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38933, "mem_38933") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38932, "mem_38932") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38931, "mem_38931") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38930, "mem_38930") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38969, "mem_38969") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38968, "mem_38968") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38967, "mem_38967") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38966, "mem_38966") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38965, "mem_38965") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38929, "mem_38929") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38922, "mem_38922") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38921, "mem_38921") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38920, "mem_38920") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38919, "mem_38919") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38918, "mem_38918") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38917, "mem_38917") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38916, "mem_38916") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38915, "mem_38915") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38914, "mem_38914") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38913, "mem_38913") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38912, "mem_38912") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38911, "mem_38911") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38910, "mem_38910") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38909, "mem_38909") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38908, "mem_38908") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38907, "mem_38907") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38906, "mem_38906") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_38903, "ext_mem_38903") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_38904, "ext_mem_38904") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_38905, "ext_mem_38905") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38902, "mem_38902") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_38895, "ext_mem_38895") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_38896, "ext_mem_38896") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_38897, "ext_mem_38897") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_38898, "ext_mem_38898") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_38899, "ext_mem_38899") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_38900, "ext_mem_38900") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_38901, "ext_mem_38901") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38894, "mem_38894") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38893, "mem_38893") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_38886, "ext_mem_38886") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_38887, "ext_mem_38887") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_38888, "ext_mem_38888") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_38889, "ext_mem_38889") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_38890, "ext_mem_38890") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_38891, "ext_mem_38891") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_38892, "ext_mem_38892") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38885, "mem_38885") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_38878, "ext_mem_38878") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_38879, "ext_mem_38879") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_38880, "ext_mem_38880") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_38881, "ext_mem_38881") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_38882, "ext_mem_38882") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_38883, "ext_mem_38883") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_38884, "ext_mem_38884") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38877, "mem_38877") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38876, "mem_38876") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38875, "mem_38875") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38874, "mem_38874") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38873, "mem_38873") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38872, "mem_38872") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38871, "mem_38871") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38870, "mem_38870") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_38863, "ext_mem_38863") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_38864, "ext_mem_38864") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_38865, "ext_mem_38865") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_38866, "ext_mem_38866") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_38867, "ext_mem_38867") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_38868, "ext_mem_38868") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_38869, "ext_mem_38869") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38862, "mem_38862") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38861, "mem_38861") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38860, "mem_38860") != 0)
        return 1;
    if (memblock_unref(ctx, &mem_38859, "mem_38859") != 0)
        return 1;
    #undef ok_17775
    #undef ok_17859
    #undef ok_17938
    #undef x_27518
    #undef x_27521
    #undef x_27527
    #undef x_27533
    
  cleanup:
    return err;
}
static int free_constants(struct futhark_context *ctx)
{
    (void) ctx;
    return 0;
}
struct futhark_i64_1d {
    struct memblock mem;
    int64_t shape[1];
};
struct futhark_i64_1d *futhark_new_i64_1d(struct futhark_context *ctx, const int64_t *data, int64_t dim0)
{
    int err = 0;
    struct futhark_i64_1d *bad = NULL;
    struct futhark_i64_1d *arr = (struct futhark_i64_1d *) malloc(sizeof(struct futhark_i64_1d));
    
    if (arr == NULL)
        return bad;
    lock_lock(&ctx->lock);
    arr->mem.references = NULL;
    if (memblock_alloc(ctx, &arr->mem, dim0 * 8, "arr->mem"))
        err = 1;
    arr->shape[0] = dim0;
    if ((size_t) dim0 * 8 > 0)
        memmove(arr->mem.mem + 0, (const unsigned char *) data + 0, (size_t) dim0 * 8);
    lock_unlock(&ctx->lock);
    if (err != 0) {
        free(arr);
        return bad;
    }
    return arr;
}
struct futhark_i64_1d *futhark_new_raw_i64_1d(struct futhark_context *ctx, unsigned char *data, int64_t dim0)
{
    int err = 0;
    struct futhark_i64_1d *bad = NULL;
    struct futhark_i64_1d *arr = (struct futhark_i64_1d *) malloc(sizeof(struct futhark_i64_1d));
    
    if (arr == NULL)
        return bad;
    lock_lock(&ctx->lock);
    arr->mem.references = NULL;
    arr->mem.mem = data;
    arr->shape[0] = dim0;
    lock_unlock(&ctx->lock);
    return arr;
}
int futhark_free_i64_1d(struct futhark_context *ctx, struct futhark_i64_1d *arr)
{
    lock_lock(&ctx->lock);
    if (memblock_unref(ctx, &arr->mem, "arr->mem") != 0)
        return 1;
    lock_unlock(&ctx->lock);
    free(arr);
    return 0;
}
int futhark_values_i64_1d(struct futhark_context *ctx, struct futhark_i64_1d *arr, int64_t *data)
{
    int err = 0;
    
    lock_lock(&ctx->lock);
    if ((size_t) arr->shape[0] * 8 > 0)
        memmove((unsigned char *) data + 0, arr->mem.mem + 0, (size_t) arr->shape[0] * 8);
    lock_unlock(&ctx->lock);
    return err;
}
int futhark_index_i64_1d(struct futhark_context *ctx, int64_t *out, struct futhark_i64_1d *arr, int64_t i0)
{
    int err = 0;
    
    if (i0 >= 0 && i0 < arr->shape[0]) {
        lock_lock(&ctx->lock);
        if (8 > 0)
            memmove((unsigned char *) out + 0, arr->mem.mem + 8 * (i0 * 1), 8);
        lock_unlock(&ctx->lock);
    } else {
        err = 1;
        set_error(ctx, strdup("Index out of bounds."));
    }
    return err;
}
unsigned char *futhark_values_raw_i64_1d(struct futhark_context *ctx, struct futhark_i64_1d *arr)
{
    (void) ctx;
    return arr->mem.mem;
}
const int64_t *futhark_shape_i64_1d(struct futhark_context *ctx, struct futhark_i64_1d *arr)
{
    (void) ctx;
    return arr->shape;
}

FUTHARK_FUN_ATTR int futrts_deleteVertices_9181(struct futhark_context *ctx, struct memblock *mem_out_p_39658, struct memblock *mem_out_p_39659, struct memblock *mem_out_p_39660, int64_t *out_prim_out_39661, struct memblock data_mem_39192, struct memblock lp_mem_39193, struct memblock rp_mem_39194, struct memblock keep_mem_39195, int64_t n_19236)
{
    (void) ctx;
    
    int err = 0;
    int64_t mem_39197_cached_sizze_39662 = 0;
    unsigned char *mem_39197 = NULL;
    int64_t mem_39199_cached_sizze_39663 = 0;
    unsigned char *mem_39199 = NULL;
    int64_t mem_39212_cached_sizze_39664 = 0;
    unsigned char *mem_39212 = NULL;
    int64_t mem_39214_cached_sizze_39665 = 0;
    unsigned char *mem_39214 = NULL;
    int64_t mem_39222_cached_sizze_39666 = 0;
    unsigned char *mem_39222 = NULL;
    int64_t mem_39224_cached_sizze_39667 = 0;
    unsigned char *mem_39224 = NULL;
    int64_t mem_39226_cached_sizze_39668 = 0;
    unsigned char *mem_39226 = NULL;
    struct memblock mem_39232;
    
    mem_39232.references = NULL;
    
    struct memblock mem_39230;
    
    mem_39230.references = NULL;
    
    struct memblock mem_39228;
    
    mem_39228.references = NULL;
    
    struct memblock mem_out_39450;
    
    mem_out_39450.references = NULL;
    
    struct memblock mem_out_39449;
    
    mem_out_39449.references = NULL;
    
    struct memblock mem_out_39448;
    
    mem_out_39448.references = NULL;
    
    bool ok_17775 = ctx->constants->ok_17775;
    bool ok_17859 = ctx->constants->ok_17859;
    bool ok_17938 = ctx->constants->ok_17938;
    bool x_27518 = ctx->constants->x_27518;
    bool x_27521 = ctx->constants->x_27521;
    bool x_27527 = ctx->constants->x_27527;
    bool x_27533 = ctx->constants->x_27533;
    int64_t prim_out_39451;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:248:27-32
    
    int64_t dzlz7bUZLztZRz20U2z20Unz7dUzg_19241 = mul64((int64_t) 2, n_19236);
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:241:15-40
    
    int64_t bytes_39196 = (int64_t) 8 * n_19236;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:241:15-40
    if (mem_39197_cached_sizze_39662 < bytes_39196) {
        err = lexical_realloc(ctx, &mem_39197, &mem_39197_cached_sizze_39662, bytes_39196);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:241:15-40
    if (mem_39199_cached_sizze_39663 < bytes_39196) {
        err = lexical_realloc(ctx, &mem_39199, &mem_39199_cached_sizze_39663, bytes_39196);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:241:15-40
    
    int64_t discard_38520;
    int64_t defunc_res_35772;
    int64_t scanacc_38513;
    int64_t redout_38515;
    
    scanacc_38513 = (int64_t) 0;
    redout_38515 = (int64_t) 0;
    for (int64_t i_38517 = 0; i_38517 < n_19236; i_38517++) {
        bool eta_p_35709 = ((bool *) keep_mem_39195.mem)[i_38517];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:245:22-57
        
        int64_t lifted_lambda_res_35711 = btoi_bool_i64(eta_p_35709);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:241:15-40
        
        int64_t defunc_0_op_res_29065 = add64(lifted_lambda_res_35711, scanacc_38513);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:245:13-57
        
        int64_t zp_res_30946 = add64(lifted_lambda_res_35711, redout_38515);
        
        ((int64_t *) mem_39197)[i_38517] = defunc_0_op_res_29065;
        ((int64_t *) mem_39199)[i_38517] = lifted_lambda_res_35711;
        
        int64_t scanacc_tmp_39452 = defunc_0_op_res_29065;
        int64_t redout_tmp_39454 = zp_res_30946;
        
        scanacc_38513 = scanacc_tmp_39452;
        redout_38515 = redout_tmp_39454;
    }
    discard_38520 = scanacc_38513;
    defunc_res_35772 = redout_38515;
    // ../lib/github.com/diku-dk/vtree/vtree.fut:235:16-238:25
    
    int64_t bytes_39213 = (int64_t) 16 * n_19236;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:241:15-40
    
    int64_t tmp_29068 = sub64(n_19236, (int64_t) 1);
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:241:15-40
    
    bool y_29070 = slt64(tmp_29068, n_19236);
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:241:15-40
    
    bool x_29069 = sle64((int64_t) 0, tmp_29068);
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:241:15-40
    
    bool bounds_check_29071 = x_29069 && y_29070;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:241:15-40
    
    bool cond_29066 = n_19236 == (int64_t) 0;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:241:15-40
    
    bool protect_assert_disj_29072 = cond_29066 || bounds_check_29071;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:241:15-40
    
    bool index_certs_29073;
    
    if (!protect_assert_disj_29072) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) tmp_29068, "] out of bounds for array of shape [", (long long) n_19236, "].", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:241:15-40\n   #1  ../lib/github.com/diku-dk/vtree/vtree.fut:259:28-54\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:241:15-40
    
    bool x_29067 = !cond_29066;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:241:15-40
    
    int64_t m_f_res_29074;
    
    if (x_29067) {
        // ../lib/github.com/diku-dk/vtree/vtree.fut:241:15-40
        
        int64_t x_35770 = ((int64_t *) mem_39197)[tmp_29068];
        
        m_f_res_29074 = x_35770;
    } else {
        m_f_res_29074 = (int64_t) 0;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:241:15-40
    
    int64_t m_29076;
    
    if (cond_29066) {
        m_29076 = (int64_t) 0;
    } else {
        m_29076 = m_f_res_29074;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:241:15-40
    
    int64_t bytes_39221 = (int64_t) 8 * m_29076;
    bool eq_x_y_30897 = defunc_res_35772 == (int64_t) 0;
    bool eq_x_zz_30898 = defunc_res_35772 == m_f_res_29074;
    bool p_and_eq_x_y_30899 = cond_29066 && eq_x_y_30897;
    bool p_and_eq_x_y_30901 = x_29067 && eq_x_zz_30898;
    bool dim_match_19303 = p_and_eq_x_y_30899 || p_and_eq_x_y_30901;
    bool empty_or_match_cert_19304;
    
    if (!dim_match_19303) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Value of (desugared) shape [", (long long) m_29076, "] cannot match shape of type \"[", (long long) defunc_res_35772, "](i64, i64, i64)\".", "-> #0  unknown location\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    
    int64_t bytes_39227 = (int64_t) 8 * defunc_res_35772;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:248:16-39
    if (mem_39212_cached_sizze_39664 < dzlz7bUZLztZRz20U2z20Unz7dUzg_19241) {
        err = lexical_realloc(ctx, &mem_39212, &mem_39212_cached_sizze_39664, dzlz7bUZLztZRz20U2z20Unz7dUzg_19241);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:248:16-39
    for (int64_t nest_i_39456 = 0; nest_i_39456 < dzlz7bUZLztZRz20U2z20Unz7dUzg_19241; nest_i_39456++) {
        ((bool *) mem_39212)[nest_i_39456] = 0;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:248:7-250:32
    
    bool acc_cert_27891;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:248:7-250:32
    for (int64_t i_38522 = 0; i_38522 < n_19236; i_38522++) {
        int64_t v_28589 = ((int64_t *) lp_mem_39193.mem)[i_38522];
        bool v_28590 = ((bool *) keep_mem_39195.mem)[i_38522];
        int64_t v_28593 = ((int64_t *) rp_mem_39194.mem)[i_38522];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:248:7-250:32
        // UpdateAcc
        if (sle64((int64_t) 0, v_28589) && slt64(v_28589, dzlz7bUZLztZRz20U2z20Unz7dUzg_19241)) {
            ((bool *) mem_39212)[v_28589] = v_28590;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:248:7-250:32
        // UpdateAcc
        if (sle64((int64_t) 0, v_28593) && slt64(v_28593, dzlz7bUZLztZRz20U2z20Unz7dUzg_19241)) {
            ((bool *) mem_39212)[v_28593] = v_28590;
        }
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:235:16-238:25
    if (mem_39214_cached_sizze_39665 < bytes_39213) {
        err = lexical_realloc(ctx, &mem_39214, &mem_39214_cached_sizze_39665, bytes_39213);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:235:16-238:25
    
    int64_t inpacc_35774;
    int64_t inpacc_35675 = (int64_t) 0;
    
    for (int64_t i_38535 = 0; i_38535 < dzlz7bUZLztZRz20U2z20Unz7dUzg_19241; i_38535++) {
        bool eta_p_38778 = ((bool *) mem_39212)[i_38535];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:235:16-52
        
        int64_t lifted_lambda_res_38779 = btoi_bool_i64(eta_p_38778);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:236:19-22
        
        int64_t defunc_0_op_res_38788 = add64(inpacc_35675, lifted_lambda_res_38779);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:237:24-47
        
        int64_t lifted_lambda_res_38789;
        
        if (eta_p_38778) {
            // ../lib/github.com/diku-dk/vtree/vtree.fut:237:36-39
            
            int64_t lifted_lambda_res_t_res_38790 = sub64(defunc_0_op_res_38788, (int64_t) 1);
            
            lifted_lambda_res_38789 = lifted_lambda_res_t_res_38790;
        } else {
            lifted_lambda_res_38789 = (int64_t) -1;
        }
        ((int64_t *) mem_39214)[i_38535] = lifted_lambda_res_38789;
        
        int64_t inpacc_tmp_39458 = defunc_0_op_res_38788;
        
        inpacc_35675 = inpacc_tmp_39458;
    }
    inpacc_35774 = inpacc_35675;
    // ../lib/github.com/diku-dk/vtree/vtree.fut:241:15-40
    if (mem_39222_cached_sizze_39666 < bytes_39221) {
        err = lexical_realloc(ctx, &mem_39222, &mem_39222_cached_sizze_39666, bytes_39221);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:241:15-40
    if (mem_39224_cached_sizze_39667 < bytes_39221) {
        err = lexical_realloc(ctx, &mem_39224, &mem_39224_cached_sizze_39667, bytes_39221);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:241:15-40
    if (mem_39226_cached_sizze_39668 < bytes_39221) {
        err = lexical_realloc(ctx, &mem_39226, &mem_39226_cached_sizze_39668, bytes_39221);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:241:15-40
    
    bool acc_cert_35422;
    bool acc_cert_35423;
    bool acc_cert_35424;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:241:15-40
    for (int64_t i_38540 = 0; i_38540 < n_19236; i_38540++) {
        bool eta_p_35469 = ((bool *) keep_mem_39195.mem)[i_38540];
        int64_t eta_p_35470 = ((int64_t *) lp_mem_39193.mem)[i_38540];
        int64_t eta_p_35471 = ((int64_t *) rp_mem_39194.mem)[i_38540];
        int64_t eta_p_35472 = ((int64_t *) mem_39199)[i_38540];
        int64_t eta_p_35473 = ((int64_t *) mem_39197)[i_38540];
        int64_t v_35477 = ((int64_t *) data_mem_39192.mem)[i_38540];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:254:26-80
        
        int64_t lifted_lambda_res_35478;
        int64_t lifted_lambda_res_35479;
        
        if (eta_p_35469) {
            // ../lib/github.com/diku-dk/vtree/vtree.fut:254:37-50
            
            bool x_35753 = sle64((int64_t) 0, eta_p_35470);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:254:37-50
            
            bool y_35754 = slt64(eta_p_35470, dzlz7bUZLztZRz20U2z20Unz7dUzg_19241);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:254:37-50
            
            bool bounds_check_35755 = x_35753 && y_35754;
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:254:37-50
            
            bool index_certs_35756;
            
            if (!bounds_check_35755) {
                set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) eta_p_35470, "] out of bounds for array of shape [", (long long) dzlz7bUZLztZRz20U2z20Unz7dUzg_19241, "].", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:254:37-50\n"));
                err = FUTHARK_PROGRAM_ERROR;
                goto cleanup;
            }
            // ../lib/github.com/diku-dk/vtree/vtree.fut:254:37-50
            
            int64_t tmp_35757 = ((int64_t *) mem_39214)[eta_p_35470];
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:254:52-65
            
            bool x_35758 = sle64((int64_t) 0, eta_p_35471);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:254:52-65
            
            bool y_35759 = slt64(eta_p_35471, dzlz7bUZLztZRz20U2z20Unz7dUzg_19241);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:254:52-65
            
            bool bounds_check_35760 = x_35758 && y_35759;
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:254:52-65
            
            bool index_certs_35761;
            
            if (!bounds_check_35760) {
                set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) eta_p_35471, "] out of bounds for array of shape [", (long long) dzlz7bUZLztZRz20U2z20Unz7dUzg_19241, "].", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:254:52-65\n"));
                err = FUTHARK_PROGRAM_ERROR;
                goto cleanup;
            }
            // ../lib/github.com/diku-dk/vtree/vtree.fut:254:52-65
            
            int64_t tmp_35762 = ((int64_t *) mem_39214)[eta_p_35471];
            
            lifted_lambda_res_35478 = tmp_35757;
            lifted_lambda_res_35479 = tmp_35762;
        } else {
            lifted_lambda_res_35478 = (int64_t) -1;
            lifted_lambda_res_35479 = (int64_t) -1;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:241:15-40
        
        bool cond_35492 = eta_p_35472 == (int64_t) 1;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:241:15-40
        
        int64_t lifted_lambda_res_35493;
        
        if (cond_35492) {
            // ../lib/github.com/diku-dk/vtree/vtree.fut:241:15-40
            
            int64_t lifted_lambda_res_t_res_35763 = sub64(eta_p_35473, (int64_t) 1);
            
            lifted_lambda_res_35493 = lifted_lambda_res_t_res_35763;
        } else {
            lifted_lambda_res_35493 = (int64_t) -1;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:241:15-40
        // UpdateAcc
        if (sle64((int64_t) 0, lifted_lambda_res_35493) && slt64(lifted_lambda_res_35493, m_29076)) {
            ((int64_t *) mem_39226)[lifted_lambda_res_35493] = lifted_lambda_res_35478;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:241:15-40
        // UpdateAcc
        if (sle64((int64_t) 0, lifted_lambda_res_35493) && slt64(lifted_lambda_res_35493, m_29076)) {
            ((int64_t *) mem_39224)[lifted_lambda_res_35493] = lifted_lambda_res_35479;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:241:15-40
        // UpdateAcc
        if (sle64((int64_t) 0, lifted_lambda_res_35493) && slt64(lifted_lambda_res_35493, m_29076)) {
            ((int64_t *) mem_39222)[lifted_lambda_res_35493] = v_35477;
        }
    }
    if (memblock_alloc(ctx, &mem_39228, bytes_39227, "mem_39228")) {
        err = 1;
        goto cleanup;
    }
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_39228.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) mem_39226, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {defunc_res_35772});
    if (memblock_alloc(ctx, &mem_39230, bytes_39227, "mem_39230")) {
        err = 1;
        goto cleanup;
    }
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_39230.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) mem_39224, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {defunc_res_35772});
    if (memblock_alloc(ctx, &mem_39232, bytes_39227, "mem_39232")) {
        err = 1;
        goto cleanup;
    }
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_39232.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) mem_39222, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {defunc_res_35772});
    if (memblock_set(ctx, &mem_out_39448, &mem_39232, "mem_39232") != 0)
        return 1;
    if (memblock_set(ctx, &mem_out_39449, &mem_39228, "mem_39228") != 0)
        return 1;
    if (memblock_set(ctx, &mem_out_39450, &mem_39230, "mem_39230") != 0)
        return 1;
    prim_out_39451 = defunc_res_35772;
    if (memblock_set(ctx, &*mem_out_p_39658, &mem_out_39448, "mem_out_39448") != 0)
        return 1;
    if (memblock_set(ctx, &*mem_out_p_39659, &mem_out_39449, "mem_out_39449") != 0)
        return 1;
    if (memblock_set(ctx, &*mem_out_p_39660, &mem_out_39450, "mem_out_39450") != 0)
        return 1;
    *out_prim_out_39661 = prim_out_39451;
    
  cleanup:
    {
        free(mem_39197);
        free(mem_39199);
        free(mem_39212);
        free(mem_39214);
        free(mem_39222);
        free(mem_39224);
        free(mem_39226);
        if (memblock_unref(ctx, &mem_39232, "mem_39232") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_39230, "mem_39230") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_39228, "mem_39228") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_out_39450, "mem_out_39450") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_out_39449, "mem_out_39449") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_out_39448, "mem_out_39448") != 0)
            return 1;
    }
    return err;
}
FUTHARK_FUN_ATTR int futrts_depth_9287(struct futhark_context *ctx, struct memblock *mem_out_p_39669, struct memblock data_mem_39192, struct memblock lp_mem_39193, struct memblock rp_mem_39194, int64_t n_26930)
{
    (void) ctx;
    
    int err = 0;
    int64_t mem_39196_cached_sizze_39670 = 0;
    unsigned char *mem_39196 = NULL;
    int64_t mem_39198_cached_sizze_39671 = 0;
    unsigned char *mem_39198 = NULL;
    int64_t mem_39206_cached_sizze_39672 = 0;
    unsigned char *mem_39206 = NULL;
    struct memblock mem_39214;
    
    mem_39214.references = NULL;
    
    struct memblock mem_out_39448;
    
    mem_out_39448.references = NULL;
    
    bool ok_17775 = ctx->constants->ok_17775;
    bool ok_17859 = ctx->constants->ok_17859;
    bool ok_17938 = ctx->constants->ok_17938;
    bool x_27518 = ctx->constants->x_27518;
    bool x_27521 = ctx->constants->x_27521;
    bool x_27527 = ctx->constants->x_27527;
    bool x_27533 = ctx->constants->x_27533;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:214:13-33
    
    int64_t bytes_39195 = (int64_t) 16 * n_26930;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:218:8-27
    
    int64_t bytes_39213 = (int64_t) 8 * n_26930;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:214:24-29
    
    int64_t dzlz7bUZLztZRz20U2z20Unz7dUzg_29056 = mul64((int64_t) 2, n_26930);
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:214:13-33
    if (mem_39196_cached_sizze_39670 < bytes_39195) {
        err = lexical_realloc(ctx, &mem_39196, &mem_39196_cached_sizze_39670, bytes_39195);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:214:13-33
    for (int64_t nest_i_39449 = 0; nest_i_39449 < dzlz7bUZLztZRz20U2z20Unz7dUzg_29056; nest_i_39449++) {
        ((int64_t *) mem_39196)[nest_i_39449] = (int64_t) 0;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:215:13-30
    
    bool acc_cert_29059;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:215:13-30
    for (int64_t i_38512 = 0; i_38512 < n_26930; i_38512++) {
        int64_t v_29063 = ((int64_t *) lp_mem_39193.mem)[i_38512];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:215:13-30
        // UpdateAcc
        if (sle64((int64_t) 0, v_29063) && slt64(v_29063, dzlz7bUZLztZRz20U2z20Unz7dUzg_29056)) {
            ((int64_t *) mem_39196)[v_29063] = (int64_t) 1;
        }
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:216:13-39
    
    bool acc_cert_29070;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:216:13-39
    for (int64_t i_38514 = 0; i_38514 < n_26930; i_38514++) {
        int64_t v_29074 = ((int64_t *) rp_mem_39194.mem)[i_38514];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:216:13-39
        // UpdateAcc
        if (sle64((int64_t) 0, v_29074) && slt64(v_29074, dzlz7bUZLztZRz20U2z20Unz7dUzg_29056)) {
            ((int64_t *) mem_39196)[v_29074] = (int64_t) -1;
        }
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:136:24-36
    if (mem_39198_cached_sizze_39671 < bytes_39195) {
        err = lexical_realloc(ctx, &mem_39198, &mem_39198_cached_sizze_39671, bytes_39195);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:136:24-36
    
    int64_t discard_38520;
    int64_t scanacc_38516 = (int64_t) 0;
    
    for (int64_t i_38518 = 0; i_38518 < dzlz7bUZLztZRz20U2z20Unz7dUzg_29056; i_38518++) {
        int64_t x_29078 = ((int64_t *) mem_39196)[i_38518];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:485:16-23
        
        int64_t zp_res_29081 = add64(x_29078, scanacc_38516);
        
        ((int64_t *) mem_39198)[i_38518] = zp_res_29081;
        
        int64_t scanacc_tmp_39452 = zp_res_29081;
        
        scanacc_38516 = scanacc_tmp_39452;
    }
    discard_38520 = scanacc_38516;
    // ../lib/github.com/diku-dk/vtree/vtree.fut:134:5-136:37
    if (mem_39206_cached_sizze_39672 < bytes_39195) {
        err = lexical_realloc(ctx, &mem_39206, &mem_39206_cached_sizze_39672, bytes_39195);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:134:5-136:37
    for (int64_t i_38523 = 0; i_38523 < dzlz7bUZLztZRz20U2z20Unz7dUzg_29056; i_38523++) {
        // ../lib/github.com/diku-dk/vtree/vtree.fut:136:11-36
        
        int64_t zv_lhs_35363 = add64((int64_t) -1, i_38523);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:136:11-36
        
        int64_t tmp_35364 = smod64(zv_lhs_35363, dzlz7bUZLztZRz20U2z20Unz7dUzg_29056);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:136:11-36
        
        int64_t lifted_lambda_res_35365 = ((int64_t *) mem_39198)[tmp_35364];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:134:19-43
        
        bool cond_35367 = i_38523 == (int64_t) 0;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:134:19-43
        
        int64_t lifted_lambda_res_35368;
        
        if (cond_35367) {
            lifted_lambda_res_35368 = (int64_t) 0;
        } else {
            lifted_lambda_res_35368 = lifted_lambda_res_35365;
        }
        ((int64_t *) mem_39206)[i_38523] = lifted_lambda_res_35368;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:218:8-27
    if (memblock_alloc(ctx, &mem_39214, bytes_39213, "mem_39214")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:218:8-27
    for (int64_t i_38527 = 0; i_38527 < n_26930; i_38527++) {
        int64_t eta_p_29094 = ((int64_t *) lp_mem_39193.mem)[i_38527];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:218:19-23
        
        bool x_29095 = sle64((int64_t) 0, eta_p_29094);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:218:19-23
        
        bool y_29096 = slt64(eta_p_29094, dzlz7bUZLztZRz20U2z20Unz7dUzg_29056);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:218:19-23
        
        bool bounds_check_29097 = x_29095 && y_29096;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:218:19-23
        
        bool index_certs_29098;
        
        if (!bounds_check_29097) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) eta_p_29094, "] out of bounds for array of shape [", (long long) dzlz7bUZLztZRz20U2z20Unz7dUzg_29056, "].", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:218:19-23\n   #1  ../lib/github.com/diku-dk/vtree/vtree.fut:484:9-485:15\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:218:19-23
        
        int64_t lifted_lambda_res_29099 = ((int64_t *) mem_39206)[eta_p_29094];
        
        ((int64_t *) mem_39214.mem)[i_38527] = lifted_lambda_res_29099;
    }
    if (memblock_set(ctx, &mem_out_39448, &mem_39214, "mem_39214") != 0)
        return 1;
    if (memblock_set(ctx, &*mem_out_p_39669, &mem_out_39448, "mem_out_39448") != 0)
        return 1;
    
  cleanup:
    {
        free(mem_39196);
        free(mem_39198);
        free(mem_39206);
        if (memblock_unref(ctx, &mem_39214, "mem_39214") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_out_39448, "mem_out_39448") != 0)
            return 1;
    }
    return err;
}
FUTHARK_FUN_ATTR int futrts_entry_test_delete_vertices(struct futhark_context *ctx, bool *out_prim_out_39673)
{
    (void) ctx;
    
    int err = 0;
    bool ok_17775 = ctx->constants->ok_17775;
    bool ok_17859 = ctx->constants->ok_17859;
    bool ok_17938 = ctx->constants->ok_17938;
    bool x_27518 = ctx->constants->x_27518;
    bool x_27521 = ctx->constants->x_27521;
    bool x_27527 = ctx->constants->x_27527;
    bool x_27533 = ctx->constants->x_27533;
    bool prim_out_39448;
    
    prim_out_39448 = ok_17775;
    *out_prim_out_39673 = prim_out_39448;
    
  cleanup:
    { }
    return err;
}
FUTHARK_FUN_ATTR int futrts_entry_test_merge_no_subtrees(struct futhark_context *ctx, bool *out_prim_out_39674)
{
    (void) ctx;
    
    int err = 0;
    bool ok_17775 = ctx->constants->ok_17775;
    bool ok_17859 = ctx->constants->ok_17859;
    bool ok_17938 = ctx->constants->ok_17938;
    bool x_27518 = ctx->constants->x_27518;
    bool x_27521 = ctx->constants->x_27521;
    bool x_27527 = ctx->constants->x_27527;
    bool x_27533 = ctx->constants->x_27533;
    bool prim_out_39448;
    
    prim_out_39448 = ok_17938;
    *out_prim_out_39674 = prim_out_39448;
    
  cleanup:
    { }
    return err;
}
FUTHARK_FUN_ATTR int futrts_entry_test_merge_tree(struct futhark_context *ctx, bool *out_prim_out_39675)
{
    (void) ctx;
    
    int err = 0;
    bool ok_17775 = ctx->constants->ok_17775;
    bool ok_17859 = ctx->constants->ok_17859;
    bool ok_17938 = ctx->constants->ok_17938;
    bool x_27518 = ctx->constants->x_27518;
    bool x_27521 = ctx->constants->x_27521;
    bool x_27527 = ctx->constants->x_27527;
    bool x_27533 = ctx->constants->x_27533;
    bool prim_out_39448;
    
    prim_out_39448 = ok_17859;
    *out_prim_out_39675 = prim_out_39448;
    
  cleanup:
    { }
    return err;
}
FUTHARK_FUN_ATTR int futrts_entry_test_parent_chain4_root0_simple(struct futhark_context *ctx, bool *out_prim_out_39676, struct memblock parent_mem_39192, struct memblock data_mem_39193)
{
    (void) ctx;
    
    int err = 0;
    int64_t mem_39198_cached_sizze_39677 = 0;
    unsigned char *mem_39198 = NULL;
    int64_t mem_39200_cached_sizze_39678 = 0;
    unsigned char *mem_39200 = NULL;
    int64_t mem_39201_cached_sizze_39679 = 0;
    unsigned char *mem_39201 = NULL;
    int64_t mem_39202_cached_sizze_39680 = 0;
    unsigned char *mem_39202 = NULL;
    int64_t mem_39209_cached_sizze_39681 = 0;
    unsigned char *mem_39209 = NULL;
    int64_t mem_39216_cached_sizze_39682 = 0;
    unsigned char *mem_39216 = NULL;
    struct memblock ext_mem_39199;
    
    ext_mem_39199.references = NULL;
    
    struct memblock ext_mem_39197;
    
    ext_mem_39197.references = NULL;
    
    struct memblock ext_mem_39194;
    
    ext_mem_39194.references = NULL;
    
    struct memblock ext_mem_39195;
    
    ext_mem_39195.references = NULL;
    
    struct memblock ext_mem_39196;
    
    ext_mem_39196.references = NULL;
    
    bool ok_17775 = ctx->constants->ok_17775;
    bool ok_17859 = ctx->constants->ok_17859;
    bool ok_17938 = ctx->constants->ok_17938;
    bool x_27518 = ctx->constants->x_27518;
    bool x_27521 = ctx->constants->x_27521;
    bool x_27527 = ctx->constants->x_27527;
    bool x_27533 = ctx->constants->x_27533;
    bool prim_out_39448;
    
    // test_operations.fut:213:11-36
    if (futrts_from_parent_9285(ctx, &ext_mem_39196, &ext_mem_39195, &ext_mem_39194, parent_mem_39192, data_mem_39193, (int64_t) 4) != 0) {
        err = 1;
        goto cleanup;
    }
    // test_operations.fut:213:7-214:22
    if (futrts_depth_9287(ctx, &ext_mem_39197, ext_mem_39196, ext_mem_39195, ext_mem_39194, (int64_t) 4) != 0) {
        err = 1;
        goto cleanup;
    }
    // test_operations.fut:214:6-220:63
    if (mem_39198_cached_sizze_39677 < (int64_t) 32) {
        err = lexical_realloc(ctx, &mem_39198, &mem_39198_cached_sizze_39677, (int64_t) 32);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // test_operations.fut:214:6-220:63
    
    struct memblock test_parent_chain4_root0_simplezistatic_array_39449 = (struct memblock) {NULL, (unsigned char *) test_parent_chain4_root0_simplezistatic_array_realtype_39683, 0, "test_parent_chain4_root0_simple.static_array_39449"};
    
    // test_operations.fut:214:6-220:63
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_39198, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) test_parent_chain4_root0_simplezistatic_array_39449.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 4});
    // test_operations.fut:192:29-49
    
    bool defunc_0_reduce_res_35633;
    bool redout_38511 = 1;
    
    for (int64_t i_38512 = 0; i_38512 < (int64_t) 4; i_38512++) {
        int64_t eta_p_35361 = ((int64_t *) ext_mem_39197.mem)[i_38512];
        int64_t eta_p_35362 = ((int64_t *) mem_39198)[i_38512];
        
        // test_operations.fut:192:39-43
        
        bool defunc_0_f_res_35363 = eta_p_35361 == eta_p_35362;
        
        // test_operations.fut:192:29-49
        
        bool x_29979 = defunc_0_f_res_35363 && redout_38511;
        bool redout_tmp_39450 = x_29979;
        
        redout_38511 = redout_tmp_39450;
    }
    defunc_0_reduce_res_35633 = redout_38511;
    if (memblock_unref(ctx, &ext_mem_39197, "ext_mem_39197") != 0)
        return 1;
    // test_operations.fut:214:6-220:63
    
    bool cond_29980;
    
    if (defunc_0_reduce_res_35633) {
        // test_operations.fut:213:7-215:31
        if (futrts_subtree_sizzes_9289(ctx, &ext_mem_39199, ext_mem_39196, ext_mem_39195, ext_mem_39194, (int64_t) 4) != 0) {
            err = 1;
            goto cleanup;
        }
        // test_operations.fut:215:9-61
        if (mem_39200_cached_sizze_39678 < (int64_t) 32) {
            err = lexical_realloc(ctx, &mem_39200, &mem_39200_cached_sizze_39678, (int64_t) 32);
            if (err != FUTHARK_SUCCESS)
                goto cleanup;
        }
        // test_operations.fut:215:9-61
        
        struct memblock test_parent_chain4_root0_simplezistatic_array_39451 = (struct memblock) {NULL, (unsigned char *) test_parent_chain4_root0_simplezistatic_array_realtype_39684, 0, "test_parent_chain4_root0_simple.static_array_39451"};
        
        // test_operations.fut:215:9-61
        lmad_copy_8b(ctx, 1, (uint64_t *) mem_39200, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) test_parent_chain4_root0_simplezistatic_array_39451.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 4});
        // test_operations.fut:192:29-49
        
        bool defunc_0_reduce_res_35539;
        bool redout_38513 = 1;
        
        for (int64_t i_38514 = 0; i_38514 < (int64_t) 4; i_38514++) {
            int64_t eta_p_35540 = ((int64_t *) ext_mem_39199.mem)[i_38514];
            int64_t eta_p_35541 = ((int64_t *) mem_39200)[i_38514];
            
            // test_operations.fut:192:39-43
            
            bool defunc_0_f_res_35542 = eta_p_35540 == eta_p_35541;
            
            // test_operations.fut:192:29-49
            
            bool x_35545 = defunc_0_f_res_35542 && redout_38513;
            bool redout_tmp_39452 = x_35545;
            
            redout_38513 = redout_tmp_39452;
        }
        defunc_0_reduce_res_35539 = redout_38513;
        if (memblock_unref(ctx, &ext_mem_39199, "ext_mem_39199") != 0)
            return 1;
        cond_29980 = defunc_0_reduce_res_35539;
    } else {
        cond_29980 = 0;
    }
    // test_operations.fut:214:6-220:63
    
    bool test_parent_chain4_root0_simple_res_29992;
    
    if (cond_29980) {
        // ../lib/github.com/diku-dk/vtree/vtree.fut:214:13-33
        if (mem_39201_cached_sizze_39679 < (int64_t) 64) {
            err = lexical_realloc(ctx, &mem_39201, &mem_39201_cached_sizze_39679, (int64_t) 64);
            if (err != FUTHARK_SUCCESS)
                goto cleanup;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:214:13-33
        for (int64_t nest_i_39453 = 0; nest_i_39453 < (int64_t) 8; nest_i_39453++) {
            ((int64_t *) mem_39201)[nest_i_39453] = (int64_t) 0;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:215:13-30
        
        bool acc_cert_35580;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:215:13-30
        for (int64_t i_38516 = 0; i_38516 < (int64_t) 4; i_38516++) {
            int64_t v_35584 = ((int64_t *) ext_mem_39195.mem)[i_38516];
            int64_t v_35585 = ((int64_t *) ext_mem_39196.mem)[i_38516];
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:215:13-30
            // UpdateAcc
            if (sle64((int64_t) 0, v_35584) && slt64(v_35584, (int64_t) 8)) {
                ((int64_t *) mem_39201)[v_35584] = v_35585;
            }
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:216:13-39
        
        bool acc_cert_35590;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:216:13-39
        for (int64_t i_38518 = 0; i_38518 < (int64_t) 4; i_38518++) {
            int64_t eta_p_35594 = ((int64_t *) ext_mem_39196.mem)[i_38518];
            int64_t v_35596 = ((int64_t *) ext_mem_39194.mem)[i_38518];
            
            // test_operations.fut:187:21-28
            
            int64_t neg_res_35597 = -eta_p_35594;
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:216:13-39
            // UpdateAcc
            if (sle64((int64_t) 0, v_35596) && slt64(v_35596, (int64_t) 8)) {
                ((int64_t *) mem_39201)[v_35596] = neg_res_35597;
            }
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:136:24-36
        if (mem_39202_cached_sizze_39680 < (int64_t) 64) {
            err = lexical_realloc(ctx, &mem_39202, &mem_39202_cached_sizze_39680, (int64_t) 64);
            if (err != FUTHARK_SUCCESS)
                goto cleanup;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:136:24-36
        
        int64_t discard_38524;
        int64_t scanacc_38520 = (int64_t) 0;
        
        for (int64_t i_38522 = 0; i_38522 < (int64_t) 8; i_38522++) {
            int64_t x_35602 = ((int64_t *) mem_39201)[i_38522];
            
            // test_operations.fut:187:13-20
            
            int64_t zp_res_35605 = add64(x_35602, scanacc_38520);
            
            ((int64_t *) mem_39202)[i_38522] = zp_res_35605;
            
            int64_t scanacc_tmp_39456 = zp_res_35605;
            
            scanacc_38520 = scanacc_tmp_39456;
        }
        discard_38524 = scanacc_38520;
        // ../lib/github.com/diku-dk/vtree/vtree.fut:134:5-136:37
        if (mem_39209_cached_sizze_39681 < (int64_t) 64) {
            err = lexical_realloc(ctx, &mem_39209, &mem_39209_cached_sizze_39681, (int64_t) 64);
            if (err != FUTHARK_SUCCESS)
                goto cleanup;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:134:5-136:37
        for (int64_t i_38527 = 0; i_38527 < (int64_t) 8; i_38527++) {
            // ../lib/github.com/diku-dk/vtree/vtree.fut:136:11-36
            
            int64_t zv_lhs_35611 = add64((int64_t) -1, i_38527);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:136:11-36
            
            int64_t tmp_35612 = smod64(zv_lhs_35611, (int64_t) 8);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:136:11-36
            
            int64_t lifted_lambda_res_35613 = ((int64_t *) mem_39202)[tmp_35612];
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:134:19-43
            
            bool cond_35614 = i_38527 == (int64_t) 0;
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:134:19-43
            
            int64_t lifted_lambda_res_35615;
            
            if (cond_35614) {
                lifted_lambda_res_35615 = (int64_t) 0;
            } else {
                lifted_lambda_res_35615 = lifted_lambda_res_35613;
            }
            ((int64_t *) mem_39209)[i_38527] = lifted_lambda_res_35615;
        }
        // test_operations.fut:220:9-63
        if (mem_39216_cached_sizze_39682 < (int64_t) 32) {
            err = lexical_realloc(ctx, &mem_39216, &mem_39216_cached_sizze_39682, (int64_t) 32);
            if (err != FUTHARK_SUCCESS)
                goto cleanup;
        }
        // test_operations.fut:220:9-63
        
        struct memblock test_parent_chain4_root0_simplezistatic_array_39459 = (struct memblock) {NULL, (unsigned char *) test_parent_chain4_root0_simplezistatic_array_realtype_39685, 0, "test_parent_chain4_root0_simple.static_array_39459"};
        
        // test_operations.fut:220:9-63
        lmad_copy_8b(ctx, 1, (uint64_t *) mem_39216, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) test_parent_chain4_root0_simplezistatic_array_39459.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 4});
        // test_operations.fut:192:29-49
        
        bool defunc_0_reduce_res_35619;
        bool redout_38529 = 1;
        
        for (int64_t i_38530 = 0; i_38530 < (int64_t) 4; i_38530++) {
            int64_t eta_p_35620 = ((int64_t *) ext_mem_39195.mem)[i_38530];
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:218:19-23
            
            bool x_35622 = sle64((int64_t) 0, eta_p_35620);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:218:19-23
            
            bool y_35623 = slt64(eta_p_35620, (int64_t) 8);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:218:19-23
            
            bool bounds_check_35624 = x_35622 && y_35623;
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:218:19-23
            
            bool index_certs_35625;
            
            if (!bounds_check_35624) {
                set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) eta_p_35620, "] out of bounds for array of shape [", (long long) (int64_t) 8, "].", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:218:19-23\n   #1  test_operations.fut:186:20-187:12\n   #2  test_operations.fut:213:7-220:27\n"));
                err = FUTHARK_PROGRAM_ERROR;
                goto cleanup;
            }
            
            int64_t eta_p_35621 = ((int64_t *) mem_39216)[i_38530];
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:218:19-23
            
            int64_t lifted_lambda_res_35626 = ((int64_t *) mem_39209)[eta_p_35620];
            
            // test_operations.fut:192:39-43
            
            bool defunc_0_f_res_35627 = lifted_lambda_res_35626 == eta_p_35621;
            
            // test_operations.fut:192:29-49
            
            bool x_35630 = defunc_0_f_res_35627 && redout_38529;
            bool redout_tmp_39460 = x_35630;
            
            redout_38529 = redout_tmp_39460;
        }
        defunc_0_reduce_res_35619 = redout_38529;
        test_parent_chain4_root0_simple_res_29992 = defunc_0_reduce_res_35619;
    } else {
        test_parent_chain4_root0_simple_res_29992 = 0;
    }
    if (memblock_unref(ctx, &ext_mem_39194, "ext_mem_39194") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_39195, "ext_mem_39195") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_39196, "ext_mem_39196") != 0)
        return 1;
    prim_out_39448 = test_parent_chain4_root0_simple_res_29992;
    *out_prim_out_39676 = prim_out_39448;
    
  cleanup:
    {
        free(mem_39198);
        free(mem_39200);
        free(mem_39201);
        free(mem_39202);
        free(mem_39209);
        free(mem_39216);
        if (memblock_unref(ctx, &ext_mem_39199, "ext_mem_39199") != 0)
            return 1;
        if (memblock_unref(ctx, &ext_mem_39197, "ext_mem_39197") != 0)
            return 1;
        if (memblock_unref(ctx, &ext_mem_39194, "ext_mem_39194") != 0)
            return 1;
        if (memblock_unref(ctx, &ext_mem_39195, "ext_mem_39195") != 0)
            return 1;
        if (memblock_unref(ctx, &ext_mem_39196, "ext_mem_39196") != 0)
            return 1;
    }
    return err;
}
FUTHARK_FUN_ATTR int futrts_entry_test_parent_singleton_simple(struct futhark_context *ctx, bool *out_prim_out_39686, struct memblock parent_mem_39192, struct memblock data_mem_39193)
{
    (void) ctx;
    
    int err = 0;
    int64_t mem_39198_cached_sizze_39687 = 0;
    unsigned char *mem_39198 = NULL;
    int64_t mem_39200_cached_sizze_39688 = 0;
    unsigned char *mem_39200 = NULL;
    int64_t mem_39201_cached_sizze_39689 = 0;
    unsigned char *mem_39201 = NULL;
    int64_t mem_39202_cached_sizze_39690 = 0;
    unsigned char *mem_39202 = NULL;
    int64_t mem_39209_cached_sizze_39691 = 0;
    unsigned char *mem_39209 = NULL;
    struct memblock ext_mem_39199;
    
    ext_mem_39199.references = NULL;
    
    struct memblock ext_mem_39197;
    
    ext_mem_39197.references = NULL;
    
    struct memblock ext_mem_39194;
    
    ext_mem_39194.references = NULL;
    
    struct memblock ext_mem_39195;
    
    ext_mem_39195.references = NULL;
    
    struct memblock ext_mem_39196;
    
    ext_mem_39196.references = NULL;
    
    bool ok_17775 = ctx->constants->ok_17775;
    bool ok_17859 = ctx->constants->ok_17859;
    bool ok_17938 = ctx->constants->ok_17938;
    bool x_27518 = ctx->constants->x_27518;
    bool x_27521 = ctx->constants->x_27521;
    bool x_27527 = ctx->constants->x_27527;
    bool x_27533 = ctx->constants->x_27533;
    bool prim_out_39448;
    
    // test_operations.fut:201:11-36
    if (futrts_from_parent_9285(ctx, &ext_mem_39196, &ext_mem_39195, &ext_mem_39194, parent_mem_39192, data_mem_39193, (int64_t) 1) != 0) {
        err = 1;
        goto cleanup;
    }
    // test_operations.fut:201:7-202:22
    if (futrts_depth_9287(ctx, &ext_mem_39197, ext_mem_39196, ext_mem_39195, ext_mem_39194, (int64_t) 1) != 0) {
        err = 1;
        goto cleanup;
    }
    // test_operations.fut:202:6-204:37
    if (mem_39198_cached_sizze_39687 < (int64_t) 8) {
        err = lexical_realloc(ctx, &mem_39198, &mem_39198_cached_sizze_39687, (int64_t) 8);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // test_operations.fut:202:6-204:37
    
    struct memblock test_parent_singleton_simplezistatic_array_39449 = (struct memblock) {NULL, (unsigned char *) test_parent_singleton_simplezistatic_array_realtype_39692, 0, "test_parent_singleton_simple.static_array_39449"};
    
    // test_operations.fut:202:6-204:37
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_39198, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) test_parent_singleton_simplezistatic_array_39449.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 1});
    
    int64_t eta_p_29971 = ((int64_t *) ext_mem_39197.mem)[(int64_t) 0];
    
    if (memblock_unref(ctx, &ext_mem_39197, "ext_mem_39197") != 0)
        return 1;
    
    int64_t eta_p_29972 = ((int64_t *) mem_39198)[(int64_t) 0];
    
    // test_operations.fut:192:39-43
    
    bool defunc_0_f_res_29973 = eta_p_29971 == eta_p_29972;
    
    // test_operations.fut:202:6-204:37
    
    bool cond_29974;
    
    if (defunc_0_f_res_29973) {
        // test_operations.fut:201:7-203:31
        if (futrts_subtree_sizzes_9289(ctx, &ext_mem_39199, ext_mem_39196, ext_mem_39195, ext_mem_39194, (int64_t) 1) != 0) {
            err = 1;
            goto cleanup;
        }
        // test_operations.fut:203:9-41
        if (mem_39200_cached_sizze_39688 < (int64_t) 8) {
            err = lexical_realloc(ctx, &mem_39200, &mem_39200_cached_sizze_39688, (int64_t) 8);
            if (err != FUTHARK_SUCCESS)
                goto cleanup;
        }
        // test_operations.fut:203:9-41
        
        struct memblock test_parent_singleton_simplezistatic_array_39450 = (struct memblock) {NULL, (unsigned char *) test_parent_singleton_simplezistatic_array_realtype_39693, 0, "test_parent_singleton_simple.static_array_39450"};
        
        // test_operations.fut:203:9-41
        lmad_copy_8b(ctx, 1, (uint64_t *) mem_39200, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) test_parent_singleton_simplezistatic_array_39450.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 1});
        
        int64_t eta_p_35422 = ((int64_t *) ext_mem_39199.mem)[(int64_t) 0];
        
        if (memblock_unref(ctx, &ext_mem_39199, "ext_mem_39199") != 0)
            return 1;
        
        int64_t eta_p_35423 = ((int64_t *) mem_39200)[(int64_t) 0];
        
        // test_operations.fut:192:39-43
        
        bool defunc_0_f_res_35424 = eta_p_35422 == eta_p_35423;
        
        cond_29974 = defunc_0_f_res_35424;
    } else {
        cond_29974 = 0;
    }
    // test_operations.fut:202:6-204:37
    
    bool test_parent_singleton_simple_res_29980;
    
    if (cond_29974) {
        int64_t v_35433 = ((int64_t *) ext_mem_39195.mem)[(int64_t) 0];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:218:19-23
        
        bool x_35462 = sle64((int64_t) 0, v_35433);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:218:19-23
        
        bool y_35463 = slt64(v_35433, (int64_t) 2);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:218:19-23
        
        bool bounds_check_35464 = x_35462 && y_35463;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:218:19-23
        
        bool index_certs_35465;
        
        if (!bounds_check_35464) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) v_35433, "] out of bounds for array of shape [", (long long) (int64_t) 2, "].", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:218:19-23\n   #1  test_operations.fut:186:20-187:12\n   #2  test_operations.fut:201:7-204:27\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:214:13-33
        if (mem_39201_cached_sizze_39689 < (int64_t) 16) {
            err = lexical_realloc(ctx, &mem_39201, &mem_39201_cached_sizze_39689, (int64_t) 16);
            if (err != FUTHARK_SUCCESS)
                goto cleanup;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:214:13-33
        for (int64_t nest_i_39451 = 0; nest_i_39451 < (int64_t) 2; nest_i_39451++) {
            ((int64_t *) mem_39201)[nest_i_39451] = (int64_t) 0;
        }
        
        int64_t v_35434 = ((int64_t *) ext_mem_39196.mem)[(int64_t) 0];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:215:13-30
        
        bool acc_cert_35436;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:215:13-30
        // UpdateAcc
        if (sle64((int64_t) 0, v_35433) && slt64(v_35433, (int64_t) 2)) {
            ((int64_t *) mem_39201)[v_35433] = v_35434;
        }
        // test_operations.fut:187:21-28
        
        int64_t neg_res_35439 = -v_35434;
        int64_t v_35440 = ((int64_t *) ext_mem_39194.mem)[(int64_t) 0];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:216:13-39
        
        bool acc_cert_35442;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:216:13-39
        // UpdateAcc
        if (sle64((int64_t) 0, v_35440) && slt64(v_35440, (int64_t) 2)) {
            ((int64_t *) mem_39201)[v_35440] = neg_res_35439;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:136:24-36
        if (mem_39202_cached_sizze_39690 < (int64_t) 16) {
            err = lexical_realloc(ctx, &mem_39202, &mem_39202_cached_sizze_39690, (int64_t) 16);
            if (err != FUTHARK_SUCCESS)
                goto cleanup;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:136:24-36
        
        int64_t discard_38516;
        int64_t scanacc_38512 = (int64_t) 0;
        
        for (int64_t i_38514 = 0; i_38514 < (int64_t) 2; i_38514++) {
            int64_t x_35446 = ((int64_t *) mem_39201)[i_38514];
            
            // test_operations.fut:187:13-20
            
            int64_t zp_res_35449 = add64(x_35446, scanacc_38512);
            
            ((int64_t *) mem_39202)[i_38514] = zp_res_35449;
            
            int64_t scanacc_tmp_39452 = zp_res_35449;
            
            scanacc_38512 = scanacc_tmp_39452;
        }
        discard_38516 = scanacc_38512;
        // ../lib/github.com/diku-dk/vtree/vtree.fut:134:5-136:37
        if (mem_39209_cached_sizze_39691 < (int64_t) 16) {
            err = lexical_realloc(ctx, &mem_39209, &mem_39209_cached_sizze_39691, (int64_t) 16);
            if (err != FUTHARK_SUCCESS)
                goto cleanup;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:134:5-136:37
        for (int64_t i_38519 = 0; i_38519 < (int64_t) 2; i_38519++) {
            // ../lib/github.com/diku-dk/vtree/vtree.fut:136:11-36
            
            int64_t zv_lhs_35455 = add64((int64_t) -1, i_38519);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:136:11-36
            
            int64_t tmp_35456 = smod64(zv_lhs_35455, (int64_t) 2);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:136:11-36
            
            int64_t lifted_lambda_res_35457 = ((int64_t *) mem_39202)[tmp_35456];
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:134:19-43
            
            bool cond_35458 = i_38519 == (int64_t) 0;
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:134:19-43
            
            int64_t lifted_lambda_res_35459;
            
            if (cond_35458) {
                lifted_lambda_res_35459 = (int64_t) 0;
            } else {
                lifted_lambda_res_35459 = lifted_lambda_res_35457;
            }
            ((int64_t *) mem_39209)[i_38519] = lifted_lambda_res_35459;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:218:19-23
        
        int64_t lifted_lambda_res_35466 = ((int64_t *) mem_39209)[v_35433];
        
        // test_operations.fut:192:39-43
        
        bool defunc_0_f_res_35467 = lifted_lambda_res_35466 == eta_p_29972;
        
        test_parent_singleton_simple_res_29980 = defunc_0_f_res_35467;
    } else {
        test_parent_singleton_simple_res_29980 = 0;
    }
    if (memblock_unref(ctx, &ext_mem_39194, "ext_mem_39194") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_39195, "ext_mem_39195") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_39196, "ext_mem_39196") != 0)
        return 1;
    prim_out_39448 = test_parent_singleton_simple_res_29980;
    *out_prim_out_39686 = prim_out_39448;
    
  cleanup:
    {
        free(mem_39198);
        free(mem_39200);
        free(mem_39201);
        free(mem_39202);
        free(mem_39209);
        if (memblock_unref(ctx, &ext_mem_39199, "ext_mem_39199") != 0)
            return 1;
        if (memblock_unref(ctx, &ext_mem_39197, "ext_mem_39197") != 0)
            return 1;
        if (memblock_unref(ctx, &ext_mem_39194, "ext_mem_39194") != 0)
            return 1;
        if (memblock_unref(ctx, &ext_mem_39195, "ext_mem_39195") != 0)
            return 1;
        if (memblock_unref(ctx, &ext_mem_39196, "ext_mem_39196") != 0)
            return 1;
    }
    return err;
}
FUTHARK_FUN_ATTR int futrts_entry_test_parent_star5_root3_simple(struct futhark_context *ctx, bool *out_prim_out_39694, struct memblock parent_mem_39192, struct memblock data_mem_39193)
{
    (void) ctx;
    
    int err = 0;
    int64_t mem_39198_cached_sizze_39695 = 0;
    unsigned char *mem_39198 = NULL;
    int64_t mem_39200_cached_sizze_39696 = 0;
    unsigned char *mem_39200 = NULL;
    int64_t mem_39201_cached_sizze_39697 = 0;
    unsigned char *mem_39201 = NULL;
    int64_t mem_39202_cached_sizze_39698 = 0;
    unsigned char *mem_39202 = NULL;
    int64_t mem_39209_cached_sizze_39699 = 0;
    unsigned char *mem_39209 = NULL;
    int64_t mem_39216_cached_sizze_39700 = 0;
    unsigned char *mem_39216 = NULL;
    struct memblock ext_mem_39199;
    
    ext_mem_39199.references = NULL;
    
    struct memblock ext_mem_39197;
    
    ext_mem_39197.references = NULL;
    
    struct memblock ext_mem_39194;
    
    ext_mem_39194.references = NULL;
    
    struct memblock ext_mem_39195;
    
    ext_mem_39195.references = NULL;
    
    struct memblock ext_mem_39196;
    
    ext_mem_39196.references = NULL;
    
    bool ok_17775 = ctx->constants->ok_17775;
    bool ok_17859 = ctx->constants->ok_17859;
    bool ok_17938 = ctx->constants->ok_17938;
    bool x_27518 = ctx->constants->x_27518;
    bool x_27521 = ctx->constants->x_27521;
    bool x_27527 = ctx->constants->x_27527;
    bool x_27533 = ctx->constants->x_27533;
    bool prim_out_39448;
    
    // test_operations.fut:229:11-36
    if (futrts_from_parent_9285(ctx, &ext_mem_39196, &ext_mem_39195, &ext_mem_39194, parent_mem_39192, data_mem_39193, (int64_t) 5) != 0) {
        err = 1;
        goto cleanup;
    }
    // test_operations.fut:229:7-230:22
    if (futrts_depth_9287(ctx, &ext_mem_39197, ext_mem_39196, ext_mem_39195, ext_mem_39194, (int64_t) 5) != 0) {
        err = 1;
        goto cleanup;
    }
    // test_operations.fut:230:6-233:71
    if (mem_39198_cached_sizze_39695 < (int64_t) 40) {
        err = lexical_realloc(ctx, &mem_39198, &mem_39198_cached_sizze_39695, (int64_t) 40);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // test_operations.fut:230:6-233:71
    
    struct memblock test_parent_star5_root3_simplezistatic_array_39449 = (struct memblock) {NULL, (unsigned char *) test_parent_star5_root3_simplezistatic_array_realtype_39701, 0, "test_parent_star5_root3_simple.static_array_39449"};
    
    // test_operations.fut:230:6-233:71
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_39198, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) test_parent_star5_root3_simplezistatic_array_39449.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 5});
    // test_operations.fut:192:29-49
    
    bool defunc_0_reduce_res_35633;
    bool redout_38511 = 1;
    
    for (int64_t i_38512 = 0; i_38512 < (int64_t) 5; i_38512++) {
        int64_t eta_p_35361 = ((int64_t *) ext_mem_39197.mem)[i_38512];
        int64_t eta_p_35362 = ((int64_t *) mem_39198)[i_38512];
        
        // test_operations.fut:192:39-43
        
        bool defunc_0_f_res_35363 = eta_p_35361 == eta_p_35362;
        
        // test_operations.fut:192:29-49
        
        bool x_29979 = defunc_0_f_res_35363 && redout_38511;
        bool redout_tmp_39450 = x_29979;
        
        redout_38511 = redout_tmp_39450;
    }
    defunc_0_reduce_res_35633 = redout_38511;
    if (memblock_unref(ctx, &ext_mem_39197, "ext_mem_39197") != 0)
        return 1;
    // test_operations.fut:230:6-233:71
    
    bool cond_29980;
    
    if (defunc_0_reduce_res_35633) {
        // test_operations.fut:229:7-231:31
        if (futrts_subtree_sizzes_9289(ctx, &ext_mem_39199, ext_mem_39196, ext_mem_39195, ext_mem_39194, (int64_t) 5) != 0) {
            err = 1;
            goto cleanup;
        }
        // test_operations.fut:231:9-67
        if (mem_39200_cached_sizze_39696 < (int64_t) 40) {
            err = lexical_realloc(ctx, &mem_39200, &mem_39200_cached_sizze_39696, (int64_t) 40);
            if (err != FUTHARK_SUCCESS)
                goto cleanup;
        }
        // test_operations.fut:231:9-67
        
        struct memblock test_parent_star5_root3_simplezistatic_array_39451 = (struct memblock) {NULL, (unsigned char *) test_parent_star5_root3_simplezistatic_array_realtype_39702, 0, "test_parent_star5_root3_simple.static_array_39451"};
        
        // test_operations.fut:231:9-67
        lmad_copy_8b(ctx, 1, (uint64_t *) mem_39200, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) test_parent_star5_root3_simplezistatic_array_39451.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 5});
        // test_operations.fut:192:29-49
        
        bool defunc_0_reduce_res_35539;
        bool redout_38513 = 1;
        
        for (int64_t i_38514 = 0; i_38514 < (int64_t) 5; i_38514++) {
            int64_t eta_p_35540 = ((int64_t *) ext_mem_39199.mem)[i_38514];
            int64_t eta_p_35541 = ((int64_t *) mem_39200)[i_38514];
            
            // test_operations.fut:192:39-43
            
            bool defunc_0_f_res_35542 = eta_p_35540 == eta_p_35541;
            
            // test_operations.fut:192:29-49
            
            bool x_35545 = defunc_0_f_res_35542 && redout_38513;
            bool redout_tmp_39452 = x_35545;
            
            redout_38513 = redout_tmp_39452;
        }
        defunc_0_reduce_res_35539 = redout_38513;
        if (memblock_unref(ctx, &ext_mem_39199, "ext_mem_39199") != 0)
            return 1;
        cond_29980 = defunc_0_reduce_res_35539;
    } else {
        cond_29980 = 0;
    }
    // test_operations.fut:230:6-233:71
    
    bool test_parent_star5_root3_simple_res_29992;
    
    if (cond_29980) {
        // ../lib/github.com/diku-dk/vtree/vtree.fut:214:13-33
        if (mem_39201_cached_sizze_39697 < (int64_t) 80) {
            err = lexical_realloc(ctx, &mem_39201, &mem_39201_cached_sizze_39697, (int64_t) 80);
            if (err != FUTHARK_SUCCESS)
                goto cleanup;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:214:13-33
        for (int64_t nest_i_39453 = 0; nest_i_39453 < (int64_t) 10; nest_i_39453++) {
            ((int64_t *) mem_39201)[nest_i_39453] = (int64_t) 0;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:215:13-30
        
        bool acc_cert_35580;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:215:13-30
        for (int64_t i_38516 = 0; i_38516 < (int64_t) 5; i_38516++) {
            int64_t v_35584 = ((int64_t *) ext_mem_39195.mem)[i_38516];
            int64_t v_35585 = ((int64_t *) ext_mem_39196.mem)[i_38516];
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:215:13-30
            // UpdateAcc
            if (sle64((int64_t) 0, v_35584) && slt64(v_35584, (int64_t) 10)) {
                ((int64_t *) mem_39201)[v_35584] = v_35585;
            }
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:216:13-39
        
        bool acc_cert_35590;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:216:13-39
        for (int64_t i_38518 = 0; i_38518 < (int64_t) 5; i_38518++) {
            int64_t eta_p_35594 = ((int64_t *) ext_mem_39196.mem)[i_38518];
            int64_t v_35596 = ((int64_t *) ext_mem_39194.mem)[i_38518];
            
            // test_operations.fut:187:21-28
            
            int64_t neg_res_35597 = -eta_p_35594;
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:216:13-39
            // UpdateAcc
            if (sle64((int64_t) 0, v_35596) && slt64(v_35596, (int64_t) 10)) {
                ((int64_t *) mem_39201)[v_35596] = neg_res_35597;
            }
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:136:24-36
        if (mem_39202_cached_sizze_39698 < (int64_t) 80) {
            err = lexical_realloc(ctx, &mem_39202, &mem_39202_cached_sizze_39698, (int64_t) 80);
            if (err != FUTHARK_SUCCESS)
                goto cleanup;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:136:24-36
        
        int64_t discard_38524;
        int64_t scanacc_38520 = (int64_t) 0;
        
        for (int64_t i_38522 = 0; i_38522 < (int64_t) 10; i_38522++) {
            int64_t x_35602 = ((int64_t *) mem_39201)[i_38522];
            
            // test_operations.fut:187:13-20
            
            int64_t zp_res_35605 = add64(x_35602, scanacc_38520);
            
            ((int64_t *) mem_39202)[i_38522] = zp_res_35605;
            
            int64_t scanacc_tmp_39456 = zp_res_35605;
            
            scanacc_38520 = scanacc_tmp_39456;
        }
        discard_38524 = scanacc_38520;
        // ../lib/github.com/diku-dk/vtree/vtree.fut:134:5-136:37
        if (mem_39209_cached_sizze_39699 < (int64_t) 80) {
            err = lexical_realloc(ctx, &mem_39209, &mem_39209_cached_sizze_39699, (int64_t) 80);
            if (err != FUTHARK_SUCCESS)
                goto cleanup;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:134:5-136:37
        for (int64_t i_38527 = 0; i_38527 < (int64_t) 10; i_38527++) {
            // ../lib/github.com/diku-dk/vtree/vtree.fut:136:11-36
            
            int64_t zv_lhs_35611 = add64((int64_t) -1, i_38527);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:136:11-36
            
            int64_t tmp_35612 = smod64(zv_lhs_35611, (int64_t) 10);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:136:11-36
            
            int64_t lifted_lambda_res_35613 = ((int64_t *) mem_39202)[tmp_35612];
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:134:19-43
            
            bool cond_35614 = i_38527 == (int64_t) 0;
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:134:19-43
            
            int64_t lifted_lambda_res_35615;
            
            if (cond_35614) {
                lifted_lambda_res_35615 = (int64_t) 0;
            } else {
                lifted_lambda_res_35615 = lifted_lambda_res_35613;
            }
            ((int64_t *) mem_39209)[i_38527] = lifted_lambda_res_35615;
        }
        // test_operations.fut:233:9-71
        if (mem_39216_cached_sizze_39700 < (int64_t) 40) {
            err = lexical_realloc(ctx, &mem_39216, &mem_39216_cached_sizze_39700, (int64_t) 40);
            if (err != FUTHARK_SUCCESS)
                goto cleanup;
        }
        // test_operations.fut:233:9-71
        
        struct memblock test_parent_star5_root3_simplezistatic_array_39459 = (struct memblock) {NULL, (unsigned char *) test_parent_star5_root3_simplezistatic_array_realtype_39703, 0, "test_parent_star5_root3_simple.static_array_39459"};
        
        // test_operations.fut:233:9-71
        lmad_copy_8b(ctx, 1, (uint64_t *) mem_39216, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) test_parent_star5_root3_simplezistatic_array_39459.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {(int64_t) 5});
        // test_operations.fut:192:29-49
        
        bool defunc_0_reduce_res_35619;
        bool redout_38529 = 1;
        
        for (int64_t i_38530 = 0; i_38530 < (int64_t) 5; i_38530++) {
            int64_t eta_p_35620 = ((int64_t *) ext_mem_39195.mem)[i_38530];
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:218:19-23
            
            bool x_35622 = sle64((int64_t) 0, eta_p_35620);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:218:19-23
            
            bool y_35623 = slt64(eta_p_35620, (int64_t) 10);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:218:19-23
            
            bool bounds_check_35624 = x_35622 && y_35623;
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:218:19-23
            
            bool index_certs_35625;
            
            if (!bounds_check_35624) {
                set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) eta_p_35620, "] out of bounds for array of shape [", (long long) (int64_t) 10, "].", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:218:19-23\n   #1  test_operations.fut:186:20-187:12\n   #2  test_operations.fut:229:7-233:27\n"));
                err = FUTHARK_PROGRAM_ERROR;
                goto cleanup;
            }
            
            int64_t eta_p_35621 = ((int64_t *) mem_39216)[i_38530];
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:218:19-23
            
            int64_t lifted_lambda_res_35626 = ((int64_t *) mem_39209)[eta_p_35620];
            
            // test_operations.fut:192:39-43
            
            bool defunc_0_f_res_35627 = lifted_lambda_res_35626 == eta_p_35621;
            
            // test_operations.fut:192:29-49
            
            bool x_35630 = defunc_0_f_res_35627 && redout_38529;
            bool redout_tmp_39460 = x_35630;
            
            redout_38529 = redout_tmp_39460;
        }
        defunc_0_reduce_res_35619 = redout_38529;
        test_parent_star5_root3_simple_res_29992 = defunc_0_reduce_res_35619;
    } else {
        test_parent_star5_root3_simple_res_29992 = 0;
    }
    if (memblock_unref(ctx, &ext_mem_39194, "ext_mem_39194") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_39195, "ext_mem_39195") != 0)
        return 1;
    if (memblock_unref(ctx, &ext_mem_39196, "ext_mem_39196") != 0)
        return 1;
    prim_out_39448 = test_parent_star5_root3_simple_res_29992;
    *out_prim_out_39694 = prim_out_39448;
    
  cleanup:
    {
        free(mem_39198);
        free(mem_39200);
        free(mem_39201);
        free(mem_39202);
        free(mem_39209);
        free(mem_39216);
        if (memblock_unref(ctx, &ext_mem_39199, "ext_mem_39199") != 0)
            return 1;
        if (memblock_unref(ctx, &ext_mem_39197, "ext_mem_39197") != 0)
            return 1;
        if (memblock_unref(ctx, &ext_mem_39194, "ext_mem_39194") != 0)
            return 1;
        if (memblock_unref(ctx, &ext_mem_39195, "ext_mem_39195") != 0)
            return 1;
        if (memblock_unref(ctx, &ext_mem_39196, "ext_mem_39196") != 0)
            return 1;
    }
    return err;
}
FUTHARK_FUN_ATTR int futrts_entry_test_split(struct futhark_context *ctx, bool *out_prim_out_39704)
{
    (void) ctx;
    
    int err = 0;
    bool ok_17775 = ctx->constants->ok_17775;
    bool ok_17859 = ctx->constants->ok_17859;
    bool ok_17938 = ctx->constants->ok_17938;
    bool x_27518 = ctx->constants->x_27518;
    bool x_27521 = ctx->constants->x_27521;
    bool x_27527 = ctx->constants->x_27527;
    bool x_27533 = ctx->constants->x_27533;
    bool prim_out_39448;
    
    prim_out_39448 = x_27518;
    *out_prim_out_39704 = prim_out_39448;
    
  cleanup:
    { }
    return err;
}
FUTHARK_FUN_ATTR int futrts_entry_test_split_at_leaf(struct futhark_context *ctx, bool *out_prim_out_39705)
{
    (void) ctx;
    
    int err = 0;
    bool ok_17775 = ctx->constants->ok_17775;
    bool ok_17859 = ctx->constants->ok_17859;
    bool ok_17938 = ctx->constants->ok_17938;
    bool x_27518 = ctx->constants->x_27518;
    bool x_27521 = ctx->constants->x_27521;
    bool x_27527 = ctx->constants->x_27527;
    bool x_27533 = ctx->constants->x_27533;
    bool prim_out_39448;
    
    prim_out_39448 = x_27521;
    *out_prim_out_39705 = prim_out_39448;
    
  cleanup:
    { }
    return err;
}
FUTHARK_FUN_ATTR int futrts_entry_test_split_multiple(struct futhark_context *ctx, bool *out_prim_out_39706)
{
    (void) ctx;
    
    int err = 0;
    bool ok_17775 = ctx->constants->ok_17775;
    bool ok_17859 = ctx->constants->ok_17859;
    bool ok_17938 = ctx->constants->ok_17938;
    bool x_27518 = ctx->constants->x_27518;
    bool x_27521 = ctx->constants->x_27521;
    bool x_27527 = ctx->constants->x_27527;
    bool x_27533 = ctx->constants->x_27533;
    bool prim_out_39448;
    
    prim_out_39448 = x_27527;
    *out_prim_out_39706 = prim_out_39448;
    
  cleanup:
    { }
    return err;
}
FUTHARK_FUN_ATTR int futrts_entry_test_split_none(struct futhark_context *ctx, bool *out_prim_out_39707)
{
    (void) ctx;
    
    int err = 0;
    bool ok_17775 = ctx->constants->ok_17775;
    bool ok_17859 = ctx->constants->ok_17859;
    bool ok_17938 = ctx->constants->ok_17938;
    bool x_27518 = ctx->constants->x_27518;
    bool x_27521 = ctx->constants->x_27521;
    bool x_27527 = ctx->constants->x_27527;
    bool x_27533 = ctx->constants->x_27533;
    bool prim_out_39448;
    
    prim_out_39448 = x_27533;
    *out_prim_out_39707 = prim_out_39448;
    
  cleanup:
    { }
    return err;
}
FUTHARK_FUN_ATTR int futrts_from_parent_9285(struct futhark_context *ctx, struct memblock *mem_out_p_39708, struct memblock *mem_out_p_39709, struct memblock *mem_out_p_39710, struct memblock parent_mem_39192, struct memblock data_mem_39193, int64_t n_26458)
{
    (void) ctx;
    
    int err = 0;
    int64_t mem_39195_cached_sizze_39711 = 0;
    unsigned char *mem_39195 = NULL;
    int64_t mem_39197_cached_sizze_39712 = 0;
    unsigned char *mem_39197 = NULL;
    int64_t mem_39211_cached_sizze_39713 = 0;
    unsigned char *mem_39211 = NULL;
    int64_t mem_39221_cached_sizze_39714 = 0;
    unsigned char *mem_39221 = NULL;
    int64_t mem_39229_cached_sizze_39715 = 0;
    unsigned char *mem_39229 = NULL;
    int64_t mem_39231_cached_sizze_39716 = 0;
    unsigned char *mem_39231 = NULL;
    int64_t mem_39245_cached_sizze_39717 = 0;
    unsigned char *mem_39245 = NULL;
    int64_t mem_39247_cached_sizze_39718 = 0;
    unsigned char *mem_39247 = NULL;
    int64_t mem_39255_cached_sizze_39719 = 0;
    unsigned char *mem_39255 = NULL;
    int64_t mem_39257_cached_sizze_39720 = 0;
    unsigned char *mem_39257 = NULL;
    int64_t mem_39273_cached_sizze_39721 = 0;
    unsigned char *mem_39273 = NULL;
    int64_t mem_39275_cached_sizze_39722 = 0;
    unsigned char *mem_39275 = NULL;
    int64_t mem_39277_cached_sizze_39723 = 0;
    unsigned char *mem_39277 = NULL;
    int64_t mem_39279_cached_sizze_39724 = 0;
    unsigned char *mem_39279 = NULL;
    int64_t mem_39281_cached_sizze_39725 = 0;
    unsigned char *mem_39281 = NULL;
    int64_t mem_39323_cached_sizze_39726 = 0;
    unsigned char *mem_39323 = NULL;
    int64_t mem_39325_cached_sizze_39727 = 0;
    unsigned char *mem_39325 = NULL;
    int64_t mem_39339_cached_sizze_39728 = 0;
    unsigned char *mem_39339 = NULL;
    int64_t mem_39341_cached_sizze_39729 = 0;
    unsigned char *mem_39341 = NULL;
    int64_t mem_39343_cached_sizze_39730 = 0;
    unsigned char *mem_39343 = NULL;
    int64_t mem_39345_cached_sizze_39731 = 0;
    unsigned char *mem_39345 = NULL;
    int64_t mem_39359_cached_sizze_39732 = 0;
    unsigned char *mem_39359 = NULL;
    int64_t mem_39361_cached_sizze_39733 = 0;
    unsigned char *mem_39361 = NULL;
    int64_t mem_39363_cached_sizze_39734 = 0;
    unsigned char *mem_39363 = NULL;
    int64_t mem_39371_cached_sizze_39735 = 0;
    unsigned char *mem_39371 = NULL;
    struct memblock mem_39413;
    
    mem_39413.references = NULL;
    
    struct memblock mem_39411;
    
    mem_39411.references = NULL;
    
    struct memblock mem_param_tmp_39503;
    
    mem_param_tmp_39503.references = NULL;
    
    struct memblock mem_param_tmp_39502;
    
    mem_param_tmp_39502.references = NULL;
    
    struct memblock mem_39391;
    
    mem_39391.references = NULL;
    
    struct memblock mem_39389;
    
    mem_39389.references = NULL;
    
    struct memblock mem_param_39387;
    
    mem_param_39387.references = NULL;
    
    struct memblock mem_param_39384;
    
    mem_param_39384.references = NULL;
    
    struct memblock ext_mem_39408;
    
    ext_mem_39408.references = NULL;
    
    struct memblock ext_mem_39409;
    
    ext_mem_39409.references = NULL;
    
    struct memblock mem_39381;
    
    mem_39381.references = NULL;
    
    struct memblock mem_39379;
    
    mem_39379.references = NULL;
    
    struct memblock mem_param_tmp_39472;
    
    mem_param_tmp_39472.references = NULL;
    
    struct memblock mem_param_tmp_39471;
    
    mem_param_tmp_39471.references = NULL;
    
    struct memblock mem_39315;
    
    mem_39315.references = NULL;
    
    struct memblock mem_39313;
    
    mem_39313.references = NULL;
    
    struct memblock mem_param_39271;
    
    mem_param_39271.references = NULL;
    
    struct memblock mem_param_39268;
    
    mem_param_39268.references = NULL;
    
    struct memblock ext_mem_39320;
    
    ext_mem_39320.references = NULL;
    
    struct memblock ext_mem_39321;
    
    ext_mem_39321.references = NULL;
    
    struct memblock mem_39265;
    
    mem_39265.references = NULL;
    
    struct memblock mem_39213;
    
    mem_39213.references = NULL;
    
    struct memblock mem_39429;
    
    mem_39429.references = NULL;
    
    struct memblock mem_39427;
    
    mem_39427.references = NULL;
    
    struct memblock ext_mem_39432;
    
    ext_mem_39432.references = NULL;
    
    struct memblock ext_mem_39435;
    
    ext_mem_39435.references = NULL;
    
    struct memblock mem_out_39450;
    
    mem_out_39450.references = NULL;
    
    struct memblock mem_out_39449;
    
    mem_out_39449.references = NULL;
    
    struct memblock mem_out_39448;
    
    mem_out_39448.references = NULL;
    
    bool ok_17775 = ctx->constants->ok_17775;
    bool ok_17859 = ctx->constants->ok_17859;
    bool ok_17938 = ctx->constants->ok_17938;
    bool x_27518 = ctx->constants->x_27518;
    bool x_27521 = ctx->constants->x_27521;
    bool x_27527 = ctx->constants->x_27527;
    bool x_27533 = ctx->constants->x_27533;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:367:3-478:22
    
    bool cond_26461 = n_26458 == (int64_t) 1;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:376:7-39
    
    bool cond_28896 = n_26458 == (int64_t) 0;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:376:7-39
    
    int64_t tmp_28898 = sub64(n_26458, (int64_t) 1);
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:376:7-39
    
    bool x_28899 = sle64((int64_t) 0, tmp_28898);
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:376:7-39
    
    bool y_28900 = slt64(tmp_28898, n_26458);
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:376:7-39
    
    bool bounds_check_28901 = x_28899 && y_28900;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:376:7-39
    
    bool protect_assert_disj_28902 = cond_28896 || bounds_check_28901;
    bool protect_assert_disj_29959 = cond_26461 || protect_assert_disj_28902;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:376:7-39
    
    bool index_certs_28903;
    
    if (!protect_assert_disj_29959) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) tmp_28898, "] out of bounds for array of shape [", (long long) n_26458, "].", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:376:7-39\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:376:7-39
    
    bool x_28897 = !cond_28896;
    bool x_38855 = !cond_26461;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:371:7-373:49
    
    int64_t defunc_0_reduce_res_38136;
    
    if (x_38855) {
        int64_t x_38857;
        int64_t redout_38511 = (int64_t) 9223372036854775807;
        
        for (int64_t i_38512 = 0; i_38512 < n_26458; i_38512++) {
            int64_t eta_p_36845 = ((int64_t *) parent_mem_39192.mem)[i_38512];
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:371:21-54
            
            bool cond_36846 = eta_p_36845 == i_38512;
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:371:21-54
            
            int64_t lifted_lambda_res_36847;
            
            if (cond_36846) {
                lifted_lambda_res_36847 = i_38512;
            } else {
                lifted_lambda_res_36847 = (int64_t) 9223372036854775807;
            }
            // ../lib/github.com/diku-dk/vtree/vtree.fut:373:14-21
            
            int64_t min_res_28249 = smin64(lifted_lambda_res_36847, redout_38511);
            int64_t redout_tmp_39451 = min_res_28249;
            
            redout_38511 = redout_tmp_39451;
        }
        x_38857 = redout_38511;
        defunc_0_reduce_res_38136 = x_38857;
    } else {
        defunc_0_reduce_res_38136 = (int64_t) 0;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:376:7-39
    
    int64_t bytes_39194 = (int64_t) 8 * n_26458;
    
    if (cond_26461) {
        if (memblock_alloc(ctx, &mem_39427, bytes_39194, "mem_39427")) {
            err = 1;
            goto cleanup;
        }
        for (int64_t nest_i_39452 = 0; nest_i_39452 < n_26458; nest_i_39452++) {
            ((int64_t *) mem_39427.mem)[nest_i_39452] = (int64_t) 0;
        }
        if (memblock_alloc(ctx, &mem_39429, bytes_39194, "mem_39429")) {
            err = 1;
            goto cleanup;
        }
        for (int64_t nest_i_39453 = 0; nest_i_39453 < n_26458; nest_i_39453++) {
            ((int64_t *) mem_39429.mem)[nest_i_39453] = (int64_t) 1;
        }
        if (memblock_set(ctx, &ext_mem_39435, &mem_39427, "mem_39427") != 0)
            return 1;
        if (memblock_set(ctx, &ext_mem_39432, &mem_39429, "mem_39429") != 0)
            return 1;
    } else {
        // ../lib/github.com/diku-dk/vtree/vtree.fut:376:7-39
        if (mem_39195_cached_sizze_39711 < bytes_39194) {
            err = lexical_realloc(ctx, &mem_39195, &mem_39195_cached_sizze_39711, bytes_39194);
            if (err != FUTHARK_SUCCESS)
                goto cleanup;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:376:7-39
        if (mem_39197_cached_sizze_39712 < bytes_39194) {
            err = lexical_realloc(ctx, &mem_39197, &mem_39197_cached_sizze_39712, bytes_39194);
            if (err != FUTHARK_SUCCESS)
                goto cleanup;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:376:7-39
        
        int64_t discard_38521;
        int64_t scanacc_38515 = (int64_t) 0;
        
        for (int64_t i_38518 = 0; i_38518 < n_26458; i_38518++) {
            // ../lib/github.com/diku-dk/vtree/vtree.fut:376:23-30
            
            bool lifted_lambda_res_36839 = i_38518 == defunc_0_reduce_res_38136;
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:376:23-30
            
            bool lifted_lambda_res_36840 = !lifted_lambda_res_36839;
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:376:7-39
            
            int64_t defunc_0_f_res_36841 = btoi_bool_i64(lifted_lambda_res_36840);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:376:7-39
            
            int64_t defunc_0_op_res_28895 = add64(defunc_0_f_res_36841, scanacc_38515);
            
            ((int64_t *) mem_39195)[i_38518] = defunc_0_op_res_28895;
            ((int64_t *) mem_39197)[i_38518] = defunc_0_f_res_36841;
            
            int64_t scanacc_tmp_39454 = defunc_0_op_res_28895;
            
            scanacc_38515 = scanacc_tmp_39454;
        }
        discard_38521 = scanacc_38515;
        // ../lib/github.com/diku-dk/vtree/vtree.fut:376:7-39
        
        int64_t m_f_res_28904;
        
        if (x_28897) {
            // ../lib/github.com/diku-dk/vtree/vtree.fut:376:7-39
            
            int64_t x_38094 = ((int64_t *) mem_39195)[tmp_28898];
            
            m_f_res_28904 = x_38094;
        } else {
            m_f_res_28904 = (int64_t) 0;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:376:7-39
        
        int64_t m_28906;
        
        if (cond_28896) {
            m_28906 = (int64_t) 0;
        } else {
            m_28906 = m_f_res_28904;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:376:7-39
        
        int64_t bytes_39210 = (int64_t) 8 * m_28906;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:376:7-39
        if (mem_39211_cached_sizze_39713 < bytes_39210) {
            err = lexical_realloc(ctx, &mem_39211, &mem_39211_cached_sizze_39713, bytes_39210);
            if (err != FUTHARK_SUCCESS)
                goto cleanup;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:376:7-39
        
        bool acc_cert_36809;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:376:7-39
        for (int64_t i_38523 = 0; i_38523 < n_26458; i_38523++) {
            int64_t eta_p_36824 = ((int64_t *) mem_39197)[i_38523];
            int64_t eta_p_36825 = ((int64_t *) mem_39195)[i_38523];
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:376:7-39
            
            bool cond_36828 = eta_p_36824 == (int64_t) 1;
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:376:7-39
            
            int64_t lifted_lambda_res_36829;
            
            if (cond_36828) {
                // ../lib/github.com/diku-dk/vtree/vtree.fut:376:7-39
                
                int64_t lifted_lambda_res_t_res_38095 = sub64(eta_p_36825, (int64_t) 1);
                
                lifted_lambda_res_36829 = lifted_lambda_res_t_res_38095;
            } else {
                lifted_lambda_res_36829 = (int64_t) -1;
            }
            // ../lib/github.com/diku-dk/vtree/vtree.fut:376:7-39
            // UpdateAcc
            if (sle64((int64_t) 0, lifted_lambda_res_36829) && slt64(lifted_lambda_res_36829, m_28906)) {
                ((int64_t *) mem_39211)[lifted_lambda_res_36829] = i_38523;
            }
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:378:7-37
        if (memblock_alloc(ctx, &mem_39213, bytes_39210, "mem_39213")) {
            err = 1;
            goto cleanup;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:378:7-37
        for (int64_t i_38526 = 0; i_38526 < m_28906; i_38526++) {
            int64_t eta_p_28255 = ((int64_t *) mem_39211)[i_38526];
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:378:18-27
            
            bool x_28256 = sle64((int64_t) 0, eta_p_28255);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:378:18-27
            
            bool y_28257 = slt64(eta_p_28255, n_26458);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:378:18-27
            
            bool bounds_check_28258 = x_28256 && y_28257;
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:378:18-27
            
            bool index_certs_28259;
            
            if (!bounds_check_28258) {
                set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) eta_p_28255, "] out of bounds for array of shape [", (long long) n_26458, "].", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:378:18-27\n"));
                err = FUTHARK_PROGRAM_ERROR;
                goto cleanup;
            }
            // ../lib/github.com/diku-dk/vtree/vtree.fut:378:18-27
            
            int64_t lifted_lambda_res_28260 = ((int64_t *) parent_mem_39192.mem)[eta_p_28255];
            
            ((int64_t *) mem_39213.mem)[i_38526] = lifted_lambda_res_28260;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:383:24-40
        if (mem_39221_cached_sizze_39714 < bytes_39194) {
            err = lexical_realloc(ctx, &mem_39221, &mem_39221_cached_sizze_39714, bytes_39194);
            if (err != FUTHARK_SUCCESS)
                goto cleanup;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:383:24-40
        for (int64_t nest_i_39459 = 0; nest_i_39459 < n_26458; nest_i_39459++) {
            ((int64_t *) mem_39221)[nest_i_39459] = (int64_t) 0;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:383:7-387:27
        for (int64_t iter_38528 = 0; iter_38528 < m_28906; iter_38528++) {
            int64_t pixel_38530 = ((int64_t *) mem_39213.mem)[iter_38528];
            bool less_than_zzero_38532 = slt64(pixel_38530, (int64_t) 0);
            bool greater_than_sizze_38533 = sle64(n_26458, pixel_38530);
            bool outside_bounds_dim_38534 = less_than_zzero_38532 || greater_than_sizze_38533;
            
            if (!outside_bounds_dim_38534) {
                int64_t read_hist_38536 = ((int64_t *) mem_39221)[pixel_38530];
                
                // ../lib/github.com/diku-dk/vtree/vtree.fut:384:23-30
                
                int64_t zp_res_28276 = add64((int64_t) 1, read_hist_38536);
                
                ((int64_t *) mem_39221)[pixel_38530] = zp_res_28276;
            }
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:136:24-36
        if (mem_39229_cached_sizze_39715 < bytes_39194) {
            err = lexical_realloc(ctx, &mem_39229, &mem_39229_cached_sizze_39715, bytes_39194);
            if (err != FUTHARK_SUCCESS)
                goto cleanup;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:136:24-36
        if (mem_39231_cached_sizze_39716 < bytes_39194) {
            err = lexical_realloc(ctx, &mem_39231, &mem_39231_cached_sizze_39716, bytes_39194);
            if (err != FUTHARK_SUCCESS)
                goto cleanup;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:136:24-36
        
        int64_t discard_38548;
        int64_t defunc_0_reduce_res_38142;
        int64_t scanacc_38541;
        int64_t redout_38543;
        
        scanacc_38541 = (int64_t) 0;
        redout_38543 = (int64_t) 0;
        for (int64_t i_38545 = 0; i_38545 < n_26458; i_38545++) {
            // ../lib/github.com/diku-dk/vtree/vtree.fut:390:25-39
            
            int64_t zp_lhs_36801 = ((int64_t *) mem_39221)[i_38545];
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:390:54-61
            
            bool bool_arg0_36802 = i_38545 == defunc_0_reduce_res_38136;
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:390:54-61
            
            bool bool_arg0_36803 = !bool_arg0_36802;
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:390:42-61
            
            int64_t bool_res_36804 = btoi_bool_i64(bool_arg0_36803);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:390:40-62
            
            int64_t lifted_lambda_res_36805 = add64(zp_lhs_36801, bool_res_36804);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:393:14-21
            
            int64_t zp_res_28949 = add64(lifted_lambda_res_36805, scanacc_38541);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:395:14-21
            
            int64_t zp_res_28287 = add64(lifted_lambda_res_36805, redout_38543);
            
            ((int64_t *) mem_39229)[i_38545] = zp_res_28949;
            ((int64_t *) mem_39231)[i_38545] = lifted_lambda_res_36805;
            
            int64_t scanacc_tmp_39461 = zp_res_28949;
            int64_t redout_tmp_39463 = zp_res_28287;
            
            scanacc_38541 = scanacc_tmp_39461;
            redout_38543 = redout_tmp_39463;
        }
        discard_38548 = scanacc_38541;
        defunc_0_reduce_res_38142 = redout_38543;
        // ../lib/github.com/diku-dk/vtree/vtree.fut:444:38-56
        
        int64_t bytes_39244 = (int64_t) 8 * defunc_0_reduce_res_38142;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:444:38-56
        if (mem_39245_cached_sizze_39717 < bytes_39244) {
            err = lexical_realloc(ctx, &mem_39245, &mem_39245_cached_sizze_39717, bytes_39244);
            if (err != FUTHARK_SUCCESS)
                goto cleanup;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:444:38-56
        for (int64_t nest_i_39465 = 0; nest_i_39465 < defunc_0_reduce_res_38142; nest_i_39465++) {
            ((int64_t *) mem_39245)[nest_i_39465] = (int64_t) -1;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:444:29-73
        if (mem_39247_cached_sizze_39718 < bytes_39194) {
            err = lexical_realloc(ctx, &mem_39247, &mem_39247_cached_sizze_39718, bytes_39194);
            if (err != FUTHARK_SUCCESS)
                goto cleanup;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:444:29-73
        if (mem_39255_cached_sizze_39719 < bytes_39194) {
            err = lexical_realloc(ctx, &mem_39255, &mem_39255_cached_sizze_39719, bytes_39194);
            if (err != FUTHARK_SUCCESS)
                goto cleanup;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:444:29-73
        
        bool acc_cert_36723;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:444:29-73
        for (int64_t i_38552 = 0; i_38552 < n_26458; i_38552++) {
            // ../lib/github.com/diku-dk/vtree/vtree.fut:136:11-36
            
            int64_t zv_lhs_36744 = add64((int64_t) -1, i_38552);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:136:11-36
            
            int64_t tmp_36745 = smod64(zv_lhs_36744, n_26458);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:136:11-36
            
            int64_t lifted_lambda_res_36746 = ((int64_t *) mem_39229)[tmp_36745];
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:134:19-43
            
            bool cond_36748 = i_38552 == (int64_t) 0;
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:134:19-43
            
            int64_t lifted_lambda_res_36749;
            
            if (cond_36748) {
                lifted_lambda_res_36749 = (int64_t) 0;
            } else {
                lifted_lambda_res_36749 = lifted_lambda_res_36746;
            }
            // ../lib/github.com/diku-dk/vtree/vtree.fut:444:29-73
            // UpdateAcc
            if (sle64((int64_t) 0, lifted_lambda_res_36749) && slt64(lifted_lambda_res_36749, defunc_0_reduce_res_38142)) {
                ((int64_t *) mem_39245)[lifted_lambda_res_36749] = i_38552;
            }
            ((int64_t *) mem_39247)[i_38552] = lifted_lambda_res_36749;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:444:29-73
        lmad_copy_8b(ctx, 1, (uint64_t *) mem_39255, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) mem_39247, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {n_26458});
        
        bool eq_x_zz_30898 = (int64_t) 0 == m_f_res_28904;
        bool p_and_eq_x_y_30901 = x_28897 && eq_x_zz_30898;
        bool cond_30759 = cond_28896 || p_and_eq_x_y_30901;
        
        // ../lib/github.com/diku-dk/sorts/radix_sort.fut:70:15-59
        
        int32_t iters_30760;
        
        if (cond_30759) {
            iters_30760 = 0;
        } else {
            iters_30760 = 32;
        }
        // ../lib/github.com/diku-dk/sorts/radix_sort.fut:77:69-80:48
        
        bool loop_nonempty_30764 = slt32(0, iters_30760);
        
        // ../lib/github.com/diku-dk/sorts/radix_sort.fut:37:27-39
        
        int64_t tmp_30766 = sub64(m_28906, (int64_t) 1);
        
        // ../lib/github.com/diku-dk/sorts/radix_sort.fut:37:27-39
        
        bool x_30767 = sle64((int64_t) 0, tmp_30766);
        
        // ../lib/github.com/diku-dk/sorts/radix_sort.fut:37:27-39
        
        bool y_30768 = slt64(tmp_30766, m_28906);
        
        // ../lib/github.com/diku-dk/sorts/radix_sort.fut:37:27-39
        
        bool bounds_check_30769 = x_30767 && y_30768;
        
        // ../lib/github.com/diku-dk/sorts/radix_sort.fut:77:69-80:48
        
        bool loop_not_taken_30770 = !loop_nonempty_30764;
        
        // ../lib/github.com/diku-dk/sorts/radix_sort.fut:77:69-80:48
        
        bool protect_assert_disj_30771 = bounds_check_30769 || loop_not_taken_30770;
        
        // ../lib/github.com/diku-dk/sorts/radix_sort.fut:37:27-39
        
        bool index_certs_30772;
        
        if (!protect_assert_disj_30771) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) tmp_30766, "] out of bounds for array of shape [", (long long) m_28906, "].", "-> #0  ../lib/github.com/diku-dk/sorts/radix_sort.fut:37:27-39\n   #1  ../lib/github.com/diku-dk/sorts/radix_sort.fut:71:31-64\n   #2  ../lib/github.com/diku-dk/sorts/radix_sort.fut:104:6-37\n   #3  ../lib/github.com/diku-dk/sorts/radix_sort.fut:112:18-32\n   #4  ../lib/github.com/diku-dk/sorts/radix_sort.fut:77:69-80:48\n   #5  ../lib/github.com/diku-dk/sorts/radix_sort.fut:111:33-112:56\n   #6  ../lib/github.com/diku-dk/vtree/vtree.fut:404:7-407:34\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        // ../lib/github.com/diku-dk/sorts/radix_sort.fut:22:27-36:55
        
        int64_t bytes_39280 = (int64_t) 4 * m_28906;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:457:7-19
        
        bool x_26676 = sle64((int64_t) 0, defunc_0_reduce_res_38136);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:457:7-19
        
        bool y_26677 = slt64(defunc_0_reduce_res_38136, n_26458);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:457:7-19
        
        bool bounds_check_26678 = x_26676 && y_26677;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:457:7-19
        
        bool index_certs_26679;
        
        if (!bounds_check_26678) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) defunc_0_reduce_res_38136, "] out of bounds for array of shape [", (long long) n_26458, "].", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:457:7-19\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:457:7-19
        
        int64_t head_26680 = ((int64_t *) mem_39255)[defunc_0_reduce_res_38136];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:460:7-74
        
        bool x_26693 = sle64((int64_t) 0, head_26680);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:460:7-74
        
        bool y_26694 = slt64(head_26680, defunc_0_reduce_res_38142);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:460:7-74
        
        bool bounds_check_26695 = x_26693 && y_26694;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:460:7-74
        
        bool index_certs_26696;
        
        if (!bounds_check_26695) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) head_26680, "] out of bounds for array of shape [", (long long) defunc_0_reduce_res_38142, "].", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:460:7-74\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:398:7-63
        if (mem_39257_cached_sizze_39720 < bytes_39194) {
            err = lexical_realloc(ctx, &mem_39257, &mem_39257_cached_sizze_39720, bytes_39194);
            if (err != FUTHARK_SUCCESS)
                goto cleanup;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:398:7-63
        for (int64_t i_38556 = 0; i_38556 < n_26458; i_38556++) {
            // ../lib/github.com/diku-dk/vtree/vtree.fut:398:25-63
            
            bool cond_28774 = i_38556 == defunc_0_reduce_res_38136;
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:398:25-63
            
            int64_t lifted_lambda_res_28775;
            
            if (cond_28774) {
                lifted_lambda_res_28775 = (int64_t) -1;
            } else {
                // ../lib/github.com/diku-dk/vtree/vtree.fut:398:54-63
                
                int64_t lifted_lambda_res_f_res_28780 = ((int64_t *) mem_39255)[i_38556];
                
                lifted_lambda_res_28775 = lifted_lambda_res_f_res_28780;
            }
            ((int64_t *) mem_39257)[i_38556] = lifted_lambda_res_28775;
        }
        // ../lib/github.com/diku-dk/sorts/radix_sort.fut:74:3-17
        if (memblock_alloc(ctx, &mem_39265, bytes_39210, "mem_39265")) {
            err = 1;
            goto cleanup;
        }
        // ../lib/github.com/diku-dk/sorts/radix_sort.fut:74:3-17
        for (int64_t i_39469 = 0; i_39469 < m_28906; i_39469++) {
            int64_t x_39470 = (int64_t) 0 + i_39469 * (int64_t) 1;
            
            ((int64_t *) mem_39265.mem)[i_39469] = x_39470;
        }
        // ../lib/github.com/diku-dk/sorts/radix_sort.fut:22:27-36:55
        if (mem_39273_cached_sizze_39721 < bytes_39210) {
            err = lexical_realloc(ctx, &mem_39273, &mem_39273_cached_sizze_39721, bytes_39210);
            if (err != FUTHARK_SUCCESS)
                goto cleanup;
        }
        // ../lib/github.com/diku-dk/sorts/radix_sort.fut:22:27-36:55
        if (mem_39275_cached_sizze_39722 < bytes_39210) {
            err = lexical_realloc(ctx, &mem_39275, &mem_39275_cached_sizze_39722, bytes_39210);
            if (err != FUTHARK_SUCCESS)
                goto cleanup;
        }
        // ../lib/github.com/diku-dk/sorts/radix_sort.fut:22:27-36:55
        if (mem_39277_cached_sizze_39723 < bytes_39210) {
            err = lexical_realloc(ctx, &mem_39277, &mem_39277_cached_sizze_39723, bytes_39210);
            if (err != FUTHARK_SUCCESS)
                goto cleanup;
        }
        // ../lib/github.com/diku-dk/sorts/radix_sort.fut:22:27-36:55
        if (mem_39279_cached_sizze_39724 < bytes_39210) {
            err = lexical_realloc(ctx, &mem_39279, &mem_39279_cached_sizze_39724, bytes_39210);
            if (err != FUTHARK_SUCCESS)
                goto cleanup;
        }
        // ../lib/github.com/diku-dk/sorts/radix_sort.fut:22:27-36:55
        if (mem_39281_cached_sizze_39725 < bytes_39280) {
            err = lexical_realloc(ctx, &mem_39281, &mem_39281_cached_sizze_39725, bytes_39280);
            if (err != FUTHARK_SUCCESS)
                goto cleanup;
        }
        // ../lib/github.com/diku-dk/sorts/radix_sort.fut:71:6-65
        if (memblock_set(ctx, &mem_param_39268, &mem_39213, "mem_39213") != 0)
            return 1;
        if (memblock_set(ctx, &mem_param_39271, &mem_39265, "mem_39265") != 0)
            return 1;
        for (int32_t i_30775 = 0; i_30775 < iters_30760; i_30775++) {
            // ../lib/github.com/diku-dk/sorts/radix_sort.fut:71:61-64
            
            int32_t radix_sort_step_arg2_30778 = mul32(2, i_30775);
            
            // ../lib/github.com/diku-dk/sorts/radix_sort.fut:25:32-35
            
            int32_t get_bit_arg0_30779 = add32(1, radix_sort_step_arg2_30778);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:406:55-66
            
            int64_t i32_res_30780 = sext_i32_i64(get_bit_arg0_30779);
            
            // ../lib/github.com/diku-dk/sorts/radix_sort.fut:103:8-46
            
            bool cond_30781 = get_bit_arg0_30779 == 63;
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:406:55-66
            
            int64_t i32_res_30782 = sext_i32_i64(radix_sort_step_arg2_30778);
            
            // ../lib/github.com/diku-dk/sorts/radix_sort.fut:103:8-46
            
            bool cond_30783 = radix_sort_step_arg2_30778 == 63;
            
            // ../lib/github.com/diku-dk/sorts/radix_sort.fut:22:27-36:55
            
            int64_t discard_38578;
            int64_t discard_38579;
            int64_t discard_38580;
            int64_t discard_38581;
            int64_t scanacc_38563;
            int64_t scanacc_38564;
            int64_t scanacc_38565;
            int64_t scanacc_38566;
            
            scanacc_38563 = (int64_t) 0;
            scanacc_38564 = (int64_t) 0;
            scanacc_38565 = (int64_t) 0;
            scanacc_38566 = (int64_t) 0;
            for (int64_t i_38572 = 0; i_38572 < m_28906; i_38572++) {
                int64_t eta_p_37001 = ((int64_t *) mem_param_39268.mem)[i_38572];
                
                // ../lib/github.com/diku-dk/vtree/vtree.fut:406:52-66
                
                int64_t za_lhs_37002 = ashr64(eta_p_37001, i32_res_30780);
                
                // ../lib/github.com/diku-dk/vtree/vtree.fut:406:68-74
                
                int64_t i64_arg0_37003 = (int64_t) 1 & za_lhs_37002;
                
                // ../lib/github.com/diku-dk/vtree/vtree.fut:406:40-74
                
                int32_t i64_res_37004 = sext_i64_i32(i64_arg0_37003);
                
                // ../lib/github.com/diku-dk/sorts/radix_sort.fut:103:8-46
                
                int32_t defunc_0_get_bit_res_37005;
                
                if (cond_30781) {
                    // ../lib/github.com/diku-dk/sorts/radix_sort.fut:103:36-39
                    
                    int32_t defunc_0_get_bit_res_t_res_38101 = 1 ^ i64_res_37004;
                    
                    defunc_0_get_bit_res_37005 = defunc_0_get_bit_res_t_res_38101;
                } else {
                    defunc_0_get_bit_res_37005 = i64_res_37004;
                }
                // ../lib/github.com/diku-dk/sorts/radix_sort.fut:25:39-42
                
                int32_t zp_lhs_37007 = mul32(2, defunc_0_get_bit_res_37005);
                
                // ../lib/github.com/diku-dk/vtree/vtree.fut:406:52-66
                
                int64_t za_lhs_37008 = ashr64(eta_p_37001, i32_res_30782);
                
                // ../lib/github.com/diku-dk/vtree/vtree.fut:406:68-74
                
                int64_t i64_arg0_37009 = (int64_t) 1 & za_lhs_37008;
                
                // ../lib/github.com/diku-dk/vtree/vtree.fut:406:40-74
                
                int32_t i64_res_37010 = sext_i64_i32(i64_arg0_37009);
                
                // ../lib/github.com/diku-dk/sorts/radix_sort.fut:103:8-46
                
                int32_t defunc_0_get_bit_res_37011;
                
                if (cond_30783) {
                    // ../lib/github.com/diku-dk/sorts/radix_sort.fut:103:36-39
                    
                    int32_t defunc_0_get_bit_res_t_res_38102 = 1 ^ i64_res_37010;
                    
                    defunc_0_get_bit_res_37011 = defunc_0_get_bit_res_t_res_38102;
                } else {
                    defunc_0_get_bit_res_37011 = i64_res_37010;
                }
                // ../lib/github.com/diku-dk/sorts/radix_sort.fut:25:43-62
                
                int32_t defunc_0_f_res_37013 = add32(zp_lhs_37007, defunc_0_get_bit_res_37011);
                
                // ../lib/github.com/diku-dk/sorts/radix_sort.fut:31:29-33
                
                bool bool_arg0_37015 = defunc_0_f_res_37013 == 0;
                
                // ../lib/github.com/diku-dk/sorts/radix_sort.fut:31:17-33
                
                int64_t bool_res_37016 = btoi_bool_i64(bool_arg0_37015);
                
                // ../lib/github.com/diku-dk/sorts/radix_sort.fut:32:29-33
                
                bool bool_arg0_37017 = defunc_0_f_res_37013 == 1;
                
                // ../lib/github.com/diku-dk/sorts/radix_sort.fut:32:17-33
                
                int64_t bool_res_37018 = btoi_bool_i64(bool_arg0_37017);
                
                // ../lib/github.com/diku-dk/sorts/radix_sort.fut:33:29-33
                
                bool bool_arg0_37019 = defunc_0_f_res_37013 == 2;
                
                // ../lib/github.com/diku-dk/sorts/radix_sort.fut:33:17-33
                
                int64_t bool_res_37020 = btoi_bool_i64(bool_arg0_37019);
                
                // ../lib/github.com/diku-dk/sorts/radix_sort.fut:34:29-33
                
                bool bool_arg0_37021 = defunc_0_f_res_37013 == 3;
                
                // ../lib/github.com/diku-dk/sorts/radix_sort.fut:34:17-33
                
                int64_t bool_res_37022 = btoi_bool_i64(bool_arg0_37021);
                
                // ../lib/github.com/diku-dk/sorts/radix_sort.fut:36:32-35
                
                int64_t defunc_0_op_res_30827 = add64(bool_res_37016, scanacc_38563);
                
                // ../lib/github.com/diku-dk/sorts/radix_sort.fut:36:32-35
                
                int64_t defunc_0_op_res_30828 = add64(bool_res_37018, scanacc_38564);
                
                // ../lib/github.com/diku-dk/sorts/radix_sort.fut:36:32-35
                
                int64_t defunc_0_op_res_30829 = add64(bool_res_37020, scanacc_38565);
                
                // ../lib/github.com/diku-dk/sorts/radix_sort.fut:36:32-35
                
                int64_t defunc_0_op_res_30830 = add64(bool_res_37022, scanacc_38566);
                
                ((int64_t *) mem_39273)[i_38572] = defunc_0_op_res_30827;
                ((int64_t *) mem_39275)[i_38572] = defunc_0_op_res_30828;
                ((int64_t *) mem_39277)[i_38572] = defunc_0_op_res_30829;
                ((int64_t *) mem_39279)[i_38572] = defunc_0_op_res_30830;
                ((int32_t *) mem_39281)[i_38572] = defunc_0_f_res_37013;
                
                int64_t scanacc_tmp_39475 = defunc_0_op_res_30827;
                int64_t scanacc_tmp_39476 = defunc_0_op_res_30828;
                int64_t scanacc_tmp_39477 = defunc_0_op_res_30829;
                int64_t scanacc_tmp_39478 = defunc_0_op_res_30830;
                
                scanacc_38563 = scanacc_tmp_39475;
                scanacc_38564 = scanacc_tmp_39476;
                scanacc_38565 = scanacc_tmp_39477;
                scanacc_38566 = scanacc_tmp_39478;
            }
            discard_38578 = scanacc_38563;
            discard_38579 = scanacc_38564;
            discard_38580 = scanacc_38565;
            discard_38581 = scanacc_38566;
            // ../lib/github.com/diku-dk/sorts/radix_sort.fut:37:27-39
            
            int64_t last_res_30831 = ((int64_t *) mem_39273)[tmp_30766];
            
            // ../lib/github.com/diku-dk/sorts/radix_sort.fut:37:27-39
            
            int64_t last_res_30832 = ((int64_t *) mem_39275)[tmp_30766];
            
            // ../lib/github.com/diku-dk/sorts/radix_sort.fut:37:27-39
            
            int64_t last_res_30833 = ((int64_t *) mem_39277)[tmp_30766];
            
            // ../lib/github.com/diku-dk/sorts/radix_sort.fut:48:15-22
            if (memblock_alloc(ctx, &mem_39313, bytes_39210, "mem_39313")) {
                err = 1;
                goto cleanup;
            }
            // ../lib/github.com/diku-dk/sorts/radix_sort.fut:48:15-22
            // ../lib/github.com/diku-dk/sorts/radix_sort.fut:48:15-22
            lmad_copy_8b(ctx, 1, (uint64_t *) mem_39313.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) mem_param_39271.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {m_28906});
            // ../lib/github.com/diku-dk/sorts/radix_sort.fut:48:15-22
            if (memblock_alloc(ctx, &mem_39315, bytes_39210, "mem_39315")) {
                err = 1;
                goto cleanup;
            }
            // ../lib/github.com/diku-dk/sorts/radix_sort.fut:48:15-22
            // ../lib/github.com/diku-dk/sorts/radix_sort.fut:48:15-22
            lmad_copy_8b(ctx, 1, (uint64_t *) mem_39315.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) mem_param_39268.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {m_28906});
            // ../lib/github.com/diku-dk/sorts/radix_sort.fut:48:6-29
            
            bool acc_cert_36890;
            bool acc_cert_36891;
            
            // ../lib/github.com/diku-dk/sorts/radix_sort.fut:47:12-48:29
            for (int64_t i_38584 = 0; i_38584 < m_28906; i_38584++) {
                int32_t eta_p_36940 = ((int32_t *) mem_39281)[i_38584];
                int64_t eta_p_36941 = ((int64_t *) mem_39273)[i_38584];
                int64_t eta_p_36942 = ((int64_t *) mem_39275)[i_38584];
                int64_t eta_p_36943 = ((int64_t *) mem_39277)[i_38584];
                int64_t eta_p_36944 = ((int64_t *) mem_39279)[i_38584];
                int64_t v_36947 = ((int64_t *) mem_param_39268.mem)[i_38584];
                int64_t v_36948 = ((int64_t *) mem_param_39271.mem)[i_38584];
                
                // ../lib/github.com/diku-dk/sorts/radix_sort.fut:40:26-30
                
                bool bool_arg0_36949 = eta_p_36940 == 0;
                
                // ../lib/github.com/diku-dk/sorts/radix_sort.fut:40:12-30
                
                int64_t bool_res_36950 = btoi_bool_i64(bool_arg0_36949);
                
                // ../lib/github.com/diku-dk/sorts/radix_sort.fut:40:9-31
                
                int64_t zp_rhs_36951 = mul64(eta_p_36941, bool_res_36950);
                
                // ../lib/github.com/diku-dk/sorts/radix_sort.fut:40:5-31
                
                int64_t zp_lhs_36952 = add64((int64_t) -1, zp_rhs_36951);
                
                // ../lib/github.com/diku-dk/sorts/radix_sort.fut:41:27-30
                
                bool bool_arg0_36953 = slt32(0, eta_p_36940);
                
                // ../lib/github.com/diku-dk/sorts/radix_sort.fut:41:13-30
                
                int64_t bool_res_36954 = btoi_bool_i64(bool_arg0_36953);
                
                // ../lib/github.com/diku-dk/sorts/radix_sort.fut:41:10-31
                
                int64_t zp_rhs_36955 = mul64(last_res_30831, bool_res_36954);
                
                // ../lib/github.com/diku-dk/sorts/radix_sort.fut:41:5-31
                
                int64_t zp_lhs_36956 = add64(zp_lhs_36952, zp_rhs_36955);
                
                // ../lib/github.com/diku-dk/sorts/radix_sort.fut:42:26-30
                
                bool bool_arg0_36957 = eta_p_36940 == 1;
                
                // ../lib/github.com/diku-dk/sorts/radix_sort.fut:42:12-30
                
                int64_t bool_res_36958 = btoi_bool_i64(bool_arg0_36957);
                
                // ../lib/github.com/diku-dk/sorts/radix_sort.fut:42:9-31
                
                int64_t zp_rhs_36959 = mul64(eta_p_36942, bool_res_36958);
                
                // ../lib/github.com/diku-dk/sorts/radix_sort.fut:42:5-31
                
                int64_t zp_lhs_36960 = add64(zp_lhs_36956, zp_rhs_36959);
                
                // ../lib/github.com/diku-dk/sorts/radix_sort.fut:43:27-30
                
                bool bool_arg0_36961 = slt32(1, eta_p_36940);
                
                // ../lib/github.com/diku-dk/sorts/radix_sort.fut:43:13-30
                
                int64_t bool_res_36962 = btoi_bool_i64(bool_arg0_36961);
                
                // ../lib/github.com/diku-dk/sorts/radix_sort.fut:43:10-31
                
                int64_t zp_rhs_36963 = mul64(last_res_30832, bool_res_36962);
                
                // ../lib/github.com/diku-dk/sorts/radix_sort.fut:43:5-31
                
                int64_t zp_lhs_36964 = add64(zp_lhs_36960, zp_rhs_36963);
                
                // ../lib/github.com/diku-dk/sorts/radix_sort.fut:44:26-30
                
                bool bool_arg0_36965 = eta_p_36940 == 2;
                
                // ../lib/github.com/diku-dk/sorts/radix_sort.fut:44:12-30
                
                int64_t bool_res_36966 = btoi_bool_i64(bool_arg0_36965);
                
                // ../lib/github.com/diku-dk/sorts/radix_sort.fut:44:9-31
                
                int64_t zp_rhs_36967 = mul64(eta_p_36943, bool_res_36966);
                
                // ../lib/github.com/diku-dk/sorts/radix_sort.fut:44:5-31
                
                int64_t zp_lhs_36968 = add64(zp_lhs_36964, zp_rhs_36967);
                
                // ../lib/github.com/diku-dk/sorts/radix_sort.fut:45:27-30
                
                bool bool_arg0_36969 = slt32(2, eta_p_36940);
                
                // ../lib/github.com/diku-dk/sorts/radix_sort.fut:45:13-30
                
                int64_t bool_res_36970 = btoi_bool_i64(bool_arg0_36969);
                
                // ../lib/github.com/diku-dk/sorts/radix_sort.fut:45:10-31
                
                int64_t zp_rhs_36971 = mul64(last_res_30833, bool_res_36970);
                
                // ../lib/github.com/diku-dk/sorts/radix_sort.fut:45:5-31
                
                int64_t zp_lhs_36972 = add64(zp_lhs_36968, zp_rhs_36971);
                
                // ../lib/github.com/diku-dk/sorts/radix_sort.fut:46:26-30
                
                bool bool_arg0_36973 = eta_p_36940 == 3;
                
                // ../lib/github.com/diku-dk/sorts/radix_sort.fut:46:12-30
                
                int64_t bool_res_36974 = btoi_bool_i64(bool_arg0_36973);
                
                // ../lib/github.com/diku-dk/sorts/radix_sort.fut:46:9-31
                
                int64_t zp_rhs_36975 = mul64(eta_p_36944, bool_res_36974);
                
                // ../lib/github.com/diku-dk/sorts/radix_sort.fut:46:5-31
                
                int64_t lifted_f_res_36976 = add64(zp_lhs_36972, zp_rhs_36975);
                
                // ../lib/github.com/diku-dk/sorts/radix_sort.fut:48:6-29
                // UpdateAcc
                if (sle64((int64_t) 0, lifted_f_res_36976) && slt64(lifted_f_res_36976, m_28906)) {
                    ((int64_t *) mem_39315.mem)[lifted_f_res_36976] = v_36947;
                }
                // ../lib/github.com/diku-dk/sorts/radix_sort.fut:48:6-29
                // UpdateAcc
                if (sle64((int64_t) 0, lifted_f_res_36976) && slt64(lifted_f_res_36976, m_28906)) {
                    ((int64_t *) mem_39313.mem)[lifted_f_res_36976] = v_36948;
                }
            }
            if (memblock_set(ctx, &mem_param_tmp_39471, &mem_39315, "mem_39315") != 0)
                return 1;
            if (memblock_set(ctx, &mem_param_tmp_39472, &mem_39313, "mem_39313") != 0)
                return 1;
            if (memblock_set(ctx, &mem_param_39268, &mem_param_tmp_39471, "mem_param_tmp_39471") != 0)
                return 1;
            if (memblock_set(ctx, &mem_param_39271, &mem_param_tmp_39472, "mem_param_tmp_39472") != 0)
                return 1;
        }
        if (memblock_set(ctx, &ext_mem_39321, &mem_param_39268, "mem_param_39268") != 0)
            return 1;
        if (memblock_set(ctx, &ext_mem_39320, &mem_param_39271, "mem_param_39271") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_39265, "mem_39265") != 0)
            return 1;
        // ../lib/github.com/diku-dk/sorts/radix_sort.fut:77:69-81:33
        if (mem_39323_cached_sizze_39726 < bytes_39210) {
            err = lexical_realloc(ctx, &mem_39323, &mem_39323_cached_sizze_39726, bytes_39210);
            if (err != FUTHARK_SUCCESS)
                goto cleanup;
        }
        // ../lib/github.com/diku-dk/sorts/radix_sort.fut:77:69-81:33
        if (mem_39325_cached_sizze_39727 < bytes_39210) {
            err = lexical_realloc(ctx, &mem_39325, &mem_39325_cached_sizze_39727, bytes_39210);
            if (err != FUTHARK_SUCCESS)
                goto cleanup;
        }
        // ../lib/github.com/diku-dk/sorts/radix_sort.fut:77:69-81:33
        for (int64_t i_38589 = 0; i_38589 < m_28906; i_38589++) {
            int64_t eta_p_30890 = ((int64_t *) ext_mem_39320.mem)[i_38589];
            
            // ../lib/github.com/diku-dk/sorts/radix_sort.fut:81:27-32
            
            bool x_30891 = sle64((int64_t) 0, eta_p_30890);
            
            // ../lib/github.com/diku-dk/sorts/radix_sort.fut:81:27-32
            
            bool y_30892 = slt64(eta_p_30890, m_28906);
            
            // ../lib/github.com/diku-dk/sorts/radix_sort.fut:81:27-32
            
            bool bounds_check_30893 = x_30891 && y_30892;
            
            // ../lib/github.com/diku-dk/sorts/radix_sort.fut:81:27-32
            
            bool index_certs_30894;
            
            if (!bounds_check_30893) {
                set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) eta_p_30890, "] out of bounds for array of shape [", (long long) m_28906, "].", "-> #0  ../lib/github.com/diku-dk/sorts/radix_sort.fut:81:27-32\n   #1  ../lib/github.com/diku-dk/sorts/radix_sort.fut:111:33-112:56\n   #2  ../lib/github.com/diku-dk/vtree/vtree.fut:404:7-407:34\n"));
                err = FUTHARK_PROGRAM_ERROR;
                goto cleanup;
            }
            // ../lib/github.com/diku-dk/sorts/radix_sort.fut:81:27-32
            
            int64_t lifted_lambda_res_30895 = ((int64_t *) mem_39213.mem)[eta_p_30890];
            
            // ../lib/github.com/diku-dk/sorts/radix_sort.fut:81:27-32
            
            int64_t lifted_lambda_res_30896 = ((int64_t *) mem_39211)[eta_p_30890];
            
            ((int64_t *) mem_39323)[i_38589] = lifted_lambda_res_30895;
            ((int64_t *) mem_39325)[i_38589] = lifted_lambda_res_30896;
        }
        if (memblock_unref(ctx, &mem_39213, "mem_39213") != 0)
            return 1;
        if (memblock_unref(ctx, &ext_mem_39320, "ext_mem_39320") != 0)
            return 1;
        // ../lib/github.com/diku-dk/vtree/vtree.fut:432:16-34
        if (mem_39339_cached_sizze_39728 < bytes_39194) {
            err = lexical_realloc(ctx, &mem_39339, &mem_39339_cached_sizze_39728, bytes_39194);
            if (err != FUTHARK_SUCCESS)
                goto cleanup;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:432:16-34
        for (int64_t nest_i_39488 = 0; nest_i_39488 < n_26458; nest_i_39488++) {
            ((int64_t *) mem_39339)[nest_i_39488] = (int64_t) -1;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:432:7-60
        
        bool acc_cert_35976;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:414:7-432:60
        
        int64_t inpacc_38118;
        int64_t inpacc_36080 = (int64_t) -1;
        
        for (int64_t i_38626 = 0; i_38626 < m_28906; i_38626++) {
            // ../lib/github.com/diku-dk/vtree/vtree.fut:415:13-416:48
            
            bool cond_38789 = i_38626 == (int64_t) 0;
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:415:13-416:48
            
            int64_t lifted_lambda_res_38790;
            
            if (cond_38789) {
                lifted_lambda_res_38790 = (int64_t) 1;
            } else {
                int64_t znze_lhs_38795 = ((int64_t *) mem_39323)[i_38626];
                
                // ../lib/github.com/diku-dk/vtree/vtree.fut:416:41-46
                
                int64_t znze_rhs_38796 = sub64(i_38626, (int64_t) 1);
                
                // ../lib/github.com/diku-dk/vtree/vtree.fut:416:37-47
                
                bool x_38797 = sle64((int64_t) 0, znze_rhs_38796);
                
                // ../lib/github.com/diku-dk/vtree/vtree.fut:416:37-47
                
                bool y_38798 = slt64(znze_rhs_38796, m_28906);
                
                // ../lib/github.com/diku-dk/vtree/vtree.fut:416:37-47
                
                bool bounds_check_38799 = x_38797 && y_38798;
                
                // ../lib/github.com/diku-dk/vtree/vtree.fut:416:37-47
                
                bool index_certs_38800;
                
                if (!bounds_check_38799) {
                    set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) znze_rhs_38796, "] out of bounds for array of shape [", (long long) m_28906, "].", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:416:37-47\n"));
                    err = FUTHARK_PROGRAM_ERROR;
                    goto cleanup;
                }
                
                int64_t znze_rhs_38801 = ((int64_t *) mem_39323)[znze_rhs_38796];
                
                // ../lib/github.com/diku-dk/vtree/vtree.fut:416:34-47
                
                bool bool_arg0_38802 = znze_lhs_38795 == znze_rhs_38801;
                
                // ../lib/github.com/diku-dk/vtree/vtree.fut:416:34-47
                
                bool bool_arg0_38803 = !bool_arg0_38802;
                
                // ../lib/github.com/diku-dk/vtree/vtree.fut:416:18-47
                
                int64_t bool_res_38804 = btoi_bool_i64(bool_arg0_38803);
                
                lifted_lambda_res_38790 = bool_res_38804;
            }
            // ../lib/github.com/diku-dk/vtree/vtree.fut:420:21-51
            
            bool cond_38805 = lifted_lambda_res_38790 == (int64_t) 1;
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:420:21-51
            
            int64_t lifted_lambda_res_38806;
            
            if (cond_38805) {
                lifted_lambda_res_38806 = i_38626;
            } else {
                lifted_lambda_res_38806 = (int64_t) -1;
            }
            // ../lib/github.com/diku-dk/vtree/vtree.fut:423:12-19
            
            int64_t max_res_38809 = smax64((int64_t) -1, lifted_lambda_res_38806);
            int64_t eta_p_38820 = ((int64_t *) mem_39323)[i_38626];
            int64_t v_38822 = ((int64_t *) mem_39325)[i_38626];
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:423:12-19
            
            int64_t max_res_38823 = smax64(inpacc_36080, max_res_38809);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:426:12-19
            
            int64_t zm_res_38824 = sub64(i_38626, max_res_38823);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:429:21-30
            
            bool x_38825 = sle64((int64_t) 0, eta_p_38820);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:429:21-30
            
            bool y_38826 = slt64(eta_p_38820, n_26458);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:429:21-30
            
            bool bounds_check_38827 = x_38825 && y_38826;
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:429:21-30
            
            bool index_certs_38828;
            
            if (!bounds_check_38827) {
                set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) eta_p_38820, "] out of bounds for array of shape [", (long long) n_26458, "].", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:429:21-30\n"));
                err = FUTHARK_PROGRAM_ERROR;
                goto cleanup;
            }
            // ../lib/github.com/diku-dk/vtree/vtree.fut:429:21-30
            
            int64_t zp_lhs_38829 = ((int64_t *) mem_39255)[eta_p_38820];
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:429:45-52
            
            bool bool_arg0_38830 = eta_p_38820 == defunc_0_reduce_res_38136;
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:429:45-52
            
            bool bool_arg0_38831 = !bool_arg0_38830;
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:429:33-52
            
            int64_t bool_res_38832 = btoi_bool_i64(bool_arg0_38831);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:429:31-53
            
            int64_t zp_lhs_38833 = add64(zp_lhs_38829, bool_res_38832);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:429:54-57
            
            int64_t lifted_lambda_res_38834 = add64(zm_res_38824, zp_lhs_38833);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:432:7-60
            // UpdateAcc
            if (sle64((int64_t) 0, v_38822) && slt64(v_38822, n_26458)) {
                ((int64_t *) mem_39339)[v_38822] = lifted_lambda_res_38834;
            }
            
            int64_t inpacc_tmp_39489 = max_res_38823;
            
            inpacc_36080 = inpacc_tmp_39489;
        }
        inpacc_38118 = inpacc_36080;
        // ../lib/github.com/diku-dk/vtree/vtree.fut:439:27-45
        if (mem_39341_cached_sizze_39729 < bytes_39244) {
            err = lexical_realloc(ctx, &mem_39341, &mem_39341_cached_sizze_39729, bytes_39244);
            if (err != FUTHARK_SUCCESS)
                goto cleanup;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:439:27-45
        for (int64_t nest_i_39491 = 0; nest_i_39491 < defunc_0_reduce_res_38142; nest_i_39491++) {
            ((int64_t *) mem_39341)[nest_i_39491] = (int64_t) -1;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:435:7-440:67
        if (mem_39343_cached_sizze_39730 < bytes_39210) {
            err = lexical_realloc(ctx, &mem_39343, &mem_39343_cached_sizze_39730, bytes_39210);
            if (err != FUTHARK_SUCCESS)
                goto cleanup;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:435:7-440:67
        if (mem_39345_cached_sizze_39731 < bytes_39210) {
            err = lexical_realloc(ctx, &mem_39345, &mem_39345_cached_sizze_39731, bytes_39210);
            if (err != FUTHARK_SUCCESS)
                goto cleanup;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:440:27-67
        if (mem_39359_cached_sizze_39732 < bytes_39210) {
            err = lexical_realloc(ctx, &mem_39359, &mem_39359_cached_sizze_39732, bytes_39210);
            if (err != FUTHARK_SUCCESS)
                goto cleanup;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:440:27-67
        if (mem_39361_cached_sizze_39733 < bytes_39210) {
            err = lexical_realloc(ctx, &mem_39361, &mem_39361_cached_sizze_39733, bytes_39210);
            if (err != FUTHARK_SUCCESS)
                goto cleanup;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:440:27-67
        
        bool acc_cert_35481;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:435:7-440:67
        for (int64_t i_38637 = 0; i_38637 < m_28906; i_38637++) {
            int64_t eta_p_35504 = ((int64_t *) mem_39211)[i_38637];
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:435:18-32
            
            bool x_35507 = sle64((int64_t) 0, eta_p_35504);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:435:18-32
            
            bool y_35508 = slt64(eta_p_35504, n_26458);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:435:18-32
            
            bool bounds_check_35509 = x_35507 && y_35508;
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:435:18-32
            
            bool index_certs_35510;
            
            if (!bounds_check_35509) {
                set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) eta_p_35504, "] out of bounds for array of shape [", (long long) n_26458, "].", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:435:18-32\n"));
                err = FUTHARK_PROGRAM_ERROR;
                goto cleanup;
            }
            // ../lib/github.com/diku-dk/vtree/vtree.fut:435:18-32
            
            int64_t lifted_lambda_res_35511 = ((int64_t *) mem_39257)[eta_p_35504];
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:437:18-34
            
            int64_t lifted_lambda_res_35517 = ((int64_t *) mem_39339)[eta_p_35504];
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:440:27-67
            // UpdateAcc
            if (sle64((int64_t) 0, lifted_lambda_res_35511) && slt64(lifted_lambda_res_35511, defunc_0_reduce_res_38142)) {
                ((int64_t *) mem_39341)[lifted_lambda_res_35511] = lifted_lambda_res_35517;
            }
            ((int64_t *) mem_39343)[i_38637] = lifted_lambda_res_35517;
            ((int64_t *) mem_39345)[i_38637] = lifted_lambda_res_35511;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:440:27-67
        lmad_copy_8b(ctx, 1, (uint64_t *) mem_39359, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) mem_39343, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {m_28906});
        // ../lib/github.com/diku-dk/vtree/vtree.fut:440:27-67
        lmad_copy_8b(ctx, 1, (uint64_t *) mem_39361, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) mem_39345, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {m_28906});
        // ../lib/github.com/diku-dk/vtree/vtree.fut:441:27-66
        
        bool acc_cert_28059;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:441:27-66
        for (int64_t i_38641 = 0; i_38641 < m_28906; i_38641++) {
            int64_t v_28063 = ((int64_t *) mem_39359)[i_38641];
            int64_t v_28064 = ((int64_t *) mem_39361)[i_38641];
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:441:27-66
            // UpdateAcc
            if (sle64((int64_t) 0, v_28063) && slt64(v_28063, defunc_0_reduce_res_38142)) {
                ((int64_t *) mem_39341)[v_28063] = v_28064;
            }
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:444:7-74
        if (mem_39363_cached_sizze_39734 < bytes_39244) {
            err = lexical_realloc(ctx, &mem_39363, &mem_39363_cached_sizze_39734, bytes_39244);
            if (err != FUTHARK_SUCCESS)
                goto cleanup;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:444:7-74
        
        int64_t discard_38647;
        int64_t scanacc_38643 = (int64_t) -1;
        
        for (int64_t i_38645 = 0; i_38645 < defunc_0_reduce_res_38142; i_38645++) {
            int64_t x_28338 = ((int64_t *) mem_39245)[i_38645];
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:444:12-19
            
            int64_t max_res_28341 = smax64(x_28338, scanacc_38643);
            
            ((int64_t *) mem_39363)[i_38645] = max_res_28341;
            
            int64_t scanacc_tmp_39496 = max_res_28341;
            
            scanacc_38643 = scanacc_tmp_39496;
        }
        discard_38647 = scanacc_38643;
        // ../lib/github.com/diku-dk/vtree/vtree.fut:447:7-451:54
        if (mem_39371_cached_sizze_39735 < bytes_39244) {
            err = lexical_realloc(ctx, &mem_39371, &mem_39371_cached_sizze_39735, bytes_39244);
            if (err != FUTHARK_SUCCESS)
                goto cleanup;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:447:7-451:54
        for (int64_t i_38650 = 0; i_38650 < defunc_0_reduce_res_38142; i_38650++) {
            // ../lib/github.com/diku-dk/vtree/vtree.fut:448:19-27
            
            int64_t v_28820 = ((int64_t *) mem_39363)[i_38650];
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:449:19-28
            
            bool x_28821 = sle64((int64_t) 0, v_28820);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:449:19-28
            
            bool y_28822 = slt64(v_28820, n_26458);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:449:19-28
            
            bool bounds_check_28823 = x_28821 && y_28822;
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:449:19-28
            
            bool index_certs_28824;
            
            if (!bounds_check_28823) {
                set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) v_28820, "] out of bounds for array of shape [", (long long) n_26458, "].", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:449:19-28\n"));
                err = FUTHARK_PROGRAM_ERROR;
                goto cleanup;
            }
            // ../lib/github.com/diku-dk/vtree/vtree.fut:449:19-28
            
            int64_t s_28825 = ((int64_t *) mem_39255)[v_28820];
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:450:19-26
            
            int64_t deg_28826 = ((int64_t *) mem_39231)[v_28820];
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:451:17-23
            
            int64_t zl_lhs_28827 = add64((int64_t) 1, i_38650);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:451:28-33
            
            int64_t zl_rhs_28828 = add64(s_28825, deg_28826);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:451:12-54
            
            bool cond_28829 = slt64(zl_lhs_28827, zl_rhs_28828);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:451:12-54
            
            int64_t lifted_lambda_res_28830;
            
            if (cond_28829) {
                lifted_lambda_res_28830 = zl_lhs_28827;
            } else {
                lifted_lambda_res_28830 = s_28825;
            }
            ((int64_t *) mem_39371)[i_38650] = lifted_lambda_res_28830;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:460:17-35
        if (memblock_alloc(ctx, &mem_39379, bytes_39244, "mem_39379")) {
            err = 1;
            goto cleanup;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:460:17-35
        for (int64_t nest_i_39499 = 0; nest_i_39499 < defunc_0_reduce_res_38142; nest_i_39499++) {
            ((int64_t *) mem_39379.mem)[nest_i_39499] = (int64_t) -1;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:460:8-50
        
        bool acc_cert_35363;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:454:7-460:50
        for (int64_t i_38653 = 0; i_38653 < defunc_0_reduce_res_38142; i_38653++) {
            int64_t eta_p_35379 = ((int64_t *) mem_39341)[i_38653];
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:454:18-32
            
            bool x_35382 = sle64((int64_t) 0, eta_p_35379);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:454:18-32
            
            bool y_35383 = slt64(eta_p_35379, defunc_0_reduce_res_38142);
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:454:18-32
            
            bool bounds_check_35384 = x_35382 && y_35383;
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:454:18-32
            
            bool index_certs_35385;
            
            if (!bounds_check_35384) {
                set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) eta_p_35379, "] out of bounds for array of shape [", (long long) defunc_0_reduce_res_38142, "].", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:454:18-32\n"));
                err = FUTHARK_PROGRAM_ERROR;
                goto cleanup;
            }
            // ../lib/github.com/diku-dk/vtree/vtree.fut:454:18-32
            
            int64_t lifted_lambda_res_35386 = ((int64_t *) mem_39371)[eta_p_35379];
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:460:8-50
            // UpdateAcc
            if (sle64((int64_t) 0, lifted_lambda_res_35386) && slt64(lifted_lambda_res_35386, defunc_0_reduce_res_38142)) {
                ((int64_t *) mem_39379.mem)[lifted_lambda_res_35386] = i_38653;
            }
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:460:7-74
        ((int64_t *) mem_39379.mem)[head_26680] = (int64_t) -1;
        // ../lib/github.com/diku-dk/vtree/vtree.fut:463:8-24
        if (memblock_alloc(ctx, &mem_39381, bytes_39244, "mem_39381")) {
            err = 1;
            goto cleanup;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:463:8-24
        for (int64_t nest_i_39501 = 0; nest_i_39501 < defunc_0_reduce_res_38142; nest_i_39501++) {
            ((int64_t *) mem_39381.mem)[nest_i_39501] = (int64_t) 1;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:463:7-44
        ((int64_t *) mem_39381.mem)[head_26680] = (int64_t) 0;
        // ../lib/github.com/diku-dk/vtree/vtree.fut:129:44-53
        
        int32_t clzz_res_29913 = futrts_clzz64(defunc_0_reduce_res_38142);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:129:7-130:43
        
        int32_t upper_bound_29914 = sub32(64, clzz_res_29913);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:129:7-130:43
        if (memblock_set(ctx, &mem_param_39384, &mem_39381, "mem_39381") != 0)
            return 1;
        if (memblock_set(ctx, &mem_param_39387, &mem_39379, "mem_39379") != 0)
            return 1;
        for (int32_t _i_29917 = 0; _i_29917 < upper_bound_29914; _i_29917++) {
            // ../lib/github.com/diku-dk/vtree/vtree.fut:122:15-23
            if (memblock_alloc(ctx, &mem_39389, bytes_39244, "mem_39389")) {
                err = 1;
                goto cleanup;
            }
            // ../lib/github.com/diku-dk/vtree/vtree.fut:122:15-23
            if (memblock_alloc(ctx, &mem_39391, bytes_39244, "mem_39391")) {
                err = 1;
                goto cleanup;
            }
            // ../lib/github.com/diku-dk/vtree/vtree.fut:122:15-23
            for (int64_t i_38658 = 0; i_38658 < defunc_0_reduce_res_38142; i_38658++) {
                // ../lib/github.com/diku-dk/vtree/vtree.fut:119:10-20
                
                int64_t zeze_lhs_29931 = ((int64_t *) mem_param_39387.mem)[i_38658];
                
                // ../lib/github.com/diku-dk/vtree/vtree.fut:119:7-121:68
                
                bool cond_29932 = zeze_lhs_29931 == (int64_t) -1;
                
                // ../lib/github.com/diku-dk/vtree/vtree.fut:119:7-121:68
                
                int64_t defunc_0_f_res_29933;
                int64_t defunc_0_f_res_29934;
                
                if (cond_29932) {
                    // ../lib/github.com/diku-dk/vtree/vtree.fut:120:13-22
                    
                    int64_t tmp_38131 = ((int64_t *) mem_param_39384.mem)[i_38658];
                    
                    defunc_0_f_res_29933 = tmp_38131;
                    defunc_0_f_res_29934 = zeze_lhs_29931;
                } else {
                    // ../lib/github.com/diku-dk/vtree/vtree.fut:121:28-46
                    
                    bool x_29937 = sle64((int64_t) 0, zeze_lhs_29931);
                    
                    // ../lib/github.com/diku-dk/vtree/vtree.fut:121:28-46
                    
                    bool y_29938 = slt64(zeze_lhs_29931, defunc_0_reduce_res_38142);
                    
                    // ../lib/github.com/diku-dk/vtree/vtree.fut:121:28-46
                    
                    bool bounds_check_29939 = x_29937 && y_29938;
                    
                    // ../lib/github.com/diku-dk/vtree/vtree.fut:121:28-46
                    
                    bool index_certs_29940;
                    
                    if (!bounds_check_29939) {
                        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) zeze_lhs_29931, "] out of bounds for array of shape [", (long long) defunc_0_reduce_res_38142, "].", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:121:28-46\n   #1  ../lib/github.com/diku-dk/vtree/vtree.fut:122:15-23\n   #2  ../lib/github.com/diku-dk/vtree/vtree.fut:130:9-43\n   #3  ../lib/github.com/diku-dk/vtree/vtree.fut:466:7-41\n"));
                        err = FUTHARK_PROGRAM_ERROR;
                        goto cleanup;
                    }
                    // ../lib/github.com/diku-dk/vtree/vtree.fut:121:13-22
                    
                    int64_t op_lhs_29936 = ((int64_t *) mem_param_39384.mem)[i_38658];
                    
                    // ../lib/github.com/diku-dk/vtree/vtree.fut:121:28-46
                    
                    int64_t op_rhs_29941 = ((int64_t *) mem_param_39384.mem)[zeze_lhs_29931];
                    
                    // ../lib/github.com/diku-dk/vtree/vtree.fut:466:19-26
                    
                    int64_t zp_res_29942 = add64(op_lhs_29936, op_rhs_29941);
                    
                    // ../lib/github.com/diku-dk/vtree/vtree.fut:121:48-67
                    
                    int64_t tmp_29947 = ((int64_t *) mem_param_39387.mem)[zeze_lhs_29931];
                    
                    defunc_0_f_res_29933 = zp_res_29942;
                    defunc_0_f_res_29934 = tmp_29947;
                }
                ((int64_t *) mem_39389.mem)[i_38658] = defunc_0_f_res_29933;
                ((int64_t *) mem_39391.mem)[i_38658] = defunc_0_f_res_29934;
            }
            if (memblock_set(ctx, &mem_param_tmp_39502, &mem_39389, "mem_39389") != 0)
                return 1;
            if (memblock_set(ctx, &mem_param_tmp_39503, &mem_39391, "mem_39391") != 0)
                return 1;
            if (memblock_set(ctx, &mem_param_39384, &mem_param_tmp_39502, "mem_param_tmp_39502") != 0)
                return 1;
            if (memblock_set(ctx, &mem_param_39387, &mem_param_tmp_39503, "mem_param_tmp_39503") != 0)
                return 1;
        }
        if (memblock_set(ctx, &ext_mem_39409, &mem_param_39384, "mem_param_39384") != 0)
            return 1;
        if (memblock_set(ctx, &ext_mem_39408, &mem_param_39387, "mem_param_39387") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_39379, "mem_39379") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_39381, "mem_39381") != 0)
            return 1;
        // ../lib/github.com/diku-dk/vtree/vtree.fut:469:7-476:41
        if (memblock_alloc(ctx, &mem_39411, bytes_39194, "mem_39411")) {
            err = 1;
            goto cleanup;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:469:7-476:41
        if (memblock_alloc(ctx, &mem_39413, bytes_39194, "mem_39413")) {
            err = 1;
            goto cleanup;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:469:7-476:41
        for (int64_t i_38665 = 0; i_38665 < n_26458; i_38665++) {
            // ../lib/github.com/diku-dk/vtree/vtree.fut:470:9-471:43
            
            bool cond_36852 = i_38665 == defunc_0_reduce_res_38136;
            
            // ../lib/github.com/diku-dk/vtree/vtree.fut:470:9-471:43
            
            int64_t lifted_lambda_res_36853;
            
            if (cond_36852) {
                lifted_lambda_res_36853 = (int64_t) 0;
            } else {
                // ../lib/github.com/diku-dk/vtree/vtree.fut:471:26-42
                
                int64_t zp_rhs_36858 = ((int64_t *) mem_39339)[i_38665];
                
                // ../lib/github.com/diku-dk/vtree/vtree.fut:471:21-43
                
                bool x_36859 = sle64((int64_t) 0, zp_rhs_36858);
                
                // ../lib/github.com/diku-dk/vtree/vtree.fut:471:21-43
                
                bool y_36860 = slt64(zp_rhs_36858, defunc_0_reduce_res_38142);
                
                // ../lib/github.com/diku-dk/vtree/vtree.fut:471:21-43
                
                bool bounds_check_36861 = x_36859 && y_36860;
                
                // ../lib/github.com/diku-dk/vtree/vtree.fut:471:21-43
                
                bool index_certs_36862;
                
                if (!bounds_check_36861) {
                    set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) zp_rhs_36858, "] out of bounds for array of shape [", (long long) defunc_0_reduce_res_38142, "].", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:471:21-43\n"));
                    err = FUTHARK_PROGRAM_ERROR;
                    goto cleanup;
                }
                // ../lib/github.com/diku-dk/vtree/vtree.fut:471:21-43
                
                int64_t zp_rhs_36863 = ((int64_t *) ext_mem_39409.mem)[zp_rhs_36858];
                
                // ../lib/github.com/diku-dk/vtree/vtree.fut:471:19-43
                
                int64_t lifted_lambda_res_f_res_36864 = add64((int64_t) 1, zp_rhs_36863);
                
                lifted_lambda_res_36853 = lifted_lambda_res_f_res_36864;
            }
            // ../lib/github.com/diku-dk/vtree/vtree.fut:475:9-476:41
            
            int64_t lifted_lambda_res_36867;
            
            if (cond_36852) {
                // ../lib/github.com/diku-dk/vtree/vtree.fut:475:32-35
                
                int64_t zm_lhs_38134 = mul64((int64_t) 2, n_26458);
                
                // ../lib/github.com/diku-dk/vtree/vtree.fut:475:36-42
                
                int64_t lifted_lambda_res_t_res_38135 = sub64(zm_lhs_38134, (int64_t) 1);
                
                lifted_lambda_res_36867 = lifted_lambda_res_t_res_38135;
            } else {
                // ../lib/github.com/diku-dk/vtree/vtree.fut:476:26-40
                
                int64_t zp_rhs_36874 = ((int64_t *) mem_39257)[i_38665];
                
                // ../lib/github.com/diku-dk/vtree/vtree.fut:476:21-41
                
                bool x_36875 = sle64((int64_t) 0, zp_rhs_36874);
                
                // ../lib/github.com/diku-dk/vtree/vtree.fut:476:21-41
                
                bool y_36876 = slt64(zp_rhs_36874, defunc_0_reduce_res_38142);
                
                // ../lib/github.com/diku-dk/vtree/vtree.fut:476:21-41
                
                bool bounds_check_36877 = x_36875 && y_36876;
                
                // ../lib/github.com/diku-dk/vtree/vtree.fut:476:21-41
                
                bool index_certs_36878;
                
                if (!bounds_check_36877) {
                    set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) zp_rhs_36874, "] out of bounds for array of shape [", (long long) defunc_0_reduce_res_38142, "].", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:476:21-41\n"));
                    err = FUTHARK_PROGRAM_ERROR;
                    goto cleanup;
                }
                // ../lib/github.com/diku-dk/vtree/vtree.fut:476:21-41
                
                int64_t zp_rhs_36879 = ((int64_t *) ext_mem_39409.mem)[zp_rhs_36874];
                
                // ../lib/github.com/diku-dk/vtree/vtree.fut:476:19-41
                
                int64_t lifted_lambda_res_f_res_36880 = add64((int64_t) 1, zp_rhs_36879);
                
                lifted_lambda_res_36867 = lifted_lambda_res_f_res_36880;
            }
            ((int64_t *) mem_39411.mem)[i_38665] = lifted_lambda_res_36867;
            ((int64_t *) mem_39413.mem)[i_38665] = lifted_lambda_res_36853;
        }
        if (memblock_unref(ctx, &ext_mem_39409, "ext_mem_39409") != 0)
            return 1;
        if (memblock_set(ctx, &ext_mem_39435, &mem_39413, "mem_39413") != 0)
            return 1;
        if (memblock_set(ctx, &ext_mem_39432, &mem_39411, "mem_39411") != 0)
            return 1;
    }
    if (memblock_set(ctx, &mem_out_39448, &data_mem_39193, "data_mem_39193") != 0)
        return 1;
    if (memblock_set(ctx, &mem_out_39449, &ext_mem_39435, "ext_mem_39435") != 0)
        return 1;
    if (memblock_set(ctx, &mem_out_39450, &ext_mem_39432, "ext_mem_39432") != 0)
        return 1;
    if (memblock_set(ctx, &*mem_out_p_39708, &mem_out_39448, "mem_out_39448") != 0)
        return 1;
    if (memblock_set(ctx, &*mem_out_p_39709, &mem_out_39449, "mem_out_39449") != 0)
        return 1;
    if (memblock_set(ctx, &*mem_out_p_39710, &mem_out_39450, "mem_out_39450") != 0)
        return 1;
    
  cleanup:
    {
        free(mem_39195);
        free(mem_39197);
        free(mem_39211);
        free(mem_39221);
        free(mem_39229);
        free(mem_39231);
        free(mem_39245);
        free(mem_39247);
        free(mem_39255);
        free(mem_39257);
        free(mem_39273);
        free(mem_39275);
        free(mem_39277);
        free(mem_39279);
        free(mem_39281);
        free(mem_39323);
        free(mem_39325);
        free(mem_39339);
        free(mem_39341);
        free(mem_39343);
        free(mem_39345);
        free(mem_39359);
        free(mem_39361);
        free(mem_39363);
        free(mem_39371);
        if (memblock_unref(ctx, &mem_39413, "mem_39413") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_39411, "mem_39411") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_param_tmp_39503, "mem_param_tmp_39503") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_param_tmp_39502, "mem_param_tmp_39502") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_39391, "mem_39391") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_39389, "mem_39389") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_param_39387, "mem_param_39387") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_param_39384, "mem_param_39384") != 0)
            return 1;
        if (memblock_unref(ctx, &ext_mem_39408, "ext_mem_39408") != 0)
            return 1;
        if (memblock_unref(ctx, &ext_mem_39409, "ext_mem_39409") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_39381, "mem_39381") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_39379, "mem_39379") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_param_tmp_39472, "mem_param_tmp_39472") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_param_tmp_39471, "mem_param_tmp_39471") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_39315, "mem_39315") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_39313, "mem_39313") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_param_39271, "mem_param_39271") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_param_39268, "mem_param_39268") != 0)
            return 1;
        if (memblock_unref(ctx, &ext_mem_39320, "ext_mem_39320") != 0)
            return 1;
        if (memblock_unref(ctx, &ext_mem_39321, "ext_mem_39321") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_39265, "mem_39265") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_39213, "mem_39213") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_39429, "mem_39429") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_39427, "mem_39427") != 0)
            return 1;
        if (memblock_unref(ctx, &ext_mem_39432, "ext_mem_39432") != 0)
            return 1;
        if (memblock_unref(ctx, &ext_mem_39435, "ext_mem_39435") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_out_39450, "mem_out_39450") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_out_39449, "mem_out_39449") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_out_39448, "mem_out_39448") != 0)
            return 1;
    }
    return err;
}
FUTHARK_FUN_ATTR int futrts_split_9182(struct futhark_context *ctx, struct memblock *mem_out_p_39736, struct memblock *mem_out_p_39737, struct memblock *mem_out_p_39738, struct memblock *mem_out_p_39739, struct memblock *mem_out_p_39740, struct memblock *mem_out_p_39741, struct memblock *mem_out_p_39742, int64_t *out_prim_out_39743, int64_t *out_prim_out_39744, int64_t *out_prim_out_39745, struct memblock data_mem_39192, struct memblock lp_mem_39193, struct memblock rp_mem_39194, struct memblock splits_mem_39195, int64_t n_20017)
{
    (void) ctx;
    
    int err = 0;
    int64_t mem_39197_cached_sizze_39746 = 0;
    unsigned char *mem_39197 = NULL;
    int64_t mem_39199_cached_sizze_39747 = 0;
    unsigned char *mem_39199 = NULL;
    int64_t mem_39215_cached_sizze_39748 = 0;
    unsigned char *mem_39215 = NULL;
    int64_t mem_39217_cached_sizze_39749 = 0;
    unsigned char *mem_39217 = NULL;
    int64_t mem_39225_cached_sizze_39750 = 0;
    unsigned char *mem_39225 = NULL;
    int64_t mem_39227_cached_sizze_39751 = 0;
    unsigned char *mem_39227 = NULL;
    int64_t mem_39235_cached_sizze_39752 = 0;
    unsigned char *mem_39235 = NULL;
    int64_t mem_39243_cached_sizze_39753 = 0;
    unsigned char *mem_39243 = NULL;
    int64_t mem_39244_cached_sizze_39754 = 0;
    unsigned char *mem_39244 = NULL;
    int64_t mem_39246_cached_sizze_39755 = 0;
    unsigned char *mem_39246 = NULL;
    int64_t mem_39248_cached_sizze_39756 = 0;
    unsigned char *mem_39248 = NULL;
    struct memblock ext_mem_39281;
    
    ext_mem_39281.references = NULL;
    
    struct memblock ext_mem_39282;
    
    ext_mem_39282.references = NULL;
    
    struct memblock ext_mem_39283;
    
    ext_mem_39283.references = NULL;
    
    struct memblock mem_39279;
    
    mem_39279.references = NULL;
    
    struct memblock mem_39278;
    
    mem_39278.references = NULL;
    
    struct memblock mem_39276;
    
    mem_39276.references = NULL;
    
    struct memblock mem_39274;
    
    mem_39274.references = NULL;
    
    struct memblock mem_39213;
    
    mem_39213.references = NULL;
    
    struct memblock mem_out_39454;
    
    mem_out_39454.references = NULL;
    
    struct memblock mem_out_39453;
    
    mem_out_39453.references = NULL;
    
    struct memblock mem_out_39452;
    
    mem_out_39452.references = NULL;
    
    struct memblock mem_out_39451;
    
    mem_out_39451.references = NULL;
    
    struct memblock mem_out_39450;
    
    mem_out_39450.references = NULL;
    
    struct memblock mem_out_39449;
    
    mem_out_39449.references = NULL;
    
    struct memblock mem_out_39448;
    
    mem_out_39448.references = NULL;
    
    bool ok_17775 = ctx->constants->ok_17775;
    bool ok_17859 = ctx->constants->ok_17859;
    bool ok_17938 = ctx->constants->ok_17938;
    bool x_27518 = ctx->constants->x_27518;
    bool x_27521 = ctx->constants->x_27521;
    bool x_27527 = ctx->constants->x_27527;
    bool x_27533 = ctx->constants->x_27533;
    int64_t prim_out_39455;
    int64_t prim_out_39456;
    int64_t prim_out_39457;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:241:15-40
    
    int64_t bytes_39196 = (int64_t) 8 * n_20017;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:241:15-40
    if (mem_39197_cached_sizze_39746 < bytes_39196) {
        err = lexical_realloc(ctx, &mem_39197, &mem_39197_cached_sizze_39746, bytes_39196);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:241:15-40
    if (mem_39199_cached_sizze_39747 < bytes_39196) {
        err = lexical_realloc(ctx, &mem_39199, &mem_39199_cached_sizze_39747, bytes_39196);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:241:15-40
    
    int64_t discard_38519;
    int64_t scanacc_38513 = (int64_t) 0;
    
    for (int64_t i_38516 = 0; i_38516 < n_20017; i_38516++) {
        bool eta_p_35390 = ((bool *) splits_mem_39195.mem)[i_38516];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:241:15-40
        
        int64_t defunc_0_f_res_35391 = btoi_bool_i64(eta_p_35390);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:241:15-40
        
        int64_t defunc_0_op_res_29061 = add64(defunc_0_f_res_35391, scanacc_38513);
        
        ((int64_t *) mem_39197)[i_38516] = defunc_0_op_res_29061;
        ((int64_t *) mem_39199)[i_38516] = defunc_0_f_res_35391;
        
        int64_t scanacc_tmp_39458 = defunc_0_op_res_29061;
        
        scanacc_38513 = scanacc_tmp_39458;
    }
    discard_38519 = scanacc_38513;
    // ../lib/github.com/diku-dk/vtree/vtree.fut:284:5-285:51
    
    int64_t tmp_28899 = sub64(n_20017, (int64_t) 1);
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:284:5-285:51
    
    bool y_28901 = slt64(tmp_28899, n_20017);
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:284:5-285:51
    
    bool x_28900 = sle64((int64_t) 0, tmp_28899);
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:284:5-285:51
    
    bool bounds_check_28902 = x_28900 && y_28901;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:284:5-285:51
    
    bool cond_28897 = n_20017 == (int64_t) 0;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:284:5-285:51
    
    bool protect_assert_disj_28903 = cond_28897 || bounds_check_28902;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:284:5-285:51
    
    bool index_certs_28904;
    
    if (!protect_assert_disj_28903) {
        set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) tmp_28899, "] out of bounds for array of shape [", (long long) n_20017, "].", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:284:5-285:51\n"));
        err = FUTHARK_PROGRAM_ERROR;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:284:5-285:51
    
    bool x_28898 = !cond_28897;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:241:15-40
    
    int64_t m_f_res_29070;
    
    if (x_28898) {
        // ../lib/github.com/diku-dk/vtree/vtree.fut:241:15-40
        
        int64_t x_35925 = ((int64_t *) mem_39197)[tmp_28899];
        
        m_f_res_29070 = x_35925;
    } else {
        m_f_res_29070 = (int64_t) 0;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:241:15-40
    
    int64_t m_29072;
    
    if (cond_28897) {
        m_29072 = (int64_t) 0;
    } else {
        m_29072 = m_f_res_29070;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:241:15-40
    
    int64_t bytes_39212 = (int64_t) 8 * m_29072;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:241:15-40
    if (memblock_alloc(ctx, &mem_39213, bytes_39212, "mem_39213")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:214:24-29
    
    int64_t dzlz7bUZLztZRz20U2z20Unz7dUzg_29916 = mul64((int64_t) 2, n_20017);
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:214:13-33
    
    int64_t bytes_39214 = (int64_t) 16 * n_20017;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:214:13-33
    if (mem_39215_cached_sizze_39748 < bytes_39214) {
        err = lexical_realloc(ctx, &mem_39215, &mem_39215_cached_sizze_39748, bytes_39214);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:214:13-33
    for (int64_t nest_i_39461 = 0; nest_i_39461 < dzlz7bUZLztZRz20U2z20Unz7dUzg_29916; nest_i_39461++) {
        ((int64_t *) mem_39215)[nest_i_39461] = (int64_t) 0;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:241:15-40
    if (mem_39217_cached_sizze_39749 < bytes_39196) {
        err = lexical_realloc(ctx, &mem_39217, &mem_39217_cached_sizze_39749, bytes_39196);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:241:15-40
    if (mem_39225_cached_sizze_39750 < bytes_39196) {
        err = lexical_realloc(ctx, &mem_39225, &mem_39225_cached_sizze_39750, bytes_39196);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:241:15-40
    
    bool acc_cert_35396;
    bool acc_cert_35730;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:241:15-40
    for (int64_t i_38524 = 0; i_38524 < n_20017; i_38524++) {
        int64_t eta_p_35754 = ((int64_t *) lp_mem_39193.mem)[i_38524];
        int64_t eta_p_35755 = ((int64_t *) rp_mem_39194.mem)[i_38524];
        int64_t eta_p_35756 = ((int64_t *) mem_39199)[i_38524];
        int64_t eta_p_35757 = ((int64_t *) mem_39197)[i_38524];
        bool eta_p_35759 = ((bool *) splits_mem_39195.mem)[i_38524];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:272:25-49
        
        int64_t lifted_lambda_res_35762;
        
        if (eta_p_35759) {
            lifted_lambda_res_35762 = eta_p_35754;
        } else {
            lifted_lambda_res_35762 = (int64_t) 0;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:215:13-30
        // UpdateAcc
        if (sle64((int64_t) 0, eta_p_35754) && slt64(eta_p_35754, dzlz7bUZLztZRz20U2z20Unz7dUzg_29916)) {
            ((int64_t *) mem_39215)[eta_p_35754] = lifted_lambda_res_35762;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:293:41-44
        
        int64_t zp_lhs_35766 = sub64(eta_p_35755, eta_p_35754);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:293:45-48
        
        int64_t zs_lhs_35767 = add64((int64_t) 1, zp_lhs_35766);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:293:50-53
        
        int64_t lifted_lambda_res_35768 = sdiv64(zs_lhs_35767, (int64_t) 2);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:241:15-40
        
        bool cond_35769 = eta_p_35756 == (int64_t) 1;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:241:15-40
        
        int64_t lifted_lambda_res_35770;
        
        if (cond_35769) {
            // ../lib/github.com/diku-dk/vtree/vtree.fut:241:15-40
            
            int64_t lifted_lambda_res_t_res_35909 = sub64(eta_p_35757, (int64_t) 1);
            
            lifted_lambda_res_35770 = lifted_lambda_res_t_res_35909;
        } else {
            lifted_lambda_res_35770 = (int64_t) -1;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:241:15-40
        // UpdateAcc
        if (sle64((int64_t) 0, lifted_lambda_res_35770) && slt64(lifted_lambda_res_35770, m_29072)) {
            ((int64_t *) mem_39213.mem)[lifted_lambda_res_35770] = lifted_lambda_res_35768;
        }
        ((int64_t *) mem_39217)[i_38524] = lifted_lambda_res_35762;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:241:15-40
    lmad_copy_8b(ctx, 1, (uint64_t *) mem_39225, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint64_t *) mem_39217, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {n_20017});
    // ../lib/github.com/diku-dk/vtree/vtree.fut:216:13-39
    
    bool acc_cert_35685;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:216:13-39
    for (int64_t i_38527 = 0; i_38527 < n_20017; i_38527++) {
        int64_t eta_p_35697 = ((int64_t *) mem_39225)[i_38527];
        int64_t v_35699 = ((int64_t *) rp_mem_39194.mem)[i_38527];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:274:31-38
        
        int64_t neg_res_35700 = -eta_p_35697;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:216:13-39
        // UpdateAcc
        if (sle64((int64_t) 0, v_35699) && slt64(v_35699, dzlz7bUZLztZRz20U2z20Unz7dUzg_29916)) {
            ((int64_t *) mem_39215)[v_35699] = neg_res_35700;
        }
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:136:24-36
    if (mem_39227_cached_sizze_39751 < bytes_39214) {
        err = lexical_realloc(ctx, &mem_39227, &mem_39227_cached_sizze_39751, bytes_39214);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:136:24-36
    
    int64_t discard_38533;
    int64_t scanacc_38529 = (int64_t) 0;
    
    for (int64_t i_38531 = 0; i_38531 < dzlz7bUZLztZRz20U2z20Unz7dUzg_29916; i_38531++) {
        int64_t x_29938 = ((int64_t *) mem_39215)[i_38531];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:274:23-30
        
        int64_t zp_res_29941 = add64(x_29938, scanacc_38529);
        
        ((int64_t *) mem_39227)[i_38531] = zp_res_29941;
        
        int64_t scanacc_tmp_39466 = zp_res_29941;
        
        scanacc_38529 = scanacc_tmp_39466;
    }
    discard_38533 = scanacc_38529;
    // ../lib/github.com/diku-dk/vtree/vtree.fut:134:5-136:37
    if (mem_39235_cached_sizze_39752 < bytes_39214) {
        err = lexical_realloc(ctx, &mem_39235, &mem_39235_cached_sizze_39752, bytes_39214);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:134:5-136:37
    for (int64_t i_38536 = 0; i_38536 < dzlz7bUZLztZRz20U2z20Unz7dUzg_29916; i_38536++) {
        // ../lib/github.com/diku-dk/vtree/vtree.fut:136:11-36
        
        int64_t zv_lhs_35678 = add64((int64_t) -1, i_38536);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:136:11-36
        
        int64_t tmp_35679 = smod64(zv_lhs_35678, dzlz7bUZLztZRz20U2z20Unz7dUzg_29916);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:136:11-36
        
        int64_t lifted_lambda_res_35680 = ((int64_t *) mem_39227)[tmp_35679];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:134:19-43
        
        bool cond_35682 = i_38536 == (int64_t) 0;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:134:19-43
        
        int64_t lifted_lambda_res_35683;
        
        if (cond_35682) {
            lifted_lambda_res_35683 = (int64_t) 0;
        } else {
            lifted_lambda_res_35683 = lifted_lambda_res_35680;
        }
        ((int64_t *) mem_39235)[i_38536] = lifted_lambda_res_35683;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:279:20-285:51
    if (mem_39243_cached_sizze_39753 < bytes_39196) {
        err = lexical_realloc(ctx, &mem_39243, &mem_39243_cached_sizze_39753, bytes_39196);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:279:20-285:51
    if (mem_39244_cached_sizze_39754 < n_20017) {
        err = lexical_realloc(ctx, &mem_39244, &mem_39244_cached_sizze_39754, n_20017);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:279:20-285:51
    if (mem_39246_cached_sizze_39755 < bytes_39196) {
        err = lexical_realloc(ctx, &mem_39246, &mem_39246_cached_sizze_39755, bytes_39196);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:279:20-285:51
    if (mem_39248_cached_sizze_39756 < bytes_39196) {
        err = lexical_realloc(ctx, &mem_39248, &mem_39248_cached_sizze_39756, bytes_39196);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:279:20-285:51
    
    int64_t discard_38552;
    int64_t scanacc_38542 = (int64_t) 0;
    
    for (int64_t i_38547 = 0; i_38547 < n_20017; i_38547++) {
        int64_t eta_p_35657 = ((int64_t *) lp_mem_39193.mem)[i_38547];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:218:19-23
        
        bool x_35659 = sle64((int64_t) 0, eta_p_35657);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:218:19-23
        
        bool y_35660 = slt64(eta_p_35657, dzlz7bUZLztZRz20U2z20Unz7dUzg_29916);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:218:19-23
        
        bool bounds_check_35661 = x_35659 && y_35660;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:218:19-23
        
        bool index_certs_35662;
        
        if (!bounds_check_35661) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) eta_p_35657, "] out of bounds for array of shape [", (long long) dzlz7bUZLztZRz20U2z20Unz7dUzg_29916, "].", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:218:19-23\n   #1  ../lib/github.com/diku-dk/vtree/vtree.fut:220:64-221:21\n   #2  ../lib/github.com/diku-dk/vtree/vtree.fut:273:7-274:22\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        
        int64_t eta_p_35658 = ((int64_t *) mem_39225)[i_38547];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:218:19-23
        
        int64_t lifted_lambda_res_35663 = ((int64_t *) mem_39235)[eta_p_35657];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:274:23-30
        
        int64_t zp_res_35665 = add64(eta_p_35658, lifted_lambda_res_35663);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:279:33-37
        
        bool lifted_lambda_res_35667 = zp_res_35665 == (int64_t) 0;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:279:33-37
        
        bool lifted_lambda_res_35668 = !lifted_lambda_res_35667;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:284:5-285:51
        
        int64_t defunc_0_f_res_35670 = btoi_bool_i64(lifted_lambda_res_35668);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:284:5-285:51
        
        int64_t defunc_0_op_res_28896 = add64(defunc_0_f_res_35670, scanacc_38542);
        
        ((int64_t *) mem_39243)[i_38547] = defunc_0_op_res_28896;
        ((bool *) mem_39244)[i_38547] = lifted_lambda_res_35667;
        ((int64_t *) mem_39246)[i_38547] = defunc_0_f_res_35670;
        ((int64_t *) mem_39248)[i_38547] = zp_res_35665;
        
        int64_t scanacc_tmp_39469 = defunc_0_op_res_28896;
        
        scanacc_38542 = scanacc_tmp_39469;
    }
    discard_38552 = scanacc_38542;
    // ../lib/github.com/diku-dk/vtree/vtree.fut:284:5-285:51
    
    int64_t m_f_res_28905;
    
    if (x_28898) {
        // ../lib/github.com/diku-dk/vtree/vtree.fut:284:5-285:51
        
        int64_t x_35924 = ((int64_t *) mem_39243)[tmp_28899];
        
        m_f_res_28905 = x_35924;
    } else {
        m_f_res_28905 = (int64_t) 0;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:284:5-285:51
    
    int64_t m_28907;
    
    if (cond_28897) {
        m_28907 = (int64_t) 0;
    } else {
        m_28907 = m_f_res_28905;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:284:5-285:51
    
    int64_t bytes_39273 = (int64_t) 8 * m_28907;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:284:5-285:51
    if (memblock_alloc(ctx, &mem_39274, bytes_39273, "mem_39274")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:284:5-285:51
    if (memblock_alloc(ctx, &mem_39276, bytes_39273, "mem_39276")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:284:5-285:51
    if (memblock_alloc(ctx, &mem_39278, bytes_39273, "mem_39278")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:284:5-285:51
    
    bool acc_cert_35579;
    bool acc_cert_35580;
    bool acc_cert_35581;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:277:17-285:51
    for (int64_t i_38556 = 0; i_38556 < n_20017; i_38556++) {
        int64_t eta_p_35616 = ((int64_t *) lp_mem_39193.mem)[i_38556];
        int64_t eta_p_35617 = ((int64_t *) mem_39248)[i_38556];
        int64_t eta_p_35618 = ((int64_t *) rp_mem_39194.mem)[i_38556];
        int64_t eta_p_35619 = ((int64_t *) mem_39246)[i_38556];
        int64_t eta_p_35620 = ((int64_t *) mem_39243)[i_38556];
        int64_t v_35624 = ((int64_t *) data_mem_39192.mem)[i_38556];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:277:22-25
        
        int64_t defunc_0_f_res_35626 = sub64(eta_p_35616, eta_p_35617);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:278:22-25
        
        int64_t defunc_0_f_res_35628 = sub64(eta_p_35618, eta_p_35617);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:284:5-285:51
        
        bool cond_35629 = eta_p_35619 == (int64_t) 1;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:284:5-285:51
        
        int64_t lifted_lambda_res_35630;
        
        if (cond_35629) {
            // ../lib/github.com/diku-dk/vtree/vtree.fut:284:5-285:51
            
            int64_t lifted_lambda_res_t_res_35917 = sub64(eta_p_35620, (int64_t) 1);
            
            lifted_lambda_res_35630 = lifted_lambda_res_t_res_35917;
        } else {
            lifted_lambda_res_35630 = (int64_t) -1;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:284:5-285:51
        // UpdateAcc
        if (sle64((int64_t) 0, lifted_lambda_res_35630) && slt64(lifted_lambda_res_35630, m_28907)) {
            ((int64_t *) mem_39278.mem)[lifted_lambda_res_35630] = defunc_0_f_res_35626;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:284:5-285:51
        // UpdateAcc
        if (sle64((int64_t) 0, lifted_lambda_res_35630) && slt64(lifted_lambda_res_35630, m_28907)) {
            ((int64_t *) mem_39276.mem)[lifted_lambda_res_35630] = defunc_0_f_res_35628;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:284:5-285:51
        // UpdateAcc
        if (sle64((int64_t) 0, lifted_lambda_res_35630) && slt64(lifted_lambda_res_35630, m_28907)) {
            ((int64_t *) mem_39274.mem)[lifted_lambda_res_35630] = v_35624;
        }
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:264:12-297:42
    if (memblock_alloc(ctx, &mem_39279, n_20017, "mem_39279")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:264:12-297:42
    // ../lib/github.com/diku-dk/vtree/vtree.fut:264:12-297:42
    lmad_copy_1b(ctx, 1, (uint8_t *) mem_39279.mem, (int64_t) 0, (int64_t []) {(int64_t) 1}, (uint8_t *) mem_39244, (int64_t) 0, (int64_t []) {(int64_t) 1}, (int64_t []) {n_20017});
    // ../lib/github.com/diku-dk/vtree/vtree.fut:264:12-297:42
    
    int64_t split_res_20103;
    
    if (futrts_deleteVertices_9181(ctx, &ext_mem_39283, &ext_mem_39282, &ext_mem_39281, &split_res_20103, data_mem_39192, lp_mem_39193, rp_mem_39194, mem_39279, n_20017) != 0) {
        err = 1;
        goto cleanup;
    }
    if (memblock_unref(ctx, &mem_39279, "mem_39279") != 0)
        return 1;
    if (memblock_set(ctx, &mem_out_39448, &mem_39274, "mem_39274") != 0)
        return 1;
    if (memblock_set(ctx, &mem_out_39449, &mem_39278, "mem_39278") != 0)
        return 1;
    if (memblock_set(ctx, &mem_out_39450, &mem_39276, "mem_39276") != 0)
        return 1;
    if (memblock_set(ctx, &mem_out_39451, &mem_39213, "mem_39213") != 0)
        return 1;
    if (memblock_set(ctx, &mem_out_39452, &ext_mem_39283, "ext_mem_39283") != 0)
        return 1;
    if (memblock_set(ctx, &mem_out_39453, &ext_mem_39282, "ext_mem_39282") != 0)
        return 1;
    if (memblock_set(ctx, &mem_out_39454, &ext_mem_39281, "ext_mem_39281") != 0)
        return 1;
    prim_out_39455 = m_28907;
    prim_out_39456 = m_29072;
    prim_out_39457 = split_res_20103;
    if (memblock_set(ctx, &*mem_out_p_39736, &mem_out_39448, "mem_out_39448") != 0)
        return 1;
    if (memblock_set(ctx, &*mem_out_p_39737, &mem_out_39449, "mem_out_39449") != 0)
        return 1;
    if (memblock_set(ctx, &*mem_out_p_39738, &mem_out_39450, "mem_out_39450") != 0)
        return 1;
    if (memblock_set(ctx, &*mem_out_p_39739, &mem_out_39451, "mem_out_39451") != 0)
        return 1;
    if (memblock_set(ctx, &*mem_out_p_39740, &mem_out_39452, "mem_out_39452") != 0)
        return 1;
    if (memblock_set(ctx, &*mem_out_p_39741, &mem_out_39453, "mem_out_39453") != 0)
        return 1;
    if (memblock_set(ctx, &*mem_out_p_39742, &mem_out_39454, "mem_out_39454") != 0)
        return 1;
    *out_prim_out_39743 = prim_out_39455;
    *out_prim_out_39744 = prim_out_39456;
    *out_prim_out_39745 = prim_out_39457;
    
  cleanup:
    {
        free(mem_39197);
        free(mem_39199);
        free(mem_39215);
        free(mem_39217);
        free(mem_39225);
        free(mem_39227);
        free(mem_39235);
        free(mem_39243);
        free(mem_39244);
        free(mem_39246);
        free(mem_39248);
        if (memblock_unref(ctx, &ext_mem_39281, "ext_mem_39281") != 0)
            return 1;
        if (memblock_unref(ctx, &ext_mem_39282, "ext_mem_39282") != 0)
            return 1;
        if (memblock_unref(ctx, &ext_mem_39283, "ext_mem_39283") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_39279, "mem_39279") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_39278, "mem_39278") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_39276, "mem_39276") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_39274, "mem_39274") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_39213, "mem_39213") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_out_39454, "mem_out_39454") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_out_39453, "mem_out_39453") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_out_39452, "mem_out_39452") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_out_39451, "mem_out_39451") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_out_39450, "mem_out_39450") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_out_39449, "mem_out_39449") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_out_39448, "mem_out_39448") != 0)
            return 1;
    }
    return err;
}
FUTHARK_FUN_ATTR int futrts_subtree_sizzes_9289(struct futhark_context *ctx, struct memblock *mem_out_p_39757, struct memblock data_mem_39192, struct memblock lp_mem_39193, struct memblock rp_mem_39194, int64_t n_27252)
{
    (void) ctx;
    
    int err = 0;
    int64_t mem_39196_cached_sizze_39758 = 0;
    unsigned char *mem_39196 = NULL;
    int64_t mem_39198_cached_sizze_39759 = 0;
    unsigned char *mem_39198 = NULL;
    int64_t mem_39206_cached_sizze_39760 = 0;
    unsigned char *mem_39206 = NULL;
    struct memblock mem_39214;
    
    mem_39214.references = NULL;
    
    struct memblock mem_out_39448;
    
    mem_out_39448.references = NULL;
    
    bool ok_17775 = ctx->constants->ok_17775;
    bool ok_17859 = ctx->constants->ok_17859;
    bool ok_17938 = ctx->constants->ok_17938;
    bool x_27518 = ctx->constants->x_27518;
    bool x_27521 = ctx->constants->x_27521;
    bool x_27527 = ctx->constants->x_27527;
    bool x_27533 = ctx->constants->x_27533;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:224:13-33
    
    int64_t bytes_39195 = (int64_t) 16 * n_27252;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:227:14-229:21
    
    int64_t bytes_39213 = (int64_t) 8 * n_27252;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:224:24-29
    
    int64_t dzlz7bUZLztZRz20U2z20Unz7dUzg_29056 = mul64((int64_t) 2, n_27252);
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:224:13-33
    if (mem_39196_cached_sizze_39758 < bytes_39195) {
        err = lexical_realloc(ctx, &mem_39196, &mem_39196_cached_sizze_39758, bytes_39195);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:224:13-33
    for (int64_t nest_i_39449 = 0; nest_i_39449 < dzlz7bUZLztZRz20U2z20Unz7dUzg_29056; nest_i_39449++) {
        ((int64_t *) mem_39196)[nest_i_39449] = (int64_t) 0;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:225:13-30
    
    bool acc_cert_29059;
    
    // ../lib/github.com/diku-dk/vtree/vtree.fut:225:13-30
    for (int64_t i_38512 = 0; i_38512 < n_27252; i_38512++) {
        int64_t v_29063 = ((int64_t *) lp_mem_39193.mem)[i_38512];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:225:13-30
        // UpdateAcc
        if (sle64((int64_t) 0, v_29063) && slt64(v_29063, dzlz7bUZLztZRz20U2z20Unz7dUzg_29056)) {
            ((int64_t *) mem_39196)[v_29063] = (int64_t) 1;
        }
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:136:24-36
    if (mem_39198_cached_sizze_39759 < bytes_39195) {
        err = lexical_realloc(ctx, &mem_39198, &mem_39198_cached_sizze_39759, bytes_39195);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:136:24-36
    
    int64_t discard_38518;
    int64_t scanacc_38514 = (int64_t) 0;
    
    for (int64_t i_38516 = 0; i_38516 < dzlz7bUZLztZRz20U2z20Unz7dUzg_29056; i_38516++) {
        int64_t x_29067 = ((int64_t *) mem_39196)[i_38516];
        
        // test_operations.fut:184:17-24
        
        int64_t zp_res_29070 = add64(x_29067, scanacc_38514);
        
        ((int64_t *) mem_39198)[i_38516] = zp_res_29070;
        
        int64_t scanacc_tmp_39451 = zp_res_29070;
        
        scanacc_38514 = scanacc_tmp_39451;
    }
    discard_38518 = scanacc_38514;
    // ../lib/github.com/diku-dk/vtree/vtree.fut:134:5-136:37
    if (mem_39206_cached_sizze_39760 < bytes_39195) {
        err = lexical_realloc(ctx, &mem_39206, &mem_39206_cached_sizze_39760, bytes_39195);
        if (err != FUTHARK_SUCCESS)
            goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:134:5-136:37
    for (int64_t i_38521 = 0; i_38521 < dzlz7bUZLztZRz20U2z20Unz7dUzg_29056; i_38521++) {
        // ../lib/github.com/diku-dk/vtree/vtree.fut:136:11-36
        
        int64_t zv_lhs_35391 = add64((int64_t) -1, i_38521);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:136:11-36
        
        int64_t tmp_35392 = smod64(zv_lhs_35391, dzlz7bUZLztZRz20U2z20Unz7dUzg_29056);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:136:11-36
        
        int64_t lifted_lambda_res_35393 = ((int64_t *) mem_39198)[tmp_35392];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:134:19-43
        
        bool cond_35395 = i_38521 == (int64_t) 0;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:134:19-43
        
        int64_t lifted_lambda_res_35396;
        
        if (cond_35395) {
            lifted_lambda_res_35396 = (int64_t) 0;
        } else {
            lifted_lambda_res_35396 = lifted_lambda_res_35393;
        }
        ((int64_t *) mem_39206)[i_38521] = lifted_lambda_res_35396;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:227:14-229:21
    if (memblock_alloc(ctx, &mem_39214, bytes_39213, "mem_39214")) {
        err = 1;
        goto cleanup;
    }
    // ../lib/github.com/diku-dk/vtree/vtree.fut:227:14-229:21
    for (int64_t i_38525 = 0; i_38525 < n_27252; i_38525++) {
        int64_t eta_p_35372 = ((int64_t *) rp_mem_39194.mem)[i_38525];
        int64_t eta_p_35373 = ((int64_t *) lp_mem_39193.mem)[i_38525];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:227:25-29
        
        bool x_35374 = sle64((int64_t) 0, eta_p_35372);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:227:25-29
        
        bool y_35375 = slt64(eta_p_35372, dzlz7bUZLztZRz20U2z20Unz7dUzg_29056);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:227:25-29
        
        bool bounds_check_35376 = x_35374 && y_35375;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:227:25-29
        
        bool index_certs_35377;
        
        if (!bounds_check_35376) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) eta_p_35372, "] out of bounds for array of shape [", (long long) dzlz7bUZLztZRz20U2z20Unz7dUzg_29056, "].", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:227:25-29\n   #1  test_operations.fut:183:7-184:16\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:228:30-34
        
        bool x_35380 = sle64((int64_t) 0, eta_p_35373);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:228:30-34
        
        bool y_35381 = slt64(eta_p_35373, dzlz7bUZLztZRz20U2z20Unz7dUzg_29056);
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:228:30-34
        
        bool bounds_check_35382 = x_35380 && y_35381;
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:228:30-34
        
        bool index_certs_35383;
        
        if (!bounds_check_35382) {
            set_error(ctx, msgprintf("Error: %s%lld%s%lld%s\n\nBacktrace:\n%s", "Index [", (long long) eta_p_35373, "] out of bounds for array of shape [", (long long) dzlz7bUZLztZRz20U2z20Unz7dUzg_29056, "].", "-> #0  ../lib/github.com/diku-dk/vtree/vtree.fut:228:30-34\n   #1  test_operations.fut:183:7-184:16\n"));
            err = FUTHARK_PROGRAM_ERROR;
            goto cleanup;
        }
        // ../lib/github.com/diku-dk/vtree/vtree.fut:227:25-29
        
        int64_t lifted_lambda_res_35378 = ((int64_t *) mem_39206)[eta_p_35372];
        
        // ../lib/github.com/diku-dk/vtree/vtree.fut:228:30-34
        
        int64_t inv_arg0_35384 = ((int64_t *) mem_39206)[eta_p_35373];
        
        // test_operations.fut:184:25-32
        
        int64_t neg_res_35385 = -inv_arg0_35384;
        
        // test_operations.fut:184:17-24
        
        int64_t zp_res_35387 = add64(lifted_lambda_res_35378, neg_res_35385);
        
        ((int64_t *) mem_39214.mem)[i_38525] = zp_res_35387;
    }
    if (memblock_set(ctx, &mem_out_39448, &mem_39214, "mem_39214") != 0)
        return 1;
    if (memblock_set(ctx, &*mem_out_p_39757, &mem_out_39448, "mem_out_39448") != 0)
        return 1;
    
  cleanup:
    {
        free(mem_39196);
        free(mem_39198);
        free(mem_39206);
        if (memblock_unref(ctx, &mem_39214, "mem_39214") != 0)
            return 1;
        if (memblock_unref(ctx, &mem_out_39448, "mem_out_39448") != 0)
            return 1;
    }
    return err;
}

int futhark_entry_test_delete_vertices(struct futhark_context *ctx, bool *out0)
{
    bool prim_out_39448 = 0;
    int ret = 0;
    
    lock_lock(&ctx->lock);
    if (ret == 0) {
        ret = futrts_entry_test_delete_vertices(ctx, &prim_out_39448);
        if (ret == 0) {
            bool ok_17775 = ctx->constants->ok_17775;
            bool ok_17859 = ctx->constants->ok_17859;
            bool ok_17938 = ctx->constants->ok_17938;
            bool x_27518 = ctx->constants->x_27518;
            bool x_27521 = ctx->constants->x_27521;
            bool x_27527 = ctx->constants->x_27527;
            bool x_27533 = ctx->constants->x_27533;
            
            *out0 = prim_out_39448;
        }
    }
    lock_unlock(&ctx->lock);
    return ret;
}
int futhark_entry_test_merge_no_subtrees(struct futhark_context *ctx, bool *out0)
{
    bool prim_out_39448 = 0;
    int ret = 0;
    
    lock_lock(&ctx->lock);
    if (ret == 0) {
        ret = futrts_entry_test_merge_no_subtrees(ctx, &prim_out_39448);
        if (ret == 0) {
            bool ok_17775 = ctx->constants->ok_17775;
            bool ok_17859 = ctx->constants->ok_17859;
            bool ok_17938 = ctx->constants->ok_17938;
            bool x_27518 = ctx->constants->x_27518;
            bool x_27521 = ctx->constants->x_27521;
            bool x_27527 = ctx->constants->x_27527;
            bool x_27533 = ctx->constants->x_27533;
            
            *out0 = prim_out_39448;
        }
    }
    lock_unlock(&ctx->lock);
    return ret;
}
int futhark_entry_test_merge_tree(struct futhark_context *ctx, bool *out0)
{
    bool prim_out_39448 = 0;
    int ret = 0;
    
    lock_lock(&ctx->lock);
    if (ret == 0) {
        ret = futrts_entry_test_merge_tree(ctx, &prim_out_39448);
        if (ret == 0) {
            bool ok_17775 = ctx->constants->ok_17775;
            bool ok_17859 = ctx->constants->ok_17859;
            bool ok_17938 = ctx->constants->ok_17938;
            bool x_27518 = ctx->constants->x_27518;
            bool x_27521 = ctx->constants->x_27521;
            bool x_27527 = ctx->constants->x_27527;
            bool x_27533 = ctx->constants->x_27533;
            
            *out0 = prim_out_39448;
        }
    }
    lock_unlock(&ctx->lock);
    return ret;
}
int futhark_entry_test_parent_chain4_root0_simple(struct futhark_context *ctx, bool *out0, const struct futhark_i64_1d *in0, const struct futhark_i64_1d *in1)
{
    bool prim_out_39448 = 0;
    int ret = 0;
    
    lock_lock(&ctx->lock);
    
    struct memblock data_mem_39193;
    
    data_mem_39193.references = NULL;
    
    struct memblock parent_mem_39192;
    
    parent_mem_39192.references = NULL;
    parent_mem_39192 = in0->mem;
    data_mem_39193 = in1->mem;
    if (!((int64_t) 4 == in0->shape[0] && (int64_t) 4 == in1->shape[0])) {
        ret = 1;
        set_error(ctx, msgprintf("Error: entry point arguments have invalid sizes.\n"));
    }
    if (ret == 0) {
        ret = futrts_entry_test_parent_chain4_root0_simple(ctx, &prim_out_39448, parent_mem_39192, data_mem_39193);
        if (ret == 0) {
            bool ok_17775 = ctx->constants->ok_17775;
            bool ok_17859 = ctx->constants->ok_17859;
            bool ok_17938 = ctx->constants->ok_17938;
            bool x_27518 = ctx->constants->x_27518;
            bool x_27521 = ctx->constants->x_27521;
            bool x_27527 = ctx->constants->x_27527;
            bool x_27533 = ctx->constants->x_27533;
            
            *out0 = prim_out_39448;
        }
    }
    lock_unlock(&ctx->lock);
    return ret;
}
int futhark_entry_test_parent_singleton_simple(struct futhark_context *ctx, bool *out0, const struct futhark_i64_1d *in0, const struct futhark_i64_1d *in1)
{
    bool prim_out_39448 = 0;
    int ret = 0;
    
    lock_lock(&ctx->lock);
    
    struct memblock data_mem_39193;
    
    data_mem_39193.references = NULL;
    
    struct memblock parent_mem_39192;
    
    parent_mem_39192.references = NULL;
    parent_mem_39192 = in0->mem;
    data_mem_39193 = in1->mem;
    if (!((int64_t) 1 == in0->shape[0] && (int64_t) 1 == in1->shape[0])) {
        ret = 1;
        set_error(ctx, msgprintf("Error: entry point arguments have invalid sizes.\n"));
    }
    if (ret == 0) {
        ret = futrts_entry_test_parent_singleton_simple(ctx, &prim_out_39448, parent_mem_39192, data_mem_39193);
        if (ret == 0) {
            bool ok_17775 = ctx->constants->ok_17775;
            bool ok_17859 = ctx->constants->ok_17859;
            bool ok_17938 = ctx->constants->ok_17938;
            bool x_27518 = ctx->constants->x_27518;
            bool x_27521 = ctx->constants->x_27521;
            bool x_27527 = ctx->constants->x_27527;
            bool x_27533 = ctx->constants->x_27533;
            
            *out0 = prim_out_39448;
        }
    }
    lock_unlock(&ctx->lock);
    return ret;
}
int futhark_entry_test_parent_star5_root3_simple(struct futhark_context *ctx, bool *out0, const struct futhark_i64_1d *in0, const struct futhark_i64_1d *in1)
{
    bool prim_out_39448 = 0;
    int ret = 0;
    
    lock_lock(&ctx->lock);
    
    struct memblock data_mem_39193;
    
    data_mem_39193.references = NULL;
    
    struct memblock parent_mem_39192;
    
    parent_mem_39192.references = NULL;
    parent_mem_39192 = in0->mem;
    data_mem_39193 = in1->mem;
    if (!((int64_t) 5 == in0->shape[0] && (int64_t) 5 == in1->shape[0])) {
        ret = 1;
        set_error(ctx, msgprintf("Error: entry point arguments have invalid sizes.\n"));
    }
    if (ret == 0) {
        ret = futrts_entry_test_parent_star5_root3_simple(ctx, &prim_out_39448, parent_mem_39192, data_mem_39193);
        if (ret == 0) {
            bool ok_17775 = ctx->constants->ok_17775;
            bool ok_17859 = ctx->constants->ok_17859;
            bool ok_17938 = ctx->constants->ok_17938;
            bool x_27518 = ctx->constants->x_27518;
            bool x_27521 = ctx->constants->x_27521;
            bool x_27527 = ctx->constants->x_27527;
            bool x_27533 = ctx->constants->x_27533;
            
            *out0 = prim_out_39448;
        }
    }
    lock_unlock(&ctx->lock);
    return ret;
}
int futhark_entry_test_split(struct futhark_context *ctx, bool *out0)
{
    bool prim_out_39448 = 0;
    int ret = 0;
    
    lock_lock(&ctx->lock);
    if (ret == 0) {
        ret = futrts_entry_test_split(ctx, &prim_out_39448);
        if (ret == 0) {
            bool ok_17775 = ctx->constants->ok_17775;
            bool ok_17859 = ctx->constants->ok_17859;
            bool ok_17938 = ctx->constants->ok_17938;
            bool x_27518 = ctx->constants->x_27518;
            bool x_27521 = ctx->constants->x_27521;
            bool x_27527 = ctx->constants->x_27527;
            bool x_27533 = ctx->constants->x_27533;
            
            *out0 = prim_out_39448;
        }
    }
    lock_unlock(&ctx->lock);
    return ret;
}
int futhark_entry_test_split_at_leaf(struct futhark_context *ctx, bool *out0)
{
    bool prim_out_39448 = 0;
    int ret = 0;
    
    lock_lock(&ctx->lock);
    if (ret == 0) {
        ret = futrts_entry_test_split_at_leaf(ctx, &prim_out_39448);
        if (ret == 0) {
            bool ok_17775 = ctx->constants->ok_17775;
            bool ok_17859 = ctx->constants->ok_17859;
            bool ok_17938 = ctx->constants->ok_17938;
            bool x_27518 = ctx->constants->x_27518;
            bool x_27521 = ctx->constants->x_27521;
            bool x_27527 = ctx->constants->x_27527;
            bool x_27533 = ctx->constants->x_27533;
            
            *out0 = prim_out_39448;
        }
    }
    lock_unlock(&ctx->lock);
    return ret;
}
int futhark_entry_test_split_multiple(struct futhark_context *ctx, bool *out0)
{
    bool prim_out_39448 = 0;
    int ret = 0;
    
    lock_lock(&ctx->lock);
    if (ret == 0) {
        ret = futrts_entry_test_split_multiple(ctx, &prim_out_39448);
        if (ret == 0) {
            bool ok_17775 = ctx->constants->ok_17775;
            bool ok_17859 = ctx->constants->ok_17859;
            bool ok_17938 = ctx->constants->ok_17938;
            bool x_27518 = ctx->constants->x_27518;
            bool x_27521 = ctx->constants->x_27521;
            bool x_27527 = ctx->constants->x_27527;
            bool x_27533 = ctx->constants->x_27533;
            
            *out0 = prim_out_39448;
        }
    }
    lock_unlock(&ctx->lock);
    return ret;
}
int futhark_entry_test_split_none(struct futhark_context *ctx, bool *out0)
{
    bool prim_out_39448 = 0;
    int ret = 0;
    
    lock_lock(&ctx->lock);
    if (ret == 0) {
        ret = futrts_entry_test_split_none(ctx, &prim_out_39448);
        if (ret == 0) {
            bool ok_17775 = ctx->constants->ok_17775;
            bool ok_17859 = ctx->constants->ok_17859;
            bool ok_17938 = ctx->constants->ok_17938;
            bool x_27518 = ctx->constants->x_27518;
            bool x_27521 = ctx->constants->x_27521;
            bool x_27527 = ctx->constants->x_27527;
            bool x_27533 = ctx->constants->x_27533;
            
            *out0 = prim_out_39448;
        }
    }
    lock_unlock(&ctx->lock);
    return ret;
}
  
