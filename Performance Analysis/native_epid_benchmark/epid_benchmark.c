/*
 * Native Intel EPID 2.0 online-operation benchmark for the Di5Guise
 * design-level computation model.
 *
 * This is genuine DAA/EPID: the timed calls are EpidSign and EpidVerify from
 * Intel's open-source EPID SDK.  Ed25519, ECDSA, BBS+, subprocess tools and
 * synthetic delay loops are not used as DAA substitutes.
 *
 * All file parsing, issuer-material authentication, key provisioning, member
 * and verifier context setup, pairing precomputation, revocation-list setup,
 * CSPRNG setup, and buffer allocation happen before either timed region.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "epid/file_parser.h"
#include "epid/gidmanip.h"
#include "epid/member/api.h"
#include "epid/types.h"
#include "epid/verifier.h"

#ifndef BCRYPT_SUCCESS
#define BCRYPT_SUCCESS(status) (((NTSTATUS)(status)) >= 0)
#endif

enum {
  kDefaultWarmup = 1000,
  kDefaultIterations = 10000,
  kQuoteSize = 32
};

static unsigned char const kQuoteMessage[kQuoteSize] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

typedef struct FileBuffer {
  unsigned char* data;
  size_t size;
} FileBuffer;

typedef struct Timings {
  double raw_ns;
  double baseline_ns;
  double corrected_ns;
} Timings;

static void PrintUsage(char const* program) {
  fprintf(stderr,
          "Usage: %s --data-dir DIR --output FILE "
          "[--warmup N] [--iterations N]\n",
          program);
}

static int ParsePositiveInt(char const* text, int* value) {
  char* end = NULL;
  long parsed = 0;
  errno = 0;
  parsed = strtol(text, &end, 10);
  if (errno != 0 || !end || *end != '\0' || parsed <= 0 ||
      parsed > INT32_MAX) {
    return 0;
  }
  *value = (int)parsed;
  return 1;
}

static int JoinPath(char* output, size_t output_size, char const* base,
                    char const* relative) {
  int written = snprintf(output, output_size, "%s\\%s", base, relative);
  return written > 0 && (size_t)written < output_size;
}

static int ReadWholeFile(char const* path, FileBuffer* file) {
  FILE* stream = NULL;
  long file_size = 0;
  size_t bytes_read = 0;

  memset(file, 0, sizeof(*file));
  stream = fopen(path, "rb");
  if (!stream) {
    fprintf(stderr, "ERROR: cannot open %s\n", path);
    return 0;
  }
  if (fseek(stream, 0, SEEK_END) != 0 ||
      (file_size = ftell(stream)) < 0 ||
      fseek(stream, 0, SEEK_SET) != 0) {
    fprintf(stderr, "ERROR: cannot determine size of %s\n", path);
    fclose(stream);
    return 0;
  }
  file->data = (unsigned char*)malloc((size_t)file_size);
  if (!file->data) {
    fprintf(stderr, "ERROR: out of memory reading %s\n", path);
    fclose(stream);
    return 0;
  }
  file->size = (size_t)file_size;
  bytes_read = fread(file->data, 1, file->size, stream);
  fclose(stream);
  if (bytes_read != file->size) {
    fprintf(stderr, "ERROR: short read from %s\n", path);
    free(file->data);
    memset(file, 0, sizeof(*file));
    return 0;
  }
  return 1;
}

static void FreeFile(FileBuffer* file) {
  free(file->data);
  memset(file, 0, sizeof(*file));
}

static int __stdcall WindowsCsprng(unsigned int* rand_data, int num_bits,
                                  void* user_data) {
  ULONG bytes = 0;
  NTSTATUS status = 0;
  (void)user_data;
  if (!rand_data || num_bits < 0) {
    return 1;
  }
  bytes = (ULONG)(((unsigned int)num_bits + 7U) / 8U);
  status = BCryptGenRandom(NULL, (PUCHAR)rand_data, bytes,
                           BCRYPT_USE_SYSTEM_PREFERRED_RNG);
  return BCRYPT_SUCCESS(status) ? 0 : 1;
}

static double CounterDeltaNs(LARGE_INTEGER begin, LARGE_INTEGER end,
                             LARGE_INTEGER frequency) {
  return ((double)(end.QuadPart - begin.QuadPart) * 1000000000.0) /
         (double)frequency.QuadPart;
}

static double CounterTicksNs(LONGLONG ticks, LARGE_INTEGER frequency) {
  return ((double)ticks * 1000000000.0) / (double)frequency.QuadPart;
}

/*
 * Measures only loop/accounting overhead. The compiler barrier prevents the
 * empty loop from disappearing; it performs no cryptographic work.
 */
static double MeasureBaselineNs(int iterations, LARGE_INTEGER frequency) {
  LARGE_INTEGER begin = {0};
  LARGE_INTEGER end = {0};
  int i = 0;
  QueryPerformanceCounter(&begin);
  for (i = 0; i < iterations; ++i) {
#if defined(__GNUC__)
    __asm__ __volatile__("" : : "r"(i) : "memory");
#else
    _ReadWriteBarrier();
#endif
  }
  QueryPerformanceCounter(&end);
  return CounterDeltaNs(begin, end, frequency) / (double)iterations;
}

/*
 * Measures one QPC begin/end bracket per sample. This matches the formal
 * one-at-a-time EpidAddPreSigs and EpidSign measurement structure.
 */
static double MeasureSingleBracketBaselineNs(int iterations,
                                             LARGE_INTEGER frequency) {
  LARGE_INTEGER begin = {0};
  LARGE_INTEGER end = {0};
  LONGLONG total_ticks = 0;
  int i = 0;
  for (i = 0; i < iterations; ++i) {
    QueryPerformanceCounter(&begin);
#if defined(__GNUC__)
    __asm__ __volatile__("" : : "r"(i) : "memory");
#else
    _ReadWriteBarrier();
#endif
    QueryPerformanceCounter(&end);
    total_ticks += end.QuadPart - begin.QuadPart;
  }
  return CounterTicksNs(total_ticks, frequency) / (double)iterations;
}

static int CheckStatus(char const* step, EpidStatus status) {
  if (status != kEpidNoErr) {
    fprintf(stderr, "ERROR: %s failed with EpidStatus=%d\n", step,
            (int)status);
    return 0;
  }
  return 1;
}

static int ParseRl(FileBuffer const* signed_file,
                   EpidCaCertificate const* ca_cert, int kind, void** output,
                   size_t* output_size) {
  EpidStatus status = kEpidErr;
  *output = NULL;
  *output_size = 0;
  if (kind == 0) {
    status = EpidParsePrivRlFile(signed_file->data, signed_file->size, ca_cert,
                                 NULL, output_size);
  } else if (kind == 1) {
    status = EpidParseSigRlFile(signed_file->data, signed_file->size, ca_cert,
                                NULL, output_size);
  } else {
    status = EpidParseGroupRlFile(signed_file->data, signed_file->size, ca_cert,
                                  NULL, output_size);
  }
  if (!CheckStatus("determine parsed revocation-list size", status)) {
    return 0;
  }
  *output = calloc(1, *output_size);
  if (!*output) {
    fprintf(stderr, "ERROR: out of memory parsing revocation list\n");
    return 0;
  }
  if (kind == 0) {
    status = EpidParsePrivRlFile(signed_file->data, signed_file->size, ca_cert,
                                 *output, output_size);
  } else if (kind == 1) {
    status = EpidParseSigRlFile(signed_file->data, signed_file->size, ca_cert,
                                *output, output_size);
  } else {
    status = EpidParseGroupRlFile(signed_file->data, signed_file->size, ca_cert,
                                  *output, output_size);
  }
  if (!CheckStatus("authenticate and parse revocation list", status)) {
    free(*output);
    *output = NULL;
    *output_size = 0;
    return 0;
  }
  return 1;
}

static int WriteJson(char const* output_path, int warmup, int iterations,
                     size_t signature_size, LARGE_INTEGER frequency,
                     Timings presig_time, Timings sign_time,
                     Timings verify_time,
                     int sign_verified_count, char const* hash_name) {
  FILE* output = fopen(output_path, "wb");
  if (!output) {
    fprintf(stderr, "ERROR: cannot write %s\n", output_path);
    return 0;
  }
  fprintf(
      output,
      "{\n"
      "  \"schema_version\": 2,\n"
      "  \"implementation\": \"Intel EPID SDK 8.0.0 (Intel EPID 2.0)\",\n"
      "  \"repository\": \"https://github.com/Intel-EPID-SDK/epid-sdk\",\n"
      "  \"commit\": \"389426ff4ba2286d2e133bec29d178427d434d8c\",\n"
      "  \"epid_version\": \"2.0\",\n"
      "  \"daa_class\": \"pairing-based Enhanced Privacy ID / DAA\",\n"
      "  \"curve\": \"256-bit Barreto-Naehrig pairing-friendly curve, "
      "embedding degree 12\",\n"
      "  \"security_level_bits\": 128,\n"
      "  \"hash_algorithm\": \"%s\",\n"
      "  \"basename_mode\": \"random basename (anonymous/unlinkable)\",\n"
      "  \"basename\": null,\n"
      "  \"revocation_lists\": {\n"
      "    \"group_rl\": \"official signed empty GroupRL (0 entries)\",\n"
      "    \"private_rl\": \"official signed empty PrivRL (0 entries)\",\n"
      "    \"signature_rl\": \"official signed empty SigRL (0 entries)\",\n"
      "    \"verifier_rl\": \"not applicable: Intel EPID forbids VerifierRL "
      "with random basename\"\n"
      "  },\n"
      "  \"presignature_policy\": {\n"
      "    \"api\": \"EpidAddPreSigs\",\n"
      "    \"policy\": \"one fresh single-use pre-signature per EpidSign\",\n"
      "    \"pool_filled_before_each_timed_sign\": true,\n"
      "    \"pool_empty_after_each_timed_sign\": true,\n"
      "    \"offline_cost_excluded_from_T_DG\": true\n"
      "  },\n"
      "  \"message_length_bytes\": 32,\n"
      "  \"message_hex\": "
      "\"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\",\n"
      "  \"signature_length_bytes\": %zu,\n"
      "  \"warmup_iterations\": %d,\n"
      "  \"measurement_iterations\": %d,\n"
      "  \"timer\": \"Windows QueryPerformanceCounter\",\n"
      "  \"qpc_frequency_hz\": %" PRId64 ",\n"
      "  \"timed_scope\": {\n"
      "    \"pre_signature_generation\": \"one offline EpidAddPreSigs "
      "pre-signature; disclosed separately and excluded from T_DG\",\n"
      "    \"T_DG\": \"one direct online EpidSign call consuming exactly one "
      "pre-signature\",\n"
      "    \"T_DV\": \"one direct EpidVerify call on an already generated "
      "valid quote\"\n"
      "  },\n"
      "  \"correctness\": {\n"
      "    \"initial_self_check\": true,\n"
      "    \"all_measured_signatures_verified\": true,\n"
      "    \"measured_signatures_verified_count\": %d,\n"
      "    \"measured_presignatures_generated_count\": %d,\n"
      "    \"presignature_pool_before_each_T_DG\": 1,\n"
      "    \"presignature_pool_after_each_T_DG\": 0,\n"
      "    \"one_presignature_consumed_per_signature\": true,\n"
      "    \"all_timed_verifications_valid\": true\n"
      "  },\n"
      "  \"offline_precomputation\": {\n"
      "    \"operation\": \"EpidAddPreSigs average per single-use "
      "pre-signature\",\n"
      "    \"included_in_di5guise_formula\": false,\n"
      "    \"raw_avg_ns\": %.6f,\n"
      "    \"raw_avg_us\": %.9f,\n"
      "    \"raw_avg_ms\": %.12f,\n"
      "    \"baseline_avg_ns\": %.6f,\n"
      "    \"corrected_avg_ns\": %.6f,\n"
      "    \"corrected_avg_us\": %.9f,\n"
      "    \"corrected_avg_ms\": %.12f\n"
      "  },\n"
      "  \"operations\": {\n"
      "    \"T_DG\": {\n"
      "      \"raw_avg_ns\": %.6f,\n"
      "      \"raw_avg_us\": %.9f,\n"
      "      \"raw_avg_ms\": %.12f,\n"
      "      \"baseline_avg_ns\": %.6f,\n"
      "      \"corrected_avg_ns\": %.6f,\n"
      "      \"corrected_avg_us\": %.9f,\n"
      "      \"corrected_avg_ms\": %.12f\n"
      "    },\n"
      "    \"T_DV\": {\n"
      "      \"raw_avg_ns\": %.6f,\n"
      "      \"raw_avg_us\": %.9f,\n"
      "      \"raw_avg_ms\": %.12f,\n"
      "      \"baseline_avg_ns\": %.6f,\n"
      "      \"corrected_avg_ns\": %.6f,\n"
      "      \"corrected_avg_us\": %.9f,\n"
      "      \"corrected_avg_ms\": %.12f\n"
      "    }\n"
      "  }\n"
      "}\n",
      hash_name, signature_size, warmup, iterations,
      (int64_t)frequency.QuadPart,
      sign_verified_count, iterations, presig_time.raw_ns,
      presig_time.raw_ns / 1000.0, presig_time.raw_ns / 1000000.0,
      presig_time.baseline_ns, presig_time.corrected_ns,
      presig_time.corrected_ns / 1000.0,
      presig_time.corrected_ns / 1000000.0,
      sign_time.raw_ns, sign_time.raw_ns / 1000.0,
      sign_time.raw_ns / 1000000.0, sign_time.baseline_ns,
      sign_time.corrected_ns, sign_time.corrected_ns / 1000.0,
      sign_time.corrected_ns / 1000000.0, verify_time.raw_ns,
      verify_time.raw_ns / 1000.0, verify_time.raw_ns / 1000000.0,
      verify_time.baseline_ns, verify_time.corrected_ns,
      verify_time.corrected_ns / 1000.0,
      verify_time.corrected_ns / 1000000.0);
  if (fclose(output) != 0) {
    fprintf(stderr, "ERROR: failed to close %s\n", output_path);
    return 0;
  }
  return 1;
}

int main(int argc, char** argv) {
  char const* data_dir = NULL;
  char const* output_path = NULL;
  int warmup = kDefaultWarmup;
  int iterations = kDefaultIterations;
  int i = 0;
  int exit_code = EXIT_FAILURE;
  char path[4096] = {0};
  FileBuffer ca_file = {0};
  FileBuffer pubkey_file = {0};
  FileBuffer privkey_file = {0};
  FileBuffer signed_sig_rl_file = {0};
  FileBuffer signed_priv_rl_file = {0};
  FileBuffer signed_group_rl_file = {0};
  EpidCaCertificate ca_cert = {0};
  GroupPubKey pub_key = {0};
  PrivKey priv_key = {0};
  MembershipCredential credential = {0};
  MemberPrecomp member_precomp = {0};
  VerifierPrecomp verifier_precomp = {0};
  SigRl* sig_rl = NULL;
  PrivRl* priv_rl = NULL;
  GroupRl* group_rl = NULL;
  size_t sig_rl_size = 0;
  size_t priv_rl_size = 0;
  size_t group_rl_size = 0;
  MemberParams member_params = {0};
  MemberCtx* member = NULL;
  size_t member_size = 0;
  VerifierCtx* verifier = NULL;
  EpidSignature* fixed_signature = NULL;
  EpidSignature* measured_signatures = NULL;
  size_t signature_size = 0;
  LARGE_INTEGER frequency = {0};
  LARGE_INTEGER begin = {0};
  LARGE_INTEGER end = {0};
  LONGLONG presig_ticks = 0;
  LONGLONG sign_ticks = 0;
  Timings sign_time = {0};
  Timings verify_time = {0};
  Timings presig_time = {0};
  EpidStatus status = kEpidErr;
  HashAlg group_hash = kInvalidHashAlg;
  char const* hash_name = "UNKNOWN";
  int verified_signatures = 0;

  for (i = 1; i < argc; ++i) {
    if (strcmp(argv[i], "--data-dir") == 0 && i + 1 < argc) {
      data_dir = argv[++i];
    } else if (strcmp(argv[i], "--output") == 0 && i + 1 < argc) {
      output_path = argv[++i];
    } else if (strcmp(argv[i], "--warmup") == 0 && i + 1 < argc) {
      if (!ParsePositiveInt(argv[++i], &warmup)) {
        PrintUsage(argv[0]);
        return EXIT_FAILURE;
      }
    } else if (strcmp(argv[i], "--iterations") == 0 && i + 1 < argc) {
      if (!ParsePositiveInt(argv[++i], &iterations)) {
        PrintUsage(argv[0]);
        return EXIT_FAILURE;
      }
    } else {
      PrintUsage(argv[0]);
      return EXIT_FAILURE;
    }
  }
  if (!data_dir || !output_path) {
    PrintUsage(argv[0]);
    return EXIT_FAILURE;
  }
  if (!QueryPerformanceFrequency(&frequency) || frequency.QuadPart <= 0) {
    fprintf(stderr, "ERROR: QueryPerformanceFrequency failed\n");
    return EXIT_FAILURE;
  }

#define LOAD_FILE(relative, destination)                                      \
  do {                                                                        \
    if (!JoinPath(path, sizeof(path), data_dir, (relative)) ||                \
        !ReadWholeFile(path, &(destination))) {                               \
      goto cleanup;                                                           \
    }                                                                         \
  } while (0)

  LOAD_FILE("cacert.bin", ca_file);
  LOAD_FILE("pubkey.bin", pubkey_file);
  LOAD_FILE("mprivkey.dat", privkey_file);
  LOAD_FILE("groupa\\sigrl_empty.bin", signed_sig_rl_file);
  LOAD_FILE("groupa\\privrl_empty.bin", signed_priv_rl_file);
  LOAD_FILE("grprl_empty.bin", signed_group_rl_file);

#undef LOAD_FILE

  if (ca_file.size != sizeof(ca_cert) ||
      privkey_file.size != sizeof(priv_key)) {
    fprintf(stderr,
            "ERROR: unexpected issuer material size (CA=%zu, private=%zu)\n",
            ca_file.size, privkey_file.size);
    goto cleanup;
  }
  memcpy(&ca_cert, ca_file.data, sizeof(ca_cert));
  memcpy(&priv_key, privkey_file.data, sizeof(priv_key));

  status = EpidParseGroupPubKeyFile(pubkey_file.data, pubkey_file.size,
                                    &ca_cert, &pub_key);
  if (!CheckStatus("authenticate and parse group public key", status)) {
    goto cleanup;
  }
  status = EpidGetHashAlg(&pub_key.gid, &group_hash);
  if (!CheckStatus("read hash algorithm from group ID", status)) {
    goto cleanup;
  }
  if (group_hash == kSha256) {
    hash_name = "SHA-256";
  } else if (group_hash == kSha384) {
    hash_name = "SHA-384";
  } else if (group_hash == kSha512) {
    hash_name = "SHA-512";
  } else if (group_hash == kSha512_256) {
    hash_name = "SHA-512/256";
  } else {
    fprintf(stderr, "ERROR: unsupported group hash algorithm %d\n",
            (int)group_hash);
    goto cleanup;
  }
  if (!ParseRl(&signed_sig_rl_file, &ca_cert, 1, (void**)&sig_rl,
               &sig_rl_size) ||
      !ParseRl(&signed_priv_rl_file, &ca_cert, 0, (void**)&priv_rl,
               &priv_rl_size) ||
      !ParseRl(&signed_group_rl_file, &ca_cert, 2, (void**)&group_rl,
               &group_rl_size)) {
    goto cleanup;
  }

  memcpy(&credential.gid, &priv_key.gid, sizeof(credential.gid));
  memcpy(&credential.A, &priv_key.A, sizeof(credential.A));
  memcpy(&credential.x, &priv_key.x, sizeof(credential.x));
  status = EpidMemberWritePrecomp(&pub_key, &credential, &member_precomp);
  if (!CheckStatus("member pairing precomputation", status)) {
    goto cleanup;
  }

  status =
      EpidMemberSetEntropyGenerator(&WindowsCsprng, NULL, &member_params);
  if (!CheckStatus("configure Windows CSPRNG", status)) {
    goto cleanup;
  }
  status = EpidMemberGetSize(&member_params, &member_size);
  if (!CheckStatus("determine member context size", status)) {
    goto cleanup;
  }
  member = (MemberCtx*)calloc(1, member_size);
  if (!member) {
    fprintf(stderr, "ERROR: cannot allocate member context\n");
    goto cleanup;
  }
  status = EpidMemberInit(&member_params, member);
  if (!CheckStatus("initialize member context", status)) {
    goto cleanup;
  }
  status = EpidProvisionKey(member, &pub_key, &priv_key, &member_precomp);
  if (!CheckStatus("provision official test member key", status)) {
    goto cleanup;
  }
  status = EpidMemberStartup(member);
  if (!CheckStatus("start member context", status)) {
    goto cleanup;
  }
  status = EpidMemberSetHashAlg(member, group_hash);
  if (!CheckStatus("set member hash from group ID", status)) {
    goto cleanup;
  }
  status = EpidMemberSetSigRl(member, sig_rl, sig_rl_size);
  if (!CheckStatus("set empty member SigRL", status)) {
    goto cleanup;
  }

  status = EpidVerifierCreate(&pub_key, NULL, &verifier);
  if (!CheckStatus("create verifier context and precompute pairings", status)) {
    goto cleanup;
  }
  status = EpidVerifierWritePrecomp(verifier, &verifier_precomp);
  if (!CheckStatus("serialize verifier precomputation", status)) {
    goto cleanup;
  }
  status = EpidVerifierSetHashAlg(verifier, group_hash);
  if (!CheckStatus("set verifier hash from group ID", status)) {
    goto cleanup;
  }
  status = EpidVerifierSetBasename(verifier, NULL, 0);
  if (!CheckStatus("set random/unlinkable verifier basename mode", status)) {
    goto cleanup;
  }
  status = EpidVerifierSetPrivRl(verifier, priv_rl, priv_rl_size);
  if (!CheckStatus("set empty verifier PrivRL", status)) {
    goto cleanup;
  }
  status = EpidVerifierSetSigRl(verifier, sig_rl, sig_rl_size);
  if (!CheckStatus("set empty verifier SigRL", status)) {
    goto cleanup;
  }
  status = EpidVerifierSetGroupRl(verifier, group_rl, group_rl_size);
  if (!CheckStatus("set empty verifier GroupRL", status)) {
    goto cleanup;
  }
  if (EpidGetVerifierRlSize(verifier) != 0) {
    fprintf(stderr,
            "ERROR: random-basename verifier unexpectedly exposed a "
            "VerifierRL\n");
    goto cleanup;
  }

  signature_size = EpidGetSigSize(sig_rl);
  fixed_signature = (EpidSignature*)calloc(1, signature_size);
  if (!fixed_signature) {
    fprintf(stderr, "ERROR: cannot allocate fixed signature\n");
    goto cleanup;
  }
  if ((size_t)iterations > SIZE_MAX / signature_size) {
    fprintf(stderr, "ERROR: signature buffer size overflow\n");
    goto cleanup;
  }
  measured_signatures =
      (EpidSignature*)calloc((size_t)iterations, signature_size);
  if (!measured_signatures) {
    fprintf(stderr, "ERROR: cannot allocate measured signature buffers\n");
    goto cleanup;
  }

  /* Initial correctness self-check before any warmup or measurement. */
  status = EpidAddPreSigs(member, 1);
  if (!CheckStatus("create one initial single-use pre-signature", status) ||
      EpidGetNumPreSigs(member) != 1) {
    fprintf(stderr, "ERROR: initial pre-signature pool size is not one\n");
    goto cleanup;
  }
  status = EpidSign(member, kQuoteMessage, sizeof(kQuoteMessage), NULL, 0,
                    fixed_signature, signature_size);
  if (!CheckStatus("initial EpidSign self-check", status)) {
    goto cleanup;
  }
  if (EpidGetNumPreSigs(member) != 0) {
    fprintf(stderr, "ERROR: initial EpidSign did not consume one pre-signature\n");
    goto cleanup;
  }
  status = EpidVerify(verifier, fixed_signature, signature_size, kQuoteMessage,
                      sizeof(kQuoteMessage));
  if (!CheckStatus("initial EpidVerify self-check", status)) {
    goto cleanup;
  }

  printf("Intel EPID native benchmark\n");
  printf("Implementation: Intel EPID SDK 8.0.0 / Intel EPID 2.0\n");
  printf("Direct APIs: EpidSign + EpidVerify\n");
  printf("Warmup: %d per operation; measured: %d per operation\n", warmup,
         iterations);
  printf("Quote: 32 bytes; signature: %zu bytes; hash: %s\n",
         signature_size, hash_name);
  printf("Basename: random base (anonymous/unlinkable; NULL, 0)\n");
  printf("Revocation lists: GroupRL=0, PrivRL=0, SigRL=0, "
         "VerifierRL=N/A for random base\n");
  printf("Pre-signature policy: one fresh EpidAddPreSigs item consumed by "
         "each EpidSign\n");
  printf("Initial correctness self-check: PASS\n");
  fflush(stdout);

  /*
   * T_DG warmup: create exactly one single-use pre-signature for every
   * untimed signing operation, then verify each result.
   */
  for (i = 0; i < warmup; ++i) {
    status = EpidAddPreSigs(member, 1);
    if (status != kEpidNoErr || EpidGetNumPreSigs(member) != 1) {
      fprintf(stderr,
              "ERROR: prepare one T_DG warmup pre-signature failed at "
              "iteration %d (EpidStatus=%d)\n",
              i, (int)status);
      goto cleanup;
    }
    status = EpidSign(member, kQuoteMessage, sizeof(kQuoteMessage), NULL, 0,
                      fixed_signature, signature_size);
    if (status != kEpidNoErr || EpidGetNumPreSigs(member) != 0 ||
        EpidVerify(verifier, fixed_signature, signature_size, kQuoteMessage,
                   sizeof(kQuoteMessage)) != kEpidNoErr) {
      fprintf(stderr, "ERROR: sign warmup/self-check failed at iteration %d\n",
              i);
      goto cleanup;
    }
  }
  if (EpidGetNumPreSigs(member) != 0) {
    fprintf(stderr,
            "ERROR: T_DG warmup did not consume exactly one pre-signature "
            "per signature\n");
    goto cleanup;
  }
  printf("T_DG warmup and validation: PASS (%d signatures)\n", warmup);
  fflush(stdout);

  /*
   * For each formal sample, generate exactly one pre-signature first, outside
   * the T_DG bracket, and then time one EpidSign that consumes it. This avoids
   * hiding precomputation in T_DG and avoids an unrealistically large pool.
   * The offline EpidAddPreSigs cost is timed and reported separately.
   */
  presig_time.baseline_ns =
      MeasureSingleBracketBaselineNs(iterations, frequency);
  sign_time.baseline_ns =
      MeasureSingleBracketBaselineNs(iterations, frequency);
  for (i = 0; i < iterations; ++i) {
    EpidSignature* slot =
        (EpidSignature*)((unsigned char*)measured_signatures +
                        (size_t)i * signature_size);
    QueryPerformanceCounter(&begin);
    status = EpidAddPreSigs(member, 1);
    QueryPerformanceCounter(&end);
    presig_ticks += end.QuadPart - begin.QuadPart;
    if (status != kEpidNoErr || EpidGetNumPreSigs(member) != 1) {
      fprintf(stderr,
              "ERROR: measured EpidAddPreSigs failed at iteration %d "
              "(EpidStatus=%d)\n",
              i, (int)status);
      goto cleanup;
    }

    QueryPerformanceCounter(&begin);
    status = EpidSign(member, kQuoteMessage, sizeof(kQuoteMessage), NULL, 0,
                      slot, signature_size);
    QueryPerformanceCounter(&end);
    sign_ticks += end.QuadPart - begin.QuadPart;
    if (status != kEpidNoErr) {
      fprintf(stderr, "ERROR: measured EpidSign failed at iteration %d\n", i);
      goto cleanup;
    }
    if (EpidGetNumPreSigs(member) != 0) {
      fprintf(stderr,
              "ERROR: measured EpidSign did not consume its one "
              "pre-signature at iteration %d\n",
              i);
      goto cleanup;
    }
  }
  presig_time.raw_ns =
      CounterTicksNs(presig_ticks, frequency) / (double)iterations;
  presig_time.corrected_ns =
      presig_time.raw_ns - presig_time.baseline_ns;
  if (presig_time.corrected_ns < 0.0) {
    presig_time.corrected_ns = 0.0;
  }
  sign_time.raw_ns =
      CounterTicksNs(sign_ticks, frequency) / (double)iterations;
  sign_time.corrected_ns = sign_time.raw_ns - sign_time.baseline_ns;
  if (sign_time.corrected_ns < 0.0) {
    sign_time.corrected_ns = 0.0;
  }
  printf("Offline pre-signatures generated and consumed one-by-one: "
         "PASS (%d items)\n",
         iterations);
  fflush(stdout);

  /*
   * Correctness is checked outside the T_DG timed region, but every signature
   * produced by the measured loop must validate.
   */
  for (i = 0; i < iterations; ++i) {
    EpidSignature const* slot =
        (EpidSignature const*)((unsigned char const*)measured_signatures +
                              (size_t)i * signature_size);
    status = EpidVerify(verifier, slot, signature_size, kQuoteMessage,
                        sizeof(kQuoteMessage));
    if (status != kEpidNoErr) {
      fprintf(stderr,
              "ERROR: measured signature failed validation at iteration %d\n",
              i);
      goto cleanup;
    }
    ++verified_signatures;
  }
  printf("T_DG measured signatures validated: PASS (%d/%d)\n",
         verified_signatures, iterations);
  fflush(stdout);

  /*
   * T_DV warmup and measurement verify one already generated valid quote.
   * No signing, allocation, parsing, or context setup occurs in this scope.
   */
  for (i = 0; i < warmup; ++i) {
    status = EpidVerify(verifier, fixed_signature, signature_size,
                        kQuoteMessage, sizeof(kQuoteMessage));
    if (status != kEpidNoErr) {
      fprintf(stderr, "ERROR: verify warmup failed at iteration %d\n", i);
      goto cleanup;
    }
  }
  printf("T_DV warmup: PASS (%d valid verifications)\n", warmup);
  fflush(stdout);

  verify_time.baseline_ns = MeasureBaselineNs(iterations, frequency);
  QueryPerformanceCounter(&begin);
  for (i = 0; i < iterations; ++i) {
    status = EpidVerify(verifier, fixed_signature, signature_size,
                        kQuoteMessage, sizeof(kQuoteMessage));
    if (status != kEpidNoErr) {
      fprintf(stderr, "ERROR: measured EpidVerify failed at iteration %d\n",
              i);
      goto cleanup;
    }
  }
  QueryPerformanceCounter(&end);
  verify_time.raw_ns =
      CounterDeltaNs(begin, end, frequency) / (double)iterations;
  verify_time.corrected_ns = verify_time.raw_ns - verify_time.baseline_ns;
  if (verify_time.corrected_ns < 0.0) {
    verify_time.corrected_ns = 0.0;
  }

  printf("Offline EpidAddPreSigs average: %.3f ns | %.6f us | %.9f ms\n",
         presig_time.raw_ns, presig_time.raw_ns / 1000.0,
         presig_time.raw_ns / 1000000.0);
  printf("Offline EpidAddPreSigs baseline-corrected: %.3f ns | %.6f us | "
         "%.9f ms\n",
         presig_time.corrected_ns, presig_time.corrected_ns / 1000.0,
         presig_time.corrected_ns / 1000000.0);
  printf("T_DG online raw average: %.3f ns | %.6f us | %.9f ms\n",
         sign_time.raw_ns, sign_time.raw_ns / 1000.0,
         sign_time.raw_ns / 1000000.0);
  printf("T_DG online baseline-corrected: %.3f ns | %.6f us | %.9f ms\n",
         sign_time.corrected_ns, sign_time.corrected_ns / 1000.0,
         sign_time.corrected_ns / 1000000.0);
  printf("T_DV raw average: %.3f ns | %.6f us | %.9f ms\n",
         verify_time.raw_ns, verify_time.raw_ns / 1000.0,
         verify_time.raw_ns / 1000000.0);
  printf("T_DV baseline-corrected: %.3f ns | %.6f us | %.9f ms\n",
         verify_time.corrected_ns, verify_time.corrected_ns / 1000.0,
         verify_time.corrected_ns / 1000000.0);
  printf("All timed verifications valid: PASS (%d/%d)\n", iterations,
         iterations);

  if (!WriteJson(output_path, warmup, iterations, signature_size, frequency,
                 presig_time, sign_time, verify_time, verified_signatures,
                 hash_name)) {
    goto cleanup;
  }
  printf("Result JSON: %s\n", output_path);
  printf("Benchmark status: OK\n");
  exit_code = EXIT_SUCCESS;

cleanup:
  EpidVerifierDelete(&verifier);
  if (member) {
    EpidMemberDeinit(member);
  }
  free(member);
  free(measured_signatures);
  free(fixed_signature);
  free(group_rl);
  free(priv_rl);
  free(sig_rl);
  FreeFile(&signed_group_rl_file);
  FreeFile(&signed_priv_rl_file);
  FreeFile(&signed_sig_rl_file);
  FreeFile(&privkey_file);
  FreeFile(&pubkey_file);
  FreeFile(&ca_file);
  return exit_code;
}
