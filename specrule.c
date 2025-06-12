#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>

#define PRIVATE_RULE_SPEC_SIZE 72

// spec_t holds the 72-byte packed spec
typedef struct {
    uint8_t data[PRIVATE_RULE_SPEC_SIZE];
} spec_t;

// Pack mask_pre and mask_post (as 64-bit ints) into 32-byte big-endian slots
void pack_spec(spec_t *spec, uint64_t mask_pre, uint64_t mask_post, uint16_t reps, bool flip) {
    // zero everything
    memset(spec->data, 0, PRIVATE_RULE_SPEC_SIZE);
    // pack mask_pre into bytes 0..31 (last 8 bytes used)
    for (int i = 0; i < 8; i++) {
        spec->data[31 - i] = (uint8_t)(mask_pre & 0xFF);
        mask_pre >>= 8;
    }
    // pack mask_post into bytes 32..63
    for (int i = 0; i < 8; i++) {
        spec->data[63 - i] = (uint8_t)(mask_post & 0xFF);
        mask_post >>= 8;
    }
    // pack reps (big-endian) into bytes 64..65
    spec->data[64] = (uint8_t)((reps >> 8) & 0xFF);
    spec->data[65] = (uint8_t)(reps & 0xFF);
    // pack flip into byte 66
    spec->data[66] = flip ? 1 : 0;
    // bytes 67..71 remain zero padding
}

// Unpack mask_pre, mask_post, reps, flip from spec
void unpack_spec(const spec_t *spec, uint64_t *mask_pre, uint64_t *mask_post, uint16_t *reps, bool *flip) {
    // read mask_pre from bytes 31..24
    *mask_pre = 0;
    for (int i = 0; i < 8; i++) {
        *mask_pre |= (uint64_t)spec->data[31 - i] << (8 * i);
    }
    // read mask_post from bytes 63..56
    *mask_post = 0;
    for (int i = 0; i < 8; i++) {
        *mask_post |= (uint64_t)spec->data[63 - i] << (8 * i);
    }
    // read reps from bytes 64..65
    *reps = ((uint16_t)spec->data[64] << 8) | spec->data[65];
    // read flip from byte 66
    *flip = spec->data[66] != 0;
}

// --- bit helpers ---
// parity of 64-bit integer
static inline int parity64(uint64_t x) {
    return __builtin_parityll(x);
}

// count bits in 64-bit integer
static inline int bit_sum64(uint64_t x) {
    return __builtin_popcountll(x);
}

// reverse bits of width bit_width
uint64_t reverse_bits(uint64_t x, int bit_width) {
    uint64_t result = 0;
    for (int i = 0; i < bit_width; i++) {
        result = (result << 1) | (x & 1ULL);
        x >>= 1;
    }
    return result;
}

// Extract an N-bit window starting at position i on a ring of length L.
static inline uint64_t extract_window_on_ring(uint64_t state, int i, int L, int N) {
    uint64_t w = 0;
    for (int j = 0; j < N; j++) {
        int idx = (i + j) % L;
        int bit = (state >> idx) & 1ULL;
        w = (w << 1) | (uint64_t)bit;
    }
    return w;
}

// Apply a 1D CA rule on a ring: for each cell i, look up the N-bit neighborhood
// and set the output bit accordingly.
uint64_t apply_rule_on_ring(uint64_t state, uint64_t rule, int L, int N) {
    uint64_t out = 0;
    for (int i = 0; i < L; i++) {
        uint64_t w     = extract_window_on_ring(state, i, L, N);
        uint64_t bit_i = (rule >> w) & 1ULL;
        out |= bit_i << i;
    }
    return out;
}


// extract N-bit window starting at position i from finite CA state, padded by pad_bit
uint64_t extract_window_finite(uint64_t state, int i, int L, int N, int pad_bit) {
    uint64_t w = 0;
    for (int j = 0; j < N; j++) {
        int idx = i + j;
        int bit = (idx >= 0 && idx < L) ? (int)((state >> idx) & 1ULL) : pad_bit;
        w = (w << 1) | (uint64_t)bit;
    }
    return w;
}

// apply rule with expansion (grow = 1) on finite CA
// returns new state; new length = L+1
uint64_t apply_rule_expand(uint64_t state, uint64_t rule, int L, int N, int pad_bit) {
    int grow = 1;
    int new_L = L + grow;
    uint64_t padded = (state << grow) | ((uint64_t)pad_bit & ((1ULL << grow) - 1));
    uint64_t out = 0;
    for (int i = 0; i < new_L; i++) {
        uint64_t w = extract_window_finite(padded, i, new_L, N, pad_bit);
        int bit_i = (rule >> w) & 1ULL;
        out |= (uint64_t)bit_i << i;
    }
    return out;
}

// implements_spec: returns true if parity(mask_pre & pre) ^ flip == parity(mask_post & post)
bool implements_spec(uint64_t pre, uint64_t post, const spec_t *spec) {
    uint64_t mask_pre, mask_post;
    uint16_t reps;
    bool flip;
    unpack_spec(spec, &mask_pre, &mask_post, &reps, &flip);
    int p1 = parity64(mask_pre & pre);
    int p2 = parity64(mask_post & post);
    return (p1 ^ (int)flip) == p2;
}

// random_bitmask: choose P distinct bit positions from N, return mask
uint64_t random_bitmask(int N, int P) {
    if (N < 0 || P < 0 || P > N) {
        fprintf(stderr, "random_bitmask: invalid N,P\n");
        exit(EXIT_FAILURE);
    }
    uint64_t mask = 0;
    int *positions = malloc(N * sizeof(int));
    for (int i = 0; i < N; i++) positions[i] = i;
    // Fisher-Yates sample P out of N
    for (int i = 0; i < P; i++) {
        int r = i + rand() % (N - i);
        int tmp = positions[i]; positions[i] = positions[r]; positions[r] = tmp;
        mask |= 1ULL << positions[i];
    }
    free(positions);
    return mask;
}

// random_rule: choose a rule in [0, 2^(2^N))
uint64_t random_rule(int N) {
    uint64_t max = 1ULL << (1 << N);
    return (uint64_t)rand() % max;
}

// get_resulting_len stub (identity)
int get_resulting_len(int L_start, int N, int M) {
    return L_start;
}

// generate random spec with 1 bit mask
spec_t get_random_spec1(int L_start, int N, int M) {
    int L = get_resulting_len(L_start, N, M);
    spec_t spec;
    pack_spec(&spec,
              random_bitmask(L_start, 1),
              random_bitmask(L, 1),
              (uint16_t)M,
              rand() & 1);
    return spec;
}
// generate random spec with 2 bit mask
spec_t get_random_spec2(int L_start, int N, int M) {
    int L = get_resulting_len(L_start, N, M);
    spec_t spec;
    pack_spec(&spec,
              random_bitmask(L_start, 2),
              random_bitmask(L, 2),
              (uint16_t)M,
              rand() & 1);
    return spec;
}

// flip_spec: invert flip bit
spec_t flip_spec(const spec_t *in) {
    spec_t out = *in;
    out.data[66] ^= 1;
    return out;
}

// spec_matches_rule: returns whether rule matches spec (either orientation), and flip flag
bool spec_matches_rule(int L_start, int N, const spec_t *spec, uint64_t rule, bool *out_flip) {
    uint64_t pad = ((1ULL << N) - 1);
    uint64_t mask_pre, mask_post;
    uint16_t reps;
    bool flip;
    unpack_spec(spec, &mask_pre, &mask_post, &reps, &flip);
    spec_t spec_flip = flip_spec(spec);
    bool ok = true, ok_flip = true;
    for (uint64_t pre = 0; pre < (1ULL << L_start); ++pre) {
        uint64_t curr = pre;
        for (int r = 0; r < reps; ++r) {
            curr = apply_rule_on_ring(curr, rule, L_start, N);
        }
        if (ok && !implements_spec(pre, curr, spec)) ok = false;
        if (ok_flip && !implements_spec(pre, curr, &spec_flip)) ok_flip = false;
        if (!ok && !ok_flip) break;
    }
    if (ok || ok_flip) {
        *out_flip = !ok; // if ok_flip only, flip true
        return true;
    }
    return false;
}

// get_spec_matching_rule: tries up to max_rules random rules
bool get_spec_matching_rule(int L_start, int N, const spec_t *spec, int max_rules, uint64_t *out_rule, bool *out_flip) {
    uint64_t total = 1ULL << (1 << N);
    uint64_t *rules = malloc(total * sizeof(uint64_t));
    for (uint64_t i = 0; i < total; ++i) rules[i] = i;
    // shuffle
    for (uint64_t i = total-1; i > 0; --i) {
        uint64_t j = rand() % (i+1);
        uint64_t tmp = rules[i]; rules[i] = rules[j]; rules[j] = tmp;
    }
    for (int i = 0; i < max_rules && i < total; ++i) {
        bool flip;
        if (spec_matches_rule(L_start,N, spec, rules[i],&flip)) {
            *out_rule = rules[i];
            *out_flip = flip;
            free(rules);
            return true;
        }
    }
    free(rules);
    return false;
}

// generate_spec_rule_pair: tries random specs until a matching rule is found
void generate_spec_rule_pair(int L_start, int N, int M, spec_t *out_spec, uint64_t *out_rule) {
    srand((unsigned)time(NULL));
    for (int attempt = 0; attempt < 1000; ++attempt) {
        spec_t spec = get_random_spec2(L_start,N,M);
        uint64_t rule;
        bool flip;
        if (!get_spec_matching_rule(L_start,N,&spec,1<<5,&rule,&flip)) continue;
        if (flip) spec = flip_spec(&spec);
        *out_spec = spec;
        *out_rule = rule;
        return;
    }
    fprintf(stderr, "generate_spec_rule_pair: no match found\n");
    exit(EXIT_FAILURE);
}

// helper to append a binary field to buf; returns number of chars written (excluding terminating '\0')
static int append_binary(char *buf, size_t bufsize, uint64_t value, int width) {
    if (width <= 0 || bufsize < (size_t)width + 1) return 0;
    // we fill from the end backwards to get leading zeros
    for (int i = 0; i < width; i++) {
        int bit = (value >> (width - 1 - i)) & 1ULL;
        buf[i] = bit ? '1' : '0';
    }
    buf[width] = '\0';
    return width;
}

// spec_string: human-readable representation in binary
void spec_string(const spec_t *spec,
                 int L_start,        // bits in mask_pre
                 int L,              // bits in mask_post
                 char *buf,          // output buffer
                 size_t bufsize)     // total size of buf
{
    uint64_t mask_pre, mask_post;
    uint16_t reps;
    bool flip;
    unpack_spec(spec, &mask_pre, &mask_post, &reps, &flip);

    // pointers into buf
    size_t pos = 0;
    int n;

    // prefix
    n = snprintf(buf + pos, bufsize - pos, "spec: ");
    pos += n;

    // mask_pre in binary
    if (pos < bufsize) {
        n = append_binary(buf + pos, bufsize - pos, mask_pre, L_start);
        pos += n;
    }

    // arrow
    if (pos < bufsize) {
        n = snprintf(buf + pos, bufsize - pos, " -> ");
        pos += n;
    }

    // mask_post in binary
    if (pos < bufsize) {
        n = append_binary(buf + pos, bufsize - pos, mask_post, L);
        pos += n;
    }

    // reps and flip
    if (pos < bufsize) {
        snprintf(buf + pos, bufsize - pos,
                 "  x %u  flip=%s",
                 reps,
                 flip ? "true" : "false");
    }
}

int main(void) {
    int N = 3;
    int L_start = 20;
    int M = 5;
    spec_t spec;
    uint64_t rule;
    generate_spec_rule_pair(L_start,N,M,&spec,&rule);
    char desc[128];
    spec_string(&spec, L_start, L_start+M, desc, sizeof(desc));
    printf("Found: %s\nRule: %llu\n", desc, (unsigned long long)rule);
    return 0;
}
