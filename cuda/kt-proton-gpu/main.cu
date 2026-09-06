// kt-proton-gpu — rebuild Proton's sparse Merkle root on an NVIDIA GPU.
//
// # Why this exists
//
// Proton's directory is a 256-level sparse binary Merkle tree. An empty subtree
// hashes to zero at every depth, so a leaf that is alone below depth d must
// still be hashed against a zero sibling once per remaining level — 256 - d
// times. With ~183M leaves branching at depth ~28, one full rebuild costs about
// 42 billion SHA-256 invocations. On the witness box that is 14 minutes with
// six workers and, when the AKD sweep is competing for cores, several hours.
//
// Between epochs the right answer is an incremental update. But an incremental
// chain drifts: it carries forward whatever state it already had, and a bug or
// a corrupted retained tree would persist unnoticed. A periodic full rebuild
// from the published leaves is what re-anchors it, and that is the job this
// does.
//
// # Division of labour
//
// The per-leaf fold is 99.6% of the work and is perfectly parallel: 183M
// independent chains of ~228 dependent hashes, no branching, 32 bytes of state.
// That runs on the GPU.
//
// Assembling the folded nodes into a root is n-1 joins — 0.4% of the work, and
// inherently level-synchronous. That runs on the host, where it is simple and
// obviously correct, rather than as a second kernel that would have to be
// trusted on the same evidence.
//
// # The invariant that governs use of this program
//
// A wrong root here is not a wrong number. In this system a root that does not
// match the one Proton signed reads as PROTON MISBEHAVING, and that finding is
// the strongest thing the project can produce. So a mismatch reported by this
// program is never evidence: it is a signal to rebuild on the CPU and let that
// decide. The asymmetry is what makes GPU acceleration safe here — a false
// mismatch costs one CPU rebuild, while a false *match* would require colliding
// with Proton's signed hash, which is not a thing a GPU bug does.

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <ctime>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <cuda_runtime.h>
#include <thrust/scan.h>
#include <thrust/execution_policy.h>
#include <algorithm>

static const int LABEL = 32, VALUE = 36, ENTRY = 68, DEPTH = 256;

#define CK(x) do { cudaError_t e = (x); if (e != cudaSuccess) { \
    fprintf(stderr, "cuda: %s at %d\n", cudaGetErrorString(e), __LINE__); exit(1); } } while (0)

// Host-side rotate, used only to precompute the constant padding schedule.
#define HROR(x,n) ((x >> n) | (x << (32-n)))

static double now_s();

__constant__ uint32_t K[64] = {
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};

// The second block of every 64-byte hash is pure padding — 0x80 then zeros then
// the bit length — so its 64-word message schedule is the same for every one of
// the 42 billion hashes. Precomputing it on the host removes 48 schedule
// expansions from half of all compressions, which is the single largest win
// available without changing the algorithm.
__constant__ uint32_t PADW[64];

#define ROR(x,n) ((x >> n) | (x << (32-n)))
#define S0(x) (ROR(x,2)^ROR(x,13)^ROR(x,22))
#define S1(x) (ROR(x,6)^ROR(x,11)^ROR(x,25))
#define s0(x) (ROR(x,7)^ROR(x,18)^(x>>3))
#define s1(x) (ROR(x,17)^ROR(x,19)^(x>>10))

#define RND(a,b,c,d,e,f,g,h,kw) { \
    uint32_t t1 = h + S1(e) + ((e&f)^((~e)&g)) + (kw); \
    uint32_t t2 = S0(a) + ((a&b)^(a&c)^(b&c)); \
    d += t1; h = t1 + t2; }

// compress_sched: one compression with a message schedule already in registers.
__device__ __forceinline__ void compress_pad(uint32_t st[8]) {
    uint32_t a=st[0],b=st[1],c=st[2],d=st[3],e=st[4],f=st[5],g=st[6],h=st[7];
#pragma unroll
    for (int i = 0; i < 64; i += 8) {
        RND(a,b,c,d,e,f,g,h, K[i+0]+PADW[i+0]); RND(h,a,b,c,d,e,f,g, K[i+1]+PADW[i+1]);
        RND(g,h,a,b,c,d,e,f, K[i+2]+PADW[i+2]); RND(f,g,h,a,b,c,d,e, K[i+3]+PADW[i+3]);
        RND(e,f,g,h,a,b,c,d, K[i+4]+PADW[i+4]); RND(d,e,f,g,h,a,b,c, K[i+5]+PADW[i+5]);
        RND(c,d,e,f,g,h,a,b, K[i+6]+PADW[i+6]); RND(b,c,d,e,f,g,h,a, K[i+7]+PADW[i+7]);
    }
    st[0]+=a; st[1]+=b; st[2]+=c; st[3]+=d; st[4]+=e; st[5]+=f; st[6]+=g; st[7]+=h;
}

__device__ __forceinline__ void compress(uint32_t st[8], uint32_t w[16]) {
    uint32_t a=st[0],b=st[1],c=st[2],d=st[3],e=st[4],f=st[5],g=st[6],h=st[7];
#pragma unroll
    for (int i = 0; i < 64; i++) {
        if (i >= 16) w[i&15] += s1(w[(i-2)&15]) + w[(i-7)&15] + s0(w[(i-15)&15]);
        uint32_t t1 = h + S1(e) + ((e&f)^((~e)&g)) + K[i] + w[i&15];
        uint32_t t2 = S0(a) + ((a&b)^(a&c)^(b&c));
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    st[0]+=a; st[1]+=b; st[2]+=c; st[3]+=d; st[4]+=e; st[5]+=f; st[6]+=g; st[7]+=h;
}

__device__ __forceinline__ void init(uint32_t st[8]) {
    st[0]=0x6a09e667; st[1]=0xbb67ae85; st[2]=0x3c6ef372; st[3]=0xa54ff53a;
    st[4]=0x510e527f; st[5]=0x9b05688c; st[6]=0x1f83d9ab; st[7]=0x5be0cd19;
}

// bits common to two 32-byte labels, MSB-first, capped at 256.
__device__ __forceinline__ int lcp(const uint8_t *a, const uint8_t *b) {
    for (int i = 0; i < LABEL; i += 4) {
        uint32_t x = (*(const uint32_t *)(a+i)) ^ (*(const uint32_t *)(b+i));
        if (x) return i*8 + __clz(__byte_perm(x, 0, 0x0123)); // to big-endian, then leading zeros
    }
    return DEPTH;
}

// Two optimisations were tried against this and measured no better, recorded
// so nobody pays for them twice:
//
//   - Two leaves per thread, interleaving two independent hash chains to hide
//     the dependency between rounds. 1.05 -> 1.06 GH/s. The kernel is bound by
//     integer throughput, not by latency, so there was no gap to fill.
//   - A rolling 16-word message schedule instead of the full 64-word one, on
//     the theory that w[64] was spilling. Identical. nvcc had already made that
//     choice.
//
// Block size makes no difference either, between 128 and 512. What did help was
// precomputing the padding block's schedule, which is shared by all 42 billion
// hashes; see PADW.
//
// foldLeaves mirrors proton.subtree's single-leaf case exactly: hash the
// 36-byte value, then fold from level 256 down to the level below the depth at
// which this leaf is alone, placing the running hash left or right by the
// label's bit for that level and leaving the sibling zero.
__global__ void foldLeaves(const uint8_t *__restrict__ labels,
                           const uint8_t *__restrict__ values,
                           uint64_t lo, uint64_t hi, uint64_t n,
                           uint8_t *__restrict__ out, uint16_t *__restrict__ depth) {
    uint64_t i = lo + blockIdx.x * (uint64_t)blockDim.x + threadIdx.x;
    if (i >= hi) return;
    const uint8_t *label = labels + i*LABEL;

    int d = 0;
    if (n > 1) {
        int l = (i > 0)     ? lcp(label - LABEL, label) : -1;
        int r = (i + 1 < n) ? lcp(label, label + LABEL) : -1;
        d = (l > r ? l : r) + 1;
    }

    // leafHash: SHA-256 of the 36-byte value. 36+1+8 <= 64, so one block.
    uint32_t st[8], w[16];
    init(st);
    const uint8_t *v = values + (i - lo)*VALUE;
#pragma unroll
    for (int j = 0; j < 9; j++)
        w[j] = ((uint32_t)v[j*4]<<24)|((uint32_t)v[j*4+1]<<16)|((uint32_t)v[j*4+2]<<8)|v[j*4+3];
    w[9] = 0x80000000u;
#pragma unroll
    for (int j = 10; j < 15; j++) w[j] = 0;
    w[15] = VALUE * 8;
    compress(st, w);

    // The fold. Levels are 1-based; level L reads bit L-1 of the label.
    for (int level = DEPTH; level > d; level--) {
        int bit = (label[(level-1) >> 3] >> (7 - ((level-1) & 7))) & 1;
        uint32_t blk[16];
        if (bit == 0) {
#pragma unroll
            for (int j = 0; j < 8; j++) { blk[j] = st[j]; blk[j+8] = 0; }
        } else {
#pragma unroll
            for (int j = 0; j < 8; j++) { blk[j] = 0; blk[j+8] = st[j]; }
        }
        init(st);
        compress(st, blk);
        compress_pad(st);          // constant padding block
    }

#pragma unroll
    for (int j = 0; j < 8; j++) {
        out[i*32 + j*4 + 0] = (uint8_t)(st[j] >> 24);
        out[i*32 + j*4 + 1] = (uint8_t)(st[j] >> 16);
        out[i*32 + j*4 + 2] = (uint8_t)(st[j] >> 8);
        out[i*32 + j*4 + 3] = (uint8_t)(st[j]);
    }
    depth[i] = (uint16_t)d;
}


// ---- GPU assembly ------------------------------------------------------
//
// The lifts are the same operation as the leaf fold — a chain of hashes against
// a zero sibling — and on the real tree there are 1.8 billion of them against
// 201 million joins. Doing them on the host cost more than the fold kernel they
// were feeding. So the node state stays in VRAM and the rounds run here.
//
// Pairing is decided without a sequential scan. For node i let pL be its common
// prefix with the node on its left and pR with the node on its right; its
// sibling lies on whichever side is longer. So i and i+1 are siblings exactly
// when pref[i] is strictly greater than both of its neighbours in the pref
// array. Ties cannot occur: an equal maximum on both sides would mean three
// nodes sharing one parent, which a binary trie does not have.

__device__ __forceinline__ void hashPair(const uint8_t *l, const uint8_t *r, uint8_t *out) {
    uint32_t st[8], w[16];
    init(st);
#pragma unroll
    for (int j = 0; j < 8; j++)
        w[j] = ((uint32_t)l[j*4]<<24)|((uint32_t)l[j*4+1]<<16)|((uint32_t)l[j*4+2]<<8)|l[j*4+3];
#pragma unroll
    for (int j = 0; j < 8; j++)
        w[8+j] = ((uint32_t)r[j*4]<<24)|((uint32_t)r[j*4+1]<<16)|((uint32_t)r[j*4+2]<<8)|r[j*4+3];
    compress(st, w);
    compress_pad(st);
#pragma unroll
    for (int j = 0; j < 8; j++) {
        out[j*4+0]=(uint8_t)(st[j]>>24); out[j*4+1]=(uint8_t)(st[j]>>16);
        out[j*4+2]=(uint8_t)(st[j]>>8);  out[j*4+3]=(uint8_t)st[j];
    }
}

// liftTo folds h upward against zero siblings, from depth `from` down to
// `target`, choosing the side by the label's bit at each level. This is
// proton.join(x, emptyNode) repeated, which is proton.combine.
__device__ __forceinline__ void liftTo(uint8_t *h, const uint8_t *label, int from, int target) {
    for (int level = from; level > target; level--) {
        int bit = (label[(level-1) >> 3] >> (7 - ((level-1) & 7))) & 1;
        uint32_t st[8], w[16];
        init(st);
#pragma unroll
        for (int j = 0; j < 16; j++) w[j] = 0;
        int off = bit ? 8 : 0;
#pragma unroll
        for (int j = 0; j < 8; j++)
            w[off+j] = ((uint32_t)h[j*4]<<24)|((uint32_t)h[j*4+1]<<16)|((uint32_t)h[j*4+2]<<8)|h[j*4+3];
        compress(st, w);
        compress_pad(st);
#pragma unroll
        for (int j = 0; j < 8; j++) {
            h[j*4+0]=(uint8_t)(st[j]>>24); h[j*4+1]=(uint8_t)(st[j]>>16);
            h[j*4+2]=(uint8_t)(st[j]>>8);  h[j*4+3]=(uint8_t)st[j];
        }
    }
}

__global__ void computePref(const uint8_t *__restrict__ labels,
                            const uint32_t *__restrict__ rep, uint64_t m,
                            int32_t *__restrict__ pref) {
    uint64_t i = blockIdx.x * (uint64_t)blockDim.x + threadIdx.x;
    if (i >= m) return;
    pref[i] = (i + 1 < m) ? lcp(labels + (uint64_t)rep[i]*LABEL,
                                labels + (uint64_t)rep[i+1]*LABEL)
                          : -1;
}

// A node starts an output group unless the node to its left claimed it.
__global__ void markStarts(const int32_t *__restrict__ pref, uint64_t m,
                           uint8_t *__restrict__ isPair, uint32_t *__restrict__ starts) {
    uint64_t i = blockIdx.x * (uint64_t)blockDim.x + threadIdx.x;
    if (i >= m) return;
    int32_t p  = pref[i];
    int32_t pl = (i > 0)     ? pref[i-1] : -1;
    int32_t pr = (i + 1 < m) ? pref[i+1] : -1;
    bool pair = (i + 1 < m) && p > pl && p > pr;
    isPair[i] = pair ? 1 : 0;
    bool claimed = false;
    if (i > 0) {
        int32_t q  = pref[i-1];
        int32_t ql = (i > 1) ? pref[i-2] : -1;
        int32_t qr = pref[i];
        claimed = q > ql && q > qr;
    }
    starts[i] = claimed ? 0u : 1u;
}

__global__ void roundKernel(const uint8_t *__restrict__ labels,
                            const uint8_t *__restrict__ hIn, const uint16_t *__restrict__ dIn,
                            const uint32_t *__restrict__ repIn, const int32_t *__restrict__ pref,
                            const uint8_t *__restrict__ isPair, const uint32_t *__restrict__ scan,
                            uint64_t m,
                            uint8_t *__restrict__ hOut, uint16_t *__restrict__ dOut,
                            uint32_t *__restrict__ repOut) {
    uint64_t i = blockIdx.x * (uint64_t)blockDim.x + threadIdx.x;
    if (i >= m) return;
    // Only group leaders do work; the second element of a pair is consumed.
    bool claimed = false;
    if (i > 0) {
        int32_t q  = pref[i-1];
        int32_t ql = (i > 1) ? pref[i-2] : -1;
        int32_t qr = pref[i];
        claimed = q > ql && q > qr;
    }
    if (claimed) return;

    uint32_t k = scan[i];
    int32_t pl = (i > 0) ? pref[i-1] : -1;
    int32_t pr = pref[i];
    int32_t p  = pl > pr ? pl : pr;
    int target = p + 1;

    uint8_t h[32];
#pragma unroll
    for (int j = 0; j < 32; j++) h[j] = hIn[i*32 + j];
    const uint8_t *la = labels + (uint64_t)repIn[i]*LABEL;
    liftTo(h, la, dIn[i], target);

    if (isPair[i]) {
        uint8_t h2[32];
#pragma unroll
        for (int j = 0; j < 32; j++) h2[j] = hIn[(i+1)*32 + j];
        const uint8_t *lb = labels + (uint64_t)repIn[i+1]*LABEL;
        liftTo(h2, lb, dIn[i+1], target);
        hashPair(h, h2, hOut + (uint64_t)k*32);
        dOut[k] = (uint16_t)p;
    } else {
#pragma unroll
        for (int j = 0; j < 32; j++) hOut[(uint64_t)k*32 + j] = h[j];
        dOut[k] = (uint16_t)target;
    }
    repOut[k] = repIn[i];
}

// The last node standing may still sit below the root; fold it the rest of the
// way. One thread: there is exactly one node.
__global__ void finishRoot(const uint8_t *__restrict__ labels, uint8_t *__restrict__ h,
                           const uint16_t *__restrict__ d, const uint32_t *__restrict__ rep) {
    if (threadIdx.x || blockIdx.x) return;
    uint8_t v[32];
#pragma unroll
    for (int j = 0; j < 32; j++) v[j] = h[j];
    liftTo(v, labels + (uint64_t)rep[0]*LABEL, d[0], 0);
#pragma unroll
    for (int j = 0; j < 32; j++) h[j] = v[j];
}

// ---- host-side assembly -------------------------------------------------
//
// The folded leaves are the leaves of a compressed binary trie: leaf i sits at
// depth d_i, the shallowest depth at which no other leaf shares its prefix.
// Assembling them is a level-synchronous sweep from the deepest level upwards.
//
// Two adjacent nodes at depth L are siblings exactly when their labels agree on
// L-1 bits, and then the parent is SHA-256(left || right). A node at depth L
// with no such neighbour has an EMPTY sibling — the case a first version of
// this got wrong — and its parent is the same hash taken against 32 zero
// bytes, on the side the label's bit for level L selects. That is precisely
// proton.join(x, emptyNode), and it is why a node carries a representative
// leaf: the bit has to come from a real label.
//
// Nodes are bucketed by depth so each level touches only its own nodes, and
// each level's output is merged into the next bucket rather than re-sorted:
// both sequences are already in label order, so the whole assembly is linear
// in the number of nodes.

static double now_s_impl() { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec + t.tv_nsec/1e9; }
static double now_s() { return now_s_impl(); }

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: kt-proton-gpu <tree.bin> [block]\n"); return 2; }
    int block = (argc > 2) ? atoi(argv[2]) : 256;

    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) { perror("open"); return 1; }
    struct stat sb; fstat(fd, &sb);
    if (sb.st_size % ENTRY) { fprintf(stderr, "not a whole number of %d-byte leaves\n", ENTRY); return 1; }
    uint64_t n = sb.st_size / ENTRY;
    const uint8_t *leaves = (const uint8_t *)mmap(nullptr, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (leaves == MAP_FAILED) { perror("mmap"); return 1; }

    uint32_t padw[64] = {0x80000000u,0,0,0,0,0,0,0,0,0,0,0,0,0,0,512};
    for (int i = 16; i < 64; i++) {
        uint32_t x = padw[i-15], y = padw[i-2];
        padw[i] = padw[i-16] + (HROR(x,7)^HROR(x,18)^(x>>3)) + padw[i-7] + (HROR(y,17)^HROR(y,19)^(y>>10));
    }
    CK(cudaMemcpyToSymbol(PADW, padw, sizeof(padw)));

    double t0 = now_s();

    // Labels and values are uploaded as separate arrays rather than as the
    // interleaved dump. The values are dead the moment the leaf hashes exist,
    // and freeing 7.2 GB of them is what leaves room for the node state to stay
    // resident on the card for the whole assembly.
    std::vector<uint8_t> hLabels((size_t)n * LABEL);
#pragma omp parallel for schedule(static)
    for (long long i = 0; i < (long long)n; i++)
        memcpy(hLabels.data() + (size_t)i*LABEL, leaves + (size_t)i*ENTRY, LABEL);

    uint8_t *dLabels, *dValues, *dHash, *dHash2;
    uint16_t *dDepth, *dDepth2;
    uint32_t *dRep, *dRep2, *dScan;
    int32_t *dPref;
    uint8_t *dIsPair;
    CK(cudaMalloc(&dLabels, (size_t)n*LABEL));
    CK(cudaMemcpy(dLabels, hLabels.data(), (size_t)n*LABEL, cudaMemcpyHostToDevice));
    CK(cudaMalloc(&dHash, (size_t)n*32));
    CK(cudaMalloc(&dDepth, (size_t)n*sizeof(uint16_t)));
    double tUp = now_s();

    // Values are streamed rather than held. All 7.2 GB of them are dead the
    // moment each leaf hash exists, and holding them alongside the node state
    // is the difference between fitting on a 24 GB card and not: the first
    // attempt at this ran out of memory by about a gigabyte.
    const uint64_t CHUNK = 8u << 20;      // 8M leaves ~ 288 MB of values
    CK(cudaMalloc(&dValues, (size_t)CHUNK*VALUE));
    std::vector<uint8_t> stage((size_t)CHUNK*VALUE);
    for (uint64_t lo = 0; lo < n; lo += CHUNK) {
        uint64_t hi = lo + CHUNK < n ? lo + CHUNK : n;
        uint64_t cnt = hi - lo;
#pragma omp parallel for schedule(static)
        for (long long j = 0; j < (long long)cnt; j++)
            memcpy(stage.data() + (size_t)j*VALUE,
                   leaves + (size_t)(lo + j)*ENTRY + LABEL, VALUE);
        CK(cudaMemcpy(dValues, stage.data(), (size_t)cnt*VALUE, cudaMemcpyHostToDevice));
        foldLeaves<<<(cnt + block - 1)/block, block>>>(dLabels, dValues, lo, hi, n, dHash, dDepth);
        CK(cudaGetLastError());
    }
    CK(cudaDeviceSynchronize());
    double tK = now_s();
    CK(cudaFree(dValues));
    stage.clear(); stage.shrink_to_fit();

    // Node state for the rounds. rep is the index of a leaf inside the node's
    // subtree, which is all that is needed to read a path bit.
    CK(cudaMalloc(&dRep, (size_t)n*sizeof(uint32_t)));
    {
        std::vector<uint32_t> ids(n);
#pragma omp parallel for schedule(static)
        for (long long i = 0; i < (long long)n; i++) ids[i] = (uint32_t)i;
        CK(cudaMemcpy(dRep, ids.data(), (size_t)n*sizeof(uint32_t), cudaMemcpyHostToDevice));
    }
    // Scratch that every round reuses. Sized once for the whole leaf set.
    CK(cudaMalloc(&dPref,   (size_t)n*sizeof(int32_t)));
    CK(cudaMalloc(&dIsPair, (size_t)n));
    CK(cudaMalloc(&dScan,   (size_t)n*sizeof(uint32_t)));

    uint64_t m = n;
    int rounds = 0;
    while (m > 1) {
        int g = (int)((m + block - 1)/block);
        computePref<<<g, block>>>(dLabels, dRep, m, dPref);
        markStarts<<<g, block>>>(dPref, m, dIsPair, dScan);
        CK(cudaGetLastError());
        thrust::exclusive_scan(thrust::device, dScan, dScan + m, dScan);

        // The output size is known before the round runs, so the destination
        // buffers are allocated at exactly that size rather than at worst case.
        // On a 24 GB card holding a 201M-leaf tree this is not a nicety: two
        // full-width node arrays plus the labels do not fit, and sizing the
        // destination to the ~55% of nodes that actually survive a round is
        // what makes the whole assembly resident.
        uint32_t lastStart = 0;
        CK(cudaMemcpy(&lastStart, dScan + (m-1), sizeof(uint32_t), cudaMemcpyDeviceToHost));
        uint8_t lastPairPrev = 0;
        if (m >= 2) CK(cudaMemcpy(&lastPairPrev, dIsPair + (m-2), 1, cudaMemcpyDeviceToHost));
        uint64_t outCount = lastStart + (lastPairPrev ? 0u : 1u);
        if (outCount == 0 || outCount >= m) {
            fprintf(stderr, "assemble: no progress at %llu nodes\n", (unsigned long long)m);
            return 1;
        }

        CK(cudaMalloc(&dHash2,  (size_t)outCount*32));
        CK(cudaMalloc(&dDepth2, (size_t)outCount*sizeof(uint16_t)));
        CK(cudaMalloc(&dRep2,   (size_t)outCount*sizeof(uint32_t)));

        roundKernel<<<g, block>>>(dLabels, dHash, dDepth, dRep, dPref, dIsPair, dScan, m,
                                  dHash2, dDepth2, dRep2);
        CK(cudaGetLastError());
        CK(cudaDeviceSynchronize());

        CK(cudaFree(dHash)); CK(cudaFree(dDepth)); CK(cudaFree(dRep));
        dHash = dHash2; dDepth = dDepth2; dRep = dRep2;
        m = outCount;
        rounds++;
        if (rounds > 512) { fprintf(stderr, "assemble: too many rounds\n"); return 1; }
    }
    finishRoot<<<1, 32>>>(dLabels, dHash, dDepth, dRep);
    CK(cudaDeviceSynchronize());
    double tEnd = now_s();

    uint8_t root[32];
    CK(cudaMemcpy(root, dHash, 32, cudaMemcpyDeviceToHost));

    char hex[65];
    for (int i = 0; i < 32; i++) sprintf(hex + i*2, "%02x", root[i]);
    printf("{\"root\":\"%s\",\"leaves\":%llu,\"rounds\":%d,"
           "\"upload_s\":%.2f,\"kernel_s\":%.2f,\"assemble_s\":%.2f,\"total_s\":%.2f}\n",
           hex, (unsigned long long)n, rounds,
           tUp-t0, tK-tUp, tEnd-tK, tEnd-t0);
    return 0;
}
