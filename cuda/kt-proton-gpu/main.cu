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

static const int LABEL = 32, VALUE = 36, ENTRY = 68, DEPTH = 256;

#define CK(x) do { cudaError_t e = (x); if (e != cudaSuccess) { \
    fprintf(stderr, "cuda: %s at %d\n", cudaGetErrorString(e), __LINE__); exit(1); } } while (0)

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
__global__ void foldLeaves(const uint8_t *__restrict__ leaves, uint64_t n,
                           uint8_t *__restrict__ out, uint16_t *__restrict__ depth) {
    uint64_t i = blockIdx.x * (uint64_t)blockDim.x + threadIdx.x;
    if (i >= n) return;
    const uint8_t *label = leaves + i*ENTRY;

    int d = 0;
    if (n > 1) {
        int l = (i > 0)     ? lcp(label - ENTRY, label) : -1;
        int r = (i + 1 < n) ? lcp(label, label + ENTRY) : -1;
        d = (l > r ? l : r) + 1;
    }

    // leafHash: SHA-256 of the 36-byte value. 36+1+8 <= 64, so one block.
    uint32_t st[8], w[16];
    init(st);
    const uint8_t *v = label + LABEL;
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

struct Node { uint8_t h[32]; uint16_t d; uint64_t rep; };

static void sha256_host(const uint8_t *in, size_t len, uint8_t *out);

static inline int hostBit(const uint8_t *label, int level) {
    return (label[(level-1) >> 3] >> (7 - ((level-1) & 7))) & 1;
}

static inline int hostLcp(const uint8_t *a, const uint8_t *b) {
    for (int i = 0; i < LABEL; i++) {
        if (a[i] != b[i]) {
            uint8_t x = a[i] ^ b[i];
            int k = 0;
            while (!(x & 0x80)) { x <<= 1; k++; }
            return i*8 + k;
        }
    }
    return DEPTH;
}

static uint64_t gJoins = 0, gLifts = 0;
static double gWalk = 0, gHash = 0, gMerge = 0;

// assemble folds the GPU's per-leaf results into the root.
//
// The first version of this swept one level at a time, visiting every live node
// at every one of the 256 levels. On the real 201M-leaf tree that is ~2 billion
// node visits and it cost 600 of the run's 658 seconds — an order of magnitude
// more than the GPU kernel it was supposed to be a footnote to.
//
// The fix comes from noticing that the rule which places a LEAF also places an
// interior node. A node acquires a sibling at depth p+1, where p is the longer
// of the common prefixes it shares with its two neighbours in label order.
// Everything between its current depth and there is a run of hashes against an
// empty sibling, and that run can be walked in one tight loop instead of one
// level per outer iteration.
//
// So each round: every node lifts straight to its pairing depth, then siblings
// join. The node count halves every round, so there are ~28 rounds rather than
// 256 sweeps, and the visits drop from ~2 billion to ~400 million. The hashes
// themselves are unchanged — this buys back the bookkeeping, not the crypto.
static void assemble(std::vector<Node> &nodes, const uint8_t *leaves, uint8_t *root) {
    while (nodes.size() > 1) {
        size_t m = nodes.size();
        double w0 = now_s();

        // Common prefix with the neighbour on each side. Parallel: it only
        // reads.
        std::vector<int32_t> pref(m);
#pragma omp parallel for schedule(static)
        for (long long i = 0; i < (long long)m - 1; i++)
            pref[i] = hostLcp(leaves + nodes[i].rep * ENTRY,
                              leaves + nodes[i+1].rep * ENTRY);
        pref[m-1] = -1;

        std::vector<uint8_t> pairs(m, 0);
        for (size_t i = 0; i + 1 < m; ) {
            int32_t l = (i > 0) ? pref[i-1] : -1;
            if (pref[i] >= l) {           // its longer prefix is to the right
                int32_t rr = (i + 2 < m) ? pref[i+1] : -1;
                if (pref[i] >= rr) { pairs[i] = 1; i += 2; continue; }
            }
            i++;
        }
        gWalk += now_s() - w0;

        double h0 = now_s();
        std::vector<uint64_t> outIdx;
        outIdx.reserve(m);
        for (size_t i = 0; i < m; ) {
            outIdx.push_back(i);
            i += pairs[i] ? 2 : 1;
        }
        std::vector<Node> up(outIdx.size());
#pragma omp parallel for schedule(dynamic, 256)
        for (long long k = 0; k < (long long)outIdx.size(); k++) {
            uint64_t i = outIdx[k];
            int32_t l = (i > 0) ? pref[i-1] : -1;
            int32_t r = pref[i];
            int32_t p = l > r ? l : r;
            int target = p + 1;            // depth at which a sibling exists

            uint8_t h[32];
            memcpy(h, nodes[i].h, 32);
            const uint8_t *la = leaves + nodes[i].rep * ENTRY;
            uint8_t buf[64];
            uint64_t lifts = 0;
            // The run against empty siblings, in one loop.
            for (int level = nodes[i].d; level > target; level--) {
                lifts++;
                memset(buf, 0, 64);
                memcpy(buf + (hostBit(la, level) ? 32 : 0), h, 32);
                sha256_host(buf, 64, h);
            }
            if (pairs[i]) {
                uint8_t h2[32];
                memcpy(h2, nodes[i+1].h, 32);
                const uint8_t *lb = leaves + nodes[i+1].rep * ENTRY;
                for (int level = nodes[i+1].d; level > target; level--) {
                    lifts++;
                    memset(buf, 0, 64);
                    memcpy(buf + (hostBit(lb, level) ? 32 : 0), h2, 32);
                    sha256_host(buf, 64, h2);
                }
                memcpy(buf, h, 32);
                memcpy(buf + 32, h2, 32);
                sha256_host(buf, 64, up[k].h);
                up[k].d = (uint16_t)p;
            } else {
                memcpy(up[k].h, h, 32);
                up[k].d = (uint16_t)target;
            }
            up[k].rep = nodes[i].rep;
#pragma omp atomic
            gLifts += lifts;
            if (pairs[i]) {
#pragma omp atomic
                gJoins++;
            }
        }
        gHash += now_s() - h0;

        if (up.size() == nodes.size() && nodes.size() > 1) {
            // No pair formed anywhere: only legitimate when one node is left.
            fprintf(stderr, "assemble: no progress with %zu nodes\n", nodes.size());
            exit(1);
        }
        nodes.swap(up);
    }
    // A lone root still sitting below depth 0 folds the rest of the way.
    uint8_t h[32];
    memcpy(h, nodes[0].h, 32);
    const uint8_t *la = leaves + nodes[0].rep * ENTRY;
    uint8_t buf[64];
    for (int level = nodes[0].d; level > 0; level--) {
        memset(buf, 0, 64);
        memcpy(buf + (hostBit(la, level) ? 32 : 0), h, 32);
        sha256_host(buf, 64, h);
    }
    memcpy(root, h, 32);
}

// A small, plain host SHA-256. Kept separate from the device code on purpose:
// the two implementations agreeing is weak evidence if they share source.
static const uint32_t HK[64] = {
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
#define HROR(x,n) ((x >> n) | (x << (32-n)))
static void sha256_host(const uint8_t *in, size_t len, uint8_t *out) {
    uint32_t st[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                      0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    uint8_t blk[128]; size_t nb;
    memcpy(blk, in, len); blk[len] = 0x80;
    size_t total = (len + 9 + 63) / 64 * 64;
    memset(blk + len + 1, 0, total - len - 1);
    uint64_t bits = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++) blk[total-1-i] = (uint8_t)(bits >> (8*i));
    nb = total / 64;
    for (size_t b = 0; b < nb; b++) {
        uint32_t w[64];
        for (int i = 0; i < 16; i++) {
            const uint8_t *p = blk + b*64 + i*4;
            w[i] = ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];
        }
        for (int i = 16; i < 64; i++) {
            uint32_t x = w[i-15], y = w[i-2];
            w[i] = w[i-16] + (HROR(x,7)^HROR(x,18)^(x>>3)) + w[i-7] + (HROR(y,17)^HROR(y,19)^(y>>10));
        }
        uint32_t a=st[0],b2=st[1],c=st[2],d=st[3],e=st[4],f=st[5],g=st[6],h=st[7];
        for (int i = 0; i < 64; i++) {
            uint32_t t1 = h + (HROR(e,6)^HROR(e,11)^HROR(e,25)) + ((e&f)^((~e)&g)) + HK[i] + w[i];
            uint32_t t2 = (HROR(a,2)^HROR(a,13)^HROR(a,22)) + ((a&b2)^(a&c)^(b2&c));
            h=g; g=f; f=e; e=d+t1; d=c; c=b2; b2=a; a=t1+t2;
        }
        st[0]+=a; st[1]+=b2; st[2]+=c; st[3]+=d; st[4]+=e; st[5]+=f; st[6]+=g; st[7]+=h;
    }
    for (int i = 0; i < 8; i++) {
        out[i*4+0]=(uint8_t)(st[i]>>24); out[i*4+1]=(uint8_t)(st[i]>>16);
        out[i*4+2]=(uint8_t)(st[i]>>8);  out[i*4+3]=(uint8_t)st[i];
    }
}

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

    // Precompute the constant padding schedule for a 64-byte message.
    uint32_t padw[64] = {0x80000000u,0,0,0,0,0,0,0,0,0,0,0,0,0,0,512};
    for (int i = 16; i < 64; i++) {
        uint32_t x = padw[i-15], y = padw[i-2];
        padw[i] = padw[i-16] + (HROR(x,7)^HROR(x,18)^(x>>3)) + padw[i-7] + (HROR(y,17)^HROR(y,19)^(y>>10));
    }
    CK(cudaMemcpyToSymbol(PADW, padw, sizeof(padw)));

    double t0 = now_s();
    uint8_t *dLeaves; uint8_t *dOut; uint16_t *dDepth;
    CK(cudaMalloc(&dLeaves, sb.st_size));
    CK(cudaMalloc(&dOut, n*32));
    CK(cudaMalloc(&dDepth, n*sizeof(uint16_t)));
    CK(cudaMemcpy(dLeaves, leaves, sb.st_size, cudaMemcpyHostToDevice));
    double tUp = now_s();

    foldLeaves<<<(n + block - 1)/block, block>>>(dLeaves, n, dOut, dDepth);
    CK(cudaGetLastError());
    CK(cudaDeviceSynchronize());
    double tK = now_s();

    std::vector<uint8_t> hOut(n*32);
    std::vector<uint16_t> hDepth(n);
    CK(cudaMemcpy(hOut.data(), dOut, n*32, cudaMemcpyDeviceToHost));
    CK(cudaMemcpy(hDepth.data(), dDepth, n*sizeof(uint16_t), cudaMemcpyDeviceToHost));
    double tDown = now_s();

    std::vector<Node> nodes(n);
    uint64_t folds = 0;
    for (uint64_t i = 0; i < n; i++) {
        memcpy(nodes[i].h, hOut.data() + i*32, 32);
        nodes[i].d = hDepth[i];
        nodes[i].rep = i;
        folds += DEPTH - hDepth[i];
    }
    uint8_t root[32];
    assemble(nodes, leaves, root);
    double tEnd = now_s();

    char hex[65];
    for (int i = 0; i < 32; i++) sprintf(hex + i*2, "%02x", root[i]);
    printf("{\"root\":\"%s\",\"leaves\":%llu,\"fold_hashes\":%llu,"
           "\"upload_s\":%.2f,\"kernel_s\":%.2f,\"download_s\":%.2f,\"assemble_s\":%.2f,\"total_s\":%.2f,\"host_joins\":%llu,\"host_lifts\":%llu,\"walk_s\":%.2f,\"hash_s\":%.2f,\"merge_s\":%.2f,"
           "\"kernel_ghs\":%.2f}\n",
           hex, (unsigned long long)n, (unsigned long long)folds,
           tUp-t0, tK-tUp, tDown-tK, tEnd-tDown, tEnd-t0,
           (unsigned long long)gJoins, (unsigned long long)gLifts, gWalk, gHash, gMerge,
           (double)folds/(tK-tUp)/1e9);
    return 0;
}
