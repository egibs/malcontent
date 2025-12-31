// Package apkdiff provides O(n+m) file reconciliation with sharded parallelism.
//
// This package is designed for comparing file lists from APK archives or container
// images where the number of files can exceed 10 million. It identifies files that
// are unchanged, updated (same identity but different version), removed, or added.
//
// # Identity Matching
//
// The package uses "identity hashing" to match files that represent the same logical
// entity but have different versions. For example:
//
//   - libfoo.so.1.0.0 and libfoo.so.2.0.0 have the same identity (libfoo.so)
//   - app-1.0.0-r0 and app-2.0.0-r5 have the same identity (app)
//   - foo.1.2.3.so and foo.4.5.6.so have the same identity (foo...so)
//
// This enables detecting version updates rather than treating them as unrelated
// file additions and removals.
//
// # Algorithm Overview
//
// The algorithm proceeds in five parallel phases:
//
//  1. Hash Computation: Compute identity and exact hashes for all files in parallel
//  2. Index Building: Build a sharded hash table of new files for O(1) lookups
//  3. Reconciliation: Match old files against new files, marking matches atomically
//  4. Addition Collection: Identify unmatched new files as additions
//  5. Result Merging: Combine per-worker results into final output
//
// # Complexity
//
//   - Time: O(n+m) where n=len(old), m=len(new)
//   - Space: O(n+m) for hash arrays and result entries
//   - Parallelism: Near-linear scaling up to available cores
//
// # Thread Safety
//
// The Diff and DiffP functions are safe to call concurrently from multiple
// goroutines. Each call creates its own internal state.
package diff

import (
	"bytes"
	"hash/maphash"
	"iter"
	"runtime"
	"sync"
	"sync/atomic"
	"unsafe"
)

// Status represents the reconciliation status of a file entry.
type Status uint8

const (
	// Unchanged indicates the file exists in both old and new with identical content.
	Unchanged Status = iota

	// Updated indicates the file exists in both old and new with the same identity
	// but different content (e.g., version update).
	Updated

	// Removed indicates the file exists only in old (was deleted).
	Removed

	// Added indicates the file exists only in new (was created).
	Added
)

// Entry represents a single file reconciliation result.
// For Unchanged/Updated entries, both Old and New are valid indices.
// For Removed entries, New is null (0xFFFFFFFF).
// For Added entries, Old is null (0xFFFFFFFF).
type Entry struct {
	Old    uint32 // Index into old slice, or null for Added entries
	New    uint32 // Index into new slice, or null for Removed entries
	Status uint32 // Status cast to uint32 for memory alignment
}

// Result contains the complete reconciliation output.
type Result struct {
	E []Entry          // All entries (Unchanged, Updated, Removed, Added)
	C [4]atomic.Uint32 // Counts per status, indexed by Status value
}

// Count returns the number of entries with the given status.
// This is an O(1) operation using pre-computed counts.
func (r *Result) Count(s Status) uint32 { return r.C[s].Load() }

// All returns an iterator over all entries with their status.
// Usage: for status, entry := range result.All() { ... }.
func (r *Result) All() iter.Seq2[Status, Entry] {
	return func(yield func(Status, Entry) bool) {
		for _, e := range r.E {
			if !yield(Status(e.Status&0xFF), e) { //nolint:gosec // masked to uint8 range
				return
			}
		}
	}
}

// Filter returns an iterator over entries with a specific status.
// Usage: for entry := range result.Filter(Updated) { ... }.
func (r *Result) Filter(s Status) iter.Seq[Entry] {
	return func(yield func(Entry) bool) {
		for _, e := range r.E {
			if Status(e.Status&0xFF) == s { //nolint:gosec // masked to uint8 range
				if !yield(e) {
					return
				}
			}
		}
	}
}

const (
	null      uint32 = 0xFFFFFFFF     // Sentinel value for missing index
	shardBits        = 8              // log2(numShards) - 256 shards balances parallelism vs overhead
	numShards        = 1 << shardBits // Number of independent shards (256)
	shardMask uint64 = numShards - 1  // Mask for extracting shard index from hash
	exFlag    uint64 = 1 << 63        // High bit flag to distinguish exact vs identity entries
)

// hashSeed is initialized once at package load time for consistent hashing.
// Using a fixed seed ensures deterministic results across calls.
var hashSeed = maphash.MakeSeed()

// shard represents one partition of the hash table.
// Using multiple shards reduces lock contention during parallel index building.
// After indexing completes, the map becomes read-only and locks are not needed.
type shard struct {
	sync.Mutex                   // Protects writes during index building only
	m          map[uint64]uint32 // Combined map: identity keys use hash, exact keys use hash|exFlag
}

// Diff compares two file lists using all available CPU cores.
// It returns a Result containing all reconciliation entries.
//
// The old and cur slices should contain file paths or identifiers.
// The algorithm matches files by identity (ignoring version numbers)
// and by exact string equality.
func Diff(old, cur []string) *Result {
	return diffP(old, cur, max(1, runtime.GOMAXPROCS(0)))
}

// diffP compares two file lists with an explicit worker count.
func diffP(old, cur []string, workers int) *Result {
	no, nn := len(old), len(cur)
	if no|nn == 0 {
		return &Result{}
	}

	// =========================================================================
	// Phase 1: Parallel Hash Computation
	// =========================================================================
	// Compute two hashes for each file:
	//   - Identity hash: Based on the "identity" portion (name without version)
	//   - Exact hash: Based on the complete string
	//
	// The identity hash enables matching files like "lib.so.1" with "lib.so.2".
	// The exact hash enables fast equality checks without string comparison.
	oldH, oldE := hashAll(old, workers)
	curH, curE := hashAll(cur, workers)

	// =========================================================================
	// Phase 2: Build Sharded Index
	// =========================================================================
	// Create a hash table of all new files for O(1) lookups during reconciliation.
	// The table is partitioned into shards to reduce lock contention.
	//
	// Each shard contains a single map with two types of entries:
	//   - Identity entries: key = identityHash, value = file index
	//   - Exact entries: key = exactHash | exFlag, value = file index
	//
	// Using a high bit flag allows storing both in one map, reducing overhead.
	shards := make([]shard, numShards)
	expectedPerShard := max(16, nn/numShards*2) // Estimate: id + ex entries per shard
	for i := range shards {
		shards[i].m = make(map[uint64]uint32, expectedPerShard)
	}

	chunk := max(1, (nn+workers-1)/workers)
	var wg sync.WaitGroup

	for w := range workers {
		lo := w * chunk
		if lo >= nn {
			break
		}
		hi := min(lo+chunk, nn)

		wg.Go(func() {
			for i := lo; i < hi; i++ {
				s := &shards[curH[i]&shardMask]
				idx := uint32(i) //nolint:gosec // index bounded by slice length
				idKey := curH[i]
				exKey := curE[i] | exFlag

				s.Lock()
				// Only store first occurrence for identity (handles duplicates)
				if _, ok := s.m[idKey]; !ok {
					s.m[idKey] = idx
				}
				// Always store exact (last occurrence wins for duplicates)
				s.m[exKey] = idx
				s.Unlock()
			}
		})
	}
	wg.Wait()

	// =========================================================================
	// Phase 3: Parallel Reconciliation
	// =========================================================================
	// For each old file, find the best match in the new file set:
	//   1. Try exact match first (same string = Unchanged)
	//   2. Try identity match (same identity, different version = Updated)
	//   3. No match found = Removed
	//
	// Uses atomic bitset to track which new files have been matched,
	// preventing the same new file from matching multiple old files.
	//
	// IMPORTANT: Maps are now immutable, so we read without locks.
	// This is safe because Go maps support concurrent reads.
	matched := make([]atomic.Uint64, (nn+63)>>6) // Bitset: 1 bit per new file
	results := make([][]Entry, workers)          // Per-worker result slices
	counts := make([][4]uint32, workers)         // Per-worker status counts

	chunk = max(1, (no+workers-1)/workers)

	for w := range workers {
		lo := w * chunk
		if lo >= no {
			break
		}
		hi := min(lo+chunk, no)
		wIdx := w

		wg.Go(func() {
			local := make([]Entry, 0, hi-lo)
			var c [4]uint32

			for i := lo; i < hi; i++ {
				oi := uint32(i) //nolint:gosec // index bounded by slice length
				sh := &shards[oldH[i]&shardMask]
				m := sh.m // Lock-free read: map is immutable after Phase 2

				// Try exact match first (Unchanged)
				exj, exok := m[oldE[i]|exFlag]
				if exok && old[i] == cur[exj] {
					if tryMark(matched, exj) {
						local = append(local, Entry{oi, exj, uint32(Unchanged)})
						c[Unchanged]++
						continue
					}
				}

				// Try identity match (Updated)
				idj, idok := m[oldH[i]]
				if idok && !isMarked(matched, idj) && idEq(old[i], cur[idj]) {
					if tryMark(matched, idj) {
						local = append(local, Entry{oi, idj, uint32(Updated)})
						c[Updated]++
						continue
					}
				}

				// No match found (Removed)
				local = append(local, Entry{oi, null, uint32(Removed)})
				c[Removed]++
			}

			results[wIdx] = local
			counts[wIdx] = c
		})
	}
	wg.Wait()

	// =========================================================================
	// Phase 4: Parallel Addition Collection
	// =========================================================================
	// Scan the matched bitset to find new files that weren't matched.
	// These are additions (files that exist only in new).
	addResults := make([][]Entry, workers)
	chunk = max(1, (nn+workers-1)/workers)

	for w := range workers {
		lo := w * chunk
		if lo >= nn {
			break
		}
		hi := min(lo+chunk, nn)
		wIdx := w

		wg.Go(func() {
			local := make([]Entry, 0, (hi-lo)/4) // Estimate ~25% additions
			for i := lo; i < hi; i++ {
				ui := uint32(i) //nolint:gosec // index bounded by slice length
				if !isMarked(matched, ui) {
					local = append(local, Entry{null, ui, uint32(Added)})
				}
			}
			addResults[wIdx] = local
		})
	}
	wg.Wait()

	// =========================================================================
	// Phase 5: Merge Results
	// =========================================================================
	// Combine per-worker results into a single Result struct.
	// Order is deterministic: reconciliation entries first (by worker order),
	// then addition entries (by worker order).
	total := 0
	for _, r := range results {
		total += len(r)
	}
	for _, a := range addResults {
		total += len(a)
	}

	r := &Result{E: make([]Entry, 0, total)}

	for w, entries := range results {
		r.E = append(r.E, entries...)
		for s := range 4 {
			r.C[s].Add(counts[w][s])
		}
	}

	for _, additions := range addResults {
		r.E = append(r.E, additions...)
		r.C[Added].Add(uint32(len(additions))) //nolint:gosec // len bounded by input size
	}

	return r
}

// tryMark attempts to atomically set bit j in the bitset.
// Returns true if we set the bit (first to mark), false if already set.
// Uses compare-and-swap for lock-free atomic updates.
func tryMark(v []atomic.Uint64, j uint32) bool {
	idx, bit := j>>6, uint64(1)<<(j&63)
	for {
		old := v[idx].Load()
		if old&bit != 0 {
			return false // Already marked by another goroutine
		}
		if v[idx].CompareAndSwap(old, old|bit) {
			return true // Successfully marked
		}
		// CAS failed, retry with new value
	}
}

// isMarked checks if bit j is set in the bitset.
func isMarked(v []atomic.Uint64, j uint32) bool {
	return v[j>>6].Load()&(1<<(j&63)) != 0
}

// hashAll computes identity and exact hashes for all strings in parallel.
// Returns two slices of equal length: identity hashes and exact hashes.
func hashAll(ss []string, workers int) (id, ex []uint64) {
	n := len(ss)
	id, ex = make([]uint64, n), make([]uint64, n)
	if n == 0 {
		return
	}

	chunk := max(1, (n+workers-1)/workers)
	var wg sync.WaitGroup

	for w := range workers {
		lo := w * chunk
		if lo >= n {
			break
		}
		hi := min(lo+chunk, n)

		wg.Go(func() {
			for i := lo; i < hi; i++ {
				id[i], ex[i] = hash(ss[i], hashSeed)
			}
		})
	}
	wg.Wait()
	return
}

// hash computes the identity hash and exact hash for a file path.
//
// The exact hash is simply the hash of the complete string.
//
// The identity hash strips version information based on common patterns:
//   - Shared libraries: "libfoo.so.1.2.3" -> hash("libfoo.so")
//   - APK packages: "app-1.0.0-r5" -> hash("app")
//   - Embedded versions: "foo.1.2.3.so" -> hash("foo") ^ hash(".so")
//
// Both hashes have the high bit cleared to leave room for the exFlag.
func hash(s string, seed maphash.Seed) (uint64, uint64) {
	b := unsafe.Slice(unsafe.StringData(s), len(s))
	n := len(b)

	// Compute exact hash using maphash (AES-NI accelerated on amd64)
	// Mask off high bit to leave room for exFlag
	ex := maphash.Bytes(seed, b) &^ exFlag

	if n == 0 {
		return ex, ex
	}

	// Try each pattern to extract identity portion
	// Pattern 1: Shared object with .so.N suffix (e.g., "libfoo.so.1.2.3")
	if i := soname(b); i > 0 {
		return maphash.Bytes(seed, b[:i]) &^ exFlag, ex
	}
	// Pattern 2: APK script with checksum (e.g., "alpine-baselayout-3.6.8-r1.Q1xxx.post-install")
	if i, j := apkscript(b); i > 0 {
		return (maphash.Bytes(seed, b[:i]) ^ maphash.Bytes(seed, b[j:])) &^ exFlag, ex
	}
	// Pattern 3: Embedded version before extension (e.g., "foo.1.2.3.so")
	if i, j := embedded(b); i > 0 {
		return (maphash.Bytes(seed, b[:i]) ^ maphash.Bytes(seed, b[j:])) &^ exFlag, ex
	}
	// Pattern 4: Version suffix (e.g., "app-1.0.0-r5")
	if i := suffix(b); i > 0 {
		return maphash.Bytes(seed, b[:i]) &^ exFlag, ex
	}

	// No version pattern found, use exact hash as identity
	return ex, ex
}

// idEq checks if two strings have the same identity.
// This is used to verify identity matches after hash lookup (handles collisions).
//
// Two strings have the same identity if their "identity spans" are equal.
// The identity span is the portion of the filename excluding version numbers.
func idEq(a, b string) bool {
	ba := unsafe.Slice(unsafe.StringData(a), len(a))
	bb := unsafe.Slice(unsafe.StringData(b), len(b))

	aj, as, ae := spans(ba)
	bj, bs, be := spans(bb)

	// Fast rejection: different span lengths means different identity
	if aj != bj || ae-as != be-bs {
		return false
	}

	return bytes.Equal(ba[:aj], bb[:bj]) && bytes.Equal(ba[as:ae], bb[bs:be])
}

// spans returns the byte ranges that comprise the identity of a filename.
// Returns (j, s, e) where [0:j] is the first span and [s:e] is the second span.
// For most patterns, only the first span is used (s == e == 0).
// For embedded versions and APK scripts, both spans are used: prefix [0:j] and suffix [s:len].
func spans(b []byte) (j, s, e int) {
	if x := soname(b); x > 0 {
		return x, 0, 0
	}
	if x, y := apkscript(b); x > 0 {
		return x, y, len(b)
	}
	if x, y := embedded(b); x > 0 {
		return x, y, len(b)
	}
	if x := suffix(b); x > 0 {
		return x, 0, 0
	}
	return len(b), 0, 0
}

// soname detects shared library versioning pattern: name.so.VERSION
// Examples: "libfoo.so.1", "libcrypto.so.1.1", "libz.so.1.2.11"
// Returns the position of the version separator (after ".so"), or 0 if not found.
func soname(b []byte) int {
	n := len(b)
	// Scan backwards looking for ".so.N" pattern
	for i := n - 2; i >= 3; i-- {
		if b[i] == '.' && b[i+1]-'0' < 10 && b[i-1] == 'o' && b[i-2] == 's' && b[i-3] == '.' {
			return i // Position just after ".so"
		}
	}
	return 0
}

// embedded detects embedded version pattern: name.VERSION.ext
// Examples: "foo.1.2.3.so", "bar.4.5.6.dylib"
// Returns (start, end) of the version portion, or (0, 0) if not found.
func embedded(b []byte) (int, int) {
	n := len(b)
	if n < 9 {
		return 0, 0
	}
	// Find the last dot (extension separator)
	ext := -1
	for i := n - 1; i > 0; i-- {
		if b[i] == '.' {
			ext = i
			break
		}
	}
	if ext < 6 || ext == n-1 {
		return 0, 0
	}
	// Scan backwards from extension looking for version pattern
	i, dots := ext-1, 0
	for i >= 0 && (b[i]-'0' < 10 || b[i] == '.') {
		if b[i] == '.' {
			dots++
		}
		i--
	}
	// Need at least 2 dots in version (e.g., "1.2.3")
	if dots >= 2 && i >= 0 && b[i+1] == '.' && b[i+2]-'0' < 10 {
		return i + 1, ext
	}
	return 0, 0
}

// apkscript detects APK package script file patterns with checksums.
// Examples: "alpine-baselayout-3.6.8-r1.Q17OteNVXn9/iSXcJI1Vf8x0TVc9Y=.post-install"
//
//	"busybox-1.37.0-r12.Q1sSNCl4MTQ0d1V/0NTXAhIjY7Nqo=.trigger"
//
// Returns (pkgEnd, scriptStart) where identity = name[:pkgEnd] + name[scriptStart:].
// Returns (0, 0) if pattern not detected.
func apkscript(b []byte) (int, int) {
	n := len(b)
	if n < 20 { // Minimum: "a-1.Q1x.trigger" pattern
		return 0, 0
	}

	// Known APK script suffixes
	suffixes := []string{".post-install", ".post-upgrade", ".pre-install", ".pre-upgrade", ".post-deinstall", ".trigger"}

	// Check if path ends with a known script suffix
	scriptStart := 0
	for _, suf := range suffixes {
		if n > len(suf) && string(b[n-len(suf):]) == suf {
			scriptStart = n - len(suf)
			break
		}
	}
	if scriptStart == 0 {
		return 0, 0
	}

	// Look for .Q1 checksum marker (APK uses Q1 prefix for checksums)
	// The checksum can contain /, +, = (base64 characters)
	checksumStart := -1
	for i := scriptStart - 2; i >= 4; i-- {
		if b[i] == '.' && i+2 < n && b[i+1] == 'Q' && b[i+2] == '1' {
			checksumStart = i
			break
		}
	}
	if checksumStart < 0 {
		return 0, 0
	}

	// Find version start: scan backwards from checksum looking for -DIGIT
	// Package name ends just before the version
	for i := checksumStart - 1; i >= 1; i-- {
		if b[i] == '-' && i+1 < checksumStart && b[i+1]-'0' < 10 {
			return i, scriptStart
		}
	}

	return 0, 0
}

// suffix detects version suffix pattern: name-VERSION or name-VERSION-rN
// Examples: "app-1.0.0", "pkg-2.3.4-r5", "tool-0.1.0-beta1"
// Returns the position of the version separator (the '-'), or 0 if not found.
func suffix(b []byte) int {
	n := len(b)
	i := n - 1
	// Handle optional "-rN" revision suffix (Alpine package convention)
	if i > 2 && b[i]-'0' < 10 {
		for i >= 0 && b[i]-'0' < 10 {
			i--
		}
		if i > 0 && b[i] == 'r' && b[i-1] == '-' {
			i -= 2
		}
	}
	// Scan backwards looking for "-N" pattern where N is a digit
	for i >= 0 {
		c := b[i]
		if c == '-' && i+1 < n && b[i+1]-'0' < 10 {
			return i
		}
		// Continue scanning through valid version characters
		if c-'0' < 10 || c == '.' || c == '-' || c == '+' || (c|32)-'a' < 26 {
			i--
			continue
		}
		break
	}
	return 0
}
