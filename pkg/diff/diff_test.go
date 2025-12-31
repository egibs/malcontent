package diff

import (
	"fmt"
	"runtime"
	"slices"
	"testing"
	"testing/synctest"
)

// testHash is a helper for tests that need to call hash directly.
func testHash(s string) (uint64, uint64) {
	return hash(s, hashSeed)
}

func TestDiff_Basic(t *testing.T) {
	old := []string{"lib.so.1", "bin/foo", "doc.md", "old.txt"}
	cur := []string{"lib.so.2", "bin/foo", "doc.md", "new.txt"}

	r := Diff(old, cur)

	want := [4]uint32{2, 1, 1, 1} // unchanged, updated, removed, added
	got := [4]uint32{r.Count(Unchanged), r.Count(Updated), r.Count(Removed), r.Count(Added)}
	if got != want {
		t.Errorf("counts = %v, want %v", got, want)
	}
}

func TestDiff_Concurrent(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		old := make([]string, 1000)
		cur := make([]string, 1000)
		for i := range 1000 {
			old[i] = fmt.Sprintf("lib/foo%d.so.1.0.0", i)
			cur[i] = fmt.Sprintf("lib/foo%d.so.1.1.0", i)
		}

		r := diffP(old, cur, 4)
		if r.Count(Updated) != 1000 {
			t.Errorf("updated = %d, want 1000", r.Count(Updated))
		}
	})
}

func TestHash_SameIdentity(t *testing.T) {
	cases := [][2]string{
		{"libfoo.so.1.0.0", "libfoo.so.2.0.0"},
		{"app-1.0.0-r0", "app-2.0.0-r5"},
		{"foo.1.2.3.so", "foo.4.5.6.so"},
	}

	for _, c := range cases {
		h1, _ := testHash(c[0])
		h2, _ := testHash(c[1])
		if h1 != h2 {
			t.Errorf("hash mismatch: %q=%x, %q=%x", c[0], h1, c[1], h2)
		}
	}
}

func TestHash_DifferentIdentity(t *testing.T) {
	cases := [][2]string{
		{"libfoo.so.1", "libbar.so.1"},
		{"app-1.0.0", "other-1.0.0"},
		{"a.txt", "b.txt"},
	}

	for _, c := range cases {
		h1, _ := testHash(c[0])
		h2, _ := testHash(c[1])
		if h1 == h2 {
			t.Errorf("unexpected collision: %q and %q", c[0], c[1])
		}
	}
}

func TestIdEq(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"libfoo.so.1.2.3", "libfoo.so.2.0.0", true},
		{"libfoo.so.1", "libbar.so.1", false},
		{"foo.1.2.3.so", "foo.4.5.6.so", true},
		{"app-1.0.0-r5", "app-2.0.0-r0", true},
		{"README.md", "README.md", true},
		{"a.txt", "b.txt", false},
	}

	for _, c := range cases {
		if got := idEq(c.a, c.b); got != c.want {
			t.Errorf("idEq(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestResult_Iterators(t *testing.T) {
	old := []string{"a.so.1", "b.so.1", "old.txt"}
	cur := []string{"a.so.1", "b.so.2", "new.txt"}

	r := Diff(old, cur)

	// Test All iterator
	var count int
	for range r.All() {
		count++
	}
	if count != len(r.E) {
		t.Errorf("All() yielded %d, want %d", count, len(r.E))
	}

	// Test Filter iterator
	var updated int
	for range r.Filter(Updated) {
		updated++
	}
	if uint32(updated) != r.Count(Updated) {
		t.Errorf("Filter(Updated) yielded %d, want %d", updated, r.Count(Updated))
	}
}

func TestDiff_Determinism(t *testing.T) {
	old := []string{"c.so.1", "a.so.1", "b.so.1"}
	cur := []string{"c.so.2", "a.so.2", "b.so.2"}

	first := Diff(old, cur)
	for range 10 {
		run := Diff(old, cur)
		if !slices.Equal(first.E, run.E) {
			t.Fatal("non-deterministic")
		}
	}
}

func TestDiff_Empty(t *testing.T) {
	r := Diff(nil, nil)
	got := [4]uint32{r.Count(Unchanged), r.Count(Updated), r.Count(Removed), r.Count(Added)}
	if got != [4]uint32{} {
		t.Errorf("expected zero counts, got %v", got)
	}
}

func TestDiff_LargeScale(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping large test")
	}

	const n = 100_000
	old := make([]string, n)
	cur := make([]string, n)

	for i := range n {
		old[i] = fmt.Sprintf("lib/libfoo%d.so.1.0.0", i)
		cur[i] = fmt.Sprintf("lib/libfoo%d.so.1.1.0", i)
	}
	// 10% unchanged
	for i := range n / 10 {
		cur[i] = old[i]
	}
	// 1% removed/added
	for i := n - n/100; i < n; i++ {
		old[i] = fmt.Sprintf("old/rm%d.so.1", i)
		cur[i] = fmt.Sprintf("cur/add%d.so.1", i)
	}

	r := Diff(old, cur)

	t.Logf("100k: unchanged=%d updated=%d removed=%d added=%d",
		r.Count(Unchanged), r.Count(Updated), r.Count(Removed), r.Count(Added))

	if r.Count(Unchanged) < n/10-n/100 {
		t.Errorf("expected ~%d unchanged", n/10)
	}
}

func BenchmarkHash(b *testing.B) {
	paths := []string{
		"libfoo.so.1.2.3",
		"app-1.0.0-r5",
		"foo.1.2.3.so",
		"README.md",
	}

	for b.Loop() {
		for _, p := range paths {
			hash(p, hashSeed)
		}
	}
}

func BenchmarkDiff1K(b *testing.B)   { benchDiff(b, 1_000) }
func BenchmarkDiff10K(b *testing.B)  { benchDiff(b, 10_000) }
func BenchmarkDiff100K(b *testing.B) { benchDiff(b, 100_000) }
func BenchmarkDiff1M(b *testing.B)   { benchDiff(b, 1_000_000) }
func BenchmarkDiff10M(b *testing.B)  { benchDiff(b, 10_000_000) }

func benchDiff(b *testing.B, n int) {
	b.Helper()
	old, cur := genData(n)
	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		Diff(old, cur)
	}
}

func BenchmarkDiff1M_Workers(b *testing.B) {
	old, cur := genData(1_000_000)
	for _, w := range []int{1, 2, 4, 8, 16} {
		b.Run(fmt.Sprintf("w=%d", w), func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				diffP(old, cur, w)
			}
		})
	}
}

func BenchmarkMemory1M(b *testing.B) {
	old, cur := genData(1_000_000)

	var m1, m2 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m1)

	r := Diff(old, cur)

	runtime.ReadMemStats(&m2)
	_ = r

	b.ReportMetric(float64(m2.TotalAlloc-m1.TotalAlloc)/1e6, "MB-alloc")
	b.ReportMetric(float64(m2.HeapAlloc-m1.HeapAlloc)/1e6, "MB-heap")
}

func genData(n int) ([]string, []string) {
	old := make([]string, n)
	cur := make([]string, n)
	for i := range n {
		old[i] = fmt.Sprintf("lib/libfoo%d.so.1.0.0", i)
		cur[i] = fmt.Sprintf("lib/libfoo%d.so.1.1.0", i)
	}
	return old, cur
}

// Benchmarks for individual pattern matchers

func BenchmarkSoname(b *testing.B) {
	paths := [][]byte{
		[]byte("lib/libcrypto.so.1.1.0"),
		[]byte("lib/libssl.so.3"),
		[]byte("usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.30"),
		[]byte("usr/bin/ls"), // no match
	}
	for b.Loop() {
		for _, p := range paths {
			soname(p)
		}
	}
}

func BenchmarkApkscript(b *testing.B) {
	paths := [][]byte{
		[]byte("alpine-baselayout-3.6.8-r1.Q17OteNVXn9iSXcJI1Vf8x0TVc9Y.post-install"),
		[]byte("busybox-1.37.0-r12.Q1sSNCl4MTQ0d1V0NTXAhIjY7Nqo.trigger"),
		[]byte("ca-certificates-20250619-r0.Q1xUNRT2WUrGiLIMFZ1e2JbKz6MQ.post-deinstall"),
		[]byte("usr/bin/ls"), // no match
	}
	for b.Loop() {
		for _, p := range paths {
			apkscript(p)
		}
	}
}

func BenchmarkSuffix(b *testing.B) {
	paths := [][]byte{
		[]byte("app-1.0.0-r5"),
		[]byte("tool-2.3.4-beta1"),
		[]byte("python3.11-pip-24.0"),
		[]byte("usr/bin/ls"), // no match
	}
	for b.Loop() {
		for _, p := range paths {
			suffix(p)
		}
	}
}

func BenchmarkEmbedded(b *testing.B) {
	paths := [][]byte{
		[]byte("foo.1.2.3.so"),
		[]byte("bar.4.5.6.dylib"),
		[]byte("libfoo.1.2.3.4.so"),
		[]byte("usr/bin/ls"), // no match
	}
	for b.Loop() {
		for _, p := range paths {
			embedded(p)
		}
	}
}

func BenchmarkSpans(b *testing.B) {
	paths := [][]byte{
		[]byte("lib/libcrypto.so.1.1.0"),
		[]byte("alpine-baselayout-3.6.8-r1.Q17OteNVXn9.post-install"),
		[]byte("app-1.0.0-r5"),
		[]byte("foo.1.2.3.so"),
		[]byte("usr/bin/ls"),
	}
	for b.Loop() {
		for _, p := range paths {
			spans(p)
		}
	}
}

func BenchmarkIdEq(b *testing.B) {
	pairs := [][2]string{
		{"lib/libcrypto.so.1.1.0", "lib/libcrypto.so.3.0.0"},
		{"alpine-baselayout-3.6.8-r1.Q17OteNVXn9.post-install", "alpine-baselayout-3.7.0-r0.Q1KfmXSO6h.post-install"},
		{"app-1.0.0-r5", "app-2.0.0-r0"},
		{"usr/bin/ls", "usr/bin/ls"},
	}
	for b.Loop() {
		for _, p := range pairs {
			idEq(p[0], p[1])
		}
	}
}

// Additional pattern matcher tests

func TestSoname(t *testing.T) {
	tests := []struct {
		input string
		want  int // position of the '.' before version number
	}{
		{"libfoo.so.1", 9},                 // identity: libfoo.so
		{"libfoo.so.1.2.3", 9},             // identity: libfoo.so
		{"libz.so.1", 7},                   // identity: libz.so
		{"libssl.so.3", 9},                 // identity: libssl.so
		{"usr/lib/libcrypto.so.1.1.0", 20}, // identity: usr/lib/libcrypto.so
		{"libfoo.so", 0},                   // no version
		{"foo.txt", 0},                     // not a .so
		{".so.1", 3},                       // minimal match (edge case)
	}

	for _, tt := range tests {
		got := soname([]byte(tt.input))
		if got != tt.want {
			t.Errorf("soname(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestApkscript(t *testing.T) {
	tests := []struct {
		input      string
		wantPkgEnd int // position of '-' before version
		wantSuffix int // position of '.' before script suffix
	}{
		// Test actual values by computing: len - len(suffix), find -digit
		{"alpine-baselayout-3.6.8-r1.Q17OteNVXn9.post-install", 17, 38},
		{"busybox-1.37.0-r12.Q1sSNCl4MTQ0.trigger", 7, 31},
		{"foo-1.0.Q1xxx.pre-install", 3, 13},
		{"foo-1.0.Q1xxx.pre-upgrade", 3, 13},
		{"foo-1.0.Q1xxx.post-upgrade", 3, 13},
		{"usr/bin/ls", 0, 0},        // no match
		{"foo.post-install", 0, 0},  // no .Q1
		{"foo-1.0.Q1xxx.txt", 0, 0}, // wrong suffix
	}

	for _, tt := range tests {
		gotPkg, gotSuffix := apkscript([]byte(tt.input))
		if gotPkg != tt.wantPkgEnd || gotSuffix != tt.wantSuffix {
			t.Errorf("apkscript(%q) = (%d, %d), want (%d, %d)",
				tt.input, gotPkg, gotSuffix, tt.wantPkgEnd, tt.wantSuffix)
		}
	}
}

func TestSuffix(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"app-1.0.0", 3},
		{"app-1.0.0-r5", 3},
		{"tool-2.3.4-beta1", 4},
		{"python-3.11", 6},
		{"usr/bin/ls", 0}, // no version suffix
		{"foo", 0},        // too short
		{"foo-bar", 0},    // no digit after -
	}

	for _, tt := range tests {
		got := suffix([]byte(tt.input))
		if got != tt.want {
			t.Errorf("suffix(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestEmbedded(t *testing.T) {
	tests := []struct {
		input string
		wantI int
		wantJ int
	}{
		{"foo.1.2.3.so", 3, 9},
		{"bar.4.5.6.dylib", 3, 9},
		{"libfoo.1.2.3.4.so", 6, 14},
		{"foo.so", 0, 0},   // no embedded version
		{"foo.1.so", 0, 0}, // only 1 dot in version
		{"foo.txt", 0, 0},  // not a library
	}

	for _, tt := range tests {
		gotI, gotJ := embedded([]byte(tt.input))
		if gotI != tt.wantI || gotJ != tt.wantJ {
			t.Errorf("embedded(%q) = (%d, %d), want (%d, %d)",
				tt.input, gotI, gotJ, tt.wantI, tt.wantJ)
		}
	}
}
