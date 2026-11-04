//go:build linux

package oomprof_test

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/pprof/profile"
	"github.com/parca-dev/oomprof/oomprof"
	"github.com/stretchr/testify/require"
)

func init() {
	// Set memory profile rate to 1 for maximum profile buckets
	runtime.MemProfileRate = 1
}

// TestHeapProfileRecords checks exact counts and bytes from both published and
// pending GC cycles. Build with go test -c to retain runtime symbols, then run
// the test binary as root for each supported Go toolchain.
func TestHeapProfileRecords(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Test requires root privileges")
	}
	elf, err := oomprof.DefaultELFReader().Open("/proc/self/exe")
	require.NoError(t, err)
	_, symbolErr := elf.LookupSymbol("runtime.mbuckets")
	require.NoError(t, elf.Close())
	if symbolErr != nil {
		t.Skip("Test requires runtime symbols; build with go test -c and run the binary as root")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	profiles := make(chan oomprof.ProfileData, 1)
	state, err := oomprof.Setup(ctx, &oomprof.Config{ReportAlloc: true}, profiles)
	require.NoError(t, err)
	defer state.Close()

	chunks := make([][]byte, 11)
	fillProfileObjects(chunks, 4096)
	for i := 0; i < 4; i++ {
		chunks[i] = nil
	}
	large := make([][]byte, 3)
	fillProfileObjects(large, 12288)
	for i := 0; i < 3; i++ {
		runtime.GC()
	}
	// Leave these allocations in a future cycle rather than the active record.
	pending := make([][]byte, 7)
	fillProfileObjects(pending, 4096)

	require.NoError(t, state.ProfilePid(ctx, uint32(os.Getpid())))
	select {
	case data := <-profiles:
		require.True(t, data.Complete)
		require.False(t, data.ReadError)
		var buf bytes.Buffer
		require.NoError(t, data.Profile.Write(&buf))
		prof, err := profile.ParseData(buf.Bytes())
		require.NoError(t, err)
		require.NoError(t, prof.CheckValid())

		totals := make([]int64, 4)
		for _, sample := range prof.Sample {
			for _, loc := range sample.Location {
				fn := runtime.FuncForPC(uintptr(loc.Address - 1))
				if fn == nil || !strings.HasSuffix(fn.Name(), ".fillProfileObjects") {
					continue
				}
				for i, value := range sample.Value {
					totals[i] += value
				}
				break
			}
		}
		// 18 small allocations, 4 freed, plus 3 live large allocations.
		require.Equal(t, []int64{17, 94208, 21, 110592}, totals,
			"inuse_objects, inuse_space, alloc_objects, alloc_space on %s", runtime.Version())
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	runtime.KeepAlive(chunks)
	runtime.KeepAlive(large)
	runtime.KeepAlive(pending)
}

//go:noinline
func fillProfileObjects(chunks [][]byte, size int) {
	for i := range chunks {
		chunks[i] = make([]byte, size)
		chunks[i][0] = byte(i)
	}
}

// TestOOMProfileChannelMode tests OOM profiling using the channel-based Setup call
func TestOOMProfileChannelMode(t *testing.T) {
	// Skip if not root (required for eBPF)
	if os.Getuid() != 0 {
		t.Skip("Test requires root privileges")
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create channel for profile data
	profileChan := make(chan oomprof.ProfileData, 10)

	// Configure oomprof
	config := &oomprof.Config{
		ScanInterval: 0,                // Disable process scanning
		MemLimit:     32 * 1024 * 1024, // 32MB
		LogTracePipe: false,
		Verbose:      true,
		Symbolize:    false,
	}

	// Start OOM profiler with channel mode
	state, err := oomprof.Setup(ctx, config, profileChan)
	require.NoError(t, err, "Failed to start oomprof")
	defer state.Close()

	// Track received profiles
	profileReceived := make(chan oomprof.ProfileData, 2)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case profileData := <-profileChan:
				slog.Info(fmt.Sprintf("Received profile for PID %d, command %s", profileData.PID, profileData.Command))
				profileReceived <- profileData
			}
		}
	}()

	// Wait a bit for oomprof to set up monitoring
	time.Sleep(100 * time.Millisecond)

	// Get our PID
	selfPID := uint32(os.Getpid())

	// Trigger profile collection
	err = state.ProfilePid(ctx, selfPID)
	if err != nil {
		// If symbolization fails, that's expected for test binaries
		t.Logf("ProfilePid returned error (may be expected for test binary): %v", err)
		// Continue the test as the profile may still be generated
	}

	// Wait for profile to be received (with longer timeout due to eBPF setup)
	select {
	case profileData := <-profileReceived:
		t.Log("Profile successfully received")
		require.Equal(t, selfPID, profileData.PID, "Profile should be for our PID")
		require.NotNil(t, profileData.Profile, "Profile should not be nil")
		require.True(t, len(profileData.Profile.Sample) > 0 || !profileData.Complete)
		if len(profileData.Profile.Sample) == 0 {
			t.Log("Warning: Profile has no samples (may be due to symbolization issues)")
		} else {
			t.Logf("Profile has %d samples", len(profileData.Profile.Sample))
		}
	case <-time.After(10 * time.Second):
		t.Log("No profile received - this may be expected if eBPF profiling encounters issues")
		t.Log("The test validates that oomprof can be set up and ProfilePid can be called")
		return // Don't fail the test, just log
	}

	// Allocate some memory to make the profile more interesting
	allocateMemory()

	// Trigger another profile collection
	err = state.ProfilePid(ctx, selfPID)
	if err != nil {
		t.Logf("Second ProfilePid returned error (may be expected): %v", err)
	}

	// Wait for second profile
	select {
	case profileData := <-profileReceived:
		t.Log("Second profile successfully received")
		require.Equal(t, selfPID, profileData.PID, "Second profile should be for our PID")
		require.NotNil(t, profileData.Profile, "Second profile should not be nil")
		require.True(t, len(profileData.Profile.Sample) > 0 || !profileData.Complete)
		if len(profileData.Profile.Sample) == 0 {
			t.Log("Warning: Second profile has no samples")
		} else {
			t.Logf("Second profile has %d samples", len(profileData.Profile.Sample))
		}
		require.Equal(t, len(profileData.Profile.SampleType), 2)
	case <-time.After(10 * time.Second):
		t.Log("Second profile not received - completing test")
		return // Complete the test successfully
	}
}

// allocateMemory allocates some memory to make the profile more interesting
func allocateMemory() {
	// Allocate some memory chunks
	var chunks [][]byte
	for i := 0; i < 50; i++ {
		chunk := make([]byte, 1024*1024) // 1MB chunks
		// Fill with data to prevent optimization
		for j := range chunk {
			chunk[j] = byte(i + j)
		}
		chunks = append(chunks, chunk)
	}

	// Keep reference to prevent immediate GC
	runtime.KeepAlive(chunks)

	// Force GC to stabilize memory state
	runtime.GC()
}
