// Copyright 2022-2025 The Parca Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build linux

package oomprof

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"runtime/pprof"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/google/pprof/profile"

	lru "github.com/elastic/go-freelru"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $GOARCH -tags linux bpf ../oomprof.c

var (
	// globalState holds the singleton State instance
	globalState *State
	// setupMutex protects against concurrent Setup calls
	setupMutex sync.Mutex
	// isInitialized tracks whether Setup has been called
	isInitialized bool
)

// ErrAlreadyInitialized is returned when Setup is called more than once.
var ErrAlreadyInitialized = errors.New("oomprof: Setup has already been called in this process")

// ErrNotInitialized is returned when GetState is called before Setup.
var ErrNotInitialized = errors.New("oomprof: Setup has not been called yet")

// ErrSelfWatch is returned when trying to watch the current process.
var ErrSelfWatch = errors.New("oomprof: cannot watch current process")

// hashUint32 is a simple hash function for uint32 PID values
func hashUint32(pid uint32) uint32 {
	return pid
}

// ExeInfo holds executable information including path and build ID.
type ExeInfo struct {
	// Path is the full path to the executable.
	Path string
	// BuildID is the build ID of the executable, used for symbolization.
	BuildID string
}

// ProfileData holds the profile information to be sent through the channel.
type ProfileData struct {
	// PID is the process ID being profiled.
	PID uint32
	// Command is the process command name.
	Command string
	// Profile is the memory profile in pprof format.
	Profile *profile.Profile
	// MaxStackErrors is the number of buckets with stack depth > MAX_STACK_DEPTH.
	MaxStackErrors uint32
	// ReadError indicates if there was an error reading the process memory.
	ReadError bool
	// OOM indicates if this profile was triggered by an OOM event.
	OOM bool
	// Complete indicates the eBPF program walked all buckets
	Complete bool
}

const (
	lowMemEvent = iota // currently unused
	profileEvent
)

// State holds the runtime state for oomprof monitoring.
// It manages eBPF programs, maps, and process tracking.
type State struct {
	maps *bpfMaps
	// Either profileChan or traceReporter will be set, not both
	profileChan   chan<- ProfileData
	traceReporter Reporter
	// pidToExeInfo stores PID to executable info mapping
	pidToExeInfo *sync.Map
	// seenPIDs is an LRU cache for tracking PIDs we've already seen (1024 entries matching eBPF map size)
	seenPIDs *lru.SyncedLRU[uint32, struct{}]
	config   *Config
	// labels stores pprof labels captured during ProfilePid calls
	labels map[string]string
	// cleanup resources
	signalDeliverTP link.Link
	oomMarkVictimTP link.Link
	bpfObjects      *bpfObjects
	oomdPids        *lru.SyncedLRU[uint32, struct{}] // LRU cache for oomd PIDs
}

// Config contains configuration options for oomprof.
type Config struct {
	// ScanInterval determines how often to scan for new Go processes.
	// If 0, automatic scanning is disabled and processes must be added via WatchPid.
	ScanInterval time.Duration
	// Symbolize enables symbolization of stack traces in the profile output.
	Symbolize bool
	// MemLimit is the memory limit in MB (currently unused).
	MemLimit int
	// Verbose enables verbose logging output.
	Verbose bool
	// LogTracePipe enables logging of BPF trace pipe output for debugging.
	LogTracePipe bool
	// ReportAlloc enables reporting allocation metrics in addition to inuse metrics.
	// When false (default), only inuse_objects and inuse_space are reported.
	// When true, alloc_objects and alloc_space are also included.
	ReportAlloc bool
}

// TestSleep is the duration tests should sleep to ensure they are scanned before they OOM.
// The test scanner runs every 10ms, so tests sleep for 20ms to ensure they are detected.
var TestSleep = 20 * time.Millisecond

// Setup initializes the eBPF programs and maps, and starts the monitoring loop.
// If Config.ScanInterval > 0, it will periodically scan for Go processes and monitor them.
// The profileChan will receive ProfileData when processes are profiled.
// Returns ErrAlreadyInitialized if Setup has already been called in this process.
func Setup(ctx context.Context, cfg *Config, profileChan chan<- ProfileData) (*State, error) {
	setupMutex.Lock()
	defer setupMutex.Unlock()

	if isInitialized {
		return nil, ErrAlreadyInitialized
	}

	state, err := setupCommon(ctx, cfg, profileChan, nil)
	if err != nil {
		return nil, err
	}

	globalState = state
	isInitialized = true

	return state, nil
}

// SetupWithReporter initializes the eBPF programs and maps with a TraceReporter.
// Instead of constructing ProfileData, it reports traces directly using the reporter.
// Returns ErrAlreadyInitialized if Setup has already been called in this process.
func SetupWithReporter(ctx context.Context, cfg *Config, traceReporter Reporter) (*State, error) {
	setupMutex.Lock()
	defer setupMutex.Unlock()

	if isInitialized {
		return nil, ErrAlreadyInitialized
	}

	state, err := setupCommon(ctx, cfg, nil, traceReporter)
	if err != nil {
		return nil, err
	}

	globalState = state
	isInitialized = true

	return state, nil
}

func (s *State) PidOomd(pid uint32) bool {
	if s.oomdPids == nil {
		return false
	}
	return s.oomdPids.Contains(pid)
}

// GetState returns the singleton State instance.
// Returns ErrNotInitialized if Setup has not been called yet.
func GetState() (*State, error) {
	setupMutex.Lock()
	defer setupMutex.Unlock()

	if !isInitialized || globalState == nil {
		return nil, ErrNotInitialized
	}

	return globalState, nil
}

// Close cleans up all resources associated with the State.
// This includes closing eBPF tracepoints and objects.
// It also resets the global state if this is the global instance.
func (s *State) Close() error {
	setupMutex.Lock()
	defer setupMutex.Unlock()

	logf("oomprof: closing State and cleaning up resources")

	if s.signalDeliverTP != nil {
		s.signalDeliverTP.Close()
		s.signalDeliverTP = nil
	}

	if s.oomMarkVictimTP != nil {
		s.oomMarkVictimTP.Close()
		s.oomMarkVictimTP = nil
	}

	if s.bpfObjects != nil {
		s.bpfObjects.Close()
		s.bpfObjects = nil
	}

	// Reset global state if this is the global instance
	if globalState == s {
		globalState = nil
		isInitialized = false
	}

	return nil
}

// setupCommon contains the common initialization logic for both Setup variants
func setupCommon(ctx context.Context, cfg *Config, profileChan chan<- ProfileData, traceReporter Reporter) (*State, error) {
	//TODO: check if kernel is older than 5.4 and exit if so
	logf("oomprof: starting BPF object loading...")

	objs, signalDeliverTP, oomMarkVictimTP, err := loadBPF()

	if err != nil {
		return nil, fmt.Errorf("loading BPF objects: %v", err)
	}

	// Create a sync.Map to store pid -> exe info mapping
	pidToExeInfo := &sync.Map{}

	// Initialize the PID tracking LRU cache with 1024 entries (matching eBPF map size)
	seenPIDs, err := lru.NewSynced[uint32, struct{}](1024, hashUint32)
	if err != nil {
		signalDeliverTP.Close()
		oomMarkVictimTP.Close()
		objs.Close()
		return nil, fmt.Errorf("failed to create PID LRU cache: %w", err)
	}

	s := &State{
		maps:            &objs.bpfMaps,
		profileChan:     profileChan,
		traceReporter:   traceReporter,
		pidToExeInfo:    pidToExeInfo,
		seenPIDs:        seenPIDs,
		config:          cfg,
		signalDeliverTP: signalDeliverTP,
		oomMarkVictimTP: oomMarkVictimTP,
		bpfObjects:      objs,
	}

	// All BPF objects are now loaded successfully
	logf("oomprof: all BPF probes attached successfully")

	if cfg.LogTracePipe {
		go readTracePipe(ctx)
	}
	// Fixme: remove entries when process goes away
	seenMap := make(map[uint32]int64)

	go s.monitorEventMap(ctx, s, s.pidToExeInfo)

	// Only run process scanning if not disabled
	if cfg.ScanInterval > 0 {
		logf("oomprof: starting process monitoring loop...")

		// Channel to signal when first scan is complete
		firstScanDone := make(chan struct{})

		// Run the process monitoring loop in a goroutine and return after one scan.
		go func() {
			firstScan := true
			for {
				select {
				case <-ctx.Done():
					logf("oomprof: context cancelled, shutting down monitoring loop")
					return
				default:
					newProcs, err := scanGoProcesses(ctx, seenMap, s.pidToExeInfo)
					if err != nil {
						slog.Error("error scanning Go processes", "error", err)
						if firstScan {
							close(firstScanDone)
							firstScan = false
						}
						continue
					}
					for _, p := range newProcs {
						if err := s.addGoProcess(p.PID, p.MBucketsAddr); err != nil {
							logf("oomprof: failed to add go process %d: %v", p.PID, err)
						}
					}

					// Signal that first scan is complete
					if firstScan {
						close(firstScanDone)
						firstScan = false
					}

					// sleep for a second with context check
					select {
					case <-ctx.Done():
						return
					case <-time.After(cfg.ScanInterval):
					}
				}
			}
		}()

		// Wait for first scan to complete before returning
		select {
		case <-firstScanDone:
			logf("oomprof: first Go process scan completed")
		case <-ctx.Done():
			s.Close()
			return nil, ctx.Err()
		}
	}

	return s, nil
}

// ReportBucketsAsTraces converts memory buckets to traces and reports them using the TraceReporter.
func (s *State) reportBucketsAsTraces(allBuckets []bpfGobucket, pid uint32, command string, binaryPath string, buildID string) error {
	if s.traceReporter == nil {
		return fmt.Errorf("no trace reporter configured")
	}

	const batchSize = 1000
	ts := uint64(time.Now().UnixNano())
	meta := SampleMeta{
		Timestamp:      ts,
		Comm:           command,
		ProcessName:    command,
		ExecutablePath: binaryPath,
		PID:            pid,
		CustomLabels:   s.labels,
		BuildID:        buildID,
	}

	// Process buckets in batches of 1000
	for batchStart := 0; batchStart < len(allBuckets); batchStart += batchSize {
		batchEnd := batchStart + batchSize
		if batchEnd > len(allBuckets) {
			batchEnd = len(allBuckets)
		}

		// Create slices for this batch
		var samples []Sample

		// Process buckets in this batch
		for _, bucket := range allBuckets[batchStart:batchEnd] {
			mr := bucket.Mem
			allocs := mr.Active.Allocs
			frees := mr.Active.Frees
			allocBytes := mr.Active.AllocBytes
			freeBytes := mr.Active.FreeBytes

			// Calculate inuse metrics
			inuse := mr.Active.Allocs - mr.Active.Frees
			inuseBytes := mr.Active.AllocBytes - mr.Active.FreeBytes

			// Aggregate future allocations
			// TODO: disable this for non-OOM situations
			for i := 0; i < 3; i++ {
				allocs += mr.Future[i].Allocs
				frees += mr.Future[i].Frees
				allocBytes += mr.Future[i].AllocBytes
				freeBytes += mr.Future[i].FreeBytes
				inuse += mr.Future[i].Allocs - mr.Future[i].Frees
				inuseBytes += mr.Future[i].AllocBytes - mr.Future[i].FreeBytes
			}

			// Skip buckets based on ReportAlloc setting
			if !s.config.ReportAlloc && inuse == 0 {
				// When only reporting inuse, skip buckets with zero inuse
				continue
			}

			// Build the sample from the stack
			stackLen := int(bucket.Header.Nstk)
			addresses := make([]Address, 0, stackLen)

			for i := 0; i < stackLen; i++ {
				addr := bucket.Stk[i]
				if addr == 0 {
					break
				}
				addresses = append(addresses, Address(addr))
			}

			sample := Sample{
				Addresses:  addresses,
				Allocs:     allocs,
				Frees:      frees,
				AllocBytes: allocBytes,
				FreeBytes:  freeBytes,
			}

			samples = append(samples, sample)
		}

		// Report this batch if we have any samples
		if len(samples) > 0 {
			if err := s.traceReporter.SampleEvents(samples, meta); err != nil {
				logf("oomprof: failed to report batch of %d trace events: %v", len(samples), err)
				// Continue processing other batches even if one fails
			}
		}
	}

	slog.Info(fmt.Sprintf("oomprof: reported all traces for PID:%v", pid))
	return nil
}

func loadBPF() (*bpfObjects, link.Link, link.Link, error) {
	// Allow the current process to lok memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, nil, nil, err
	}
	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}

	// Set program options - disable CO-RE for compatibility
	var progOpts ebpf.ProgramOptions
	// Only enable verbose logging if we're in debug mode
	if slog.Default().Enabled(context.Background(), slog.LevelDebug) {
		progOpts.LogLevel = ebpf.LogLevelBranch | ebpf.LogLevelInstruction | ebpf.LogLevelStats
		progOpts.LogSizeStart = 1024 * 1024
	} else {
		progOpts.LogDisabled = true
	}

	opts := ebpf.CollectionOptions{
		Maps:     ebpf.MapOptions{},
		Programs: progOpts,
	}

	// Load BPF objects - this is the slow part that might get stuck
	loadStart := time.Now()
	if err := loadBpfObjects(&objs, &opts); err != nil {
		// Try to find VerifierError in the error chain
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			slog.Error(fmt.Sprintf("oomprof: verifier error details:\n%+v", verr))
		} else {
			// Try unwrapping the error
			slog.Error(fmt.Sprintf("oomprof: BPF load error: %+v", err))
			// Check each level of the error chain
			currentErr := err
			for i := 0; i < 10; i++ {
				currentErr = errors.Unwrap(currentErr)
				if currentErr == nil {
					break
				}
				if errors.As(currentErr, &verr) {
					slog.Error(fmt.Sprintf("oomprof: found VerifierError at level %d:\n%+v", i+1, verr))
					break
				}
			}
		}

		return nil, nil, nil, fmt.Errorf("loading objects: %v", err)
	}
	logf("oomprof: loaded BPF programs and maps in %v", time.Since(loadStart))

	// Register tail call program for bucket processing
	tailCallIndex := uint32(0) // RECORD_PROFILE_BUCKETS_PROG = 0
	if err := objs.TailCallMap.Put(tailCallIndex, objs.RecordProfileBucketsProg); err != nil {
		objs.Close()
		return nil, nil, nil, fmt.Errorf("registering tail call program: %v", err)
	}

	// Initialize profile_pid map with key 0 and value 0
	var key uint32 = 0
	var pidValue int32 = 0
	if err := objs.ProfilePid.Put(key, pidValue); err != nil {
		objs.Close()
		return nil, nil, nil, fmt.Errorf("initializing profile_pid map: %w", err)
	}

	oomMarkVictimTracepoint, err := link.Tracepoint("oom", "mark_victim", objs.OomMarkVictimHandler, nil)
	if err != nil {
		objs.Close()
		return nil, nil, nil, err
	}

	signalDeliverTP, err := link.Tracepoint("signal", "signal_deliver", objs.SignalProbe, nil)
	if err != nil {
		oomMarkVictimTracepoint.Close()
		objs.Close()
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			fmt.Printf("%+v\n", verr)
		}
		return nil, nil, nil, fmt.Errorf("linking tracepoint: %v", err)
	}

	return &objs, signalDeliverTP, oomMarkVictimTracepoint, nil
}

// Consider making this a public API and letting clients manage which processes to monitor.
func (s *State) addGoProcess(pid uint32, mbucketsAddr uint64) error {
	// update go_procs map
	goProc := bpfGoProc{
		Mbuckets:    mbucketsAddr,
		ReportAlloc: s.config.ReportAlloc,
	}
	if err := s.maps.GoProcs.Put(pid, &goProc); err != nil {
		slog.Error("oomprof: error putting PID into go_procs map", "error", err, "pid", pid)
		return err
	}
	return nil
}

// WatchPid adds a specific PID to be monitored by oomprof.
// This is used when ScanInterval is 0 to manually specify which process to monitor.
// Returns immediately if the PID is already being monitored (fast path).
// The expensive ELF parsing and symbol lookup happens in the background to avoid blocking.
// Returns ErrSelfWatch if attempting to watch the current process, typically a guardian
// parent process will watch its child process.
func (s *State) WatchPid(pid uint32) error {
	// Prevent watching our own process, no point in monitoring ourselves
	currentPID := uint32(os.Getpid())
	if pid == currentPID {
		return ErrSelfWatch
	}

	// Fast path: check if we've already seen this PID
	if _, exists := s.seenPIDs.Get(pid); exists {
		return nil // Already monitoring this PID
	}

	// Mark PID as seen immediately to avoid duplicate work
	s.seenPIDs.Add(pid, struct{}{})

	// Background the expensive work (ELF parsing and symbol lookup)
	go func(pid uint32) {
		if err := s.addProcess(pid); err != nil {
			logf("oomprof: failed to add process %d: %v", pid, err)
		}
	}(pid)

	return nil
}

// watchPIDSync is a synchronous version of WatchPid that immediately adds the PID
// to the monitoring state without backgrounding the expensive work. Its used by
// ProfilePid and can be used on ourself.
func (s *State) watchPIDSync(pid uint32) error {
	// Fast path: check if we've already seen this PID
	if _, exists := s.seenPIDs.Get(pid); exists {
		return nil // Already monitoring this PID
	}

	// Mark PID as seen immediately to avoid duplicate work
	s.seenPIDs.Add(pid, struct{}{})

	// Synchronously add the process
	return s.addProcess(pid)
}

func (s *State) addProcess(pid uint32) error {
	// Look up the mbuckets address for this PID
	mbucketsAddr, err := s.getMBucketsAddrForPID(pid, s.pidToExeInfo)
	if err != nil {
		logf("oomprof: failed to get mbuckets address for PID %d: %v", pid, err)
		return err
	}

	logf("oomprof: resolved mbuckets address for PID %d: 0x%x", pid, mbucketsAddr)

	// Add to eBPF monitoring
	if err := s.addGoProcess(pid, mbucketsAddr); err != nil {
		slog.Error("oomprof: failed to add Go process to eBPF monitoring", "error", err, "pid", pid)
		return err
	}
	logf("oomprof: successfully added PID %d to eBPF monitoring", pid)
	return nil
}

// getMBucketsAddrForPID looks up the mbuckets address for a specific PID by reading its ELF file
func (s *State) getMBucketsAddrForPID(pid uint32, pidToExeInfo *sync.Map) (uint64, error) {
	// Get the executable path for this PID
	exePath := fmt.Sprintf("/proc/%d/exe", pid)

	// Resolve the actual executable path by following the symlink
	realExePath, err := os.Readlink(exePath)
	if err != nil {
		return 0, fmt.Errorf("failed to read exe link for PID %d: %w", pid, err)
	}

	// Try to open the executable using the ELF reader
	elfReader := GetELFReader()
	elfFile, err := elfReader.Open(exePath)
	if err != nil {
		return 0, fmt.Errorf("failed to open ELF file for PID %d: %w", pid, err)
	}
	defer elfFile.Close()

	// Get Go version for this executable
	goVersion, err := elfFile.GoVersion()
	if err != nil || goVersion == "" {
		return 0, fmt.Errorf("not a Go program or failed to get Go version for PID %d: %w", pid, err)
	}

	// Get the BuildID
	buildID, err := elfFile.GetBuildID()
	if err != nil {
		logf("oomprof: failed to get build ID for PID %d, using empty string", pid)
		buildID = "" // Use empty string if we can't get the build ID
	}

	// Look up the mbuckets symbol
	mbucketsAddr, err := elfFile.LookupSymbol("runtime.mbuckets")
	if err != nil {
		return 0, fmt.Errorf("failed to find runtime.mbuckets symbol for PID %d: %w", pid, err)
	}

	// Store the PID to exe info mapping in the sync.Map
	exeInfo := &ExeInfo{
		Path:    realExePath,
		BuildID: buildID,
	}
	pidToExeInfo.Store(pid, exeInfo)

	logf("oomprof: resolved mbuckets address for PID %d: 0x%x, buildID: %s, exePath: %s, goVersion: %s",
		pid, mbucketsAddr.Address, buildID, realExePath, goVersion)

	return mbucketsAddr.Address, nil
}

// capturePprofLabels captures current pprof labels and stores them in the state
func (s *State) capturePprofLabels(ctx context.Context) {
	// Convert runtime/pprof.LabelSet to map[string][]string
	pprof.ForLabels(ctx, func(key, value string) bool {
		if s.labels == nil {
			s.labels = make(map[string]string)
		}
		s.labels[key] = value
		return true
	})
}

// UnwatchPid removes a PID from all tracking maps and stops monitoring it.
// This includes removing it from the eBPF go_procs map, pidToExeInfo map,
// seenPIDs cache, and oomdPids cache (if present).
func (s *State) UnwatchPid(pid uint32) {
	logf("oomprof: removing PID %d from oomprof monitoring", pid)

	// Check if this PID is currently being profiled
	var key uint32 = 0
	var currentProfilePid int32
	if err := s.maps.ProfilePid.Lookup(key, &currentProfilePid); err == nil && currentProfilePid == int32(pid) {
		// This PID is currently being profiled, delay cleanup to allow perf_event processing
		logf("oomprof: PID %d is currently being profiled, delaying cleanup", pid)

		// Fork a background goroutine to handle delayed cleanup
		go func() {
			// Wait for profile_pid to be cleared or changed by the normal processing flow
			for i := 0; i < 10; i++ { // Try for up to 5 seconds (10 * 500ms)
				time.Sleep(500 * time.Millisecond)

				var delayedProfilePid int32
				if err := s.maps.ProfilePid.Lookup(key, &delayedProfilePid); err != nil || delayedProfilePid != int32(pid) {
					// profile_pid has been cleared or changed to a different PID
					logf("oomprof: profile_pid for PID %d has been cleared or changed to %d", pid, delayedProfilePid)
					s.performPidCleanup(pid)
					return
				}
			}

			// Timeout after 5 seconds, proceed with cleanup anyway
			slog.Error("oomprof: timeout waiting for profile_pid to clear, proceeding with cleanup", "pid", pid)
			s.performPidCleanup(pid)
		}()
		return
	}

	// Not currently being profiled, perform immediate cleanup
	s.performPidCleanup(pid)
}

// performPidCleanup does the actual cleanup work for UnwatchPid
func (s *State) performPidCleanup(pid uint32) {
	// Remove from eBPF go_procs map
	if err := s.maps.GoProcs.Delete(pid); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		slog.Warn("Failed to delete PID from go_procs map", "error", err, "pid", pid)
	}

	// Remove from pidToExeInfo sync.Map
	s.pidToExeInfo.Delete(pid)

	// Remove from seenPIDs LRU cache
	s.seenPIDs.Remove(pid)

	// Remove from oomdPids cache if it exists
	if s.oomdPids != nil {
		s.oomdPids.Remove(pid)
	}

	// Clear the profile_pid map, it appears we can pick a process to be a victim and then
	// decide not to kill it so this handles that case.
	var key uint32 = 0
	var pidValue int32 = 0
	if err := s.maps.ProfilePid.Put(key, pidValue); err != nil {
		slog.Error("Failed to clear profile_pid map", "error", err)
	}

	logf("oomprof: removed PID %d from all tracking maps and caches", pid)
}

// ProfilePid profiles a specific PID by setting it in the profile_pid map and sending a signal.
// This triggers an immediate memory profile collection for the specified process.
// Returns an error if the PID is not found in the monitored processes.
func (s *State) ProfilePid(ctx context.Context, pid uint32) error {
	// Make sure we're watching it.
	if err := s.watchPIDSync(pid); err != nil {
		return fmt.Errorf("failed to watch PID %d: %w", pid, err)
	}

	// Check if the PID exists in go_procs map
	var gop bpfGoProc
	if err := s.maps.GoProcs.Lookup(pid, &gop); err != nil {
		return fmt.Errorf("PID %d not found in go_procs map: %w", pid, err)
	}

	// Reset num_buckets to 0 to allow re-profiling and update ReportAlloc
	gop.NumBuckets = 0
	gop.ReportAlloc = s.config.ReportAlloc
	if err := s.maps.GoProcs.Put(pid, &gop); err != nil {
		return fmt.Errorf("failed to reset num_buckets for PID %d: %w", pid, err)
	}

	// Set the PID in profile_pid map
	var key uint32 = 0
	pidValue := int32(pid)
	if err := s.maps.ProfilePid.Put(key, pidValue); err != nil {
		return fmt.Errorf("failed to set profile_pid: %w", err)
	}

	// Send SIGUSR1 to trigger profile collection
	if err := syscall.Kill(int(pid), syscall.SIGUSR1); err != nil {
		// Reset profile_pid on error
		if err := s.maps.ProfilePid.Put(key, int32(0)); err != nil {
			logf("oomprof: failed to reset profile_pid: %v", err)
		}
		return fmt.Errorf("failed to send SIGUSR1 to PID %d: %w", pid, err)
	}

	// copy pprof labels
	s.capturePprofLabels(ctx)

	slog.Info("oomprof: sent SIGUSR1 to PID, waiting for profile...", "pid", pid)

	// Wait for profile_pid to be reset to 0 by monitorEventMap
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
			var currentPid int32
			if err := s.maps.ProfilePid.Lookup(key, &currentPid); err != nil {
				return fmt.Errorf("failed to check profile_pid: %w", err)
			}
			if currentPid == 0 {
				slog.Info("oomprof: profile for PID completed", "pid", pid)
				return nil
			}
		}
	}
}

// processBuckets reads buckets from the eBPF map and returns them
func processBuckets(maps *bpfMaps, numBuckets uint32) ([]bpfGobucket, error) {
	const maxBatchSize = uint32(32) // Adjust based on your needs and kernel limits

	var allBuckets []bpfGobucket
	var cursor ebpf.MapBatchCursor

	// Process buckets in batches
	for start := uint32(0); start < numBuckets; start += maxBatchSize {
		// Calculate batch size
		batchSize := maxBatchSize
		if start+batchSize > numBuckets {
			batchSize = numBuckets - start
		}

		// Prepare keys and values for batch lookup
		keys := make([]uint32, batchSize)
		values := make([]bpfGobucket, batchSize)

		for i := uint32(0); i < batchSize; i++ {
			keys[i] = start + i
		}

		// Batch lookup
		count, err := maps.MemBuckets.BatchLookup(&cursor, keys, values, nil)
		if err != nil {
			return nil, fmt.Errorf("batch lookup failed at offset %d: %v", start, err)
		}

		// Add retrieved buckets to our collection
		allBuckets = append(allBuckets, values[:count]...)

		// If we got fewer buckets than requested, we've reached the end
		if count < int(batchSize) {
			break
		}
	}

	slog.Info("oomprof: retrieved buckets", "retrieved", len(allBuckets), "total", numBuckets)

	return allBuckets, nil
}

func readProfile(allBuckets []bpfGobucket, binaryPath string, buildID string, symbolize bool, reportAlloc bool) (*profile.Profile, error) {
	// Convert to pprof format
	convertStart := time.Now()
	prof, err := bucketsToPprof(allBuckets, binaryPath, buildID, symbolize, reportAlloc)
	if err != nil {
		return nil, fmt.Errorf("failed to convert buckets to pprof: %v", err)
	}
	logf("oomprof: converted %d buckets to pprof format in %v", len(allBuckets), time.Since(convertStart))

	return prof, nil
}

func (s *State) monitorEventMap(ctx context.Context, state *State, pidToExeInfo *sync.Map) {
	eventReader, err := perf.NewReader(state.maps.SignalEvents, 1)
	if err != nil {
		slog.Error("oomprof: error creating perf reader", "error", err)
		return
	}
	defer func() {
		if err := eventReader.Close(); err != nil {
			logf("oomprof: failed to close event reader: %v", err)
		}
	}()

	// Close reader when context is cancelled
	go func() {
		<-ctx.Done()
		if err := eventReader.Close(); err != nil {
			logf("oomprof: failed to close event reader: %v", err)
		}
	}()

	for {
		var pid uint32
		select {
		case <-ctx.Done():
			return
		default:
			rec, err := eventReader.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					return
				}
				slog.Error("oomprof: reading from perf event reader", "error", err)
				continue
			}
			if rec.LostSamples != 0 {
				slog.Warn("oomprof: perf event ring buffer full", "lost_samples", rec.LostSamples)
				continue
			}
			// Extract the PID from the raw sample data
			ev := bpfEvent{}
			if err := binary.Read(bytes.NewBuffer(rec.RawSample), binary.LittleEndian, &ev); err != nil {
				slog.Error("parsing perf event", "error", err)
				continue
			}
			switch ev.EventType {
			case profileEvent:
				pid = ev.Payload

				var gop bpfGoProc
				if err := state.maps.GoProcs.Lookup(pid, &gop); err != nil {
					slog.Error("error getting PID from go_procs map", "error", err, "pid", pid)
					continue
				}
				slog.Info(fmt.Sprintf("oomprof: got profile event for PID %d with buckets %d, complete: %t, read_error: %t", pid, gop.NumBuckets, gop.Complete, gop.ReadError))

				// Retrieve the exe info from the sync.Map
				var exeInfo *ExeInfo
				if infoValue, ok := pidToExeInfo.Load(pid); ok {
					exeInfo = infoValue.(*ExeInfo)
				} else {
					slog.Warn("exe info not found for PID", "pid", pid)
					exeInfo = &ExeInfo{Path: "", BuildID: ""}
				}

				logf("oomprof: retrieved exe info for PID %d: path=%s, buildID=%s", pid, exeInfo.Path, exeInfo.BuildID)

				// Extract command name from exe path
				command := "unknown"
				if exeInfo.Path != "" {
					// Get just the basename of the binary path
					if idx := strings.LastIndex(exeInfo.Path, "/"); idx != -1 {
						command = exeInfo.Path[idx+1:]
					} else {
						command = exeInfo.Path
					}
				}

				// Read buckets from eBPF map
				allBuckets, err := processBuckets(state.maps, gop.NumBuckets)
				if err != nil {
					slog.Error("oomprof: error reading buckets for PID", "error", err, "pid", pid)
					continue
				}

				// Handle either ProfileData channel or TraceReporter
				if state.profileChan != nil {
					// Original pprof mode
					prof, err := readProfile(allBuckets, exeInfo.Path, exeInfo.BuildID, s.config.Symbolize, s.config.ReportAlloc)
					if err != nil {
						slog.Error("error reading profile for PID", "error", err, "pid", pid)
					} else {
						slog.Debug("Successfully read profile for PID", "pid", pid)
						// Send profile data through channel
						sendStart := time.Now()
						slog.Debug("Attempting to send profile to channel", "pid", pid)
						select {
						case state.profileChan <- ProfileData{
							PID:            pid,
							Command:        command,
							Profile:        prof,
							ReadError:      gop.ReadError,
							MaxStackErrors: gop.MaxStackErrors,
							Complete:       gop.Complete,
						}:
							slog.Info("Successfully sent profile to channel", "pid", pid, "send_duration", time.Since(sendStart))
							// Clear the profile_pid map after successfully sending the profile
							var key uint32 = 0
							var pidValue int32 = 0
							if err := state.maps.ProfilePid.Put(key, pidValue); err != nil {
								slog.Error("Failed to clear profile_pid map", "error", err)
							}
						case <-ctx.Done():
							slog.Debug("Context cancelled while sending profile", "pid", pid)
							return
						}
					}
				} else if state.traceReporter != nil {
					// TraceReporter mode
					err = state.reportBucketsAsTraces(allBuckets, pid, command, exeInfo.Path, exeInfo.BuildID)
					if err != nil {
						slog.Error("oomprof: error reporting traces for PID", "error", err, "pid", pid)
					} else {
						logf("oomprof: successfully reported traces for PID %d", pid)
						// Clear the profile_pid map after successfully reporting
						var key uint32 = 0
						var pidValue int32 = 0
						if err := state.maps.ProfilePid.Put(key, pidValue); err != nil {
							slog.Error("oomprof: failed to clear profile_pid map", "error", err)
						}
					}
				}
			}
		}
	}
}
