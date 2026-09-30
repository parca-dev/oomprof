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

package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/parca-dev/oomprof/oomprof"
)

func main() {
	// Enable memory profiling for this process
	runtime.MemProfile(nil, false)

	var pidsFlag string
	var debug bool
	flag.StringVar(&pidsFlag, "p", "", "Comma-delimited list of PIDs to profile")
	flag.BoolVar(&debug, "debug", false, "Enable debug logging")
	flag.Parse()

	// Configure logging
	if debug {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}

	ctx := context.Background()

	// Create channel for profile data with buffer to avoid blocking
	profileChan := make(chan oomprof.ProfileData, 10)

	cfg := oomprof.Config{
		MemLimit:     32,
		Verbose:      true,
		Symbolize:    true,
		LogTracePipe: debug,
	}
	state, err := oomprof.Setup(ctx, &cfg, profileChan)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to setup OOM profiler: %v\n", err)
		os.Exit(1)
	}
	defer state.Close()

	// Start goroutine to write profiles to disk
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		slog.Debug("Profile writer goroutine started")
		for profile := range profileChan {
			slog.Debug("Received profile", "pid", profile.PID, "command", profile.Command)

			// Skip empty profiles
			if profile.Profile == nil || len(profile.Profile.Sample) == 0 {
				slog.Debug("Skipping empty profile", "pid", profile.PID)
				continue
			}

			// Create filename with timestamp: command-pid-YYYYMMDDHHmmss.pb.gz
			timestamp := time.Now().Format("20060102150405")
			filename := fmt.Sprintf("%s-%d-%s.pb.gz", profile.Command, profile.PID, timestamp)
			f, err := os.Create(filename)
			if err != nil {
				slog.Error("Failed to create profile file", "error", err, "filename", filename)
				continue
			}

			if err := profile.Profile.Write(f); err != nil {
				slog.Error("Failed to write profile", "error", err, "filename", filename)
			}
			f.Close()
			slog.Info("Profile written", "filename", filename)
		}
		slog.Debug("Profile writer goroutine exiting")
	}()

	// If -p flag is provided, profile specific PIDs
	if pidsFlag != "" {
		pids := strings.Split(pidsFlag, ",")
		for _, pidStr := range pids {
			pidStr = strings.TrimSpace(pidStr)
			var pid int

			if pidStr == "self" {
				// Profile the current process (oompa itself)
				pid = os.Getpid()
				slog.Debug("Profiling self", "pid", pid)
			} else {
				var err error
				pid, err = strconv.Atoi(pidStr)
				if err != nil {
					slog.Error("Invalid PID", "pid", pidStr)
					continue
				}
				slog.Debug("Profiling PID", "pid", pid)
			}

			if err := state.ProfilePid(ctx, uint32(pid)); err != nil {
				slog.Error("Failed to profile PID", "error", err, "pid", pid)
			}
		}
		// Close the channel after all PIDs are profiled
		close(profileChan)
		// Wait for all profiles to be written
		wg.Wait()
	} else {
		// For OOM monitoring mode, keep running until interrupted
		wg.Wait()
	}
}
