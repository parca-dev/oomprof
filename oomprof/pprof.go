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
	"fmt"
	"log/slog"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/google/pprof/profile"
)

func bucketsToPprof(buckets []bpfGobucket, binaryPath string, buildID string, symbolize bool, reportAlloc bool) (*profile.Profile, error) {
	// Create a new pprof profile
	prof := &profile.Profile{
		DefaultSampleType: "inuse_space",
		SampleType: []*profile.ValueType{
			{Type: "inuse_objects", Unit: "count"},
			{Type: "inuse_space", Unit: "bytes"},
		},
		PeriodType: &profile.ValueType{Type: "space", Unit: "bytes"},
		Period:     512 * 1024, // TODO: read this from process
		TimeNanos:  time.Now().UnixNano(),
	}

	if reportAlloc {
		prof.SampleType = append(prof.SampleType,
			&profile.ValueType{Type: "alloc_objects", Unit: "count"},
			&profile.ValueType{Type: "alloc_space", Unit: "bytes"})

	}

	// Create a mapping for the binary if we have the path
	var mainMapping *profile.Mapping
	if binaryPath != "" {
		mainMapping = &profile.Mapping{
			ID:      1,
			Start:   0,
			Limit:   ^uint64(0), // Use max uint64 as we don't know the actual size
			File:    binaryPath,
			BuildID: buildID,
		}
		prof.Mapping = append(prof.Mapping, mainMapping)
	}

	// Track unique locations and functions
	locationMap := make(map[uint64]*profile.Location)
	functionMap := make(map[uint64]*profile.Function)
	nextLocationID := uint64(1)
	nextFunctionID := uint64(1)

	// Collect all unique addresses first
	uniqueAddrs := make(map[uint64]bool)
	for _, bucket := range buckets {
		mr := bucket.Mem
		allocs := mr.Active.Allocs
		inuse := mr.Active.Allocs - mr.Active.Frees
		for i := 0; i < 3; i++ {
			allocs += mr.Future[i].Allocs
			inuse += mr.Future[i].Allocs - mr.Future[i].Frees
		}
		// Skip buckets based on ReportAlloc setting
		if !reportAlloc && inuse == 0 {
			// When only reporting inuse, skip buckets with zero inuse
			continue
		}

		stackLen := int(bucket.Header.Nstk)
		for i := 0; i < stackLen; i++ {
			addr := bucket.Stk[i]
			if addr != 0 {
				uniqueAddrs[addr] = true
			}
		}
	}

	// Batch symbolize all addresses at once
	symbolMap := make(map[uint64]symbolInfo)
	if binaryPath != "" && len(uniqueAddrs) > 0 && symbolize {
		symbolMap = batchResolveSymbols(binaryPath, uniqueAddrs)
	}

	// Process each bucket
	for b, _ := range buckets {
		mr := buckets[b].Mem
		allocs, allocBytes := mr.Active.Allocs, mr.Active.AllocBytes
		inuse, inuseBytes := mr.Active.Allocs-mr.Active.Frees, mr.Active.AllocBytes-mr.Active.FreeBytes
		for i := 0; i < 3; i++ {
			allocs += mr.Future[i].Allocs
			allocBytes += mr.Future[i].AllocBytes
			inuse += mr.Future[i].Allocs - mr.Future[i].Frees
			inuseBytes += mr.Future[i].AllocBytes - mr.Future[i].FreeBytes
		}
		if !reportAlloc && inuse == 0 {
			// When only reporting inuse, skip buckets with zero inuse
			continue
		}

		// Create locations for the stack trace
		var locations []*profile.Location

		// Process stack frames (up to nstk)
		stackLen := int(buckets[b].Header.Nstk)

		for i := 0; i < stackLen; i++ {
			addr := buckets[b].Stk[i]
			if addr == 0 {
				break
			}

			// Check if we already have this location
			loc, exists := locationMap[addr]
			if !exists {
				// Create a new location
				loc = &profile.Location{
					ID:      nextLocationID,
					Address: addr,
					Mapping: mainMapping,
				}
				nextLocationID++

				// Create a function for this location using symbol resolution
				_, fnExists := functionMap[addr]
				if !fnExists {
					var funcName, location string
					var lineNum int64 = 1

					if symInfo, ok := symbolMap[addr]; ok {
						funcName = symInfo.name
						location = symInfo.file
						lineNum = symInfo.line

						fn := &profile.Function{
							ID:         nextFunctionID,
							Name:       funcName,
							SystemName: funcName,
							Filename:   location,
							StartLine:  lineNum,
						}
						nextFunctionID++
						functionMap[addr] = fn
						prof.Function = append(prof.Function, fn)

						// Add function to location
						loc.Line = []profile.Line{
							{
								Function: fn,
								Line:     1,
							},
						}

					}
				}

				locationMap[addr] = loc
				prof.Location = append(prof.Location, loc)
			}

			locations = append(locations, loc)
		}

		// Create a sample
		values := []int64{int64(inuse), int64(inuseBytes)}
		if reportAlloc {
			values = append(values, int64(allocs), int64(allocBytes))
		}
		sample := &profile.Sample{
			Location: locations,
			Value:    values,
		}
		prof.Sample = append(prof.Sample, sample)
	}

	// Sort locations by ID
	for i := range prof.Location {
		for j := i + 1; j < len(prof.Location); j++ {
			if prof.Location[i].ID > prof.Location[j].ID {
				prof.Location[i], prof.Location[j] = prof.Location[j], prof.Location[i]
			}
		}
	}

	return prof, nil
}

type symbolInfo struct {
	name string
	file string
	line int64
}

// batchResolveSymbols uses a single addr2line call to resolve all addresses at once
func batchResolveSymbols(binaryPath string, addrs map[uint64]bool) map[uint64]symbolInfo {
	result := make(map[uint64]symbolInfo)

	if len(addrs) == 0 {
		return result
	}

	// Build address list
	var addrList []string
	var addrOrder []uint64
	for addr := range addrs {
		addrList = append(addrList, fmt.Sprintf("0x%x", addr))
		addrOrder = append(addrOrder, addr)
	}

	slog.Debug("Batch symbolizing addresses", "count", len(addrList))
	startTime := time.Now()

	// Call addr2line with all addresses at once
	cmd := exec.Command("addr2line", append([]string{"-e", binaryPath, "-f", "-C"}, addrList...)...)
	output, err := cmd.Output()
	if err != nil {
		slog.Debug("addr2line batch call failed", "error", err)
		// Return empty symbols
		for _, addr := range addrOrder {
			result[addr] = symbolInfo{
				name: fmt.Sprintf("func_%x", addr),
				file: "",
				line: 0,
			}
		}
		return result
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")

	// addr2line outputs 2 lines per address: function name, then file:line
	for i := 0; i < len(addrOrder) && i*2+1 < len(lines); i++ {
		addr := addrOrder[i]
		funcName := strings.TrimSpace(lines[i*2])
		location := strings.TrimSpace(lines[i*2+1])

		var lineNum int64 = 1
		var fileName string = location

		// Extract line number if available
		if parts := strings.Split(location, ":"); len(parts) >= 2 {
			fileName = parts[0]
			if num, err := strconv.ParseInt(parts[1], 10, 64); err == nil {
				lineNum = num
			}
		}

		// Use address as function name if symbolization failed
		if funcName == "??" || location == "??:0" {
			funcName = fmt.Sprintf("func_%x", addr)
			fileName = ""
			lineNum = 0
		}

		result[addr] = symbolInfo{
			name: funcName,
			file: fileName,
			line: lineNum,
		}
	}

	slog.Debug("Batch symbolization completed", "duration", time.Since(startTime))
	return result
}
