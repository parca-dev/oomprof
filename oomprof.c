// clang-format off
//go:build ignore
// clang-format on

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

// Produced by:
// bpftool btf dump file /sys/kernel/btf/vmlinux format c > include/vmlinux.h
#include "include/vmlinux.h"

// ARM64 compatibility definitions
#include "include/arm64_compat.h"

#include "include/bpf_core_read.h"
#include "include/bpf_helpers.h"
#include "include/bpf_tracing.h"

// Override bpf_printk to always use bpf_trace_printk for compatibility with older kernels
// FIXME: regenerate headers using a 5.4 kernel
#undef bpf_printk
#define bpf_printk(fmt, args...) \
({ \
	char ____fmt[] = fmt; \
	bpf_trace_printk(____fmt, sizeof(____fmt), ##args); \
})

// Conditional debug logging macro - for now just use bpf_printk directly
// TODO: Make this runtime configurable without verifier issues
#define DEBUG_PRINT(fmt, args...) bpf_printk(fmt, ##args)

#define MAX_STACK_DEPTH 64
#define MAX_BUCKETS_PER_CALL 3362
// Maximum number of tail calls allowed. With MAX_BUCKETS_PER_LOOP=2729, this allows
// processing up to (10+1) * 2729 = 30,019 buckets, which fits within the 30,000
// mem_buckets map limit. If this value is increased, mem_buckets max_entries must
// also be increased proportionally: new_limit >= (MAX_TAIL_CALLS+1) * MAX_BUCKETS_PER_LOOP
#define MAX_TAIL_CALLS 30

char __license[] SEC("license") = "Dual MIT/GPL";

typedef enum Programs {
    RECORD_PROFILE_BUCKETS_PROG=0
} Programs;

// https://github.com/golang/go/blob/6885bad7dd/src/runtime/mprof.go#L148
struct memRecordCycle {
  u64 allocs;
  u64 frees;
  u64 allocBytes;
  u64 freeBytes;
};

// https://github.com/golang/go/blob/6885bad7dd/src/runtime/mprof.go#L87
struct memRecord {
  struct memRecordCycle active;
  struct memRecordCycle	future[3];
};

// Go 1.27 removed byte counters; bytes are counts * gobucket_header.size.
// https://github.com/golang/go/commit/d247ed00e498e9717fb7c80d126bee5a8afdb4e8
struct memRecordCycleGo127 {
  u64 allocs;
  u64 frees;
};

struct memRecordGo127 {
  struct memRecordCycleGo127 active;
  struct memRecordCycleGo127 future[3];
};

// https://github.com/golang/go/blob/6885bad7dd/src/runtime/mprof.go#L75
struct gobucket_header {
  u64 next;
  u64 allnext;
  u64 bucketType; // memBucket or blockBucket (includes mutexProfile)
  u64 hash;
  u64 size;
  u64 nstk;
};

// This isn't the real Go structure, we have a fixed stack and there's
// is variable, we calculate the address of the memRecord in Go.
struct gobucket {
  struct gobucket_header header;
  u64 stk[MAX_STACK_DEPTH];
  // Raw runtime record, decoded in userspace according to the process's Go version.
  u64 record[sizeof(struct memRecord) / sizeof(u64)];
};


struct GoProc {
  u64 mbuckets; // static doesn't change
  u32 num_buckets;  // updated after profile is recorded
  u32 maxStackErrors;
  bool readError;
  bool complete;
  bool reportAlloc; // whether to report alloc metrics or just inuse
  bool started; // whether the process has started profiling
  u8 compactMemRecord; // Go 1.27+ stores counts without byte counters
};

struct Event {
    u32 event_type;
    u32 payload;
};

struct ProfileState {
    u32 pid;
    u64 gobp;
    u32 bucket_count;
    u32 num_tail_calls;  // used to limit tail calls
};


// Tail call map for bucket processing - support up to 10 tail calls
struct {
  __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, u32);
} tail_call_map SEC(".maps");

// State for tail call bucket processing
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, int);
  __type(value, struct ProfileState);
  __uint(max_entries, 1);
} profile_state SEC(".maps");

#define MAX_BUCKETS 60000

// Default to handle large real programs with many allocation sites
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, u32);
  __type(value, struct gobucket);
  __uint(max_entries, MAX_BUCKETS);
} mem_buckets SEC(".maps");

// Map of go procs to mbuckets address
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u32);
  __type(value, struct GoProc);
  __uint(max_entries, 1024);
} go_procs SEC(".maps");

// Global entry for the pid of the process we are profiling, key always 0
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u32);
  __type(value, pid_t);
  __uint(max_entries, 1);
} profile_pid SEC(".maps");


struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __type(key, u32);
  //__type(value, u32);  // Should be u32 (file descriptor)
  //__uint(max_entries, 1024);
  //__type(value, struct Event);
} signal_events SEC(".maps");

// Dummy map just to export the struct - never actually used
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, struct Event);  // This forces BTF generation
    __uint(max_entries, 1);
} dummy_event_map SEC(".maps");

// Dummy map just to export the struct - never actually used
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, struct memRecord);  // This forces BTF generation
    __uint(max_entries, 1);
} dummy_record_map SEC(".maps");

static inline __attribute__((__always_inline__)) int
record_profile_buckets(void *ctx, struct ProfileState *state) {
  DEBUG_PRINT("recording profile buckets for pid: %d mbuckets:%llx buckets:%d\n", state->pid, state->gobp,state->bucket_count);
  struct gobucket *mbp = 0;
  pid_t pid = state->pid;
  int err = 0;
  struct GoProc* gop = bpf_map_lookup_elem(&go_procs, &pid);
  if (!gop) {
    DEBUG_PRINT("signal_probe: go_procs lookup failed: %d\n", pid);
    return 0;
  }

  // Select the size without branching: two loop paths exceed the verifier budget.
  u32 record_size = sizeof(struct memRecordGo127) + ((gop->compactMemRecord ^ 1) & 1) *
    (sizeof(struct memRecord) - sizeof(struct memRecordGo127));

  for (u32 i=0; state->gobp != 0; i++, state->gobp = mbp->header.allnext) {
    if (i >= MAX_BUCKETS_PER_CALL) {
      state->num_tail_calls++;
      if (state->num_tail_calls > MAX_TAIL_CALLS) {
        DEBUG_PRINT("record_profile_buckets: too many tail calls, aborting\n");
        return 0;
      }
      bpf_tail_call(ctx, &tail_call_map, RECORD_PROFILE_BUCKETS_PROG);
      return 0;
    }

    int key = state->bucket_count;
    mbp = bpf_map_lookup_elem(&mem_buckets, &key);
    if (!mbp) {
      DEBUG_PRINT("mem_buckets lookup failed %d:%llx\n", i, state->gobp);
      return 0;
    }

    // read header first
    if ((err = bpf_probe_read_user(&mbp->header, sizeof(struct gobucket_header), (void*)state->gobp))) {
      DEBUG_PRINT("failed to read bucket header at %llx err: %d\n", state->gobp, err);
      gop->readError = true;
      break;
    }
    // read stack next
    u64 stack_size = mbp->header.nstk * sizeof(u64);
    if (stack_size > (MAX_STACK_DEPTH * sizeof(u64))) {
      DEBUG_PRINT("skipping bucket %d: nstk=%llu > MAX=%d\n ", i, mbp->header.nstk, MAX_STACK_DEPTH);
      continue;
    }
    if ((err = bpf_probe_read_user(&mbp->stk, stack_size, (void*)(state->gobp + sizeof(struct gobucket_header))))) {
      DEBUG_PRINT("failed to read bucket stack at %llx err: %d\n", state->gobp + sizeof(struct gobucket_header), err);
      gop->readError = true;
      break;
    }
    // Read only the target's record size. Decoding stays in userspace to keep
    // the bucket loop within the verifier's instruction budget.
    if ((err = bpf_probe_read_user(&mbp->record, record_size, (void*)(state->gobp + sizeof(struct gobucket_header) + stack_size)))) {
      DEBUG_PRINT("failed to read bucket memRecord at %llx err: %d\n", state->gobp + sizeof(struct gobucket_header) + stack_size, err);
      gop->readError = true;
      break;
    }

    state->bucket_count++;
    // Need this to appease the verifier and allow the
    if (state->bucket_count >= MAX_BUCKETS) {
      DEBUG_PRINT("record_profile_buckets: bucket count exceeded max, aborting\n");
      return 0;
    }
  }

  if (state->gobp == 0) {
    gop->complete = true;
  }

  DEBUG_PRINT("found %d gobuckets\n", state->bucket_count);
  gop->num_buckets = state->bucket_count;

  // Signal userland
  DEBUG_PRINT("sending profile recorded event: %d\n", state->pid);
  struct Event ev = { .event_type = 1, .payload = state->pid};
  bpf_perf_event_output(ctx, &signal_events, BPF_F_CURRENT_CPU,
                        &ev, sizeof(struct Event));

  return 0;
}

SEC("tracepoint/record_profile_buckets_tail_call")
int record_profile_buckets_prog(void *ctx) {
  int key=0;
  struct ProfileState *state = bpf_map_lookup_elem(&profile_state, &key);
  if (!state) {
    return 0;
  }
  return record_profile_buckets(ctx, state);
}

// don't rely on BTF
struct _trace_event_raw_mark_victim {
	__u64 unused;
	int pid;
};

SEC("tracepoint/oom/mark_victim")
int oom_mark_victim_handler(struct _trace_event_raw_mark_victim *args) {
  pid_t victim_pid = args->pid;
  DEBUG_PRINT("oom_mark_victim_handler: victim pid: %d\n", victim_pid);

  int key=0;
  pid_t *target_pid = bpf_map_lookup_elem(&profile_pid, &key);
  if (!target_pid) {
    DEBUG_PRINT("profile_pid lookup failed\n");
    return 0;
  }

  if (*target_pid != 0) {
    DEBUG_PRINT("profile_pid already set to %d, ignoring new victim pid %d\n",
               *target_pid, victim_pid);
    return 0;
  }

  struct GoProc* gop = bpf_map_lookup_elem(&go_procs, &victim_pid);
  if (!gop) {
    // If we don't know about him we can't profile him.
    DEBUG_PRINT("oom_mark_victim: go_procs lookup failed, ignoring %d\n", victim_pid);
    return 0;
  }

  // Set the target PID in the profile_pid map so signal_probe can read it
  // so we can distinguish true oom kills from non-oom kills.
  *target_pid = victim_pid;

  return 0;
}

SEC("tracepoint/signal/signal_deliver")
int signal_probe(struct trace_event_raw_signal_deliver *ctx) {
  pid_t pid = bpf_get_current_pid_tgid() >> 32;
  struct GoProc* gop = bpf_map_lookup_elem(&go_procs, &pid);
  if (!gop) {
    return 0;
  }
  //DEBUG_PRINT("signal_probe: go_procs lookup succeeded: %d\n", pid);

  int key=0;
  pid_t *target_pid = bpf_map_lookup_elem(&profile_pid, &key);
  if (!target_pid) {
    DEBUG_PRINT("profile_pid lookup failed\n");
    return 0;
  }
  if (*target_pid != pid) {
    return 0;
  }
  DEBUG_PRINT("signal_probe: target pid == current pid, proceeding\n");
  // num_buckets reset after reading, ignore if not zero.
  if (gop->started) {
    DEBUG_PRINT("signal_probe: already recorded profile for pid %d, ignoring signal\n", pid);
    return 0;
  }
  gop->started = true;
  DEBUG_PRINT("go proc %d got signal\n", pid);

  struct ProfileState *state = bpf_map_lookup_elem(&profile_state, &key);
  if (!state) {
    return 0;
  }
  state->pid = pid;
  state->bucket_count = 0;
  state->num_tail_calls = 0;
  u64 gobp;
  if (bpf_probe_read_user(&gobp, sizeof(void*), (void*)gop->mbuckets)) {
    DEBUG_PRINT("failed to read mbuckets pointer for pid: %d\n", pid);
    return 0;
  }
  state->gobp = gobp;
  record_profile_buckets(ctx, state);

  return 0;
}
