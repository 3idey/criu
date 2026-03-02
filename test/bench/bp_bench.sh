#!/bin/bash
#
# bp_bench.sh - Benchmark hardware breakpoint impact on restore performance
#
# Measures CRIU restore time with and without hardware breakpoints at
# various thread counts. Uses CRIU_FAULT=130 (FI_NO_BREAKPOINTS) to
# disable breakpoints without any code changes.
#
# Usage: sudo ./bp_bench.sh [iterations]
#
# Output: A table comparing restore times (microseconds) with and
# without hardware breakpoints for thread counts 1, 10, 50, 100, 500.
#
# Requires: criu built in ../../criu/criu, gcc

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CRIU="${SCRIPT_DIR}/../../criu/criu"
WORKER_SRC="${SCRIPT_DIR}/bp_bench_worker.c"
WORKER_BIN="${SCRIPT_DIR}/bp_bench_worker"
WORK_DIR="/tmp/bp_bench_$$"
ITERATIONS="${1:-5}"
THREAD_COUNTS="1 10 50 100 500 1000 10000"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BOLD='\033[1m'
NC='\033[0m'

cleanup()
{
	# Kill any lingering worker processes
	if [[ -f "${WORK_DIR}/worker.pid" ]]; then
		local pid
		pid=$(cat "${WORK_DIR}/worker.pid" 2>/dev/null || true)
		if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
			kill -9 "$pid" 2>/dev/null || true
			wait "$pid" 2>/dev/null || true
		fi
	fi
	rm -rf "${WORK_DIR}"
}

die()
{
	echo -e "${RED}ERROR: $*${NC}" >&2
	cleanup
	exit 1
}

info()
{
	echo -e "${GREEN}>>> $*${NC}"
}

# Check prerequisites
check_prereqs()
{
	[[ $(id -u) -eq 0 ]] || die "Must run as root"
	[[ -x "$CRIU" ]] || die "CRIU binary not found at $CRIU"
	command -v gcc >/dev/null || die "gcc not found"
}

# Compile the worker
compile_worker()
{
	info "Compiling worker program..."
	gcc -O2 -pthread -o "$WORKER_BIN" "$WORKER_SRC"
}

# Start the worker process with N threads
# Sets WORKER_PID on success
start_worker()
{
	local nr_threads="$1"
	local pid_file="${WORK_DIR}/worker.pid"

	rm -f "$pid_file"
	"$WORKER_BIN" "$nr_threads" "$pid_file" &
	local bgpid=$!

	# Wait for PID file
	local tries=0
	while [[ ! -s "$pid_file" ]] && kill -0 "$bgpid" 2>/dev/null; do
		sleep 0.1
		tries=$((tries + 1))
		if [[ $tries -ge 50 ]]; then
			die "Worker did not write PID file in 5s"
		fi
	done

	WORKER_PID=$(cat "$pid_file")

	# Verify it's running and threads are up
	sleep 0.2
	if ! kill -0 "$WORKER_PID" 2>/dev/null; then
		die "Worker process $WORKER_PID is not running"
	fi
}

# Dump a process
do_dump()
{
	local pid="$1"
	local img_dir="$2"

	rm -rf "$img_dir"
	mkdir -p "$img_dir"

	"$CRIU" dump -t "$pid" -D "$img_dir" --shell-job -v0 2>/dev/null
}

# Restore a process and return restore_time in microseconds
# Args: img_dir [env_var_name env_var_value]
# Prints restore_time to stdout
do_restore()
{
	local img_dir="$1"
	local stats_dir="${WORK_DIR}/stats"
	local env_prefix=""

	if [[ "${2:-}" == "CRIU_FAULT" ]]; then
		env_prefix="CRIU_FAULT=${3}"
	fi

	rm -rf "$stats_dir"
	mkdir -p "$stats_dir"

	# Restore with --display-stats, capture output
	local output
	if [[ -n "$env_prefix" ]]; then
		output=$(env "$env_prefix" "$CRIU" restore \
			-D "$img_dir" \
			-W "$stats_dir" \
			--shell-job -d \
			--display-stats \
			-v0 2>&1) || true
	else
		output=$("$CRIU" restore \
			-D "$img_dir" \
			-W "$stats_dir" \
			--shell-job -d \
			--display-stats \
			-v0 2>&1) || true
	fi

	# Extract restore time from output
	local rtime
	rtime=$(echo "$output" | grep "Resume time:" | \
		sed 's/.*Resume time: \([0-9]*\) us.*/\1/')

	if [[ -z "$rtime" ]]; then
		echo "0"
	else
		echo "$rtime"
	fi

	# Kill the restored process
	sleep 0.2
	if [[ -f "${img_dir}/core-"* ]]; then
		# Find PID of restored process from pidfile
		local pid_file="${WORK_DIR}/worker.pid"
		if [[ -f "$pid_file" ]]; then
			local pid
			pid=$(cat "$pid_file" 2>/dev/null || true)
			if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
				kill -9 "$pid" 2>/dev/null || true
				wait "$pid" 2>/dev/null || true
			fi
		fi
	fi
}

# Kill any leftover worker by PID
kill_worker()
{
	if [[ -n "${WORKER_PID:-}" ]] && kill -0 "$WORKER_PID" 2>/dev/null; then
		kill -9 "$WORKER_PID" 2>/dev/null || true
		wait "$WORKER_PID" 2>/dev/null || true
	fi
}

# Run one benchmark: dump, then restore N times with and without BP
# Args: nr_threads
# Outputs: "with_bp_avg without_bp_avg"
run_bench()
{
	local nr_threads="$1"
	local img_dir="${WORK_DIR}/images"
	local sum_bp=0
	local sum_nobp=0
	local i

	for ((i = 1; i <= ITERATIONS; i++)); do
		# --- With breakpoints (default CRIU behavior) ---
		start_worker "$nr_threads"
		do_dump "$WORKER_PID" "$img_dir"

		local rtime_bp
		rtime_bp=$(do_restore "$img_dir")
		sum_bp=$((sum_bp + rtime_bp))
		kill_worker

		# --- Without breakpoints (CRIU_FAULT=130) ---
		start_worker "$nr_threads"
		do_dump "$WORKER_PID" "$img_dir"

		local rtime_nobp
		rtime_nobp=$(do_restore "$img_dir" "CRIU_FAULT" "130")
		sum_nobp=$((sum_nobp + rtime_nobp))
		kill_worker
	done

	local avg_bp=$((sum_bp / ITERATIONS))
	local avg_nobp=$((sum_nobp / ITERATIONS))

	echo "$avg_bp $avg_nobp"
}

# Print results table
print_header()
{
	echo ""
	echo -e "${BOLD}Hardware Breakpoint Restore Performance Benchmark${NC}"
	echo -e "${BOLD}==================================================${NC}"
	echo ""
	echo "System: $(uname -srm)"
	echo "CPU:    $(grep 'model name' /proc/cpuinfo | head -1 | cut -d: -f2 | xargs)"
	echo "Virt:   $(systemd-detect-virt 2>/dev/null || echo 'unknown')"
	echo "CRIU:   $($CRIU --version 2>&1 | head -1)"
	echo "Iterations per data point: $ITERATIONS"
	echo ""
	printf "${BOLD}%-12s %15s %15s %12s${NC}\n" \
		"Threads" "With BP (us)" "Without BP (us)" "Diff (%)"
	printf "%-12s %15s %15s %12s\n" \
		"--------" "------------" "---------------" "--------"
}

print_row()
{
	local threads="$1"
	local bp_time="$2"
	local nobp_time="$3"

	local diff_pct
	if [[ "$nobp_time" -gt 0 ]]; then
		# Calculate percentage: ((bp - nobp) / nobp) * 100
		diff_pct=$(awk "BEGIN { printf \"%.1f\", (($bp_time - $nobp_time) / $nobp_time) * 100 }")
	else
		diff_pct="N/A"
	fi

	printf "%-12s %15s %15s %11s%%\n" \
		"$threads" "$bp_time" "$nobp_time" "$diff_pct"
}

# ---- Main ----

main()
{
	check_prereqs
	compile_worker
	mkdir -p "$WORK_DIR"

	trap cleanup EXIT

	print_header

	for nt in $THREAD_COUNTS; do
		info "Benchmarking with $nt thread(s)..."
		local result
		result=$(run_bench "$nt")
		local bp_time nobp_time
		bp_time=$(echo "$result" | awk '{print $1}')
		nobp_time=$(echo "$result" | awk '{print $2}')
		print_row "$nt" "$bp_time" "$nobp_time"
	done

	echo ""
	echo "Notes:"
	echo "  'With BP'    = hardware breakpoints enabled (current default)"
	echo "  'Without BP' = CRIU_FAULT=130 (FI_NO_BREAKPOINTS, uses PTRACE_SYSCALL)"
	echo "  Positive diff% means breakpoints are slower"
	echo ""
}

main "$@"
