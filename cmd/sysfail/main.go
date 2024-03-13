package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/fuweid/failpoint-bpf/internal"
	"github.com/fuweid/failpoint-bpf/internal/pidfd"
)

var (
	fpFlags   stringSliceFlags
	targetPid uint
)

func init() {
	flag.Var(&fpFlags, "inject", "Perform syscall failpoint, format: syscall[:delay_enter=delay][:delay_exit=delay]:when=first[..last][+step]")
	flag.UintVar(&targetPid, "pid", 0, "Target process id")
}

func main() {
	flag.Parse()

	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "sysfail: %s\n", err)
		os.Exit(1)
	}
}

// run sysfail.
func run() error {
	specs, err := parseFailpointSpecs(fpFlags)
	if err != nil {
		return fmt.Errorf("failed to parse failpoint spec: %w", err)
	}

	fi, err := internal.NewFailpointInjection(uint32(targetPid), specs)
	if err != nil {
		return fmt.Errorf("failed to prepare failpoint injection: %w", err)
	}
	defer fi.Stop()

	pfd, err := pidfd.Open(uint32(targetPid), 0)
	if err != nil {
		return fmt.Errorf("failed to ensure process %v is alive: %w", targetPid, err)
	}

	poller, err := pidfd.NewEpoller()
	if err != nil {
		return fmt.Errorf("failed to init epoller: %w", err)
	}
	defer poller.Close()

	go poller.Run()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = poller.Add(pfd, func() error {
		cancel()
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to watch process %v's exit event: %w", targetPid, err)
	}

	err = fi.Start()
	if err != nil {
		return err
	}

	<-ctx.Done()
	return renderSyscallStat(fi)
}

// parseFailpointSpecs parses --inject options into failpoint specs.
func parseFailpointSpecs(specInStrs []string) (map[string]internal.FailpointSpec, error) {
	specs := make(map[string]internal.FailpointSpec, len(specInStrs))
	for _, specInStr := range specInStrs {
		items := strings.Split(specInStr, ":")
		if len(items) < 2 {
			return nil, fmt.Errorf("invalid inject format: %s", specInStr)
		}

		syscall := items[0]

		var delayEnterMsec, delayExitMsec uint32
		for _, item := range items[1 : len(items)-1] {
			switch {
			case strings.HasPrefix(item, "delay_enter="):
				item = strings.TrimPrefix(item, "delay_enter=")
				delay, err := strconv.ParseUint(item, 10, 64)
				if err != nil {
					return nil, fmt.Errorf("failed to parse delay_enter %s: %w", item, err)
				}
				delayEnterMsec = uint32(delay)
			case strings.HasPrefix(item, "delay_exit="):
				item = strings.TrimPrefix(item, "delay_exit=")
				delay, err := strconv.ParseUint(item, 10, 64)
				if err != nil {
					return nil, fmt.Errorf("failed to parse delay_exit %s: %w", item, err)
				}
				delayExitMsec = uint32(delay)
			default:
				return nil, fmt.Errorf("unknown setting %s", item)
			}
		}

		whenExpr, err := parseWhenExpr(items[len(items)-1])
		if err != nil {
			return nil, fmt.Errorf("invalid when expr: %w", err)
		}

		specs[syscall] = internal.FailpointSpec{
			When:           whenExpr,
			DelayEnterMsec: delayEnterMsec,
			DelayExitMsec:  delayExitMsec,
		}
	}
	if len(specs) == 0 {
		return nil, fmt.Errorf("--inject option is required")
	}
	return specs, nil
}

// parseWhenExpr returns when expression.
func parseWhenExpr(expr string) (internal.WhenExpr, error) {
	if !strings.HasPrefix(expr, "when=") {
		return internal.WhenExpr{}, fmt.Errorf("invalid when expr %s", expr)
	}

	expr = strings.TrimPrefix(expr, "when=")

	hasLast := strings.Contains(expr, "..")
	hasStep := strings.Contains(expr, "+")

	var (
		first, last, step uint32
		pattern           = ""
		patternErr        = ""
		nums              []any
	)

	switch {
	case hasLast && hasStep:
		pattern = "%d..%d+%d"
		patternErr = "first..last+step"
		nums = append(nums, &first, &last, &step)
	case hasLast && !hasStep:
		pattern = "%d..%d"
		patternErr = "first..last"
		nums = append(nums, &first, &last)
	case !hasLast && hasStep:
		pattern = "%d+%d"
		patternErr = "first+step"
		nums = append(nums, &first, &step)
	default:
		pattern = "%d"
		patternErr = "first"
		nums = append(nums, &first)
	}

	n, err := fmt.Sscanf(expr, pattern, nums...)
	if err != nil {
		return internal.WhenExpr{}, fmt.Errorf("failed to parse expr %s (expected format %s): %w", expr, patternErr, err)
	}
	if n != len(nums) {
		return internal.WhenExpr{}, fmt.Errorf("expected format %s, but got %s", patternErr, expr)
	}
	return internal.WhenExpr{
		First: first,
		Last:  last,
		Step:  step,
	}, nil
}

// renderSyscallStat prints syscall stats.
func renderSyscallStat(fi *internal.FailpointInjection) error {
	stats, err := fi.DumpSyscallStats()
	if err != nil {
		return err
	}

	var tw = tabwriter.NewWriter(os.Stdout, 1, 8, 1, ' ', 0)
	fmt.Fprintln(tw, "SYSCALL\tCOUNT\t")
	for sys, cnt := range stats {
		fmt.Fprintf(tw, "%v\t%v\t\n", sys, cnt)
	}
	return tw.Flush()
}

type stringSliceFlags []string

func (ss *stringSliceFlags) String() string {
	return strings.Join(*ss, ",")
}

func (ss *stringSliceFlags) Set(value string) error {
	*ss = append(*ss, value)
	return nil
}
