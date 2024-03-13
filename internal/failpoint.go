package internal

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"runtime"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

//go:generate cp ../bpf/.output/failpoint.bpf.o failpoint.bpf.o
var (
	//go:embed failpoint.bpf.o
	progByteCode []byte

	// progFailpointMapName is dataset storing failpoints.
	progFailpointMapName = "sys_failpoints"
)

// WhenExpr follows strace(1) convention to define expression for injecting
// failpoint to target syscalls.
//
// The format of the subexpression is: first[..last][+[step]].
//
// REF: https://man7.org/linux/man-pages/man1/strace.1.html
type WhenExpr struct {
	First uint32
	Last  uint32
	Step  uint32
}

// FailpointSpec is the specification to allow bpf prog to perform injection on
// the target syscall.
type FailpointSpec struct {
	When WhenExpr
	// DelayEnterMsec is the duration used to delay on entering the syscall.
	DelayEnterMsec uint32
	// DelayExitMsec is the duration used to delay on exiting the syscall.
	DelayExitMsec uint32
}

// NewFailpointInjection returns failpoint injection handler.
func NewFailpointInjection(pid uint32, specs map[string]FailpointSpec) (*FailpointInjection, error) {
	if pid == 0 {
		return nil, fmt.Errorf("invalid pid(%d)", pid)
	}

	if err := validateSpecs(specs); err != nil {
		return nil, err
	}

	bpfSpec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(progByteCode))
	if err != nil {
		return nil, fmt.Errorf("failed to load bpf program: %w", err)
	}

	bpfObjs, err := buildBpfObjs(bpfSpec, pid, specs)
	if err != nil {
		return nil, err
	}

	syscalls := make([]string, 0, len(specs))
	for sys := range specs {
		syscalls = append(syscalls, sys)
	}

	// TODO: use pidfd to watch exit event
	return &FailpointInjection{
		pid:      pid,
		syscalls: syscalls,
		bpfObjs:  bpfObjs,
	}, nil
}

type FailpointInjection struct {
	pid      uint32
	syscalls []string
	bpfObjs  *ebpf.Collection
}

// Start is to attach bpf handler to interested syscalls.
func (fi *FailpointInjection) Start() (retErr error) {
	defer func() {
		if retErr != nil {
			fi.Stop()
		}
	}()

	for _, sys := range fi.syscalls {
		switch runtime.GOARCH {
		case "amd64":
			sysFunc := fmt.Sprintf("__x64_sys_%s", sys)
			for _, progName := range []string{"handle_sys_entry_event", "handle_sys_exit_event"} {
				prog := fi.bpfObjs.Programs[progName+sysFunc]

				_, err := link.AttachTracing(link.TracingOptions{
					Program: prog,
				})

				if err != nil {
					return fmt.Errorf("failed to link %s: %w", sysFunc, err)
				}
			}
		default:
			return fmt.Errorf("unsupported arch %s", runtime.GOARCH)
		}
	}

	// watch exit event
	_, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sched_process_exit",
		Program: fi.bpfObjs.Programs["handle_sched_process_exit"],
	})
	if err != nil {
		return fmt.Errorf("failed to add sched_process_exit handler: %w", err)
	}

	err = fi.bpfObjs.Maps[".bss"].Update(uint32(0), &fi.pid, ebpf.UpdateExist)
	if err != nil {
		return fmt.Errorf("failed to update filter_pid in .bss section: %w", err)
	}
	return nil
}

// DumpSyscallStats dumps syscall stats.
func (fi *FailpointInjection) DumpSyscallStats() (map[string]uint64, error) {
	res := make(map[string]uint64)

	for _, sys := range fi.syscalls {
		addr, err := SyscallAddress(sys)
		if err != nil {
			return nil, err
		}

		var count uint64
		err = fi.bpfObjs.Maps["sys_entry_counts"].Lookup(addr, &count)
		if err != nil {
			if !errors.Is(err, ebpf.ErrKeyNotExist) {
				return nil, err
			}
		}
		res[sys] = count
	}
	return res, nil
}

// Stop is to stop all the event handlers.
func (fi *FailpointInjection) Stop() {
	for _, bMap := range fi.bpfObjs.Maps {
		bMap.Close()
	}
	for _, bProg := range fi.bpfObjs.Programs {
		bProg.Close()
	}
}

func buildBpfObjs(bpfSpec *ebpf.CollectionSpec, pid uint32, specs map[string]FailpointSpec) (_ *ebpf.Collection, retErr error) {
	// TODO: can we just load one program and attach that one to all the
	// interested syscalls?
	for sys := range specs {
		switch runtime.GOARCH {
		case "amd64":
			sysFunc := fmt.Sprintf("__x64_sys_%s", strings.ToLower(sys))
			for _, progName := range []string{"handle_sys_entry_event", "handle_sys_exit_event"} {
				copied := bpfSpec.Programs[progName].Copy()
				copied.Type = ebpf.Tracing
				copied.Flags = unix.BPF_F_SLEEPABLE
				copied.AttachType = ebpf.AttachTraceFExit
				copied.AttachTo = sysFunc

				bpfSpec.Programs[progName+sysFunc] = copied
			}

		default:
			return nil, fmt.Errorf("unsupported arch %s", runtime.GOARCH)
		}
	}

	objs, err := ebpf.NewCollection(bpfSpec)
	if err != nil {
		return nil, fmt.Errorf("failed to load bpf objects into kernel: %w", err)
	}
	defer func() {
		if retErr != nil {
			for _, bMap := range objs.Maps {
				bMap.Close()
			}
			for _, bProg := range objs.Programs {
				bProg.Close()
			}
		}
	}()

	for sys, spec := range specs {
		addr, err := SyscallAddress(sys)
		if err != nil {
			return nil, fmt.Errorf("failed to ensure %s syscall address: %w", sys, err)
		}

		err = objs.Maps[progFailpointMapName].Update(addr, &spec, ebpf.UpdateNoExist)
		if err != nil {
			return nil, fmt.Errorf("failed to update failpoint specs for syscall %s in bpf map: %w", sys, err)
		}
	}
	return objs, nil
}

func validateSpecs(specs map[string]FailpointSpec) error {
	for sys, spec := range specs {
		if _, err := SyscallAddress(sys); err != nil {
			return fmt.Errorf("failed to ensure %s syscall address: %w", sys, err)
		}
		if err := validateWhenExpr(spec.When); err != nil {
			return fmt.Errorf("invalid failpoint spec on syscall %s: %w", sys, err)
		}
	}
	if len(specs) == 0 {
		return fmt.Errorf("empty failpoint specs")
	}
	return nil
}

func validateWhenExpr(when WhenExpr) error {
	if when.First == 0 {
		if when.Last > 0 || when.Step > 0 {
			return fmt.Errorf("invalid when expression: first is unset but last(%d) or step(%d) is set",
				when.Last, when.Step)
		}
		return nil
	}

	if when.Last != 0 && when.Last < when.First {
		return fmt.Errorf("invalid when expression: first(%d) should be less than last(%d)",
			when.First, when.Last)
	}
	return nil
}
