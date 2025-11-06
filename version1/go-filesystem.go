package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
)

type Config struct {
	CheckSMART       bool
	CheckFSIntegrity bool
	Timeout          time.Duration
	MaxFileSize      int64
	ExcludeFS        []string
}

type DiskStats struct {
	Device      string  `json:"device"`
	Mountpoint  string  `json:"mountpoint"`
	TotalGB     float64 `json:"total_gb"`
	UsedGB      float64 `json:"used_gb"`
	UsedPercent float64 `json:"used_percent"`
	InodePercent float64 `json:"inode_percent"`
	Healthy     bool    `json:"healthy"`
}

type CheckResult struct {
	Timestamp time.Time   `json:"timestamp"`
	Duration  string      `json:"duration"`
	Checks    []string    `json:"checks_performed"`
	Errors    []string    `json:"errors"`
	DiskStats []DiskStats `json:"disk_stats,omitempty"`
}

var defaultConfig = Config{
	CheckSMART:       true,
	CheckFSIntegrity: true,
	Timeout:          30 * time.Second,
	MaxFileSize:      1024 * 1024,
	ExcludeFS:        []string{"tmpfs", "devtmpfs", "proc", "sysfs", "nfs", "cifs"},
}

func printHeader(title string) {
	fmt.Printf("%s┌──────────────────────────────────────────────┐%s\n", colorCyan, colorReset)
	fmt.Printf("%s│ %-44s │%s\n", colorCyan, title, colorReset)
	fmt.Printf("%s└──────────────────────────────────────────────┘%s\n", colorCyan, colorReset)
}

func printSummary(startTime time.Time, errors []string) {
	elapsed := time.Since(startTime).Round(time.Millisecond)
	printHeader("Summary")
	fmt.Printf("  Check completed at: %s\n", time.Now().Format("2006-01-02 15:04:05 MST"))
	fmt.Printf("  Duration: %s\n", elapsed)
	if len(errors) == 0 {
		fmt.Printf("  Status: %sAll checks completed successfully%s\n", colorCyan, colorReset)
	} else {
		fmt.Printf("  Status: %sIssues detected%s\n", colorRed, colorReset)
		for i, err := range errors {
			fmt.Printf("  Error %d: %s\n", i+1, err)
		}
	}
}

func safeGlob(pattern string) ([]string, error) {
	if strings.Contains(pattern, "..") || strings.Contains(pattern, "//") {
		return nil, fmt.Errorf("invalid pattern")
	}
	return filepath.Glob(pattern)
}

func isAllowedCommand(cmd string) bool {
	allowed := map[string]bool{
		"smartctl": true,
		"dmesg":    true,
		"fsck":     true,
		"blkid":    true,
	}
	return allowed[cmd]
}

func safeExecCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	if !isAllowedCommand(name) {
		return nil, fmt.Errorf("command not allowed: %s", name)
	}
	
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.CombinedOutput()
}

func shouldSkipFS(fstype string, config Config) bool {
	for _, exclude := range config.ExcludeFS {
		if strings.HasPrefix(fstype, exclude) {
			return true
		}
	}
	return false
}

func readProcMounts(config Config) ([]string, error) {
	file, err := os.Open("/proc/mounts")
	if err != nil {
		return nil, err
	}
	defer file.Close()
	
	var mounts []string
	scanner := bufio.NewScanner(io.LimitReader(file, config.MaxFileSize))
	for scanner.Scan() {
		mounts = append(mounts, scanner.Text())
	}
	return mounts, scanner.Err()
}

func withRecovery(name string, fn func() error, errors *[]string) {
	defer func() {
		if r := recover(); r != nil {
			*errors = append(*errors, fmt.Sprintf("%s: panic: %v", name, r))
		}
	}()
	
	if err := fn(); err != nil {
		*errors = append(*errors, fmt.Sprintf("%s: %v", name, err))
	}
}

func checkDiskUsage(ctx context.Context, config Config, errors *[]string) error {
	printHeader("Disk Usage")
	mounts, err := readProcMounts(config)
	if err != nil {
		return fmt.Errorf("failed to read /proc/mounts: %v", err)
	}

	var diskStats []DiskStats
	
	for _, line := range mounts {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		device, mountpoint, fstype := fields[0], fields[1], fields[2]
		if shouldSkipFS(fstype, config) {
			continue
		}

		var stat syscall.Statfs_t
		if err := syscall.Statfs(mountpoint, &stat); err != nil {
			*errors = append(*errors, fmt.Sprintf("Disk Usage: Statfs error on %s: %v", device, err))
			continue
		}

		blockSize := uint64(stat.Bsize)
		total := stat.Blocks * blockSize
		free := stat.Bfree * blockSize
		used := total - free

		var usedPercent float64
		if total > 0 {
			usedPercent = float64(used) / float64(total) * 100
		}

		totalInodes := stat.Files
		freeInodes := stat.Ffree
		usedInodes := totalInodes - freeInodes

		var inodePercent float64
		if totalInodes > 0 {
			inodePercent = float64(usedInodes) / float64(totalInodes) * 100
		}

		healthy := usedPercent <= 90 && inodePercent <= 90
		
		stats := DiskStats{
			Device:      device,
			Mountpoint:  mountpoint,
			TotalGB:     float64(total) / 1024 / 1024 / 1024,
			UsedGB:      float64(used) / 1024 / 1024 / 1024,
			UsedPercent: usedPercent,
			InodePercent: inodePercent,
			Healthy:     healthy,
		}
		diskStats = append(diskStats, stats)

		fmt.Printf("  %-20s\n", device)
		fmt.Printf("    Mountpoint: %-30s\n", mountpoint)
		fmt.Printf("    Size:       %-10.2f GB\n", stats.TotalGB)
		fmt.Printf("    Used:       %-10.2f GB\n", stats.UsedGB)
		fmt.Printf("    Available:  %-10.2f GB\n", float64(free)/1024/1024/1024)
		fmt.Printf("    Use%%:       %-10.1f%%\n", usedPercent)
		fmt.Printf("    Inodes:     %d/%d (%.1f%%)\n", usedInodes, totalInodes, inodePercent)

		if usedPercent > 90 {
			fmt.Printf("    %sWARNING: %s is over 90%% full!%s\n", colorYellow, device, colorReset)
		}
		if inodePercent > 90 {
			fmt.Printf("    %sWARNING: %s has over 90%% inode usage!%s\n", colorYellow, device, colorReset)
		}
		fmt.Println()
	}
	
	return nil
}

func checkMountedFilesystems(ctx context.Context, config Config, errors *[]string) error {
	printHeader("Mounted Filesystems")
	mounts, err := readProcMounts(config)
	if err != nil {
		return fmt.Errorf("failed to read /proc/mounts: %v", err)
	}

	for _, line := range mounts {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		fmt.Printf("  Device:       %-30s\n", fields[0])
		fmt.Printf("  Mountpoint:   %-30s\n", fields[1])
		fmt.Printf("  Type:         %-15s\n", fields[2])
		fmt.Printf("  Options:      %-30s\n", fields[3])
		fmt.Println()
	}
	return nil
}

func detectFilesystemType(ctx context.Context, device string) (string, error) {
	output, err := safeExecCommand(ctx, "blkid", "-o", "value", "-s", "TYPE", device)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func checkFilesystemIntegrity(ctx context.Context, config Config, errors *[]string) error {
	printHeader("Filesystem Integrity Check")
	if os.Geteuid() != 0 {
		fmt.Printf("  %sSkipped: Requires root privileges.%s\n", colorYellow, colorReset)
		return nil
	}

	mounts, err := readProcMounts(config)
	if err != nil {
		return fmt.Errorf("failed to read /proc/mounts: %v", err)
	}

	for _, line := range mounts {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		device, mountpoint, fstype := fields[0], fields[1], fields[2]
		if shouldSkipFS(fstype, config) {
			continue
		}

		fmt.Printf("  Checking %-20s (%s, type %s)\n", device, mountpoint, fstype)
		if mountpoint == "/" {
			fmt.Printf("    %sSkipped root filesystem check (running fsck on / is unsafe while mounted).%s\n", colorYellow, colorReset)
			continue
		}

		cmdCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		output, err := safeExecCommand(cmdCtx, "fsck", "-n", device)
		cancel()
		
		if err != nil {
			*errors = append(*errors, fmt.Sprintf("Filesystem Integrity: fsck error on %s: %v", device, err))
			fmt.Printf("    %sError: %v\nOutput: %s%s\n", colorRed, err, string(output), colorReset)
		} else {
			fmt.Printf("    %sClean: No issues found.%s\n", colorCyan, colorReset)
		}
	}
	return nil
}

func checkIOErrors(ctx context.Context, config Config, errors *[]string) error {
	printHeader("Recent I/O Errors")
	cmdCtx, cancel := context.WithTimeout(ctx, config.Timeout)
	defer cancel()
	
	output, err := safeExecCommand(cmdCtx, "dmesg", "--kernel", "--level=err,warn")
	if err != nil {
		return fmt.Errorf("failed to run dmesg: %v", err)
	}

	lines := strings.Split(string(output), "\n")
	if len(lines) == 0 || (len(lines) == 1 && lines[0] == "") {
		fmt.Printf("  %sNo I/O or filesystem errors found.%s\n", colorCyan, colorReset)
		return nil
	}

	for _, line := range lines {
		if line != "" {
			fmt.Printf("  %s%s%s\n", colorRed, line, colorReset)
		}
	}
	return nil
}

func checkOpenFiles(ctx context.Context, config Config, errors *[]string) error {
	printHeader("Open File Descriptors")

	file, err := os.Open("/proc/sys/fs/file-nr")
	if err != nil {
		return fmt.Errorf("failed to read /proc/sys/fs/file-nr: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(io.LimitReader(file, config.MaxFileSize))
	if scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 3 {
			used, _, max := fields[0], fields[1], fields[2]
			usedNum, err := strconv.Atoi(used)
			if err != nil {
				return fmt.Errorf("failed to parse used file descriptors: %v", err)
			}
			maxNum, err := strconv.Atoi(max)
			if err != nil {
				return fmt.Errorf("failed to parse max file descriptors: %v", err)
			}
			percent := float64(usedNum) / float64(maxNum) * 100
			fmt.Printf("  System-wide: %s/%s (%.1f%%)\n", used, max, percent)
			if percent > 90 {
				fmt.Printf("  %sWARNING: File descriptor usage is over 90%%!%s\n", colorYellow, colorReset)
			}
		}
	}
	return scanner.Err()
}

func checkSMARTStatus(ctx context.Context, config Config, errors *[]string) error {
	printHeader("SMART Health Status")
	cmd := exec.Command("smartctl", "--version")
	if err := cmd.Run(); err != nil {
		fmt.Printf("  %sSkipped: smartctl not found. Install 'smartmontools'.%s\n", colorYellow, colorReset)
		return nil
	}

	devices, err := safeGlob("/dev/sd[a-z]")
	if err != nil {
		return fmt.Errorf("invalid device pattern: %v", err)
	}
	
	nvmeDevices, err := safeGlob("/dev/nvme[0-9]n[0-9]")
	if err != nil {
		return fmt.Errorf("invalid NVMe pattern: %v", err)
	}
	devices = append(devices, nvmeDevices...)

	if len(devices) == 0 {
		fmt.Printf("  %sNo block devices found (/dev/sdX or /dev/nvmeXnY).%s\n", colorYellow, colorReset)
		return nil
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	
	for _, device := range devices {
		wg.Add(1)
		go func(dev string) {
			defer wg.Done()
			
			cmdCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			
			fmt.Printf("  Checking %-20s\n", dev)
			output, err := safeExecCommand(cmdCtx, "smartctl", "-H", dev)
			
			mu.Lock()
			defer mu.Unlock()
			
			if err != nil {
				if cmdCtx.Err() == context.DeadlineExceeded {
					*errors = append(*errors, fmt.Sprintf("SMART Status: timeout on %s", dev))
					fmt.Printf("    %sTimeout: Device check timed out.%s\n", colorRed, colorReset)
				} else {
					*errors = append(*errors, fmt.Sprintf("SMART Status: error on %s: %v", dev, err))
					fmt.Printf("    %sError: %v\nOutput: %s%s\n", colorRed, err, string(output), colorReset)
				}
			} else if strings.Contains(string(output), "PASSED") {
				fmt.Printf("    %sPASSED: SMART health OK.%s\n", colorCyan, colorReset)
			} else {
				fmt.Printf("    %sCheck: %s%s\n", colorYellow, string(output), colorReset)
			}
		}(device)
	}
	wg.Wait()
	return nil
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	
	go func() {
		<-ctx.Done()
		fmt.Printf("\n%sReceived interrupt, shutting down...%s\n", colorYellow, colorReset)
		os.Exit(1)
	}()
	
	startTime := time.Now()
	fmt.Printf("%sFilesystem Check Started at %s%s\n", colorCyan, startTime.Format("2006-01-02 15:04:05 MST"), colorReset)

	var errors []string
	config := defaultConfig
	
	withRecovery("Disk Usage", func() error {
		return checkDiskUsage(ctx, config, &errors)
	}, &errors)
	
	withRecovery("Mounted Filesystems", func() error {
		return checkMountedFilesystems(ctx, config, &errors)
	}, &errors)
	
	withRecovery("Filesystem Integrity", func() error {
		return checkFilesystemIntegrity(ctx, config, &errors)
	}, &errors)
	
	withRecovery("I/O Errors", func() error {
		return checkIOErrors(ctx, config, &errors)
	}, &errors)
	
	withRecovery("Open Files", func() error {
		return checkOpenFiles(ctx, config, &errors)
	}, &errors)
	
	withRecovery("SMART Status", func() error {
		return checkSMARTStatus(ctx, config, &errors)
	}, &errors)

	printSummary(startTime, errors)
	if len(errors) > 0 {
		os.Exit(1)
	}
}
