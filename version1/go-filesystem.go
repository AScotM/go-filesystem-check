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
	colorReset   = "\033[0m"
	colorRed     = "\033[38;5;203m"
	colorOrange  = "\033[38;5;215m"
	colorYellow  = "\033[38;5;227m"
	colorGreen   = "\033[38;5;120m"
	colorCyan    = "\033[38;5;87m"
	colorBlue    = "\033[38;5;75m"
	colorPurple  = "\033[38;5;141m"
	colorGray    = "\033[38;5;245m"
	colorDarkGray = "\033[38;5;238m"
)

type Config struct {
	CheckSMART       bool
	CheckFSIntegrity bool
	Timeout          time.Duration
	MaxFileSize      int64
	ExcludeFS        []string
	OutputJSON       bool
}

type DiskStats struct {
	Device       string  `json:"device"`
	Mountpoint   string  `json:"mountpoint"`
	Filesystem   string  `json:"filesystem"`
	TotalGB      float64 `json:"total_gb"`
	UsedGB       float64 `json:"used_gb"`
	AvailableGB  float64 `json:"available_gb"`
	UsedPercent  float64 `json:"used_percent"`
	InodePercent float64 `json:"inode_percent"`
	Healthy      bool    `json:"healthy"`
	Status       string  `json:"status"`
}

type CheckResult struct {
	Timestamp time.Time   `json:"timestamp"`
	Duration  string      `json:"duration"`
	Hostname  string      `json:"hostname"`
	Checks    []string    `json:"checks_performed"`
	Errors    []string    `json:"errors"`
	Warnings  []string    `json:"warnings"`
	DiskStats []DiskStats `json:"disk_stats"`
}

var defaultConfig = Config{
	CheckSMART:       true,
	CheckFSIntegrity: true,
	Timeout:          30 * time.Second,
	MaxFileSize:      1024 * 1024,
	ExcludeFS:        []string{"tmpfs", "devtmpfs", "proc", "sysfs", "nfs", "cifs"},
	OutputJSON:       false,
}

func printHeader(title string) {
	fmt.Printf("%s╔══════════════════════════════════════════════╗%s\n", colorPurple, colorReset)
	fmt.Printf("%s║ %-44s ║%s\n", colorPurple, title, colorReset)
	fmt.Printf("%s╚══════════════════════════════════════════════╝%s\n", colorPurple, colorReset)
}

func printStatus(status, message string) {
	var color string
	switch status {
	case "OK":
		color = colorGreen
	case "WARN":
		color = colorYellow
	case "ERROR":
		color = colorRed
	case "INFO":
		color = colorCyan
	default:
		color = colorGray
	}
	fmt.Printf("%s[%-5s]%s %s\n", color, status, colorReset, message)
}

func printSummary(result CheckResult) {
	printHeader("SYSTEM CHECK SUMMARY")
	fmt.Printf("%s  Hostname:    %s%s\n", colorBlue, result.Hostname, colorReset)
	fmt.Printf("%s  Completed:   %s%s\n", colorBlue, result.Timestamp.Format("2006-01-02 15:04:05 MST"), colorReset)
	fmt.Printf("%s  Duration:    %s%s\n", colorBlue, result.Duration, colorReset)
	fmt.Printf("%s  Checks:      %d performed%s\n", colorBlue, len(result.Checks), colorReset)
	
	if len(result.Errors) == 0 && len(result.Warnings) == 0 {
		printStatus("OK", "All systems operational")
	} else {
		if len(result.Warnings) > 0 {
			fmt.Printf("\n%s  Warnings:%s\n", colorYellow, colorReset)
			for i, warn := range result.Warnings {
				fmt.Printf("    %d. %s\n", i+1, warn)
			}
		}
		if len(result.Errors) > 0 {
			fmt.Printf("\n%s  Errors:%s\n", colorRed, colorReset)
			for i, err := range result.Errors {
				fmt.Printf("    %d. %s\n", i+1, err)
			}
		}
	}
}

func safeGlob(pattern string) ([]string, error) {
	if strings.ContainsAny(pattern, "..*/") {
		return nil, fmt.Errorf("invalid pattern: %s", pattern)
	}
	return filepath.Glob(pattern)
}

func isAllowedCommand(cmd string) bool {
	allowed := map[string]bool{
		"smartctl": true,
		"dmesg":    true,
		"fsck":     true,
		"blkid":    true,
		"lsblk":    true,
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

func withRecovery(name string, fn func() ([]string, []string)) ([]string, []string) {
	var errors, warnings []string
	defer func() {
		if r := recover(); r != nil {
			errors = append(errors, fmt.Sprintf("%s: panic: %v", name, r))
		}
	}()
	
	newErrors, newWarnings := fn()
	errors = append(errors, newErrors...)
	warnings = append(warnings, newWarnings...)
	return errors, warnings
}

func checkDiskUsage(ctx context.Context, config Config) ([]string, []string) {
	var errors, warnings []string
	
	if !config.OutputJSON {
		printHeader("DISK USAGE ANALYSIS")
	}

	mounts, err := readProcMounts(config)
	if err != nil {
		return []string{fmt.Sprintf("Disk Usage: %v", err)}, warnings
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

		var stat syscall.Statfs_t
		if err := syscall.Statfs(mountpoint, &stat); err != nil {
			errors = append(errors, fmt.Sprintf("Disk Usage: Statfs error on %s: %v", device, err))
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

		status := "OK"
		if usedPercent > 95 || inodePercent > 95 {
			status = "ERROR"
			errors = append(errors, fmt.Sprintf("Disk Usage: %s is critically full (%.1f%%)", device, usedPercent))
		} else if usedPercent > 85 || inodePercent > 85 {
			status = "WARN"
			warnings = append(warnings, fmt.Sprintf("Disk Usage: %s is nearly full (%.1f%%)", device, usedPercent))
		}

		if !config.OutputJSON {
			fmt.Printf("\n%s%s%s\n", colorCyan, device, colorReset)
			fmt.Printf("  %sMountpoint:%s %s\n", colorGray, colorReset, mountpoint)
			fmt.Printf("  %sFilesystem:%s %s\n", colorGray, colorReset, fstype)
			fmt.Printf("  %sSize:      %s%10.2f GB%s\n", colorGray, colorBlue, float64(total)/1073741824, colorReset)
			fmt.Printf("  %sUsed:      %s%10.2f GB%s %s(%.1f%%)%s\n", colorGray, colorOrange, float64(used)/1073741824, colorReset, colorGray, usedPercent, colorReset)
			fmt.Printf("  %sAvailable: %s%10.2f GB%s\n", colorGray, colorGreen, float64(free)/1073741824, colorReset)
			fmt.Printf("  %sInodes:    %s%10d/%d%s %s(%.1f%%)%s\n", colorGray, colorPurple, usedInodes, totalInodes, colorReset, colorGray, inodePercent, colorReset)
			
			switch status {
			case "OK":
				printStatus("OK", "Disk space adequate")
			case "WARN":
				printStatus("WARN", "Disk space low")
			case "ERROR":
				printStatus("ERROR", "Disk space critical")
			}
		}
	}
	
	return errors, warnings
}

func checkMountedFilesystems(ctx context.Context, config Config) ([]string, []string) {
	var errors, warnings []string
	
	if !config.OutputJSON {
		printHeader("MOUNTED FILESYSTEMS")
	}

	mounts, err := readProcMounts(config)
	if err != nil {
		return []string{fmt.Sprintf("Mounted Filesystems: %v", err)}, warnings
	}

	for _, line := range mounts {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		
		if !config.OutputJSON {
			fmt.Printf("\n%s%s%s\n", colorCyan, fields[0], colorReset)
			fmt.Printf("  %sMountpoint:%s %s\n", colorGray, colorReset, fields[1])
			fmt.Printf("  %sType:      %s %s\n", colorGray, colorReset, fields[2])
			fmt.Printf("  %sOptions:   %s %s\n", colorGray, colorReset, fields[3])
		}
	}
	return errors, warnings
}

func checkFilesystemIntegrity(ctx context.Context, config Config) ([]string, []string) {
	var errors, warnings []string
	
	if !config.OutputJSON {
		printHeader("FILESYSTEM INTEGRITY")
	}

	if os.Geteuid() != 0 {
		warnings = append(warnings, "Filesystem Integrity: Requires root privileges")
		if !config.OutputJSON {
			printStatus("WARN", "Skipped - requires root privileges")
		}
		return errors, warnings
	}

	mounts, err := readProcMounts(config)
	if err != nil {
		return []string{fmt.Sprintf("Filesystem Integrity: %v", err)}, warnings
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

		if !config.OutputJSON {
			fmt.Printf("\n%sChecking:%s %s\n", colorGray, colorReset, device)
		}

		if mountpoint == "/" {
			warnings = append(warnings, fmt.Sprintf("Filesystem Integrity: Skipped root filesystem %s", device))
			if !config.OutputJSON {
				printStatus("WARN", "Skipped root filesystem (unsafe while mounted)")
			}
			continue
		}

		cmdCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		_, err := safeExecCommand(cmdCtx, "fsck", "-n", device)
		cancel()
		
		if err != nil {
			errors = append(errors, fmt.Sprintf("Filesystem Integrity: %s: %v", device, err))
			if !config.OutputJSON {
				printStatus("ERROR", fmt.Sprintf("Check failed: %v", err))
			}
		} else {
			if !config.OutputJSON {
				printStatus("OK", "No filesystem errors detected")
			}
		}
	}
	return errors, warnings
}

func checkIOErrors(ctx context.Context, config Config) ([]string, []string) {
	var errors, warnings []string
	
	if !config.OutputJSON {
		printHeader("I/O ERROR SCAN")
	}

	cmdCtx, cancel := context.WithTimeout(ctx, config.Timeout)
	defer cancel()
	
	output, err := safeExecCommand(cmdCtx, "dmesg", "--kernel", "--level=err,warn")
	if err != nil {
		return []string{fmt.Sprintf("I/O Errors: %v", err)}, warnings
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) == 0 || (len(lines) == 1 && lines[0] == "") {
		if !config.OutputJSON {
			printStatus("OK", "No recent I/O errors found")
		}
		return errors, warnings
	}

	errorCount := len(lines)
	if errorCount > 10 {
		lines = lines[:10]
		warnings = append(warnings, fmt.Sprintf("I/O Errors: Showing first 10 of %d errors", errorCount))
	}

	for _, line := range lines {
		errors = append(errors, fmt.Sprintf("I/O Error: %s", line))
		if !config.OutputJSON {
			fmt.Printf("%s%s%s\n", colorRed, line, colorReset)
		}
	}
	
	if !config.OutputJSON {
		printStatus("ERROR", fmt.Sprintf("Found %d I/O errors", errorCount))
	}
	return errors, warnings
}

func checkOpenFiles(ctx context.Context, config Config) ([]string, []string) {
	var errors, warnings []string
	
	if !config.OutputJSON {
		printHeader("FILE DESCRIPTOR USAGE")
	}

	file, err := os.Open("/proc/sys/fs/file-nr")
	if err != nil {
		return []string{fmt.Sprintf("Open Files: %v", err)}, warnings
	}
	defer file.Close()

	scanner := bufio.NewScanner(io.LimitReader(file, config.MaxFileSize))
	if scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 3 {
			used, _, max := fields[0], fields[1], fields[2]
			usedNum, _ := strconv.Atoi(used)
			maxNum, _ := strconv.Atoi(max)
			
			if maxNum > 0 {
				percent := float64(usedNum) / float64(maxNum) * 100
				
				if !config.OutputJSON {
					fmt.Printf("%sUsed:%s  %s%d%s\n", colorGray, colorReset, colorBlue, usedNum, colorReset)
					fmt.Printf("%sMax:%s   %s%d%s\n", colorGray, colorReset, colorGray, maxNum, colorReset)
					fmt.Printf("%sUsage:%s %s%.1f%%%s\n", colorGray, colorReset, colorCyan, percent, colorReset)
				}
				
				if percent > 95 {
					errors = append(errors, fmt.Sprintf("Open Files: Critical usage at %.1f%%", percent))
					if !config.OutputJSON {
						printStatus("ERROR", "File descriptor usage critical")
					}
				} else if percent > 85 {
					warnings = append(warnings, fmt.Sprintf("Open Files: High usage at %.1f%%", percent))
					if !config.OutputJSON {
						printStatus("WARN", "File descriptor usage high")
					}
				} else {
					if !config.OutputJSON {
						printStatus("OK", "File descriptor usage normal")
					}
				}
			}
		}
	}
	
	if err := scanner.Err(); err != nil {
		errors = append(errors, fmt.Sprintf("Open Files: %v", err))
	}
	return errors, warnings
}

func checkSMARTStatus(ctx context.Context, config Config) ([]string, []string) {
	var errors, warnings []string
	
	if !config.OutputJSON {
		printHeader("SMART HEALTH STATUS")
	}

	if _, err := exec.LookPath("smartctl"); err != nil {
		warnings = append(warnings, "SMART Status: smartctl not found")
		if !config.OutputJSON {
			printStatus("WARN", "smartctl not installed")
		}
		return errors, warnings
	}

	devices, _ := safeGlob("/dev/sd[a-z]")
	nvmeDevices, _ := safeGlob("/dev/nvme[0-9]n[0-9]")
	devices = append(devices, nvmeDevices...)

	if len(devices) == 0 {
		warnings = append(warnings, "SMART Status: No storage devices detected")
		if !config.OutputJSON {
			printStatus("WARN", "No storage devices found")
		}
		return errors, warnings
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	
	for _, device := range devices {
		wg.Add(1)
		go func(dev string) {
			defer wg.Done()
			
			cmdCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()
			
			output, err := safeExecCommand(cmdCtx, "smartctl", "-H", dev)
			
			mu.Lock()
			defer mu.Unlock()
			
			if err != nil {
				if cmdCtx.Err() == context.DeadlineExceeded {
					errors = append(errors, fmt.Sprintf("SMART Status: %s timeout", dev))
				} else {
					warnings = append(warnings, fmt.Sprintf("SMART Status: %s: %v", dev, err))
				}
			} else if strings.Contains(string(output), "PASSED") || strings.Contains(string(output), "OK") {
				if !config.OutputJSON {
					fmt.Printf("%s%s%s ", colorGreen, dev, colorReset)
					printStatus("OK", "Healthy")
				}
			} else {
				errors = append(errors, fmt.Sprintf("SMART Status: %s may be failing", dev))
				if !config.OutputJSON {
					fmt.Printf("%s%s%s ", colorRed, dev, colorReset)
					printStatus("ERROR", "Check advised")
				}
			}
		}(device)
	}
	wg.Wait()
	return errors, warnings
}

func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	
	go func() {
		<-ctx.Done()
		fmt.Printf("\n%s✗ Monitoring interrupted%s\n", colorRed, colorReset)
		os.Exit(1)
	}()
	
	startTime := time.Now()
	hostname := getHostname()
	
	if !defaultConfig.OutputJSON {
		fmt.Printf("%s🖥️  SYSTEM STORAGE ANALYSIS%s\n", colorPurple, colorReset)
		fmt.Printf("%sHost: %s%s\n\n", colorGray, hostname, colorReset)
	}

	var allErrors, allWarnings []string
	checks := []string{"Disk Usage", "Mounted Filesystems", "Filesystem Integrity", "I/O Errors", "Open Files", "SMART Status"}
	
	diskErrors, diskWarnings := withRecovery("Disk Usage", func() ([]string, []string) {
		return checkDiskUsage(ctx, defaultConfig)
	})
	allErrors = append(allErrors, diskErrors...)
	allWarnings = append(allWarnings, diskWarnings...)
	
	mountErrors, mountWarnings := withRecovery("Mounted Filesystems", func() ([]string, []string) {
		return checkMountedFilesystems(ctx, defaultConfig)
	})
	allErrors = append(allErrors, mountErrors...)
	allWarnings = append(allWarnings, mountWarnings...)
	
	fsErrors, fsWarnings := withRecovery("Filesystem Integrity", func() ([]string, []string) {
		return checkFilesystemIntegrity(ctx, defaultConfig)
	})
	allErrors = append(allErrors, fsErrors...)
	allWarnings = append(allWarnings, fsWarnings...)
	
	ioErrors, ioWarnings := withRecovery("I/O Errors", func() ([]string, []string) {
		return checkIOErrors(ctx, defaultConfig)
	})
	allErrors = append(allErrors, ioErrors...)
	allWarnings = append(allWarnings, ioWarnings...)
	
	fileErrors, fileWarnings := withRecovery("Open Files", func() ([]string, []string) {
		return checkOpenFiles(ctx, defaultConfig)
	})
	allErrors = append(allErrors, fileErrors...)
	allWarnings = append(allWarnings, fileWarnings...)
	
	smartErrors, smartWarnings := withRecovery("SMART Status", func() ([]string, []string) {
		return checkSMARTStatus(ctx, defaultConfig)
	})
	allErrors = append(allErrors, smartErrors...)
	allWarnings = append(allWarnings, smartWarnings...)

	result := CheckResult{
		Timestamp: time.Now(),
		Duration:  time.Since(startTime).Round(time.Millisecond).String(),
		Hostname:  hostname,
		Checks:    checks,
		Errors:    allErrors,
		Warnings:  allWarnings,
	}

	if !defaultConfig.OutputJSON {
		fmt.Println()
		printSummary(result)
	}

	if len(allErrors) > 0 {
		os.Exit(1)
	}
}
