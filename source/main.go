package main

import (
	"bufio"
	"context"
	"encoding/json"
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
	colorReset    = "\033[0m"
	colorRed      = "\033[38;5;203m"
	colorOrange   = "\033[38;5;215m"
	colorYellow   = "\033[38;5;227m"
	colorGreen    = "\033[38;5;120m"
	colorCyan     = "\033[38;5;87m"
	colorBlue     = "\033[38;5;75m"
	colorPurple   = "\033[38;5;141m"
	colorGray     = "\033[38;5;245m"
	colorDarkGray = "\033[38;5;238m"
)

type Config struct {
	CheckSMART       bool
	CheckFSIntegrity bool
	CheckDiskTemp    bool
	Timeout          time.Duration
	MaxFileSize      int64
	ExcludeFS        []string
	OutputJSON       bool
	DiskUsageWarn    float64
	DiskUsageCrit    float64
	InodeUsageWarn   float64
	InodeUsageCrit   float64
	FileDescWarn     float64
	FileDescCrit     float64
	MaxTempWarn      int
	MaxTempCrit      int
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
	Temperature  int     `json:"temperature,omitempty"`
}

type CheckResult struct {
	Timestamp time.Time   `json:"timestamp"`
	Duration  string      `json:"duration"`
	Hostname  string      `json:"hostname"`
	Checks    []string    `json:"checks_performed"`
	Errors    []string    `json:"errors"`
	Warnings  []string    `json:"warnings"`
	DiskStats []DiskStats `json:"disk_stats"`
	Summary   SummaryStats `json:"summary"`
}

type SummaryStats struct {
	TotalDisks   int     `json:"total_disks"`
	HealthyDisks int     `json:"healthy_disks"`
	TotalFS      int     `json:"total_filesystems"`
	HealthyFS    int     `json:"healthy_filesystems"`
	TotalChecks  int     `json:"total_checks"`
	PassedChecks int     `json:"passed_checks"`
	AvgDiskUsage float64 `json:"avg_disk_usage"`
	MaxTemp      int     `json:"max_temperature"`
	FailedChecks int     `json:"failed_checks"`
}

var defaultConfig = Config{
	CheckSMART:       true,
	CheckFSIntegrity: true,
	CheckDiskTemp:    true,
	Timeout:          30 * time.Second,
	MaxFileSize:      1024 * 1024,
	ExcludeFS:        []string{"tmpfs", "devtmpfs", "proc", "sysfs", "nfs", "cifs", "overlay", "aufs"},
	OutputJSON:       false,
	DiskUsageWarn:    85.0,
	DiskUsageCrit:    95.0,
	InodeUsageWarn:   85.0,
	InodeUsageCrit:   95.0,
	FileDescWarn:     85.0,
	FileDescCrit:     95.0,
	MaxTempWarn:      50,
	MaxTempCrit:      60,
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
	fmt.Printf("%s  Checks:      %d/%d passed%s\n", colorBlue, result.Summary.PassedChecks, result.Summary.TotalChecks, colorReset)
	fmt.Printf("%s  Disks:       %d/%d healthy%s\n", colorBlue, result.Summary.HealthyDisks, result.Summary.TotalDisks, colorReset)
	fmt.Printf("%s  Filesystems: %d/%d healthy%s\n", colorBlue, result.Summary.HealthyFS, result.Summary.TotalFS, colorReset)
	fmt.Printf("%s  Avg Usage:   %.1f%%%s\n", colorBlue, result.Summary.AvgDiskUsage, colorReset)
	
	if result.Summary.MaxTemp > 0 {
		tempColor := colorGreen
		if result.Summary.MaxTemp > defaultConfig.MaxTempCrit {
			tempColor = colorRed
		} else if result.Summary.MaxTemp > defaultConfig.MaxTempWarn {
			tempColor = colorYellow
		}
		fmt.Printf("%s  Max Temp:    %s%d°C%s\n", colorBlue, tempColor, result.Summary.MaxTemp, colorReset)
	}

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

func printJSON(result CheckResult) {
	jsonData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "%sError generating JSON: %v%s\n", colorRed, err, colorReset)
		os.Exit(1)
	}
	fmt.Println(string(jsonData))
}

func safeGlob(pattern string) ([]string, error) {
	baseDir := filepath.Dir(pattern)
	cleanBaseDir := filepath.Clean(baseDir)
	
	allowedDirs := []string{"/dev", "/proc", "/sys"}
	allowed := false
	for _, dir := range allowedDirs {
		if strings.HasPrefix(cleanBaseDir, dir) {
			allowed = true
			break
		}
	}
	
	if !allowed {
		return nil, fmt.Errorf("access denied to directory: %s", cleanBaseDir)
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
	
	path, err := exec.LookPath(name)
	if err != nil {
		return nil, fmt.Errorf("command not found: %s", name)
	}
	
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin:/sbin:/usr/sbin"}
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

func getStorageDevices() ([]string, error) {
	patterns := []string{
		"/dev/sd[a-z]",
		"/dev/sd[a-z][a-z]",
		"/dev/nvme[0-9]n[0-9]",
		"/dev/mmcblk[0-9]",
		"/dev/vd[a-z]",
	}
	
	var devices []string
	for _, pattern := range patterns {
		matches, err := safeGlob(pattern)
		if err != nil {
			continue
		}
		devices = append(devices, matches...)
	}
	
	if len(devices) == 0 {
		return nil, fmt.Errorf("no storage devices found")
	}
	
	return devices, nil
}

func withRecovery(name string, fn func() ([]string, []string, []DiskStats)) ([]string, []string, []DiskStats) {
	var errors, warnings []string
	var diskStats []DiskStats
	defer func() {
		if r := recover(); r != nil {
			errors = append(errors, fmt.Sprintf("%s: panic: %v", name, r))
		}
	}()
	
	newErrors, newWarnings, newDiskStats := fn()
	errors = append(errors, newErrors...)
	warnings = append(warnings, newWarnings...)
	diskStats = append(diskStats, newDiskStats...)
	return errors, warnings, diskStats
}

func showProgress(current, total int, message string) {
	if total == 0 {
		return
	}
	
	width := 40
	percent := float64(current) / float64(total) * 100
	filled := int(float64(width) * percent / 100)
	
	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	fmt.Printf("\r%s [%s] %.1f%% %s", colorCyan, bar, percent, message)
	
	if current == total {
		fmt.Printf("\n")
	}
}

func checkDiskUsage(ctx context.Context, config Config) ([]string, []string, []DiskStats) {
	var errors, warnings []string
	var allDiskStats []DiskStats
	
	if !config.OutputJSON {
		printHeader("DISK USAGE ANALYSIS")
	}

	mounts, err := readProcMounts(config)
	if err != nil {
		return []string{fmt.Sprintf("Disk Usage: %v", err)}, warnings, allDiskStats
	}

	validMounts := 0
	totalUsage := 0.0
	
	for i, line := range mounts {
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
			totalUsage += usedPercent
			validMounts++
		}

		totalInodes := stat.Files
		freeInodes := stat.Ffree
		usedInodes := totalInodes - freeInodes

		var inodePercent float64
		if totalInodes > 0 {
			inodePercent = float64(usedInodes) / float64(totalInodes) * 100
		}

		healthy := true
		status := "OK"
		if usedPercent > config.DiskUsageCrit || inodePercent > config.InodeUsageCrit {
			status = "ERROR"
			healthy = false
			errors = append(errors, fmt.Sprintf("Disk Usage: %s is critically full (%.1f%%)", device, usedPercent))
		} else if usedPercent > config.DiskUsageWarn || inodePercent > config.InodeUsageWarn {
			status = "WARN"
			healthy = false
			warnings = append(warnings, fmt.Sprintf("Disk Usage: %s is nearly full (%.1f%%)", device, usedPercent))
		}

		diskStat := DiskStats{
			Device:       device,
			Mountpoint:   mountpoint,
			Filesystem:   fstype,
			TotalGB:      float64(total) / 1073741824,
			UsedGB:       float64(used) / 1073741824,
			AvailableGB:  float64(free) / 1073741824,
			UsedPercent:  usedPercent,
			InodePercent: inodePercent,
			Healthy:      healthy,
			Status:       status,
		}
		allDiskStats = append(allDiskStats, diskStat)

		if !config.OutputJSON {
			showProgress(i+1, len(mounts), fmt.Sprintf("Checking %s", device))
			if i == len(mounts)-1 || (i+1)%5 == 0 {
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
	}
	
	if validMounts > 0 && !config.OutputJSON {
		fmt.Printf("\n%sAverage disk usage: %.1f%%%s\n", colorBlue, totalUsage/float64(validMounts), colorReset)
	}
	
	return errors, warnings, allDiskStats
}

func checkMountedFilesystems(ctx context.Context, config Config) ([]string, []string, []DiskStats) {
	var errors, warnings []string
	
	if !config.OutputJSON {
		printHeader("MOUNTED FILESYSTEMS")
	}

	mounts, err := readProcMounts(config)
	if err != nil {
		return []string{fmt.Sprintf("Mounted Filesystems: %v", err)}, warnings, nil
	}

	fsCount := 0
	for i, line := range mounts {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		
		if !config.OutputJSON {
			showProgress(i+1, len(mounts), "Listing filesystems")
			if i == len(mounts)-1 || (i+1)%10 == 0 {
				fmt.Printf("\n%s%s%s\n", colorCyan, fields[0], colorReset)
				fmt.Printf("  %sMountpoint:%s %s\n", colorGray, colorReset, fields[1])
				fmt.Printf("  %sType:      %s %s\n", colorGray, colorReset, fields[2])
				fmt.Printf("  %sOptions:   %s %s\n", colorGray, colorReset, fields[3])
			}
		}
		fsCount++
	}
	
	if !config.OutputJSON {
		fmt.Printf("\n%sTotal filesystems: %d%s\n", colorBlue, fsCount, colorReset)
	}
	
	return errors, warnings, nil
}

func checkFilesystemIntegrity(ctx context.Context, config Config) ([]string, []string, []DiskStats) {
	var errors, warnings []string
	
	if !config.OutputJSON {
		printHeader("FILESYSTEM INTEGRITY")
	}

	if os.Geteuid() != 0 {
		warnings = append(warnings, "Filesystem Integrity: Requires root privileges")
		if !config.OutputJSON {
			printStatus("INFO", "Filesystem integrity checks require root privileges")
		}
		return errors, warnings, nil
	}

	mounts, err := readProcMounts(config)
	if err != nil {
		return []string{fmt.Sprintf("Filesystem Integrity: %v", err)}, warnings, nil
	}

	checked := 0
	for i, line := range mounts {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		device, fstype := fields[0], fields[2]
		if shouldSkipFS(fstype, config) {
			continue
		}

		if !config.OutputJSON {
			showProgress(i+1, len(mounts), fmt.Sprintf("Checking %s", device))
		}

		cmdCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		output, err := safeExecCommand(cmdCtx, "fsck", "-n", device)
		cancel()
		
		if err != nil {
			if strings.Contains(string(output), "filesystem mounted") {
				warnings = append(warnings, fmt.Sprintf("Filesystem Integrity: %s is mounted", device))
				if !config.OutputJSON && i == len(mounts)-1 {
					printStatus("INFO", "Filesystem is mounted (check with -n is safe)")
				}
			} else {
				errors = append(errors, fmt.Sprintf("Filesystem Integrity: %s: %v", device, err))
				if !config.OutputJSON && i == len(mounts)-1 {
					printStatus("ERROR", fmt.Sprintf("Check failed: %v", err))
				}
			}
		} else {
			checked++
			if !config.OutputJSON && i == len(mounts)-1 {
				printStatus("OK", "No filesystem errors detected")
			}
		}
	}
	
	if !config.OutputJSON && checked > 0 {
		fmt.Printf("\n%sFilesystems checked: %d%s\n", colorBlue, checked, colorReset)
	}
	
	return errors, warnings, nil
}

func checkIOErrors(ctx context.Context, config Config) ([]string, []string, []DiskStats) {
	var errors, warnings []string
	
	if !config.OutputJSON {
		printHeader("I/O ERROR SCAN")
	}

	cmdCtx, cancel := context.WithTimeout(ctx, config.Timeout)
	defer cancel()
	
	output, err := safeExecCommand(cmdCtx, "dmesg", "--kernel", "--level=err,warn")
	if err != nil {
		return []string{fmt.Sprintf("I/O Errors: %v", err)}, warnings, nil
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) == 0 || (len(lines) == 1 && lines[0] == "") {
		if !config.OutputJSON {
			printStatus("OK", "No recent I/O errors found")
		}
		return errors, warnings, nil
	}

	ioErrors := 0
	for _, line := range lines {
		if strings.Contains(line, "I/O error") || strings.Contains(line, "device error") ||
			strings.Contains(line, "timeout") || strings.Contains(line, "reset") {
			ioErrors++
			errors = append(errors, fmt.Sprintf("I/O Error: %s", line))
		}
	}

	if !config.OutputJSON {
		if ioErrors > 0 {
			printStatus("ERROR", fmt.Sprintf("Found %d I/O related errors", ioErrors))
			for i := 0; i < min(5, ioErrors); i++ {
				fmt.Printf("%s%s%s\n", colorRed, errors[i], colorReset)
			}
			if ioErrors > 5 {
				fmt.Printf("%s... and %d more errors%s\n", colorGray, ioErrors-5, colorReset)
			}
		} else {
			printStatus("OK", "No storage-related I/O errors found")
		}
	}
	
	return errors, warnings, nil
}

func checkOpenFiles(ctx context.Context, config Config) ([]string, []string, []DiskStats) {
	var errors, warnings []string
	
	if !config.OutputJSON {
		printHeader("FILE DESCRIPTOR USAGE")
	}

	file, err := os.Open("/proc/sys/fs/file-nr")
	if err != nil {
		return []string{fmt.Sprintf("Open Files: %v", err)}, warnings, nil
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
				
				if percent > config.FileDescCrit {
					errors = append(errors, fmt.Sprintf("Open Files: Critical usage at %.1f%%", percent))
					if !config.OutputJSON {
						printStatus("ERROR", "File descriptor usage critical")
					}
				} else if percent > config.FileDescWarn {
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
	return errors, warnings, nil
}

func checkSMARTStatus(ctx context.Context, config Config) ([]string, []string, []DiskStats) {
	var errors, warnings []string
	
	if !config.OutputJSON {
		printHeader("SMART HEALTH STATUS")
	}

	path, err := exec.LookPath("smartctl")
	if err != nil {
		if !config.OutputJSON {
			printStatus("INFO", "smartctl not installed - install smartmontools package")
		}
		return errors, warnings, nil
	}
	
	testCmd := exec.CommandContext(ctx, path, "--scan")
	if err := testCmd.Run(); err != nil {
		warnings = append(warnings, "SMART Status: Requires root privileges or disk access")
		if !config.OutputJSON {
			printStatus("WARN", "Insufficient permissions for smartctl")
		}
		return errors, warnings, nil
	}

	devices, err := getStorageDevices()
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("SMART Status: %v", err))
		if !config.OutputJSON {
			printStatus("WARN", "No storage devices found")
		}
		return errors, warnings, nil
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, 3)
	healthyDisks := 0
	maxTemp := 0
	
	for i, device := range devices {
		wg.Add(1)
		go func(dev string, idx int) {
			defer wg.Done()
			
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			
			cmdCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
			healthOutput, healthErr := safeExecCommand(cmdCtx, path, "-H", dev)
			cancel()
			
			temp := 0
			if config.CheckDiskTemp {
				tempCtx, tempCancel := context.WithTimeout(ctx, 10*time.Second)
				tempOutput, _ := safeExecCommand(tempCtx, path, "-A", dev)
				tempCancel()
				
				lines := strings.Split(string(tempOutput), "\n")
				for _, line := range lines {
					if strings.Contains(line, "Temperature") || strings.Contains(line, "Airflow_Temp") {
						fields := strings.Fields(line)
						if len(fields) >= 10 {
							if t, err := strconv.Atoi(fields[9]); err == nil {
								temp = t
								break
							}
						}
					}
				}
			}
			
			mu.Lock()
			defer mu.Unlock()
			
			if !config.OutputJSON {
				showProgress(idx+1, len(devices), fmt.Sprintf("Checking %s", dev))
			}
			
			if healthErr != nil {
				if ctx.Err() == context.DeadlineExceeded {
					errors = append(errors, fmt.Sprintf("SMART Status: %s timeout", dev))
				} else {
					warnings = append(warnings, fmt.Sprintf("SMART Status: %s: %v", dev, healthErr))
				}
			} else if strings.Contains(string(healthOutput), "PASSED") || strings.Contains(string(healthOutput), "OK") {
				healthyDisks++
				if temp > maxTemp {
					maxTemp = temp
				}
				
				if !config.OutputJSON && idx == len(devices)-1 {
					statusMsg := "Healthy"
					if temp > 0 {
						statusMsg = fmt.Sprintf("Healthy (%d°C)", temp)
					}
					fmt.Printf("\n%s%s%s ", colorGreen, dev, colorReset)
					printStatus("OK", statusMsg)
				}
			} else {
				errors = append(errors, fmt.Sprintf("SMART Status: %s may be failing", dev))
				if !config.OutputJSON && idx == len(devices)-1 {
					fmt.Printf("\n%s%s%s ", colorRed, dev, colorReset)
					printStatus("ERROR", "Check advised")
				}
			}
		}(device, i)
	}
	wg.Wait()
	
	if !config.OutputJSON {
		fmt.Printf("\n%sSMART disks checked: %d/%d healthy%s\n", colorBlue, healthyDisks, len(devices), colorReset)
		if maxTemp > 0 {
			tempColor := colorGreen
			if maxTemp > config.MaxTempCrit {
				tempColor = colorRed
			} else if maxTemp > config.MaxTempWarn {
				tempColor = colorYellow
			}
			fmt.Printf("%sMaximum temperature: %s%d°C%s\n", colorBlue, tempColor, maxTemp, colorReset)
		}
	}
	
	return errors, warnings, nil
}

func checkDiskTemperature(ctx context.Context, config Config) ([]string, []string, []DiskStats) {
	var errors, warnings []string
	
	if !config.CheckDiskTemp {
		return errors, warnings, nil
	}
	
	if !config.OutputJSON {
		printHeader("DISK TEMPERATURE")
	}

	devices, err := getStorageDevices()
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("Disk Temperature: %v", err))
		return errors, warnings, nil
	}

	path, err := exec.LookPath("smartctl")
	if err != nil {
		if !config.OutputJSON {
			printStatus("INFO", "smartctl not available for temperature checks")
		}
		return errors, warnings, nil
	}

	maxTemp := 0
	hotDisks := 0
	
	for i, device := range devices {
		cmdCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		output, err := safeExecCommand(cmdCtx, path, "-A", device)
		cancel()
		
		if err != nil {
			continue
		}
		
		if !config.OutputJSON {
			showProgress(i+1, len(devices), fmt.Sprintf("Checking %s", device))
		}
		
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "Temperature") || strings.Contains(line, "Airflow_Temp") {
				fields := strings.Fields(line)
				if len(fields) >= 10 {
					if temp, err := strconv.Atoi(fields[9]); err == nil {
						if temp > maxTemp {
							maxTemp = temp
						}
						
						if temp > config.MaxTempCrit {
							errors = append(errors, fmt.Sprintf("Disk Temperature: %s at %d°C (CRITICAL)", device, temp))
							hotDisks++
						} else if temp > config.MaxTempWarn {
							warnings = append(warnings, fmt.Sprintf("Disk Temperature: %s at %d°C (WARNING)", device, temp))
							hotDisks++
						}
						
						if !config.OutputJSON && i == len(devices)-1 {
							tempColor := colorGreen
							status := "OK"
							if temp > config.MaxTempCrit {
								tempColor = colorRed
								status = "ERROR"
							} else if temp > config.MaxTempWarn {
								tempColor = colorYellow
								status = "WARN"
							}
							fmt.Printf("\n%s%s%s: %s%d°C%s - %s\n", colorCyan, device, colorReset, tempColor, temp, colorReset, status)
						}
						break
					}
				}
			}
		}
	}
	
	if !config.OutputJSON {
		if maxTemp > 0 {
			fmt.Printf("\n%sMaximum temperature: %d°C%s\n", colorBlue, maxTemp, colorReset)
			if hotDisks > 0 {
				fmt.Printf("%sHot disks detected: %d%s\n", colorYellow, hotDisks, colorReset)
			} else {
				printStatus("OK", "All disks within temperature limits")
			}
		} else {
			printStatus("INFO", "Temperature data not available")
		}
	}
	
	return errors, warnings, nil
}

func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}

func calculateSummary(result CheckResult, totalChecks int) SummaryStats {
	summary := SummaryStats{
		TotalChecks:  totalChecks,
		FailedChecks: len(result.Errors),
	}
	
	summary.PassedChecks = totalChecks - summary.FailedChecks
	
	healthyDisks := 0
	totalUsage := 0.0
	fsCount := 0
	
	for _, stat := range result.DiskStats {
		if stat.Healthy {
			healthyDisks++
		}
		totalUsage += stat.UsedPercent
		fsCount++
	}
	
	summary.TotalDisks = len(result.DiskStats)
	summary.HealthyDisks = healthyDisks
	summary.TotalFS = fsCount
	
	if fsCount > 0 {
		summary.AvgDiskUsage = totalUsage / float64(fsCount)
		summary.HealthyFS = fsCount
		for _, stat := range result.DiskStats {
			if !stat.Healthy {
				summary.HealthyFS--
			}
		}
	}
	
	return summary
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	
	go func() {
		<-ctx.Done()
		if !defaultConfig.OutputJSON {
			fmt.Printf("\n%s✗ Monitoring interrupted%s\n", colorRed, colorReset)
		}
		os.Exit(1)
	}()
	
	startTime := time.Now()
	hostname := getHostname()
	
	if !defaultConfig.OutputJSON {
		fmt.Printf("%s🖥️  SYSTEM STORAGE ANALYSIS%s\n", colorPurple, colorReset)
		fmt.Printf("%sHost: %s%s\n\n", colorGray, hostname, colorReset)
	}

	var allErrors, allWarnings []string
	var allDiskStats []DiskStats
	checks := []string{"Disk Usage", "Mounted Filesystems", "Filesystem Integrity", "I/O Errors", "Open Files", "SMART Status"}
	if defaultConfig.CheckDiskTemp {
		checks = append(checks, "Disk Temperature")
	}
	
	diskErrors, diskWarnings, diskStats := withRecovery("Disk Usage", func() ([]string, []string, []DiskStats) {
		return checkDiskUsage(ctx, defaultConfig)
	})
	allErrors = append(allErrors, diskErrors...)
	allWarnings = append(allWarnings, diskWarnings...)
	allDiskStats = append(allDiskStats, diskStats...)
	
	mountErrors, mountWarnings, mountStats := withRecovery("Mounted Filesystems", func() ([]string, []string, []DiskStats) {
		return checkMountedFilesystems(ctx, defaultConfig)
	})
	allErrors = append(allErrors, mountErrors...)
	allWarnings = append(allWarnings, mountWarnings...)
	allDiskStats = append(allDiskStats, mountStats...)
	
	fsErrors, fsWarnings, fsStats := withRecovery("Filesystem Integrity", func() ([]string, []string, []DiskStats) {
		return checkFilesystemIntegrity(ctx, defaultConfig)
	})
	allErrors = append(allErrors, fsErrors...)
	allWarnings = append(allWarnings, fsWarnings...)
	allDiskStats = append(allDiskStats, fsStats...)
	
	ioErrors, ioWarnings, ioStats := withRecovery("I/O Errors", func() ([]string, []string, []DiskStats) {
		return checkIOErrors(ctx, defaultConfig)
	})
	allErrors = append(allErrors, ioErrors...)
	allWarnings = append(allWarnings, ioWarnings...)
	allDiskStats = append(allDiskStats, ioStats...)
	
	fileErrors, fileWarnings, fileStats := withRecovery("Open Files", func() ([]string, []string, []DiskStats) {
		return checkOpenFiles(ctx, defaultConfig)
	})
	allErrors = append(allErrors, fileErrors...)
	allWarnings = append(allWarnings, fileWarnings...)
	allDiskStats = append(allDiskStats, fileStats...)
	
	smartErrors, smartWarnings, smartStats := withRecovery("SMART Status", func() ([]string, []string, []DiskStats) {
		return checkSMARTStatus(ctx, defaultConfig)
	})
	allErrors = append(allErrors, smartErrors...)
	allWarnings = append(allWarnings, smartWarnings...)
	allDiskStats = append(allDiskStats, smartStats...)
	
	tempErrors, tempWarnings, tempStats := withRecovery("Disk Temperature", func() ([]string, []string, []DiskStats) {
		return checkDiskTemperature(ctx, defaultConfig)
	})
	allErrors = append(allErrors, tempErrors...)
	allWarnings = append(allWarnings, tempWarnings...)
	allDiskStats = append(allDiskStats, tempStats...)

	result := CheckResult{
		Timestamp: time.Now(),
		Duration:  time.Since(startTime).Round(time.Millisecond).String(),
		Hostname:  hostname,
		Checks:    checks,
		Errors:    allErrors,
		Warnings:  allWarnings,
		DiskStats: allDiskStats,
	}

	result.Summary = calculateSummary(result, len(checks))

	if defaultConfig.OutputJSON {
		printJSON(result)
	} else {
		fmt.Println()
		printSummary(result)
	}

	if len(allErrors) > 0 {
		os.Exit(1)
	}
}
