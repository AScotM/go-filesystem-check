package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// ANSI color codes for terminal output
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
)

// printHeader prints a styled section header
func printHeader(title string) {
	fmt.Printf("%s┌──────────────────────────────────────────────┐%s\n", colorCyan, colorReset)
	fmt.Printf("%s│ %-44s │%s\n", colorCyan, title, colorReset)
	fmt.Printf("%s└──────────────────────────────────────────────┘%s\n", colorCyan, colorReset)
}

// printSummary prints a summary of the checks
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

// checkDiskUsage retrieves disk usage using syscall.Statfs
func checkDiskUsage(errors *[]string) {
	printHeader("Disk Usage")
	file, err := os.Open("/proc/mounts")
	if err != nil {
		*errors = append(*errors, fmt.Sprintf("Disk Usage: failed to open /proc/mounts: %v", err))
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		device, mountpoint, fstype := fields[0], fields[1], fields[2]
		if strings.HasPrefix(fstype, "tmpfs") || strings.HasPrefix(fstype, "devtmpfs") ||
			strings.HasPrefix(fstype, "proc") || strings.HasPrefix(fstype, "sysfs") {
			continue
		}

		var stat syscall.Statfs_t
		if err := syscall.Statfs(mountpoint, &stat); err != nil {
			fmt.Printf("  %-20s Error: %v\n", device, err)
			continue
		}

		blockSize := uint64(stat.Bsize)
		total := stat.Blocks * blockSize
		free := stat.Bfree * blockSize
		used := total - free
		usedPercent := float64(used) / float64(total) * 100
		totalInodes := stat.Files
		freeInodes := stat.Ffree
		usedInodes := totalInodes - freeInodes
		inodePercent := float64(usedInodes) / float64(totalInodes) * 100

		fmt.Printf("  %-20s\n", device)
		fmt.Printf("    Mountpoint: %-30s\n", mountpoint)
		fmt.Printf("    Size:       %-10.2f GB\n", float64(total)/1024/1024/1024)
		fmt.Printf("    Used:       %-10.2f GB\n", float64(used)/1024/1024/1024)
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
	if err := scanner.Err(); err != nil {
		*errors = append(*errors, fmt.Sprintf("Disk Usage: error reading /proc/mounts: %v", err))
	}
}

// checkMountedFilesystems lists mounted filesystems from /proc/mounts
func checkMountedFilesystems(errors *[]string) {
	printHeader("Mounted Filesystems")
	file, err := os.Open("/proc/mounts")
	if err != nil {
		*errors = append(*errors, fmt.Sprintf("Mounted Filesystems: failed to open /proc/mounts: %v", err))
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		fmt.Printf("  Device:       %-30s\n", fields[0])
		fmt.Printf("  Mountpoint:   %-30s\n", fields[1])
		fmt.Printf("  Type:         %-15s\n", fields[2])
		fmt.Printf("  Options:      %-30s\n", fields[3])
		fmt.Println()
	}
	if err := scanner.Err(); err != nil {
		*errors = append(*errors, fmt.Sprintf("Mounted Filesystems: error reading /proc/mounts: %v", err))
	}
}

// checkFilesystemIntegrity checks for filesystem errors (basic, read-only)
func checkFilesystemIntegrity(errors *[]string) {
	printHeader("Filesystem Integrity Check")
	if os.Geteuid() != 0 {
		fmt.Printf("  %sSkipped: Requires root privileges.%s\n", colorYellow, colorReset)
		return
	}

	file, err := os.Open("/proc/mounts")
	if err != nil {
		*errors = append(*errors, fmt.Sprintf("Filesystem Integrity: failed to open /proc/mounts: %v", err))
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		device, mountpoint, fstype := fields[0], fields[1], fields[2]
		if strings.HasPrefix(fstype, "tmpfs") || strings.HasPrefix(fstype, "devtmpfs") ||
			strings.HasPrefix(fstype, "proc") || strings.HasPrefix(fstype, "sysfs") ||
			fstype == "nfs" || fstype == "cifs" {
			continue
		}

		fmt.Printf("  Checking %-20s (%s, type %s)\n", device, mountpoint, fstype)
		cmd := exec.Command("fsck", "-n", device)
		output, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Printf("    %sError: %v\nOutput: %s%s\n", colorRed, err, string(output), colorReset)
			*errors = append(*errors, fmt.Sprintf("Filesystem Integrity: fsck error on %s: %v", device, err))
		} else {
			fmt.Printf("    %sClean: No issues found.%s\n", colorCyan, colorReset)
		}
	}
	if err := scanner.Err(); err != nil {
		*errors = append(*errors, fmt.Sprintf("Filesystem Integrity: error reading /proc/mounts: %v", err))
	}
}

// checkIOErrors checks for I/O errors in dmesg
func checkIOErrors(errors *[]string) {
	printHeader("Recent I/O Errors")
	cmd := exec.Command("dmesg")
	output, err := cmd.Output()
	if err != nil {
		*errors = append(*errors, fmt.Sprintf("I/O Errors: failed to run dmesg: %v", err))
		fmt.Printf("  %sError: Failed to run dmesg: %v%s\n", colorRed, err, colorReset)
		return
	}

	lines := strings.Split(string(output), "\n")
	found := false
	for _, line := range lines {
		if strings.Contains(strings.ToLower(line), "i/o error") ||
			strings.Contains(strings.ToLower(line), "disk error") ||
			strings.Contains(strings.ToLower(line), "filesystem error") {
			fmt.Printf("  %s%s%s\n", colorRed, line, colorReset)
			found = true
		}
	}
	if !found {
		fmt.Printf("  %sNo I/O or filesystem errors found.%s\n", colorCyan, colorReset)
	}
}

// checkOpenFiles counts open file descriptors in /proc
func checkOpenFiles(errors *[]string) {
	printHeader("Open File Descriptors")
	procDir := "/proc"
	entries, err := os.ReadDir(procDir)
	if err != nil {
		*errors = append(*errors, fmt.Sprintf("Open Files: failed to read /proc: %v", err))
		fmt.Printf("  %sError: Failed to read /proc: %v%s\n", colorRed, err, colorReset)
		return
	}

	totalFds := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		fdPath := filepath.Join(procDir, entry.Name(), "fd")
		fds, err := os.ReadDir(fdPath)
		if err != nil {
			continue
		}
		totalFds += len(fds)
	}
	fmt.Printf("  Total Open FDs: %d\n", totalFds)

	file, err := os.Open("/proc/sys/fs/file-nr")
	if err != nil {
		*errors = append(*errors, fmt.Sprintf("Open Files: failed to read /proc/sys/fs/file-nr: %v", err))
		fmt.Printf("  %sError: Failed to read /proc/sys/fs/file-nr: %v%s\n", colorRed, err, colorReset)
		return
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	if scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 3 {
			used, _, max := fields[0], fields[1], fields[2]
			usedNum, err := strconv.Atoi(used)
			if err != nil {
				*errors = append(*errors, fmt.Sprintf("Open Files: failed to parse used file descriptors: %v", err))
				return
			}
			maxNum, err := strconv.Atoi(max)
			if err != nil {
				*errors = append(*errors, fmt.Sprintf("Open Files: failed to parse max file descriptors: %v", err))
				return
			}
			percent := float64(usedNum) / float64(maxNum) * 100
			fmt.Printf("  System-wide: %s/%s (%.1f%%)\n", used, max, percent)
			if percent > 90 {
				fmt.Printf("  %sWARNING: File descriptor usage is over 90%%!%s\n", colorYellow, colorReset)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		*errors = append(*errors, fmt.Sprintf("Open Files: error reading /proc/sys/fs/file-nr: %v", err))
	}
}

// checkSMARTStatus checks SMART health status
func checkSMARTStatus(errors *[]string) {
	printHeader("SMART Health Status")
	cmd := exec.Command("smartctl", "--version")
	if err := cmd.Run(); err != nil {
		fmt.Printf("  %sSkipped: smartctl not found. Install 'smartmontools'.%s\n", colorYellow, colorReset)
		return
	}

	devices, err := filepath.Glob("/dev/sd[a-z]")
	if err != nil {
		*errors = append(*errors, fmt.Sprintf("SMART Status: failed to list block devices: %v", err))
		fmt.Printf("  %sError: Failed to list block devices: %v%s\n", colorRed, err, colorReset)
		return
	}
	if len(devices) == 0 {
		fmt.Printf("  %sNo block devices found (/dev/sdX).%s\n", colorYellow, colorReset)
		return
	}

	for _, device := range devices {
		fmt.Printf("  Checking %-20s\n", device)
		cmd := exec.Command("smartctl", "-H", device)
		output, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Printf("    %sError: %v\nOutput: %s%s\n", colorRed, err, string(output), colorReset)
			*errors = append(*errors, fmt.Sprintf("SMART Status: error on %s: %v", device, err))
		} else if strings.Contains(string(output), "PASSED") {
			fmt.Printf("    %sPASSED: SMART health OK.%s\n", colorCyan, colorReset)
		} else {
			fmt.Printf("    %sCheck: %s%s\n", colorYellow, string(output), colorReset)
		}
	}
}

func main() {
	startTime := time.Now()
	fmt.Printf("%sFilesystem Check Started at %s%s\n", colorCyan, startTime.Format("2006-01-02 15:04:05 EEST"), colorReset)

	var errors []string
	checkDiskUsage(&errors)
	checkMountedFilesystems(&errors)
	checkFilesystemIntegrity(&errors)
	checkIOErrors(&errors)
	checkOpenFiles(&errors)
	checkSMARTStatus(&errors)

	printSummary(startTime, errors)
}
