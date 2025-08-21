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

// printHeader prints a formatted section header
func printHeader(title string) {
	fmt.Println("========================================")
	fmt.Println(title)
	fmt.Println("========================================")
}

// checkDiskUsage retrieves disk usage using syscall.Statfs
func checkDiskUsage() error {
	printHeader("Disk Usage")
	file, err := os.Open("/proc/mounts")
	if err != nil {
		return fmt.Errorf("failed to open /proc/mounts: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		device, mountpoint, fstype := fields[0], fields[1], fields[2]
		// Skip non-physical filesystems
		if strings.HasPrefix(fstype, "tmpfs") || strings.HasPrefix(fstype, "devtmpfs") ||
			strings.HasPrefix(fstype, "proc") || strings.HasPrefix(fstype, "sysfs") {
			continue
		}

		var stat syscall.Statfs_t
		if err := syscall.Statfs(mountpoint, &stat); err != nil {
			fmt.Printf("Error getting stats for %s: %v\n", mountpoint, err)
			continue
		}

		// Disk usage calculations
		blockSize := uint64(stat.Bsize)
		total := stat.Blocks * blockSize
		free := stat.Bfree * blockSize
		used := total - free
		usedPercent := float64(used) / float64(total) * 100

		// Inode usage calculations
		totalInodes := stat.Files
		freeInodes := stat.Ffree
		usedInodes := totalInodes - freeInodes
		inodePercent := float64(usedInodes) / float64(totalInodes) * 100

		fmt.Printf("Filesystem: %s\n", device)
		fmt.Printf("Mountpoint: %s\n", mountpoint)
		fmt.Printf("Size: %.2f GB\n", float64(total)/1024/1024/1024)
		fmt.Printf("Used: %.2f GB\n", float64(used)/1024/1024/1024)
		fmt.Printf("Available: %.2f GB\n", float64(free)/1024/1024/1024)
		fmt.Printf("Use%%: %.1f%%\n", usedPercent)
		fmt.Printf("Inodes Used: %d/%d (%.1f%%)\n", usedInodes, totalInodes, inodePercent)
		fmt.Println()
		if usedPercent > 90 {
			fmt.Printf("WARNING: %s is over 90%% full!\n", device)
		}
		if inodePercent > 90 {
			fmt.Printf("WARNING: %s has over 90%% inode usage!\n", device)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading /proc/mounts: %v", err)
	}
	return nil
}

// checkMountedFilesystems lists mounted filesystems from /proc/mounts
func checkMountedFilesystems() error {
	printHeader("Mounted Filesystems")
	file, err := os.Open("/proc/mounts")
	if err != nil {
		return fmt.Errorf("failed to open /proc/mounts: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		fmt.Printf("Device: %s\n", fields[0])
		fmt.Printf("Mountpoint: %s\n", fields[1])
		fmt.Printf("Filesystem Type: %s\n", fields[2])
		fmt.Printf("Mount Options: %s\n", fields[3])
		fmt.Println()
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading /proc/mounts: %v", err)
	}
	return nil
}

// checkFilesystemIntegrity checks for filesystem errors (basic, read-only)
func checkFilesystemIntegrity() error {
	printHeader("Filesystem Integrity Check")
	if os.Geteuid() != 0 {
		fmt.Println("Skipped: Filesystem integrity check requires root privileges.")
		return nil
	}

	file, err := os.Open("/proc/mounts")
	if err != nil {
		return fmt.Errorf("failed to open /proc/mounts: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		device, mountpoint, fstype := fields[0], fields[1], fields[2]
		// Skip non-physical and network filesystems
		if strings.HasPrefix(fstype, "tmpfs") || strings.HasPrefix(fstype, "devtmpfs") ||
			strings.HasPrefix(fstype, "proc") || strings.HasPrefix(fstype, "sysfs") ||
			fstype == "nfs" || fstype == "cifs" {
			continue
		}

		fmt.Printf("Checking %s (mounted on %s, type %s)...\n", device, mountpoint, fstype)
		// Run fsck in read-only mode (-n)
		cmd := exec.Command("fsck", "-n", device)
		output, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Printf("fsck error on %s: %v\nOutput: %s\n", device, err, string(output))
		} else {
			fmt.Printf("No issues found on %s or filesystem is clean.\n", device)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading /proc/mounts: %v", err)
	}
	return nil
}

// checkIOErrors checks for I/O errors in dmesg
func checkIOErrors() error {
	printHeader("Recent I/O Errors")
	cmd := exec.Command("dmesg")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to run dmesg: %v", err)
	}

	lines := strings.Split(string(output), "\n")
	found := false
	for _, line := range lines {
		if strings.Contains(strings.ToLower(line), "i/o error") ||
			strings.Contains(strings.ToLower(line), "disk error") ||
			strings.Contains(strings.ToLower(line), "filesystem error") {
			fmt.Println(line)
			found = true
		}
	}
	if !found {
		fmt.Println("No recent I/O or filesystem errors found in dmesg.")
	}
	return nil
}

// checkOpenFiles counts open file descriptors in /proc
func checkOpenFiles() error {
	printHeader("Open File Descriptors")
	procDir := "/proc"
	entries, err := os.ReadDir(procDir)
	if err != nil {
		return fmt.Errorf("failed to read /proc: %v", err)
	}

	totalFds := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		// Check if the entry is a PID (numeric)
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
	fmt.Printf("Total open file descriptors: %d\n", totalFds)

	// Check system-wide file descriptor limit
	file, err := os.Open("/proc/sys/fs/file-nr")
	if err != nil {
		return fmt.Errorf("failed to read /proc/sys/fs/file-nr: %v", err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
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
			fmt.Printf("System-wide: %s/%s (%.1f%%)\n", used, max, percent)
			if percent > 90 {
				fmt.Println("WARNING: File descriptor usage is over 90%!")
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading /proc/sys/fs/file-nr: %v", err)
	}
	return nil
}

// checkSMARTStatus checks SMART health status (placeholder)
func checkSMARTStatus() error {
	printHeader("SMART Health Status")
	// Try to run smartctl if available
	cmd := exec.Command("smartctl", "--version")
	if err := cmd.Run(); err != nil {
		fmt.Println("smartctl not found, skipping SMART checks.")
		fmt.Println("Install 'smartmontools' and run `smartctl -H /dev/sdX` manually for each disk.")
		return nil
	}

	// Scan for block devices
	devices, err := filepath.Glob("/dev/sd[a-z]")
	if err != nil {
		return fmt.Errorf("failed to list block devices: %v", err)
	}
	if len(devices) == 0 {
		fmt.Println("No block devices found (/dev/sdX).")
		return nil
	}

	for _, device := range devices {
		fmt.Printf("Checking SMART status for %s...\n", device)
		cmd := exec.Command("smartctl", "-H", device)
		output, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Printf("Error checking %s: %v\nOutput: %s\n", device, err, string(output))
		} else {
			if strings.Contains(string(output), "PASSED") {
				fmt.Printf("%s: SMART health PASSED\n", device)
			} else {
				fmt.Printf("%s: SMART health check output:\n%s\n", device, string(output))
			}
		}
	}
	return nil
}

func main() {
	fmt.Printf("Starting Filesystem Check at %s\n", time.Now().Format("2006-01-02 15:04:05 MST"))

	// Run checks
	if err := checkDiskUsage(); err != nil {
		fmt.Fprintf(os.Stderr, "Error in disk usage check: %v\n", err)
	}
	if err := checkMountedFilesystems(); err != nil {
		fmt.Fprintf(os.Stderr, "Error in mounted filesystems check: %v\n", err)
	}
	if err := checkFilesystemIntegrity(); err != nil {
		fmt.Fprintf(os.Stderr, "Error in filesystem integrity check: %v\n", err)
	}
	if err := checkIOErrors(); err != nil {
		fmt.Fprintf(os.Stderr, "Error in I/O errors check: %v\n", err)
	}
	if err := checkOpenFiles(); err != nil {
		fmt.Fprintf(os.Stderr, "Error in open files check: %v\n", err)
	}
	if err := checkSMARTStatus(); err != nil {
		fmt.Fprintf(os.Stderr, "Error in SMART status check: %v\n", err)
	}

	fmt.Println("========================================")
	fmt.Println("Filesystem check completed.")
	fmt.Println("========================================")
}
