package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"homelab-horizon/internal/config"
	"homelab-horizon/internal/server"
	"homelab-horizon/internal/wireguard"
)

const systemdService = `[Unit]
Description=Homelab Horizon - Split-Horizon DNS & VPN Management
After=network.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s
Restart=on-failure
RestartSec=5

User=root
Group=root

ProtectSystem=strict
ReadWritePaths=/etc/wireguard /etc/dnsmasq.d /etc/haproxy /proc/sys/net/ipv4

AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=false
PrivateTmp=true

[Install]
WantedBy=multi-user.target
`

func main() {
	configPath := flag.String("config", "", "Path to configuration file (optional)")
	install := flag.String("install", "", "Install service (systemd)")
	check := flag.Bool("check", false, "Check system configuration and offer to fix issues")
	configTemplate := flag.Bool("config-template", false, "Print a commented config template and exit")
	iamPolicy := flag.Bool("iam-policy", false, "Print IAM policy template for Route53 access")
	flag.Parse()

	if *configTemplate {
		fmt.Print(config.Template())
		return
	}

	if *iamPolicy {
		fmt.Print(config.IAMPolicyTemplate())
		return
	}

	if *check {
		if err := runCheck(); err != nil {
			log.Fatalf("Check failed: %v", err)
		}
		return
	}

	if *install != "" {
		if err := installService(*install); err != nil {
			log.Fatalf("Installation failed: %v", err)
		}
		return
	}

	if os.Geteuid() != 0 {
		log.Println("Warning: Not running as root. Some operations may fail.")
	}

	var cfg *config.Config
	var cfgPath string
	var err error

	if *configPath != "" {
		cfg, err = config.Load(*configPath)
		cfgPath = *configPath
		if err != nil {
			log.Fatalf("Failed to load config: %v", err)
		}
		fmt.Printf("Loaded config from %s\n", cfgPath)
	} else {
		cfg, cfgPath, err = config.LoadAuto()
		if err != nil {
			log.Fatalf("Failed to load config: %v", err)
		}
	}

	fmt.Printf("Config search paths: %s\n", strings.Join(config.SearchPaths, ", "))

	srv, err := server.NewWithConfig(cfg, cfgPath)
	if err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}

	if err := srv.Run(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

// askYesNo prompts the user for a yes/no response
func askYesNo(prompt string) bool {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("%s [y/N]: ", prompt)
	response, _ := reader.ReadString('\n')
	response = strings.ToLower(strings.TrimSpace(response))
	return response == "y" || response == "yes"
}

// askString prompts the user for a string input with a default
func askString(prompt, defaultVal string) string {
	reader := bufio.NewReader(os.Stdin)
	if defaultVal != "" {
		fmt.Printf("%s [%s]: ", prompt, defaultVal)
	} else {
		fmt.Printf("%s: ", prompt)
	}
	response, _ := reader.ReadString('\n')
	response = strings.TrimSpace(response)
	if response == "" {
		return defaultVal
	}
	return response
}

func runCheck() error {
	fmt.Println("Homelab Horizon System Check")
	fmt.Println("============================")
	fmt.Println()

	isRoot := os.Geteuid() == 0
	if !isRoot {
		fmt.Println("Warning: Not running as root. Some checks may be incomplete.")
		fmt.Println("Re-run with sudo for full functionality.")
		fmt.Println()
	}

	// Load config
	cfg, cfgPath, _ := config.LoadAuto()
	fmt.Println()

	allGood := true

	// 1. Check if wg is installed
	fmt.Print("Checking WireGuard... ")
	if _, err := exec.LookPath("wg"); err != nil {
		fmt.Println("NOT FOUND")
		fmt.Println("  WireGuard tools not installed.")
		fmt.Println("  Install with: apt install wireguard-tools")
		allGood = false
	} else {
		fmt.Println("OK")
	}

	// 2. Check if dnsmasq is installed
	fmt.Print("Checking dnsmasq... ")
	if _, err := exec.LookPath("dnsmasq"); err != nil {
		fmt.Println("NOT FOUND")
		if cfg.DNSMasqEnabled {
			fmt.Println("  dnsmasq not installed but enabled in config.")
			fmt.Println("  Install with: apt install dnsmasq")
			fmt.Println("  Or disable in config: \"dnsmasq_enabled\": false")
			allGood = false
		} else {
			fmt.Println("  (disabled in config, OK)")
		}
	} else {
		fmt.Println("OK")
	}

	// 3. Check if qrencode is installed
	fmt.Print("Checking qrencode... ")
	if _, err := exec.LookPath("qrencode"); err != nil {
		fmt.Println("NOT FOUND")
		fmt.Println("  QR codes will be disabled.")
		fmt.Println("  Install with: apt install qrencode")
	} else {
		fmt.Println("OK")
	}

	// 4. Check if haproxy is installed
	fmt.Print("Checking haproxy... ")
	if _, err := exec.LookPath("haproxy"); err != nil {
		fmt.Println("NOT FOUND")
		if cfg.HAProxyEnabled {
			fmt.Println("  haproxy not installed but enabled in config.")
			fmt.Println("  Install with: apt install haproxy")
			allGood = false
		} else {
			fmt.Println("  (disabled in config, OK)")
		}
	} else {
		fmt.Println("OK")
	}

	// 5. Check if haproxy is running (if enabled)
	if cfg.HAProxyEnabled {
		fmt.Print("Checking haproxy service... ")
		cmd := exec.Command("systemctl", "is-active", "haproxy")
		if err := cmd.Run(); err != nil {
			fmt.Println("NOT RUNNING")
			if isRoot && askYesNo("  Start haproxy service?") {
				if err := exec.Command("systemctl", "start", "haproxy").Run(); err != nil {
					fmt.Printf("  Error: %v\n", err)
				} else {
					fmt.Println("  haproxy started.")
				}
			}
		} else {
			fmt.Println("RUNNING")
		}
	}

	// 6. Check WireGuard interface config
	fmt.Printf("Checking WireGuard config (%s)... ", cfg.WGConfigPath)
	if _, err := os.Stat(cfg.WGConfigPath); os.IsNotExist(err) {
		fmt.Println("NOT FOUND")
		allGood = false
		if isRoot && askYesNo("  Create WireGuard server config?") {
			if err := createWGConfig(cfg, cfgPath); err != nil {
				fmt.Printf("  Error: %v\n", err)
			} else {
				fmt.Println("  Created WireGuard config.")
			}
		}
	} else if err != nil {
		fmt.Printf("ERROR: %v\n", err)
		allGood = false
	} else {
		fmt.Println("OK")
	}

	// 7. Check WireGuard interface is up
	fmt.Printf("Checking WireGuard interface (%s)... ", cfg.WGInterface)
	cmd := exec.Command("wg", "show", cfg.WGInterface)
	if err := cmd.Run(); err != nil {
		fmt.Println("DOWN")
		if isRoot && askYesNo("  Bring up WireGuard interface?") {
			if err := exec.Command("wg-quick", "up", cfg.WGInterface).Run(); err != nil {
				fmt.Printf("  Error: %v\n", err)
			} else {
				fmt.Println("  Interface is now up.")
			}
		}
	} else {
		fmt.Println("UP")
	}

	// 8. Check systemd service
	fmt.Print("Checking systemd service... ")
	servicePath := "/etc/systemd/system/homelab-horizon.service"
	if _, err := os.Stat(servicePath); os.IsNotExist(err) {
		fmt.Println("NOT INSTALLED")
		if isRoot && askYesNo("  Install systemd service?") {
			if err := installService("systemd"); err != nil {
				fmt.Printf("  Error: %v\n", err)
			}
		}
	} else {
		// Check if enabled
		cmd := exec.Command("systemctl", "is-enabled", "homelab-horizon")
		if err := cmd.Run(); err != nil {
			fmt.Println("INSTALLED (not enabled)")
			if isRoot && askYesNo("  Enable service to start on boot?") {
				exec.Command("systemctl", "enable", "homelab-horizon").Run()
				fmt.Println("  Service enabled.")
			}
		} else {
			fmt.Println("OK (enabled)")
		}
	}

	// 9. Check file permissions
	fmt.Println()
	fmt.Println("Checking file access...")

	// WireGuard config directory
	wgDir := filepath.Dir(cfg.WGConfigPath)
	fmt.Printf("  %s: ", wgDir)
	if err := checkWriteAccess(wgDir); err != nil {
		fmt.Printf("NO ACCESS (%v)\n", err)
		allGood = false
	} else {
		fmt.Println("OK")
	}

	// dnsmasq config directory
	if cfg.DNSMasqEnabled {
		dnsmasqDir := filepath.Dir(cfg.DNSMasqConfigPath)
		fmt.Printf("  %s: ", dnsmasqDir)
		if err := checkWriteAccess(dnsmasqDir); err != nil {
			fmt.Printf("NO ACCESS (%v)\n", err)
			if isRoot && askYesNo("  Create dnsmasq config directory?") {
				if err := os.MkdirAll(dnsmasqDir, 0755); err != nil {
					fmt.Printf("  Error: %v\n", err)
				} else {
					fmt.Println("  Created directory.")
				}
			}
		} else {
			fmt.Println("OK")
		}
	}

	// 10. Check IP forwarding
	fmt.Print("Checking IP forwarding... ")
	data, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil {
		fmt.Printf("ERROR: %v\n", err)
	} else if strings.TrimSpace(string(data)) != "1" {
		fmt.Println("DISABLED")
		allGood = false
		if isRoot && askYesNo("  Enable IP forwarding?") {
			if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644); err != nil {
				fmt.Printf("  Error: %v\n", err)
			} else {
				fmt.Println("  IP forwarding enabled.")
				fmt.Println("  To make permanent, add to /etc/sysctl.conf:")
				fmt.Println("    net.ipv4.ip_forward=1")
			}
		}
	} else {
		fmt.Println("OK")
	}

	// 11. Check masquerade rule
	fmt.Printf("Checking NAT masquerade (%s)... ", cfg.VPNRange)
	cmd = exec.Command("iptables", "-t", "nat", "-C", "POSTROUTING", "-s", cfg.VPNRange, "-j", "MASQUERADE")
	if err := cmd.Run(); err != nil {
		fmt.Println("NOT FOUND")
		allGood = false
		if isRoot && askYesNo("  Add masquerade rule?") {
			if err := exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", cfg.VPNRange, "-j", "MASQUERADE").Run(); err != nil {
				fmt.Printf("  Error: %v\n", err)
			} else {
				fmt.Println("  Masquerade rule added.")
				fmt.Println("  To make permanent, save with: iptables-save > /etc/iptables/rules.v4")
			}
		}
	} else {
		fmt.Println("OK")
	}

	// Summary
	fmt.Println()
	fmt.Println("======================")
	if allGood {
		fmt.Println("All checks passed!")
	} else {
		fmt.Println("Some issues found. Review above and fix as needed.")
	}
	fmt.Println()
	fmt.Printf("Config file: %s\n", cfgPath)
	fmt.Printf("Web UI will listen on: %s\n", cfg.ListenAddr)
	fmt.Println()

	return nil
}

func checkWriteAccess(path string) error {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		// Check if we can create it
		parent := filepath.Dir(path)
		return checkWriteAccess(parent)
	}
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("not a directory")
	}
	// Try to create a temp file
	testFile := filepath.Join(path, ".homelab-horizon-test")
	f, err := os.Create(testFile)
	if err != nil {
		return fmt.Errorf("cannot write")
	}
	f.Close()
	os.Remove(testFile)
	return nil
}

func createWGConfig(cfg *config.Config, cfgPath string) error {
	// Generate server keys
	privKey, pubKey, err := wireguard.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("generating keys: %w", err)
	}

	// Determine server IP from VPN range
	serverIP := strings.Split(cfg.VPNRange, "/")[0]
	serverIP = strings.TrimSuffix(serverIP, ".0") + ".1"

	// Ask for listen port
	listenPort := askString("WireGuard listen port", "51820")

	// Ask for server endpoint
	endpoint := askString("Public endpoint (domain or IP)", cfg.ServerEndpoint)
	if !strings.Contains(endpoint, ":") {
		endpoint = endpoint + ":" + listenPort
	}

	// Create directory if needed
	wgDir := filepath.Dir(cfg.WGConfigPath)
	if err := os.MkdirAll(wgDir, 0700); err != nil {
		return fmt.Errorf("creating directory: %w", err)
	}

	// Write config
	wgConfig := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s/24
ListenPort = %s
PostUp = iptables -A FORWARD -i %%i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i %%i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
`, privKey, serverIP, listenPort)

	if err := os.WriteFile(cfg.WGConfigPath, []byte(wgConfig), 0600); err != nil {
		return fmt.Errorf("writing config: %w", err)
	}

	// Update app config with server public key and endpoint
	cfg.ServerPublicKey = pubKey
	cfg.ServerEndpoint = endpoint
	if err := config.Save(cfgPath, cfg); err != nil {
		fmt.Printf("Warning: could not save app config: %v\n", err)
	}

	fmt.Printf("  Server public key: %s\n", pubKey)
	return nil
}

func installService(target string) error {
	if target != "systemd" {
		return fmt.Errorf("unknown install target: %s (supported: systemd)", target)
	}

	if os.Geteuid() != 0 {
		return fmt.Errorf("must run as root to install systemd service")
	}

	// Find our binary path
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot determine executable path: %w", err)
	}
	execPath, err = filepath.Abs(execPath)
	if err != nil {
		return fmt.Errorf("cannot resolve executable path: %w", err)
	}

	// Install to /usr/local/bin if not already there
	installPath := "/usr/local/bin/homelab-horizon"
	if execPath != installPath {
		fmt.Printf("Copying %s to %s\n", execPath, installPath)
		input, err := os.ReadFile(execPath)
		if err != nil {
			return fmt.Errorf("reading binary: %w", err)
		}
		if err := os.WriteFile(installPath, input, 0755); err != nil {
			return fmt.Errorf("installing binary: %w", err)
		}
	}

	// Generate service file
	serviceContent := fmt.Sprintf(systemdService, installPath)
	servicePath := "/etc/systemd/system/homelab-horizon.service"
	if err := os.WriteFile(servicePath, []byte(serviceContent), 0644); err != nil {
		return fmt.Errorf("writing service file: %w", err)
	}
	fmt.Printf("Created %s\n", servicePath)

	// Reload systemd
	fmt.Println("Reloading systemd...")
	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w", err)
	}

	fmt.Println()
	fmt.Println("Installation complete!")
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Println("  1. Create config (optional): /etc/homelab-horizon.json")
	fmt.Println("  2. Start service: systemctl start homelab-horizon")
	fmt.Println("  3. Enable on boot: systemctl enable homelab-horizon")
	fmt.Println("  4. View admin token: journalctl -u homelab-horizon | head")
	fmt.Println()

	return nil
}
