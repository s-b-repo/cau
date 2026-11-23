package posture

import (
	"encoding/json"
	"strings"
)

func readMacFirewall(result *Firewall, output string) {
	var enabled bool
	switch strings.TrimSpace(output) {
	case "Firewall is enabled. (State = 1)", "Firewall is enabled. (State = 2)":
		enabled = true
	case "Firewall is disabled. (State = 0)":
	default:
		return
	}
	result.Status = observed
	result.Profiles = []FirewallProfile{{Name: "application", Enabled: enabled}}
}

func readFileVault(result *DiskEncryption, output string) {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	switch strings.TrimSpace(lines[0]) {
	case "FileVault is On.":
		result.Protection = "on"
	case "FileVault is Off.":
		result.Protection = "off"
	default:
		return
	}
	result.Status = observed
	// fdesetup reports FileVault protection separately from the encryption
	// conversion state. Apple Silicon storage can be encrypted with protection off.
	for _, line := range lines[1:] {
		line = strings.ToLower(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(line, "encryption in progress"):
			result.Volume = "encrypting"
		case strings.HasPrefix(line, "decryption in progress"):
			result.Volume = "decrypting"
		}
	}
}

func readWindowsSettings(result *Report, data []byte, warned bool) {
	var settings struct {
		Firewall []struct{ Name, Enabled string }
		Disk     *struct{ Protection, Volume string }
	}
	if err := json.Unmarshal(data, &settings); err != nil {
		return
	}
	profiles := make(map[string]bool, 3)
	incomplete := warned
	for _, profile := range settings.Firewall {
		name := strings.ToLower(profile.Name)
		_, duplicate := profiles[name]
		if duplicate || (name != "domain" && name != "private" && name != "public") ||
			(profile.Enabled != "True" && profile.Enabled != "False") {
			incomplete = true
			continue
		}
		profiles[name] = profile.Enabled == "True"
	}
	for _, name := range []string{"domain", "private", "public"} {
		if enabled, ok := profiles[name]; ok {
			result.Firewall.Profiles = append(result.Firewall.Profiles, FirewallProfile{Name: name, Enabled: enabled})
		}
	}
	if len(profiles) == 3 && !incomplete {
		result.Firewall.Status = observed
	} else if len(profiles) > 0 {
		result.Firewall.Status = partial
	}
	if settings.Disk == nil {
		return
	}
	disk := &result.DiskEncryption
	switch settings.Disk.Protection {
	case "On", "Off":
		disk.Protection = strings.ToLower(settings.Disk.Protection)
	}
	switch settings.Disk.Volume {
	case "FullyEncrypted":
		disk.Volume = "encrypted"
	case "FullyDecrypted":
		disk.Volume = "decrypted"
	case "EncryptionInProgress":
		disk.Volume = "encrypting"
	case "DecryptionInProgress":
		disk.Volume = "decrypting"
	case "EncryptionPaused":
		disk.Volume = "encryption_paused"
	case "DecryptionPaused":
		disk.Volume = "decryption_paused"
	}
	switch {
	case disk.Protection != "unknown" && disk.Volume != "unknown" && !warned:
		disk.Status = observed
	case disk.Protection != "unknown" || disk.Volume != "unknown":
		disk.Status = partial
	}
}
