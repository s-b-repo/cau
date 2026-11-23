package posture

import "testing"

func TestMacPostureReportsProtectionIndependently(t *testing.T) {
	result := newReport("darwin", "application-firewall", "filevault", unavailable)
	readMacFirewall(&result.Firewall, "Firewall is disabled. (State = 0)\n")
	readFileVault(&result.DiskEncryption, "FileVault is Off.\nDecryption in progress: Percent completed = 80")
	if !result.Complete() || len(result.Firewall.Profiles) != 1 || result.Firewall.Profiles[0].Enabled ||
		result.DiskEncryption.Protection != "off" || result.DiskEncryption.Volume != "decrypting" {
		t.Fatalf("unexpected posture: %+v", result)
	}
}

func TestWindowsPostureReportsCoveragePerProvider(t *testing.T) {
	result := newReport("windows", "windows-firewall-active-store", "bitlocker-system-volume", unavailable)
	readWindowsSettings(&result, []byte(`{
		"firewall": [{"name":"Private","enabled":"True"},{"name":"Public","enabled":"NotConfigured"}],
		"disk": {"protection":"Off","volume":"FullyEncrypted"}
	}`), false)
	if result.Complete() || result.Firewall.Status != partial || len(result.Firewall.Profiles) != 1 ||
		result.DiskEncryption.Status != observed || result.DiskEncryption.Protection != "off" || result.DiskEncryption.Volume != "encrypted" {
		t.Fatalf("unexpected partial posture: %+v", result)
	}
	result = newReport("windows", "windows-firewall-active-store", "bitlocker-system-volume", unavailable)
	readWindowsSettings(&result, []byte(`{
		"firewall": [{"name":"Domain","enabled":"True"},{"name":"Private","enabled":"False"},{"name":"Public","enabled":"True"}],
		"disk": null
	}`), false)
	if result.Complete() || result.Firewall.Status != observed || len(result.Firewall.Profiles) != 3 ||
		result.Firewall.Profiles[1].Enabled || result.DiskEncryption.Status != unavailable {
		t.Fatalf("bitlocker query failure hid firewall evidence: %+v", result)
	}
}
