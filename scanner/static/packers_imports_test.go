package static

import "testing"

// A packer keeps one import from every library, so the list of libraries is
// what survives. The stub's own kernel32 imports are always there; what is
// tested is what the rest of the list is allowed to say.
func packedWith(imports ...[2]string) peSpec {
	s := upxSpec()
	s.imports = append(s.imports, imports...)
	return s
}

func TestPackedCredentialLibraries(t *testing.T) {
	// The shape of a packed credential dumper: one arbitrary function from
	// each library, the SAM client and LSA's crypto library among them.
	r := analyze(t, buildPE(t, packedWith(
		[2]string{"ADVAPI32.dll", "CopySid"},
		[2]string{"SAMLIB.dll", "SamConnect"},
		[2]string{"cryptdll.dll", "MD5Init"},
	)))
	if !hasClass(r, "packer.credential-imports") {
		t.Fatalf("no packer.credential-imports in %v", classes(r))
	}
	if !r.Detected() {
		t.Fatalf("score %d does not reach the threshold: %v", r.Score, classes(r))
	}
}

// The library is the evidence, not the function the linker happened to put
// first: the same image with a different survivor from samlib reads the same.
func TestPackedCredentialLibraryWhateverFunctionSurvived(t *testing.T) {
	r := analyze(t, buildPE(t, packedWith([2]string{"samlib.dll", "SamCloseHandle"})))
	if !hasClass(r, "packer.credential-imports") {
		t.Fatalf("no packer.credential-imports in %v", classes(r))
	}
}

// What ordinary packed software has. A registry read and a service query are
// in the import table of an installer and a driver utility; share and network
// enumeration are in every file manager and every Qt program. An earlier
// version of the rule scored two of these together as credential dumping.
func TestPackedOrdinaryImportsSayNothing(t *testing.T) {
	for name, extra := range map[string][][2]string{
		"registry and services":  {{"ADVAPI32.dll", "RegOpenKeyExA"}, {"ADVAPI32.dll", "OpenServiceW"}, {"ADVAPI32.dll", "RegQueryValueExW"}},
		"shares and the network": {{"ADVAPI32.dll", "OpenServiceA"}, {"MPR.dll", "WNetAddConnection2A"}, {"NETAPI32.dll", "NetShareEnum"}},
		"data protection":        {{"CRYPT32.dll", "CryptUnprotectData"}, {"WLANAPI.dll", "WlanOpenHandle"}},
	} {
		t.Run(name, func(t *testing.T) {
			base := analyze(t, buildPE(t, upxSpec()))
			r := analyze(t, buildPE(t, packedWith(extra...)))
			if hasClass(r, "packer.credential-imports") {
				t.Fatalf("ordinary imports read as evidence: %v", classes(r))
			}
			if r.Detected() && !base.Detected() {
				t.Fatalf("ordinary imports convicted a packed image: %v", classes(r))
			}
		})
	}
}

// The reading is for packed images only. An unpacked credential tool shows
// its strings and is another detector's business.
func TestUnpackedImportsAreNotRead(t *testing.T) {
	s := benignSpec()
	s.imports = append(s.imports, [2]string{"SAMLIB.dll", "SamConnect"}, [2]string{"MPR.dll", "WNetAddConnection2W"}, [2]string{"NETAPI32.dll", "NetShareEnum"})
	r := analyze(t, buildPE(t, s))
	if hasClass(r, "packer.credential-imports") {
		t.Fatalf("an unpacked image was read as packed: %v", classes(r))
	}
}
