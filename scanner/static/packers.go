package static

import (
	"bytes"
	"strings"
)

// Packer identifies a packer or protector from structural evidence.
type Packer struct {
	Name string `json:"name"`
	// Evidence lists what matched: section names, entry-point bytes, or the
	// generic "packed" profile.
	Evidence []string `json:"evidence"`
	// Generic is true when no named packer matched but the file has the
	// structural profile of a packed executable.
	Generic bool `json:"generic,omitempty"`
}

// sectionPackers maps section names to the packer that creates them. Names
// are compared exactly after trimming; the table is deliberately conservative:
// only names that no compiler emits.
var sectionPackers = map[string]string{
	"UPX0": "UPX", "UPX1": "UPX", "UPX2": "UPX", "UPX3": "UPX", "UPX!": "UPX", ".UPX0": "UPX", ".UPX1": "UPX",
	".vmp0": "VMProtect", ".vmp1": "VMProtect", ".vmp2": "VMProtect", ".vmp3": "VMProtect",
	".themida": "Themida", ".Themida": "Themida", ".winlice": "WinLicense", ".WinLice": "WinLicense",
	".aspack": "ASPack", ".adata": "ASPack", ".ASPack": "ASPack",
	".petite":  "Petite",
	".MPRESS1": "MPRESS", ".MPRESS2": "MPRESS",
	".enigma1": "Enigma", ".enigma2": "Enigma",
	".nsp0": "NsPack", ".nsp1": "NsPack", ".nsp2": "NsPack", "nsp0": "NsPack", "nsp1": "NsPack", "nsp2": "NsPack",
	".RLPack": "RLPack", ".packed": "RLPack",
	".Upack": "Upack", ".ByDwing": "Upack",
	".perplex": "Perplex",
	"PEC2":     "PECompact", "PEC2TO": "PECompact", "PEC2MO": "PECompact", "PECompact2": "PECompact", "pec1": "PECompact", "pec": "PECompact",
	".yP": "Y0da Protector", ".y0da": "Y0da Protector",
	".boom":   "The Boomerang List Builder",
	".ccg":    "CCG Packer",
	".MaskPE": "MaskPE",
	".neolit": "NeoLite", ".neolite": "NeoLite",
	".taz":     "PESpin",
	".tsustub": "TSULoader", ".tsuarch": "TSULoader",
	".svkp":    "SVKP",
	".shrink1": "Shrinker", ".shrink2": "Shrinker", ".shrink3": "Shrinker",
	".spack":  "Simple Pack",
	".Stone":  "Stone's PE Encryptor",
	".WWPACK": "WWPack", ".WWP32": "WWPack",
	".mackt":   "ImpRec",
	"krypton":  "Krypton",
	"MEW":      "MEW",
	".mnbvcx1": "most protector", ".mnbvcx2": "most protector",
	".pelock": "PELock", "PELOCKnt": "PELock",
	"ProCrypt": "ProCrypt",
	".sforce3": "StarForce",
	".ndata":   "NSIS", // installer stub, not a packer; identified for accuracy, weighted low
	"_winzip_": "WinZip Self-Extractor",
	".textbss": "", // MSVC incremental linking; listed to document it is NOT a packer
	"BitArts":  "Crunch",
	".FSG":     "FSG", "FSG!": "FSG",
	".kkrunchy": "kkrunchy",
	".dyamar":   "DYAMAR",
	".rmnet":    "Ramnit", // infector marker rather than packer; still structural evidence
}

// installerStubs are packers-in-name-only: self-extracting installers whose
// compressed payload is expected and whose stub is well understood.
var installerStubs = map[string]bool{"NSIS": true, "WinZip Self-Extractor": true}

// entryPointSignatures are byte patterns at the entry point. 0 in mask means
// wildcard.
var entryPointSignatures = []struct {
	name string
	sig  []byte
	mask []byte
}{
	// UPX (x86): pushad; mov esi, <src>; lea edi, [esi+<delta>]
	{"UPX", []byte{0x60, 0xBE, 0, 0, 0, 0, 0x8D, 0xBE}, []byte{1, 1, 0, 0, 0, 0, 1, 1}},
	// UPX (x64): push rbp? Classic: 53 56 57 55 48 8D 35 (push rbx/rsi/rdi/rbp; lea rsi)
	{"UPX", []byte{0x53, 0x56, 0x57, 0x55, 0x48, 0x8D, 0x35}, []byte{1, 1, 1, 1, 1, 1, 1}},
	// ASPack: pushad; call $+5; pop ebp
	{"ASPack", []byte{0x60, 0xE8, 0x03, 0x00, 0x00, 0x00, 0xE9, 0xEB}, []byte{1, 1, 1, 1, 1, 1, 1, 1}},
	// FSG 2.0: xchg; mov; ... distinctive 87 25
	{"FSG", []byte{0x87, 0x25}, []byte{1, 1}},
	// PECompact 2.x: mov eax, <>; push eax; push <>; push <>; ... B8 ?? ?? ?? ?? 50 64 FF 35
	{"PECompact", []byte{0xB8, 0, 0, 0, 0, 0x50, 0x64, 0xFF, 0x35, 0x00, 0x00, 0x00, 0x00}, []byte{1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1}},
	// MEW 11: mov esi,<>; mov edi,<>; ... E9 ?? ?? ?? ?? 00 00 00 02
	{"MEW", []byte{0xE9, 0, 0, 0, 0, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00}, []byte{1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1}},
	// Petite: mov eax,<>; push eax; push <>; ... B8 ?? ?? ?? ?? 66 9C 60 50
	{"Petite", []byte{0xB8, 0, 0, 0, 0, 0x66, 0x9C, 0x60, 0x50}, []byte{1, 0, 0, 0, 0, 1, 1, 1, 1}},
}

// loaderOnlyImports is the import profile of an unpacking stub: just enough to
// resolve everything else at run time.
var loaderOnlyImports = map[string]bool{
	"loadlibrarya": true, "loadlibraryw": true, "loadlibraryexa": true, "loadlibraryexw": true,
	"getprocaddress": true, "virtualalloc": true, "virtualprotect": true, "virtualfree": true,
	"exitprocess": true, "getmodulehandlea": true, "getmodulehandlew": true,
}

// What a packed executable's import table still says.
//
// A packer compresses the program's strings and most of its import table, but
// the Windows loader has to map every library before the stub runs, so the stub
// keeps one import from each: the list of libraries survives, the list of
// functions does not. (Measured on UPX-packed mimikatz, pwdump and 111 packed
// Wine executables: one function per library, whichever the linker put first.)
// So the evidence that is left is which libraries the program needs, and that
// is what these tables read. A function name is only used where it happens to
// be the one that survived.
//
// The structural pass leaves an unpacked program's imports alone on purpose: a
// credential tool that shows its strings is the heuristic detector's business.
// A packed one has had those strings taken away, and its library list is the
// only thing left that says what it is.

// credentialLibraries exist to serve or to read the credential stores: the SAM
// client and server, LSA's own crypto and server libraries, the vault client,
// and the authentication packages themselves. Ordinary software reaches
// credentials through advapi32 and crypt32 and links none of these; of 700
// executables and libraries that Wine ships, none does.
//
// The table stops there on purpose. The libraries a remote password dumper
// also needs (advapi32 for the registry and services, mpr and netapi32 for
// shares) are linked by a file manager, an installer and every Qt program, and
// a packed image already sits one point under the threshold on structure
// alone: reading any of those as evidence would convict packed software for
// being ordinary. Two packed dumpers in the lab's dev split link nothing else,
// and this pass does not report them.
var credentialLibraries = map[string]bool{
	"samlib.dll": true, "samsrv.dll": true, "cryptdll.dll": true, "lsasrv.dll": true,
	"vaultcli.dll": true, "wdigest.dll": true, "kerberos.dll": true, "msv1_0.dll": true,
	"tspkg.dll": true, "livessp.dll": true,
}

// credentialImports are functions that read stored credentials whatever
// library the packer left them under.
//
// LsaFreeReturnBuffer is the one that frees what the LSA hands back, so a
// program that calls it is a program that asked the LSA for something. A
// packer that keeps one import per library happens to keep it, and it is
// what the two packed credential editors in the corpus are read by.
var credentialImports = map[string]bool{
	"samconnect": true, "samenumerateusersindomain": true, "samqueryinformationuser": true,
	"lsaretrieveprivatedata": true, "lsaenumeratelogonsessions": true, "lsafreereturnbuffer": true,
	"credenumeratea": true, "credenumeratew": true, "vaultenumeratevaults": true, "vaultenumerateitems": true,
}

// packedCredentialImports names what in a packed image's import table reads
// credential stores.
func packedCredentialImports(p *PE) []string {
	var hits []string
	for _, d := range p.Imports {
		dll := strings.ToLower(d.Name)
		if credentialLibraries[dll] {
			hits = append(hits, dll)
			continue
		}
		for _, f := range d.Functions {
			if credentialImports[strings.ToLower(f.Name)] {
				hits = append(hits, dll+"."+f.Name)
			}
		}
	}
	return hits
}

// identifyPacker combines section-name, entry-point and structural evidence.
func identifyPacker(p *PE, data []byte) *Packer {
	var pk Packer
	names := map[string]bool{}

	for _, s := range p.Sections {
		name := strings.TrimSpace(s.Name)
		if pn, ok := sectionPackers[name]; ok && pn != "" {
			if !names[pn] {
				names[pn] = true
			}
			pk.Evidence = append(pk.Evidence, "section "+name)
			if pk.Name == "" {
				pk.Name = pn
			}
		}
	}

	if off, ok := p.rvaToOffset(p.EntryPoint); ok {
		for _, sig := range entryPointSignatures {
			if matchMasked(data, off, sig.sig, sig.mask) {
				pk.Evidence = append(pk.Evidence, "entry-point bytes match "+sig.name)
				if pk.Name == "" {
					pk.Name = sig.name
				}
				names[sig.name] = true
			}
		}
	}

	if pk.Name != "" {
		return &pk
	}

	// Generic profile: entry point in a writable section, few imports, high
	// entropy in the entry section, or a large zero-raw-size section that the
	// stub will fill. Two or more of these together is a packed executable
	// whatever it calls its sections.
	score := 0
	var ev []string
	if idx := p.sectionIndexForRVA(p.EntryPoint); idx >= 0 {
		s := p.Sections[idx]
		if s.Writable() && s.Executable() {
			score++
			ev = append(ev, "entry point in a writable+executable section")
		}
		if s.Entropy > 7.0 && s.RawSize >= 1024 {
			score++
			ev = append(ev, "entry section entropy > 7.0")
		}
	}
	if n := p.ImportCount; !p.IsCLR && n > 0 && n <= 8 && importsAreLoaderOnly(p) {
		score++
		ev = append(ev, "import table is a loader stub (LoadLibrary/GetProcAddress class only)")
	}
	for _, s := range p.Sections {
		if s.RawSize == 0 && s.Executable() && s.VirtualSize >= 64<<10 && !s.Uninitialized() {
			score++
			ev = append(ev, "executable section "+strings.TrimSpace(s.Name)+" has no raw data but a large virtual size")
			break
		}
	}
	if score >= 2 {
		return &Packer{Name: "generic packer", Generic: true, Evidence: ev}
	}
	return nil
}

func importsAreLoaderOnly(p *PE) bool {
	seen := 0
	for _, d := range p.Imports {
		for _, f := range d.Functions {
			if f.ByOrdinal {
				return false
			}
			if !loaderOnlyImports[strings.ToLower(f.Name)] {
				return false
			}
			seen++
		}
	}
	return seen > 0
}

func matchMasked(data []byte, off int, sig, mask []byte) bool {
	if off < 0 || off+len(sig) > len(data) {
		return false
	}
	window := data[off : off+len(sig)]
	for i := range sig {
		if mask[i] != 0 && window[i] != sig[i] {
			return false
		}
	}
	return !bytes.Equal(window, make([]byte, len(sig))) // all-zero windows match nothing
}
