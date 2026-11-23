package scanner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/s-b-repo/cau/internal/intel"
	"github.com/s-b-repo/cau/internal/peeler"
	"github.com/s-b-repo/cau/internal/safefs"
	"github.com/s-b-repo/cau/scanner/archive"
	"github.com/s-b-repo/cau/scanner/chm"
	"github.com/s-b-repo/cau/scanner/encchain"
	"github.com/s-b-repo/cau/scanner/iso"
	"github.com/s-b-repo/cau/scanner/linuxpkg"
	"github.com/s-b-repo/cau/scanner/lnk"
	"github.com/s-b-repo/cau/scanner/ole"
	"github.com/s-b-repo/cau/scanner/pdf"
	"github.com/s-b-repo/cau/scanner/static"
	"github.com/s-b-repo/cau/scanner/stego"
	"github.com/s-b-repo/cau/scanner/tradecraft"
)

// DefaultMaxInMemory is the largest file the engine reads into memory once and
// hands to every detector. Larger files are streamed. Hashing and YARA use
// the same open descriptor, and in-memory detectors are skipped.
const DefaultMaxInMemory int64 = 64 << 20 // 64 MiB

// memoryBudget bounds the file bytes all scans in the process hold at once. Each
// worker may read up to DefaultMaxInMemory and several detectors copy what they
// read, so a burst of large files on a machine with many workers could otherwise
// hold gigabytes. Scans over budget wait for their turn and are not cut short, so
// this changes when a large file is scanned and never what is found in it.
const memoryBudget int64 = 128 << 20

// budgetFrom is the size below which a file isn't counted: the budget is for bursts
// of large files, and the lock would cost a small one more than it saves.
const budgetFrom int64 = 1 << 20

var inMemory = newBudget(memoryBudget)

type budget struct {
	mu    sync.Mutex
	freed *sync.Cond
	used  int64
	limit int64
}

func newBudget(limit int64) *budget {
	b := &budget{limit: limit}
	b.freed = sync.NewCond(&b.mu)
	return b
}

// acquire waits until n bytes fit, and returns the release. A request larger than
// the whole budget runs alone rather than never.
func (b *budget) acquire(n int64) (release func()) {
	n = min(n, b.limit)
	b.mu.Lock()
	defer b.mu.Unlock()
	for b.used > 0 && b.used+n > b.limit {
		b.freed.Wait()
	}
	b.used += n
	return func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		b.used -= n
		b.freed.Broadcast()
	}
}

// detectorAttempts is how many times one detector may run on one file. It is
// bounded because the file is hostile: a panic that repeats must cost a known
// amount, not a loop an attacker can hold open.
const detectorAttempts = 2

// DetectorPanic is a detector that panicked on a file. A crash on crafted input is
// worth a human's attention even when the retry completes, so it is reported
// either way. Recovered says the retry finished and the detector's opinion is in
// the result; when false, the file went without that opinion.
type DetectorPanic struct {
	Detector  string
	Value     string
	Attempts  int
	Recovered bool
}

// Engine runs every configured detector over a file with a single read.
//
// Before the engine existed, each file was opened and parsed up to four times
// (hash, YARA, PE imports, strings). Now the bytes are read once, hashed in
// memory, scanned in memory by libyara and handed to the heuristics as a slice.
//
// The zero value scans with hashes only. An Engine is safe for concurrent use.
type Engine struct {
	// DB is the hash signature database. nil disables hash detection.
	DB *SignatureDB
	// Yara is the compiled ruleset. nil disables YARA.
	Yara *YaraScanner
	// Heuristics enables the string/API heuristic detector.
	Heuristics bool
	// HeuristicThreshold overrides the package default (0 = use
	// HeuristicThreshold).
	HeuristicThreshold int
	// MaxInMemory overrides DefaultMaxInMemory (0 = default).
	MaxInMemory int64
	// Jobs is the number of files scanned concurrently by ScanDirectory
	// (0 = runtime.GOMAXPROCS(0)).
	Jobs int
	// FollowSymlinks makes ScanDirectory scan the targets of symbolic links to
	// regular files. Symlinks to directories are never followed (loop risk).
	// A link that is followed is resolved to the file it names, so the result
	// and any prevention acting on it reach the target rather than the link.
	FollowSymlinks bool

	// Static enables the structural analysis layer (entropy, fuzzy hashes, PE
	// anatomy and anomalies). Its result rides on ScanResult.Static.
	Static bool
	// StaticThreshold overrides static.Threshold (0 = package default).
	StaticThreshold int
	// FuzzyDB enables TLSH / ssdeep / imphash similarity lookups during the
	// static pass. nil disables them; the digests are still computed.
	FuzzyDB *static.FuzzyDB
	// StaticNoFuzzy skips TLSH/ssdeep computation, the most expensive part of
	// the static pass on large inputs.
	StaticNoFuzzy bool
	// SignerBlocklist flags PE files signed by a known-abused code-signing
	// certificate during the static pass. nil disables the check.
	SignerBlocklist *static.SignerBlocklist

	// Stego enables the invisible-codepoint detector for text and code
	// artifacts. Its result rides on ScanResult.Stego.
	Stego bool
	// StegoThreshold overrides stego.Threshold (0 = package default).
	StegoThreshold int

	// EncChain enables the encoded-executable detector (base64/hex layers
	// decoding to a PE/ELF header). Its result rides on ScanResult.EncChain.
	EncChain bool
	// EncChainThreshold overrides encchain.Threshold (0 = package default).
	EncChainThreshold int

	// LNK enables the Windows Shell Link (.lnk) detector. Its result rides on
	// ScanResult.LNK.
	LNK bool
	// LNKThreshold overrides lnk.Threshold (0 = package default).
	LNKThreshold int

	// OLE enables the OLE compound-file (VBA macro) detector. Its result rides
	// on ScanResult.OLE.
	OLE bool
	// OLEThreshold overrides ole.Threshold (0 = package default).
	OLEThreshold int

	// PDF enables the PDF malicious-document detector. Its result rides on
	// ScanResult.PDF.
	PDF bool
	// PDFThreshold overrides pdf.Threshold (0 = package default).
	PDFThreshold int

	// ISO enables the ISO 9660 malicious-container detector. Its result rides
	// on ScanResult.ISO.
	ISO bool
	// ISOThreshold overrides iso.Threshold (0 = package default).
	ISOThreshold int

	// LinuxPkg enables the Linux software-package detector (.deb/.rpm/Arch/
	// Flatpak/AppImage/PKGBUILD install scripts). Its result rides on
	// ScanResult.LinuxPkg.
	LinuxPkg bool
	// LinuxPkgThreshold overrides linuxpkg.Threshold (0 = package default).
	LinuxPkgThreshold int
	// IntelSource, when set, supplies the feed for each scan in place of Intel, for
	// a caller that replaces the feed while scans are running.
	IntelSource func() *intel.Feed
	// Intel is the abuse-intelligence feed. When non-nil, indicators found in a
	// package's install scripts are matched against it. nil disables feed
	// matching (the offline default).
	Intel *intel.Feed

	// Peel enables the obfuscation-chain peeler (NOVEL-012). Its result rides
	// on ScanResult.Peel.
	Peel bool
	// PeelIndicators runs the detection rules and the heuristic indicators
	// over the peeler's decoded layers, so a base64-wrapped script is caught
	// even when the decode is a script and not an executable. The cost is
	// capped per file.
	PeelIndicators bool
	// PeelThreshold overrides peeler.Threshold (0 = package default).
	PeelThreshold int

	// Archive enables the compressed-container detector (ZIP/TAR/gzip and
	// tar.gz: decompression bombs, Zip-Slip, lure and payload members). Its
	// result rides on ScanResult.Archive.
	Archive bool
	// ArchiveThreshold overrides archive.Threshold (0 = package default).
	ArchiveThreshold int

	// CHM enables the Compiled HTML Help (CHM/ITSS) detector (embedded
	// executables, shortcuts and dangerous scripts). Its result rides on
	// ScanResult.CHM.
	CHM bool
	// CHMThreshold overrides chm.Threshold (0 = package default).
	CHMThreshold int

	// Tradecraft enables the behavioural pass over scripts and payload bytes.
	// Its result rides on ScanResult.Tradecraft.
	Tradecraft bool
	// TradecraftThreshold overrides tradecraft.Threshold (0 = package default).
	TradecraftThreshold int

	// beforeDetector, when set, runs at the start of every detector attempt. It
	// is how a test makes one panic.
	beforeDetector func(name string)

	// NoFusion leaves ScanResult.Fusion nil. Fusion is on by default because
	// it costs nothing: it is a view over results already computed.
	NoFusion bool
}

func (e *Engine) feed() *intel.Feed {
	if e.IntelSource != nil {
		return e.IntelSource()
	}
	return e.Intel
}

func (e *Engine) maxInMemory() int64 {
	if e.MaxInMemory > 0 {
		return e.MaxInMemory
	}
	return DefaultMaxInMemory
}

func (e *Engine) jobs() int {
	if e.Jobs > 0 {
		return e.Jobs
	}
	return runtime.GOMAXPROCS(0) // unlike NumCPU, this respects a CPU quota
}

func (e *Engine) threshold() int {
	if e.HeuristicThreshold > 0 {
		return e.HeuristicThreshold
	}
	return HeuristicThreshold
}

func (e *Engine) staticThreshold() int {
	if e.StaticThreshold > 0 {
		return e.StaticThreshold
	}
	return static.Threshold
}

func (e *Engine) stegoThreshold() int {
	if e.StegoThreshold > 0 {
		return e.StegoThreshold
	}
	return stego.Threshold
}

func (e *Engine) encChainThreshold() int {
	if e.EncChainThreshold > 0 {
		return e.EncChainThreshold
	}
	return encchain.Threshold
}

func (e *Engine) lnkThreshold() int {
	if e.LNKThreshold > 0 {
		return e.LNKThreshold
	}
	return lnk.Threshold
}

func (e *Engine) oleThreshold() int {
	if e.OLEThreshold > 0 {
		return e.OLEThreshold
	}
	return ole.Threshold
}

func (e *Engine) pdfThreshold() int {
	if e.PDFThreshold > 0 {
		return e.PDFThreshold
	}
	return pdf.Threshold
}

func (e *Engine) isoThreshold() int {
	if e.ISOThreshold > 0 {
		return e.ISOThreshold
	}
	return iso.Threshold
}

func (e *Engine) linuxPkgThreshold() int {
	if e.LinuxPkgThreshold > 0 {
		return e.LinuxPkgThreshold
	}
	return linuxpkg.Threshold
}

func (e *Engine) peelThreshold() int {
	if e.PeelThreshold > 0 {
		return e.PeelThreshold
	}
	return peeler.Threshold
}

func (e *Engine) archiveThreshold() int {
	if e.ArchiveThreshold > 0 {
		return e.ArchiveThreshold
	}
	return archive.Threshold
}

func (e *Engine) chmThreshold() int {
	if e.CHMThreshold > 0 {
		return e.CHMThreshold
	}
	return chm.Threshold
}

func (e *Engine) tradecraftThreshold() int {
	if e.TradecraftThreshold > 0 {
		return e.TradecraftThreshold
	}
	return tradecraft.Threshold
}

// ScanFile runs every configured detector over one file. The heuristic result
// is nil when heuristics are disabled or the file could not be read. With
// FollowSymlinks a path that is itself a symbolic link is resolved to the file
// it names, so ScanResult.FilePath is the file that was scanned rather than the
// link that named it.
func (e *Engine) ScanFile(path string) (res ScanResult, h *HeuristicResult) {
	start := time.Now()
	res = ScanResult{FilePath: path, Verdict: VerdictClean}

	// Defence in depth: a parser bug on a hostile file must degrade to a
	// per-file error, never crash the scan and lose every other file's
	// result. Whatever a detector had already set (a hash or YARA hit, or a
	// pass that completed) is kept; a file that was still clean becomes an
	// error so it is flagged as unscannable rather than silently clean.
	defer func() {
		if r := recover(); r != nil {
			res.Warnings = append(res.Warnings,
				fmt.Sprintf("scan aborted by an internal panic (likely a malformed file): %v", r))
			res.Panics = append(res.Panics, DetectorPanic{Detector: "engine", Value: fmt.Sprint(r), Attempts: 1})
			if res.Verdict == VerdictClean {
				res.Verdict = VerdictError
				if res.Error == nil {
					res.Error = fmt.Errorf("internal panic while scanning %s: %v", path, r)
				}
			}
			res.ScanTime = time.Since(start)
		}
	}()

	fail := func(err error) (ScanResult, *HeuristicResult) {
		res.Error = err
		res.Verdict = VerdictError
		res.ScanTime = time.Since(start)
		return res, nil
	}

	// A response needs the target's path when the caller chose to follow links.
	if e.FollowSymlinks {
		if li, lerr := os.Lstat(path); lerr == nil && li.Mode()&os.ModeSymlink != 0 {
			if real, rerr := filepath.EvalSymlinks(path); rerr == nil {
				path, res.FilePath = real, real
			}
		}
	}

	f, fi, err := safefs.Open(path)
	if err != nil {
		if errors.Is(err, safefs.ErrNotRegular) {
			if st, statErr := os.Stat(path); statErr == nil && st.IsDir() {
				return fail(fmt.Errorf("%s is a directory", path))
			}
		}
		return fail(fmt.Errorf("could not open file: %w", err))
	}
	defer f.Close()
	res.Size = fi.Size()

	var data []byte
	var d digests
	if fi.Size() <= e.maxInMemory() {
		if fi.Size() >= budgetFrom {
			defer inMemory.acquire(fi.Size())()
		}
		data, err = safefs.ReadAll(f, fi, e.maxInMemory())
		switch {
		case errors.Is(err, safefs.ErrTooLarge):
			data = nil // it grew past the limit after the stat: a large file now
			if _, err := f.Seek(0, io.SeekStart); err != nil {
				return fail(fmt.Errorf("could not rewind file: %w", err))
			}
			if fi, err = f.Stat(); err != nil {
				return fail(fmt.Errorf("could not stat open file: %w", err))
			}
		case err != nil:
			return fail(fmt.Errorf("could not read file: %w", err))
		}
	}
	if data != nil {
		res.Size = int64(len(data))
		d = hashBytes(data)
	} else {
		// Use the size from the open file to bound the stream even if a writer
		// keeps appending. Some virtual regular files report size zero.
		var src io.Reader = f
		if fi.Size() > 0 {
			src = io.LimitReader(f, fi.Size())
		}
		if d, err = hashReader(src); err != nil {
			return fail(fmt.Errorf("could not stream file: %w", err))
		}
		if res.Size, err = f.Seek(0, io.SeekCurrent); err != nil {
			return fail(fmt.Errorf("could not determine streamed size: %w", err))
		}
	}
	res.MD5, res.SHA1, res.SHA256 = d.md5, d.sha1, d.sha256
	streamChanged := func() bool {
		after, err := f.Stat()
		return err != nil || !sameStreamVersion(fi, after) || (fi.Size() > 0 && res.Size != fi.Size())
	}

	// ── hash detection: SHA256 first, stop at first match ──
	if e.DB != nil {
		for _, c := range []struct{ t, v string }{{"SHA256", d.sha256}, {"SHA1", d.sha1}, {"MD5", d.md5}} {
			if sig, found := e.DB.Lookup(c.v); found {
				res.Detected = true
				res.MatchType = c.t
				res.MatchHash = c.v
				res.ThreatName = sig.ThreatName
				res.Verdict = VerdictMalicious
				break
			}
		}
	}

	// ── every detector at once ─────────────────────────
	// Each reads the same bytes, which none of them writes, and fills only its
	// own field of res, last thing, so a panic leaves nothing behind and a retry
	// starts clean. A detector that panics is run again, and the panic is recorded
	// either way: it costs that detector's opinion at worst and never the verdicts
	// of the others. Fusion is the one real dependency, so it runs after the join.
	var mu sync.Mutex
	note := func(w string) {
		mu.Lock()
		defer mu.Unlock()
		res.Warnings = append(res.Warnings, w)
	}
	attempt := func(name string, detector func()) (panicked any) {
		defer func() { panicked = recover() }()
		if e.beforeDetector != nil {
			e.beforeDetector(name)
		}
		detector()
		return nil
	}
	var wg sync.WaitGroup
	run := func(name string, detector func()) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p := DetectorPanic{Detector: name}
			for p.Attempts < detectorAttempts && !p.Recovered {
				p.Attempts++
				if r := attempt(name, detector); r == nil {
					p.Recovered = true
				} else if p.Value == "" {
					p.Value = fmt.Sprint(r)
				}
			}
			if p.Attempts == 1 && p.Recovered {
				return // it simply ran
			}
			mu.Lock()
			defer mu.Unlock()
			res.Panics = append(res.Panics, p)
		}()
	}

	// ── YARA ───────────────────────────────────────────
	// yaraErr is a pass that could not finish (error, timeout). It is written
	// by the detector and read after wg.Wait below, which orders the access.
	var yaraErr error
	var changedBeforeYara bool
	if e.Yara != nil {
		run("yara", func() {
			var matches []YaraMatch
			if data != nil {
				matches, yaraErr = e.Yara.ScanMemYaraStrict(data)
			} else if streamChanged() {
				changedBeforeYara = true
				return
			} else if fi.Size() == 0 {
				// A virtual file can have contents but report size zero,
				// in which case a descriptor mapping would miss them.
				var buf []byte
				if _, yaraErr = f.Seek(0, io.SeekStart); yaraErr == nil {
					buf, yaraErr = safefs.ReadAll(f, fi, e.Yara.maxScanSz)
				}
				if yaraErr == nil {
					if hashBytes(buf) != d {
						changedBeforeYara = true
						return
					}
					matches, yaraErr = e.Yara.ScanMemYaraStrict(buf)
				}
			} else {
				matches, yaraErr = e.Yara.scanDescriptor(f, path)
			}
			if yaraErr != nil {
				// Matches collected before the failure are kept: dropping them
				// would turn a malicious sample into a clean one.
				note(fmt.Sprintf("YARA: %v", yaraErr))
			}
			if len(matches) > 0 {
				res.YaraMatches = matches
				res.Verdict = VerdictMalicious
			}
		})
	}

	// ── heuristics ─────────────────────────────────────
	if e.Heuristics {
		run("heuristics", func() {
			var hr HeuristicResult
			if data != nil {
				hr = ScanHeuristicsData(path, data, HeuristicOptions{Threshold: e.threshold()})
			} else {
				hr = HeuristicResult{
					FilePath:  path,
					Threshold: e.threshold(),
					Skipped: fmt.Sprintf("file is %d bytes, over the %d byte in-memory limit",
						fi.Size(), e.maxInMemory()),
				}
			}
			h = &hr
		})
	}

	// ── static / structural ────────────────────────────
	if e.Static {
		run("static", func() {
			if data != nil {
				res.Static = static.Analyze(data, static.Options{
					Threshold:       e.staticThreshold(),
					FuzzyDB:         e.FuzzyDB,
					NoFuzzy:         e.StaticNoFuzzy,
					SignerBlocklist: e.SignerBlocklist,
				})
				res.Static.FilePath = path
			} else {
				res.Static = &static.Result{
					FilePath:  path,
					Size:      int(fi.Size()),
					Threshold: e.staticThreshold(),
					Skipped: fmt.Sprintf("file is %d bytes, over the %d byte in-memory limit",
						fi.Size(), e.maxInMemory()),
				}
			}
		})
	}

	// ── stego / invisible codepoints ───────────────────
	if e.Stego {
		run("stego", func() {
			if data != nil {
				res.Stego = stego.Scan(data, stego.Options{Threshold: e.stegoThreshold()})
				res.Stego.FilePath = path
			} else {
				res.Stego = &stego.Result{
					FilePath:  path,
					Size:      int(fi.Size()),
					Threshold: e.stegoThreshold(),
					Skipped: fmt.Sprintf("file is %d bytes, over the %d byte in-memory limit",
						fi.Size(), e.maxInMemory()),
				}
			}
		})
	}

	// ── encoded-executable chain ───────────────────────
	if e.EncChain {
		run("encchain", func() {
			if data != nil {
				res.EncChain = encchain.Analyze(data, encchain.Options{Threshold: e.encChainThreshold()})
				res.EncChain.FilePath = path
			} else {
				res.EncChain = &encchain.Result{
					FilePath:  path,
					Size:      int(fi.Size()),
					Threshold: e.encChainThreshold(),
					Skipped: fmt.Sprintf("file is %d bytes, over the %d byte in-memory limit",
						fi.Size(), e.maxInMemory()),
				}
			}
		})
	}

	// ── Windows Shell Link (.lnk) ──────────────────────
	if e.LNK {
		run("lnk", func() {
			if data != nil {
				res.LNK = lnk.Analyze(data, lnk.Options{Threshold: e.lnkThreshold()})
				res.LNK.FilePath = path
			} else {
				res.LNK = &lnk.Result{
					FilePath:  path,
					Size:      int(fi.Size()),
					Threshold: e.lnkThreshold(),
					Skipped: fmt.Sprintf("file is %d bytes, over the %d byte in-memory limit",
						fi.Size(), e.maxInMemory()),
				}
			}
		})
	}

	// ── OLE compound-file (VBA macros) ─────────────────
	if e.OLE {
		run("ole", func() {
			if data != nil {
				res.OLE = ole.Analyze(data, ole.Options{Threshold: e.oleThreshold()})
				res.OLE.FilePath = path
			} else {
				res.OLE = &ole.Result{
					FilePath:  path,
					Size:      int(fi.Size()),
					Threshold: e.oleThreshold(),
					Skipped: fmt.Sprintf("file is %d bytes, over the %d byte in-memory limit",
						fi.Size(), e.maxInMemory()),
				}
			}
		})
	}

	// ── PDF malicious-document ─────────────────────────
	if e.PDF {
		run("pdf", func() {
			if data != nil {
				res.PDF = pdf.Analyze(data, pdf.Options{Threshold: e.pdfThreshold()})
				res.PDF.FilePath = path
			} else {
				res.PDF = &pdf.Result{
					FilePath:  path,
					Size:      int(fi.Size()),
					Threshold: e.pdfThreshold(),
					Skipped: fmt.Sprintf("file is %d bytes, over the %d byte in-memory limit",
						fi.Size(), e.maxInMemory()),
				}
			}
		})
	}

	// ── ISO 9660 malicious-container ───────────────────
	if e.ISO {
		run("iso", func() {
			if data != nil {
				res.ISO = iso.Analyze(data, iso.Options{Threshold: e.isoThreshold()})
				res.ISO.FilePath = path
			} else {
				res.ISO = &iso.Result{
					FilePath:  path,
					Size:      int(fi.Size()),
					Threshold: e.isoThreshold(),
					Skipped: fmt.Sprintf("file is %d bytes, over the %d byte in-memory limit",
						fi.Size(), e.maxInMemory()),
				}
			}
		})
	}

	// ── Linux software package (.deb/.rpm/Arch/Flatpak/AppImage) ──
	if e.LinuxPkg {
		run("linuxpkg", func() {
			if data != nil {
				res.LinuxPkg = linuxpkg.Analyze(data, linuxpkg.Options{Threshold: e.linuxPkgThreshold(), Intel: e.feed()})
				res.LinuxPkg.FilePath = path
			} else {
				res.LinuxPkg = &linuxpkg.Result{
					FilePath:  path,
					Size:      int(fi.Size()),
					Threshold: e.linuxPkgThreshold(),
					Skipped: fmt.Sprintf("file is %d bytes, over the %d byte in-memory limit",
						fi.Size(), e.maxInMemory()),
				}
			}
		})
	}

	// ── obfuscation-chain peeler ───────────────────────
	if e.Peel {
		run("peel", func() {
			if data != nil {
				p := peeler.New()
				if e.PeelIndicators {
					// The leaves are what the rescan below reads; without
					// them the peel pays nothing for it.
					p = peeler.New(peeler.WithLeaves(maxLeafRescanBytes))
				}
				// The engine's ScanFile takes no context, so the peel cannot
				// be cancelled from here; its own budget (nodes, bytes, depth,
				// wall clock) is what bounds the work.
				pr := p.Peel(context.Background(), data) // audit:ok no caller context to pass: ScanFile has no context parameter
				pr.FilePath = path
				pr.Threshold = e.peelThreshold()
				if e.PeelIndicators {
					e.rescanLeaves(&pr, path, &res)
				}
				res.Peel = &pr
			} else {
				res.Peel = &peeler.Result{
					FilePath:  path,
					Size:      int(fi.Size()),
					Threshold: e.peelThreshold(),
					Skipped: fmt.Sprintf("file is %d bytes, over the %d byte in-memory limit",
						fi.Size(), e.maxInMemory()),
				}
			}
		})
	}

	// ── compressed container (archive) ─────────────────
	if e.Archive {
		run("archive", func() {
			if data != nil {
				res.Archive = archive.Analyze(data, archive.Options{Threshold: e.archiveThreshold()})
				res.Archive.FilePath = path
			} else {
				res.Archive = &archive.Result{
					FilePath:  path,
					Size:      int(fi.Size()),
					Threshold: e.archiveThreshold(),
					Skipped: fmt.Sprintf("file is %d bytes, over the %d byte in-memory limit",
						fi.Size(), e.maxInMemory()),
				}
			}
		})
	}

	// ── Compiled HTML Help (CHM) ───────────────────────
	if e.CHM {
		run("chm", func() {
			if data != nil {
				res.CHM = chm.Analyze(data, chm.Options{Threshold: e.chmThreshold()})
				res.CHM.FilePath = path
			} else {
				res.CHM = &chm.Result{
					FilePath:  path,
					Size:      int(fi.Size()),
					Threshold: e.chmThreshold(),
					Skipped: fmt.Sprintf("file is %d bytes, over the %d byte in-memory limit",
						fi.Size(), e.maxInMemory()),
				}
			}
		})
	}

	// ── behaviour: scripts and payload bytes ───────────
	if e.Tradecraft {
		run("tradecraft", func() {
			if data != nil {
				res.Tradecraft = tradecraft.Analyze(data, tradecraft.Options{Threshold: e.tradecraftThreshold()})
				res.Tradecraft.FilePath = path
			} else {
				res.Tradecraft = &tradecraft.Result{
					FilePath:  path,
					Size:      int(fi.Size()),
					Threshold: e.tradecraftThreshold(),
					Skipped: fmt.Sprintf("file is %d bytes, over the %d byte in-memory limit",
						fi.Size(), e.maxInMemory()),
				}
			}
		})
	}

	wg.Wait()
	sort.Slice(res.Panics, func(i, j int) bool { return res.Panics[i].Detector < res.Panics[j].Detector })
	for _, p := range res.Panics {
		if p.Recovered {
			res.Warnings = append(res.Warnings, fmt.Sprintf("detector %s panicked (likely a malformed file) and completed on retry: %s", p.Detector, p.Value))
			continue
		}
		res.Warnings = append(res.Warnings, fmt.Sprintf("detector %s gave up after %d attempts on an internal panic (likely a malformed file): %s", p.Detector, p.Attempts, p.Value))
		if res.Verdict == VerdictClean {
			res.Verdict = VerdictError
			if res.Error == nil {
				res.Error = fmt.Errorf("internal panic in detector %s while scanning %s: %s", p.Detector, path, p.Value)
			}
		}
	}

	// ── a pass that could not finish is not a clean verdict ──
	// A YARA scan that errored or timed out judged only part of the file, and
	// the report would keep its warning while still labelling the file clean
	// and exiting 0. Something found keeps its verdict, because the matches are
	// evidence; nothing found means the file was not scanned, which is what
	// ERROR already means everywhere else in this result.
	if yaraErr != nil && res.Verdict == VerdictClean {
		res.Verdict = VerdictError
		if res.Error == nil {
			res.Error = fmt.Errorf("YARA scan of %s did not complete, so the file is only partly scanned: %w", path, yaraErr)
		}
	}

	// The descriptor pins the identity, but its contents and the name can
	// still change. Recheck the bytes on the descriptor before returning
	// evidence and confirm that the reported path still identifies that file.
	if data == nil {
		changed := changedBeforeYara || streamChanged()
		if !changed && e.Yara != nil && fi.Size() != 0 {
			again, err := hashReader(io.NewSectionReader(f, 0, res.Size))
			changed = err != nil || again != d || streamChanged()
		}
		after, err := os.Stat(path)
		if changed || err != nil || !sameStreamVersion(fi, after) {
			res.Error = fmt.Errorf("%s changed while it was scanned", path)
			res.Warnings = append(res.Warnings, res.Error.Error())
			res.Detected = false
			res.MatchType, res.MatchHash, res.ThreatName = "", "", ""
			res.YaraMatches = nil
			res.Verdict = VerdictError
			res.ScanTime = time.Since(start)
			return res, h
		}
	}

	// ── fusion ─────────────────────────────────────────
	if !e.NoFusion {
		res.Fusion = e.fuse(&res, h)
	}

	res.ScanTime = time.Since(start)
	return res, h
}

func sameStreamVersion(a, b os.FileInfo) bool {
	return os.SameFile(a, b) && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime()) &&
		fileChangeTime(a) == fileChangeTime(b)
}

// ScanDirectory returns every scan result in walk order. Use
// ScanDirectoryEach when the caller can consume results one at a time.
func (e *Engine) ScanDirectory(root string, progress func(done, total int, path string)) ([]ScanResult, []HeuristicResult) {
	results := make([]ScanResult, 0, 64)
	heur := make([]HeuristicResult, 0, 64)
	e.scanDirectoryEach(root, progress, func(res ScanResult, h *HeuristicResult) {
		results = append(results, res)
		if h != nil {
			heur = append(heur, *h)
		}
	})
	return results, heur
}

// ScanDirectoryEach visits results in lexical walk order, including errors
// from unreadable paths. At most a worker-sized queue of results waits for
// the visitor, which is called serially by the caller's goroutine.
func (e *Engine) ScanDirectoryEach(root string, visit func(ScanResult, *HeuristicResult)) {
	e.scanDirectoryEach(root, nil, visit)
}

func (e *Engine) scanDirectoryEach(root string, progress func(done, total int, path string), visit func(ScanResult, *HeuristicResult)) {
	type job struct {
		result ScanResult
		heur   *HeuristicResult
		ready  chan struct{}
	}
	workers := e.jobs()
	work := make(chan *job)
	ordered := make(chan *job, workers)
	cancel := make(chan struct{})
	defer close(cancel)
	var (
		found atomic.Int64
		wg    sync.WaitGroup
		mu    sync.Mutex
		done  int
	)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range work {
				if j.result.Error == nil {
					j.result, j.heur = e.ScanFile(j.result.FilePath)
				}
				if progress != nil {
					mu.Lock()
					done++
					progress(done, int(found.Load()), j.result.FilePath)
					mu.Unlock()
				}
				close(j.ready)
			}
		}()
	}
	add := func(path string, err error) error {
		j := &job{
			result: ScanResult{FilePath: path, Verdict: VerdictError, Error: err},
			ready:  make(chan struct{}),
		}
		found.Add(1)
		select {
		case ordered <- j:
		case <-cancel:
			return filepath.SkipAll
		}
		select {
		case work <- j:
			return nil
		case <-cancel:
			return filepath.SkipAll
		}
	}

	go func() {
		defer close(ordered)
		defer close(work)
		walkErr := filepath.WalkDir(safefs.WalkRoot(root), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				if stop := add(path, err); stop != nil {
					return stop
				}
				if d != nil && d.IsDir() {
					return filepath.SkipDir
				}
				return nil // keep walking
			}
			if d.IsDir() {
				return nil
			}
			mode := d.Type()
			if mode&os.ModeSymlink != 0 {
				if !e.FollowSymlinks {
					return nil
				}
				target, serr := os.Stat(path)
				if serr != nil || !target.Mode().IsRegular() {
					return nil // dangling, or a symlink to a directory: never follow
				}
			} else if !mode.IsRegular() {
				return nil // sockets, fifos, devices
			}
			return add(path, nil)
		})
		if walkErr != nil {
			_ = add(root, fmt.Errorf("directory walk failed: %w", walkErr)) // audit:ok cancellation can stop this final error from being delivered
		}
	}()
	for j := range ordered {
		<-j.ready
		visit(j.result, j.heur)
	}
	wg.Wait()
}

// SortResults orders results by path. ScanDirectory already returns walk
// order, which is lexical per directory; this is for callers that merged
// several roots.
func SortResults(results []ScanResult) {
	sort.SliceStable(results, func(i, j int) bool { return results[i].FilePath < results[j].FilePath })
}
