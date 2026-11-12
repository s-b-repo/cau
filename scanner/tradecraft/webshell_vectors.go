package tradecraft

// This file carries the web shells that never call an execution function.
//
// A web shell is a page whose capability is chosen by the request. The vectors
// in script.go cover the common capability, running a command. Two more appear
// in real toolkits and need no exec sink at all:
//
//   - the page fetches a URL the request chose and sends the body back, which
//     makes the server a proxy into whatever network it can reach;
//   - the page resolves a name the request chose, which makes it a resolver
//     for the same network.
//
// Both are followed the way the exec shape is, by a textual taint walk from the
// request to the call. A third shape rides along with them: the page compares
// the visitor's address with a hard-coded list and answers 404 to everyone
// else, which is how a toolkit keeps a scanner from finding its pages.
//
// Reading a file the request named is not a shell. An admin panel's file
// editor does it behind a permission check, and a first version of the fetch
// check convicted WordPress's theme editor for it. The fetch only counts when
// the page also parses the request value as a URL or passes the upstream's
// headers on, which are the proxy's own steps and not the editor's. The resolver and the gate each have an ordinary
// reading, so neither convicts alone.

import (
	"regexp"
	"strings"
)

// Web-shell finding classes.
const (
	classPHPURLFetch = "tradecraft.webshell.php-request-url-fetch"
	classPHPDNSQuery = "tradecraft.webshell.php-request-dns-query"
	classPHPIPGate   = "tradecraft.webshell.php-ip-allowlist-gate"
	classASPURLFetch = "tradecraft.webshell.asp-request-url-fetch"
)

func init() {
	catalog[classPHPURLFetch] = catalogEntry{8, "T1505.003", "a request parameter is parsed as a URL, fetched by the server and streamed back: the page is a proxy into the server's network"}
	catalog[classASPURLFetch] = catalogEntry{8, "T1505.003", "a request parameter becomes the URL an XMLHTTP object fetches, and the answer is written back: the page is a proxy into the server's network"}
	catalog[classPHPDNSQuery] = catalogEntry{6, "T1505.003", "a request parameter chooses the name the page resolves: the server answers DNS questions on request"}
	catalog[classPHPIPGate] = catalogEntry{4, "T1505.003", "the page answers only a hard-coded list of client addresses and refuses everyone else"}
}

// taintWalk is a textual walk from request input to a call, for one language.
// It is not a parser: it knows nothing of scope, so a name tainted in one
// function is tainted in all of them, and it knows nothing of sanitisers. That
// errs toward reporting, which suits a check whose finding is "the request
// reaches this call".
type taintWalk struct {
	assign *regexp.Regexp // group 1 the name assigned, group 2 the expression
	source *regexp.Regexp // request input
	name   *regexp.Regexp // group 1 a variable name in an expression
	fold   bool           // names are case-insensitive
}

func (t taintWalk) key(name string) string {
	if t.fold {
		return strings.ToLower(name)
	}
	return name
}

// tainted returns the names that carry request input. Assignments are followed
// for a few rounds, because the common shape is two hops deep:
// `$url = $_GET['u']; $full = buildurl($url); fopen($full)`.
func (t taintWalk) tainted(text string) map[string]bool {
	tainted := map[string]bool{}
	assigns := t.assign.FindAllStringSubmatch(text, 4096)
	for pass := 0; pass < 3; pass++ {
		for _, a := range assigns {
			name := t.key(a[1])
			if tainted[name] {
				continue
			}
			rhs := a[2]
			hit := t.source.MatchString(rhs)
			for _, m := range t.name.FindAllStringSubmatch(rhs, -1) {
				hit = hit || tainted[t.key(m[1])]
			}
			if hit {
				tainted[name] = true
			}
		}
	}
	return tainted
}

// reaches reports the first call to sink that is handed request input, either
// directly or through a tainted name. sink captures the call's arguments; an
// expression with alternatives captures them in whichever group took part.
func (t taintWalk) reaches(text string, sink *regexp.Regexp, tainted map[string]bool) string {
	for _, m := range sink.FindAllStringSubmatch(text, 1024) {
		args := strings.Join(m[1:], " ")
		if t.source.MatchString(args) {
			return trunc(m[0], 120)
		}
		for _, n := range t.name.FindAllStringSubmatch(args, -1) {
			if tainted[t.key(n[1])] {
				return trunc(m[0], 120)
			}
		}
	}
	return ""
}

var (
	phpWalk = taintWalk{
		assign: regexp.MustCompile(`\$(\w+)\s*=\s*([^;\n]{0,400})`),
		source: rx(reqSuper),
		name:   regexp.MustCompile(`\$(\w+)`),
	}
	// Classic ASP is VBScript: one statement a line, names without a sigil and
	// without case. Only the collections a client fills count as the request;
	// ServerVariables is mostly the server describing itself.
	aspWalk = taintWalk{
		assign: regexp.MustCompile(`(?im)^[ \t]*(?:set[ \t]+)?([a-z_]\w*)[ \t]*=[ \t]*([^\n]{1,400})`),
		source: regexp.MustCompile(`(?i)\brequest(?:\.(?:querystring|form|cookies))?\s*\(`),
		name:   regexp.MustCompile(`\b([A-Za-z_]\w*)\b`),
		fold:   true,
	}

	// Where a PHP page opens something to read. curl takes its URL either at
	// creation or as an option.
	phpFetchSink = rx(`\b(?:fopen|file_get_contents|curl_init)\s*\(([^;\n]{0,300})|\bcurl_setopt\s*\(\s*[^,\n]{1,60},\s*CURLOPT_URL\s*,([^;\n]{0,300})`)
	// Where a PHP page treats a value as a URL.
	phpURLParse = rx(`\bparse_url\s*\(([^;\n]{0,300})`)
	// Where a page re-emits headers it holds in a variable: the upstream's
	// headers, passed on. A page of its own sets headers it wrote itself.
	phpHeaderReplay = rx(`\bheader\s*\(\s*\$\w+\s*[\[,)]`)
	// Where a fetched body goes back to the client.
	phpStreamOut = rx(`\b(?:fpassthru|readfile|fread|stream_get_contents|curl_exec)\s*\(`)
	// Where a PHP page resolves a name.
	phpDNSSink = rx(`\b(?:dns_get_record|checkdnsrr|gethostbynamel?|gethostbyaddr)\s*\(([^;\n]{0,300})`)

	// The allow-list gate: the visitor's address compared with something, a
	// hard-coded array with an address in it, and a refusal.
	phpIPGate   = rx(`\$_SERVER\s*\[\s*["']REMOTE_ADDR["']\s*\]\s*[!=]==?`)
	phpIPList   = rx(`\$\w+\s*=\s*(?:array\s*\(|\[)\s*["']\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}["']`)
	phpIPRefuse = rx(`\b404\b[^\n]{0,80}\n?[^\n]{0,80}\b(?:die|exit)\b|\b(?:die|exit)\s*\(\s*\)\s*;`)

	// Where a classic ASP page fetches: the object, and the call that names
	// the URL. Open takes the method first, so the URL is what follows it.
	aspXMLHTTP   = rx(`\bCreateObject\s*\(\s*["'](?:MSXML2|Microsoft)\.(?:Server)?XMLHTTP(?:\.\d\.\d)?["']\s*\)`)
	aspOpenSink  = rx(`\.Open\b[ \t(]*[^,\n]{1,60},([^\n]{1,300})`)
	aspStreamOut = rx(`\bResponse\s*\.\s*(?:Write|BinaryWrite)\b`)
)

// scanRequestFlows runs the web-shell checks that are a flow rather than a
// pattern: request input reaching a fetch or a resolver, and the address gate.
func (w *walker) scanRequestFlows(text, origin string) {
	if strings.Contains(text, "$_") { // PHP's superglobals have one spelling
		w.scanPHPFlows(text, origin)
	}
	if aspXMLHTTP.MatchString(text) {
		tainted := aspWalk.tainted(text)
		if ev := aspWalk.reaches(text, aspOpenSink, tainted); ev != "" && aspStreamOut.MatchString(text) {
			w.add(classASPURLFetch, catalog[classASPURLFetch], origin, ev)
		}
	}
}

func (w *walker) scanPHPFlows(text, origin string) {
	tainted := phpWalk.tainted(text)
	if ev := phpTaintedExec(text, tainted); ev != "" {
		w.add(classPHPTaintExec, catalog[classPHPTaintExec], origin, ev)
	}
	// The proxy: something the request chose is opened and a body is streamed
	// out, and the page does one of the two things only a relay does with it:
	// parse the request value as a URL, or pass the upstream's headers on.
	if ev := phpWalk.reaches(text, phpFetchSink, tainted); ev != "" && phpStreamOut.MatchString(text) &&
		(phpWalk.reaches(text, phpURLParse, tainted) != "" || phpHeaderReplay.MatchString(text)) {
		w.add(classPHPURLFetch, catalog[classPHPURLFetch], origin, ev)
	}
	if ev := phpWalk.reaches(text, phpDNSSink, tainted); ev != "" {
		w.add(classPHPDNSQuery, catalog[classPHPDNSQuery], origin, ev)
	}
	// All three parts of the gate are required, so a page that logs the
	// visitor's address, or one that keeps a list of addresses, is not one.
	if loc := phpIPGate.FindStringIndex(text); loc != nil && phpIPList.MatchString(text) && phpIPRefuse.MatchString(text) {
		w.add(classPHPIPGate, catalog[classPHPIPGate], origin, trunc(text[loc[0]:loc[1]], 120))
	}
}

var (
	phpSinkArg = rx(phpSink + `([^;\n]{0,300})`)
	// assert() was an eval for strings, and is now how every typed codebase
	// states an invariant. An argument that is a test is the second use.
	phpAssertCall = rx(`\bassert\s*\(`)
	phpAssertTest = rx(`\binstanceof\b|[!=<>]=|[<>]|\bis_\w+\s*\(|\bisset\s*\(|\bnull\b|\bcount\s*\(`)
)

// phpTaintedExec follows request input through assignments to an exec sink, for
// the shape `$c = $_GET['x']; system($c);` that a same-expression check misses.
// A line that launders input through escapeshellarg still reports. That is the
// right way to be wrong here, because the sink running attacker-shaped input is
// the finding.
func phpTaintedExec(text string, tainted map[string]bool) string {
	if len(tainted) == 0 {
		return ""
	}
	for _, m := range phpSinkArg.FindAllStringSubmatch(text, 1024) {
		if phpAssertCall.MatchString(m[0]) && phpAssertTest.MatchString(m[1]) {
			continue
		}
		for _, n := range phpWalk.name.FindAllStringSubmatch(m[1], -1) {
			if tainted[n[1]] {
				return trunc(m[0], 120)
			}
		}
	}
	return ""
}
