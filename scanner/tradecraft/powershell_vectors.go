package tradecraft

// This file carries the Windows script tradecraft the main vectors in
// script.go did not: the shapes a post-exploitation toolkit is made of that
// are neither a loader nor a shell.
//
// The catalog's rule decides every score here. Eight is a verdict by itself and
// is kept for behaviour with no ordinary use: a command assembled out of
// characters of unrelated strings, a per-user handler planted where an
// auto-elevating binary will read it, a boot sector written to a physical
// drive. Everything an administrator's script also does scores below eight and
// convicts only beside a second signal, however often an offensive toolkit
// does it: starting a process, forwarding a port, removing an update and
// taking a screenshot are all things a helpdesk script does on a Tuesday.
//
// That division was measured, not assumed. A first version of this file gave
// every shape here eight points so that each lab sample it was written from
// would convict alone. On the dev split that took the engine from 166 to 210
// of 222; on the held-out split, which shares no tool with dev, from 171 to
// 179 of 280 with one more false positive; and on 7,686 scripts from eighteen
// public administration repositories (PowerShell itself, Pester, dbatools,
// CSS-Exchange, Chocolatey packages and others) it took this pass from 8
// false verdicts to 63. One rule that asked for a Substring call, a -join and
// a ForEach-Object anywhere in a file accounted for 51 of them. A rule fitted
// to one sample describes the sample. docs/evaluation.md has the figures for
// the version that is here.
//
// Every vector names a behaviour and not a project, and where the behaviour
// has parts they are required close together (see vector.within): a listener
// in one function and a client in another are a module, not a relay.
//
// Nothing here scores an API name on its own. OpenProcess, ReadProcessMemory
// and SeDebugPrivilege are what the heuristic detector already counts, and the
// fusion lattice treats two detectors that agree as two pieces of evidence: a
// class here that counted the same names again turned psutil's own test file
// into a fused verdict.

// Windows script finding classes.
const (
	classPSLauncherAssembly = "tradecraft.script.runtime-command-assembly"
	classPSLoggingTamper    = "tradecraft.script.logging-tamper"
	classPSUACHijack        = "tradecraft.script.uac-bypass-registry"
	classPSWMISubscription  = "tradecraft.script.wmi-event-subscription"
	classPSAccessibility    = "tradecraft.script.accessibility-debugger"
	classPSCredentialBrute  = "tradecraft.script.credential-brute-force"
	classPSForcedAuth       = "tradecraft.script.shortcut-file-remote-fetch"
	classPSScriptConsole    = "tradecraft.script.app-server-script-console"
	classPSAppDeploy        = "tradecraft.script.app-server-deploy"
	classPSBootRecord       = "tradecraft.script.boot-record-overwrite"
	classPSDropAndRun       = "tradecraft.script.drop-and-run"

	classPSOutlookRule    = "tradecraft.script.outlook-rule-tampering"
	classPSVaultConfig    = "tradecraft.script.password-store-config"
	classPSIntercept      = "tradecraft.script.traffic-interception"
	classPSPortProxy      = "tradecraft.script.port-proxy"
	classPSPatchRemoval   = "tradecraft.script.silent-patch-removal"
	classPSLureShortcut   = "tradecraft.script.shortcut-to-interpreter"
	classPSTerminalHook   = "tradecraft.script.terminal-profile-hook"
	classPSScreenshotLoop = "tradecraft.script.timed-screenshot"
	classPSTcpRelay       = "tradecraft.script.tcp-relay"
)

func init() {
	for class, entry := range map[string]catalogEntry{
		// No ordinary use: each of these convicts alone.
		classPSLauncherAssembly: {8, "T1027.010", "the name of the command the script runs is assembled from characters of unrelated strings, so the command appears nowhere in the file"},
		classPSLoggingTamper:    {8, "T1562.002", "the script reaches into PowerShell's own logging state by reflection: script-block logging or the event provider is switched off from inside"},
		classPSUACHijack:        {8, "T1548.002", "the script plants a per-user handler under a class that an auto-elevating Windows binary opens: a UAC bypass"},
		classPSWMISubscription:  {8, "T1546.003", "the script binds a WMI event filter to a consumer that runs a command: persistence that survives without a file in any autostart location"},
		classPSAccessibility:    {8, "T1546.008", "the script sets a debugger for an accessibility program that runs at the logon screen, so pressing its hotkey starts something else as SYSTEM"},
		classPSCredentialBrute:  {8, "T1110", "the script walks a list of passwords and tries each one against an authentication interface"},
		classPSForcedAuth:       {8, "T1187", "the script writes a shell command file whose icon is on a remote share, so merely listing the folder makes Windows authenticate to that host"},
		classPSScriptConsole:    {8, "T1190", "the script posts a process-starting script to an application server's script console"},
		classPSAppDeploy:        {8, "T1190", "the script calls an application server's JMX deployer over HTTP to install an archive it names"},
		classPSBootRecord:       {8, "T1561.002", "the script writes a boot sector straight to a physical drive"},
		classPSDropAndRun:       {8, "T1027.009", "the script rebuilds a binary from text it carries or fetched, writes it to disk and starts it"},

		// Things administrators also do: each corroborates.
		classPSOutlookRule:    {6, "T1137.005", "the script creates a mailbox rule through Outlook's object model"},
		classPSVaultConfig:    {6, "T1555.005", "the script locates a password manager's configuration, key file and protected master key"},
		classPSIntercept:      {5, "T1557", "the script stands up an HTTP listener and mints a certificate authority it then trusts: the parts of a TLS interception point"},
		classPSPortProxy:      {5, "T1090.001", "the script installs a port forward with the Windows port proxy"},
		classPSPatchRemoval:   {5, "T1562.001", "the script uninstalls a numbered Windows update silently"},
		classPSLureShortcut:   {4, "T1204.002", "the script writes a shortcut that starts a script interpreter with arguments, minimised or under another program's icon"},
		classPSTerminalHook:   {4, "T1546", "the script rewrites the command line of a Windows Terminal profile"},
		classPSScreenshotLoop: {4, "T1113", "the script captures the screen in a loop with a pause between frames"},
		classPSTcpRelay:       {3, "T1090", "the script both accepts connections and opens its own: the two ends of a relay"},
	} {
		catalog[class] = entry
	}
	vectors = append(vectors, windowsScriptVectors...)
}

var windowsScriptVectors = []vector{
	// ── A command assembled from unrelated strings ──
	// Characters picked out of a variable the shell always defines, to spell a
	// command without writing it: $env:ComSpec[4,24,25]-join'' is "iex". One
	// index is how a script reads a drive letter, so there have to be several,
	// or two picks added together.
	v(classPSLauncherAssembly, "[", `\$(?:env:ComSpec|ShellId|PSHome|env:Public|VerbosePreference(?:\.ToString\(\))?)\s*\[\s*\d+\s*(?:,\s*\d+\s*)+\]`+
		`|\$(?:env:ComSpec|ShellId|PSHome|env:Public)\s*\[\s*\d+\s*\]\s*\+\s*\$(?:env:ComSpec|ShellId|PSHome|env:Public)\s*\[\s*\d+\s*\]`),
	// The same trick through a variable found by wildcard: the only variable
	// *mdr* matches is MaximumDriveCount, and it is asked for its name, not its
	// value, because the name holds the letters.
	v(classPSLauncherAssembly, "mdr", `(?:Get-Variable|\bGV\b|\bVariable:)[^\n]{0,24}\*mdr\*`),
	// The call operator applied to a command name glued from fragments. Member
	// access by a computed name ($x.('Na'+'me')) is ordinary, so the operator
	// has to start an expression rather than follow an object.
	v(classPSLauncherAssembly, "+", `(?:^|[\s;|({=])[&.]\s*\(\s*['"][a-z-]{1,8}['"]\s*\+\s*['"][a-z-]{1,8}['"]`),
	// Format strings whose placeholders are out of order and whose arguments
	// are fragments: "{2}{0}{1}" -f 'pres','sion','Invoke-Ex'. Once is
	// localisation; repeated, it is how a command is hidden from a string search.
	v(classPSLauncherAssembly, "-f", `['"]\{[1-9]\d?\}\{\d\d?\}(?:\{\d\d?\})*['"]\s*-f\s*['"]`).atLeast(2),

	// ── Logging switched off from inside ──
	// The fields are private, so reflection is the only way to them, and there
	// is no supported reason to go.
	v(classPSLoggingTamper, "getfield", `GetField\(\s*['"](?:cachedGroupPolicySettings|etwProvider|m_enabled)['"]`),

	// ── A handler planted for an auto-elevating binary ──
	// fodhelper, computerdefaults and eventvwr run elevated without a prompt
	// and open these classes from the user's own hive. Nothing else writes them.
	v(classPSUACHijack, "classes", `Classes\\+(?:ms-settings|mscfile)\\+shell\\+open\\+command`),

	// ── A WMI event subscription that runs a command ──
	// All three objects are needed for the subscription to exist, so all three
	// are required: a script that only queries __EventFilter is an inventory.
	v(classPSWMISubscription, "__eventfilter", `__EventFilter\b`, `\b(?:CommandLine|ActiveScript)EventConsumer\b`, `__FilterToConsumerBinding\b`),

	// ── A debugger set on a logon-screen accessibility program ──
	v(classPSAccessibility, "image file execution options",
		`Image File Execution Options\\+(?:sethc|utilman|osk|narrator|magnify|displayswitch|atbroker)\.exe`, `\bDebugger\b`).within(nearby),

	// ── A list of passwords tried one by one ──
	// The loop is over the passwords, which is what separates guessing from
	// using one: a script that validates the credential it was given has no
	// such loop. The attempt has to be in reach of the loop.
	v(classPSCredentialBrute, "foreach", `foreach\s*\(\s*\$\w+\s+in\s+(?:\$\w*(?:pass|pwd|wordlist|dictionary)\w*|\(?\s*Get-Content\s+\$\w*(?:pass|pwd|wordlist|dict)\w*)`,
		`ValidateCredentials\s*\(|DirectoryEntry\s*\(|["']Authorization["']|PSCredential\b|\bnet\s+use\b|New-PSSession\b|SqlConnection\b`).within(sameUnit),

	// ── A shell command file with its icon on a remote share ──
	// Explorer fetches the icon to draw the folder, and fetching it from a UNC
	// path is an authentication. This is the file's own syntax, so the file
	// itself matches as well as a script that writes one.
	v(classPSForcedAuth, "iconfile", `IconFile\s*=\s*\\\\`, `\[Shell\]`).within(nearby),

	// ── An application server's script console ──
	// The form field is the console's own, and what is posted to it starts a
	// process. URL-encoded or not, on one line.
	v(classPSScriptConsole, "script=", `\bscript=[^\n]{0,200}(?:ProcessBuilder|Runtime\.getRuntime|\.execute\s*\(|\.execute%28)`),

	// ── An archive deployed through a management console ──
	// The JMX console's HTTP adaptor is asked to invoke a deployer. A build
	// script that uploads a .war to Tomcat's manager is not this.
	v(classPSAppDeploy, "jmx-console", `jmx-console/HtmlAdaptor[^\n]{0,300}(?:MainDeployer|DeploymentFileRepository|BSHDeployer)`),

	// ── A boot sector written to a physical drive ──
	// The raw device, a write, and the two bytes every boot sector ends with.
	// The device path is often written inside another string, with its
	// backslashes doubled.
	v(classPSBootRecord, "physicaldrive", `\\{2,4}\.\\{1,2}PhysicalDrive`, `\bWriteFile\b`, `(?s)0x55\b.{0,200}?0xAA\b`),

	// ── A binary rebuilt from text, written out and started ──
	// The bytes come from text (a hex dump split on spaces, or base64), go to
	// a file, and the next thing the script does is run something. An
	// installer downloads a file; it does not carry or fetch one as text.
	v(classPSDropAndRun, "writeallbytes", `WriteAllBytes\s*\(`,
		`\[byte\[\]\]\s*\$\w+\s*=\s*\$\w+\s*-split|FromBase64String\s*\(`,
		`Start-Process\b|Invoke-Expression\b|\biex\b|Invoke-Item\b|Diagnostics\.Process\]::Start`).within(nearby),

	// ── A mailbox rule created through Outlook ──
	v(classPSOutlookRule, "getrules", `\.GetRules\s*\(\s*\)`, `\.Create\s*\(`, `\bOlRuleType\b|\bolRuleReceive\b`).within(sameUnit),

	// ── A password manager's key material ──
	// The protected master key has one name, and nothing but the manager and
	// a thief looks for it.
	v(classPSVaultConfig, "protecteduserkey", `ProtectedUserKey\.bin`),
	v(classPSVaultConfig, "keepass", `KeePass\.config\.xml`, `KeyFilePath|KeeKeySourceValue|TriggerSystem`),

	// ── The parts of a TLS interception point ──
	// A listener, a certificate marked as an authority, and the trusted-root
	// store. A developer's test server has the first and sometimes the second.
	v(classPSIntercept, "httplistener", `\bHttpListener\b`, `BasicConstraints|\bisCA\b`, `StoreName\]::Root|Cert:\\\w+\\Root\b|["']Root["']`),

	// ── A port forward installed in the stack ──
	v(classPSPortProxy, "portproxy", `\bnetsh\b[^\n]{0,120}\bportproxy\s+add\b[^\n]{0,200}\bconnectaddress\s*=`),

	// ── An update removed quietly ──
	v(classPSPatchRemoval, "wusa", `\bwusa(?:\.exe)?\b[^\n]{0,40}/uninstall\b[^\n]{0,120}/kb:[^\n]{0,80}/quiet`),

	// ── A shortcut to an interpreter, dressed as something else ──
	// The target is the interpreter itself, it is given arguments, and the
	// window is minimised or the icon borrowed. A shortcut to a program has a
	// program for its target.
	v(classPSLureShortcut, "targetpath", `\.TargetPath\s*=\s*["'][^"'\n]{0,80}(?:powershell|pwsh|cmd|mshta|wscript|cscript|rundll32|regsvr32)(?:\.exe)?["']`,
		`\.Arguments\s*=`, `\.WindowStyle\s*=\s*7\b|\.IconLocation\s*=`).within(nearby),

	// ── A terminal profile's command line rewritten ──
	v(classPSTerminalHook, "settings.json", `WindowsTerminal\w*\\LocalState\\settings\.json|Windows Terminal\\settings\.json`,
		`\bcommandline\b`, `ConvertTo-Json\b|Set-Content\b|Out-File\b`),

	// ── The screen captured on a timer ──
	v(classPSScreenshotLoop, "copyfromscreen", `\bCopyFromScreen\b`, `\bStart-Sleep\b`, `\b(?:while|do|for)\s*[({]`).within(sameUnit),

	// ── The two ends of a relay ──
	// The .NET namespace keeps this to .NET code: Python's listen and connect
	// are spelled the same and mean a test fixture far more often than a relay.
	// Even so a loopback test both listens and dials, which is why this only
	// corroborates.
	v(classPSTcpRelay, "net.sockets", `Net\.Sockets\b`, `\bAcceptTcpClient\b|\bAcceptSocket\b|\.BeginAccept\w*\s*\(|\.Listen\s*\(`,
		`New-Object\s+(?:System\.)?Net\.Sockets\.TcpClient\b|\.(?:Begin)?Connect\s*\(`),
}
