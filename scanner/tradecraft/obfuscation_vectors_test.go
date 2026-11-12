package tradecraft

import "testing"

// The two obfuscation shapes that are not "a command assembled from unrelated
// strings" have to convict on their own, and they have to stay away from the
// ordinary things that resemble them.

func TestPunctuationVariableCommand(t *testing.T) {
	src := "$VariableInstantiation += '${;} = + $( ) ; ${=} = ${;} ; ${+} = ++ ${;} '\n" +
		"${[Char]} = '${;} = \"[\"'\n" +
		"$Iex = '${;} = \"$( @{ } ) \"[ ${+}${[} ]'\n" +
		"$SetupCommand = $VariableInstantiation + ${[Char]} + $Iex\n" +
		"$SetupCommand = '( ' + \"'$RandomString'\" + ' | % { ' + $SetupCommand + ' ) ; '\n" +
		"$x = Get-Random -Input @('a','b')\n"
	r := Analyze([]byte(src), Options{})
	if !has(r, classPSPunctuationName) {
		t.Fatalf("no %s in %+v", classPSPunctuationName, r.Findings)
	}
	if !r.Detected() {
		t.Fatalf("score %d below threshold: %+v", r.Score, r.Findings)
	}
}

func TestASTRewrite(t *testing.T) {
	src := "$Ast = Get-Ast -ScriptString $ScriptString\n" +
		"[System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.CommandAst'," +
		"'System.Management.Automation.Language.AssignmentStatementAst',\n" +
		"'System.Management.Automation.Language.BinaryExpressionAst')\n" +
		"$Ast.FindAll({$args[0] -is [System.Management.Automation.Language.CommandAst]}, $true)\n" +
		"$Ast.Extent.Text = $Ast.Extent.Text -replace 'x','y'\n"
	r := Analyze([]byte(src), Options{})
	if !has(r, classPSASTRewrite) {
		t.Fatalf("no %s in %+v", classPSASTRewrite, r.Findings)
	}
}

// A script that reads a syntax tree — a linter, a formatter — names two node
// types and stops, and must not be read as rewriting one.
func TestASTReaderStaysQuiet(t *testing.T) {
	src := "$ast = [System.Management.Automation.Language.Parser]::ParseInput($src, [ref]$t, [ref]$e)\n" +
		"$ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.Extent.Text }\n"
	r := Analyze([]byte(src), Options{})
	if has(r, classPSASTRewrite) {
		t.Fatalf("false positive: %+v", r.Findings)
	}
}

// The shell's own parameter expansion must not be read as a PowerShell
// variable with a punctuation name: `${(f)name}` is zsh, `${+name}` is "is it
// set", and a rule that matched them would fire on every completion file on
// the machine.
func TestShellParameterExpansionStaysQuiet(t *testing.T) {
	for _, src := range []string{
		"print -r -- ${(f)\"$(echo hi)\"}\n",
		"echo ${+named}\n",
		"local x=${(P)name}\n",
		"typeset -A map; map[${key}]=1\n",
	} {
		r := Analyze([]byte(src), Options{})
		if has(r, classPSPunctuationName) {
			t.Fatalf("shell expansion matched: %+v", r.Findings)
		}
	}
}

// The syntax-tree namespace is in no administration script, and a file that
// only mentions it is not obfuscating anything.
func TestASTNamespaceAloneStaysQuiet(t *testing.T) {
	for _, src := range []string{
		"$t = [System.Management.Automation.Language.Parser]::ParseInput($code, [ref]$null, [ref]$null)\n",
		"# System.Management.Automation.Language.CommandAst is the type to look for\n",
	} {
		r := Analyze([]byte(src), Options{})
		if has(r, classPSASTRewrite) {
			t.Fatalf("false positive: %+v", r.Findings)
		}
	}
}
