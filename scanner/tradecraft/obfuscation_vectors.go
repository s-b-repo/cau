package tradecraft

// This file carries the two PowerShell obfuscation shapes the command-assembly
// class does not cover: a command carried in variables whose names are made of
// punctuation, and a script that is parsed into a syntax tree and rewritten
// rather than encoded.
//
// Both score eight, which is a verdict on its own, and both earn it by being
// shapes no administration script has. A variable named "${;}" is not a name
// anyone types, and a script that names the syntax-tree types one by one and
// walks the tree is not doing administration. The parts have to sit together
// (see vector.within), because a file that mentions a syntax tree in one
// function and a command name in another is a library.
//
// The punctuation variable is the tight one, and the way it is tight matters:
// the name has to be *entirely* punctuation. The shell's own `${(f)name}` and
// `${+name}` forms are not, and a rule that matched them would fire on every
// zsh completion file on the machine.

const (
	classPSPunctuationName = "tradecraft.script.punctuation-variable-command"
	classPSASTRewrite      = "tradecraft.script.ast-rewrite"
)

func init() {
	catalog[classPSPunctuationName] = catalogEntry{8, "T1027.010", "the command is carried in variables whose names are made of punctuation, so no name in the file reads as a command"}
	catalog[classPSASTRewrite] = catalogEntry{8, "T1027.010", "the script parses another script into a syntax tree and rewrites it: obfuscation by construction rather than by encoding"}
	vectors = append(vectors, obfuscationVectors...)
}

var obfuscationVectors = []vector{
	// A variable whose whole name is punctuation. The characters of the
	// command are carried in ${;} and ${=} and the like, so the command is
	// nowhere in the file as a string, and the reassembly and the execution
	// have to be there too.
	v(classPSPunctuationName, "$", `\$\{[;=&@.\[\]()|]{1,2}\}`,
		`(?i)\biex\b|Invoke-Expression|\[ScriptBlock\]::Create`,
		`(?i)-join\b|ForEach-Object\b|Get-Random\b`).within(600),

	// The script is parsed and rewritten: it names the node types it will
	// rewrite, one by one, and walks the tree. The anchor is the syntax-tree
	// namespace, and it has to appear more than once, because a script that
	// *reads* a tree — a linter, a formatter — names two types and stops.
	// The node types are named as strings, which is what a table of types to
	// rewrite looks like and what a type check does not.
	v(classPSASTRewrite, "automation.language", `System\.Management\.Automation\.Language\.`,
		`['"]System\.Management\.Automation\.Language\.\w+Ast['"]`,
		`(?i)FindAll\s*\(|\.Extent\b|SafeGetValue|Get-Ast`).atLeast(3).within(2000),
}
