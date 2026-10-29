package shell

import (
	"strings"

	"cyberboar.dev/cyberboar/internal/fold"
)

// The PowerShell cmdlets the analysis reads (docs/powershell.md). A cmdlet
// not listed here is read like a program: every word it is given is checked
// as a path, and if it takes input from a pipeline, that input may name any path

// psUse is what a cmdlet does with the paths it is given
type psUse int

const (
	psPrint  psUse = iota // only prints them (Write-Output)
	psNames               // reads a directory's names, not what it holds (Get-ChildItem)
	psRead                // reads the files (Get-Content)
	psWrite               // writes them (Set-Content)
	psModify              // deletes, moves or replaces them (Remove-Item)
)

// psParam is one parameter of a cmdlet
type psParam struct {
	name     string
	isSwitch bool
	path     bool // its value is a path
	wildcard bool // a path that may hold wildcards (-Path, not -LiteralPath)
	use      psUse
}

// psCmdlet is a cmdlet with the parameters the analysis binds
type psCmdlet struct {
	name string
	use  psUse
	// params are keyed by folded name and alias; list has each once, in order
	params     map[string]*psParam
	list       []*psParam
	names      []string // every folded name and alias, for prefix matching
	positional []string // the parameters bound by position, in order
	// pipePaths: input from a pipeline may bind to a path parameter
	pipePaths bool
}

// psCommon are the common parameters every cmdlet takes
const psCommon = "Verbose=vb! Debug=db! ErrorAction=ea WarningAction=wa InformationAction=infa ProgressAction=proga " +
	"ErrorVariable=ev WarningVariable=wv InformationVariable=iv OutVariable=ov OutBuffer=ob PipelineVariable=pv " +
	"WhatIf=wi! Confirm=cf! UseTransaction=usetx!"

// psPathParams are the path parameters most file cmdlets share
const psPathParams = "Path* LiteralPath=PSPath,LP@ Filter Include Exclude Credential "

// psCmdletSpecs lists each cmdlet with its aliases and parameters. A
// parameter is written Name=alias,alias, then "*" for a path that may hold
// wildcards, "@" for a literal path or "!" for a switch, and nothing for
// another value. A path parameter may end in n, r, w or m when only its
// name is read, or it is read, written or modified, instead of what the
// cmdlet does with the others
var psCmdletSpecs = []struct {
	name, aliases, params, positional string
	use                               psUse
	pipePaths                         bool
}{
	{"Get-Content", "gc cat type", psPathParams + "ReadCount TotalCount=First,Head Tail=Last Delimiter Force! Raw! Wait! Encoding AsByteStream! Stream", "Path", psRead, true},
	{"Set-Content", "", psPathParams + "Value Force! PassThru! NoNewline! Encoding AsByteStream! Stream", "Path Value", psWrite, true},
	{"Add-Content", "ac", psPathParams + "Value Force! PassThru! NoNewline! Encoding AsByteStream! Stream", "Path Value", psWrite, true},
	{"Clear-Content", "clc", psPathParams + "Force! Stream", "Path", psWrite, true},
	{"Out-File", "", "FilePath=Path@ LiteralPath=PSPath,LP@ Encoding Append! Force! NoClobber=NoOverwrite! Width NoNewline! InputObject", "FilePath Encoding", psWrite, false},
	{"Tee-Object", "tee", "FilePath=Path@ LiteralPath=PSPath,LP@ Append! Encoding Variable InputObject", "FilePath", psWrite, false},
	{"Remove-Item", "rm del erase rd rmdir ri", psPathParams + "Recurse! Force! Stream", "Path", psModify, true},
	{"Move-Item", "mv move mi", psPathParams + "Destination@ Force! PassThru!", "Path Destination", psModify, true},
	{"Rename-Item", "ren rni", "Path@ LiteralPath=PSPath,LP@ NewName@ Force! PassThru! Credential", "Path NewName", psModify, true},
	{"Copy-Item", "cp copy cpi", "Path*r LiteralPath=PSPath,LP@r Filter Include Exclude Credential Destination@m Container! Force! Recurse! PassThru! FromSession ToSession", "Path Destination", psRead, true},
	{"New-Item", "ni mkdir md", "Path@ Name ItemType=Type Value=Target Force! Credential", "Path", psWrite, true},
	{"Get-ChildItem", "gci ls dir", psPathParams + "Recurse=s! Depth Force! Name! Attributes FollowSymlink! Directory=ad,d! File=af! Hidden=ah,h! ReadOnly=ar! System=as!", "Path Filter", psNames, true},
	{"Get-Item", "gi", psPathParams + "Force! Stream", "Path", psNames, true},
	{"Test-Path", "", psPathParams + "PathType=Type IsValid! OlderThan NewerThan", "Path", psNames, true},
	{"Resolve-Path", "rvpa", "Path* LiteralPath=PSPath,LP@ Relative! RelativeBasePath@ Credential", "Path", psNames, true},
	{"Get-ItemProperty", "gp", psPathParams + "Name", "Path Name", psNames, true},
	{"Select-String", "sls", "Pattern Path* LiteralPath=PSPath,LP@ InputObject SimpleMatch! CaseSensitive! Quiet! List! NoEmphasis! Include Exclude NotMatch! AllMatches! Encoding Context Raw! Culture", "Pattern Path", psRead, true},
	{"Get-FileHash", "", "Path* LiteralPath=PSPath,LP@ Algorithm InputStream", "Path Algorithm", psRead, true},
	{"Expand-Archive", "", "Path* LiteralPath=PSPath,LP@ DestinationPath@m Force! PassThru!", "Path DestinationPath", psRead, true},
	{"Compress-Archive", "", "Path* LiteralPath=PSPath,LP@ DestinationPath@w CompressionLevel Update! Force! PassThru!", "Path DestinationPath", psRead, true},
	{"Import-Csv", "ipcsv", "Path* LiteralPath=PSPath,LP@ Delimiter UseCulture! Header Encoding", "Path Delimiter", psRead, true},
	{"Export-Csv", "epcsv", "Path@ LiteralPath=PSPath,LP@ InputObject Force! NoClobber=NoOverwrite! Encoding Append! Delimiter UseCulture! IncludeTypeInformation=ITI! NoTypeInformation=NTI! QuoteFields=QF UseQuotes=UQ NoHeader!", "Path Delimiter", psWrite, false},
	{"Set-Location", "cd chdir sl", "Path* LiteralPath=PSPath,LP@ PassThru! StackName", "Path", psNames, true},
	{"Push-Location", "pushd", "Path* LiteralPath=PSPath,LP@ PassThru! StackName", "Path", psNames, true},
	{"Pop-Location", "popd", "PassThru! StackName", "", psNames, false},
	{"Invoke-WebRequest", "iwr", "Uri OutFile@w InFile@r Method Body Headers ContentType UserAgent TimeoutSec UseBasicParsing! SkipCertificateCheck! PassThru! Proxy Form MaximumRedirection Resume! SkipHttpErrorCheck! Authentication Token WebSession SessionVariable=SV Credential", "Uri", psPrint, false},
	{"Invoke-RestMethod", "irm", "Uri OutFile@w InFile@r Method Body Headers ContentType UserAgent TimeoutSec UseBasicParsing! SkipCertificateCheck! PassThru! Proxy Form MaximumRedirection Resume! SkipHttpErrorCheck! Authentication Token WebSession SessionVariable=SV Credential ResponseHeadersVariable=RHV StatusCodeVariable", "Uri", psPrint, false},
	{"Start-Process", "saps start", "FilePath=PSPath,Path@r ArgumentList=Args Credential WorkingDirectory Verb WindowStyle RedirectStandardError=RSE@w RedirectStandardInput=RSI@r RedirectStandardOutput=RSO@w Environment LoadUserProfile=Lup! NoNewWindow=nnw! PassThru! UseNewEnvironment! Wait!", "FilePath ArgumentList", psRead, false},
	{"Invoke-Expression", "iex", "Command", "Command", psPrint, false},
	{"Invoke-Item", "ii", psPathParams, "Path", psRead, true},
	{"Set-Item", "si", psPathParams + "Value Force! PassThru!", "Path Value", psWrite, true},
	{"Clear-Item", "cli", psPathParams + "Force!", "Path", psWrite, true},
	{"New-ItemProperty", "", psPathParams + "Name PropertyType=Type Value Force!", "Path Name Value", psWrite, true},
	{"Set-ItemProperty", "sp", psPathParams + "Name Value Type InputObject Force! PassThru!", "Path Name Value", psWrite, true},
	{"Remove-ItemProperty", "rp", psPathParams + "Name Force!", "Path Name", psWrite, true},
	{"Clear-ItemProperty", "clp", psPathParams + "Name Force! PassThru!", "Path Name", psWrite, true},
	{"Rename-ItemProperty", "rnp", psPathParams + "Name NewName Force! PassThru!", "Path Name NewName", psWrite, true},
	{"Get-ItemPropertyValue", "gpv", psPathParams + "Name", "Path Name", psNames, true},
	{"Convert-Path", "cvpa", "Path* LiteralPath=PSPath,LP@", "Path", psNames, true},
	{"Get-Acl", "", psPathParams + "InputObject AllCentralAccessPolicies! Audit!", "Path", psNames, true},
	{"Set-Acl", "", psPathParams + "AclObject InputObject ClearCentralAccessPolicy! PassThru!", "Path AclObject", psModify, true},
	{"Unblock-File", "", "Path* LiteralPath=PSPath,LP@", "Path", psWrite, true},
	{"Format-Hex", "fhx", "Path* LiteralPath=PSPath,LP@ InputObject Encoding Count Offset Raw!", "Path", psRead, true},
	{"Import-Clixml", "", "Path* LiteralPath=PSPath,LP@ IncludeTotalCount! Skip First", "Path", psRead, true},
	{"Export-Clixml", "", "Path@ LiteralPath=PSPath,LP@ InputObject Depth Force! NoClobber=NoOverwrite! Encoding", "Path", psWrite, false},
	{"Import-PowerShellDataFile", "", "Path* LiteralPath=PSPath,LP@ SkipLimitCheck!", "Path", psRead, true},
	{"Select-Xml", "", "XPath Path* LiteralPath=PSPath,LP@ Xml Content Namespace", "XPath Path", psRead, true},
	{"Start-Transcript", "", "Path@ LiteralPath=PSPath,LP@ OutputDirectory@ Append! Force! NoClobber=NoOverwrite! IncludeInvocationHeader! UseMinimalHeader!", "Path", psWrite, false},
	{"New-PSDrive", "ndr mount", "Name PSProvider Root@n Description Scope Persist! Credential", "Name PSProvider Root", psPrint, false},
	{"New-Object", "", "TypeName ArgumentList=Args Property ComObject Strict!", "TypeName ArgumentList", psPrint, false},
	{"Set-Alias", "sal", "Name Value Description Option PassThru! Scope Force!", "Name Value", psPrint, false},
	{"New-Alias", "nal", "Name Value Description Option PassThru! Scope Force!", "Name Value", psPrint, false},
}

// psPrintCmdlets only print or compute with what they are given. Their
// words are checked like echo's: against deny and ask rules alone
var psPrintCmdlets = []struct{ name, aliases string }{
	{"Write-Output", "echo write"}, {"Write-Host", ""}, {"Write-Error", ""}, {"Write-Warning", ""},
	{"Write-Verbose", ""}, {"Write-Debug", ""}, {"Write-Information", ""}, {"Write-Progress", ""},
	{"Out-Host", "oh"}, {"Out-Null", ""}, {"Out-String", ""}, {"Out-Default", ""},
	{"Format-Table", "ft"}, {"Format-List", "fl"}, {"Format-Wide", "fw"}, {"Format-Custom", "fc"},
	{"Select-Object", "select"}, {"Where-Object", "where ?"}, {"ForEach-Object", "foreach %"}, {"Sort-Object", "sort"},
	{"Measure-Object", "measure"}, {"Group-Object", "group"}, {"Get-Unique", "gu"},
	{"Compare-Object", "compare diff"}, {"Get-Date", ""}, {"Start-Sleep", "sleep"},
	{"Get-Command", "gcm"}, {"Get-Help", "man"}, {"Get-Member", "gm"}, {"Get-Variable", "gv"},
	{"Get-Location", "gl pwd"}, {"Get-Process", "gps ps"}, {"Get-Host", ""}, {"Get-Random", ""},
	{"Get-Culture", ""}, {"Get-Uptime", ""}, {"ConvertTo-Json", ""}, {"ConvertFrom-Json", ""},
	{"ConvertTo-Csv", ""}, {"ConvertFrom-Csv", ""}, {"ConvertFrom-StringData", ""},
	{"Join-Path", ""}, {"Split-Path", ""}, {"Clear-Host", "cls clear"}, {"New-Guid", ""},
	{"Get-History", "h history ghy"}, {"Get-Alias", "gal"}, {"Get-PSDrive", "gdr"},
	{"Get-Service", "gsv"}, {"Get-ExecutionPolicy", ""},
}

// psUnixAliases are aliases PowerShell defines only on Windows: elsewhere
// these names run the programs
var psUnixAliases = set("cat", "cp", "ls", "man", "mv", "ps", "rm", "rmdir", "sleep", "sort", "tee", "write", "diff", "clear", "mkdir", "mount")

// psLegacyAliases are aliases only Windows PowerShell 5.1 defines; in
// PowerShell 7 these names run the programs. Both readings are checked
var psLegacyAliases = map[string]string{"curl": "Invoke-WebRequest", "wget": "Invoke-WebRequest", "sc": "Set-Content"}

var (
	psCmdlets = map[string]*psCmdlet{} // keyed by folded name
	psAliases = map[string]string{}    // folded alias to the cmdlet's name
)

func init() {
	common := psParseParams(psCommon, psPrint)
	for _, s := range psCmdletSpecs {
		c := &psCmdlet{name: s.name, use: s.use, params: map[string]*psParam{}, pipePaths: s.pipePaths}
		for _, p := range append(psParseParams(s.params, s.use), common...) {
			c.list = append(c.list, p.param)
			for _, n := range p.keys {
				c.params[n] = p.param
				c.names = append(c.names, n)
			}
		}
		c.positional = strings.Fields(s.positional)
		psAddCmdlet(c, s.aliases)
	}
	for _, s := range psPrintCmdlets {
		psAddCmdlet(&psCmdlet{name: s.name, use: psPrint}, s.aliases)
	}
	for _, p := range common {
		psCommonParams.list = append(psCommonParams.list, p.param)
		for _, n := range p.keys {
			psCommonParams.params[n] = p.param
			psCommonParams.names = append(psCommonParams.names, n)
		}
	}
}

// psCommonParams has the common parameters alone, to find them among the
// arguments of a cmdlet whose others aren't bound
var psCommonParams = &psCmdlet{name: "common parameters", params: map[string]*psParam{}}

func psAddCmdlet(c *psCmdlet, aliases string) {
	psCmdlets[fold.String(c.name)] = c
	for _, al := range strings.Fields(aliases) {
		psAliases[fold.String(al)] = c.name
	}
}

type psParamKeys struct {
	param *psParam
	keys  []string
}

// psParseParams reads a parameter list written as psCmdletSpecs describes
func psParseParams(spec string, use psUse) []psParamKeys {
	var out []psParamKeys
	for _, f := range strings.Fields(spec) {
		p := &psParam{use: use}
		if u, ok := map[byte]psUse{'n': psNames, 'r': psRead, 'w': psWrite, 'm': psModify}[f[len(f)-1]]; ok {
			if n := len(f); n > 1 && (f[n-2] == '*' || f[n-2] == '@') {
				p.use = u
				f = f[:n-1]
			}
		}
		switch f[len(f)-1] {
		case '!':
			p.isSwitch = true
		case '*':
			p.path, p.wildcard = true, true
		case '@':
			p.path = true
		}
		f = strings.TrimRight(f, "!*@")
		name, aliases, _ := strings.Cut(f, "=")
		p.name = name
		keys := []string{fold.String(name)}
		for _, al := range strings.Split(aliases, ",") {
			if al != "" {
				keys = append(keys, fold.String(al))
			}
		}
		out = append(out, psParamKeys{p, keys})
	}
	return out
}

// param finds the parameter -name names: by its name or an alias, or by a
// prefix of exactly one of them, as PowerShell's binder does. nil when no
// parameter or more than one matches
func (c *psCmdlet) param(name string) *psParam {
	n := fold.String(name)
	if p, ok := c.params[n]; ok {
		return p
	}
	var found *psParam
	for _, k := range c.names {
		if strings.HasPrefix(k, n) {
			if found != nil && found != c.params[k] {
				return nil
			}
			found = c.params[k]
		}
	}
	return found
}

// psVerbs are PowerShell's approved verbs (Get-Verb). A name made of one of
// them, "-" and a noun is a cmdlet or function, not a program
var psVerbs = set("add", "approve", "assert", "backup", "block", "build", "checkpoint", "clear", "close", "compare",
	"complete", "compress", "confirm", "connect", "convert", "convertfrom", "convertto", "copy", "debug", "deny",
	"deploy", "disable", "disconnect", "dismount", "edit", "enable", "enter", "exit", "expand", "export", "find",
	"format", "get", "grant", "group", "hide", "import", "initialize", "install", "invoke", "join", "limit", "lock",
	"measure", "merge", "mount", "move", "new", "open", "optimize", "out", "ping", "pop", "protect", "publish",
	"push", "read", "receive", "redo", "register", "remove", "rename", "repair", "request", "reset", "resize",
	"resolve", "restart", "restore", "resume", "revoke", "save", "search", "select", "send", "set", "show", "skip",
	"split", "start", "step", "stop", "submit", "suspend", "switch", "sync", "test", "trace", "unblock", "undo",
	"uninstall", "unlock", "unprotect", "unpublish", "unregister", "update", "use", "wait", "watch", "where",
	"foreach", "sort", "tee", "write")

// psModifyVerbs are the verbs of cmdlets that may delete, move or replace
// what they are given
var psModifyVerbs = set("clear", "move", "remove", "rename", "reset", "set", "uninstall", "unregister")

// psVerbNoun reports a name shaped like a cmdlet's, Verb-Noun, and its verb
func psVerbNoun(name string) (verb string, ok bool) {
	v, noun, found := strings.Cut(fold.String(name), "-")
	if !found || noun == "" || !psVerbs[v] {
		return "", false
	}
	return v, true
}

// psSafeTypes are .NET types whose static members only compute: their
// methods read or change no file and run no code. nil allows every method
var psSafeTypes = map[string]map[string]bool{
	"math": nil, "string": nil, "char": nil, "int": nil, "int16": nil, "int32": nil, "int64": nil, "long": nil,
	"uint32": nil, "uint64": nil, "double": nil, "single": nil, "float": nil, "decimal": nil, "bool": nil,
	"boolean": nil, "byte": nil, "datetime": nil, "datetimeoffset": nil, "timespan": nil, "guid": nil,
	"convert": nil, "bitconverter": nil, "text.encoding": nil, "regex": nil,
	"text.regularexpressions.regex": nil, "version": nil, "uri": nil, "array": nil, "enum": nil,
	"globalization.cultureinfo": nil, "cultureinfo": nil, "stringcomparer": nil,
	"io.path": set("combine", "getfilename", "getfilenamewithoutextension", "getextension", "getdirectoryname",
		"getfullpath", "ispathrooted", "changeextension", "gettemppath", "getrelativepath", "join",
		"getinvalidfilenamechars", "getinvalidpathchars", "hasextension", "getpathroot", "trimendingdirectoryseparator"),
	"environment":                           set("getenvironmentvariable", "getenvironmentvariables", "getfolderpath", "getlogicaldrives"),
	"management.automation.wildcardpattern": set("escape", "containswildcardcharacters", "unescape"),
	"wildcardpattern":                       set("escape", "containswildcardcharacters", "unescape"),
}

// psSafeType reports whether a static call of method on type t only computes
func psSafeType(t, method string) bool {
	t = strings.TrimPrefix(fold.String(t), "system.")
	methods, ok := psSafeTypes[t]
	return ok && (methods == nil || methods[fold.String(method)])
}

// psCodeMethods are instance methods that run code they are given or that
// the object holds: script blocks and the engine's own entry points
var psCodeMethods = set("invoke", "invokereturnasis", "invokewithcontext", "invokescript", "newscriptblock",
	"expandstring", "getnewclosure", "addscript", "addcommand", "begininvoke")

// psSafeMethods are instance methods that only compute on the strings,
// numbers and collections they are called on
var psSafeMethods = set("trim", "trimstart", "trimend", "tostring", "toupper", "tolower", "toupperinvariant",
	"tolowerinvariant", "split", "replace", "substring", "contains", "startswith", "endswith", "indexof",
	"indexofany", "lastindexof", "lastindexofany", "padleft", "padright", "equals", "gettype", "compareto",
	"insert", "normalize", "tochararray", "gethashcode", "containskey", "containsvalue", "add", "addrange",
	"toarray", "getenumerator", "match", "matches", "ismatch", "format", "join", "getvalue", "getbytes",
	"getstring", "isnullorempty", "isnullorwhitespace", "where", "count")
