package shell

import (
	"slices"
	"testing"

	"cyberboar.dev/cyberboar/internal/fold"
)

// What a cmdlet parameter's value does, for TestPSCmdletParamsClassified.
const (
	psData    = "data the cmdlet computes with or sends: no path, no code"
	psNarrows = "narrows or names a part of the paths given to -Path, which are checked"
	psSession = "who or where it runs as: the paths it is given are still checked"
	psChecked = "checked by the analysis itself"
)

// psParamEffects says what every parameter of psCmdletSpecs that takes a
// value other than a path does. Shared names first, then Cmdlet.Param.
var psParamEffects = map[string]string{
	"Filter": psNarrows, "Include": psNarrows, "Exclude": psNarrows, "Stream": psNarrows,
	"Credential": psSession, "Encoding": psData, "InputObject": psData, "Delimiter": psData,
	"StackName": psData, "Description": psData, "Scope": psData,

	"Get-Content.ReadCount": psData, "Get-Content.TotalCount": psData, "Get-Content.Tail": psData,
	"Set-Content.Value": psData, "Add-Content.Value": psData, // the secrets check reads it
	"Out-File.Width":        psData,
	"Copy-Item.FromSession": psSession, "Copy-Item.ToSession": psSession,
	"New-Item.Name": psChecked, "New-Item.ItemType": psChecked, "New-Item.Value": psChecked, // psNewItem: link targets
	"Get-ChildItem.Depth": psData, "Get-ChildItem.Attributes": psData,
	"Test-Path.PathType": psData, "Test-Path.OlderThan": psData, "Test-Path.NewerThan": psData,
	"Get-ItemProperty.Name": psData,
	"Select-String.Pattern": psData, "Select-String.Context": psData, "Select-String.Culture": psData,
	"Get-FileHash.Algorithm": psData, "Get-FileHash.InputStream": psData, // a stream opened elsewhere on the line, checked there
	"Compress-Archive.CompressionLevel": psData,
	"Import-Csv.Header":                 psData,
	"Export-Csv.QuoteFields":            psData, "Export-Csv.UseQuotes": psData,
	"Invoke-Expression.Command":  psChecked, // inline code
	"Start-Process.ArgumentList": psChecked, "Start-Process.WorkingDirectory": psChecked,
	"Start-Process.Environment": psChecked, // psStartEnv
	"Start-Process.Verb":        psData,    // how FilePath, a checked program, is opened
	"Start-Process.WindowStyle": psData,
	"Set-Item.Value":            psChecked, // env: and function: paths take it (psEnvWord)
	"New-ItemProperty.Name":     psData, "New-ItemProperty.PropertyType": psData, "New-ItemProperty.Value": psData,
	"Set-ItemProperty.Name": psData, "Set-ItemProperty.Value": psData, "Set-ItemProperty.Type": psData,
	"Remove-ItemProperty.Name": psData, "Clear-ItemProperty.Name": psData,
	"Rename-ItemProperty.Name": psData, "Rename-ItemProperty.NewName": psData,
	"Get-ItemPropertyValue.Name": psData,
	"Set-Acl.AclObject":          psData,
	"Format-Hex.Count":           psData, "Format-Hex.Offset": psData,
	"Import-Clixml.Skip": psData, "Import-Clixml.First": psData,
	"Export-Clixml.Depth": psData,
	"Select-Xml.XPath":    psData, "Select-Xml.Xml": psData, "Select-Xml.Content": psData, "Select-Xml.Namespace": psData,
	"New-PSDrive.Name": psChecked, "New-PSDrive.PSProvider": psChecked, // any drive path becomes unknown
	"New-Object.TypeName": psChecked, "New-Object.ArgumentList": psChecked,
	"New-Object.Property": psChecked, "New-Object.ComObject": psChecked, // psNewObject
	"Set-Alias.Name": psChecked, "Set-Alias.Value": psChecked, "Set-Alias.Option": psData,
	"New-Alias.Name": psChecked, "New-Alias.Value": psChecked, "New-Alias.Option": psData,
}

func init() {
	for _, c := range []string{"Invoke-WebRequest", "Invoke-RestMethod"} {
		for _, p := range []string{"Method", "Body", "Headers", "ContentType", "UserAgent", "TimeoutSec",
			"Proxy", "MaximumRedirection", "Authentication", "Token", "WebSession"} {
			psParamEffects[c+"."+p] = psData
		}
		psParamEffects[c+".Uri"] = psChecked  // psWebURI: file: URLs and paths
		psParamEffects[c+".Form"] = psChecked // psWebForm: file objects
	}
}

// Every parameter of a bound cmdlet has a decision: a path or a switch,
// which the binder handles, a variable name (psNamedVariables), or an entry
// in psParamEffects. One added to the table without a decision fails here.
func TestPSCmdletParamsClassified(t *testing.T) {
	common := map[*psParam]bool{}
	for _, p := range psCommonParams.list {
		common[p] = true
	}
	seen := map[string]bool{}
	for _, s := range psCmdletSpecs {
		for _, p := range psCmdlets[fold.String(s.name)].list {
			key := s.name + "." + p.name
			seen[key] = true
			switch {
			case p.path || p.isSwitch || common[p] || slices.Contains(psVariableParams, p.name):
			case psParamEffects[key] != "":
			case psParamEffects[p.name] != "":
				seen[p.name] = true
			default:
				t.Errorf("%s -%s: no decision on what its value does (psParamEffects)", s.name, p.name)
			}
		}
	}
	for key := range psParamEffects {
		if !seen[key] {
			t.Errorf("psParamEffects lists %s, which no cmdlet has", key)
		}
	}
}
