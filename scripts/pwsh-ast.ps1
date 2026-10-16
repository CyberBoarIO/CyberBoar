# Prints PowerShell's own syntax tree for each command line, in the form
# internal/engine/shell/pwsh's differential test compares with its parser
# (TestPowerShellDifferential, scripts/pwsh-differential.sh)
# It only parses: Parser.ParseInput builds a syntax tree and runs nothing
#
# Input: a JSON array of base64-encoded UTF-8 strings
# Output: one JSON object in UTF-8, {"version": ...,
# "results": [...]}, a result per input: {"ok": false} when PowerShell
# reports a parse error, else {"ok": true, "ast": "..."}, the tree written as
# Type@start-end{properties}(children), offsets in UTF-16 units and children
# in source order
# Works under Windows PowerShell 5.1 and PowerShell 7

param([Parameter(Mandatory = $true)][string]$InputPath)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false

# Q quotes s as a single-quoted string, escaping backslashes and quotes
function Q([string]$s) {
    "'" + $s.Replace('\', '\\').Replace("'", "\'") + "'"
}

# Get-Prop returns the named property of n, or $null when n lacks it
# Reading a missing property directly fails under Set-StrictMode
function Get-Prop($n, [string]$name) {
    $p = $n.PSObject.Properties[$name]
    if ($null -eq $p) { return $null }
    return $p.Value
}

# Get-Props returns the node's recorded properties as a string, or '' when the
# node type has none.
function Get-Props($n) {
    switch ($n.GetType().Name) {
        'StringConstantExpressionAst' { return (Q $n.Value) + ';' + $n.StringConstantType }
        'ExpandableStringExpressionAst' { return (Q $n.Value) + ';' + $n.StringConstantType }
        'ConstantExpressionAst' { return Q $n.Extent.Text }
        'VariableExpressionAst' { return (Q $n.VariablePath.UserPath) + ';' + $n.Splatted }
        'CommandParameterAst' { return Q $n.ParameterName }
        'CommandAst' { return [string]$n.InvocationOperator }
        'FileRedirectionAst' { return [string]$n.FromStream + ';' + $n.Append }
        'MergingRedirectionAst' { return [string]$n.FromStream + ';' + $n.ToStream }
        'BinaryExpressionAst' { return [string]$n.Operator }
        'UnaryExpressionAst' { return [string]$n.TokenKind }
        'AssignmentStatementAst' { return [string]$n.Operator }
        'MemberExpressionAst' { return [string]$n.Static }
        'InvokeMemberExpressionAst' { return [string]$n.Static }
        'TypeExpressionAst' { return Q $n.TypeName.FullName }
        'TypeConstraintAst' { return Q $n.TypeName.FullName }
        'AttributeAst' { return Q $n.TypeName.FullName }
        'NamedAttributeArgumentAst' { return (Q $n.ArgumentName) + ';' + $n.ExpressionOmitted }
        'PipelineAst' { return [string][bool](Get-Prop $n 'Background') }
        'PipelineChainAst' { return [string]$n.Operator + ';' + $n.Background }
        'FunctionDefinitionAst' { return (Q $n.Name) + ';' + $n.IsFilter }
        'NamedBlockAst' { return [string]$n.BlockKind + ';' + $n.Unnamed }
        'SwitchStatementAst' { return [string]$n.Flags }
    }
    return ''
}

# Get-Dump returns n and its children in the format described at the top
function Get-Dump($n) {
    $kids = @($n.FindAll({ param($c) [object]::ReferenceEquals($c.Parent, $n) }, $true) |
        Sort-Object { $_.Extent.StartOffset }, { $_.Extent.EndOffset })
    $s = $n.GetType().Name + '@' + $n.Extent.StartOffset + '-' + $n.Extent.EndOffset
    $p = Get-Props $n
    if ($p -ne '') { $s += '{' + $p + '}' }
    if ($kids.Count -gt 0) {
        $s += '(' + (($kids | ForEach-Object { Get-Dump $_ }) -join ' ') + ')'
    }
    return $s
}

$inputs = @(Get-Content -Raw -Encoding UTF8 -LiteralPath $InputPath | ConvertFrom-Json)
$out = New-Object System.Collections.Generic.List[object]
foreach ($b64 in $inputs) {
    $src = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String([string]$b64))
    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseInput($src, [ref]$tokens, [ref]$errors)
    if ($errors.Count -gt 0) {
        $out.Add([ordered]@{ ok = $false })
        continue
    }
    $out.Add([ordered]@{ ok = $true; ast = (Get-Dump $ast) })
}
ConvertTo-Json -InputObject ([ordered]@{ version = [string]$PSVersionTable.PSVersion; results = $out.ToArray() }) -Depth 5 -Compress
