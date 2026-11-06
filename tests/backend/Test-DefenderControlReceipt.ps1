# Pure synthetic wire validation only. NEVER dot-source/execute the controller.
# Kept outside npm test: no PowerShell/native launch occurs in that gate.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$source = Join-Path $PSScriptRoot '..\..\tools\backend\defender-control\Invoke-DefenderControl.ps1'
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'CONTROLLER_PARSE_FAILED' }
$function = $ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Test-CompletedReceipt'},$false)
if (!$function) { throw 'VALIDATOR_MISSING' }
# This one reviewed definition only uses strings/regex/base64; no filesystem,
# process, token, registry, P/Invoke or controller top-level statements execute.
. ([scriptblock]::Create($function.Extent.Text))
$id = '0123456789abcdef0123456789abcdef'
$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('{"AMRunningMode":"Normal","RealTimeProtectionEnabled":true}' + "`n"))
$template = '{"kind":"SecAppDefenderControlV1","run_id":"RUNID","outcome":"Completed","error":"NONE","backend_created":true,"backend_resumed":true,"backend_exit":0,"root_exited":true,"job_empty":true,"pipes_closed":true,"elapsed_ms":100,"stdout_base64":"PAYLOAD"}' + "`n"
$valid = $template.Replace('RUNID',$id).Replace('PAYLOAD',$encoded)
if (!(Test-CompletedReceipt $valid $id)) { throw 'POSITIVE_FAILED' }
if (!(Test-CompletedReceipt ($valid.Replace($encoded,'')) $id)) { throw 'EMPTY_OUTPUT_LIFECYCLE_FAILED' }
$negative = @(
    $valid.Replace('"job_empty":true','"job_empty":false,"job_empty":true'),
    $valid.Replace('"kind":"SecAppDefenderControlV1"','"kind":"Other"'),
    $valid.Replace('"outcome":"Completed"','"outcome":"Failed"'),
    $valid.Replace('"error":"NONE"','"error":"TIMEOUT"'),
    $valid.Replace('"backend_created":true','"backend_created":false'),
    $valid.Replace('"backend_resumed":true','"backend_resumed":false'),
    $valid.Replace('"backend_exit":0','"backend_exit":1'),
    $valid.Replace('"root_exited":true','"root_exited":false'),
    $valid.Replace('"job_empty":true','"job_empty":false'),
    $valid.Replace('"pipes_closed":true','"pipes_closed":false'),
    $valid.Replace('"elapsed_ms":100','"elapsed_ms":40000'),
    $valid.Replace('"elapsed_ms":100','"elapsed_ms":-1'),
    $valid.Replace('"elapsed_ms":100','"elapsed_ms":0100'),
    $valid.Replace($id,('f' * 32)),
    $valid.Replace($encoded,'=bad'),
    $valid.Replace($encoded,'Zh=='),
    $valid.Replace($encoded,([Convert]::ToBase64String((New-Object byte[] 4097)))),
    $valid.Replace('"kind":','"extra":true,"kind":'),
    $valid.TrimEnd("`n"),
    ($valid + 'tail'),
    ($valid + "`n"),
    (' ' + $valid),
    ('x' * 8193)
)
foreach ($text in $negative) { if (Test-CompletedReceipt $text $id) { throw 'NEGATIVE_ACCEPTED' } }
if (Test-CompletedReceipt $valid 'invalid') { throw 'ID_ACCEPTED' }
"PureReceiptVectors=$($negative.Count+3); Passed=True; NativeControllerExecuted=False"
