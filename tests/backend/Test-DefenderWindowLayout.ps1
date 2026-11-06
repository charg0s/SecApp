# Synthetic layout construction only: no window show, UI automation, controller,
# identity/registry reads, native compiler, helper, backend or UAC.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$sourcePath = Join-Path $PSScriptRoot '../../tools/ui/Show-DefenderWindow.ps1'
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($sourcePath, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'WINDOW_PARSE_FAILED' }
$source = [IO.File]::ReadAllText($sourcePath, [Text.Encoding]::UTF8)
$start = $source.IndexOf('$form = New-Object Windows.Forms.Form', [StringComparison]::Ordinal)
$end = $source.IndexOf('function Show-Failure', [StringComparison]::Ordinal)
if ($start -lt 0 -or $end -le $start) { throw 'LAYOUT_BOUNDARY' }
$layoutSource = $source.Substring($start, $end - $start)
if ($layoutSource -match 'ShowDialog|Test-ExistingEventSource|Send-Command|Start-Process|ReadAsync') { throw 'LAYOUT_EFFECT' }
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
try {
    . ([scriptblock]::Create($layoutSource))
    if ($layout.RowCount -ne 7 -or $buttons.Controls.Count -ne 4) { throw 'LAYOUT_SHAPE' }
    if (!$details.ReadOnly -or !$details.Multiline -or $answer.MaxLength -ne 64) { throw 'LAYOUT_INPUT' }
    if ($tabs.TabPages.Count -ne 2 -or !$reportView.ReadOnly) { throw 'LAYOUT_REPORT' }
    if ($primary.Enabled -or $save.Enabled -or $cancel.Enabled -or $answer.Enabled) { throw 'LAYOUT_INITIAL_AUTHORITY' }
    if ($form.MinimumSize.Width -lt 740 -or $form.MinimumSize.Height -lt 650) { throw 'LAYOUT_MIN_SIZE' }
    if ($form.Visible) { throw 'LAYOUT_UNEXPECTED_VISIBILITY' }
    # Exercise only the pure view update on these never-shown controls. No input
    # handlers, file dialog, registry, pipe reads or external-window automation.
    $update = @($ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Apply-State' }, $true))
    if ($update.Count -ne 1) { throw 'VIEW_UPDATE_BOUNDARY' }
    . ([scriptblock]::Create($update[0].Extent.Text))
    $script:state = 'Connecting'; $script:closeAfterDiscard = $false; $script:html = $null
    $message = [pscustomobject]@{ kind='SecAppDesktopStateV1'; state='Ready'; text='SYNTHETIC'; code=$null; reportHtml=$null; reportText=$null }
    Apply-State $message
    if (!$primary.Enabled -or $answer.Enabled -or $save.Enabled) { throw 'VIEW_READY' }
    $message.state = 'AwaitingConfirmation'; Apply-State $message
    if (!$answer.Enabled -or !$cancel.Enabled -or !$primary.Enabled) { throw 'VIEW_CONFIRMATION' }
    $message.state = 'Running'; Apply-State $message
    if ($primary.Enabled -or $cancel.Enabled -or $answer.Enabled -or $close.Enabled) { throw 'VIEW_RUNNING' }
    $message.state = 'Finished'; $message.code = 0; $message.reportText = 'SYNTHETIC REPORT'; $message.reportHtml = '<!doctype html><title>SYNTHETIC</title>'
    Apply-State $message
    if (!$save.Enabled -or $reportView.Text -ne 'SYNTHETIC REPORT' -or $tabs.SelectedTab -ne $reportPage) { throw 'VIEW_REPORT' }
    $message.state = 'Failed'; $message.code = 1; $message.reportHtml = $null; $message.reportText = $null
    Apply-State $message
    if ($save.Enabled -or !$close.Enabled -or $null -ne $script:html) { throw 'VIEW_FAILED' }
    $message.state = 'Forged'; $rejected = $false
    try { Apply-State $message } catch { $rejected = $true }
    if (!$rejected) { throw 'VIEW_UNKNOWN_STATE' }
    if ($form.Visible) { throw 'VIEW_UNEXPECTED_VISIBILITY' }
    'WINPS51_LAYOUT_AND_VIEW_STATES_OK'
} finally { if ($null -ne (Get-Variable form -ErrorAction SilentlyContinue)) { $form.Dispose() } }
