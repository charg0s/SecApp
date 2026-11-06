# Explicit single-operation development controller. Never called by npm test.
# Compile-only does not invoke the helper. RunPrepared requires a separate explicit
# switch and the reviewed helper hash; no automatic retry or installation.
[CmdletBinding(DefaultParameterSetName = 'Compile')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Compile')][switch]$CompileOnly,
    [Parameter(Mandatory = $true, ParameterSetName = 'Run')][ValidatePattern('^[0-9a-f]{32}$')][string]$RunPrepared,
    [Parameter(Mandatory = $true, ParameterSetName = 'Discard')][ValidatePattern('^[0-9a-f]{32}$')][string]$DiscardPrepared,
    [Parameter(Mandatory = $true, ParameterSetName = 'Run')]
    [Parameter(Mandatory = $true, ParameterSetName = 'Discard')][ValidatePattern('^[0-9a-f]{64}$')][string]$ExpectedHelperSha256,
    [Parameter(ParameterSetName = 'Run')][switch]$CleanupOnSuccess
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$utf8 = New-Object System.Text.UTF8Encoding($false, $true)
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$sid = $identity.User.Value
$trusted = @($sid, 'S-1-5-18', 'S-1-5-32-544')
$locks = New-Object 'System.Collections.Generic.List[System.IDisposable]'
$helper = $null
$directory = $null
$runAttempted = $false
$finished = $false
$bridge = $null
$namespaceFailure = $null
$runId = $null
$workspaceCreated = $false
# Fixed development location, outside AppData/MSIX per-package redirection.
# Only the NEW GUID child receives a security descriptor; never this parent.
$workspaceRoot = 'C:\Dev'
$operationLock = $null
$preparedNames = @('DefenderControl.cs', 'Workspace.cs', 'require-administrator.manifest', 'SecAppDefenderControl.exe', 'velociraptor.exe', 'build.json')

# Define only the required Win32 imports in memory. This avoids Add-Type/CodeDOM
# compiler files in an inherited public TEMP before a private workspace exists.
function Initialize-FilesystemBridge {
    $name = New-Object Reflection.AssemblyName('SecApp.ControlFs')
    $assembly = [AppDomain]::CurrentDomain.DefineDynamicAssembly($name, [Reflection.Emit.AssemblyBuilderAccess]::Run)
    $module = $assembly.DefineDynamicModule('ControlFs')
    $type = $module.DefineType('SecApp.ControlFs.Native', [Reflection.TypeAttributes]'Public,Abstract,Sealed')
    $methods = @(
        @('CreateDirectoryW', [bool], [type[]]@([string],[IntPtr])),
        @('CreateFileW', [IntPtr], [type[]]@([string],[uint32],[uint32],[IntPtr],[uint32],[uint32],[IntPtr])),
        @('GetFileInformationByHandle', [bool], [type[]]@([IntPtr],[IntPtr])),
        @('GetFinalPathNameByHandleW', [uint32], [type[]]@([IntPtr],[Text.StringBuilder],[uint32],[uint32])),
        @('GetVolumeInformationW', [bool], [type[]]@([string],[Text.StringBuilder],[uint32],[IntPtr],[IntPtr],[IntPtr],[Text.StringBuilder],[uint32]))
    )
    foreach ($definition in $methods) {
        $method = $type.DefinePInvokeMethod($definition[0], 'kernel32.dll', $definition[0],
            [Reflection.MethodAttributes]'Public,Static,PinvokeImpl', [Reflection.CallingConventions]::Standard,
            $definition[1], $definition[2], [Runtime.InteropServices.CallingConvention]::Winapi,
            [Runtime.InteropServices.CharSet]::Unicode)
        $method.SetImplementationFlags([Reflection.MethodImplAttributes]::PreserveSig)
    }
    return $type.CreateType()
}

function Hold-DirectoryChain([string]$Path) {
    $full = [IO.Path]::GetFullPath($Path)
    if ($full.Length -ge 240 -or $full -notmatch '^[A-Za-z]:\\' -or $full.Substring(2).Contains(':')) { throw 'NAMESPACE_LOCAL_PATH' }
    $root = [IO.Path]::GetPathRoot($full)
    $drive = New-Object IO.DriveInfo($root)
    if ($drive.DriveType -ne [IO.DriveType]::Fixed) { throw 'NAMESPACE_LOCAL_DRIVE' }
    $volume = [Runtime.InteropServices.Marshal]::AllocHGlobal(12)
    try {
        if (!$bridge::GetVolumeInformationW($root, $null, 0, $volume, [IntPtr]::Add($volume,4), [IntPtr]::Add($volume,8), $null, 0) -or
            ([Runtime.InteropServices.Marshal]::ReadInt32($volume,8) -band 8) -eq 0) { throw 'PERSISTENT_ACLS_REQUIRED' }
    } finally { [Runtime.InteropServices.Marshal]::FreeHGlobal($volume) }
    $paths = New-Object 'System.Collections.Generic.List[string]'
    for ($cursor=$full; $cursor; $cursor=[IO.Path]::GetDirectoryName($cursor)) { $paths.Add($cursor) }
    $paths.Reverse()
    $index = 0
    foreach ($current in $paths) {
        # LIST_DIRECTORY participates in sharing checks; metadata-only access does not.
        $raw = $bridge::CreateFileW($current, 0x81, 3, [IntPtr]::Zero, 3, 0x02200000, [IntPtr]::Zero)
        $held = New-Object Microsoft.Win32.SafeHandles.SafeFileHandle($raw, $true)
        $locks.Add($held)
        if ($held.IsInvalid) { throw 'NAMESPACE_LOCK' }
        $info = [Runtime.InteropServices.Marshal]::AllocHGlobal(52)
        try {
            if (!$bridge::GetFileInformationByHandle($raw, $info)) { throw 'NAMESPACE_INFO' }
            $attributes = [Runtime.InteropServices.Marshal]::ReadInt32($info)
            if (($attributes -band 0x10) -eq 0 -or ($attributes -band 0x400) -ne 0) { throw 'NAMESPACE_REPARSE_OR_TYPE' }
        } finally { [Runtime.InteropServices.Marshal]::FreeHGlobal($info) }
        $final = New-Object Text.StringBuilder(512)
        $length = $bridge::GetFinalPathNameByHandleW($raw, $final, 512, 0)
        if ($length -eq 0) { throw 'NAMESPACE_FINAL_QUERY' }
        if ($length -ge 512) { throw 'NAMESPACE_FINAL_LIMIT' }
        if ($final.Length -eq 0) { throw 'NAMESPACE_FINAL_MARSHAL' }
        $actual = $final.ToString().TrimEnd('\')
        $expected = ('\\?\'+$current).TrimEnd('\')
        if (![string]::Equals($actual, $expected, [StringComparison]::OrdinalIgnoreCase)) {
            $common = 0
            while ($common -lt [Math]::Min($actual.Length,$expected.Length) -and [char]::ToUpperInvariant($actual[$common]) -eq [char]::ToUpperInvariant($expected[$common])) { $common++ }
            # Numeric diagnostics only: never disclose the path or native message.
            $script:namespaceFailure = @{ancestor_index=$index; actual_length=$actual.Length; expected_length=$expected.Length; common_prefix_length=$common}
            throw 'NAMESPACE_FINAL_PATH'
        }
        $index++
    }
}

function New-PrivateWorkspace([string]$Path) {
    $sddl = 'O:'+$sid+'D:P(A;OICI;FA;;;'+$sid+')(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
    $security = New-Object Security.AccessControl.RawSecurityDescriptor($sddl)
    $bytes = New-Object byte[] $security.BinaryLength
    $security.GetBinaryForm($bytes,0)
    $descriptor = [Runtime.InteropServices.Marshal]::AllocHGlobal($bytes.Length)
    $attributes = [Runtime.InteropServices.Marshal]::AllocHGlobal(24)
    try {
        [Runtime.InteropServices.Marshal]::Copy($bytes,0,$descriptor,$bytes.Length)
        [Runtime.InteropServices.Marshal]::Copy((New-Object byte[] 24),0,$attributes,24)
        [Runtime.InteropServices.Marshal]::WriteInt32($attributes,0,24)
        [Runtime.InteropServices.Marshal]::WriteIntPtr($attributes,8,$descriptor)
        # Existing name => refusal. No Set-Acl / ACL setter / repair operation.
        if (!$bridge::CreateDirectoryW($Path,$attributes)) { throw 'WORKSPACE_CREATE_NEW' }
        $script:workspaceCreated = $true
    } finally {
        [Runtime.InteropServices.Marshal]::FreeHGlobal($attributes)
        [Runtime.InteropServices.Marshal]::FreeHGlobal($descriptor)
    }
    Hold-DirectoryChain $Path
    Assert-PrivateWorkspace $Path
    if ([IO.Directory]::GetFileSystemEntries($Path).Length -ne 0) { throw 'WORKSPACE_NOT_EMPTY' }
}

function Assert-PrivateWorkspace([string]$Path) {
    Assert-Private $Path $true
    $acl = [IO.Directory]::GetAccessControl($Path)
    if (!$acl.AreAccessRulesProtected -or $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $sid) { throw 'WORKSPACE_OWNER_OR_INHERITANCE' }
    $rules = $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])
    $remaining = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($trustee in $trusted) { $null = $remaining.Add($trustee) }
    if ($rules.Count -ne 3) { throw 'WORKSPACE_ACL_COUNT' }
    foreach ($rule in $rules) {
        if ($rule.IsInherited -or $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            $rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl -or
            $rule.InheritanceFlags -ne [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit' -or
            $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None -or
            !$remaining.Remove($rule.IdentityReference.Value)) { throw 'WORKSPACE_ACL' }
    }
    if ($remaining.Count -ne 0) { throw 'WORKSPACE_ACL' }
}

function Assert-LocalPath([string]$Path) {
    $full = [IO.Path]::GetFullPath($Path)
    if ($full.Length -ge 240 -or $full -notmatch '^[A-Za-z]:\\' -or $full.Substring(2).Contains(':')) { throw 'LOCAL_PATH' }
    $cursor = $full
    while ($cursor) {
        if (([IO.File]::GetAttributes($cursor) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'REPARSE_PATH' }
        $cursor = [IO.Path]::GetDirectoryName($cursor)
    }
    $drive = New-Object IO.DriveInfo([IO.Path]::GetPathRoot($full))
    if ($drive.DriveType -ne [IO.DriveType]::Fixed) { throw 'LOCAL_DRIVE' }
}
function Assert-Private([string]$Path, [bool]$IsDirectory) {
    Assert-LocalPath $Path
    if ($IsDirectory) { $acl = [IO.Directory]::GetAccessControl($Path) }
    else { $acl = [IO.File]::GetAccessControl($Path) }
    $descriptor = New-Object Security.AccessControl.RawSecurityDescriptor($acl.GetSecurityDescriptorBinaryForm(), 0)
    if ($null -eq $descriptor.DiscretionaryAcl -or $null -eq $descriptor.Owner -or $trusted -notcontains $descriptor.Owner.Value) { throw 'PRIVATE_OWNER_OR_DACL' }
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
            ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -eq 0 -and
            $trusted -notcontains $rule.IdentityReference.Value) { throw 'PRIVATE_ACCESS' }
    }
}
function New-FixedFile([string]$Path, [byte[]]$Bytes) {
    $file = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $file.Write($Bytes, 0, $Bytes.Length); $file.Flush($true) } finally { $file.Dispose() }
}
function Hash-Stream([IO.Stream]$Stream) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $Stream.Position = 0; $hash = $sha.ComputeHash($Stream); $Stream.Position = 0; return [BitConverter]::ToString($hash).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}
function Lock-File([string]$Path) {
    Assert-Private $Path $false
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $locks.Add($stream)
    Assert-Private $Path $false
    return $stream
}
function Bounded-Read([string]$Path, [int]$Limit) {
    $file = Lock-File $Path
    if ($file.Length -gt $Limit) { throw 'INPUT_LIMIT' }
    $bytes = New-Object byte[] ($Limit + 1)
    $count = 0
    do { $n = $file.Read($bytes, $count, $bytes.Length - $count); $count += $n } while ($n -gt 0 -and $count -lt $bytes.Length)
    if ($count -gt $Limit) { throw 'INPUT_LIMIT' }
    return $utf8.GetString($bytes, 0, $count)
}
function Lock-Operation {
    $path = Join-Path $directory 'controller.lock'
    Assert-Private $path $false
    $script:operationLock = [IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    $locks.Add($operationLock)
    if ($operationLock.Length -ne 0) { throw 'CONTROLLER_LOCK_INVALID' }
}
function Test-CompletedReceipt([string]$Text, [string]$Id) {
    # Match the helper's EXACT bounded wire grammar, not ConvertFrom-Json's
    # last-key-wins representation. Used only with an observed helper exit 0.
    if ($Text.Length -gt 8192 -or $Id -cnotmatch '\A[0-9a-f]{32}\z') { return $false }
    $pattern = '\A\{"kind":"SecAppDefenderControlV1","run_id":"' + $Id + '","outcome":"Completed","error":"NONE","backend_created":true,"backend_resumed":true,"backend_exit":0,"root_exited":true,"job_empty":true,"pipes_closed":true,"elapsed_ms":(0|[1-9][0-9]{0,4}),"stdout_base64":"([A-Za-z0-9+/]{0,5464}={0,2})"\}\n\z'
    $match = [regex]::Match($Text,$pattern)
    if (!$match.Success -or [int]$match.Groups[1].Value -ge 40000) { return $false }
    $bytes = $null
    try {
        $encoded = $match.Groups[2].Value
        $bytes = [Convert]::FromBase64String($encoded)
        return $bytes.Length -le 4096 -and [Convert]::ToBase64String($bytes) -ceq $encoded
    } catch { return $false }
    finally { if ($bytes) { [Array]::Clear($bytes,0,$bytes.Length) } }
}
function Remove-OwnedDataFiles([string[]]$Names) {
    # Namespace leases and the exclusive operation lock remain held throughout.
    # Deliberately keep the directory and zero-byte lock: no delete-after-unlock
    # race, recursive deletion, unknown-file deletion or existing-ACL changes.
    if (!$operationLock -or !$operationLock.CanRead) { throw 'CLEANUP_LOCK_REQUIRED' }
    if ([IO.Path]::GetFullPath($directory) -cne (Join-Path $workspaceRoot ('SecApp-Control-' + $runId))) { throw 'CLEANUP_BOUNDARY' }
    Assert-PrivateWorkspace $directory
    $expected = @($Names) + @('controller.lock')
    $entries = @(Get-ChildItem -LiteralPath $directory -Force)
    if ($entries.Count -ne $expected.Count) { throw 'CLEANUP_UNKNOWN_ENTRY' }
    foreach ($entry in $entries) {
        if ($entry.PSIsContainer -or $expected -cnotcontains $entry.Name) { throw 'CLEANUP_UNKNOWN_ENTRY' }
        Assert-Private $entry.FullName $false
    }
    foreach ($held in $locks) { if ($held -is [IO.FileStream] -and ![object]::ReferenceEquals($held,$operationLock)) { $held.Dispose() } }
    foreach ($name in $Names) {
        if ($preparedNames -cnotcontains $name -and @('attempted.once','secapp-empty.config.yaml','result.json','cancel.request') -cnotcontains $name) { throw 'CLEANUP_NAME' }
        [IO.File]::Delete((Join-Path $directory $name))
    }
    $remaining = @(Get-ChildItem -LiteralPath $directory -Force)
    if ($remaining.Count -ne 1 -or $remaining[0].Name -cne 'controller.lock') { throw 'CLEANUP_NOT_CONFIRMED' }
}
try {
    if (![Environment]::Is64BitProcess) { throw 'X64_REQUIRED' }
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'ORDINARY_CONTROLLER_REQUIRED' }
    $bridge = Initialize-FilesystemBridge
    Hold-DirectoryChain $workspaceRoot
    $runId = if ($CompileOnly) { [Guid]::NewGuid().ToString('N') } elseif ($DiscardPrepared) { $DiscardPrepared } else { $RunPrepared }
    $directory = Join-Path $workspaceRoot ('SecApp-Control-' + $runId)
    $image = Join-Path $directory 'SecAppDefenderControl.exe'
    if ($CompileOnly) {
        New-PrivateWorkspace $directory
        New-FixedFile (Join-Path $directory 'controller.lock') (New-Object byte[] 0)
        Lock-Operation
        foreach ($name in @('DefenderControl.cs', 'Workspace.cs', 'require-administrator.manifest')) {
            $source = Join-Path $PSScriptRoot $name
            $input = [IO.File]::Open($source,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
            try {
                if ($input.Length -gt 131072) { throw 'SOURCE_LIMIT' }
                $output = [IO.File]::Open((Join-Path $directory $name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
                try { $input.CopyTo($output,65536); $output.Flush($true) } finally { $output.Dispose() }
            } finally { $input.Dispose() }
        }
        $windows = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
        $framework = Join-Path $windows 'Microsoft.NET\Framework64\v4.0.30319'
        $compiler = Join-Path $framework 'csc.exe'
        Assert-LocalPath $compiler
        $start = New-Object Diagnostics.ProcessStartInfo
        $start.FileName = $compiler; $start.UseShellExecute = $false; $start.CreateNoWindow = $true
        $start.WorkingDirectory = $directory
        $start.RedirectStandardOutput = $true; $start.RedirectStandardError = $true
        $start.EnvironmentVariables.Clear()
        $start.EnvironmentVariables['SystemRoot'] = $windows; $start.EnvironmentVariables['WINDIR'] = $windows
        $start.EnvironmentVariables['TEMP'] = $directory; $start.EnvironmentVariables['TMP'] = $directory
        $references = @('mscorlib.dll', 'System.dll', 'System.Core.dll') | ForEach-Object { '/reference:"' + (Join-Path $framework $_) + '"' }
        $start.Arguments = '/nologo /noconfig /nostdlib+ /target:exe /platform:x64 /checked+ /optimize+ /debug- /warn:4 /warnaserror+ /out:SecAppDefenderControl.exe /win32manifest:require-administrator.manifest ' + ($references -join ' ') + ' DefenderControl.cs Workspace.cs'
        $compilerProcess = New-Object Diagnostics.Process; $compilerProcess.StartInfo = $start
        try {
            $null = $compilerProcess.Start()
            # Bounded asynchronous reads: check the limit before retaining more.
            $outBuffer = New-Object char[] 32769; $errBuffer = New-Object char[] 32769
            $outCount = 0; $errCount = 0; $outEnd = $false; $errEnd = $false
            $outTask = $compilerProcess.StandardOutput.ReadAsync($outBuffer, 0, $outBuffer.Length)
            $errTask = $compilerProcess.StandardError.ReadAsync($errBuffer, 0, $errBuffer.Length)
            $timer = [Diagnostics.Stopwatch]::StartNew()
            while (!$outEnd -or !$errEnd -or !$compilerProcess.HasExited) {
                if ($timer.ElapsedMilliseconds -ge 20000) { throw 'COMPILE_TIMEOUT' }
                if (!$outEnd -and $outTask.IsCompleted) {
                    $n = $outTask.Result; $outCount += $n
                    if ($outCount -gt 32768) { throw 'COMPILER_OUTPUT_LIMIT' }
                    if ($n -eq 0) { $outEnd = $true }
                    else { $outTask = $compilerProcess.StandardOutput.ReadAsync($outBuffer, $outCount, $outBuffer.Length - $outCount) }
                }
                if (!$errEnd -and $errTask.IsCompleted) {
                    $n = $errTask.Result; $errCount += $n
                    if ($errCount -gt 32768) { throw 'COMPILER_OUTPUT_LIMIT' }
                    if ($n -eq 0) { $errEnd = $true }
                    else { $errTask = $compilerProcess.StandardError.ReadAsync($errBuffer, $errCount, $errBuffer.Length - $errCount) }
                }
                Start-Sleep -Milliseconds 10
            }
            $diagnostic = [string]::new($outBuffer, 0, $outCount) + [string]::new($errBuffer, 0, $errCount)
            if ($compilerProcess.ExitCode -ne 0) {
                $codes = @([regex]::Matches($diagnostic, '\((\d+),(\d+)\): (?:error|warning) (CS\d+)') | ForEach-Object {
                    @{line=[int]$_.Groups[1].Value; column=[int]$_.Groups[2].Value; code=$_.Groups[3].Value}
                })
                @{outcome='CompileFailed'; diagnostics=$codes} | ConvertTo-Json -Depth 4 -Compress
                exit 1
            }
        } finally {
            if (!$compilerProcess.HasExited) { $compilerProcess.Kill(); $null = $compilerProcess.WaitForExit(3000) }
            $compilerProcess.Dispose()
        }
        $local = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
        $acquisition = Join-Path $local 'SecApp\backend-acquisition-v0.77.3-20261106'
        $original = Join-Path $acquisition 'velociraptor-v0.77.3-windows-amd64.exe'
        Assert-LocalPath $original
        # The acquisition path may be OS-virtualized. Only these locked, pinned
        # bytes are copied; the source is NEVER executed or used by the helper.
        $source = [IO.File]::Open($original,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        $locks.Add($source)
        $backendHash = '3d20a5a2d272e3eb2bccae4a80ebe469fc1a6f63eb4a8f8a586dbae356437d32'
        if ($source.Length -ne 73422840 -or (Hash-Stream $source) -cne $backendHash) { throw 'BACKEND_PIN' }
        # Streaming CREATE_NEW: never transfer source ACLs to the private copy.
        $copyPath = Join-Path $directory 'velociraptor.exe'
        $copy = [IO.File]::Open($copyPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try { $source.CopyTo($copy,65536); $copy.Flush($true) } finally { $copy.Dispose() }
        $copyCheck = Lock-File $copyPath
        if ($copyCheck.Length -ne 73422840 -or (Hash-Stream $copyCheck) -cne $backendHash) { throw 'BACKEND_COPY_PIN' }
        $receipt = [ordered]@{
            kind='SecAppDefenderBuildV1'; run_id=$runId
            source_sha256=(Get-FileHash -LiteralPath (Join-Path $directory 'DefenderControl.cs') -Algorithm SHA256).Hash.ToLowerInvariant()
            workspace_sha256=(Get-FileHash -LiteralPath (Join-Path $directory 'Workspace.cs') -Algorithm SHA256).Hash.ToLowerInvariant()
            manifest_sha256=(Get-FileHash -LiteralPath (Join-Path $directory 'require-administrator.manifest') -Algorithm SHA256).Hash.ToLowerInvariant()
            helper_sha256=(Get-FileHash -LiteralPath $image -Algorithm SHA256).Hash.ToLowerInvariant()
            executed=$false
        }
        New-FixedFile (Join-Path $directory 'build.json') $utf8.GetBytes(($receipt | ConvertTo-Json -Compress))
        $receipt | ConvertTo-Json -Compress
        exit 0
    }

    # Ordinary controller only: the helper/backend are the sole elevated processes.
    Hold-DirectoryChain $directory
    Assert-PrivateWorkspace $directory
    Lock-Operation
    $expectedFiles = @($preparedNames) + @('controller.lock')
    $entries = @(Get-ChildItem -LiteralPath $directory -Force)
    if ($entries.Count -ne $expectedFiles.Count) { throw 'RUN_DIRECTORY_NOT_FRESH' }
    foreach ($entry in $entries) { if ($entry.PSIsContainer -or $expectedFiles -notcontains $entry.Name) { throw 'RUN_DIRECTORY_NOT_FRESH' }; Assert-Private $entry.FullName $false }
    $receipt = (Bounded-Read (Join-Path $directory 'build.json') 2048) | ConvertFrom-Json
    if ($receipt.kind -ne 'SecAppDefenderBuildV1' -or $receipt.run_id -cne $runId -or $receipt.executed -ne $false) { throw 'BUILD_RECEIPT' }
    if ($receipt.source_sha256 -cne (Get-FileHash -LiteralPath (Join-Path $PSScriptRoot 'DefenderControl.cs') -Algorithm SHA256).Hash.ToLowerInvariant() -or
        $receipt.manifest_sha256 -cne (Get-FileHash -LiteralPath (Join-Path $PSScriptRoot 'require-administrator.manifest') -Algorithm SHA256).Hash.ToLowerInvariant() -or
        $receipt.workspace_sha256 -cne (Get-FileHash -LiteralPath (Join-Path $PSScriptRoot 'Workspace.cs') -Algorithm SHA256).Hash.ToLowerInvariant()) { throw 'SOURCE_CHANGED_SINCE_REVIEW' }
    $backend = Lock-File (Join-Path $directory 'velociraptor.exe')
    if ($backend.Length -ne 73422840 -or (Hash-Stream $backend) -cne '3d20a5a2d272e3eb2bccae4a80ebe469fc1a6f63eb4a8f8a586dbae356437d32') { throw 'BACKEND_PIN' }
    $lockedImage = Lock-File $image
    $actualHash = Hash-Stream $lockedImage
    if ($actualHash -cne $ExpectedHelperSha256 -or $actualHash -cne $receipt.helper_sha256) { throw 'HELPER_HASH' }
    if ($DiscardPrepared) {
        # Fresh exact set excludes attempted.once: this route cannot clean a run.
        Remove-OwnedDataFiles $preparedNames
        @{kind='SecAppDefenderDiscardV1';run_id=$runId;data_files_removed=$true;workspace_removed=$false} | ConvertTo-Json -Compress
        exit 0
    }
    New-FixedFile (Join-Path $directory 'attempted.once') $utf8.GetBytes("Single UAC attempt; no automatic retry.`n")
    $runAttempted = $true
    $parent = [Diagnostics.Process]::GetCurrentProcess()
    $started = $parent.StartTime.ToUniversalTime().ToFileTimeUtc().ToString([Globalization.CultureInfo]::InvariantCulture)
    $arguments = @('--run', $runId, '--parent', $PID.ToString([Globalization.CultureInfo]::InvariantCulture), '--started', $started)
    # The user, never automation, accepts the Windows UAC dialog.
    $helper = Start-Process -FilePath $image -ArgumentList $arguments -WorkingDirectory $directory -Verb RunAs -WindowStyle Hidden -PassThru
    if (!$helper.WaitForExit(45000)) {
        New-FixedFile (Join-Path $directory 'cancel.request') $utf8.GetBytes("cancel`n")
        if (!$helper.WaitForExit(5000)) { throw 'HELPER_EXIT_UNCONFIRMED' }
    }
    $finished = $true
    $helper.Refresh()
    if (!(Test-Path -LiteralPath (Join-Path $directory 'result.json'))) {
        @{kind='SecAppDefenderControllerError'; error='HELPER_NO_RESULT'; helper_exit_confirmed=$true; helper_exit_code=$helper.ExitCode} | ConvertTo-Json -Compress
        exit 1
    }
    $result = Bounded-Read (Join-Path $directory 'result.json') 8192
    if ($CleanupOnSuccess) {
        $removed = $false
        if ($finished -and $helper.HasExited -and $helper.ExitCode -eq 0 -and (Test-CompletedReceipt $result $runId)) {
            try {
                $names = @($preparedNames) + @('attempted.once','secapp-empty.config.yaml','result.json')
                if (Test-Path -LiteralPath (Join-Path $directory 'cancel.request')) { $names += 'cancel.request' }
                Remove-OwnedDataFiles $names
                $removed = $true
            } catch { $removed = $false }
        }
        # Versioned envelope preserves exact inner JSON and reports cleanup honestly.
        @{kind='SecAppDefenderRunEnvelopeV1';run_id=$runId;helper_exit_confirmed=$finished;helper_exit_code=$helper.ExitCode;data_files_removed=$removed;workspace_removed=$false;result_json=$result} | ConvertTo-Json -Compress
        if ($helper.ExitCode -ne 0 -or !$removed) { exit 1 }
        exit 0
    }
    # Print the private bounded transport only to the caller, not a persistent log.
    [Console]::Out.Write($result)
    if ($helper.ExitCode -ne 0) { exit 1 }
    exit 0
} catch {
    $code = if ($_.Exception.Message -cmatch '^[A-Z][A-Z0-9_]{0,63}$') { $_.Exception.Message } else { 'CONTROLLED_FAILURE' }
    $failure = @{kind='SecAppDefenderControllerError'; error=$code; helper_exit_confirmed=$finished; run_id=$runId; workspace_created=$workspaceCreated}
    if ($code -ceq 'NAMESPACE_FINAL_PATH' -and $namespaceFailure) { $failure.namespace = $namespaceFailure }
    $failure | ConvertTo-Json -Compress
    exit 1
} finally {
    if ($runAttempted -and !$finished -and $directory -and !(Test-Path -LiteralPath (Join-Path $directory 'cancel.request'))) {
        try { New-FixedFile (Join-Path $directory 'cancel.request') $utf8.GetBytes("cancel`n") } catch { }
    }
    foreach ($held in $locks) { $held.Dispose() }
    if ($helper) { $helper.Dispose() }
    $identity.Dispose()
    # No recursive deletion or raw report persistence elsewhere. Exact owned files
    # are removed separately only after confirmed helper exit and result handling.
}
