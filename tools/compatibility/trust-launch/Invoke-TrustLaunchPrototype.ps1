[CmdletBinding()]
param(
    [ValidateRange(10000, 900000)]
    [int]$TimeoutMilliseconds = 600000,

    [ValidateRange(65536, 16777216)]
    [int]$MaximumStreamBytes = 4194304,

    [switch]$CompileOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:FailurePrefix = 'TL-WRAPPER-'
$script:ExpectedSha256 = 'c91cf8a32731c4c45c148393bc7d2af688c392194a9fffc4535e8b583260d55e'

function Fail-Wrapper {
    param([Parameter(Mandatory = $true)][string]$Code)

    throw [System.InvalidOperationException]::new("$($script:FailurePrefix)$Code")
}

function Get-CryptographicHex {
    param([ValidateRange(16, 64)][int]$ByteCount = 16)

    $bytes = New-Object byte[] $ByteCount
    $random = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $random.GetBytes($bytes)
    }
    finally {
        $random.Dispose()
    }
    return ([System.BitConverter]::ToString($bytes)).Replace('-', '').ToLowerInvariant()
}

function Get-NormalizedPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    return [System.IO.Path]::GetFullPath($Path).TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar)
}

function Test-PathWithin {
    param(
        [Parameter(Mandatory = $true)][string]$Candidate,
        [Parameter(Mandatory = $true)][string]$Parent
    )

    $normalizedCandidate = Get-NormalizedPath -Path $Candidate
    $normalizedParent = Get-NormalizedPath -Path $Parent
    $prefix = $normalizedParent + [System.IO.Path]::DirectorySeparatorChar
    return $normalizedCandidate.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)
}

function Assert-DirectoryNotReparse {
    param([Parameter(Mandatory = $true)][string]$Path)

    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (-not $item.PSIsContainer -or
        (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)) {
        Fail-Wrapper 'DIRECTORY-REPARSE-OR-NOT-DIRECTORY'
    }
}

function New-CryptographicDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$Parent,
        [Parameter(Mandatory = $true)][string]$Prefix
    )

    Assert-DirectoryNotReparse -Path $Parent
    $leaf = "$Prefix$(Get-CryptographicHex -ByteCount 16)"
    $path = Join-Path $Parent $leaf
    try {
        $created = New-Item -ItemType Directory -Path $path -ErrorAction Stop
    }
    catch {
        Fail-Wrapper 'CREATE-NEW-DIRECTORY'
    }
    if ($created.FullName -cne $path -and
        -not [string]::Equals($created.FullName, $path, [System.StringComparison]::OrdinalIgnoreCase)) {
        Fail-Wrapper 'CREATE-NEW-DIRECTORY-PATH'
    }
    Assert-DirectoryNotReparse -Path $path
    if (@(Get-ChildItem -LiteralPath $path -Force -ErrorAction Stop).Count -ne 0) {
        Fail-Wrapper 'CREATE-NEW-DIRECTORY-NOT-EMPTY'
    }
    return $path
}

function Find-LocalCSharpCompiler {
    $programFiles = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::ProgramFiles)
    $roslynCandidates = @(
        (Join-Path $programFiles 'Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\Roslyn\csc.exe'),
        (Join-Path $programFiles 'Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\Roslyn\csc.exe'),
        (Join-Path $programFiles 'Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\Roslyn\csc.exe'),
        (Join-Path $programFiles 'Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\Roslyn\csc.exe')
    )
    foreach ($candidate in $roslynCandidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return [pscustomobject]@{ path = $candidate; kind = 'Roslyn' }
        }
    }

    if ([string]::IsNullOrWhiteSpace($env:SystemRoot)) {
        Fail-Wrapper 'SYSTEMROOT-MISSING'
    }
    $framework64 = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    if (Test-Path -LiteralPath $framework64 -PathType Leaf) {
        return [pscustomobject]@{ path = $framework64; kind = 'Framework64' }
    }
    Fail-Wrapper 'CSHARP-COMPILER-NOT-FOUND'
}

function ConvertTo-WindowsCommandLineArgument {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value)

    if ($Value.Length -gt 0 -and $Value -notmatch '[\s"]') {
        return $Value
    }

    $builder = New-Object System.Text.StringBuilder
    [void]$builder.Append([char]34)
    $backslashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq [char]92) {
            $backslashes += 1
            continue
        }
        if ($character -eq [char]34) {
            for ($index = 0; $index -lt (($backslashes * 2) + 1); $index += 1) {
                [void]$builder.Append([char]92)
            }
            [void]$builder.Append([char]34)
            $backslashes = 0
            continue
        }
        for ($index = 0; $index -lt $backslashes; $index += 1) {
            [void]$builder.Append([char]92)
        }
        $backslashes = 0
        [void]$builder.Append($character)
    }
    for ($index = 0; $index -lt ($backslashes * 2); $index += 1) {
        [void]$builder.Append([char]92)
    }
    [void]$builder.Append([char]34)
    return $builder.ToString()
}

function Join-WindowsCommandLine {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)

    return (($Arguments | ForEach-Object { ConvertTo-WindowsCommandLineArgument -Value $_ }) -join ' ')
}

function Invoke-BoundedProcess {
    param(
        [Parameter(Mandatory = $true)][string]$FileName,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)][string]$PrivateTempRoot,
        [Parameter(Mandatory = $true)][int]$TimeoutMs,
        [Parameter(Mandatory = $true)][int]$StreamLimitBytes
    )

    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $FileName
    $startInfo.Arguments = Join-WindowsCommandLine -Arguments $Arguments
    $startInfo.WorkingDirectory = $WorkingDirectory
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.ErrorDialog = $false
    $startInfo.LoadUserProfile = $false
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.EnvironmentVariables.Clear()
    $startInfo.EnvironmentVariables['SystemRoot'] = $env:SystemRoot
    $startInfo.EnvironmentVariables['WINDIR'] = if ([string]::IsNullOrWhiteSpace($env:WINDIR)) {
        $env:SystemRoot
    }
    else {
        $env:WINDIR
    }
    $startInfo.EnvironmentVariables['TEMP'] = $PrivateTempRoot
    $startInfo.EnvironmentVariables['TMP'] = $PrivateTempRoot

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    $stdoutRetained = New-Object System.IO.MemoryStream
    $stderrRetained = New-Object System.IO.MemoryStream
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $started = $false
    try {
        try {
            $started = $process.Start()
        }
        catch {
            Fail-Wrapper 'PROCESS-START'
        }
        if (-not $started) {
            Fail-Wrapper 'PROCESS-START'
        }
        $process.StandardInput.Close()

        $stdoutStream = $process.StandardOutput.BaseStream
        $stderrStream = $process.StandardError.BaseStream
        $stdoutBuffer = New-Object byte[] 8192
        $stderrBuffer = New-Object byte[] 8192
        $stdoutTask = $stdoutStream.ReadAsync($stdoutBuffer, 0, $stdoutBuffer.Length)
        $stderrTask = $stderrStream.ReadAsync($stderrBuffer, 0, $stderrBuffer.Length)
        $stdoutDone = $false
        $stderrDone = $false
        [long]$stdoutObserved = 0
        [long]$stderrObserved = 0
        $timedOut = $false
        $outputLimitExceeded = $false
        $terminationInvoked = $false

        while (-not ($stdoutDone -and $stderrDone -and $process.HasExited)) {
            if (-not $stdoutDone -and $stdoutTask.IsCompleted) {
                try {
                    $count = [int]$stdoutTask.Result
                }
                catch {
                    Fail-Wrapper 'STDOUT-DRAIN'
                }
                if ($count -eq 0) {
                    $stdoutDone = $true
                }
                else {
                    $stdoutObserved += $count
                    $remaining = [int][System.Math]::Max(0, $StreamLimitBytes - $stdoutRetained.Length)
                    if ($remaining -gt 0) {
                        $stdoutRetained.Write($stdoutBuffer, 0, [System.Math]::Min($remaining, $count))
                    }
                    if ($stdoutObserved -gt $StreamLimitBytes) {
                        $outputLimitExceeded = $true
                    }
                    $stdoutTask = $stdoutStream.ReadAsync($stdoutBuffer, 0, $stdoutBuffer.Length)
                }
            }

            if (-not $stderrDone -and $stderrTask.IsCompleted) {
                try {
                    $count = [int]$stderrTask.Result
                }
                catch {
                    Fail-Wrapper 'STDERR-DRAIN'
                }
                if ($count -eq 0) {
                    $stderrDone = $true
                }
                else {
                    $stderrObserved += $count
                    $remaining = [int][System.Math]::Max(0, $StreamLimitBytes - $stderrRetained.Length)
                    if ($remaining -gt 0) {
                        $stderrRetained.Write($stderrBuffer, 0, [System.Math]::Min($remaining, $count))
                    }
                    if ($stderrObserved -gt $StreamLimitBytes) {
                        $outputLimitExceeded = $true
                    }
                    $stderrTask = $stderrStream.ReadAsync($stderrBuffer, 0, $stderrBuffer.Length)
                }
            }

            if (-not $process.HasExited -and $stopwatch.ElapsedMilliseconds -gt $TimeoutMs) {
                $timedOut = $true
            }
            if (($timedOut -or $outputLimitExceeded) -and -not $process.HasExited -and -not $terminationInvoked) {
                $terminationInvoked = $true
                try {
                    $process.Kill()
                }
                catch {
                    # A concurrent normal exit is acceptable; the final state is checked below.
                }
            }
            if (-not ($stdoutDone -and $stderrDone -and $process.HasExited)) {
                Start-Sleep -Milliseconds 5
            }
        }

        $process.WaitForExit()
        return [pscustomobject]@{
            exit_code = [int]$process.ExitCode
            stdout = $stdoutRetained.ToArray()
            stderr = $stderrRetained.ToArray()
            stdout_observed_bytes = $stdoutObserved
            stderr_observed_bytes = $stderrObserved
            timed_out = $timedOut
            output_limit_exceeded = $outputLimitExceeded
            termination_invoked = $terminationInvoked
        }
    }
    finally {
        $stopwatch.Stop()
        $stdoutRetained.Dispose()
        $stderrRetained.Dispose()
        if ($started -and -not $process.HasExited) {
            try {
                $process.Kill()
                $process.WaitForExit(5000) | Out-Null
            }
            catch {
                # Cleanup verification in the caller remains fail-closed.
            }
        }
        $process.Dispose()
    }
}

function ConvertFrom-StrictUtf8 {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][string]$Code
    )

    try {
        $utf8 = New-Object System.Text.UTF8Encoding($false, $true)
        return $utf8.GetString($Bytes)
    }
    catch {
        Fail-Wrapper "$Code-UTF8"
    }
}

function Initialize-ScopedRunBase {
    param([Parameter(Mandatory = $true)][string]$LocalAppDataRoot)

    if (-not [System.IO.Path]::IsPathRooted($LocalAppDataRoot)) {
        Fail-Wrapper 'LOCALAPPDATA-NOT-ABSOLUTE'
    }
    $current = Get-NormalizedPath -Path $LocalAppDataRoot
    Assert-DirectoryNotReparse -Path $current
    foreach ($segment in @('SecApp', 'compat', 'trust-launch')) {
        $current = Join-Path $current $segment
        try {
            [void][System.IO.Directory]::CreateDirectory($current)
        }
        catch {
            Fail-Wrapper 'RUN-BASE-CREATE'
        }
        Assert-DirectoryNotReparse -Path $current
    }
    return $current
}

function Find-ReferenceAssemblyRoot {
    $programFilesX86 = [System.Environment]::GetFolderPath(
        [System.Environment+SpecialFolder]::ProgramFilesX86)
    $candidates = @(
        (Join-Path $programFilesX86 'Reference Assemblies\Microsoft\Framework\.NETFramework\v4.8'),
        (Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319')
    )
    foreach ($candidate in $candidates) {
        $complete = $true
        foreach ($assembly in @('mscorlib.dll', 'System.dll', 'System.Core.dll')) {
            if (-not (Test-Path -LiteralPath (Join-Path $candidate $assembly) -PathType Leaf)) {
                $complete = $false
            }
        }
        if ($complete) {
            return $candidate
        }
    }
    Fail-Wrapper 'REFERENCE-ASSEMBLIES-NOT-FOUND'
}

function Remove-PrivateDirectory {
    param(
        [Parameter(Mandatory = $false)][AllowNull()][string]$Path,
        [Parameter(Mandatory = $true)][string]$AllowedParent
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $true
    }
    $normalizedPath = Get-NormalizedPath -Path $Path
    if (-not (Test-PathWithin -Candidate $normalizedPath -Parent $AllowedParent)) {
        return $false
    }
    try {
        if (Test-Path -LiteralPath $normalizedPath) {
            $allowedParentItem = Get-Item -LiteralPath $AllowedParent -Force -ErrorAction Stop
            $targetItem = Get-Item -LiteralPath $normalizedPath -Force -ErrorAction Stop
            if ((($allowedParentItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) -or
                (($targetItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) -or
                -not $targetItem.PSIsContainer) {
                return $false
            }
            Remove-Item -LiteralPath $normalizedPath -Recurse -Force -ErrorAction Stop
        }
    }
    catch {
        return $false
    }
    return -not (Test-Path -LiteralPath $normalizedPath)
}

$repositoryRoot = $null
$scopedRunBase = $null
$buildRoot = $null
$sessionRunBase = $null
$launcherWorkingDirectory = $null
$launcherStdout = $null
$launcherStderrText = $null
$launcherExitCode = 1
$launcherFileLock = $null
$compileOnlySummary = $null
$failureCode = $null
$cleanupComplete = $true

try {
    if ([string]::IsNullOrWhiteSpace($env:SystemRoot) -or
        -not [System.IO.Path]::IsPathRooted($env:SystemRoot)) {
        Fail-Wrapper 'SYSTEMROOT-MISSING'
    }
    $repositoryRoot = Get-NormalizedPath -Path (Join-Path $PSScriptRoot '..\..\..')
    $sourcePath = Get-NormalizedPath -Path (Join-Path $PSScriptRoot 'TrustLaunchProbe.cs')
    if (-not (Test-PathWithin -Candidate $sourcePath -Parent $repositoryRoot) -or
        -not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
        Fail-Wrapper 'PROBE-SOURCE-MISSING'
    }

    if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        Fail-Wrapper 'LOCALAPPDATA-MISSING'
    }
    $scopedRunBase = Initialize-ScopedRunBase -LocalAppDataRoot $env:LOCALAPPDATA
    if (Test-PathWithin -Candidate $scopedRunBase -Parent $repositoryRoot) {
        Fail-Wrapper 'RUN-BASE-INSIDE-REPOSITORY'
    }

    $buildRoot = New-CryptographicDirectory -Parent $scopedRunBase -Prefix 'build-'
    $sessionRunBase = New-CryptographicDirectory -Parent $scopedRunBase -Prefix 'session-'
    $launcherWorkingDirectory = New-CryptographicDirectory -Parent $scopedRunBase -Prefix 'cwd-'

    $cachedExecutable = Get-NormalizedPath -Path (Join-Path $env:LOCALAPPDATA (
        'SecApp\compat\velociraptor\v0.77.1\bin\' +
        'velociraptor-v0.77.1-windows-amd64.exe'))
    if (-not (Test-Path -LiteralPath $cachedExecutable -PathType Leaf)) {
        Fail-Wrapper 'CACHED-SOURCE-MISSING'
    }

    $compiler = Find-LocalCSharpCompiler
    $referenceRoot = Find-ReferenceAssemblyRoot
    $launcherPath = Join-Path $buildRoot 'TrustLaunchProbe.exe'
    $compilerArguments = @(
        '/nologo',
        '/noconfig',
        '/target:exe',
        '/platform:x64',
        '/checked+',
        '/optimize+',
        '/debug-',
        '/warn:4',
        "/out:$launcherPath",
        "/reference:$(Join-Path $referenceRoot 'mscorlib.dll')",
        "/reference:$(Join-Path $referenceRoot 'System.dll')",
        "/reference:$(Join-Path $referenceRoot 'System.Core.dll')",
        $sourcePath
    )
    if ($compiler.kind -eq 'Roslyn') {
        $compilerArguments = @('/deterministic+', '/langversion:latest') + $compilerArguments
    }

    $compileResult = Invoke-BoundedProcess `
        -FileName $compiler.path `
        -Arguments $compilerArguments `
        -WorkingDirectory $buildRoot `
        -PrivateTempRoot $buildRoot `
        -TimeoutMs ([System.Math]::Min($TimeoutMilliseconds, 120000)) `
        -StreamLimitBytes $MaximumStreamBytes
    if ($compileResult.timed_out) {
        Fail-Wrapper 'COMPILE-TIMEOUT'
    }
    if ($compileResult.output_limit_exceeded) {
        Fail-Wrapper 'COMPILE-OUTPUT-LIMIT'
    }
    if ($compileResult.exit_code -ne 0 -or
        -not (Test-Path -LiteralPath $launcherPath -PathType Leaf)) {
        Fail-Wrapper "COMPILE-FAILED-$($compileResult.exit_code)"
    }
    try {
        $launcherFileLock = [System.IO.File]::Open(
            $launcherPath,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::Read)
    }
    catch {
        Fail-Wrapper 'COMPILED-LAUNCHER-LOCK'
    }
    if ($launcherFileLock.Length -le 0) {
        Fail-Wrapper 'COMPILED-LAUNCHER-EMPTY'
    }

    $unexpectedBuildEntries = @(Get-ChildItem -LiteralPath $buildRoot -Force | Where-Object {
        $_.Name -notin @('TrustLaunchProbe.exe', 'TrustLaunchProbe.pdb')
    })
    if ($unexpectedBuildEntries.Count -ne 0) {
        Fail-Wrapper 'COMPILE-UNEXPECTED-OUTPUT'
    }

    if ($CompileOnly) {
        $compileOnlySummary = [pscustomobject]@{
            status = 'PASS'
            compiler_kind = $compiler.kind
            target = 'x64-netfx'
            compiled = $true
            velociraptor_execution_attempted = $false
        }
    }
    else {
        $launcherArguments = @(
            'suite',
            '--source', $cachedExecutable,
            '--expected-sha256', $script:ExpectedSha256,
            '--run-root', $sessionRunBase
        )
        $launcherResult = Invoke-BoundedProcess `
            -FileName $launcherPath `
            -Arguments $launcherArguments `
            -WorkingDirectory $launcherWorkingDirectory `
            -PrivateTempRoot $launcherWorkingDirectory `
            -TimeoutMs $TimeoutMilliseconds `
            -StreamLimitBytes $MaximumStreamBytes

        if ($launcherResult.timed_out) {
            Fail-Wrapper 'LAUNCHER-TIMEOUT'
        }
        if ($launcherResult.output_limit_exceeded) {
            Fail-Wrapper 'LAUNCHER-OUTPUT-LIMIT'
        }
        if ($launcherResult.exit_code -notin @(0, 1, 2)) {
            Fail-Wrapper 'LAUNCHER-EXIT-CODE'
        }

        $launcherExitCode = [int]$launcherResult.exit_code
        if ($launcherExitCode -in @(0, 2)) {
            if ($launcherResult.stdout.Length -eq 0 -or $launcherResult.stderr.Length -ne 0) {
                Fail-Wrapper 'LAUNCHER-RESULT-CONTRACT'
            }
            $launcherJson = ConvertFrom-StrictUtf8 -Bytes $launcherResult.stdout -Code 'LAUNCHER-STDOUT'
            if ($launcherJson -match '(?i)(?:^|[^A-Z0-9_])[A-Z]:[\\/]' -or
                $launcherJson -match '(?i)S-1-[0-9]+(?:-[0-9]+){1,}') {
                Fail-Wrapper 'LAUNCHER-PRIVACY'
            }
            try {
                $parsedLauncherResult = $launcherJson | ConvertFrom-Json -ErrorAction Stop
            }
            catch {
                Fail-Wrapper 'LAUNCHER-JSON'
            }
            if ($null -eq $parsedLauncherResult -or $parsedLauncherResult -is [System.Array]) {
                Fail-Wrapper 'LAUNCHER-JSON-ROOT'
            }
            $launcherStdout = $launcherResult.stdout
        }
        else {
            if ($launcherResult.stdout.Length -ne 0) {
                Fail-Wrapper 'HARNESS-FAILURE-STDOUT'
            }
            $launcherStderrText = ConvertFrom-StrictUtf8 -Bytes $launcherResult.stderr -Code 'LAUNCHER-STDERR'
            if ($launcherStderrText -notmatch '^trust-launch-probe: [A-Z0-9_]+(?::[0-9]+)?\r?\n?$') {
                Fail-Wrapper 'HARNESS-FAILURE-DIAGNOSTIC'
            }
        }
    }
}
catch {
    $failureCode = [string]$_.Exception.Message
    if (-not $failureCode.StartsWith($script:FailurePrefix, [System.StringComparison]::Ordinal)) {
        $failureCode = "$($script:FailurePrefix)UNCONTROLLED-FAILURE"
    }
}
finally {
    if ($null -ne $launcherFileLock) {
        $launcherFileLock.Dispose()
        $launcherFileLock = $null
    }
    if (-not [string]::IsNullOrWhiteSpace($scopedRunBase)) {
        foreach ($privateRoot in @($launcherWorkingDirectory, $sessionRunBase, $buildRoot)) {
            if (-not (Remove-PrivateDirectory -Path $privateRoot -AllowedParent $scopedRunBase)) {
                $cleanupComplete = $false
            }
        }
    }
    elseif (-not [string]::IsNullOrWhiteSpace($launcherWorkingDirectory) -or
        -not [string]::IsNullOrWhiteSpace($sessionRunBase) -or
        -not [string]::IsNullOrWhiteSpace($buildRoot)) {
        $cleanupComplete = $false
    }
    if (-not $cleanupComplete) {
        $failureCode = "$($script:FailurePrefix)CLEANUP-FAILED"
    }
    elseif (-not [string]::IsNullOrWhiteSpace($scopedRunBase)) {
        try {
            $runBaseItem = Get-Item -LiteralPath $scopedRunBase -Force -ErrorAction Stop
            if ((($runBaseItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0) -and
                @(Get-ChildItem -LiteralPath $scopedRunBase -Force -ErrorAction Stop).Count -eq 0) {
                [System.IO.Directory]::Delete($scopedRunBase, $false)
            }
        }
        catch {
            # The shared scoped base may be in use by another concurrent prototype run.
        }
    }
}

if ($null -ne $failureCode) {
    [Console]::Error.WriteLine("Invoke-TrustLaunchPrototype: $failureCode")
    exit 1
}

if ($CompileOnly) {
    $compileOnlySummary | Add-Member -NotePropertyName cleanup_complete -NotePropertyValue $cleanupComplete
    [Console]::Out.WriteLine(($compileOnlySummary | ConvertTo-Json -Compress))
    exit 0
}

if ($launcherExitCode -eq 1) {
    [Console]::Error.Write($launcherStderrText)
    exit 1
}

$standardOutput = [Console]::OpenStandardOutput()
$standardOutput.Write($launcherStdout, 0, $launcherStdout.Length)
$standardOutput.Flush()
exit $launcherExitCode
