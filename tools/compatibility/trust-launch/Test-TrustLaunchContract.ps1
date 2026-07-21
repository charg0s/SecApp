[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ContractPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:FailurePrefix = 'TL-CONTRACT-'

function Fail-Contract {
    param([Parameter(Mandatory = $true)][string]$Code)

    throw [System.InvalidOperationException]::new("$($script:FailurePrefix)$Code")
}

function New-OrdinalStringSet {
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyCollection()]
        [string[]]$Values = @()
    )

    $set = New-Object 'System.Collections.Generic.Dictionary[string,bool]' (
        [System.StringComparer]::Ordinal)
    foreach ($value in $Values) {
        if ($set.ContainsKey($value)) {
            Fail-Contract 'INTERNAL-DUPLICATE-SET-VALUE'
        }
        $set.Add($value, $true)
    }
    return ,$set
}

function Assert-ExactProperties {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string[]]$Expected,
        [Parameter(Mandatory = $true)][string]$Code
    )

    if ($null -eq $Value -or $Value -is [string] -or $Value -is [System.Array] -or $Value -is [ValueType]) {
        Fail-Contract "$Code-OBJECT-REQUIRED"
    }

    $actual = @($Value.PSObject.Properties | ForEach-Object { $_.Name })
    if ($actual.Count -ne $Expected.Count) {
        Fail-Contract "$Code-PROPERTY-SET"
    }

    $expectedSet = New-OrdinalStringSet -Values $Expected
    foreach ($name in $actual) {
        if (-not $expectedSet.ContainsKey($name)) {
            Fail-Contract "$Code-PROPERTY-SET"
        }
    }
}

function Assert-Boolean {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string]$Code
    )

    if ($Value -isnot [bool]) {
        Fail-Contract "$Code-BOOLEAN-REQUIRED"
    }
}

function Assert-UniqueStringArray {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string]$Code,
        [int]$MinimumCount = 1
    )

    if ($Value -isnot [System.Array] -or $Value.Count -lt $MinimumCount) {
        Fail-Contract "$Code-ARRAY-REQUIRED"
    }

    $seen = New-OrdinalStringSet
    foreach ($entry in $Value) {
        if ($entry -isnot [string] -or [string]::IsNullOrWhiteSpace($entry)) {
            Fail-Contract "$Code-STRING-REQUIRED"
        }
        if ($seen.ContainsKey($entry)) {
            Fail-Contract "$Code-DUPLICATE"
        }
        $seen.Add($entry, $true)
    }

    return $seen
}

function Assert-ExactStringSet {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string[]]$Expected,
        [Parameter(Mandatory = $true)][string]$Code
    )

    $actualSet = Assert-UniqueStringArray -Value $Value -Code $Code -MinimumCount $Expected.Count
    if ($actualSet.Count -ne $Expected.Count) {
        Fail-Contract "$Code-EXACT-SET"
    }
    foreach ($entry in $Expected) {
        if (-not $actualSet.ContainsKey($entry)) {
            Fail-Contract "$Code-EXACT-SET"
        }
    }
}

function Assert-PrivacySafeValue {
    param(
        [Parameter(Mandatory = $false)]$Value,
        [Parameter(Mandatory = $false)][string]$PropertyName = ''
    )

    $forbiddenPropertyNames = @{
        'username' = $true
        'user_name' = $true
        'account_name' = $true
        'account_identity' = $true
        'sid' = $true
        'user_sid' = $true
        'pid' = $true
        'process_id' = $true
        'module_path' = $true
        'module_paths' = $true
        'raw_module' = $true
        'raw_modules' = $true
        'raw_module_list' = $true
        'stdout' = $true
        'stderr' = $true
        'raw_stdout' = $true
        'raw_stderr' = $true
        'raw_output' = $true
        'environment_values' = $true
    }

    if (-not [string]::IsNullOrEmpty($PropertyName)) {
        $normalizedName = $PropertyName.ToLowerInvariant()
        if ($forbiddenPropertyNames.ContainsKey($normalizedName)) {
            Fail-Contract 'PRIVACY-FORBIDDEN-FIELD'
        }
    }

    if ($null -eq $Value) {
        return
    }
    if ($Value -is [string]) {
        if ($Value -match '(?i)(?:^|[^A-Z0-9_])[A-Z]:[\\/]' -or
            $Value -match '(?i)\\\\(?:\?\\|\.\\|[^\\/\s]+[\\/][^\\/\s]+)' -or
            $Value -match '^/(?:Users|home|var|tmp|etc|opt|root)/' -or
            $Value -match '(?i)S-1-[0-9]+(?:-[0-9]+){1,}') {
            Fail-Contract 'PRIVACY-SENSITIVE-STRING'
        }
        return
    }
    if ($Value -is [System.Array]) {
        foreach ($entry in $Value) {
            Assert-PrivacySafeValue -Value $entry
        }
        return
    }
    if ($Value -is [ValueType]) {
        return
    }

    foreach ($property in $Value.PSObject.Properties) {
        Assert-PrivacySafeValue -Value $property.Value -PropertyName $property.Name
    }
}

function Assert-CaseArray {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][bool]$FalsePositive
    )

    $code = if ($FalsePositive) { 'FALSE-POSITIVE-CASES' } else { 'MANDATORY-CASES' }
    if ($Value -isnot [System.Array] -or $Value.Count -lt 1) {
        Fail-Contract "$code-ARRAY-REQUIRED"
    }

    $allowedOutcomes = New-OrdinalStringSet -Values @(
        'Pass',
        'Fail',
        'Blocked',
        'NotTested'
    )
    $expectedIds = if ($FalsePositive) {
        @(
            'TL-FP-001-EXPECTED-SHA256',
            'TL-FP-002-SOURCE-FILE-ID',
            'TL-FP-003-DESTINATION-FILE-ID',
            'TL-FP-004-FILE-LOCK',
            'TL-FP-005-WRITE-REPLACE',
            'TL-FP-006-ADJACENT-MARKER',
            'TL-FP-007-ROOT-REPARSE',
            'TL-FP-008-JOB-ASSIGNMENT',
            'TL-FP-009-CHILD-JOB-MEMBERSHIP',
            'TL-FP-010-DESCENDANT-SURVIVAL',
            'TL-FP-011-CHILD-ELEVATION',
            'TL-FP-012-LINKED-TOKEN',
            'TL-FP-013-UNEXPECTED-MODULE',
            'TL-FP-014-MITIGATION-MISSING',
            'TL-FP-015-HANDLE-LEAK',
            'TL-FP-016-SILENT-FALLBACK'
        )
    }
    else {
        @(
            'TL-ID-001-SOURCE-HANDLE',
            'TL-ID-002-DESTINATION-COPY',
            'TL-ID-003-DESTINATION-MISMATCH',
            'TL-ID-004-WRITE-LOCK',
            'TL-ID-005-REPLACE-LOCK',
            'TL-ID-006-DELETE-LOCK',
            'TL-ID-007-FILE-RENAME-LOCK',
            'TL-ID-008-EXEC-DIRECTORY-MUTATION',
            'TL-ID-009-ADJACENT-MARKER',
            'TL-ID-010-REPARSE-REPLACEMENT',
            'TL-ID-011-UNLOCK-CONTROL',
            'TL-TOK-001-CURRENT',
            'TL-TOK-002-DEFAULT',
            'TL-TOK-003-RUNASINVOKER',
            'TL-TOK-004-RESTRICTED-ATTEMPT',
            'TL-TOK-005-CHILD',
            'TL-JOB-001-ATOMIC-ASSIGN',
            'TL-JOB-002-NESTED',
            'TL-JOB-003-NORMAL',
            'TL-JOB-004-TIMEOUT',
            'TL-JOB-005-CANCEL',
            'TL-JOB-006-TREE',
            'TL-JOB-007-KILL-CLOSE',
            'TL-JOB-008-ACTIVE-LIMIT',
            'TL-JOB-009-ASSIGNMENT-FAIL',
            'TL-JOB-010-NO-ORPHAN',
            'TL-IMG-001-IMPORTS',
            'TL-IMG-002-MITIGATION',
            'TL-IMG-003-INITIAL',
            'TL-IMG-004-RUNTIME',
            'TL-IMG-005-UNEXPECTED-MODULE-REJECT',
            'TL-HND-001-EXPLICIT-LIST',
            'TL-ENV-001-ALLOWLIST',
            'TL-VR-001-PRECONDITIONS',
            'TL-VR-002-VERSION',
            'TL-VR-003-HELP',
            'TL-VR-004-SYNTHETIC',
            'TL-CLEAN-001-NO-HELPERS',
            'TL-CLEAN-002-NO-VELOCIRAPTOR',
            'TL-CLEAN-003-RUN-ROOT'
        )
    }
    if ($Value.Count -ne $expectedIds.Count) {
        Fail-Contract "$code-EXACT-ID-SET"
    }
    $seen = New-OrdinalStringSet
    $categories = New-OrdinalStringSet
    $notTestedCount = 0

    foreach ($case in $Value) {
        Assert-ExactProperties -Value $case -Expected @('case_id', 'required_outcome') -Code $code
        if ($case.case_id -isnot [string] -or $case.required_outcome -isnot [string]) {
            Fail-Contract "$code-STRING-FIELDS"
        }

        $caseId = $case.case_id
        $outcome = $case.required_outcome
        if ($caseId -cne $caseId.ToUpperInvariant()) {
            Fail-Contract "$code-ID-UPPERCASE"
        }
        if ($seen.ContainsKey($caseId)) {
            Fail-Contract "$code-DUPLICATE-ID"
        }
        $seen.Add($caseId, $true)
        if (-not $allowedOutcomes.ContainsKey($outcome)) {
            Fail-Contract "$code-OUTCOME-ENUM"
        }
        if ($outcome -cne 'Pass') {
            Fail-Contract "$code-REQUIRED-OUTCOME"
        }
        if ($outcome -eq 'NotTested') {
            $notTestedCount += 1
        }

        if ($FalsePositive) {
            if ($caseId -notmatch '^TL-FP-[A-Z0-9][A-Z0-9-]*$') {
                Fail-Contract "$code-ID-FORMAT"
            }
        }
        else {
            if ($caseId -notmatch '^TL-(ID|TOK|JOB|IMG|HND|ENV|VR|CLEAN)-[A-Z0-9][A-Z0-9-]*$') {
                Fail-Contract "$code-ID-FORMAT"
            }
            $categories[$Matches[1]] = $true
        }
    }

    if (-not $FalsePositive) {
        foreach ($requiredCategory in @('ID', 'TOK', 'JOB', 'IMG', 'HND', 'ENV', 'VR', 'CLEAN')) {
            if (-not $categories.ContainsKey($requiredCategory)) {
                Fail-Contract "$code-CATEGORY-COVERAGE"
            }
        }
    }

    foreach ($expectedId in $expectedIds) {
        if (-not $seen.ContainsKey($expectedId)) {
            Fail-Contract "$code-EXACT-ID-SET"
        }
    }

    return [pscustomobject]@{
        ids = $seen
        count = $seen.Count
        not_tested_count = $notTestedCount
    }
}

function Assert-ReadinessCriteria {
    param([Parameter(Mandatory = $true)]$Value)

    $expectedIds = @(
        'path_file_race_protected',
        'non_elevated_per_process_launch',
        'job_before_workload',
        'descendants_contained',
        'kill_close_cancel_cleanup',
        'loader_and_root_fail_closed',
        'verified_identity_maintained',
        'mandatory_tests_unskipped'
    )
    if ($Value -isnot [System.Array] -or $Value.Count -ne $expectedIds.Count) {
        Fail-Contract 'READINESS-CRITERIA-EXACT-SET'
    }

    $expectedSet = New-OrdinalStringSet -Values $expectedIds
    $seen = New-OrdinalStringSet
    $satisfiedCount = 0
    foreach ($criterion in $Value) {
        Assert-ExactProperties -Value $criterion -Expected @(
            'criterion_id',
            'required',
            'prototype_result'
        ) -Code 'READINESS-CRITERION'
        if ($criterion.criterion_id -isnot [string] -or
            -not $expectedSet.ContainsKey($criterion.criterion_id) -or
            $seen.ContainsKey($criterion.criterion_id)) {
            Fail-Contract 'READINESS-CRITERIA-EXACT-SET'
        }
        $seen.Add($criterion.criterion_id, $true)
        Assert-Boolean -Value $criterion.required -Code 'READINESS-CRITERION-REQUIRED'
        Assert-Boolean -Value $criterion.prototype_result -Code 'READINESS-CRITERION-RESULT'
        if (-not $criterion.required) {
            Fail-Contract 'READINESS-CRITERION-MUST-BE-REQUIRED'
        }
        if ($criterion.prototype_result) {
            $satisfiedCount += 1
        }
    }

    foreach ($expectedId in $expectedIds) {
        if (-not $seen.ContainsKey($expectedId)) {
            Fail-Contract 'READINESS-CRITERIA-EXACT-SET'
        }
    }

    return $satisfiedCount
}

try {
    $fixtureItem = Get-Item -LiteralPath $ContractPath -ErrorAction Stop
    if ($fixtureItem.PSIsContainer -or $fixtureItem.Length -le 0 -or $fixtureItem.Length -gt 1048576) {
        Fail-Contract 'FIXTURE-SIZE'
    }

    try {
        $bytes = [System.IO.File]::ReadAllBytes($fixtureItem.FullName)
    }
    catch {
        Fail-Contract 'FIXTURE-READ'
    }

    $offset = 0
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        $offset = 3
    }
    try {
        $utf8 = New-Object System.Text.UTF8Encoding($false, $true)
        $json = $utf8.GetString($bytes, $offset, $bytes.Length - $offset)
    }
    catch {
        Fail-Contract 'FIXTURE-UTF8'
    }
    try {
        $contract = $json | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        Fail-Contract 'FIXTURE-JSON'
    }

    Assert-ExactProperties -Value $contract -Expected @(
        'contract_version',
        'stage',
        'status',
        'readiness',
        'backend_pin',
        'threat_model',
        'accepted_path_classes',
        'allowed_velociraptor_commands',
        'mandatory_cases',
        'false_positive_cases',
        'privacy'
    ) -Code 'TOP-LEVEL'

    if ($contract.contract_version -isnot [int] -or $contract.contract_version -ne 1) {
        Fail-Contract 'CONTRACT-VERSION'
    }
    if ($contract.stage -cne 'VELOCIRAPTOR-ADAPTER-TRUST-LAUNCH1') {
        Fail-Contract 'STAGE'
    }

    $allowedStatuses = New-OrdinalStringSet -Values @(
        'trust_launch_contract_ready_for_review',
        'trust_launch_partial_blockers_remain',
        'trust_launch_binary_binding_failed',
        'trust_launch_non_elevated_launch_unresolved',
        'trust_launch_job_containment_unresolved',
        'unable_to_test_trust_launch_safely'
    )
    if ($contract.status -isnot [string] -or -not $allowedStatuses.ContainsKey($contract.status)) {
        Fail-Contract 'STATUS-ENUM'
    }

    Assert-ExactProperties -Value $contract.readiness -Expected @(
        'production_adapter_ready',
        'mandatory_cases_complete',
        'criteria'
    ) -Code 'READINESS'
    Assert-Boolean -Value $contract.readiness.production_adapter_ready -Code 'PRODUCTION-READY'
    Assert-Boolean -Value $contract.readiness.mandatory_cases_complete -Code 'MANDATORY-COMPLETE'
    if ($contract.readiness.production_adapter_ready) {
        Fail-Contract 'PRODUCTION-READY-MUST-BE-FALSE'
    }
    $satisfiedReadinessCriteria = Assert-ReadinessCriteria -Value $contract.readiness.criteria

    Assert-ExactProperties -Value $contract.backend_pin -Expected @(
        'release',
        'source_commit',
        'asset_name',
        'sha256',
        'authenticode_signer',
        'openpgp_fingerprint'
    ) -Code 'BACKEND-PIN'
    if ($contract.backend_pin.release -cne 'v0.77.1' -or
        $contract.backend_pin.source_commit -cne '3137c7f714ab344dd37d0df1d5393573e41b30a5' -or
        $contract.backend_pin.asset_name -cne 'velociraptor-v0.77.1-windows-amd64.exe' -or
        $contract.backend_pin.sha256 -cne 'c91cf8a32731c4c45c148393bc7d2af688c392194a9fffc4535e8b583260d55e' -or
        $contract.backend_pin.authenticode_signer -cne 'Rapid7 LLC' -or
        $contract.backend_pin.openpgp_fingerprint -cne '0572F28B4EF19A043F4CBBE0B22A7FB19CB6CFA1') {
        Fail-Contract 'BACKEND-PIN-VALUE'
    }

    Assert-ExactProperties -Value $contract.threat_model -Expected @(
        'assurance',
        'in_scope',
        'out_of_scope'
    ) -Code 'THREAT-MODEL'
    if ($contract.threat_model.assurance -isnot [string] -or
        [string]::IsNullOrWhiteSpace($contract.threat_model.assurance) -or
        $contract.threat_model.assurance -match '(?i)all local attackers') {
        Fail-Contract 'THREAT-MODEL-ASSURANCE'
    }
    [void](Assert-UniqueStringArray -Value $contract.threat_model.in_scope -Code 'THREAT-IN-SCOPE')
    [void](Assert-UniqueStringArray -Value $contract.threat_model.out_of_scope -Code 'THREAT-OUT-OF-SCOPE')

    Assert-ExactStringSet -Value $contract.accepted_path_classes -Expected @(
        'PrivateExecutionRoot',
        'System32',
        'WindowsComponentStore'
    ) -Code 'PATH-CLASSES'
    Assert-ExactStringSet -Value $contract.allowed_velociraptor_commands -Expected @(
        'version',
        'help',
        'synthetic_custom_artifact'
    ) -Code 'ALLOWED-COMMANDS'

    $mandatory = Assert-CaseArray -Value $contract.mandatory_cases -FalsePositive $false
    $falsePositive = Assert-CaseArray -Value $contract.false_positive_cases -FalsePositive $true
    foreach ($falsePositiveId in $falsePositive.ids.Keys) {
        if ($mandatory.ids.ContainsKey($falsePositiveId)) {
            Fail-Contract 'CASE-ID-OVERLAP'
        }
    }

    if ($contract.status -eq 'trust_launch_contract_ready_for_review') {
        if (-not $contract.readiness.mandatory_cases_complete -or
            $mandatory.not_tested_count -ne 0 -or
            $satisfiedReadinessCriteria -ne 8) {
            Fail-Contract 'READY-WITH-INCOMPLETE-CASES'
        }
    }

    Assert-ExactProperties -Value $contract.privacy -Expected @(
        'synthetic_only',
        'contains_absolute_paths',
        'contains_account_identity',
        'contains_raw_module_paths',
        'contains_process_ids',
        'contains_raw_output'
    ) -Code 'PRIVACY'
    foreach ($privacyBoolean in @(
        'synthetic_only',
        'contains_absolute_paths',
        'contains_account_identity',
        'contains_raw_module_paths',
        'contains_process_ids',
        'contains_raw_output'
    )) {
        Assert-Boolean -Value $contract.privacy.$privacyBoolean -Code 'PRIVACY-FLAG'
    }
    if (-not $contract.privacy.synthetic_only -or
        $contract.privacy.contains_absolute_paths -or
        $contract.privacy.contains_account_identity -or
        $contract.privacy.contains_raw_module_paths -or
        $contract.privacy.contains_process_ids -or
        $contract.privacy.contains_raw_output) {
        Fail-Contract 'PRIVACY-FLAG-VALUE'
    }

    Assert-PrivacySafeValue -Value $contract

    [pscustomobject]@{
        status = 'PASS'
        contract_version = 1
        stage = 'VELOCIRAPTOR-ADAPTER-TRUST-LAUNCH1'
        declared_status = $contract.status
        mandatory_case_count = $mandatory.count
        false_positive_case_count = $falsePositive.count
        mandatory_not_tested_count = $mandatory.not_tested_count
        readiness_criteria_satisfied = $satisfiedReadinessCriteria
        binary_execution_attempted = $false
        privacy_scan_passed = $true
    } | ConvertTo-Json -Depth 4
}
catch {
    $controlledCode = [string]$_.Exception.Message
    if (-not $controlledCode.StartsWith($script:FailurePrefix, [System.StringComparison]::Ordinal)) {
        $controlledCode = "$($script:FailurePrefix)VALIDATION-FAILED"
    }
    [Console]::Error.WriteLine("Test-TrustLaunchContract: $controlledCode")
    exit 1
}
