[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Path,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedSha256,

    [ValidateSet('AMD64', 'I386', 'ARM64')]
    [string]$ExpectedArchitecture = 'AMD64'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.Security

if (-not ('SecAppOfflineWinTrust' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class SecAppOfflineWinTrust
{
    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_FILE_INFO
    {
        public UInt32 cbStruct;
        public IntPtr pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public UInt32 cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public UInt32 dwUIChoice;
        public UInt32 fdwRevocationChecks;
        public UInt32 dwUnionChoice;
        public IntPtr pFile;
        public UInt32 dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public UInt32 dwProvFlags;
        public UInt32 dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    private static extern Int32 WinVerifyTrust(
        IntPtr hwnd,
        ref Guid actionId,
        IntPtr trustData);

    public static Int32 VerifyFileCacheOnly(string fileName)
    {
        IntPtr pathPointer = IntPtr.Zero;
        IntPtr fileInfoPointer = IntPtr.Zero;
        IntPtr trustDataPointer = IntPtr.Zero;
        Guid action = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

        try
        {
            pathPointer = Marshal.StringToCoTaskMemUni(fileName);
            WINTRUST_FILE_INFO fileInfo = new WINTRUST_FILE_INFO();
            fileInfo.cbStruct = (UInt32)Marshal.SizeOf(typeof(WINTRUST_FILE_INFO));
            fileInfo.pcwszFilePath = pathPointer;
            fileInfo.hFile = IntPtr.Zero;
            fileInfo.pgKnownSubject = IntPtr.Zero;

            fileInfoPointer = Marshal.AllocCoTaskMem(Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)));
            Marshal.StructureToPtr(fileInfo, fileInfoPointer, false);

            WINTRUST_DATA trustData = new WINTRUST_DATA();
            trustData.cbStruct = (UInt32)Marshal.SizeOf(typeof(WINTRUST_DATA));
            trustData.dwUIChoice = 2;                 // WTD_UI_NONE
            trustData.fdwRevocationChecks = 0;        // WTD_REVOKE_NONE
            trustData.dwUnionChoice = 1;              // WTD_CHOICE_FILE
            trustData.pFile = fileInfoPointer;
            trustData.dwStateAction = 1;              // WTD_STATEACTION_VERIFY
            trustData.dwProvFlags = 0x1000u | 0x2000u | 0x10u;
                                                      // CACHE_ONLY_URL_RETRIEVAL,
                                                      // DISABLE_MD2_MD4,
                                                      // REVOCATION_CHECK_NONE

            trustDataPointer = Marshal.AllocCoTaskMem(Marshal.SizeOf(typeof(WINTRUST_DATA)));
            Marshal.StructureToPtr(trustData, trustDataPointer, false);
            Int32 result = WinVerifyTrust(IntPtr.Zero, ref action, trustDataPointer);

            trustData = (WINTRUST_DATA)Marshal.PtrToStructure(trustDataPointer, typeof(WINTRUST_DATA));
            trustData.dwStateAction = 2;              // WTD_STATEACTION_CLOSE
            Marshal.StructureToPtr(trustData, trustDataPointer, true);
            WinVerifyTrust(IntPtr.Zero, ref action, trustDataPointer);
            return result;
        }
        finally
        {
            if (trustDataPointer != IntPtr.Zero) Marshal.FreeCoTaskMem(trustDataPointer);
            if (fileInfoPointer != IntPtr.Zero) Marshal.FreeCoTaskMem(fileInfoPointer);
            if (pathPointer != IntPtr.Zero) Marshal.FreeCoTaskMem(pathPointer);
        }
    }
}
'@
}

function Get-CertificateSummary {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)

    if ($null -eq $Certificate) {
        return $null
    }

    return [ordered]@{
        subject = $Certificate.Subject
        issuer = $Certificate.Issuer
        serial_number = $Certificate.SerialNumber
        thumbprint_sha1 = $Certificate.Thumbprint.ToLowerInvariant()
        not_before_utc = $Certificate.NotBefore.ToUniversalTime().ToString('o')
        not_after_utc = $Certificate.NotAfter.ToUniversalTime().ToString('o')
    }
}

function Get-OfflineChainSummary {
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]$ExtraStore,
        [Nullable[datetime]]$VerificationTime
    )

    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    try {
        $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
        $chain.ChainPolicy.RevocationFlag = [System.Security.Cryptography.X509Certificates.X509RevocationFlag]::ExcludeRoot
        $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag
        $chain.ChainPolicy.UrlRetrievalTimeout = [TimeSpan]::Zero
        if ($chain.ChainPolicy.PSObject.Properties.Name -contains 'DisableCertificateDownloads') {
            $chain.ChainPolicy.DisableCertificateDownloads = $true
        }
        if ($null -ne $ExtraStore -and $ExtraStore.Count -gt 0) {
            $chain.ChainPolicy.ExtraStore.AddRange($ExtraStore)
        }
        if ($null -ne $VerificationTime) {
            $chain.ChainPolicy.VerificationTime = [datetime]$VerificationTime
        }

        $valid = $chain.Build($Certificate)
        $statuses = @($chain.ChainStatus | ForEach-Object {
            [ordered]@{
                status = $_.Status.ToString()
                information = $_.StatusInformation.Trim()
            }
        })
        $elements = @($chain.ChainElements | ForEach-Object {
            Get-CertificateSummary -Certificate $_.Certificate
        })
        return [ordered]@{
            valid_offline_no_revocation = $valid
            statuses = $statuses
            elements = $elements
        }
    }
    finally {
        $chain.Dispose()
    }
}

function Find-GeneralizedTime {
    param([byte[]]$Bytes)

    $ascii = [Text.Encoding]::ASCII.GetString($Bytes)
    $match = [regex]::Match($ascii, '(?<![0-9])([0-9]{14}(?:\.[0-9]{1,9})?Z)(?![0-9])')
    if ($match.Success) {
        return $match.Groups[1].Value
    }
    return $null
}

$resolvedPath = (Resolve-Path -LiteralPath $Path).Path
$item = Get-Item -LiteralPath $resolvedPath
if (-not $item.PSIsContainer -and $item.Length -gt 0) {
    $actualSha256 = (Get-FileHash -LiteralPath $resolvedPath -Algorithm SHA256).Hash.ToLowerInvariant()
}
else {
    throw 'Authenticode input must be a non-empty file'
}

if ($actualSha256 -ne $ExpectedSha256.ToLowerInvariant()) {
    throw 'SHA-256 does not match the independently pinned release digest'
}

$stream = [IO.File]::Open($resolvedPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
$reader = New-Object IO.BinaryReader($stream)
try {
    if ($reader.ReadUInt16() -ne 0x5a4d) {
        throw 'Invalid DOS MZ signature'
    }
    $stream.Position = 0x3c
    $peOffset = $reader.ReadUInt32()
    if ($peOffset -gt ($stream.Length - 256)) {
        throw 'PE header offset is out of bounds'
    }
    $stream.Position = $peOffset
    if ($reader.ReadUInt32() -ne 0x00004550) {
        throw 'Invalid PE signature'
    }
    $machine = $reader.ReadUInt16()
    $architecture = switch ($machine) {
        0x8664 { 'AMD64' }
        0x014c { 'I386' }
        0xaa64 { 'ARM64' }
        default { 'Unknown' }
    }
    if ($architecture -ne $ExpectedArchitecture) {
        throw "PE architecture $architecture does not match required $ExpectedArchitecture"
    }
    $sectionCount = $reader.ReadUInt16()
    $stream.Position = $peOffset + 20
    $optionalHeaderSize = $reader.ReadUInt16()
    $stream.Position = $peOffset + 24
    $optionalMagic = $reader.ReadUInt16()
    if ($optionalMagic -eq 0x20b) {
        $dataDirectoryOffset = $peOffset + 24 + 112
    }
    elseif ($optionalMagic -eq 0x10b) {
        $dataDirectoryOffset = $peOffset + 24 + 96
    }
    else {
        throw 'Unsupported PE optional-header magic'
    }
    if (($dataDirectoryOffset + 40) -gt ($peOffset + 24 + $optionalHeaderSize)) {
        throw 'PE security directory is outside the optional header'
    }

    $stream.Position = $dataDirectoryOffset + 32
    $certificateOffset = $reader.ReadUInt32()
    $certificateTableSize = $reader.ReadUInt32()
    if ($certificateOffset -eq 0 -or $certificateTableSize -lt 8 -or
        ([uint64]$certificateOffset + [uint64]$certificateTableSize) -gt [uint64]$stream.Length) {
        throw 'PE certificate table is absent or out of bounds'
    }

    $stream.Position = $certificateOffset
    $certificateLength = $reader.ReadUInt32()
    $certificateRevision = $reader.ReadUInt16()
    $certificateType = $reader.ReadUInt16()
    if ($certificateLength -lt 8 -or $certificateLength -gt $certificateTableSize -or $certificateType -ne 2) {
        throw 'Unsupported or invalid WIN_CERTIFICATE entry'
    }
    $cmsBytes = $reader.ReadBytes([int]$certificateLength - 8)
    if ($cmsBytes.Length -ne ([int]$certificateLength - 8)) {
        throw 'Truncated Authenticode CMS payload'
    }
}
finally {
    $reader.Dispose()
    $stream.Dispose()
}

$cms = New-Object System.Security.Cryptography.Pkcs.SignedCms
$cms.Decode($cmsBytes)
$cms.CheckSignature($true)
if ($cms.SignerInfos.Count -ne 1) {
    throw 'Expected exactly one primary Authenticode signer'
}
$signerInfo = $cms.SignerInfos[0]
$signerCertificate = $signerInfo.Certificate
if ($null -eq $signerCertificate) {
    throw 'Authenticode signer certificate is missing'
}

$timestampKind = 'None'
$timestampCertificate = $null
$timestampCryptographicStatus = 'NotPresent'
$timestampTimeRaw = $null

if ($signerInfo.CounterSignerInfos.Count -gt 0) {
    if ($signerInfo.CounterSignerInfos.Count -ne 1) {
        throw 'Multiple legacy Authenticode countersignatures are not accepted'
    }
    $timestampKind = 'LegacyCounterSignature'
    $counterSigner = $signerInfo.CounterSignerInfos[0]
    $counterSigner.CheckSignature($true)
    $timestampCertificate = $counterSigner.Certificate
    foreach ($attribute in $counterSigner.SignedAttributes) {
        if ($attribute.Oid.Value -eq '1.2.840.113549.1.9.5' -and $attribute.Values.Count -eq 1) {
            $signingTime = New-Object -TypeName System.Security.Cryptography.Pkcs.Pkcs9SigningTime -ArgumentList (,$attribute.Values[0].RawData)
            $timestampTimeRaw = $signingTime.SigningTime.ToUniversalTime().ToString('o')
        }
    }
    $timestampCryptographicStatus = 'Valid'
}
else {
    $rfc3161Attributes = @($signerInfo.UnsignedAttributes | Where-Object {
        $_.Oid.Value -eq '1.3.6.1.4.1.311.3.3.1'
    })
    if ($rfc3161Attributes.Count -gt 1) {
        throw 'Multiple RFC3161 timestamp attributes are not accepted'
    }
    if ($rfc3161Attributes.Count -eq 1) {
        if ($rfc3161Attributes[0].Values.Count -ne 1) {
            throw 'RFC3161 timestamp attribute must contain exactly one value'
        }
        $timestampKind = 'RFC3161'
        $timestampCms = New-Object System.Security.Cryptography.Pkcs.SignedCms
        $timestampCms.Decode($rfc3161Attributes[0].Values[0].RawData)
        $timestampCms.CheckSignature($true)
        if ($timestampCms.SignerInfos.Count -ne 1) {
            throw 'Expected exactly one RFC3161 timestamp signer'
        }
        $timestampCertificate = $timestampCms.SignerInfos[0].Certificate
        $timestampTimeRaw = Find-GeneralizedTime -Bytes $timestampCms.ContentInfo.Content
        $timestampCryptographicStatus = 'Valid'
        foreach ($certificate in $timestampCms.Certificates) {
            [void]$cms.Certificates.Add($certificate)
        }
    }
}

$verificationTime = $null
if ($timestampTimeRaw -and $timestampTimeRaw -match '^[0-9]{14}Z$') {
    $verificationTime = [datetime]::ParseExact(
        $timestampTimeRaw,
        'yyyyMMddHHmmssZ',
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal)
}

$winTrustResult = [SecAppOfflineWinTrust]::VerifyFileCacheOnly($resolvedPath)
$winTrustHex = ('0x{0:X8}' -f ([uint32]$winTrustResult))
$streams = @(Get-Item -LiteralPath $resolvedPath -Stream * -ErrorAction Stop | ForEach-Object {
    [ordered]@{ name = $_.Stream; length = $_.Length }
})
$adjacentDlls = @(Get-ChildItem -LiteralPath $item.DirectoryName -File -Filter '*.dll' | ForEach-Object { $_.Name })

$result = [ordered]@{
    status = if ($winTrustResult -eq 0) { 'VALID_OFFLINE_CACHE_ONLY_NO_REVOCATION' } else { 'INVALID' }
    file_name = $item.Name
    file_size_bytes = $item.Length
    sha256 = $actualSha256
    pe = [ordered]@{
        machine_hex = ('0x{0:X4}' -f $machine)
        architecture = $architecture
        optional_header = if ($optionalMagic -eq 0x20b) { 'PE32+' } else { 'PE32' }
        section_count = $sectionCount
    }
    winverifytrust = [ordered]@{
        result = $winTrustHex
        cache_only_url_retrieval = $true
        revocation_mode = 'NoCheck'
    }
    authenticode = [ordered]@{
        cms_signature = 'Valid'
        win_certificate_revision = ('0x{0:X4}' -f $certificateRevision)
        certificate_table_size = $certificateTableSize
        signer = Get-CertificateSummary -Certificate $signerCertificate
        signer_chain = Get-OfflineChainSummary -Certificate $signerCertificate -ExtraStore $cms.Certificates -VerificationTime $verificationTime
        timestamp = [ordered]@{
            kind = $timestampKind
            cryptographic_status = $timestampCryptographicStatus
            time = $timestampTimeRaw
            signer = Get-CertificateSummary -Certificate $timestampCertificate
            chain = if ($null -ne $timestampCertificate) {
                Get-OfflineChainSummary -Certificate $timestampCertificate -ExtraStore $cms.Certificates -VerificationTime $verificationTime
            } else { $null }
        }
    }
    alternate_streams = $streams
    adjacent_dlls = $adjacentDlls
}

$result | ConvertTo-Json -Depth 12
if ($winTrustResult -ne 0) {
    exit 1
}
