using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;

// Development-only Windows trust-launch compatibility probe. This is not a
// production launcher. It deliberately leaves unsupported claims as NotTested.
internal static class Program
{
    private const string ExpectedStatus = "trust_launch_partial_blockers_remain";
    internal const string PinnedSha256 = "c91cf8a32731c4c45c148393bc7d2af688c392194a9fffc4535e8b583260d55e";
    private const int ExitHarnessFailure = 1;
    private const int ExitSecurityBlocker = 2;

    private static int Main(string[] args)
    {
        try
        {
            if (args.Length == 0)
            {
                throw new ControlledException("USAGE", null);
            }

            string mode = args[0];
            Dictionary<string, string> options = ParseOptions(args, 1);
            if (String.Equals(mode, "suite", StringComparison.Ordinal))
            {
                return new ProbeSuite(options).Run();
            }
            if (String.Equals(mode, "race-worker", StringComparison.Ordinal))
            {
                return RaceWorker.Run(options);
            }
            if (String.Equals(mode, "tree-parent", StringComparison.Ordinal))
            {
                return TreeWorker.RunParent(options);
            }
            if (String.Equals(mode, "tree-child", StringComparison.Ordinal))
            {
                return TreeWorker.RunChild(options);
            }
            if (String.Equals(mode, "handle-leak", StringComparison.Ordinal))
            {
                return HandleLeakWorker.Run(options);
            }
            if (String.Equals(mode, "environment-report", StringComparison.Ordinal))
            {
                return EnvironmentWorker.Run(options);
            }
            if (String.Equals(mode, "reparse-worker", StringComparison.Ordinal))
            {
                return ReparseWorker.Run(options);
            }

            throw new ControlledException("UNKNOWN_MODE", null);
        }
        catch (ControlledException error)
        {
            Console.Error.WriteLine("trust-launch-probe: " + error.Code +
                (error.SystemError.HasValue ? ":" + error.SystemError.Value.ToString(CultureInfo.InvariantCulture) : String.Empty));
            return ExitHarnessFailure;
        }
        catch (Exception)
        {
            Console.Error.WriteLine("trust-launch-probe: UNCONTROLLED_HARNESS_FAILURE");
            return ExitHarnessFailure;
        }
    }

    internal static Dictionary<string, string> ParseOptions(string[] args, int start)
    {
        Dictionary<string, string> result = new Dictionary<string, string>(StringComparer.Ordinal);
        if (((args.Length - start) & 1) != 0)
        {
            throw new ControlledException("OPTION_VALUE_REQUIRED", null);
        }
        for (int index = start; index < args.Length; index += 2)
        {
            string name = args[index];
            string value = args[index + 1];
            if (!name.StartsWith("--", StringComparison.Ordinal) || result.ContainsKey(name))
            {
                throw new ControlledException("INVALID_OR_DUPLICATE_OPTION", null);
            }
            if (value.IndexOf('\0') >= 0)
            {
                throw new ControlledException("NUL_IN_OPTION", null);
            }
            result.Add(name, value);
        }
        return result;
    }

    internal static string Required(Dictionary<string, string> options, string name)
    {
        string value;
        if (!options.TryGetValue(name, out value) || value.Length == 0)
        {
            throw new ControlledException("MISSING_OPTION", null);
        }
        return value;
    }

    internal static int BoundedInt(Dictionary<string, string> options, string name, int minimum, int maximum)
    {
        string text = Required(options, name);
        int value;
        if (!Int32.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out value) ||
            value < minimum || value > maximum)
        {
            throw new ControlledException("INVALID_BOUNDED_INTEGER", null);
        }
        return value;
    }

    internal static string QuoteArgument(string value)
    {
        if (value.IndexOf('\0') >= 0)
        {
            throw new ControlledException("NUL_IN_ARGUMENT", null);
        }
        if (value.Length != 0 && value.IndexOfAny(new char[] { ' ', '\t', '"' }) < 0)
        {
            return value;
        }

        StringBuilder builder = new StringBuilder();
        builder.Append('"');
        int slashes = 0;
        for (int index = 0; index < value.Length; index++)
        {
            char character = value[index];
            if (character == '\\')
            {
                slashes++;
                continue;
            }
            if (character == '"')
            {
                builder.Append('\\', checked(slashes * 2 + 1));
                builder.Append('"');
                slashes = 0;
                continue;
            }
            builder.Append('\\', slashes);
            slashes = 0;
            builder.Append(character);
        }
        builder.Append('\\', checked(slashes * 2));
        builder.Append('"');
        return builder.ToString();
    }

    internal static string BuildCommandLine(string application, IList<string> arguments)
    {
        StringBuilder builder = new StringBuilder(QuoteArgument(application));
        for (int index = 0; index < arguments.Count; index++)
        {
            builder.Append(' ');
            builder.Append(QuoteArgument(arguments[index]));
        }
        if (builder.Length >= 32767)
        {
            throw new ControlledException("COMMAND_LINE_TOO_LONG", null);
        }
        return builder.ToString();
    }

    internal static int SecurityBlockerExitCode
    {
        get { return ExitSecurityBlocker; }
    }

    internal static string DefaultFinalStatus
    {
        get { return ExpectedStatus; }
    }
}

internal sealed class ControlledException : Exception
{
    internal readonly string Code;
    internal readonly int? SystemError;

    internal ControlledException(string code, int? systemError)
        : base(code)
    {
        Code = code;
        SystemError = systemError;
    }
}

internal sealed class CaseResult
{
    internal readonly string Id;
    internal string Outcome;
    internal string Code;
    internal int? SystemError;

    internal CaseResult(string id)
    {
        Id = id;
        Outcome = "NotTested";
        Code = "NOT_REACHED";
        SystemError = null;
    }

    internal void Set(string outcome, string code, int? systemError)
    {
        Outcome = outcome;
        Code = code;
        SystemError = systemError;
    }
}

internal static class MandatoryCases
{
    internal static readonly string[] All = new string[]
    {
        "TL-ID-001-SOURCE-HANDLE",
        "TL-ID-002-DESTINATION-COPY",
        "TL-ID-003-DESTINATION-MISMATCH",
        "TL-ID-004-WRITE-LOCK",
        "TL-ID-005-REPLACE-LOCK",
        "TL-ID-006-DELETE-LOCK",
        "TL-ID-007-FILE-RENAME-LOCK",
        "TL-ID-008-EXEC-DIRECTORY-MUTATION",
        "TL-ID-009-ADJACENT-MARKER",
        "TL-ID-010-REPARSE-REPLACEMENT",
        "TL-ID-011-UNLOCK-CONTROL",
        "TL-TOK-001-CURRENT",
        "TL-TOK-002-DEFAULT",
        "TL-TOK-003-RUNASINVOKER",
        "TL-TOK-004-RESTRICTED-ATTEMPT",
        "TL-TOK-005-CHILD",
        "TL-JOB-001-ATOMIC-ASSIGN",
        "TL-JOB-002-NESTED",
        "TL-JOB-003-NORMAL",
        "TL-JOB-004-TIMEOUT",
        "TL-JOB-005-CANCEL",
        "TL-JOB-006-TREE",
        "TL-JOB-007-KILL-CLOSE",
        "TL-JOB-008-ACTIVE-LIMIT",
        "TL-JOB-009-ASSIGNMENT-FAIL",
        "TL-JOB-010-NO-ORPHAN",
        "TL-IMG-001-IMPORTS",
        "TL-IMG-002-MITIGATION",
        "TL-IMG-003-INITIAL",
        "TL-IMG-004-RUNTIME",
        "TL-IMG-005-UNEXPECTED-MODULE-REJECT",
        "TL-HND-001-EXPLICIT-LIST",
        "TL-ENV-001-ALLOWLIST",
        "TL-VR-001-PRECONDITIONS",
        "TL-VR-002-VERSION",
        "TL-VR-003-HELP",
        "TL-VR-004-SYNTHETIC",
        "TL-CLEAN-001-NO-HELPERS",
        "TL-CLEAN-002-NO-VELOCIRAPTOR",
        "TL-CLEAN-003-RUN-ROOT",
        "TL-FP-001-EXPECTED-SHA256",
        "TL-FP-002-SOURCE-FILE-ID",
        "TL-FP-003-DESTINATION-FILE-ID",
        "TL-FP-004-FILE-LOCK",
        "TL-FP-005-WRITE-REPLACE",
        "TL-FP-006-ADJACENT-MARKER",
        "TL-FP-007-ROOT-REPARSE",
        "TL-FP-008-JOB-ASSIGNMENT",
        "TL-FP-009-CHILD-JOB-MEMBERSHIP",
        "TL-FP-010-DESCENDANT-SURVIVAL",
        "TL-FP-011-CHILD-ELEVATION",
        "TL-FP-012-LINKED-TOKEN",
        "TL-FP-013-UNEXPECTED-MODULE",
        "TL-FP-014-MITIGATION-MISSING",
        "TL-FP-015-HANDLE-LEAK",
        "TL-FP-016-SILENT-FALLBACK"
    };
}

internal sealed class SafeKernelHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    private SafeKernelHandle()
        : base(true)
    {
    }

    internal SafeKernelHandle(IntPtr handle, bool ownsHandle)
        : base(ownsHandle)
    {
        SetHandle(handle);
    }

    protected override bool ReleaseHandle()
    {
        return NativeMethods.CloseHandle(handle);
    }
}

[StructLayout(LayoutKind.Sequential)]
internal struct FileId128
{
    internal ulong Low;
    internal ulong High;
}

[StructLayout(LayoutKind.Sequential)]
internal struct FileIdInfo
{
    internal ulong VolumeSerialNumber;
    internal FileId128 FileId;
}

[StructLayout(LayoutKind.Sequential)]
internal struct FileAttributeTagInfo
{
    internal uint FileAttributes;
    internal uint ReparseTag;
}

[StructLayout(LayoutKind.Sequential)]
internal struct FileCaseSensitiveInfo
{
    internal uint Flags;
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal struct StartupInfo
{
    internal int cb;
    internal string lpReserved;
    internal string lpDesktop;
    internal string lpTitle;
    internal uint dwX;
    internal uint dwY;
    internal uint dwXSize;
    internal uint dwYSize;
    internal uint dwXCountChars;
    internal uint dwYCountChars;
    internal uint dwFillAttribute;
    internal uint dwFlags;
    internal short wShowWindow;
    internal short cbReserved2;
    internal IntPtr lpReserved2;
    internal IntPtr hStdInput;
    internal IntPtr hStdOutput;
    internal IntPtr hStdError;
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal struct StartupInfoEx
{
    internal StartupInfo StartupInfo;
    internal IntPtr lpAttributeList;
}

[StructLayout(LayoutKind.Sequential)]
internal struct ProcessInformation
{
    internal IntPtr hProcess;
    internal IntPtr hThread;
    internal uint dwProcessId;
    internal uint dwThreadId;
}

[StructLayout(LayoutKind.Sequential)]
internal struct SecurityAttributes
{
    internal int nLength;
    internal IntPtr lpSecurityDescriptor;
    [MarshalAs(UnmanagedType.Bool)]
    internal bool bInheritHandle;
}

[StructLayout(LayoutKind.Sequential)]
internal struct JobBasicLimitInformation
{
    internal long PerProcessUserTimeLimit;
    internal long PerJobUserTimeLimit;
    internal uint LimitFlags;
    internal UIntPtr MinimumWorkingSetSize;
    internal UIntPtr MaximumWorkingSetSize;
    internal uint ActiveProcessLimit;
    internal UIntPtr Affinity;
    internal uint PriorityClass;
    internal uint SchedulingClass;
}

[StructLayout(LayoutKind.Sequential)]
internal struct IoCounters
{
    internal ulong ReadOperationCount;
    internal ulong WriteOperationCount;
    internal ulong OtherOperationCount;
    internal ulong ReadTransferCount;
    internal ulong WriteTransferCount;
    internal ulong OtherTransferCount;
}

[StructLayout(LayoutKind.Sequential)]
internal struct JobExtendedLimitInformation
{
    internal JobBasicLimitInformation BasicLimitInformation;
    internal IoCounters IoInfo;
    internal UIntPtr ProcessMemoryLimit;
    internal UIntPtr JobMemoryLimit;
    internal UIntPtr PeakProcessMemoryUsed;
    internal UIntPtr PeakJobMemoryUsed;
}

[StructLayout(LayoutKind.Sequential)]
internal struct SidAndAttributes
{
    internal IntPtr Sid;
    internal uint Attributes;
}

[StructLayout(LayoutKind.Sequential)]
internal struct Luid
{
    internal uint LowPart;
    internal int HighPart;
}

internal static class NativeMethods
{
    internal const uint GenericRead = 0x80000000;
    internal const uint GenericWrite = 0x40000000;
    internal const uint FileReadAttributes = 0x00000080;
    internal const uint Synchronize = 0x00100000;
    internal const uint FileShareRead = 0x00000001;
    internal const uint FileShareWrite = 0x00000002;
    internal const uint FileShareDelete = 0x00000004;
    internal const uint CreateNew = 1;
    internal const uint OpenExisting = 3;
    internal const uint FileAttributeNormal = 0x00000080;
    internal const uint FileAttributeDirectory = 0x00000010;
    internal const uint FileAttributeReparsePoint = 0x00000400;
    internal const uint FileFlagBackupSemantics = 0x02000000;
    internal const uint FileFlagOpenReparsePoint = 0x00200000;
    internal const uint FileFlagSequentialScan = 0x08000000;
    internal const uint FileCsFlagCaseSensitiveDir = 0x00000001;
    internal const int FileAttributeTagInfoClass = 9;
    internal const int FileIdInfoClass = 18;
    internal const int FileCaseSensitiveInfoClass = 23;

    internal const uint StartfUseStdHandles = 0x00000100;
    internal const uint CreateSuspended = 0x00000004;
    internal const uint CreateUnicodeEnvironment = 0x00000400;
    internal const uint ExtendedStartupInfoPresent = 0x00080000;
    internal const uint CreateNoWindow = 0x08000000;
    internal const uint HandleFlagInherit = 0x00000001;
    internal const uint ProcThreadAttributeHandleList = 0x00020002;
    internal const uint ProcThreadAttributeMitigationPolicy = 0x00020007;
    internal const uint ProcThreadAttributeJobList = 0x0002000d;
    internal const ulong ImageLoadNoRemoteAlwaysOn = 1UL << 52;
    internal const ulong ImageLoadNoLowLabelAlwaysOn = 1UL << 56;
    internal const ulong ImageLoadPreferSystem32AlwaysOn = 1UL << 60;
    internal const int ProcessImageLoadPolicy = 10;

    internal const int JobObjectBasicProcessIdList = 3;
    internal const int JobObjectExtendedLimitInformation = 9;
    internal const uint JobObjectLimitActiveProcess = 0x00000008;
    internal const uint JobObjectLimitProcessMemory = 0x00000100;
    internal const uint JobObjectLimitJobMemory = 0x00000200;
    internal const uint JobObjectLimitBreakawayOk = 0x00000800;
    internal const uint JobObjectLimitSilentBreakawayOk = 0x00001000;
    internal const uint JobObjectLimitKillOnJobClose = 0x00002000;

    internal const uint TokenAssignPrimary = 0x0001;
    internal const uint TokenDuplicate = 0x0002;
    internal const uint TokenQuery = 0x0008;
    internal const uint TokenAdjustDefault = 0x0080;
    internal const int TokenGroups = 2;
    internal const int TokenPrivileges = 3;
    internal const int TokenElevationType = 18;
    internal const int TokenLinkedToken = 19;
    internal const int TokenElevation = 20;
    internal const int TokenIntegrityLevel = 25;
    internal const uint DisableMaxPrivilege = 0x00000001;
    internal const uint SeGroupEnabled = 0x00000004;
    internal const uint SeGroupUseForDenyOnly = 0x00000010;
    internal const uint SePrivilegeEnabled = 0x00000002;

    internal const uint ProcessQueryLimitedInformation = 0x1000;
    internal const uint ProcessSynchronize = 0x00100000;
    internal const uint ProcessTerminate = 0x00000001;
    internal const uint WaitObject0 = 0;
    internal const uint WaitTimeout = 258;
    internal const uint Infinite = 0xffffffff;
    internal const uint StillActive = 259;
    internal const uint MoveFileReplaceExisting = 0x00000001;
    internal const uint MoveFileWriteThrough = 0x00000008;
    internal const uint SymbolicLinkFlagDirectory = 0x00000001;
    internal const uint SymbolicLinkFlagAllowUnprivilegedCreate = 0x00000002;
    internal const uint ListModulesAll = 0x00000003;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern SafeFileHandle CreateFileW(
        string fileName, uint desiredAccess, uint shareMode, IntPtr securityAttributes,
        uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool ReadFile(
        SafeFileHandle file, byte[] buffer, uint bytesToRead, out uint bytesRead, IntPtr overlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool WriteFile(
        SafeFileHandle file, byte[] buffer, uint bytesToWrite, out uint bytesWritten, IntPtr overlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool SetFilePointerEx(
        SafeFileHandle file, long distance, out long newPosition, uint moveMethod);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetFileSizeEx(SafeFileHandle file, out long size);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool FlushFileBuffers(SafeFileHandle file);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetFileInformationByHandleEx(
        SafeFileHandle file, int informationClass, out FileIdInfo information, uint size);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetFileInformationByHandleEx(
        SafeFileHandle file, int informationClass, out FileAttributeTagInfo information, uint size);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetFileInformationByHandleEx(
        SafeFileHandle file, int informationClass, out FileCaseSensitiveInfo information, uint size);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern uint GetFinalPathNameByHandleW(
        SafeFileHandle file, StringBuilder path, uint capacity, uint flags);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool DeleteFileW(string path);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool MoveFileExW(string existingPath, string newPath, uint flags);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CreateDirectoryW(string path, IntPtr securityAttributes);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CreateSymbolicLinkW(
        string symbolicLink, string target, uint flags);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool RemoveDirectoryW(string path);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern SafeKernelHandle CreateJobObjectW(IntPtr securityAttributes, string name);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool SetInformationJobObject(
        SafeKernelHandle job, int informationClass, ref JobExtendedLimitInformation information, uint length);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool QueryInformationJobObject(
        SafeKernelHandle job, int informationClass, IntPtr information, uint length, out uint returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool AssignProcessToJobObject(SafeKernelHandle job, SafeKernelHandle process);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool IsProcessInJob(
        IntPtr process, IntPtr job, [MarshalAs(UnmanagedType.Bool)] out bool result);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool IsProcessInJob(
        SafeKernelHandle process, SafeKernelHandle job, [MarshalAs(UnmanagedType.Bool)] out bool result);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool TerminateJobObject(SafeKernelHandle job, uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool InitializeProcThreadAttributeList(
        IntPtr attributeList, int attributeCount, int flags, ref IntPtr size);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool UpdateProcThreadAttribute(
        IntPtr attributeList, uint flags, IntPtr attribute, IntPtr value,
        UIntPtr size, IntPtr previousValue, IntPtr returnSize);

    [DllImport("kernel32.dll")]
    internal static extern void DeleteProcThreadAttributeList(IntPtr attributeList);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CreateProcessW(
        string applicationName, StringBuilder commandLine, IntPtr processAttributes,
        IntPtr threadAttributes, [MarshalAs(UnmanagedType.Bool)] bool inheritHandles,
        uint creationFlags, IntPtr environment, string currentDirectory,
        ref StartupInfoEx startupInfo, out ProcessInformation processInformation);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CreateProcessAsUserW(
        SafeKernelHandle token, string applicationName, StringBuilder commandLine,
        IntPtr processAttributes, IntPtr threadAttributes,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandles, uint creationFlags,
        IntPtr environment, string currentDirectory, ref StartupInfoEx startupInfo,
        out ProcessInformation processInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern uint ResumeThread(SafeKernelHandle thread);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool TerminateProcess(SafeKernelHandle process, uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern uint WaitForSingleObject(SafeKernelHandle handle, uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetExitCodeProcess(SafeKernelHandle process, out uint exitCode);

    [DllImport("kernel32.dll")]
    internal static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll")]
    internal static extern uint GetCurrentProcessId();

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern uint GetProcessId(SafeKernelHandle process);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern SafeKernelHandle OpenProcess(uint desiredAccess, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint processId);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool QueryFullProcessImageNameW(
        SafeKernelHandle process, uint flags, StringBuilder path, ref uint size);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool K32EnumProcessModulesEx(
        SafeKernelHandle process, [Out] IntPtr[] modules, uint bytes,
        out uint bytesNeeded, uint filterFlag);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern uint K32GetModuleFileNameExW(
        SafeKernelHandle process, IntPtr module, StringBuilder path, uint capacity);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetProcessMitigationPolicy(
        SafeKernelHandle process, int policy, out uint buffer, int length);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool OpenProcessToken(IntPtr process, uint desiredAccess, out SafeKernelHandle token);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool OpenProcessToken(SafeKernelHandle process, uint desiredAccess, out SafeKernelHandle token);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetTokenInformation(
        SafeKernelHandle token, int informationClass, IntPtr information,
        uint informationLength, out uint returnLength);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool LookupPrivilegeNameW(
        string systemName, IntPtr luid, StringBuilder name, ref uint nameLength);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CreateRestrictedToken(
        SafeKernelHandle existingToken, uint flags, uint disableSidCount,
        IntPtr sidsToDisable, uint deletePrivilegeCount, IntPtr privilegesToDelete,
        uint restrictedSidCount, IntPtr sidsToRestrict, out SafeKernelHandle newToken);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool ConvertStringSidToSidW(string stringSid, out IntPtr sid);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool EqualSid(IntPtr sid1, IntPtr sid2);

    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);

    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern IntPtr GetSidSubAuthority(IntPtr sid, uint index);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern IntPtr LocalFree(IntPtr memory);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern SafeFileHandle CreateFileW(
        string fileName, uint desiredAccess, uint shareMode, ref SecurityAttributes securityAttributes,
        uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool SetHandleInformation(SafeHandle handle, uint mask, uint flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetHandleInformation(IntPtr handle, out uint flags);
}

internal sealed class FileIdentity
{
    internal ulong Volume;
    internal ulong FileLow;
    internal ulong FileHigh;
    internal long Size;
    internal uint Attributes;
    internal uint ReparseTag;
    internal string FinalPath;
    internal string Sha256;

    internal bool SameObject(FileIdentity other)
    {
        return other != null && Volume == other.Volume && FileLow == other.FileLow &&
            FileHigh == other.FileHigh && Size == other.Size &&
            String.Equals(FinalPath, other.FinalPath, StringComparison.OrdinalIgnoreCase);
    }
}

internal static class FileOperations
{
    internal const long MaximumExecutableBytes = 1024L * 1024L * 1024L;

    internal static SafeFileHandle OpenReadLock(string path)
    {
        SafeFileHandle handle = NativeMethods.CreateFileW(
            path, NativeMethods.GenericRead, NativeMethods.FileShareRead, IntPtr.Zero,
            NativeMethods.OpenExisting, NativeMethods.FileAttributeNormal |
            NativeMethods.FileFlagSequentialScan | NativeMethods.FileFlagOpenReparsePoint,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new ControlledException("OPEN_READ_LOCK_FAILED", error);
        }
        ClearInherit(handle, "SOURCE_HANDLE_NONINHERIT_FAILED");
        return handle;
    }

    internal static SafeFileHandle CreateNewWriter(string path)
    {
        SafeFileHandle handle = NativeMethods.CreateFileW(
            path, NativeMethods.GenericRead | NativeMethods.GenericWrite,
            NativeMethods.FileShareRead, IntPtr.Zero, NativeMethods.CreateNew,
            NativeMethods.FileAttributeNormal | NativeMethods.FileFlagSequentialScan, IntPtr.Zero);
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new ControlledException("DESTINATION_CREATE_NEW_FAILED", error);
        }
        ClearInherit(handle, "DESTINATION_HANDLE_NONINHERIT_FAILED");
        return handle;
    }

    internal static SafeFileHandle OpenDirectory(string path, uint shareMode)
    {
        SafeFileHandle handle = NativeMethods.CreateFileW(
            path, NativeMethods.FileReadAttributes | NativeMethods.Synchronize, shareMode,
            IntPtr.Zero, NativeMethods.OpenExisting,
            NativeMethods.FileFlagBackupSemantics | NativeMethods.FileFlagOpenReparsePoint,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new ControlledException("DIRECTORY_HANDLE_OPEN_FAILED", error);
        }
        ClearInherit(handle, "DIRECTORY_HANDLE_NONINHERIT_FAILED");
        return handle;
    }

    internal static FileIdentity Inspect(SafeFileHandle handle, bool hash)
    {
        FileIdInfo id;
        if (!NativeMethods.GetFileInformationByHandleEx(
            handle, NativeMethods.FileIdInfoClass, out id,
            checked((uint)Marshal.SizeOf(typeof(FileIdInfo)))))
        {
            throw LastError("FILE_ID_QUERY_FAILED");
        }
        FileAttributeTagInfo tag;
        if (!NativeMethods.GetFileInformationByHandleEx(
            handle, NativeMethods.FileAttributeTagInfoClass, out tag,
            checked((uint)Marshal.SizeOf(typeof(FileAttributeTagInfo)))))
        {
            throw LastError("FILE_ATTRIBUTE_QUERY_FAILED");
        }
        long size;
        if (!NativeMethods.GetFileSizeEx(handle, out size))
        {
            throw LastError("FILE_SIZE_QUERY_FAILED");
        }
        if (size < 0 || size > MaximumExecutableBytes)
        {
            throw new ControlledException("FILE_SIZE_OUT_OF_RANGE", null);
        }
        return new FileIdentity
        {
            Volume = id.VolumeSerialNumber,
            FileLow = id.FileId.Low,
            FileHigh = id.FileId.High,
            Size = size,
            Attributes = tag.FileAttributes,
            ReparseTag = tag.ReparseTag,
            FinalPath = FinalPath(handle),
            Sha256 = hash ? Hash(handle) : null
        };
    }

    internal static string FinalPath(SafeFileHandle handle)
    {
        uint required = NativeMethods.GetFinalPathNameByHandleW(handle, null, 0, 0);
        if (required == 0 || required > 32768)
        {
            throw LastError("FINAL_PATH_SIZE_FAILED");
        }
        StringBuilder builder = new StringBuilder(checked((int)required + 1));
        uint written = NativeMethods.GetFinalPathNameByHandleW(
            handle, builder, checked((uint)builder.Capacity), 0);
        if (written == 0 || written >= builder.Capacity)
        {
            throw LastError("FINAL_PATH_QUERY_FAILED");
        }
        return builder.ToString();
    }

    internal static string Hash(SafeFileHandle handle)
    {
        long ignored;
        if (!NativeMethods.SetFilePointerEx(handle, 0, out ignored, 0))
        {
            throw LastError("HASH_SEEK_FAILED");
        }
        byte[] buffer = new byte[128 * 1024];
        using (SHA256 sha = SHA256.Create())
        {
            while (true)
            {
                uint read;
                if (!NativeMethods.ReadFile(handle, buffer, checked((uint)buffer.Length), out read, IntPtr.Zero))
                {
                    throw LastError("HASH_READ_FAILED");
                }
                if (read == 0)
                {
                    break;
                }
                sha.TransformBlock(buffer, 0, checked((int)read), buffer, 0);
            }
            sha.TransformFinalBlock(new byte[0], 0, 0);
            if (!NativeMethods.SetFilePointerEx(handle, 0, out ignored, 0))
            {
                throw LastError("HASH_RESET_FAILED");
            }
            return Hex(sha.Hash);
        }
    }

    internal static long Copy(SafeFileHandle source, SafeFileHandle destination)
    {
        long ignored;
        if (!NativeMethods.SetFilePointerEx(source, 0, out ignored, 0))
        {
            throw LastError("COPY_SOURCE_SEEK_FAILED");
        }
        byte[] buffer = new byte[128 * 1024];
        long total = 0;
        while (true)
        {
            uint read;
            if (!NativeMethods.ReadFile(source, buffer, checked((uint)buffer.Length), out read, IntPtr.Zero))
            {
                throw LastError("COPY_READ_FAILED");
            }
            if (read == 0)
            {
                break;
            }
            uint written;
            if (!NativeMethods.WriteFile(destination, buffer, read, out written, IntPtr.Zero))
            {
                throw LastError("COPY_WRITE_FAILED");
            }
            if (written != read)
            {
                throw new ControlledException("COPY_SHORT_WRITE", null);
            }
            total = checked(total + read);
            if (total > MaximumExecutableBytes)
            {
                throw new ControlledException("COPY_LIMIT_EXCEEDED", null);
            }
        }
        if (!NativeMethods.FlushFileBuffers(destination))
        {
            throw LastError("COPY_FLUSH_FAILED");
        }
        if (!NativeMethods.SetFilePointerEx(source, 0, out ignored, 0) ||
            !NativeMethods.SetFilePointerEx(destination, 0, out ignored, 0))
        {
            throw LastError("COPY_RESET_FAILED");
        }
        return total;
    }

    internal static void ValidateOrdinaryFile(FileIdentity identity)
    {
        if ((identity.Attributes & NativeMethods.FileAttributeDirectory) != 0 ||
            (identity.Attributes & NativeMethods.FileAttributeReparsePoint) != 0 ||
            identity.ReparseTag != 0 || identity.Size <= 0)
        {
            throw new ControlledException("NON_ORDINARY_EXECUTABLE", null);
        }
    }

    internal static void ValidateDirectoryHandle(SafeFileHandle handle)
    {
        FileAttributeTagInfo tag;
        if (!NativeMethods.GetFileInformationByHandleEx(
            handle, NativeMethods.FileAttributeTagInfoClass, out tag,
            checked((uint)Marshal.SizeOf(typeof(FileAttributeTagInfo)))))
        {
            throw LastError("DIRECTORY_ATTRIBUTE_QUERY_FAILED");
        }
        if ((tag.FileAttributes & NativeMethods.FileAttributeDirectory) == 0 ||
            (tag.FileAttributes & NativeMethods.FileAttributeReparsePoint) != 0 || tag.ReparseTag != 0)
        {
            throw new ControlledException("DIRECTORY_REPARSE_REJECTED", null);
        }
        FileCaseSensitiveInfo caseInfo;
        if (NativeMethods.GetFileInformationByHandleEx(
            handle, NativeMethods.FileCaseSensitiveInfoClass, out caseInfo,
            checked((uint)Marshal.SizeOf(typeof(FileCaseSensitiveInfo)))) &&
            (caseInfo.Flags & NativeMethods.FileCsFlagCaseSensitiveDir) != 0)
        {
            throw new ControlledException("CASE_SENSITIVE_DIRECTORY_REJECTED", null);
        }
    }

    internal static ControlledException LastError(string code)
    {
        return new ControlledException(code, Marshal.GetLastWin32Error());
    }

    internal static void ClearInherit(SafeHandle handle, string code)
    {
        if (!NativeMethods.SetHandleInformation(
            handle, NativeMethods.HandleFlagInherit, 0))
        {
            int error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new ControlledException(code, error);
        }
    }

    internal static string Hex(byte[] bytes)
    {
        StringBuilder builder = new StringBuilder(bytes.Length * 2);
        for (int index = 0; index < bytes.Length; index++)
        {
            builder.Append(bytes[index].ToString("x2", CultureInfo.InvariantCulture));
        }
        return builder.ToString();
    }
}

internal sealed class TokenSnapshot
{
    internal int ElevationType;
    internal bool Elevated;
    internal bool LinkedTokenPresent;
    internal uint IntegrityRid;
    internal bool AdminEnabled;
    internal bool AdminDenyOnly;
    internal int DangerousEnabledPrivilegeCount;

    internal bool IsNonElevated
    {
        get { return !Elevated && IntegrityRid <= 0x2000 && !AdminEnabled; }
    }
}

internal static class TokenOperations
{
    private static readonly HashSet<string> DangerousPrivileges = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "SeAssignPrimaryTokenPrivilege", "SeBackupPrivilege", "SeCreateTokenPrivilege",
        "SeDebugPrivilege", "SeImpersonatePrivilege", "SeIncreaseQuotaPrivilege",
        "SeLoadDriverPrivilege", "SeRelabelPrivilege", "SeRestorePrivilege",
        "SeTakeOwnershipPrivilege", "SeTcbPrivilege"
    };

    internal static SafeKernelHandle OpenCurrent(uint access)
    {
        SafeKernelHandle token;
        if (!NativeMethods.OpenProcessToken(NativeMethods.GetCurrentProcess(), access, out token))
        {
            throw FileOperations.LastError("OPEN_CURRENT_TOKEN_FAILED");
        }
        FileOperations.ClearInherit(token, "CURRENT_TOKEN_NONINHERIT_FAILED");
        return token;
    }

    internal static TokenSnapshot Inspect(SafeKernelHandle token)
    {
        TokenSnapshot result = new TokenSnapshot();
        result.ElevationType = ReadInt32(token, NativeMethods.TokenElevationType);
        result.Elevated = ReadInt32(token, NativeMethods.TokenElevation) != 0;
        result.LinkedTokenPresent = HasLinkedToken(token);
        result.IntegrityRid = ReadIntegrity(token);
        ReadGroups(token, result);
        result.DangerousEnabledPrivilegeCount = ReadDangerousPrivileges(token);
        return result;
    }

    private static int ReadInt32(SafeKernelHandle token, int informationClass)
    {
        IntPtr buffer = Marshal.AllocHGlobal(4);
        try
        {
            uint returned;
            if (!NativeMethods.GetTokenInformation(token, informationClass, buffer, 4, out returned) || returned < 4)
            {
                throw FileOperations.LastError("TOKEN_SCALAR_QUERY_FAILED");
            }
            return Marshal.ReadInt32(buffer);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static bool HasLinkedToken(SafeKernelHandle token)
    {
        IntPtr buffer = Marshal.AllocHGlobal(IntPtr.Size);
        try
        {
            uint returned;
            if (!NativeMethods.GetTokenInformation(
                token, NativeMethods.TokenLinkedToken, buffer, checked((uint)IntPtr.Size), out returned))
            {
                int error = Marshal.GetLastWin32Error();
                if (error == 1312 || error == 87)
                {
                    return false;
                }
                throw new ControlledException("TOKEN_LINKED_QUERY_FAILED", error);
            }
            IntPtr linked = Marshal.ReadIntPtr(buffer);
            if (linked == IntPtr.Zero)
            {
                return false;
            }
            using (SafeKernelHandle owned = new SafeKernelHandle(linked, true))
            {
                return true;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static uint ReadIntegrity(SafeKernelHandle token)
    {
        IntPtr buffer = QueryVariable(token, NativeMethods.TokenIntegrityLevel);
        try
        {
            IntPtr sid = Marshal.ReadIntPtr(buffer);
            IntPtr countPointer = NativeMethods.GetSidSubAuthorityCount(sid);
            if (countPointer == IntPtr.Zero)
            {
                throw FileOperations.LastError("TOKEN_INTEGRITY_SID_INVALID");
            }
            byte count = Marshal.ReadByte(countPointer);
            if (count == 0)
            {
                throw new ControlledException("TOKEN_INTEGRITY_SID_EMPTY", null);
            }
            IntPtr ridPointer = NativeMethods.GetSidSubAuthority(sid, checked((uint)count - 1));
            if (ridPointer == IntPtr.Zero)
            {
                throw FileOperations.LastError("TOKEN_INTEGRITY_RID_FAILED");
            }
            return unchecked((uint)Marshal.ReadInt32(ridPointer));
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static void ReadGroups(SafeKernelHandle token, TokenSnapshot snapshot)
    {
        IntPtr adminSid;
        if (!NativeMethods.ConvertStringSidToSidW("S-1-5-32-544", out adminSid))
        {
            throw FileOperations.LastError("ADMIN_SID_CREATE_FAILED");
        }
        IntPtr buffer = IntPtr.Zero;
        try
        {
            buffer = QueryVariable(token, NativeMethods.TokenGroups);
            uint count = unchecked((uint)Marshal.ReadInt32(buffer));
            if (count > 4096)
            {
                throw new ControlledException("TOKEN_GROUP_COUNT_EXCEEDED", null);
            }
            int offset = IntPtr.Size == 8 ? 8 : 4;
            int stride = Marshal.SizeOf(typeof(SidAndAttributes));
            for (uint index = 0; index < count; index++)
            {
                IntPtr entry = IntPtr.Add(buffer, checked(offset + (int)index * stride));
                IntPtr sid = Marshal.ReadIntPtr(entry);
                uint attributes = unchecked((uint)Marshal.ReadInt32(entry, IntPtr.Size));
                if (NativeMethods.EqualSid(sid, adminSid))
                {
                    snapshot.AdminEnabled = (attributes & NativeMethods.SeGroupEnabled) != 0 &&
                        (attributes & NativeMethods.SeGroupUseForDenyOnly) == 0;
                    snapshot.AdminDenyOnly = (attributes & NativeMethods.SeGroupUseForDenyOnly) != 0;
                }
            }
        }
        finally
        {
            if (buffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(buffer);
            }
            NativeMethods.LocalFree(adminSid);
        }
    }

    private static int ReadDangerousPrivileges(SafeKernelHandle token)
    {
        IntPtr buffer = QueryVariable(token, NativeMethods.TokenPrivileges);
        try
        {
            uint count = unchecked((uint)Marshal.ReadInt32(buffer));
            if (count > 1024)
            {
                throw new ControlledException("TOKEN_PRIVILEGE_COUNT_EXCEEDED", null);
            }
            int enabledDangerous = 0;
            for (uint index = 0; index < count; index++)
            {
                int offset = checked(4 + (int)index * 12);
                uint attributes = unchecked((uint)Marshal.ReadInt32(buffer, offset + 8));
                if ((attributes & NativeMethods.SePrivilegeEnabled) == 0)
                {
                    continue;
                }
                IntPtr luid = IntPtr.Add(buffer, offset);
                uint nameLength = 0;
                NativeMethods.LookupPrivilegeNameW(null, luid, null, ref nameLength);
                int firstError = Marshal.GetLastWin32Error();
                if (nameLength == 0 || (firstError != 122 && firstError != 0))
                {
                    throw new ControlledException("PRIVILEGE_NAME_SIZE_FAILED", firstError);
                }
                StringBuilder name = new StringBuilder(checked((int)nameLength + 1));
                uint capacity = checked((uint)name.Capacity);
                if (!NativeMethods.LookupPrivilegeNameW(null, luid, name, ref capacity))
                {
                    throw FileOperations.LastError("PRIVILEGE_NAME_QUERY_FAILED");
                }
                if (DangerousPrivileges.Contains(name.ToString()))
                {
                    enabledDangerous++;
                }
            }
            return enabledDangerous;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static IntPtr QueryVariable(SafeKernelHandle token, int informationClass)
    {
        uint required;
        NativeMethods.GetTokenInformation(token, informationClass, IntPtr.Zero, 0, out required);
        int firstError = Marshal.GetLastWin32Error();
        if (required == 0 || required > 1024 * 1024 || (firstError != 122 && firstError != 0))
        {
            throw new ControlledException("TOKEN_BUFFER_SIZE_FAILED", firstError);
        }
        IntPtr buffer = Marshal.AllocHGlobal(checked((int)required));
        uint returned;
        if (!NativeMethods.GetTokenInformation(token, informationClass, buffer, required, out returned) || returned > required)
        {
            int error = Marshal.GetLastWin32Error();
            Marshal.FreeHGlobal(buffer);
            throw new ControlledException("TOKEN_BUFFER_QUERY_FAILED", error);
        }
        return buffer;
    }

    internal static SafeKernelHandle CreateRestricted(SafeKernelHandle current)
    {
        string[] adminSids = new string[]
        {
            "S-1-5-32-544", "S-1-5-32-547", "S-1-5-32-548",
            "S-1-5-32-549", "S-1-5-32-550", "S-1-5-32-551"
        };
        List<IntPtr> sidPointers = new List<IntPtr>();
        IntPtr array = IntPtr.Zero;
        try
        {
            int stride = Marshal.SizeOf(typeof(SidAndAttributes));
            array = Marshal.AllocHGlobal(checked(stride * adminSids.Length));
            for (int index = 0; index < adminSids.Length; index++)
            {
                IntPtr sid;
                if (!NativeMethods.ConvertStringSidToSidW(adminSids[index], out sid))
                {
                    throw FileOperations.LastError("RESTRICTED_SID_CREATE_FAILED");
                }
                sidPointers.Add(sid);
                SidAndAttributes item = new SidAndAttributes { Sid = sid, Attributes = 0 };
                Marshal.StructureToPtr(item, IntPtr.Add(array, checked(index * stride)), false);
            }
            SafeKernelHandle restricted;
            if (!NativeMethods.CreateRestrictedToken(
                current, NativeMethods.DisableMaxPrivilege, checked((uint)adminSids.Length), array,
                0, IntPtr.Zero, 0, IntPtr.Zero, out restricted))
            {
                throw FileOperations.LastError("CREATE_RESTRICTED_TOKEN_FAILED");
            }
            FileOperations.ClearInherit(restricted, "RESTRICTED_TOKEN_NONINHERIT_FAILED");
            return restricted;
        }
        finally
        {
            if (array != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(array);
            }
            for (int index = 0; index < sidPointers.Count; index++)
            {
                NativeMethods.LocalFree(sidPointers[index]);
            }
        }
    }
}

internal sealed class AttributeList : IDisposable
{
    private IntPtr list;
    private bool initialized;
    private readonly List<IntPtr> values = new List<IntPtr>();

    internal AttributeList(int count)
    {
        IntPtr size = IntPtr.Zero;
        NativeMethods.InitializeProcThreadAttributeList(IntPtr.Zero, count, 0, ref size);
        int error = Marshal.GetLastWin32Error();
        if (size == IntPtr.Zero || error != 122)
        {
            throw new ControlledException("ATTRIBUTE_LIST_SIZE_FAILED", error);
        }
        list = Marshal.AllocHGlobal(size);
        if (!NativeMethods.InitializeProcThreadAttributeList(list, count, 0, ref size))
        {
            error = Marshal.GetLastWin32Error();
            Marshal.FreeHGlobal(list);
            list = IntPtr.Zero;
            throw new ControlledException("ATTRIBUTE_LIST_INIT_FAILED", error);
        }
        initialized = true;
    }

    internal IntPtr Pointer
    {
        get { return list; }
    }

    internal void AddPointerArray(uint attribute, IList<IntPtr> pointers)
    {
        if (pointers.Count == 0 || pointers.Count > 64)
        {
            throw new ControlledException("ATTRIBUTE_POINTER_COUNT_INVALID", null);
        }
        IntPtr value = Marshal.AllocHGlobal(checked(IntPtr.Size * pointers.Count));
        values.Add(value);
        for (int index = 0; index < pointers.Count; index++)
        {
            Marshal.WriteIntPtr(value, checked(index * IntPtr.Size), pointers[index]);
        }
        Add(attribute, value, new UIntPtr(checked((uint)(IntPtr.Size * pointers.Count))));
    }

    internal void AddUInt64(uint attribute, ulong number)
    {
        IntPtr value = Marshal.AllocHGlobal(8);
        values.Add(value);
        Marshal.WriteInt64(value, unchecked((long)number));
        Add(attribute, value, new UIntPtr(8));
    }

    private void Add(uint attribute, IntPtr value, UIntPtr size)
    {
        if (!NativeMethods.UpdateProcThreadAttribute(
            list, 0, new IntPtr(unchecked((long)attribute)), value, size, IntPtr.Zero, IntPtr.Zero))
        {
            throw FileOperations.LastError("ATTRIBUTE_UPDATE_FAILED");
        }
    }

    public void Dispose()
    {
        if (initialized)
        {
            NativeMethods.DeleteProcThreadAttributeList(list);
            initialized = false;
        }
        for (int index = 0; index < values.Count; index++)
        {
            Marshal.FreeHGlobal(values[index]);
        }
        values.Clear();
        if (list != IntPtr.Zero)
        {
            Marshal.FreeHGlobal(list);
            list = IntPtr.Zero;
        }
    }
}

internal sealed class ChildProcess : IDisposable
{
    internal SafeKernelHandle ProcessHandle;
    internal SafeKernelHandle ThreadHandle;
    internal readonly uint ProcessId;
    internal readonly bool AtomicJobRequested;
    internal readonly bool RestrictedTokenUsed;
    private bool disposed;

    internal ChildProcess(ProcessInformation information, bool atomicJobRequested, bool restrictedTokenUsed)
    {
        ProcessHandle = new SafeKernelHandle(information.hProcess, true);
        ThreadHandle = new SafeKernelHandle(information.hThread, true);
        ProcessId = information.dwProcessId;
        AtomicJobRequested = atomicJobRequested;
        RestrictedTokenUsed = restrictedTokenUsed;
    }

    internal void Resume()
    {
        uint previous = NativeMethods.ResumeThread(ThreadHandle);
        if (previous == UInt32.MaxValue)
        {
            throw FileOperations.LastError("RESUME_THREAD_FAILED");
        }
        if (previous != 1)
        {
            throw new ControlledException("UNEXPECTED_SUSPEND_COUNT", null);
        }
    }

    internal bool Wait(uint milliseconds)
    {
        uint result = NativeMethods.WaitForSingleObject(ProcessHandle, milliseconds);
        if (result == NativeMethods.WaitObject0)
        {
            return true;
        }
        if (result == NativeMethods.WaitTimeout)
        {
            return false;
        }
        throw FileOperations.LastError("PROCESS_WAIT_FAILED");
    }

    internal uint ExitCode()
    {
        uint exitCode;
        if (!NativeMethods.GetExitCodeProcess(ProcessHandle, out exitCode))
        {
            throw FileOperations.LastError("PROCESS_EXIT_QUERY_FAILED");
        }
        return exitCode;
    }

    internal void KillIfAlive()
    {
        if (ProcessHandle == null || ProcessHandle.IsClosed || ProcessHandle.IsInvalid)
        {
            return;
        }
        uint wait = NativeMethods.WaitForSingleObject(ProcessHandle, 0);
        if (wait == NativeMethods.WaitTimeout)
        {
            NativeMethods.TerminateProcess(ProcessHandle, 0xE0010001);
            NativeMethods.WaitForSingleObject(ProcessHandle, 5000);
        }
    }

    public void Dispose()
    {
        if (disposed)
        {
            return;
        }
        KillIfAlive();
        disposed = true;
        if (ThreadHandle != null)
        {
            ThreadHandle.Dispose();
        }
        if (ProcessHandle != null)
        {
            ProcessHandle.Dispose();
        }
    }
}

internal static class ProcessLauncher
{
    internal static ChildProcess CreateSuspended(
        string application, IList<string> arguments, string currentDirectory,
        string privateTemp, SafeKernelHandle job, bool includeJobAttribute,
        SafeKernelHandle restrictedToken, bool includeMitigation)
    {
        if (!Path.IsPathRooted(application) || !Path.IsPathRooted(currentDirectory) || !Path.IsPathRooted(privateTemp))
        {
            throw new ControlledException("PROCESS_PATH_NOT_ABSOLUTE", null);
        }

        SecurityAttributes inheritable = new SecurityAttributes
        {
            nLength = Marshal.SizeOf(typeof(SecurityAttributes)),
            lpSecurityDescriptor = IntPtr.Zero,
            bInheritHandle = true
        };
        using (SafeFileHandle stdin = OpenNull(NativeMethods.GenericRead, ref inheritable))
        using (SafeFileHandle stdout = OpenNull(NativeMethods.GenericWrite, ref inheritable))
        using (SafeFileHandle stderr = OpenNull(NativeMethods.GenericWrite, ref inheritable))
        using (AttributeList attributes = new AttributeList(1 + (includeMitigation ? 1 : 0) + (includeJobAttribute ? 1 : 0)))
        {
            List<IntPtr> inherited = new List<IntPtr>
            {
                stdin.DangerousGetHandle(), stdout.DangerousGetHandle(), stderr.DangerousGetHandle()
            };
            attributes.AddPointerArray(NativeMethods.ProcThreadAttributeHandleList, inherited);
            if (includeMitigation)
            {
                attributes.AddUInt64(
                    NativeMethods.ProcThreadAttributeMitigationPolicy,
                    NativeMethods.ImageLoadNoRemoteAlwaysOn |
                    NativeMethods.ImageLoadNoLowLabelAlwaysOn |
                    NativeMethods.ImageLoadPreferSystem32AlwaysOn);
            }
            if (includeJobAttribute)
            {
                if (job == null || job.IsInvalid || job.IsClosed)
                {
                    throw new ControlledException("JOB_ATTRIBUTE_WITHOUT_JOB", null);
                }
                attributes.AddPointerArray(
                    NativeMethods.ProcThreadAttributeJobList,
                    new IntPtr[] { job.DangerousGetHandle() });
            }

            StartupInfoEx startup = new StartupInfoEx();
            startup.StartupInfo.cb = Marshal.SizeOf(typeof(StartupInfoEx));
            startup.StartupInfo.dwFlags = NativeMethods.StartfUseStdHandles;
            startup.StartupInfo.hStdInput = stdin.DangerousGetHandle();
            startup.StartupInfo.hStdOutput = stdout.DangerousGetHandle();
            startup.StartupInfo.hStdError = stderr.DangerousGetHandle();
            startup.lpAttributeList = attributes.Pointer;

            IntPtr environment = BuildEnvironment(privateTemp);
            try
            {
                StringBuilder command = new StringBuilder(Program.BuildCommandLine(application, arguments));
                ProcessInformation information;
                uint flags = NativeMethods.CreateSuspended | NativeMethods.CreateUnicodeEnvironment |
                    NativeMethods.ExtendedStartupInfoPresent | NativeMethods.CreateNoWindow;
                bool created;
                if (restrictedToken != null)
                {
                    created = NativeMethods.CreateProcessAsUserW(
                        restrictedToken, application, command, IntPtr.Zero, IntPtr.Zero, true,
                        flags, environment, currentDirectory, ref startup, out information);
                }
                else
                {
                    created = NativeMethods.CreateProcessW(
                        application, command, IntPtr.Zero, IntPtr.Zero, true,
                        flags, environment, currentDirectory, ref startup, out information);
                }
                if (!created)
                {
                    int error = Marshal.GetLastWin32Error();
                    throw new ControlledException(
                        restrictedToken == null ? "CREATE_PROCESS_FAILED" : "CREATE_PROCESS_AS_USER_FAILED",
                        error);
                }
                return new ChildProcess(information, includeJobAttribute, restrictedToken != null);
            }
            finally
            {
                Marshal.FreeHGlobal(environment);
            }
        }
    }

    private static SafeFileHandle OpenNull(uint access, ref SecurityAttributes attributes)
    {
        SafeFileHandle handle = NativeMethods.CreateFileW(
            "NUL", access, NativeMethods.FileShareRead | NativeMethods.FileShareWrite,
            ref attributes, NativeMethods.OpenExisting, NativeMethods.FileAttributeNormal, IntPtr.Zero);
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new ControlledException("OPEN_NULL_FAILED", error);
        }
        return handle;
    }

    internal static IntPtr BuildEnvironment(string privateTemp)
    {
        string systemRoot = Environment.GetEnvironmentVariable("SystemRoot");
        if (String.IsNullOrEmpty(systemRoot) || !Path.IsPathRooted(systemRoot))
        {
            throw new ControlledException("SYSTEM_ROOT_INVALID", null);
        }
        SortedDictionary<string, string> environment = new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "SystemRoot", systemRoot },
            { "WINDIR", systemRoot },
            { "TEMP", privateTemp },
            { "TMP", privateTemp },
            { "PATH", Path.Combine(systemRoot, "System32") }
        };
        StringBuilder builder = new StringBuilder();
        foreach (KeyValuePair<string, string> item in environment)
        {
            if (item.Key.IndexOf('=') >= 0 || item.Value.IndexOf('\0') >= 0)
            {
                throw new ControlledException("ENVIRONMENT_VALUE_INVALID", null);
            }
            builder.Append(item.Key);
            builder.Append('=');
            builder.Append(item.Value);
            builder.Append('\0');
        }
        builder.Append('\0');
        byte[] bytes = Encoding.Unicode.GetBytes(builder.ToString());
        IntPtr memory = Marshal.AllocHGlobal(bytes.Length);
        Marshal.Copy(bytes, 0, memory, bytes.Length);
        return memory;
    }

    internal static SafeKernelHandle CreateJob(uint activeProcessLimit, bool memoryLimits)
    {
        SafeKernelHandle job = NativeMethods.CreateJobObjectW(IntPtr.Zero, null);
        if (job.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            job.Dispose();
            throw new ControlledException("CREATE_JOB_FAILED", error);
        }
        FileOperations.ClearInherit(job, "JOB_HANDLE_NONINHERIT_FAILED");
        JobExtendedLimitInformation limits = new JobExtendedLimitInformation();
        limits.BasicLimitInformation.LimitFlags =
            NativeMethods.JobObjectLimitKillOnJobClose | NativeMethods.JobObjectLimitActiveProcess;
        limits.BasicLimitInformation.ActiveProcessLimit = activeProcessLimit;
        if (memoryLimits)
        {
            limits.BasicLimitInformation.LimitFlags |=
                NativeMethods.JobObjectLimitProcessMemory | NativeMethods.JobObjectLimitJobMemory;
            limits.ProcessMemoryLimit = new UIntPtr(256UL * 1024UL * 1024UL);
            limits.JobMemoryLimit = new UIntPtr(512UL * 1024UL * 1024UL);
        }
        if (!NativeMethods.SetInformationJobObject(
            job, NativeMethods.JobObjectExtendedLimitInformation, ref limits,
            checked((uint)Marshal.SizeOf(typeof(JobExtendedLimitInformation)))))
        {
            int error = Marshal.GetLastWin32Error();
            job.Dispose();
            throw new ControlledException("SET_JOB_LIMITS_FAILED", error);
        }
        return job;
    }

    internal static bool VerifyMitigation(ChildProcess child)
    {
        uint flags;
        if (!NativeMethods.GetProcessMitigationPolicy(
            child.ProcessHandle, NativeMethods.ProcessImageLoadPolicy, out flags, 4))
        {
            throw FileOperations.LastError("MITIGATION_QUERY_FAILED");
        }
        return (flags & 0x7) == 0x7;
    }

    internal static bool VerifyJob(ChildProcess child, SafeKernelHandle job)
    {
        bool inJob;
        if (!NativeMethods.IsProcessInJob(child.ProcessHandle, job, out inJob))
        {
            throw FileOperations.LastError("JOB_MEMBERSHIP_QUERY_FAILED");
        }
        return inJob;
    }

    internal static TokenSnapshot InspectToken(ChildProcess child)
    {
        SafeKernelHandle token;
        if (!NativeMethods.OpenProcessToken(child.ProcessHandle, NativeMethods.TokenQuery, out token))
        {
            throw FileOperations.LastError("OPEN_CHILD_TOKEN_FAILED");
        }
        using (token)
        {
            return TokenOperations.Inspect(token);
        }
    }

    internal static string QueryImage(ChildProcess child)
    {
        uint capacity = 32768;
        StringBuilder builder = new StringBuilder(checked((int)capacity));
        if (!NativeMethods.QueryFullProcessImageNameW(child.ProcessHandle, 0, builder, ref capacity))
        {
            throw FileOperations.LastError("PROCESS_IMAGE_QUERY_FAILED");
        }
        return builder.ToString();
    }

    internal static ModuleInventory TryInventoryModules(
        ChildProcess child, string expectedMainImage, string privateRunRoot,
        out int? systemError)
    {
        const int maximumModules = 512;
        IntPtr[] modules = new IntPtr[maximumModules];
        uint bytesNeeded;
        uint bytes = checked((uint)(modules.Length * IntPtr.Size));
        if (!NativeMethods.K32EnumProcessModulesEx(
            child.ProcessHandle, modules, bytes, out bytesNeeded, NativeMethods.ListModulesAll))
        {
            systemError = Marshal.GetLastWin32Error();
            return null;
        }
        if ((bytesNeeded % checked((uint)IntPtr.Size)) != 0 || bytesNeeded > bytes)
        {
            throw new ControlledException("MODULE_COUNT_EXCEEDED", null);
        }

        ModuleInventory inventory = new ModuleInventory();
        int count = checked((int)(bytesNeeded / checked((uint)IntPtr.Size)));
        for (int index = 0; index < count; index++)
        {
            StringBuilder path = new StringBuilder(32768);
            uint written = NativeMethods.K32GetModuleFileNameExW(
                child.ProcessHandle, modules[index], path, checked((uint)path.Capacity));
            if (written == 0 || written >= checked((uint)path.Capacity - 1u))
            {
                inventory.Unknown++;
                continue;
            }
            inventory.Add(ClassifyModulePath(path.ToString(), expectedMainImage, privateRunRoot));
        }
        systemError = null;
        return inventory;
    }

    private static string ClassifyModulePath(
        string modulePath, string expectedMainImage, string privateRunRoot)
    {
        string normalized;
        string expected;
        try
        {
            normalized = Path.GetFullPath(modulePath).TrimEnd(
                Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            expected = Path.GetFullPath(expectedMainImage).TrimEnd(
                Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        }
        catch
        {
            return ModuleInventory.UnknownClass;
        }
        if (String.Equals(normalized, expected, StringComparison.OrdinalIgnoreCase))
        {
            return ModuleInventory.PrivateExecutionRootClass;
        }

        string systemRoot = Environment.GetEnvironmentVariable("SystemRoot");
        if (!String.IsNullOrEmpty(systemRoot))
        {
            string system32 = Path.Combine(systemRoot, "System32");
            string componentStore = Path.Combine(systemRoot, "WinSxS");
            if (PathWithin(system32, normalized)) return ModuleInventory.System32Class;
            if (PathWithin(componentStore, normalized)) return ModuleInventory.WindowsComponentStoreClass;
        }

        List<string> userWritableRoots = new List<string>();
        AddRoot(userWritableRoots, Path.GetDirectoryName(expected));
        AddRoot(userWritableRoots, privateRunRoot);
        AddRoot(userWritableRoots, Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData));
        AddRoot(userWritableRoots, Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
        AddRoot(userWritableRoots, Environment.GetEnvironmentVariable("TEMP"));
        AddRoot(userWritableRoots, Environment.GetEnvironmentVariable("TMP"));
        for (int index = 0; index < userWritableRoots.Count; index++)
        {
            if (PathWithin(userWritableRoots[index], normalized))
            {
                return ModuleInventory.UnexpectedUserWritableClass;
            }
        }
        return ModuleInventory.UnknownClass;
    }

    private static void AddRoot(List<string> roots, string path)
    {
        if (!String.IsNullOrEmpty(path) && Path.IsPathRooted(path))
        {
            roots.Add(Path.GetFullPath(path));
        }
    }

    private static bool PathWithin(string root, string candidate)
    {
        try
        {
            string normalizedRoot = Path.GetFullPath(root).TrimEnd(
                Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            string normalizedCandidate = Path.GetFullPath(candidate).TrimEnd(
                Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            return String.Equals(normalizedRoot, normalizedCandidate, StringComparison.OrdinalIgnoreCase) ||
                normalizedCandidate.StartsWith(
                    normalizedRoot + Path.DirectorySeparatorChar,
                    StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    internal static List<uint> QueryJobPids(SafeKernelHandle job)
    {
        const int capacity = 4096;
        IntPtr buffer = Marshal.AllocHGlobal(capacity);
        try
        {
            uint returned;
            if (!NativeMethods.QueryInformationJobObject(
                job, NativeMethods.JobObjectBasicProcessIdList, buffer, capacity, out returned))
            {
                throw FileOperations.LastError("JOB_PID_LIST_FAILED");
            }
            uint count = unchecked((uint)Marshal.ReadInt32(buffer, 4));
            if (count > 256)
            {
                throw new ControlledException("JOB_PID_COUNT_EXCEEDED", null);
            }
            List<uint> pids = new List<uint>();
            for (uint index = 0; index < count; index++)
            {
                long raw = IntPtr.Size == 8
                    ? Marshal.ReadInt64(buffer, checked(8 + (int)index * 8))
                    : Marshal.ReadInt32(buffer, checked(8 + (int)index * 4));
                if (raw > 0 && raw <= UInt32.MaxValue)
                {
                    pids.Add(checked((uint)raw));
                }
            }
            return pids;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }
}

internal sealed class RaceResult
{
    internal bool Succeeded;
    internal int Error;
}

internal static class RaceWorker
{
    internal static int Run(Dictionary<string, string> options)
    {
        string operation = Program.Required(options, "--operation");
        string scopeRoot = Path.GetFullPath(Program.Required(options, "--scope-root"));
        string target = Path.GetFullPath(Program.Required(options, "--target"));
        string replacement = options.ContainsKey("--replacement")
            ? Path.GetFullPath(options["--replacement"]) : null;
        if (!IsPermittedScope(scopeRoot) || !IsWithinScope(scopeRoot, target) ||
            (replacement != null && !IsWithinScope(scopeRoot, replacement)))
        {
            throw new ControlledException("RACE_SCOPE_REJECTED", null);
        }
        RaceResult result = Execute(operation, target, replacement);
        Console.Out.WriteLine((result.Succeeded ? "1" : "0") + ":" +
            result.Error.ToString(CultureInfo.InvariantCulture));
        return 0;
    }

    private static RaceResult Execute(string operation, string target, string replacement)
    {
        if (String.Equals(operation, "write", StringComparison.Ordinal))
        {
            using (SafeFileHandle handle = NativeMethods.CreateFileW(
                target, NativeMethods.GenericWrite,
                NativeMethods.FileShareRead | NativeMethods.FileShareWrite | NativeMethods.FileShareDelete,
                IntPtr.Zero, NativeMethods.OpenExisting, NativeMethods.FileAttributeNormal, IntPtr.Zero))
            {
                if (handle.IsInvalid)
                {
                    return FailedLastError();
                }
                byte[] one = new byte[] { 0x5a };
                uint written;
                bool ok = NativeMethods.WriteFile(handle, one, 1, out written, IntPtr.Zero) && written == 1;
                return new RaceResult { Succeeded = ok, Error = ok ? 0 : Marshal.GetLastWin32Error() };
            }
        }
        if (String.Equals(operation, "replace", StringComparison.Ordinal))
        {
            if (String.IsNullOrEmpty(replacement) || !Path.IsPathRooted(replacement))
            {
                throw new ControlledException("RACE_REPLACEMENT_INVALID", null);
            }
            bool ok = NativeMethods.MoveFileExW(
                replacement, target,
                NativeMethods.MoveFileReplaceExisting | NativeMethods.MoveFileWriteThrough);
            return new RaceResult { Succeeded = ok, Error = ok ? 0 : Marshal.GetLastWin32Error() };
        }
        if (String.Equals(operation, "delete", StringComparison.Ordinal))
        {
            bool ok = NativeMethods.DeleteFileW(target);
            return new RaceResult { Succeeded = ok, Error = ok ? 0 : Marshal.GetLastWin32Error() };
        }
        if (String.Equals(operation, "rename", StringComparison.Ordinal) ||
            String.Equals(operation, "dir-rename", StringComparison.Ordinal))
        {
            string renamed = target + ".renamed";
            bool ok = NativeMethods.MoveFileExW(target, renamed, NativeMethods.MoveFileWriteThrough);
            return new RaceResult { Succeeded = ok, Error = ok ? 0 : Marshal.GetLastWin32Error() };
        }
        if (String.Equals(operation, "adjacent", StringComparison.Ordinal))
        {
            using (SafeFileHandle handle = NativeMethods.CreateFileW(
                target, NativeMethods.GenericWrite, NativeMethods.FileShareRead,
                IntPtr.Zero, NativeMethods.CreateNew, NativeMethods.FileAttributeNormal, IntPtr.Zero))
            {
                if (handle.IsInvalid)
                {
                    return FailedLastError();
                }
                return new RaceResult { Succeeded = true, Error = 0 };
            }
        }
        throw new ControlledException("UNKNOWN_RACE_OPERATION", null);
    }

    private static RaceResult FailedLastError()
    {
        return new RaceResult { Succeeded = false, Error = Marshal.GetLastWin32Error() };
    }

    internal static bool IsPermittedScope(string scopeRoot)
    {
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (String.IsNullOrEmpty(localAppData) || !Path.IsPathRooted(localAppData))
        {
            return false;
        }
        string allowedBase = Path.GetFullPath(Path.Combine(
            localAppData, "SecApp", "compat", "trust-launch"));
        if (!IsWithinScope(allowedBase, scopeRoot))
        {
            return false;
        }
        string name = new DirectoryInfo(scopeRoot).Name;
        const string prefix = "trust-launch-";
        if (!name.StartsWith(prefix, StringComparison.Ordinal) || name.Length != prefix.Length + 32)
        {
            return false;
        }
        for (int index = prefix.Length; index < name.Length; index++)
        {
            char character = name[index];
            if (!((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')))
            {
                return false;
            }
        }
        return Directory.Exists(scopeRoot);
    }

    internal static bool IsWithinScope(string scopeRoot, string path)
    {
        string root = scopeRoot.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        string candidate = path.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        return String.Equals(root, candidate, StringComparison.OrdinalIgnoreCase) ||
            candidate.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }
}

internal static class TreeWorker
{
    internal static int RunParent(Dictionary<string, string> options)
    {
        int wait = Program.BoundedInt(options, "--wait-ms", 10, 60000);
        string self = Process.GetCurrentProcess().MainModule.FileName;
        ProcessStartInfo start = new ProcessStartInfo();
        start.FileName = self;
        start.Arguments = "tree-child --wait-ms " + wait.ToString(CultureInfo.InvariantCulture);
        start.UseShellExecute = false;
        start.CreateNoWindow = true;
        try
        {
            using (Process child = Process.Start(start))
            {
                Thread.Sleep(wait);
                if (!child.HasExited)
                {
                    child.WaitForExit(Math.Min(wait, 5000));
                }
            }
            return 0;
        }
        catch
        {
            Thread.Sleep(Math.Min(wait, 2000));
            return 42;
        }
    }

    internal static int RunChild(Dictionary<string, string> options)
    {
        int wait = Program.BoundedInt(options, "--wait-ms", 10, 60000);
        Thread.Sleep(wait);
        return 0;
    }
}

internal static class HandleLeakWorker
{
    internal static int Run(Dictionary<string, string> options)
    {
        string text = Program.Required(options, "--handle");
        long value;
        ulong volume;
        ulong fileLow;
        ulong fileHigh;
        if (!Int64.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out value) || value <= 0 ||
            !UInt64.TryParse(Program.Required(options, "--volume"), NumberStyles.None, CultureInfo.InvariantCulture, out volume) ||
            !UInt64.TryParse(Program.Required(options, "--file-low"), NumberStyles.None, CultureInfo.InvariantCulture, out fileLow) ||
            !UInt64.TryParse(Program.Required(options, "--file-high"), NumberStyles.None, CultureInfo.InvariantCulture, out fileHigh))
        {
            throw new ControlledException("HANDLE_VALUE_INVALID", null);
        }
        using (SafeFileHandle candidate = new SafeFileHandle(new IntPtr(value), false))
        {
            FileIdInfo identity;
            bool query = NativeMethods.GetFileInformationByHandleEx(
                candidate, NativeMethods.FileIdInfoClass, out identity,
                checked((uint)Marshal.SizeOf(typeof(FileIdInfo))));
            bool leaked = query && identity.VolumeSerialNumber == volume &&
                identity.FileId.Low == fileLow && identity.FileId.High == fileHigh;
            return leaked ? 23 : 0;
        }
    }
}

internal static class EnvironmentWorker
{
    private const int SystemRootMissing = 1 << 0;
    private const int WindirMissing = 1 << 1;
    private const int TempMissing = 1 << 2;
    private const int TmpMissing = 1 << 3;
    private const int PathMissing = 1 << 4;
    private const int UnexpectedVariable = 1 << 5;
    private const int PrivateTempMismatch = 1 << 6;
    private const int TrustedPathMismatch = 1 << 7;
    private const int ProxyVariablePresent = 1 << 8;
    private const int ToolchainVariablePresent = 1 << 9;
    private const int CredentialVariablePresent = 1 << 10;
    private const int CompatibilityLayerPresent = 1 << 11;
    private const int WindirMismatch = 1 << 12;

    internal static int Run(Dictionary<string, string> options)
    {
        if (options.Count != 1)
        {
            throw new ControlledException("ENVIRONMENT_OPTION_SET_INVALID", null);
        }
        string expectedTemp = Path.GetFullPath(Program.Required(options, "--expected-temp"));
        DirectoryInfo parent = Directory.GetParent(expectedTemp);
        if (parent == null || !RaceWorker.IsPermittedScope(parent.FullName) ||
            !RaceWorker.IsWithinScope(parent.FullName, expectedTemp) ||
            !String.Equals(new DirectoryInfo(expectedTemp).Name, "temp", StringComparison.Ordinal))
        {
            throw new ControlledException("ENVIRONMENT_EXPECTED_TEMP_SCOPE_REJECTED", null);
        }

        Dictionary<string, string> observed = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        System.Collections.IDictionary environment = Environment.GetEnvironmentVariables();
        foreach (System.Collections.DictionaryEntry entry in environment)
        {
            string key = entry.Key as string;
            string value = entry.Value as string;
            if (key == null || value == null || observed.ContainsKey(key))
            {
                return UnexpectedVariable;
            }
            observed.Add(key, value);
        }

        int failures = 0;
        string systemRoot;
        string windir;
        string temp;
        string tmp;
        string path;
        if (!observed.TryGetValue("SystemRoot", out systemRoot)) failures |= SystemRootMissing;
        if (!observed.TryGetValue("WINDIR", out windir)) failures |= WindirMissing;
        if (!observed.TryGetValue("TEMP", out temp)) failures |= TempMissing;
        if (!observed.TryGetValue("TMP", out tmp)) failures |= TmpMissing;
        if (!observed.TryGetValue("PATH", out path)) failures |= PathMissing;

        string[] allowed = new string[] { "SystemRoot", "WINDIR", "TEMP", "TMP", "PATH" };
        if (observed.Count != allowed.Length)
        {
            failures |= UnexpectedVariable;
        }
        foreach (string key in observed.Keys)
        {
            bool allowedKey = false;
            for (int index = 0; index < allowed.Length; index++)
            {
                if (String.Equals(key, allowed[index], StringComparison.OrdinalIgnoreCase))
                {
                    allowedKey = true;
                    break;
                }
            }
            if (!allowedKey) failures |= UnexpectedVariable;
            if (IsProxyVariable(key)) failures |= ProxyVariablePresent;
            if (IsToolchainVariable(key)) failures |= ToolchainVariablePresent;
            if (IsCredentialVariable(key)) failures |= CredentialVariablePresent;
            if (String.Equals(key, "__COMPAT_LAYER", StringComparison.OrdinalIgnoreCase))
            {
                failures |= CompatibilityLayerPresent;
            }
        }

        if (temp != null && tmp != null &&
            (!SamePath(temp, expectedTemp) || !SamePath(tmp, expectedTemp)))
        {
            failures |= PrivateTempMismatch;
        }
        if (systemRoot != null && path != null &&
            !SamePath(path, Path.Combine(systemRoot, "System32")))
        {
            failures |= TrustedPathMismatch;
        }
        if (systemRoot != null && windir != null && !SamePath(systemRoot, windir))
        {
            failures |= WindirMismatch;
        }
        return failures;
    }

    private static bool SamePath(string first, string second)
    {
        try
        {
            return String.Equals(
                Path.GetFullPath(first).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar),
                Path.GetFullPath(second).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar),
                StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private static bool IsProxyVariable(string key)
    {
        return String.Equals(key, "HTTP_PROXY", StringComparison.OrdinalIgnoreCase) ||
            String.Equals(key, "HTTPS_PROXY", StringComparison.OrdinalIgnoreCase) ||
            String.Equals(key, "ALL_PROXY", StringComparison.OrdinalIgnoreCase) ||
            String.Equals(key, "NO_PROXY", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsToolchainVariable(string key)
    {
        string upper = key.ToUpperInvariant();
        return upper == "PYTHONPATH" || upper == "PYTHONHOME" || upper == "NODE_PATH" ||
            upper == "NODE_OPTIONS" || upper == "CLASSPATH" || upper == "JAVA_TOOL_OPTIONS" ||
            upper == "_JAVA_OPTIONS" || upper == "RUBYLIB" || upper == "PERL5LIB" ||
            upper == "PSMODULEPATH" || upper == "BASH_ENV" || upper == "ENV" ||
            upper == "INCLUDE" || upper == "LIB" || upper == "LIBPATH" || upper == "CL" ||
            upper == "LINK" || upper.StartsWith("DOTNET_", StringComparison.Ordinal) ||
            upper.StartsWith("COMPLUS_", StringComparison.Ordinal) ||
            upper.StartsWith("COR_", StringComparison.Ordinal) ||
            upper.StartsWith("NPM_", StringComparison.Ordinal) ||
            upper.StartsWith("GIT_", StringComparison.Ordinal) ||
            upper.StartsWith("GEM_", StringComparison.Ordinal);
    }

    private static bool IsCredentialVariable(string key)
    {
        string upper = key.ToUpperInvariant();
        return upper.IndexOf("TOKEN", StringComparison.Ordinal) >= 0 ||
            upper.IndexOf("SECRET", StringComparison.Ordinal) >= 0 ||
            upper.IndexOf("PASSWORD", StringComparison.Ordinal) >= 0 ||
            upper.IndexOf("PASSWD", StringComparison.Ordinal) >= 0 ||
            upper.IndexOf("CREDENTIAL", StringComparison.Ordinal) >= 0 ||
            upper.IndexOf("API_KEY", StringComparison.Ordinal) >= 0 ||
            upper.IndexOf("ACCESS_KEY", StringComparison.Ordinal) >= 0 ||
            upper.IndexOf("PRIVATE_KEY", StringComparison.Ordinal) >= 0;
    }
}

internal static class ReparseWorker
{
    internal const int BlockedAsExpected = 10;
    internal const int UnexpectedlySucceeded = 11;
    internal const int NotSupported = 12;
    internal const int NotTested = 13;

    internal static int Run(Dictionary<string, string> options)
    {
        if (options.Count != 3)
        {
            throw new ControlledException("REPARSE_OPTION_SET_INVALID", null);
        }
        string scopeRoot = Path.GetFullPath(Program.Required(options, "--scope-root"));
        string target = Path.GetFullPath(Program.Required(options, "--target"));
        string alternate = Path.GetFullPath(Program.Required(options, "--alternate"));
        if (!RaceWorker.IsPermittedScope(scopeRoot) ||
            !RaceWorker.IsWithinScope(scopeRoot, target) ||
            !RaceWorker.IsWithinScope(scopeRoot, alternate) ||
            !String.Equals(Path.GetDirectoryName(target), scopeRoot, StringComparison.OrdinalIgnoreCase) ||
            !String.Equals(Path.GetDirectoryName(alternate), scopeRoot, StringComparison.OrdinalIgnoreCase) ||
            !String.Equals(new DirectoryInfo(target).Name, "reparse-target", StringComparison.Ordinal) ||
            !String.Equals(new DirectoryInfo(alternate).Name, "reparse-alternate", StringComparison.Ordinal))
        {
            throw new ControlledException("REPARSE_SCOPE_REJECTED", null);
        }

        string original = target + ".original";
        bool renamed = false;
        bool linkCreated = false;
        bool cleanup = true;
        int result = NotTested;
        try
        {
            if (!NativeMethods.MoveFileExW(target, original, NativeMethods.MoveFileWriteThrough))
            {
                int error = Marshal.GetLastWin32Error();
                result = error == 5 || error == 32 ? BlockedAsExpected : NotTested;
            }
            else
            {
                renamed = true;
                result = UnexpectedlySucceeded;
                linkCreated = NativeMethods.CreateSymbolicLinkW(
                    target, alternate,
                    NativeMethods.SymbolicLinkFlagDirectory |
                    NativeMethods.SymbolicLinkFlagAllowUnprivilegedCreate);
                if (!linkCreated)
                {
                    int error = Marshal.GetLastWin32Error();
                    if (error == 50 || error == 87 || error == 1314)
                    {
                        // The successful rename is already a protection failure. Lack of
                        // symlink privilege does not convert it into a security proof.
                        result = UnexpectedlySucceeded;
                    }
                }
            }
        }
        finally
        {
            if (linkCreated)
            {
                try
                {
                    FileAttributes attributes = File.GetAttributes(target);
                    cleanup = (attributes & FileAttributes.ReparsePoint) != 0 &&
                        NativeMethods.RemoveDirectoryW(target);
                }
                catch
                {
                    cleanup = false;
                }
            }
            if (renamed)
            {
                cleanup = NativeMethods.MoveFileExW(original, target, NativeMethods.MoveFileWriteThrough) && cleanup;
            }
            try
            {
                FileAttributes targetAttributes = File.GetAttributes(target);
                FileAttributes alternateAttributes = File.GetAttributes(alternate);
                cleanup = cleanup &&
                    (targetAttributes & FileAttributes.ReparsePoint) == 0 &&
                    (alternateAttributes & FileAttributes.ReparsePoint) == 0 &&
                    !Directory.Exists(original) && !File.Exists(original);
            }
            catch
            {
                cleanup = false;
            }
        }
        return cleanup ? result : NotTested;
    }
}

internal sealed class EnvironmentObservation
{
    internal bool Observed;
    internal int FailureMask;
    internal bool SystemRootPresent;
    internal bool WindirPresent;
    internal bool TempPresent;
    internal bool TmpPresent;
    internal bool PathPresent;
    internal bool ExactAllowlist;
    internal bool PrivateTemp;
    internal bool TrustedWindowsPath;
    internal bool ProxyVariablesAbsent;
    internal bool ToolchainVariablesAbsent;
    internal bool CredentialVariablesAbsent;
    internal bool CompatibilityLayerAbsent;
    internal bool WindirMatchesSystemRoot;

    internal static EnvironmentObservation FromExitCode(uint exitCode)
    {
        int mask = unchecked((int)exitCode);
        return new EnvironmentObservation
        {
            Observed = true,
            FailureMask = mask,
            SystemRootPresent = (mask & (1 << 0)) == 0,
            WindirPresent = (mask & (1 << 1)) == 0,
            TempPresent = (mask & (1 << 2)) == 0,
            TmpPresent = (mask & (1 << 3)) == 0,
            PathPresent = (mask & (1 << 4)) == 0,
            ExactAllowlist = (mask & (1 << 5)) == 0,
            PrivateTemp = (mask & ((1 << 2) | (1 << 3) | (1 << 6))) == 0,
            TrustedWindowsPath = (mask & ((1 << 0) | (1 << 4) | (1 << 7))) == 0,
            ProxyVariablesAbsent = (mask & (1 << 8)) == 0,
            ToolchainVariablesAbsent = (mask & (1 << 9)) == 0,
            CredentialVariablesAbsent = (mask & (1 << 10)) == 0,
            CompatibilityLayerAbsent = (mask & (1 << 11)) == 0,
            WindirMatchesSystemRoot = (mask & ((1 << 0) | (1 << 1) | (1 << 12))) == 0
        };
    }
}

internal sealed class ModuleInventory
{
    internal const string PrivateExecutionRootClass = "PrivateExecutionRoot";
    internal const string System32Class = "System32";
    internal const string WindowsComponentStoreClass = "WindowsComponentStore";
    internal const string UnexpectedUserWritableClass = "UnexpectedUserWritable";
    internal const string UnknownClass = "Unknown";

    internal int PrivateExecutionRoot;
    internal int System32;
    internal int WindowsComponentStore;
    internal int UnexpectedUserWritable;
    internal int Unknown;

    internal int Total
    {
        get
        {
            return checked(PrivateExecutionRoot + System32 + WindowsComponentStore +
                UnexpectedUserWritable + Unknown);
        }
    }

    internal bool MainImagePresent
    {
        get { return PrivateExecutionRoot > 0; }
    }

    internal void Add(string classification)
    {
        if (classification == PrivateExecutionRootClass) PrivateExecutionRoot++;
        else if (classification == System32Class) System32++;
        else if (classification == WindowsComponentStoreClass) WindowsComponentStore++;
        else if (classification == UnexpectedUserWritableClass) UnexpectedUserWritable++;
        else Unknown++;
    }

    internal void MergeMaximum(ModuleInventory other)
    {
        if (other == null) return;
        PrivateExecutionRoot = Math.Max(PrivateExecutionRoot, other.PrivateExecutionRoot);
        System32 = Math.Max(System32, other.System32);
        WindowsComponentStore = Math.Max(WindowsComponentStore, other.WindowsComponentStore);
        UnexpectedUserWritable = Math.Max(UnexpectedUserWritable, other.UnexpectedUserWritable);
        Unknown = Math.Max(Unknown, other.Unknown);
    }
}

internal sealed class ModuleObservation
{
    internal bool MainImagePathMatch;
    internal bool ReopenedFileIdentityMatch;
    internal bool MappedImageIdentityBound;
    internal bool PreventiveLoaderPolicy;
    internal ModuleInventory Initial;
    internal ModuleInventory Runtime;
    internal int? InitialSystemError;
    internal int? RuntimeSystemError;
}

internal sealed class PeInventory
{
    internal readonly List<string> Imports = new List<string>();
    internal bool HighestAvailableObserved;
}

internal static class PeParser
{
    private sealed class Section
    {
        internal uint VirtualAddress;
        internal uint VirtualSize;
        internal uint RawSize;
        internal uint RawPointer;
    }

    internal static PeInventory Parse(SafeFileHandle handle, long length)
    {
        if (length <= 0 || length > 256L * 1024L * 1024L)
        {
            throw new ControlledException("PE_SIZE_OUT_OF_RANGE", null);
        }
        byte[] bytes = ReadAll(handle, checked((int)length));
        if (ReadU16(bytes, 0) != 0x5a4d)
        {
            throw new ControlledException("PE_DOS_SIGNATURE_INVALID", null);
        }
        uint peOffsetRaw = ReadU32(bytes, 0x3c);
        int peOffset = CheckedOffset(peOffsetRaw, 24, bytes.Length);
        if (ReadU32(bytes, peOffset) != 0x00004550)
        {
            throw new ControlledException("PE_SIGNATURE_INVALID", null);
        }
        ushort machine = ReadU16(bytes, peOffset + 4);
        ushort sectionCount = ReadU16(bytes, peOffset + 6);
        ushort optionalSize = ReadU16(bytes, peOffset + 20);
        if (machine != 0x8664 || sectionCount == 0 || sectionCount > 96 || optionalSize < 224)
        {
            throw new ControlledException("PE_LAYOUT_UNSUPPORTED", null);
        }
        int optional = checked(peOffset + 24);
        CheckedOffset(checked((uint)optional), optionalSize, bytes.Length);
        if (ReadU16(bytes, optional) != 0x20b)
        {
            throw new ControlledException("PE_NOT_PE32_PLUS", null);
        }
        uint directoryCount = ReadU32(bytes, optional + 108);
        if (directoryCount < 2)
        {
            throw new ControlledException("PE_IMPORT_DIRECTORY_ABSENT", null);
        }
        uint importRva = ReadU32(bytes, optional + 120);
        uint importSize = ReadU32(bytes, optional + 124);
        int sectionOffset = checked(optional + optionalSize);
        List<Section> sections = new List<Section>();
        for (int index = 0; index < sectionCount; index++)
        {
            int current = CheckedOffset(checked((uint)(sectionOffset + checked(index * 40))), 40, bytes.Length);
            sections.Add(new Section
            {
                VirtualSize = ReadU32(bytes, current + 8),
                VirtualAddress = ReadU32(bytes, current + 12),
                RawSize = ReadU32(bytes, current + 16),
                RawPointer = ReadU32(bytes, current + 20)
            });
        }

        PeInventory inventory = new PeInventory();
        if (importRva != 0 && importSize >= 20)
        {
            int descriptor = RvaToOffset(importRva, sections, bytes.Length);
            int maximum = Math.Min(4096, checked((int)(importSize / 20)));
            for (int index = 0; index < maximum; index++)
            {
                int current = CheckedOffset(checked((uint)(descriptor + checked(index * 20))), 20, bytes.Length);
                uint originalThunk = ReadU32(bytes, current);
                uint time = ReadU32(bytes, current + 4);
                uint forwarder = ReadU32(bytes, current + 8);
                uint nameRva = ReadU32(bytes, current + 12);
                uint firstThunk = ReadU32(bytes, current + 16);
                if (originalThunk == 0 && time == 0 && forwarder == 0 && nameRva == 0 && firstThunk == 0)
                {
                    break;
                }
                if (nameRva == 0)
                {
                    throw new ControlledException("PE_IMPORT_NAME_MISSING", null);
                }
                string name = ReadAsciiZ(bytes, RvaToOffset(nameRva, sections, bytes.Length), 512);
                if (name.IndexOfAny(new char[] { '\\', '/', ':', '\0' }) >= 0)
                {
                    throw new ControlledException("PE_IMPORT_NAME_INVALID", null);
                }
                inventory.Imports.Add(name.ToUpperInvariant());
            }
        }
        inventory.HighestAvailableObserved = ContainsAscii(bytes, "highestAvailable") ||
            ContainsUtf16(bytes, "highestAvailable");
        return inventory;
    }

    private static byte[] ReadAll(SafeFileHandle handle, int length)
    {
        long ignored;
        if (!NativeMethods.SetFilePointerEx(handle, 0, out ignored, 0))
        {
            throw FileOperations.LastError("PE_SEEK_FAILED");
        }
        byte[] bytes = new byte[length];
        byte[] chunk = new byte[128 * 1024];
        int offset = 0;
        while (offset < length)
        {
            uint read;
            uint wanted = checked((uint)Math.Min(chunk.Length, length - offset));
            if (!NativeMethods.ReadFile(handle, chunk, wanted, out read, IntPtr.Zero))
            {
                throw FileOperations.LastError("PE_READ_FAILED");
            }
            if (read == 0)
            {
                throw new ControlledException("PE_UNEXPECTED_EOF", null);
            }
            Buffer.BlockCopy(chunk, 0, bytes, offset, checked((int)read));
            offset = checked(offset + (int)read);
        }
        if (!NativeMethods.SetFilePointerEx(handle, 0, out ignored, 0))
        {
            throw FileOperations.LastError("PE_RESET_FAILED");
        }
        return bytes;
    }

    private static int RvaToOffset(uint rva, IList<Section> sections, int length)
    {
        int match = -1;
        for (int index = 0; index < sections.Count; index++)
        {
            Section section = sections[index];
            ulong start = section.VirtualAddress;
            ulong span = Math.Max(section.VirtualSize, section.RawSize);
            ulong end = start + span;
            if ((ulong)rva >= start && (ulong)rva < end)
            {
                ulong delta = (ulong)rva - start;
                if (delta >= section.RawSize)
                {
                    throw new ControlledException("PE_RVA_NOT_FILE_BACKED", null);
                }
                ulong raw = (ulong)section.RawPointer + delta;
                if (raw >= (ulong)length || match >= 0)
                {
                    throw new ControlledException("PE_RVA_AMBIGUOUS", null);
                }
                match = checked((int)raw);
            }
        }
        if (match < 0)
        {
            throw new ControlledException("PE_RVA_UNMAPPED", null);
        }
        return match;
    }

    private static string ReadAsciiZ(byte[] bytes, int offset, int maximum)
    {
        int end = offset;
        int limit = Math.Min(bytes.Length, checked(offset + maximum));
        while (end < limit && bytes[end] != 0)
        {
            if (bytes[end] < 0x21 || bytes[end] > 0x7e)
            {
                throw new ControlledException("PE_ASCII_NAME_INVALID", null);
            }
            end++;
        }
        if (end == offset || end == limit)
        {
            throw new ControlledException("PE_ASCII_NAME_UNTERMINATED", null);
        }
        return Encoding.ASCII.GetString(bytes, offset, end - offset);
    }

    private static bool ContainsAscii(byte[] bytes, string text)
    {
        byte[] needle = Encoding.ASCII.GetBytes(text);
        return Contains(bytes, needle);
    }

    private static bool ContainsUtf16(byte[] bytes, string text)
    {
        byte[] needle = Encoding.Unicode.GetBytes(text);
        return Contains(bytes, needle);
    }

    private static bool Contains(byte[] haystack, byte[] needle)
    {
        for (int index = 0; index <= haystack.Length - needle.Length; index++)
        {
            int offset = 0;
            while (offset < needle.Length && haystack[index + offset] == needle[offset])
            {
                offset++;
            }
            if (offset == needle.Length)
            {
                return true;
            }
        }
        return false;
    }

    private static ushort ReadU16(byte[] bytes, int offset)
    {
        CheckedOffset(checked((uint)offset), 2, bytes.Length);
        return checked((ushort)(bytes[offset] | (bytes[offset + 1] << 8)));
    }

    private static uint ReadU32(byte[] bytes, int offset)
    {
        CheckedOffset(checked((uint)offset), 4, bytes.Length);
        return unchecked((uint)(bytes[offset] | (bytes[offset + 1] << 8) |
            (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24)));
    }

    private static int CheckedOffset(uint offset, int size, int length)
    {
        ulong end = (ulong)offset + checked((uint)size);
        if (end > (ulong)length)
        {
            throw new ControlledException("PE_BOUNDS_REJECTED", null);
        }
        return checked((int)offset);
    }
}

internal sealed class ProbeSuite
{
    private readonly Dictionary<string, CaseResult> cases = new Dictionary<string, CaseResult>(StringComparer.Ordinal);
    private readonly string sourcePath;
    private readonly string expectedSha256;
    private readonly string runBase;
    private readonly string selfPath;
    private string runRoot;
    private string executionDirectory;
    private string currentDirectory;
    private string privateTemp;
    private string destinationPath;
    private SafeFileHandle sourceLock;
    private SafeFileHandle destinationLock;
    private SafeFileHandle runBaseLock;
    private SafeFileHandle runRootLock;
    private SafeFileHandle executionDirectoryLock;
    private SafeFileHandle currentDirectoryLock;
    private SafeFileHandle tempDirectoryLock;
    private SafeFileHandle helperSelfLock;
    private FileIdentity sourceIdentity;
    private FileIdentity destinationIdentity;
    private FileIdentity helperSelfIdentity;
    private TokenSnapshot currentToken;
    private TokenSnapshot restrictedChildToken;
    private PeInventory peInventory;
    private EnvironmentObservation environmentObservation;
    private ModuleObservation moduleObservation;
    private string reparseResult = "NotTested";
    private bool cleanupSucceeded;
    private bool adjacentMutationSucceeded;
    private bool restrictedLaunchSucceeded;
    private string fatalCode;
    private int? fatalSystemError;

    internal ProbeSuite(Dictionary<string, string> options)
    {
        if (options.Count != 3)
        {
            throw new ControlledException("SUITE_OPTION_SET_INVALID", null);
        }
        sourcePath = Path.GetFullPath(Program.Required(options, "--source"));
        expectedSha256 = Program.Required(options, "--expected-sha256").ToLowerInvariant();
        runBase = Path.GetFullPath(Program.Required(options, "--run-root"));
        selfPath = Path.GetFullPath(Process.GetCurrentProcess().MainModule.FileName);
        if (!Path.IsPathRooted(sourcePath) || !Path.IsPathRooted(runBase) ||
            expectedSha256.Length != 64 || !IsLowerHex(expectedSha256))
        {
            throw new ControlledException("SUITE_INPUT_INVALID", null);
        }
        if (!Directory.Exists(runBase))
        {
            throw new ControlledException("RUN_BASE_ABSENT", null);
        }
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string expectedSource = Path.GetFullPath(Path.Combine(
            localAppData, "SecApp", "compat", "velociraptor", "v0.77.1", "bin",
            "velociraptor-v0.77.1-windows-amd64.exe"));
        string allowedRunBase = Path.GetFullPath(Path.Combine(
            localAppData, "SecApp", "compat", "trust-launch"));
        if (!String.Equals(expectedSha256, Program.PinnedSha256, StringComparison.Ordinal) ||
            !String.Equals(sourcePath, expectedSource, StringComparison.OrdinalIgnoreCase) ||
            !IsPathWithin(allowedRunBase, runBase) || !IsPathWithin(allowedRunBase, selfPath))
        {
            throw new ControlledException("PINNED_SCOPE_REQUIRED", null);
        }
        for (int index = 0; index < MandatoryCases.All.Length; index++)
        {
            string id = MandatoryCases.All[index];
            if (cases.ContainsKey(id))
            {
                throw new ControlledException("DUPLICATE_MANDATORY_CASE", null);
            }
            cases.Add(id, new CaseResult(id));
        }
    }

    internal int Run()
    {
        try
        {
            CreatePrivateRoot();
            RunIdentityAndRaceTests();
            RunPeAndTokenTests();
            RunJobAndProcessTests();
            RunRestrictedTokenTest();
            SetUnprovenCases();
            RunFalsePositiveTests();
            BlockUnreached("NOT_EXECUTED_AFTER_BLOCKER", null);
        }
        catch (ControlledException error)
        {
            fatalCode = error.Code;
            fatalSystemError = error.SystemError;
            BlockUnreached("PREREQUISITE_FAILED", error.SystemError);
        }
        catch (Exception)
        {
            fatalCode = "UNCONTROLLED_SUITE_FAILURE";
            BlockUnreached("HARNESS_FAILURE", null);
        }
        finally
        {
            Cleanup();
        }

        Console.Out.Write(BuildSummary());
        return cleanupSucceeded && fatalCode == null
            ? Program.SecurityBlockerExitCode : ExitHarnessFailureCode();
    }

    private void CreatePrivateRoot()
    {
        runBaseLock = FileOperations.OpenDirectory(
            runBase, NativeMethods.FileShareRead | NativeMethods.FileShareWrite);
        FileOperations.ValidateDirectoryHandle(runBaseLock);
        string finalBase = FileOperations.FinalPath(runBaseLock).TrimEnd(
            Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        byte[] random = new byte[16];
        using (RandomNumberGenerator generator = RandomNumberGenerator.Create())
        {
            generator.GetBytes(random);
        }
        string leaf = "trust-launch-" + FileOperations.Hex(random);
        runRoot = Path.Combine(runBase, leaf);
        string basePrefix = runBase.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;
        if (!runRoot.StartsWith(basePrefix, StringComparison.OrdinalIgnoreCase) ||
            Directory.Exists(runRoot) || File.Exists(runRoot))
        {
            throw new ControlledException("RUN_ROOT_CREATE_NEW_PRECONDITION_FAILED", null);
        }
        if (!NativeMethods.CreateDirectoryW(runRoot, IntPtr.Zero))
        {
            throw FileOperations.LastError("RUN_ROOT_CREATE_NEW_FAILED");
        }
        executionDirectory = Path.Combine(runRoot, "execution");
        currentDirectory = Path.Combine(runRoot, "cwd");
        privateTemp = Path.Combine(runRoot, "temp");
        if (!NativeMethods.CreateDirectoryW(executionDirectory, IntPtr.Zero) ||
            !NativeMethods.CreateDirectoryW(currentDirectory, IntPtr.Zero) ||
            !NativeMethods.CreateDirectoryW(privateTemp, IntPtr.Zero))
        {
            throw FileOperations.LastError("PRIVATE_SUBDIRECTORY_CREATE_NEW_FAILED");
        }
        destinationPath = Path.Combine(executionDirectory, "backend.exe");

        runRootLock = FileOperations.OpenDirectory(
            runRoot, NativeMethods.FileShareRead | NativeMethods.FileShareWrite);
        FileOperations.ValidateDirectoryHandle(runRootLock);
        string final = FileOperations.FinalPath(runRootLock);
        string finalPrefix = finalBase + Path.DirectorySeparatorChar;
        if (String.IsNullOrEmpty(final) ||
            !final.StartsWith(finalPrefix, StringComparison.OrdinalIgnoreCase))
        {
            throw new ControlledException("RUN_ROOT_FINAL_PATH_MISMATCH", null);
        }
        currentDirectoryLock = FileOperations.OpenDirectory(
            currentDirectory, NativeMethods.FileShareRead | NativeMethods.FileShareWrite);
        tempDirectoryLock = FileOperations.OpenDirectory(
            privateTemp, NativeMethods.FileShareRead | NativeMethods.FileShareWrite);
        FileOperations.ValidateDirectoryHandle(currentDirectoryLock);
        FileOperations.ValidateDirectoryHandle(tempDirectoryLock);
        helperSelfLock = FileOperations.OpenReadLock(selfPath);
        helperSelfIdentity = FileOperations.Inspect(helperSelfLock, false);
        FileOperations.ValidateOrdinaryFile(helperSelfIdentity);
    }

    private void RunIdentityAndRaceTests()
    {
        sourceLock = FileOperations.OpenReadLock(sourcePath);
        sourceIdentity = FileOperations.Inspect(sourceLock, true);
        FileOperations.ValidateOrdinaryFile(sourceIdentity);
        if (!String.Equals(sourceIdentity.Sha256, expectedSha256, StringComparison.Ordinal))
        {
            Set("TL-ID-001-SOURCE-HANDLE", "Fail", "SOURCE_DIGEST_MISMATCH", null);
            throw new ControlledException("SOURCE_DIGEST_MISMATCH", null);
        }
        Set("TL-ID-001-SOURCE-HANDLE", "Pass", "HANDLE_IDENTITY_AND_SHA256_VERIFIED", null);

        FileIdentity creationIdentity;
        using (SafeFileHandle writer = FileOperations.CreateNewWriter(destinationPath))
        {
            long copied = FileOperations.Copy(sourceLock, writer);
            creationIdentity = FileOperations.Inspect(writer, true);
            if (copied != sourceIdentity.Size || !String.Equals(creationIdentity.Sha256, expectedSha256, StringComparison.Ordinal))
            {
                Set("TL-ID-002-DESTINATION-COPY", "Fail", "COPY_IDENTITY_MISMATCH", null);
                throw new ControlledException("COPY_IDENTITY_MISMATCH", null);
            }
        }

        destinationLock = FileOperations.OpenReadLock(destinationPath);
        destinationIdentity = FileOperations.Inspect(destinationLock, true);
        FileOperations.ValidateOrdinaryFile(destinationIdentity);
        if (!creationIdentity.SameObject(destinationIdentity) ||
            !String.Equals(destinationIdentity.Sha256, expectedSha256, StringComparison.Ordinal))
        {
            Set("TL-ID-002-DESTINATION-COPY", "Fail", "DESTINATION_REOPEN_MISMATCH", null);
            throw new ControlledException("DESTINATION_REOPEN_MISMATCH", null);
        }
        Set("TL-ID-002-DESTINATION-COPY", "Pass", "CREATE_NEW_COPY_FLUSH_REOPEN_VERIFIED", null);

        string mismatchPath = Path.Combine(runRoot, "digest-mismatch.bin");
        WriteCreateNew(mismatchPath, new byte[] { 0x53, 0x65, 0x63, 0x41, 0x70, 0x70 });
        using (SafeFileHandle mismatchHandle = FileOperations.OpenReadLock(mismatchPath))
        {
            FileIdentity mismatch = FileOperations.Inspect(mismatchHandle, true);
            bool rejected = !String.Equals(mismatch.Sha256, expectedSha256, StringComparison.Ordinal);
            Set("TL-ID-003-DESTINATION-MISMATCH", rejected ? "Pass" : "Fail",
                rejected ? "ACTUAL_DIGEST_MISMATCH_REJECTED" : "MISMATCH_FALSELY_ACCEPTED", null);
        }

        executionDirectoryLock = FileOperations.OpenDirectory(executionDirectory, NativeMethods.FileShareRead);
        FileOperations.ValidateDirectoryHandle(executionDirectoryLock);
        string[] contents = Directory.GetFileSystemEntries(executionDirectory);
        if (contents.Length != 1 || !String.Equals(Path.GetFullPath(contents[0]), destinationPath, StringComparison.OrdinalIgnoreCase))
        {
            throw new ControlledException("EXECUTION_DIRECTORY_CONTENTS_UNEXPECTED", null);
        }

        RaceResult write = InvokeRace("write", destinationPath, null);
        SetMutationCase("TL-ID-004-WRITE-LOCK", write, "WRITE_BLOCKED");

        string replacement = Path.Combine(runRoot, "replacement-one.bin");
        WriteCreateNew(replacement, new byte[] { 1, 2, 3, 4 });
        RaceResult replace = InvokeRace("replace", destinationPath, replacement);
        SetMutationCase("TL-ID-005-REPLACE-LOCK", replace, "REPLACE_BLOCKED");

        RaceResult delete = InvokeRace("delete", destinationPath, null);
        SetMutationCase("TL-ID-006-DELETE-LOCK", delete, "DELETE_BLOCKED");

        RaceResult rename = InvokeRace("rename", destinationPath, null);
        SetMutationCase("TL-ID-007-FILE-RENAME-LOCK", rename, "FILE_RENAME_BLOCKED");

        RaceResult directoryRename = InvokeRace("dir-rename", executionDirectory, null);
        SetMutationCase("TL-ID-008-EXEC-DIRECTORY-MUTATION", directoryRename, "DIRECTORY_RENAME_BLOCKED");

        string marker = Path.Combine(executionDirectory, "probe.dll");
        RaceResult adjacent = InvokeRace("adjacent", marker, null);
        adjacentMutationSucceeded = adjacent.Succeeded;
        if (adjacent.Succeeded)
        {
            Set("TL-ID-009-ADJACENT-MARKER", "Fail", "MUTATION_SUCCEEDED", null);
            NativeMethods.DeleteFileW(marker);
        }
        else
        {
            Set("TL-ID-009-ADJACENT-MARKER", "Pass", "ADJACENT_CREATE_BLOCKED", adjacent.Error);
        }

        RunReparseReplacementTest();

        destinationLock.Dispose();
        destinationLock = null;
        executionDirectoryLock.Dispose();
        executionDirectoryLock = null;
        RaceResult control = InvokeRace("write", destinationPath, null);
        if (control.Succeeded)
        {
            Set("TL-ID-011-UNLOCK-CONTROL", "Pass", "POST_RELEASE_MUTATION_SUCCEEDED", null);
        }
        else
        {
            Set("TL-ID-011-UNLOCK-CONTROL", "Fail", "POST_RELEASE_CONTROL_FAILED", control.Error);
        }
    }

    private void RunReparseReplacementTest()
    {
        string target = Path.Combine(runRoot, "reparse-target");
        string alternate = Path.Combine(runRoot, "reparse-alternate");
        string original = target + ".original";
        string outcome = "NotTested";
        string code = "REPARSE_OPERATION_NOT_REACHED";
        int? systemError = null;
        bool cleanup = false;
        SafeFileHandle targetLock = null;
        try
        {
            if (!NativeMethods.CreateDirectoryW(target, IntPtr.Zero) ||
                !NativeMethods.CreateDirectoryW(alternate, IntPtr.Zero))
            {
                throw FileOperations.LastError("REPARSE_FIXTURE_CREATE_NEW_FAILED");
            }
            targetLock = FileOperations.OpenDirectory(
                target, NativeMethods.FileShareRead | NativeMethods.FileShareWrite);
            FileOperations.ValidateDirectoryHandle(targetLock);
            string initialFinalPath = ComparableFinalPath(FileOperations.FinalPath(targetLock));
            if (!String.Equals(initialFinalPath, Path.GetFullPath(target), StringComparison.OrdinalIgnoreCase))
            {
                outcome = "Fail";
                code = "REPARSE_INITIAL_FINAL_PATH_MISMATCH";
            }
            else
            {
                using (SafeKernelHandle job = ProcessLauncher.CreateJob(1, false))
                using (ChildProcess child = ProcessLauncher.CreateSuspended(
                    selfPath,
                    new string[]
                    {
                        "reparse-worker", "--scope-root", runRoot,
                        "--target", target, "--alternate", alternate
                    },
                    currentDirectory, privateTemp, job, true, null, true))
                {
                    if (!ProcessLauncher.VerifyJob(child, job) ||
                        !ProcessLauncher.VerifyMitigation(child))
                    {
                        outcome = "Fail";
                        code = "REPARSE_WORKER_PRE_RESUME_INVARIANT_FAILED";
                    }
                    else
                    {
                        child.Resume();
                        if (!child.Wait(5000))
                        {
                            NativeMethods.TerminateJobObject(job, 0xE0030001);
                            child.Wait(5000);
                            outcome = "Fail";
                            code = "REPARSE_WORKER_TIMEOUT";
                        }
                        else
                        {
                            uint exitCode = child.ExitCode();
                            if (exitCode == ReparseWorker.BlockedAsExpected)
                            {
                                reparseResult = "BlockedAsExpected";
                                outcome = "Pass";
                                code = "REPARSE_RENAME_BLOCKED_BY_OPEN_DIRECTORY_HANDLE";
                            }
                            else if (exitCode == ReparseWorker.UnexpectedlySucceeded)
                            {
                                reparseResult = "UnexpectedlySucceeded";
                                outcome = "Fail";
                                code = "REPARSE_REPLACEMENT_SEQUENCE_UNEXPECTEDLY_SUCCEEDED";
                            }
                            else if (exitCode == ReparseWorker.NotSupported)
                            {
                                reparseResult = "NotSupported";
                                outcome = "NotTested";
                                code = "REPARSE_OPERATION_NOT_SUPPORTED";
                            }
                            else
                            {
                                reparseResult = "NotTested";
                                outcome = "NotTested";
                                code = "REPARSE_OPERATION_NOT_TESTED";
                            }
                        }
                    }
                }
            }

            FileOperations.ValidateDirectoryHandle(targetLock);
            bool pathStable = String.Equals(
                ComparableFinalPath(FileOperations.FinalPath(targetLock)),
                Path.GetFullPath(target), StringComparison.OrdinalIgnoreCase);
            FileAttributes targetAttributes = File.GetAttributes(target);
            FileAttributes alternateAttributes = File.GetAttributes(alternate);
            bool noReparseRemains =
                (targetAttributes & FileAttributes.ReparsePoint) == 0 &&
                (alternateAttributes & FileAttributes.ReparsePoint) == 0 &&
                !Directory.Exists(original) && !File.Exists(original);
            if (!pathStable || !noReparseRemains)
            {
                outcome = "Fail";
                code = "REPARSE_IDENTITY_OR_CLEANUP_VERIFICATION_FAILED";
            }
        }
        catch (ControlledException error)
        {
            outcome = "NotTested";
            code = error.Code;
            systemError = error.SystemError;
            reparseResult = "NotTested";
        }
        catch
        {
            outcome = "NotTested";
            code = "REPARSE_WORKER_UNCONTROLLED_FAILURE";
            reparseResult = "NotTested";
        }
        finally
        {
            if (targetLock != null) targetLock.Dispose();
            cleanup = RemoveReparseFixture(target) &
                RemoveReparseFixture(original) &
                RemoveReparseFixture(alternate);
        }
        if (!cleanup)
        {
            outcome = "Fail";
            code = "REPARSE_FIXTURE_CLEANUP_FAILED";
        }
        Set("TL-ID-010-REPARSE-REPLACEMENT", outcome, code, systemError);
    }

    private static bool RemoveReparseFixture(string path)
    {
        try
        {
            if (!Directory.Exists(path) && !File.Exists(path)) return true;
            FileAttributes attributes = File.GetAttributes(path);
            if ((attributes & FileAttributes.Directory) == 0) return false;
            if ((attributes & FileAttributes.ReparsePoint) != 0)
            {
                if (!NativeMethods.RemoveDirectoryW(path)) return false;
            }
            else
            {
                Directory.Delete(path, false);
            }
            return !Directory.Exists(path) && !File.Exists(path);
        }
        catch
        {
            return false;
        }
    }

    private static string ComparableFinalPath(string path)
    {
        if (path.StartsWith("\\\\?\\UNC\\", StringComparison.OrdinalIgnoreCase))
        {
            return "\\\\" + path.Substring(8);
        }
        if (path.StartsWith("\\\\?\\", StringComparison.OrdinalIgnoreCase))
        {
            return path.Substring(4);
        }
        return Path.GetFullPath(path);
    }

    private void RunPeAndTokenTests()
    {
        peInventory = PeParser.Parse(sourceLock, sourceIdentity.Size);
        if (peInventory.Imports.Count == 0 || !peInventory.HighestAvailableObserved)
        {
            Set("TL-IMG-001-IMPORTS", "Fail", "PE_INVENTORY_INCOMPLETE", null);
        }
        else
        {
            Set("TL-IMG-001-IMPORTS", "Pass", "PE_IMPORTS_AND_MANIFEST_OBSERVED", null);
        }

        using (SafeKernelHandle token = TokenOperations.OpenCurrent(
            NativeMethods.TokenQuery | NativeMethods.TokenDuplicate |
            NativeMethods.TokenAssignPrimary | NativeMethods.TokenAdjustDefault))
        {
            currentToken = TokenOperations.Inspect(token);
        }
        Set("TL-TOK-001-CURRENT", "Pass", "TOKEN_CLASSIFIED_WITHOUT_IDENTITY", null);
        if (currentToken.ElevationType == 3 && currentToken.LinkedTokenPresent)
        {
            Set("TL-TOK-002-DEFAULT", "Pass", "DEFAULT_REJECTED_FILTERED_ADMIN", null);
        }
        else if (currentToken.IsNonElevated && !currentToken.LinkedTokenPresent)
        {
            Set("TL-TOK-002-DEFAULT", "Pass", "DEFAULT_CANDIDATE_STANDARD_TOKEN", null);
        }
        else
        {
            Set("TL-TOK-002-DEFAULT", "Fail", "DEFAULT_TOKEN_NOT_ACCEPTABLE", null);
        }
        Set("TL-TOK-003-RUNASINVOKER", "NotTested", "COMPARISON_WITHHELD_AFTER_SECURITY_BLOCKER", null);
    }

    private void RunJobAndProcessTests()
    {
        bool outer;
        if (!NativeMethods.IsProcessInJob(NativeMethods.GetCurrentProcess(), IntPtr.Zero, out outer))
        {
            throw FileOperations.LastError("OUTER_JOB_QUERY_FAILED");
        }

        using (SafeFileHandle selfLock = FileOperations.OpenReadLock(selfPath))
        using (SafeKernelHandle job = ProcessLauncher.CreateJob(2, true))
        using (ChildProcess child = ProcessLauncher.CreateSuspended(
            selfPath, new string[] { "tree-child", "--wait-ms", "100" },
            currentDirectory, privateTemp, job, true, null, true))
        {
            bool inJob = ProcessLauncher.VerifyJob(child, job);
            if (!inJob)
            {
                Set("TL-JOB-001-ATOMIC-ASSIGN", "Fail", "CHILD_NOT_IN_JOB", null);
                throw new ControlledException("CHILD_NOT_IN_JOB", null);
            }
            Set("TL-JOB-001-ATOMIC-ASSIGN", "Pass", "JOB_LIST_ASSIGNED_DURING_CREATION", null);
            Set("TL-JOB-002-NESTED", "Pass", outer ? "OUTER_JOB_NESTED_ASSIGNMENT_SUCCEEDED" : "NO_OUTER_JOB_ASSIGNMENT_SUCCEEDED", null);

            if (!ProcessLauncher.VerifyMitigation(child))
            {
                Set("TL-IMG-002-MITIGATION", "Fail", "IMAGE_LOAD_POLICY_MISSING", null);
                throw new ControlledException("IMAGE_LOAD_POLICY_MISSING", null);
            }
            Set("TL-IMG-002-MITIGATION", "Pass", "IMAGE_LOAD_POLICY_0X7_VERIFIED", null);

            string actualImage = Path.GetFullPath(ProcessLauncher.QueryImage(child));
            if (!String.Equals(actualImage, selfPath, StringComparison.OrdinalIgnoreCase))
            {
                Set("TL-IMG-003-INITIAL", "Fail", "MAIN_IMAGE_PATH_MISMATCH", null);
                throw new ControlledException("MAIN_IMAGE_PATH_MISMATCH", null);
            }
            TokenSnapshot childToken = ProcessLauncher.InspectToken(child);
            if (!childToken.IsNonElevated)
            {
                Set("TL-TOK-005-CHILD", "Fail", "SYNTHETIC_CHILD_TOKEN_ELEVATED", null);
                throw new ControlledException("SYNTHETIC_CHILD_TOKEN_ELEVATED", null);
            }
            child.Resume();
            if (!child.Wait(5000) || child.ExitCode() != 0)
            {
                Set("TL-JOB-003-NORMAL", "Fail", "NORMAL_CHILD_DID_NOT_EXIT", null);
            }
            else
            {
                Set("TL-JOB-003-NORMAL", "Pass", "NORMAL_EXIT_IN_JOB", null);
            }
        }

        RunTimedJobCase("TL-JOB-004-TIMEOUT", "TIMEOUT_TERMINATED_JOB");
        RunTimedJobCase("TL-JOB-005-CANCEL", "EXPLICIT_CANCEL_TERMINATED_JOB");
        RunTreeKillOnClose();
        RunActiveLimit();
        RunAssignmentFailureGuard();
        RunHandleLeakTest();
        RunEnvironmentObservation();
        RunModuleObservation();
    }

    private void RunEnvironmentObservation()
    {
        string outcome = "NotTested";
        string code = "ENVIRONMENT_OBSERVATION_NOT_REACHED";
        int? systemError = null;
        try
        {
            using (SafeKernelHandle job = ProcessLauncher.CreateJob(1, false))
            using (ChildProcess child = ProcessLauncher.CreateSuspended(
                selfPath,
                new string[] { "environment-report", "--expected-temp", privateTemp },
                currentDirectory, privateTemp, job, true, null, true))
            {
                if (!ProcessLauncher.VerifyJob(child, job) ||
                    !ProcessLauncher.VerifyMitigation(child))
                {
                    outcome = "Fail";
                    code = "ENVIRONMENT_CHILD_PRE_RESUME_INVARIANT_FAILED";
                }
                else
                {
                    child.Resume();
                    if (!child.Wait(5000))
                    {
                        NativeMethods.TerminateJobObject(job, 0xE0040001);
                        child.Wait(5000);
                        outcome = "Fail";
                        code = "ENVIRONMENT_CHILD_TIMEOUT";
                    }
                    else
                    {
                        uint exitCode = child.ExitCode();
                        if ((exitCode & ~0x1fffu) != 0)
                        {
                            outcome = "Fail";
                            code = "ENVIRONMENT_REPORT_EXIT_MASK_INVALID";
                        }
                        else
                        {
                            environmentObservation = EnvironmentObservation.FromExitCode(exitCode);
                            bool accepted = exitCode == 0;
                            outcome = accepted ? "Pass" : "Fail";
                            code = accepted
                                ? "EXACT_ENVIRONMENT_ALLOWLIST_AND_DENYLIST_OBSERVED"
                                : "ENVIRONMENT_ALLOWLIST_OR_DENYLIST_FAILED";
                        }
                    }
                }
            }
        }
        catch (ControlledException error)
        {
            outcome = "NotTested";
            code = error.Code;
            systemError = error.SystemError;
        }
        Set("TL-ENV-001-ALLOWLIST", outcome, code, systemError);
    }

    private void RunModuleObservation()
    {
        moduleObservation = new ModuleObservation
        {
            MappedImageIdentityBound = false,
            PreventiveLoaderPolicy = false
        };
        try
        {
            using (SafeKernelHandle job = ProcessLauncher.CreateJob(1, false))
            using (ChildProcess child = ProcessLauncher.CreateSuspended(
                selfPath, new string[] { "tree-child", "--wait-ms", "2500" },
                currentDirectory, privateTemp, job, true, null, true))
            {
                if (!ProcessLauncher.VerifyJob(child, job) ||
                    !ProcessLauncher.VerifyMitigation(child))
                {
                    throw new ControlledException("MODULE_CHILD_PRE_RESUME_INVARIANT_FAILED", null);
                }

                string actualImage = Path.GetFullPath(ProcessLauncher.QueryImage(child));
                moduleObservation.MainImagePathMatch = String.Equals(
                    actualImage, selfPath, StringComparison.OrdinalIgnoreCase);
                if (moduleObservation.MainImagePathMatch)
                {
                    using (SafeFileHandle imageLock = FileOperations.OpenReadLock(actualImage))
                    {
                        FileIdentity reopened = FileOperations.Inspect(imageLock, false);
                        FileOperations.ValidateOrdinaryFile(reopened);
                        moduleObservation.ReopenedFileIdentityMatch =
                            helperSelfIdentity.SameObject(reopened);
                    }
                }

                moduleObservation.Initial = ProcessLauncher.TryInventoryModules(
                    child, selfPath, runRoot, out moduleObservation.InitialSystemError);

                child.Resume();
                Stopwatch timer = Stopwatch.StartNew();
                ModuleInventory runtime = null;
                int? lastRuntimeError = null;
                while (timer.ElapsedMilliseconds < 1000)
                {
                    ModuleInventory sample = ProcessLauncher.TryInventoryModules(
                        child, selfPath, runRoot, out lastRuntimeError);
                    if (sample != null)
                    {
                        if (runtime == null) runtime = new ModuleInventory();
                        runtime.MergeMaximum(sample);
                    }
                    if (child.Wait(0)) break;
                    Thread.Sleep(25);
                }
                moduleObservation.Runtime = runtime;
                moduleObservation.RuntimeSystemError = runtime == null ? lastRuntimeError : null;

                if (!child.Wait(0))
                {
                    if (!NativeMethods.TerminateJobObject(job, 0xE0050001))
                    {
                        throw FileOperations.LastError("MODULE_OBSERVATION_JOB_TERMINATION_FAILED");
                    }
                    if (!child.Wait(5000))
                    {
                        throw new ControlledException("MODULE_OBSERVATION_CHILD_SURVIVED", null);
                    }
                }
            }
        }
        catch (ControlledException error)
        {
            Set("TL-IMG-003-INITIAL", "NotTested", error.Code, error.SystemError);
            Set("TL-IMG-004-RUNTIME", "NotTested", error.Code, error.SystemError);
            Set("TL-IMG-005-UNEXPECTED-MODULE-REJECT", "NotTested", error.Code, error.SystemError);
            return;
        }

        if (!moduleObservation.MainImagePathMatch)
        {
            Set("TL-IMG-003-INITIAL", "Fail", "MAIN_IMAGE_PATH_MISMATCH", null);
        }
        else if (!moduleObservation.ReopenedFileIdentityMatch)
        {
            Set("TL-IMG-003-INITIAL", "Fail", "REOPENED_MAIN_IMAGE_FILE_ID_MISMATCH", null);
        }
        else if (moduleObservation.Initial == null)
        {
            Set("TL-IMG-003-INITIAL", "NotTested", "INITIAL_MODULE_ENUMERATION_UNAVAILABLE",
                moduleObservation.InitialSystemError);
        }
        else if (!moduleObservation.Initial.MainImagePresent || moduleObservation.Initial.Total == 0)
        {
            Set("TL-IMG-003-INITIAL", "Fail", "INITIAL_MAIN_IMAGE_NOT_ENUMERATED", null);
        }
        else if (moduleObservation.Initial.UnexpectedUserWritable != 0)
        {
            Set("TL-IMG-003-INITIAL", "Fail", "INITIAL_UNEXPECTED_USER_WRITABLE_MODULE", null);
        }
        else
        {
            Set("TL-IMG-003-INITIAL", "Pass",
                moduleObservation.Initial.Unknown == 0
                    ? "INITIAL_MODULES_CLASSIFIED_MAIN_FILE_ID_REOPENED"
                    : "INITIAL_MODULES_CLASSIFIED_WITH_UNKNOWN_MAIN_FILE_ID_REOPENED", null);
        }

        if (moduleObservation.Runtime == null)
        {
            Set("TL-IMG-004-RUNTIME", "NotTested", "RUNTIME_MODULE_ENUMERATION_UNAVAILABLE",
                moduleObservation.RuntimeSystemError);
        }
        else if (!moduleObservation.Runtime.MainImagePresent || moduleObservation.Runtime.Total == 0)
        {
            Set("TL-IMG-004-RUNTIME", "Fail", "RUNTIME_MAIN_IMAGE_NOT_ENUMERATED", null);
        }
        else if (moduleObservation.Runtime.UnexpectedUserWritable != 0)
        {
            Set("TL-IMG-004-RUNTIME", "Fail", "RUNTIME_UNEXPECTED_USER_WRITABLE_MODULE", null);
        }
        else
        {
            Set("TL-IMG-004-RUNTIME", "Pass",
                moduleObservation.Runtime.Unknown == 0
                    ? "RUNTIME_MODULES_CLASSIFIED"
                    : "RUNTIME_MODULES_CLASSIFIED_WITH_UNKNOWN", null);
        }

        bool unexpected =
            (moduleObservation.Initial != null && moduleObservation.Initial.UnexpectedUserWritable != 0) ||
            (moduleObservation.Runtime != null && moduleObservation.Runtime.UnexpectedUserWritable != 0);
        if (unexpected)
        {
            Set("TL-IMG-005-UNEXPECTED-MODULE-REJECT", "Fail",
                "UNEXPECTED_USER_WRITABLE_MODULE_REJECTED_SYNTHETIC_OBSERVATION", null);
        }
        else if (moduleObservation.Initial == null || moduleObservation.Runtime == null)
        {
            Set("TL-IMG-005-UNEXPECTED-MODULE-REJECT", "NotTested",
                "MODULE_REJECTION_REQUIRES_BOTH_OBSERVATION_WINDOWS", null);
        }
        else
        {
            Set("TL-IMG-005-UNEXPECTED-MODULE-REJECT", "Pass",
                "NO_UNEXPECTED_USER_WRITABLE_MODULE_FAIL_CLOSED_RULE_ACTIVE", null);
        }
    }

    private void RunTimedJobCase(string id, string passCode)
    {
        using (SafeKernelHandle job = ProcessLauncher.CreateJob(1, false))
        using (ChildProcess child = ProcessLauncher.CreateSuspended(
            selfPath, new string[] { "tree-child", "--wait-ms", "30000" },
            currentDirectory, privateTemp, job, true, null, true))
        {
            if (!ProcessLauncher.VerifyJob(child, job) || !ProcessLauncher.VerifyMitigation(child))
            {
                Set(id, "Fail", "PRE_RESUME_INVARIANT_FAILED", null);
                return;
            }
            child.Resume();
            if (child.Wait(150))
            {
                Set(id, "Fail", "LONG_CHILD_EXITED_EARLY", null);
                return;
            }
            if (!NativeMethods.TerminateJobObject(job, 0xE0020001))
            {
                Set(id, "Fail", "TERMINATE_JOB_FAILED", Marshal.GetLastWin32Error());
                return;
            }
            Set(id, child.Wait(5000) ? "Pass" : "Fail",
                child.Wait(0) ? passCode : "JOB_TERMINATION_TIMEOUT", null);
        }
    }

    private void RunTreeKillOnClose()
    {
        SafeKernelHandle job = null;
        ChildProcess parent = null;
        List<SafeKernelHandle> memberHandles = new List<SafeKernelHandle>();
        try
        {
            job = ProcessLauncher.CreateJob(2, true);
            parent = ProcessLauncher.CreateSuspended(
                selfPath, new string[] { "tree-parent", "--wait-ms", "30000" },
                currentDirectory, privateTemp, job, true, null, true);
            if (!ProcessLauncher.VerifyJob(parent, job))
            {
                Set("TL-JOB-006-TREE", "Fail", "PARENT_NOT_IN_JOB", null);
                return;
            }
            parent.Resume();
            List<uint> pids = WaitForJobMembers(job, 2, 3000);
            if (pids.Count != 2)
            {
                Set("TL-JOB-006-TREE", "Fail", "DESCENDANT_NOT_OBSERVED_IN_JOB", null);
                return;
            }
            for (int index = 0; index < pids.Count; index++)
            {
                SafeKernelHandle process = NativeMethods.OpenProcess(
                    NativeMethods.ProcessSynchronize | NativeMethods.ProcessQueryLimitedInformation |
                    NativeMethods.ProcessTerminate,
                    false, pids[index]);
                if (process.IsInvalid)
                {
                    process.Dispose();
                    throw FileOperations.LastError("OPEN_JOB_MEMBER_FAILED");
                }
                bool member;
                if (!NativeMethods.IsProcessInJob(process, job, out member) || !member)
                {
                    process.Dispose();
                    Set("TL-JOB-006-TREE", "Fail", "DESCENDANT_MEMBERSHIP_FAILED", null);
                    return;
                }
                memberHandles.Add(process);
            }
            Set("TL-JOB-006-TREE", "Pass", "PARENT_AND_CHILD_IN_SAME_JOB", null);

            job.Dispose();
            job = null;
            bool allExited = true;
            for (int index = 0; index < memberHandles.Count; index++)
            {
                if (NativeMethods.WaitForSingleObject(memberHandles[index], 5000) != NativeMethods.WaitObject0)
                {
                    allExited = false;
                }
            }
            Set("TL-JOB-007-KILL-CLOSE", allExited ? "Pass" : "Fail",
                allExited ? "KILL_ON_CLOSE_TERMINATED_TREE" : "TREE_SURVIVED_JOB_CLOSE", null);
            Set("TL-JOB-010-NO-ORPHAN", allExited ? "Pass" : "Fail",
                allExited ? "NO_SURVIVING_JOB_MEMBERS" : "ORPHAN_DESCENDANT", null);
            if (!allExited)
            {
                for (int index = 0; index < memberHandles.Count; index++)
                {
                    NativeMethods.TerminateProcess(memberHandles[index], 0xE0020003);
                    NativeMethods.WaitForSingleObject(memberHandles[index], 5000);
                }
            }
        }
        finally
        {
            if (job != null)
            {
                NativeMethods.TerminateJobObject(job, 0xE0020002);
                job.Dispose();
            }
            for (int index = 0; index < memberHandles.Count; index++)
            {
                memberHandles[index].Dispose();
            }
            if (parent != null)
            {
                parent.Dispose();
            }
        }
    }

    private void RunActiveLimit()
    {
        using (SafeKernelHandle job = ProcessLauncher.CreateJob(1, false))
        using (ChildProcess parent = ProcessLauncher.CreateSuspended(
            selfPath, new string[] { "tree-parent", "--wait-ms", "1000" },
            currentDirectory, privateTemp, job, true, null, true))
        {
            parent.Resume();
            bool exited = parent.Wait(5000);
            List<uint> pids = ProcessLauncher.QueryJobPids(job);
            bool bounded = pids.Count <= 1;
            bool expectedDenial = exited && parent.ExitCode() == 42;
            Set("TL-JOB-008-ACTIVE-LIMIT", expectedDenial && bounded ? "Pass" : "Fail",
                expectedDenial && bounded ? "ACTIVE_PROCESS_LIMIT_ENFORCED" : "ACTIVE_PROCESS_LIMIT_FAILED", null);
        }
    }

    private void RunAssignmentFailureGuard()
    {
        using (SafeKernelHandle job = ProcessLauncher.CreateJob(1, false))
        using (ChildProcess child = ProcessLauncher.CreateSuspended(
            selfPath, new string[] { "tree-child", "--wait-ms", "30000" },
            currentDirectory, privateTemp, job, false, null, true))
        {
            bool inJob = ProcessLauncher.VerifyJob(child, job);
            if (inJob)
            {
                Set("TL-JOB-009-ASSIGNMENT-FAIL", "Fail", "UNEXPECTED_JOB_MEMBERSHIP", null);
                return;
            }
            child.KillIfAlive();
            bool exited = child.Wait(5000);
            Set("TL-JOB-009-ASSIGNMENT-FAIL", exited ? "Pass" : "Fail",
                exited ? "UNASSIGNED_SUSPENDED_CHILD_REJECTED" : "UNASSIGNED_CHILD_SURVIVED", null);
        }
    }

    private void RunHandleLeakTest()
    {
        if (!NativeMethods.SetHandleInformation(
            sourceLock, NativeMethods.HandleFlagInherit, NativeMethods.HandleFlagInherit))
        {
            Set("TL-HND-001-EXPLICIT-LIST", "Blocked", "SENTINEL_INHERIT_FLAG_FAILED", Marshal.GetLastWin32Error());
            return;
        }
        try
        {
            using (SafeKernelHandle job = ProcessLauncher.CreateJob(1, false))
            using (ChildProcess child = ProcessLauncher.CreateSuspended(
                selfPath,
                new string[]
                {
                    "handle-leak", "--handle", sourceLock.DangerousGetHandle().ToInt64().ToString(CultureInfo.InvariantCulture),
                    "--volume", sourceIdentity.Volume.ToString(CultureInfo.InvariantCulture),
                    "--file-low", sourceIdentity.FileLow.ToString(CultureInfo.InvariantCulture),
                    "--file-high", sourceIdentity.FileHigh.ToString(CultureInfo.InvariantCulture)
                },
                currentDirectory, privateTemp, job, true, null, true))
            {
                child.Resume();
                bool exited = child.Wait(5000);
                bool noLeak = exited && child.ExitCode() == 0;
                Set("TL-HND-001-EXPLICIT-LIST", noLeak ? "Pass" : "Fail",
                    noLeak ? "UNLISTED_INHERITABLE_SENTINEL_NOT_INHERITED" : "INHERITED_HANDLE_LEAK", null);
            }
        }
        finally
        {
            if (!NativeMethods.SetHandleInformation(
                sourceLock, NativeMethods.HandleFlagInherit, 0))
            {
                throw FileOperations.LastError("SENTINEL_INHERIT_RESTORE_FAILED");
            }
        }
    }

    private void RunRestrictedTokenTest()
    {
        try
        {
            using (SafeKernelHandle current = TokenOperations.OpenCurrent(
                NativeMethods.TokenQuery | NativeMethods.TokenDuplicate |
                NativeMethods.TokenAssignPrimary | NativeMethods.TokenAdjustDefault))
            using (SafeKernelHandle restricted = TokenOperations.CreateRestricted(current))
            using (SafeKernelHandle job = ProcessLauncher.CreateJob(1, false))
            using (ChildProcess child = ProcessLauncher.CreateSuspended(
                selfPath, new string[] { "tree-child", "--wait-ms", "100" },
                currentDirectory, privateTemp, job, true, restricted, true))
            {
                TokenSnapshot snapshot = ProcessLauncher.InspectToken(child);
                restrictedChildToken = snapshot;
                bool inJob = ProcessLauncher.VerifyJob(child, job);
                bool mitigation = ProcessLauncher.VerifyMitigation(child);
                bool acceptable = snapshot.IsNonElevated && snapshot.ElevationType != 2 &&
                    !snapshot.AdminEnabled && snapshot.AdminDenyOnly &&
                    !snapshot.LinkedTokenPresent && snapshot.DangerousEnabledPrivilegeCount == 0 &&
                    inJob && mitigation;
                if (!acceptable)
                {
                    string code = !snapshot.IsNonElevated || snapshot.ElevationType == 2
                        ? "RESTRICTED_CHILD_ELEVATED"
                        : snapshot.AdminEnabled || !snapshot.AdminDenyOnly
                            ? "RESTRICTED_ADMIN_GROUP_STATE_INVALID"
                            : snapshot.LinkedTokenPresent
                                ? "RESTRICTED_CHILD_LINKED_TOKEN_PRESENT"
                                : snapshot.DangerousEnabledPrivilegeCount != 0
                                    ? "RESTRICTED_DANGEROUS_PRIVILEGE_ENABLED"
                                    : !inJob
                                        ? "RESTRICTED_CHILD_NOT_IN_JOB"
                                        : "RESTRICTED_IMAGE_MITIGATION_MISSING";
                    Set("TL-TOK-004-RESTRICTED-ATTEMPT", "Fail", code, null);
                    Set("TL-TOK-005-CHILD", "Fail", code, null);
                    return;
                }
                child.Resume();
                bool exited = child.Wait(5000) && child.ExitCode() == 0;
                restrictedLaunchSucceeded = exited;
                Set("TL-TOK-004-RESTRICTED-ATTEMPT", exited ? "Pass" : "Fail",
                    exited ? "RESTRICTED_PRIMARY_TOKEN_CREATED_SYNTHETIC_CHILD" : "RESTRICTED_CHILD_EXIT_FAILED", null);
                Set("TL-TOK-005-CHILD", exited ? "Pass" : "Fail",
                    exited ? "NON_ELEVATED_NO_ADMIN_CHILD_VERIFIED" : "CHILD_TOKEN_TEST_FAILED", null);
            }
        }
        catch (ControlledException error)
        {
            Set("TL-TOK-004-RESTRICTED-ATTEMPT", "Fail", error.Code, error.SystemError);
            Set("TL-TOK-005-CHILD", "Blocked", "RESTRICTED_PROCESS_NOT_CREATED", error.SystemError);
        }
    }

    private void SetUnprovenCases()
    {
        SetIfUnreached("TL-IMG-004-RUNTIME", "NotTested", "MODULE_ENUMERATION_NOT_IMPLEMENTED");
        SetIfUnreached("TL-IMG-005-UNEXPECTED-MODULE-REJECT", "NotTested", "RUNTIME_MODULE_REJECTION_NOT_EXERCISED");
        Set("TL-VR-001-PRECONDITIONS", "Fail",
            adjacentMutationSucceeded ? "ADJACENT_DLL_MUTATION_SUCCEEDED" : "MANDATORY_IMAGE_BINDING_TESTS_NOT_COMPLETE", null);
        Set("TL-VR-002-VERSION", "NotTested", "LAUNCH_PRECONDITIONS_FAILED", null);
        Set("TL-VR-003-HELP", "NotTested", "LAUNCH_PRECONDITIONS_FAILED", null);
        Set("TL-VR-004-SYNTHETIC", "NotTested", "LAUNCH_PRECONDITIONS_FAILED", null);
    }

    private void RunFalsePositiveTests()
    {
        string[] ids = new string[]
        {
            "TL-FP-001-EXPECTED-SHA256", "TL-FP-002-SOURCE-FILE-ID",
            "TL-FP-003-DESTINATION-FILE-ID", "TL-FP-004-FILE-LOCK",
            "TL-FP-005-WRITE-REPLACE", "TL-FP-006-ADJACENT-MARKER",
            "TL-FP-007-ROOT-REPARSE", "TL-FP-008-JOB-ASSIGNMENT",
            "TL-FP-009-CHILD-JOB-MEMBERSHIP", "TL-FP-010-DESCENDANT-SURVIVAL",
            "TL-FP-011-CHILD-ELEVATION", "TL-FP-012-LINKED-TOKEN",
            "TL-FP-013-UNEXPECTED-MODULE", "TL-FP-014-MITIGATION-MISSING",
            "TL-FP-015-HANDLE-LEAK", "TL-FP-016-SILENT-FALLBACK"
        };
        for (int index = 0; index < ids.Length; index++)
        {
            SecurityGateState state = SecurityGateState.Safe();
            state.Inject(index);
            bool rejected = !SecurityGateAccepts(state);
            Set(ids[index], rejected ? "Pass" : "Fail",
                rejected ? "INJECTED_UNSAFE_STATE_REJECTED" : "FALSE_POSITIVE_GATE_FAILED", null);
        }
    }

    private static bool SecurityGateAccepts(SecurityGateState state)
    {
        return state.ExpectedSha256 && state.SourceFileId && state.DestinationFileId &&
            state.FileLock && state.WriteReplaceBlocked && state.AdjacentBlocked &&
            state.RootNotReparse && state.JobAssigned && state.ChildInJob &&
            state.NoDescendantSurvives && state.ChildNotElevated && state.NoLinkedFullToken &&
            state.ModuleAllowed && state.MitigationPresent && state.NoHandleLeak &&
            state.NoSilentFallback;
    }

    private RaceResult InvokeRace(string operation, string target, string replacement)
    {
        ProcessStartInfo start = new ProcessStartInfo();
        start.FileName = selfPath;
        StringBuilder arguments = new StringBuilder();
        AppendArgument(arguments, "race-worker");
        AppendArgument(arguments, "--operation");
        AppendArgument(arguments, operation);
        AppendArgument(arguments, "--scope-root");
        AppendArgument(arguments, runRoot);
        AppendArgument(arguments, "--target");
        AppendArgument(arguments, target);
        if (replacement != null)
        {
            AppendArgument(arguments, "--replacement");
            AppendArgument(arguments, replacement);
        }
        start.Arguments = arguments.ToString();
        start.WorkingDirectory = privateTemp;
        start.UseShellExecute = false;
        start.CreateNoWindow = true;
        start.RedirectStandardInput = false;
        start.RedirectStandardOutput = true;
        start.RedirectStandardError = true;
        start.EnvironmentVariables.Clear();
        string systemRoot = Environment.GetEnvironmentVariable("SystemRoot");
        start.EnvironmentVariables["SystemRoot"] = systemRoot;
        start.EnvironmentVariables["WINDIR"] = systemRoot;
        start.EnvironmentVariables["TEMP"] = privateTemp;
        start.EnvironmentVariables["TMP"] = privateTemp;
        start.EnvironmentVariables["PATH"] = Path.Combine(systemRoot, "System32");

        using (Process process = Process.Start(start))
        {
            if (!process.WaitForExit(5000))
            {
                process.Kill();
                process.WaitForExit(1000);
                throw new ControlledException("RACE_WORKER_TIMEOUT", null);
            }
            string output = process.StandardOutput.ReadToEnd();
            string errorText = process.StandardError.ReadToEnd();
            if (process.ExitCode != 0 || output.Length > 64 || errorText.Length != 0)
            {
                throw new ControlledException("RACE_WORKER_FAILED", process.ExitCode);
            }
            string[] pieces = output.Trim().Split(':');
            int error;
            if (pieces.Length != 2 || (pieces[0] != "0" && pieces[0] != "1") ||
                !Int32.TryParse(pieces[1], NumberStyles.None, CultureInfo.InvariantCulture, out error))
            {
                throw new ControlledException("RACE_WORKER_OUTPUT_INVALID", null);
            }
            return new RaceResult { Succeeded = pieces[0] == "1", Error = error };
        }
    }

    private static void AppendArgument(StringBuilder builder, string value)
    {
        if (builder.Length != 0)
        {
            builder.Append(' ');
        }
        builder.Append(Program.QuoteArgument(value));
    }

    private static void WriteCreateNew(string path, byte[] bytes)
    {
        using (FileStream stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read))
        {
            stream.Write(bytes, 0, bytes.Length);
            stream.Flush(true);
        }
    }

    private static List<uint> WaitForJobMembers(SafeKernelHandle job, int count, int timeoutMilliseconds)
    {
        Stopwatch timer = Stopwatch.StartNew();
        List<uint> pids = new List<uint>();
        while (timer.ElapsedMilliseconds < timeoutMilliseconds)
        {
            pids = ProcessLauncher.QueryJobPids(job);
            if (pids.Count >= count)
            {
                return pids;
            }
            Thread.Sleep(20);
        }
        return pids;
    }

    private void SetMutationCase(string id, RaceResult result, string blockedCode)
    {
        if (result.Succeeded)
        {
            Set(id, "Fail", "MUTATION_SUCCEEDED", null);
        }
        else if (result.Error == 5 || result.Error == 32)
        {
            Set(id, "Pass", blockedCode, result.Error);
        }
        else
        {
            Set(id, "Fail", "UNEXPECTED_MUTATION_ERROR", result.Error);
        }
    }

    private void Cleanup()
    {
        bool sourceStable = true;
        try
        {
            if (sourceLock != null && !sourceLock.IsClosed && sourceIdentity != null)
            {
                string after = FileOperations.Hash(sourceLock);
                sourceStable = String.Equals(after, expectedSha256, StringComparison.Ordinal);
            }
        }
        catch
        {
            sourceStable = false;
        }

        DisposeFile(ref destinationLock);
        DisposeFile(ref executionDirectoryLock);
        DisposeFile(ref currentDirectoryLock);
        DisposeFile(ref tempDirectoryLock);
        DisposeFile(ref helperSelfLock);
        DisposeFile(ref sourceLock);
        DisposeFile(ref runRootLock);
        DisposeFile(ref runBaseLock);

        bool helpersAbsent = NoOtherNamedProcess(Path.GetFileNameWithoutExtension(selfPath));
        bool velociraptorAbsent = NoOtherNamedProcess("velociraptor-v0.77.1-windows-amd64");
        Set("TL-CLEAN-001-NO-HELPERS", helpersAbsent ? "Pass" : "Fail",
            helpersAbsent ? "NO_SYNTHETIC_HELPER_PROCESS_REMAINS" : "SYNTHETIC_HELPER_PROCESS_REMAINS", null);
        Set("TL-CLEAN-002-NO-VELOCIRAPTOR", velociraptorAbsent ? "Pass" : "Fail",
            velociraptorAbsent ? "NO_VELOCIRAPTOR_PROCESS_PRESENT" : "VELOCIRAPTOR_PROCESS_PRESENT", null);

        bool removed = false;
        try
        {
            if (!String.IsNullOrEmpty(runRoot))
            {
                string fullRoot = Path.GetFullPath(runRoot);
                string prefix = runBase.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;
                if (!fullRoot.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) ||
                    !new DirectoryInfo(fullRoot).Name.StartsWith("trust-launch-", StringComparison.Ordinal))
                {
                    throw new ControlledException("CLEANUP_SCOPE_REJECTED", null);
                }
                if (Directory.Exists(fullRoot))
                {
                    DeleteScopedTreeWithoutRecursion(fullRoot);
                }
                removed = !Directory.Exists(fullRoot) && !File.Exists(fullRoot);
            }
        }
        catch
        {
            removed = false;
        }
        cleanupSucceeded = removed && sourceStable && helpersAbsent && velociraptorAbsent;
        Set("TL-CLEAN-003-RUN-ROOT", cleanupSucceeded ? "Pass" : "Fail",
            cleanupSucceeded ? "SCOPED_RUN_ROOT_REMOVED_SOURCE_UNCHANGED" : "CLEANUP_OR_SOURCE_STABILITY_FAILED", null);
    }

    private static void DisposeFile(ref SafeFileHandle handle)
    {
        if (handle != null)
        {
            handle.Dispose();
            handle = null;
        }
    }

    private static void DeleteScopedTreeWithoutRecursion(string root)
    {
        string rootPrefix = root.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) +
            Path.DirectorySeparatorChar;
        string[] firstLevel = Directory.GetFileSystemEntries(root);
        for (int index = 0; index < firstLevel.Length; index++)
        {
            string entry = Path.GetFullPath(firstLevel[index]);
            if (!entry.StartsWith(rootPrefix, StringComparison.OrdinalIgnoreCase))
            {
                throw new ControlledException("CLEANUP_ENTRY_OUT_OF_SCOPE", null);
            }
            FileAttributes attributes = File.GetAttributes(entry);
            bool directory = (attributes & FileAttributes.Directory) != 0;
            bool reparse = (attributes & FileAttributes.ReparsePoint) != 0;
            if (!directory)
            {
                File.Delete(entry);
                continue;
            }
            if (reparse)
            {
                Directory.Delete(entry, false);
                continue;
            }
            string[] secondLevel = Directory.GetFileSystemEntries(entry);
            for (int childIndex = 0; childIndex < secondLevel.Length; childIndex++)
            {
                string child = Path.GetFullPath(secondLevel[childIndex]);
                string entryPrefix = entry.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) +
                    Path.DirectorySeparatorChar;
                if (!child.StartsWith(entryPrefix, StringComparison.OrdinalIgnoreCase))
                {
                    throw new ControlledException("CLEANUP_CHILD_OUT_OF_SCOPE", null);
                }
                FileAttributes childAttributes = File.GetAttributes(child);
                if ((childAttributes & FileAttributes.Directory) != 0)
                {
                    if ((childAttributes & FileAttributes.ReparsePoint) == 0)
                    {
                        throw new ControlledException("CLEANUP_UNEXPECTED_DIRECTORY_DEPTH", null);
                    }
                    Directory.Delete(child, false);
                }
                else
                {
                    File.Delete(child);
                }
            }
            Directory.Delete(entry, false);
        }
        Directory.Delete(root, false);
    }

    private void BlockUnreached(string code, int? systemError)
    {
        for (int index = 0; index < MandatoryCases.All.Length; index++)
        {
            CaseResult item = cases[MandatoryCases.All[index]];
            if (item.Code == "NOT_REACHED")
            {
                item.Set("Blocked", code, systemError);
            }
        }
    }

    private void SetIfUnreached(string id, string outcome, string code)
    {
        if (cases[id].Code == "NOT_REACHED")
        {
            cases[id].Set(outcome, code, null);
        }
    }

    private void Set(string id, string outcome, string code, int? systemError)
    {
        CaseResult item;
        if (!cases.TryGetValue(id, out item))
        {
            throw new ControlledException("UNKNOWN_CASE_ID", null);
        }
        if (item.Code != "NOT_REACHED" && !id.StartsWith("TL-CLEAN-", StringComparison.Ordinal))
        {
            throw new ControlledException("CASE_SET_TWICE", null);
        }
        if (outcome != "Pass" && outcome != "Fail" && outcome != "Blocked" && outcome != "NotTested")
        {
            throw new ControlledException("INVALID_CASE_OUTCOME", null);
        }
        item.Set(outcome, code, systemError);
    }

    private string BuildSummary()
    {
        StringBuilder builder = new StringBuilder();
        builder.Append("{\n  \"contract_version\": 1,\n");
        builder.Append("  \"status\": ");
        JsonString(builder, Program.DefaultFinalStatus);
        builder.Append(",\n  \"readiness\": false,\n");
        builder.Append("  \"verified_against_documented_user_mode_threat_model\": false,\n");
        builder.Append("  \"velociraptor_process_created\": false,\n");
        builder.Append("  \"cleanup_complete\": ");
        builder.Append(cleanupSucceeded ? "true" : "false");
        builder.Append(",\n  \"source_identity\": {\"sha256_match\": ");
        builder.Append(sourceIdentity != null && String.Equals(sourceIdentity.Sha256, expectedSha256, StringComparison.Ordinal) ? "true" : "false");
        builder.Append(", \"path_class\": \"CompatibilityCache\"},\n");
        builder.Append("  \"reparse_observation\": {\"result\": ");
        JsonString(builder, reparseResult);
        builder.Append(", \"general_reparse_protection_proven\": false},\n");
        builder.Append("  \"environment_observation\": {");
        if (environmentObservation == null)
        {
            builder.Append("\"observed\": false");
        }
        else
        {
            builder.Append("\"observed\": true, \"failure_mask\": ")
                .Append(environmentObservation.FailureMask.ToString(CultureInfo.InvariantCulture));
            builder.Append(", \"system_root_present\": ").Append(environmentObservation.SystemRootPresent ? "true" : "false");
            builder.Append(", \"windir_present\": ").Append(environmentObservation.WindirPresent ? "true" : "false");
            builder.Append(", \"temp_present\": ").Append(environmentObservation.TempPresent ? "true" : "false");
            builder.Append(", \"tmp_present\": ").Append(environmentObservation.TmpPresent ? "true" : "false");
            builder.Append(", \"path_present\": ").Append(environmentObservation.PathPresent ? "true" : "false");
            builder.Append(", \"exact_allowlist\": ").Append(environmentObservation.ExactAllowlist ? "true" : "false");
            builder.Append(", \"temp_tmp_private\": ").Append(environmentObservation.PrivateTemp ? "true" : "false");
            builder.Append(", \"path_trusted_windows_only\": ").Append(environmentObservation.TrustedWindowsPath ? "true" : "false");
            builder.Append(", \"proxy_variables_absent\": ").Append(environmentObservation.ProxyVariablesAbsent ? "true" : "false");
            builder.Append(", \"toolchain_module_variables_absent\": ").Append(environmentObservation.ToolchainVariablesAbsent ? "true" : "false");
            builder.Append(", \"credential_token_variables_absent\": ").Append(environmentObservation.CredentialVariablesAbsent ? "true" : "false");
            builder.Append(", \"compatibility_layer_absent\": ").Append(environmentObservation.CompatibilityLayerAbsent ? "true" : "false");
            builder.Append(", \"windir_matches_system_root\": ").Append(environmentObservation.WindirMatchesSystemRoot ? "true" : "false");
        }
        builder.Append("},\n  \"module_observation\": {");
        if (moduleObservation == null)
        {
            builder.Append("\"observed\": false");
        }
        else
        {
            builder.Append("\"observed\": true");
            builder.Append(", \"preventive_loader_policy\": ").Append(moduleObservation.PreventiveLoaderPolicy ? "true" : "false");
            builder.Append(", \"mapped_image_identity_bound\": ").Append(moduleObservation.MappedImageIdentityBound ? "true" : "false");
            builder.Append(", \"main_image_path_match\": ").Append(moduleObservation.MainImagePathMatch ? "true" : "false");
            builder.Append(", \"reopened_file_identity_match\": ").Append(moduleObservation.ReopenedFileIdentityMatch ? "true" : "false");
            builder.Append(", \"initial_system_error\": ");
            AppendNullableInt(builder, moduleObservation.InitialSystemError);
            builder.Append(", \"runtime_system_error\": ");
            AppendNullableInt(builder, moduleObservation.RuntimeSystemError);
            builder.Append(", \"initial\": ");
            AppendModuleInventory(builder, moduleObservation.Initial);
            builder.Append(", \"runtime\": ");
            AppendModuleInventory(builder, moduleObservation.Runtime);
        }
        builder.Append("},\n");
        builder.Append("  \"token\": {");
        if (currentToken == null)
        {
            builder.Append("\"classified\": false");
        }
        else
        {
            builder.Append("\"classified\": true, \"elevation_type\": ");
            JsonString(builder, ElevationTypeName(currentToken.ElevationType));
            builder.Append(", \"elevated\": ").Append(currentToken.Elevated ? "true" : "false");
            builder.Append(", \"linked_token_present\": ").Append(currentToken.LinkedTokenPresent ? "true" : "false");
            builder.Append(", \"integrity_class\": ");
            JsonString(builder, IntegrityName(currentToken.IntegrityRid));
            builder.Append(", \"admin_group_enabled\": ").Append(currentToken.AdminEnabled ? "true" : "false");
            builder.Append(", \"dangerous_enabled_privilege_count\": ")
                .Append(currentToken.DangerousEnabledPrivilegeCount.ToString(CultureInfo.InvariantCulture));
        }
        builder.Append("},\n  \"pe\": {\"import_count\": ");
        builder.Append(peInventory == null ? "null" : peInventory.Imports.Count.ToString(CultureInfo.InvariantCulture));
        builder.Append(", \"import_names\": [");
        if (peInventory != null)
        {
            peInventory.Imports.Sort(StringComparer.Ordinal);
            for (int index = 0; index < peInventory.Imports.Count; index++)
            {
                if (index != 0) builder.Append(", ");
                JsonString(builder, peInventory.Imports[index]);
            }
        }
        builder.Append(']');
        builder.Append(", \"highest_available_observed\": ");
        builder.Append(peInventory != null && peInventory.HighestAvailableObserved ? "true" : "false");
        builder.Append("},\n  \"restricted_child_token\": {");
        if (restrictedChildToken == null)
        {
            builder.Append("\"classified\": false");
        }
        else
        {
            builder.Append("\"classified\": true, \"elevation_type\": ");
            JsonString(builder, ElevationTypeName(restrictedChildToken.ElevationType));
            builder.Append(", \"elevated\": ").Append(restrictedChildToken.Elevated ? "true" : "false");
            builder.Append(", \"linked_token_present\": ").Append(restrictedChildToken.LinkedTokenPresent ? "true" : "false");
            builder.Append(", \"integrity_class\": ");
            JsonString(builder, IntegrityName(restrictedChildToken.IntegrityRid));
            builder.Append(", \"admin_group_enabled\": ").Append(restrictedChildToken.AdminEnabled ? "true" : "false");
            builder.Append(", \"admin_group_deny_only\": ").Append(restrictedChildToken.AdminDenyOnly ? "true" : "false");
            builder.Append(", \"dangerous_enabled_privilege_count\": ")
                .Append(restrictedChildToken.DangerousEnabledPrivilegeCount.ToString(CultureInfo.InvariantCulture));
        }
        builder.Append("},\n  \"fatal\": {");
        if (fatalCode == null)
        {
            builder.Append("\"code\": null, \"system_error\": null");
        }
        else
        {
            builder.Append("\"code\": ");
            JsonString(builder, fatalCode);
            builder.Append(", \"system_error\": ");
            AppendNullableInt(builder, fatalSystemError);
        }
        builder.Append("},\n  \"cases\": [\n");
        for (int index = 0; index < MandatoryCases.All.Length; index++)
        {
            CaseResult item = cases[MandatoryCases.All[index]];
            builder.Append("    {\"id\": ");
            JsonString(builder, item.Id);
            builder.Append(", \"outcome\": ");
            JsonString(builder, item.Outcome);
            builder.Append(", \"code\": ");
            JsonString(builder, item.Code);
            builder.Append(", \"system_error\": ");
            AppendNullableInt(builder, item.SystemError);
            builder.Append('}');
            builder.Append(index + 1 == MandatoryCases.All.Length ? "\n" : ",\n");
        }
        builder.Append("  ]\n}\n");
        return builder.ToString();
    }

    private static void AppendModuleInventory(StringBuilder builder, ModuleInventory inventory)
    {
        if (inventory == null)
        {
            builder.Append("null");
            return;
        }
        builder.Append("{\"PrivateExecutionRoot\": ")
            .Append(inventory.PrivateExecutionRoot.ToString(CultureInfo.InvariantCulture));
        builder.Append(", \"System32\": ")
            .Append(inventory.System32.ToString(CultureInfo.InvariantCulture));
        builder.Append(", \"WindowsComponentStore\": ")
            .Append(inventory.WindowsComponentStore.ToString(CultureInfo.InvariantCulture));
        builder.Append(", \"UnexpectedUserWritable\": ")
            .Append(inventory.UnexpectedUserWritable.ToString(CultureInfo.InvariantCulture));
        builder.Append(", \"Unknown\": ")
            .Append(inventory.Unknown.ToString(CultureInfo.InvariantCulture));
        builder.Append('}');
    }

    private static void AppendNullableInt(StringBuilder builder, int? value)
    {
        builder.Append(value.HasValue ? value.Value.ToString(CultureInfo.InvariantCulture) : "null");
    }

    private static void JsonString(StringBuilder builder, string value)
    {
        builder.Append('"');
        for (int index = 0; index < value.Length; index++)
        {
            char character = value[index];
            switch (character)
            {
                case '"': builder.Append("\\\""); break;
                case '\\': builder.Append("\\\\"); break;
                case '\b': builder.Append("\\b"); break;
                case '\f': builder.Append("\\f"); break;
                case '\n': builder.Append("\\n"); break;
                case '\r': builder.Append("\\r"); break;
                case '\t': builder.Append("\\t"); break;
                default:
                    if (character < 0x20)
                    {
                        builder.Append("\\u");
                        builder.Append(((int)character).ToString("x4", CultureInfo.InvariantCulture));
                    }
                    else
                    {
                        builder.Append(character);
                    }
                    break;
            }
        }
        builder.Append('"');
    }

    private static string ElevationTypeName(int value)
    {
        if (value == 1) return "Default";
        if (value == 2) return "Full";
        if (value == 3) return "Limited";
        return "Unknown";
    }

    private static string IntegrityName(uint rid)
    {
        if (rid < 0x1000) return "Untrusted";
        if (rid < 0x2000) return "Low";
        if (rid < 0x3000) return "Medium";
        if (rid < 0x4000) return "High";
        if (rid < 0x5000) return "System";
        return "Protected";
    }

    private static bool IsLowerHex(string value)
    {
        for (int index = 0; index < value.Length; index++)
        {
            char character = value[index];
            if (!((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')))
            {
                return false;
            }
        }
        return true;
    }

    private static int ExitHarnessFailureCode()
    {
        return 1;
    }

    private static bool NoOtherNamedProcess(string name)
    {
        Process[] processes = Process.GetProcessesByName(name);
        try
        {
            int current = Process.GetCurrentProcess().Id;
            for (int index = 0; index < processes.Length; index++)
            {
                try
                {
                    if (processes[index].Id != current && !processes[index].HasExited)
                    {
                        return false;
                    }
                }
                catch (InvalidOperationException)
                {
                    // A process that exited during this bounded name check is absent.
                }
            }
            return true;
        }
        finally
        {
            for (int index = 0; index < processes.Length; index++)
            {
                processes[index].Dispose();
            }
        }
    }

    private static bool IsPathWithin(string root, string candidate)
    {
        string normalizedRoot = Path.GetFullPath(root).TrimEnd(
            Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        string normalizedCandidate = Path.GetFullPath(candidate).TrimEnd(
            Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        return String.Equals(normalizedRoot, normalizedCandidate, StringComparison.OrdinalIgnoreCase) ||
            normalizedCandidate.StartsWith(
                normalizedRoot + Path.DirectorySeparatorChar,
                StringComparison.OrdinalIgnoreCase);
    }
}

internal sealed class SecurityGateState
{
    internal bool ExpectedSha256;
    internal bool SourceFileId;
    internal bool DestinationFileId;
    internal bool FileLock;
    internal bool WriteReplaceBlocked;
    internal bool AdjacentBlocked;
    internal bool RootNotReparse;
    internal bool JobAssigned;
    internal bool ChildInJob;
    internal bool NoDescendantSurvives;
    internal bool ChildNotElevated;
    internal bool NoLinkedFullToken;
    internal bool ModuleAllowed;
    internal bool MitigationPresent;
    internal bool NoHandleLeak;
    internal bool NoSilentFallback;

    internal static SecurityGateState Safe()
    {
        return new SecurityGateState
        {
            ExpectedSha256 = true,
            SourceFileId = true,
            DestinationFileId = true,
            FileLock = true,
            WriteReplaceBlocked = true,
            AdjacentBlocked = true,
            RootNotReparse = true,
            JobAssigned = true,
            ChildInJob = true,
            NoDescendantSurvives = true,
            ChildNotElevated = true,
            NoLinkedFullToken = true,
            ModuleAllowed = true,
            MitigationPresent = true,
            NoHandleLeak = true,
            NoSilentFallback = true
        };
    }

    internal void Inject(int index)
    {
        switch (index)
        {
            case 0: ExpectedSha256 = false; break;
            case 1: SourceFileId = false; break;
            case 2: DestinationFileId = false; break;
            case 3: FileLock = false; break;
            case 4: WriteReplaceBlocked = false; break;
            case 5: AdjacentBlocked = false; break;
            case 6: RootNotReparse = false; break;
            case 7: JobAssigned = false; break;
            case 8: ChildInJob = false; break;
            case 9: NoDescendantSurvives = false; break;
            case 10: ChildNotElevated = false; break;
            case 11: NoLinkedFullToken = false; break;
            case 12: ModuleAllowed = false; break;
            case 13: MitigationPresent = false; break;
            case 14: NoHandleLeak = false; break;
            case 15: NoSilentFallback = false; break;
            default: throw new ControlledException("FALSE_POSITIVE_INDEX_INVALID", null);
        }
    }
}
