// Development-only, self-launching synthetic experiment. NOT a backend launcher.
// No caller-supplied image/argv, collectors, UAC, shell, DLL or reparse probes.
// Same-user image/root integrity and preventive loader policy are NOT provided.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;

namespace SecApp.SyntheticLaunch
{
    internal sealed class Failure : Exception
    {
        internal readonly string Code;
        internal readonly int NativeError;
        internal Failure(string code, int error) { Code = code; NativeError = error; }
        internal static Failure Last(string code) { return new Failure(code, Marshal.GetLastWin32Error()); }
    }

    internal sealed class Handle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private Handle() : base(true) { }
        internal Handle(IntPtr value) : base(true) { SetHandle(value); }
        protected override bool ReleaseHandle() { return Native.CloseHandle(handle); }
    }

    internal sealed class Handles : IDisposable
    {
        private readonly List<Handle> values = new List<Handle>();
        internal Handle Own(Handle value) { values.Add(value); return value; }
        public void Dispose() { for (int i = values.Count - 1; i >= 0; --i) values[i].Dispose(); }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SecurityAttributes
    {
        internal int Length;
        internal IntPtr Descriptor;
        [MarshalAs(UnmanagedType.Bool)] internal bool Inherit;
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct StartupInfo
    {
        internal int Size;
        internal string Reserved, Desktop, Title;
        internal uint X, Y, XSize, YSize, XCount, YCount, Fill, Flags;
        internal short Show, ReservedBytes;
        internal IntPtr Reserved2, Input, Output, Error;
    }
    [StructLayout(LayoutKind.Sequential)]
    internal struct StartupInfoEx { internal StartupInfo Startup; internal IntPtr Attributes; }
    [StructLayout(LayoutKind.Sequential)]
    internal struct ProcessInfo { internal IntPtr Process, Thread; internal uint Pid, Tid; }
    [StructLayout(LayoutKind.Sequential)]
    internal struct BasicLimits
    {
        internal long ProcessTime, JobTime;
        internal uint Flags;
        internal UIntPtr MinimumWorkingSet, MaximumWorkingSet;
        internal uint ActiveProcesses;
        internal UIntPtr Affinity;
        internal uint Priority, Scheduling;
    }
    [StructLayout(LayoutKind.Sequential)]
    internal struct IoCounters { internal ulong A, B, C, D, E, F; }
    [StructLayout(LayoutKind.Sequential)]
    internal struct ExtendedLimits
    {
        internal BasicLimits Basic;
        internal IoCounters Io;
        internal UIntPtr ProcessMemory, JobMemory, PeakProcessMemory, PeakJobMemory;
    }
    [StructLayout(LayoutKind.Sequential)]
    internal struct Accounting
    {
        internal long UserTime, KernelTime, PeriodUserTime, PeriodKernelTime;
        internal uint PageFaults, TotalProcesses, ActiveProcesses, TerminatedProcesses;
    }
    [StructLayout(LayoutKind.Sequential)]
    internal struct SidAttributes { internal IntPtr Sid; internal uint Attributes; }

    internal static class Native
    {
        [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32.dll")] internal static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32.dll")] internal static extern IntPtr GetStdHandle(int which);
        [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool CreatePipe(out Handle read, out Handle write, ref SecurityAttributes attributes, uint size);
        [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool SetHandleInformation(Handle handle, uint mask, uint flags);
        [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool PeekNamedPipe(Handle pipe, IntPtr buffer, uint size, IntPtr read, out uint available, IntPtr remaining);
        [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool ReadFile(Handle file, byte[] bytes, uint size, out uint read, IntPtr overlapped);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] internal static extern Handle CreateJobObjectW(IntPtr attributes, string name);
        [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool SetInformationJobObject(Handle job, int type, ref ExtendedLimits limits, uint size);
        [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool QueryInformationJobObject(Handle job, int type, out Accounting info, uint size, out uint returned);
        [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool IsProcessInJob(IntPtr process, IntPtr job, out bool inJob);
        [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool TerminateJobObject(Handle job, uint exitCode);
        [DllImport("kernel32.dll", SetLastError = true)] internal static extern uint WaitForSingleObject(Handle handle, uint milliseconds);
        [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool GetExitCodeProcess(Handle process, out uint code);
        [DllImport("kernel32.dll", SetLastError = true)] internal static extern uint ResumeThread(Handle thread);
        [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool TerminateProcess(Handle process, uint code);
        [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, int flags, ref IntPtr size);
        [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, IntPtr attribute, IntPtr value, UIntPtr size, IntPtr previous, IntPtr returned);
        [DllImport("kernel32.dll")] internal static extern void DeleteProcThreadAttributeList(IntPtr list);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] internal static extern bool CreateProcessW(string app, StringBuilder command, IntPtr processAttributes, IntPtr threadAttributes, bool inherit, uint flags, IntPtr environment, string directory, ref StartupInfoEx startup, out ProcessInfo info);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] internal static extern bool CreateProcessAsUserW(Handle token, string app, StringBuilder command, IntPtr processAttributes, IntPtr threadAttributes, bool inherit, uint flags, IntPtr environment, string directory, ref StartupInfoEx startup, out ProcessInfo info);
        [DllImport("advapi32.dll", SetLastError = true)] internal static extern bool OpenProcessToken(IntPtr process, uint access, out Handle token);
        [DllImport("advapi32.dll", SetLastError = true)] internal static extern bool GetTokenInformation(Handle token, int type, IntPtr buffer, uint size, out uint returned);
        [DllImport("advapi32.dll", SetLastError = true)] internal static extern bool CreateRestrictedToken(Handle existing, uint flags, uint disableCount, IntPtr disableSids, uint deleteCount, IntPtr deletePrivileges, uint restrictCount, IntPtr restrictSids, out Handle token);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] internal static extern bool ConvertStringSidToSidW(string sid, out IntPtr result);
        [DllImport("advapi32.dll")] internal static extern bool EqualSid(IntPtr left, IntPtr right);
        [DllImport("advapi32.dll")] internal static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);
        [DllImport("advapi32.dll")] internal static extern IntPtr GetSidSubAuthority(IntPtr sid, uint index);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] internal static extern bool LookupPrivilegeNameW(string system, IntPtr luid, StringBuilder name, ref uint size);
        [DllImport("kernel32.dll")] internal static extern IntPtr LocalFree(IntPtr memory);
    }

    internal sealed class Attributes : IDisposable
    {
        internal IntPtr Pointer;
        private bool initialized;
        private readonly List<IntPtr> storage = new List<IntPtr>();
        internal Attributes(IntPtr[] handles, Handle job)
        {
            try
            {
                IntPtr size = IntPtr.Zero;
                Native.InitializeProcThreadAttributeList(IntPtr.Zero, job == null ? 1 : 2, 0, ref size);
                if (size.ToInt64() <= 0 || size.ToInt64() > 65536) throw new Failure("ATTRIBUTE_SIZE", 0);
                Pointer = Marshal.AllocHGlobal(size);
                if (!Native.InitializeProcThreadAttributeList(Pointer, job == null ? 1 : 2, 0, ref size)) throw Failure.Last("ATTRIBUTE_INIT");
                initialized = true;
                Add(0x20002, handles);
                if (job != null) Add(0x2000d, new IntPtr[] { job.DangerousGetHandle() });
            }
            catch { Dispose(); throw; }
        }
        private void Add(int attribute, IntPtr[] values)
        {
            int bytes = checked(values.Length * IntPtr.Size);
            IntPtr memory = Marshal.AllocHGlobal(bytes);
            storage.Add(memory);
            Marshal.Copy(values, 0, memory, values.Length);
            if (!Native.UpdateProcThreadAttribute(Pointer, 0, new IntPtr(attribute), memory, new UIntPtr((uint)bytes), IntPtr.Zero, IntPtr.Zero)) throw Failure.Last("ATTRIBUTE_UPDATE");
        }
        public void Dispose()
        {
            if (initialized) { Native.DeleteProcThreadAttributeList(Pointer); initialized = false; }
            foreach (IntPtr memory in storage) Marshal.FreeHGlobal(memory);
            storage.Clear();
            if (Pointer != IntPtr.Zero) { Marshal.FreeHGlobal(Pointer); Pointer = IntPtr.Zero; }
        }
    }

    internal sealed class TokenState
    {
        internal bool Elevated, AdminEnabled;
        internal uint Integrity;
        internal int DangerousEnabled;
        internal string Linked = "Unknown";
        internal bool EffectiveStandard { get { return !Elevated && !AdminEnabled && Integrity <= 0x2000 && DangerousEnabled == 0; } }
    }

    internal static class Tokens
    {
        private static readonly HashSet<string> dangerous = new HashSet<string>(new string[] {
            "SeAssignPrimaryTokenPrivilege", "SeBackupPrivilege", "SeCreateTokenPrivilege",
            "SeDebugPrivilege", "SeImpersonatePrivilege", "SeIncreaseQuotaPrivilege",
            "SeLoadDriverPrivilege", "SeRelabelPrivilege", "SeRestorePrivilege",
            "SeTakeOwnershipPrivilege", "SeTcbPrivilege"
        }, StringComparer.Ordinal);

        private static IntPtr Query(Handle token, int type)
        {
            uint size;
            Native.GetTokenInformation(token, type, IntPtr.Zero, 0, out size);
            if (size == 0 || size > 1048576) throw Failure.Last("TOKEN_SIZE");
            IntPtr memory = Marshal.AllocHGlobal(checked((int)size));
            if (!Native.GetTokenInformation(token, type, memory, size, out size))
            { int error = Marshal.GetLastWin32Error(); Marshal.FreeHGlobal(memory); throw new Failure("TOKEN_QUERY", error); }
            return memory;
        }
        internal static TokenState Inspect(IntPtr process)
        {
            Handle token;
            if (!Native.OpenProcessToken(process, 8, out token)) throw Failure.Last("TOKEN_OPEN");
            using (token)
            {
                TokenState state = new TokenState();
                IntPtr memory = Query(token, 20);
                try { state.Elevated = Marshal.ReadInt32(memory) != 0; } finally { Marshal.FreeHGlobal(memory); }
                memory = Query(token, 25);
                try
                {
                    IntPtr sid = Marshal.ReadIntPtr(memory);
                    byte count = Marshal.ReadByte(Native.GetSidSubAuthorityCount(sid));
                    if (count == 0) throw new Failure("INTEGRITY_SID", 0);
                    state.Integrity = unchecked((uint)Marshal.ReadInt32(Native.GetSidSubAuthority(sid, (uint)(count - 1))));
                }
                finally { Marshal.FreeHGlobal(memory); }
                IntPtr admin;
                if (!Native.ConvertStringSidToSidW("S-1-5-32-544", out admin)) throw Failure.Last("ADMIN_SID");
                try
                {
                    memory = Query(token, 2);
                    try
                    {
                        int count = Marshal.ReadInt32(memory);
                        if (count < 0 || count > 4096) throw new Failure("TOKEN_GROUP_COUNT", 0);
                        int stride = Marshal.SizeOf(typeof(SidAttributes));
                        for (int i = 0; i < count; ++i)
                        {
                            SidAttributes group = (SidAttributes)Marshal.PtrToStructure(IntPtr.Add(memory, 8 + i * stride), typeof(SidAttributes));
                            if (Native.EqualSid(group.Sid, admin)) state.AdminEnabled = (group.Attributes & 4) != 0 && (group.Attributes & 16) == 0;
                        }
                    }
                    finally { Marshal.FreeHGlobal(memory); }
                }
                finally { Native.LocalFree(admin); }
                memory = Query(token, 3);
                try
                {
                    int count = Marshal.ReadInt32(memory);
                    if (count < 0 || count > 4096) throw new Failure("TOKEN_PRIVILEGE_COUNT", 0);
                    for (int i = 0; i < count; ++i)
                    {
                        IntPtr entry = IntPtr.Add(memory, 4 + i * 12);
                        if ((Marshal.ReadInt32(entry, 8) & 2) == 0) continue;
                        uint length = 256;
                        StringBuilder name = new StringBuilder((int)length);
                        if (!Native.LookupPrivilegeNameW(null, entry, name, ref length)) throw Failure.Last("PRIVILEGE_NAME");
                        if (dangerous.Contains(name.ToString())) ++state.DangerousEnabled;
                    }
                }
                finally { Marshal.FreeHGlobal(memory); }
                // Observe metadata, never use the linked token or request elevation.
                memory = Marshal.AllocHGlobal(IntPtr.Size);
                try
                {
                    uint returned;
                    if (Native.GetTokenInformation(token, 19, memory, (uint)IntPtr.Size, out returned))
                    {
                        IntPtr linked = Marshal.ReadIntPtr(memory);
                        state.Linked = linked == IntPtr.Zero ? "Absent" : "Present";
                        if (linked != IntPtr.Zero) using (Handle unused = new Handle(linked)) { }
                    }
                    else
                    {
                        int error = Marshal.GetLastWin32Error();
                        state.Linked = error == 1312 ? "Absent" : "Unknown";
                    }
                }
                finally { Marshal.FreeHGlobal(memory); }
                return state;
            }
        }
        internal static Handle Restricted()
        {
            Handle current;
            if (!Native.OpenProcessToken(Native.GetCurrentProcess(), 0x8b, out current)) throw Failure.Last("RESTRICT_SOURCE");
            using (current)
            {
                string[] sids = { "S-1-5-32-544", "S-1-5-32-547", "S-1-5-32-548", "S-1-5-32-549", "S-1-5-32-550", "S-1-5-32-551" };
                List<IntPtr> allocated = new List<IntPtr>();
                int stride = Marshal.SizeOf(typeof(SidAttributes));
                IntPtr list = Marshal.AllocHGlobal(stride * sids.Length);
                try
                {
                    for (int i = 0; i < sids.Length; ++i)
                    {
                        IntPtr sid;
                        if (!Native.ConvertStringSidToSidW(sids[i], out sid)) throw Failure.Last("RESTRICT_SID");
                        allocated.Add(sid);
                        Marshal.StructureToPtr(new SidAttributes { Sid = sid, Attributes = 0 }, IntPtr.Add(list, i * stride), false);
                    }
                    Handle restricted;
                    // Experimental privilege/group reduction, NOT an isolation sandbox.
                    if (!Native.CreateRestrictedToken(current, 1, (uint)sids.Length, list, 0, IntPtr.Zero, 0, IntPtr.Zero, out restricted)) throw Failure.Last("RESTRICT_CREATE");
                    return restricted;
                }
                finally { foreach (IntPtr sid in allocated) Native.LocalFree(sid); Marshal.FreeHGlobal(list); }
            }
        }
    }

    internal sealed class PipeBuffer
    {
        internal const int Limit = 4096;
        private readonly byte[] scratch = new byte[4096];
        private readonly MemoryStream retained = new MemoryStream(Limit);
        internal readonly Handle Pipe;
        internal bool Closed, Exceeded;
        internal PipeBuffer(Handle pipe) { Pipe = pipe; }
        internal string Text { get { return Encoding.ASCII.GetString(retained.ToArray()); } }
        internal bool Bounded { get { return retained.Length <= Limit; } }
        internal void Drain()
        {
            if (Closed) return;
            // At most two chunks per stream/poll: a busy stdout cannot starve cancellation.
            for (int i = 0; i < 2; ++i)
            {
                uint available;
                if (!Native.PeekNamedPipe(Pipe, IntPtr.Zero, 0, IntPtr.Zero, out available, IntPtr.Zero))
                { if (Marshal.GetLastWin32Error() == 109) { Closed = true; return; } throw Failure.Last("PIPE_PEEK"); }
                if (available == 0) return;
                uint read;
                if (!Native.ReadFile(Pipe, scratch, Math.Min(available, (uint)scratch.Length), out read, IntPtr.Zero))
                { if (Marshal.GetLastWin32Error() == 109) { Closed = true; return; } throw Failure.Last("PIPE_READ"); }
                if (read == 0) return;
                int keep = Math.Min((int)read, Limit - (int)retained.Length);
                if (keep < read) Exceeded = true;
                retained.Write(scratch, 0, keep);
            }
        }
    }

    internal sealed class Result
    {
        internal string Id, Expected, Outcome = "Error", Error = "None", Linked = "NotObserved";
        internal bool Created, Resumed, EffectiveStandard, RootExited, JobEmpty, PipesClosed, Bounded = true, TreeObserved, Passed;
        internal int NativeError;
        internal uint? ExitCode;
        private static string B(bool value) { return value ? "true" : "false"; }
        internal string Json()
        {
            // All string fields come from fixed literals in this file; no machine strings.
            return "{\"id\":\"" + Id + "\",\"expected\":\"" + Expected + "\",\"outcome\":\"" + Outcome +
                "\",\"passed\":" + B(Passed) + ",\"created\":" + B(Created) + ",\"resumed\":" + B(Resumed) +
                ",\"effective_standard\":" + B(EffectiveStandard) + ",\"linked_metadata\":\"" + Linked +
                "\",\"root_exited\":" + B(RootExited) + ",\"job_empty\":" + B(JobEmpty) + ",\"pipes_closed\":" + B(PipesClosed) +
                ",\"buffers_bounded\":" + B(Bounded) + ",\"tree_observed\":" + B(TreeObserved) +
                ",\"exit_code\":" + (ExitCode.HasValue ? ExitCode.Value.ToString(System.Globalization.CultureInfo.InvariantCulture) : "null") +
                ",\"error\":\"" + Error + "\",\"native_error\":" + NativeError + "}";
        }
    }

    internal static class Program
    {
        private static string Image { get { return typeof(Program).Assembly.Location; } }
        private static string DirectoryPath { get { return Path.GetDirectoryName(Image); } }
        private static StringBuilder Command(string mode) { return new StringBuilder("\"" + Image + "\" --child " + mode); }
        private static void Check(bool value, string code) { if (!value) throw Failure.Last(code); }
        private static uint Active(Handle job)
        {
            Accounting info;
            uint returned;
            Check(Native.QueryInformationJobObject(job, 1, out info, (uint)Marshal.SizeOf(typeof(Accounting)), out returned), "JOB_QUERY");
            return info.ActiveProcesses;
        }
        private static bool Exited(Handle process)
        {
            uint wait = Native.WaitForSingleObject(process, 0);
            if (wait == 0) return true;
            if (wait == 258) return false;
            throw Failure.Last("PROCESS_WAIT");
        }
        private static void Pipe(Handles handles, bool parentReads, out Handle read, out Handle write)
        {
            SecurityAttributes attributes = new SecurityAttributes { Length = Marshal.SizeOf(typeof(SecurityAttributes)), Inherit = true };
            Check(Native.CreatePipe(out read, out write, ref attributes, 4096), "PIPE_CREATE");
            handles.Own(read); handles.Own(write);
            Check(Native.SetHandleInformation(parentReads ? read : write, 1, 0), "PIPE_INHERIT");
        }
        private static IntPtr EnvironmentBlock()
        {
            string root = Environment.GetEnvironmentVariable("SystemRoot");
            if (String.IsNullOrEmpty(root) || !Path.IsPathRooted(root)) throw new Failure("SYSTEM_ROOT", 0);
            return Marshal.StringToHGlobalUni("SystemRoot=" + root + "\0TEMP=" + DirectoryPath + "\0TMP=" + DirectoryPath + "\0WINDIR=" + root + "\0\0");
        }
        private static Result Run(string id, string mode, string expected, bool restricted, bool preCancelled, bool injected)
        {
            Result result = new Result { Id = id, Expected = expected };
            using (Handles handles = new Handles())
            using (CancellationTokenSource cancellation = new CancellationTokenSource())
            {
                Handle process = null, job = null;
                PipeBuffer output = null, error = null;
                try
                {
                    if (preCancelled) cancellation.Cancel();
                    if (cancellation.IsCancellationRequested)
                    {
                        result.Outcome = "CancelledBeforeCreate";
                        result.Passed = expected == result.Outcome && !result.Created;
                        return result;
                    }
                    job = handles.Own(Native.CreateJobObjectW(IntPtr.Zero, null));
                    Check(!job.IsInvalid, "JOB_CREATE");
                    ExtendedLimits limits = new ExtendedLimits();
                    limits.Basic.Flags = 0x2000 | 8; // Kill on close; process-count ceiling. No breakaway.
                    limits.Basic.ActiveProcesses = 4;
                    Check(Native.SetInformationJobObject(job, 9, ref limits, (uint)Marshal.SizeOf(typeof(ExtendedLimits))), "JOB_LIMITS");
                    Handle inputRead, inputWrite, outputRead, outputWrite, errorRead, errorWrite;
                    Pipe(handles, false, out inputRead, out inputWrite);
                    Pipe(handles, true, out outputRead, out outputWrite);
                    Pipe(handles, true, out errorRead, out errorWrite);
                    inputWrite.Dispose(); // Fixed EOF input; no interactive child input.
                    output = new PipeBuffer(outputRead); error = new PipeBuffer(errorRead);
                    Handle token = restricted ? handles.Own(Tokens.Restricted()) : null;
                    using (Attributes attributes = new Attributes(new IntPtr[] { inputRead.DangerousGetHandle(), outputWrite.DangerousGetHandle(), errorWrite.DangerousGetHandle() }, job))
                    {
                        StartupInfoEx startup = new StartupInfoEx();
                        startup.Startup.Size = Marshal.SizeOf(typeof(StartupInfoEx));
                        startup.Startup.Flags = 0x100;
                        startup.Startup.Input = inputRead.DangerousGetHandle();
                        startup.Startup.Output = outputWrite.DangerousGetHandle();
                        startup.Startup.Error = errorWrite.DangerousGetHandle();
                        startup.Attributes = attributes.Pointer;
                        ProcessInfo info;
                        IntPtr environment = EnvironmentBlock();
                        try
                        {
                            // Assign Job at creation, before any child code; unsupported => fail, no fallback.
                            uint flags = 0x4 | 0x400 | 0x80000 | 0x08000000;
                            bool created = restricted
                                ? Native.CreateProcessAsUserW(token, Image, Command(mode), IntPtr.Zero, IntPtr.Zero, true, flags, environment, DirectoryPath, ref startup, out info)
                                : Native.CreateProcessW(Image, Command(mode), IntPtr.Zero, IntPtr.Zero, true, flags, environment, DirectoryPath, ref startup, out info);
                            Check(created, "PROCESS_CREATE");
                        }
                        finally { Marshal.FreeHGlobal(environment); }
                        process = handles.Own(new Handle(info.Process));
                        Handle thread = handles.Own(new Handle(info.Thread));
                        result.Created = true;
                        inputRead.Dispose(); outputWrite.Dispose(); errorWrite.Dispose();
                        bool inJob;
                        Check(Native.IsProcessInJob(process.DangerousGetHandle(), job.DangerousGetHandle(), out inJob) && inJob, "JOB_MEMBERSHIP");
                        TokenState state = Tokens.Inspect(process.DangerousGetHandle());
                        result.EffectiveStandard = state.EffectiveStandard;
                        result.Linked = state.Linked;
                        if (!state.EffectiveStandard) throw new Failure("CHILD_PRIVILEGE_POLICY", 0);
                        if (injected) throw new Failure("INJECTED_PRE_RESUME", 0);
                        if (Native.ResumeThread(thread) != 1) throw Failure.Last("RESUME");
                        result.Resumed = true;
                    }
                    Stopwatch elapsed = Stopwatch.StartNew();
                    long readyAt = -1;
                    while (true)
                    {
                        output.Drain(); error.Drain();
                        uint active = Active(job);
                        bool exited = Exited(process);
                        bool ready = output.Text.Contains("READY\n");
                        // A Job count alone may include an OS console helper. Require the
                        // synthetic leaf's own handshake, not just a second Job member.
                        bool leaf = output.Text.Contains("LEAF\n");
                        result.TreeObserved |= ready && leaf && (active >= 2 || (exited && active >= 1));
                        if (ready && readyAt < 0) readyAt = elapsed.ElapsedMilliseconds;
                        if (mode == "cancel-tree" && ready && result.TreeObserved) cancellation.Cancel();
                        if (output.Exceeded) { result.Outcome = "StdoutLimit"; break; }
                        if (error.Exceeded) { result.Outcome = "StderrLimit"; break; }
                        if (cancellation.IsCancellationRequested) { result.Outcome = "Cancelled"; break; }
                        if (elapsed.ElapsedMilliseconds >= 4000 || (mode == "timeout-tree" && readyAt >= 0 && elapsed.ElapsedMilliseconds - readyAt >= 300))
                        { result.Outcome = "Timeout"; break; }
                        if (exited)
                        {
                            uint exitCode;
                            Check(Native.GetExitCodeProcess(process, out exitCode), "EXIT_CODE");
                            result.ExitCode = exitCode;
                            if (active > 0 && (mode != "leave-tree" || result.TreeObserved))
                            { result.Outcome = "DescendantsAfterParentExit"; break; }
                            if (output.Closed && error.Closed)
                            {
                                result.Outcome = result.ExitCode == 0 ? "Completed" : "NonZeroExit";
                                if (mode == "normal" && (output.Text != "OUT\n" || error.Text != "ERR\n")) result.Outcome = "OutputMismatch";
                                break;
                            }
                        }
                        Thread.Sleep(5);
                    }
                }
                catch (Failure failure)
                {
                    result.Error = failure.Code; result.NativeError = failure.NativeError;
                    result.Outcome = failure.Code == "INJECTED_PRE_RESUME" ? "InjectedBeforeResume" : "Error";
                }
                catch { result.Error = "INTERNAL_ERROR"; result.Outcome = "Error"; }
                finally
                {
                    if (process != null)
                    {
                        try
                        {
                            // Also covers faults before ResumeThread and descendant-held pipe handles.
                            Native.TerminateJobObject(job, 125);
                            // Defensive cleanup of our root also if a membership/query invariant failed.
                            if (!Exited(process)) Native.TerminateProcess(process, 125);
                            Stopwatch cleanup = Stopwatch.StartNew();
                            while (cleanup.ElapsedMilliseconds < 3000)
                            {
                                output.Drain(); error.Drain();
                                result.RootExited = Exited(process);
                                result.JobEmpty = Active(job) == 0;
                                result.PipesClosed = output.Closed && error.Closed;
                                if (result.RootExited && result.JobEmpty && result.PipesClosed) break;
                                Thread.Sleep(5);
                            }
                            result.Bounded = output.Bounded && error.Bounded;
                            if (!result.RootExited || !result.JobEmpty || !result.PipesClosed)
                            { result.Outcome = "CleanupFailed"; result.Error = "CLEANUP_DEADLINE"; }
                        }
                        catch { result.Outcome = "CleanupFailed"; result.Error = "CLEANUP_QUERY"; }
                    }
                }
                result.Passed = result.Outcome == expected && result.Created && result.EffectiveStandard &&
                    result.RootExited && result.JobEmpty && result.PipesClosed && result.Bounded &&
                    (injected ? !result.Resumed : result.Resumed) &&
                    (!mode.EndsWith("tree", StringComparison.Ordinal) || result.TreeObserved) &&
                    (mode != "nonzero" || result.ExitCode == 17);
            }
            return result;
        }
        private static void Descendant()
        {
            IntPtr input = Native.GetStdHandle(-10), output = Native.GetStdHandle(-11), error = Native.GetStdHandle(-12);
            using (Attributes attributes = new Attributes(new IntPtr[] { input, output, error }, null))
            {
                StartupInfoEx startup = new StartupInfoEx();
                startup.Startup.Size = Marshal.SizeOf(typeof(StartupInfoEx));
                startup.Startup.Flags = 0x100;
                startup.Startup.Input = input; startup.Startup.Output = output; startup.Startup.Error = error;
                startup.Attributes = attributes.Pointer;
                ProcessInfo info;
                Check(Native.CreateProcessW(Image, Command("sleep"), IntPtr.Zero, IntPtr.Zero, true, 0x80000 | 0x08000000, IntPtr.Zero, DirectoryPath, ref startup, out info), "DESCENDANT_CREATE");
                using (Handle process = new Handle(info.Process))
                using (Handle thread = new Handle(info.Thread)) { }
            }
        }
        private static int Child(string mode)
        {
            bool inJob;
            if (!Native.IsProcessInJob(Native.GetCurrentProcess(), IntPtr.Zero, out inJob) || !inJob) return 91;
            if (!Tokens.Inspect(Native.GetCurrentProcess()).EffectiveStandard) return 92;
            Console.Out.NewLine = "\n"; Console.Error.NewLine = "\n";
            if (mode == "normal") { Console.WriteLine("OUT"); Console.Error.WriteLine("ERR"); return 0; }
            if (mode == "nonzero") return 17;
            if (mode == "flood-out" || mode == "flood-err")
            {
                TextWriter writer = mode == "flood-out" ? Console.Out : Console.Error;
                string data = new string('x', 1024);
                for (int i = 0; i < 1024; ++i) writer.Write(data);
                writer.Flush(); return 0;
            }
            if (mode == "timeout-tree" || mode == "cancel-tree" || mode == "leave-tree")
            { Descendant(); Console.WriteLine("READY"); Console.Out.Flush(); if (mode == "leave-tree") return 0; }
            else if (mode == "sleep") { Console.WriteLine("LEAF"); Console.Out.Flush(); }
            else return 93;
            // A second independent ceiling even if the supervisor malfunctions.
            Thread.Sleep(15000); return 94;
        }
        private static int Main(string[] args)
        {
            try
            {
                if (IntPtr.Size != 8) throw new Failure("X64_REQUIRED", 0);
                if (args.Length == 2 && args[0] == "--child") return Child(args[1]);
                if (args.Length != 1 || args[0] != "--suite") throw new Failure("FIXED_SUITE_REQUIRED", 0);
                if (!Tokens.Inspect(Native.GetCurrentProcess()).EffectiveStandard) throw new Failure("PARENT_PRIVILEGE_POLICY", 0);
                Result[] results = {
                    Run("SN-001", "normal", "Completed", false, false, false),
                    Run("SN-002", "normal", "Completed", true, false, false),
                    Run("SN-003", "timeout-tree", "Timeout", true, false, false),
                    Run("SN-004", "cancel-tree", "Cancelled", true, false, false),
                    Run("SN-005", "flood-out", "StdoutLimit", true, false, false),
                    Run("SN-006", "flood-err", "StderrLimit", true, false, false),
                    Run("SN-007", "nonzero", "NonZeroExit", true, false, false),
                    Run("SN-008", "leave-tree", "DescendantsAfterParentExit", true, false, false),
                    Run("SN-009", "normal", "CancelledBeforeCreate", true, true, false),
                    Run("SN-010", "normal", "InjectedBeforeResume", true, false, true)
                };
                bool passed = true;
                StringBuilder json = new StringBuilder("{\"stage\":\"BACKEND-NATIVE-SYNTHETIC1\",\"production_ready\":false,\"velociraptor_executed\":false,\"cases\":[");
                for (int i = 0; i < results.Length; ++i) { if (i > 0) json.Append(','); json.Append(results[i].Json()); passed &= results[i].Passed; }
                Console.WriteLine(json.Append("]}").ToString());
                return passed ? 0 : 1;
            }
            catch (Failure failure)
            { Console.WriteLine("{\"stage\":\"BACKEND-NATIVE-SYNTHETIC1\",\"error\":\"" + failure.Code + "\",\"native_error\":" + failure.NativeError + "}"); return 2; }
            catch { Console.WriteLine("{\"stage\":\"BACKEND-NATIVE-SYNTHETIC1\",\"error\":\"INTERNAL_ERROR\"}"); return 2; }
        }
    }
}
