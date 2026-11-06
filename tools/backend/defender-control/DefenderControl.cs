// One explicitly confirmed elevated control operation; NOT a general launcher.
// Trusted Windows/user session required. No service, token rewriting or ACL writes.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using Microsoft.Win32.SafeHandles;
using SecApp.ControlWorkspace;

namespace SecApp.DefenderControl
{
    internal sealed class Failure : Exception
    {
        internal readonly string Code;
        internal Failure(string code) { Code = code; }
    }
    internal sealed class Handle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private Handle() : base(true) { }
        internal Handle(IntPtr value) : base(true) { SetHandle(value); }
        protected override bool ReleaseHandle() { return Native.CloseHandle(handle); }
    }
    internal sealed class Owned : IDisposable
    {
        private readonly List<IDisposable> values = new List<IDisposable>();
        internal T Add<T>(T value) where T : IDisposable { values.Add(value); return value; }
        public void Dispose() { for (int i = values.Count - 1; i >= 0; --i) values[i].Dispose(); }
    }
    [StructLayout(LayoutKind.Sequential)] internal struct SecurityAttributes
    { internal int Length; internal IntPtr Descriptor; [MarshalAs(UnmanagedType.Bool)] internal bool Inherit; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] internal struct StartupInfo
    {
        internal int Size; internal string Reserved, Desktop, Title;
        internal uint X, Y, XSize, YSize, XCount, YCount, Fill, Flags;
        internal short Show, ReservedBytes; internal IntPtr Reserved2, Input, Output, Error;
    }
    [StructLayout(LayoutKind.Sequential)] internal struct StartupInfoEx
    { internal StartupInfo Startup; internal IntPtr Attributes; }
    [StructLayout(LayoutKind.Sequential)] internal struct ProcessInfo
    { internal IntPtr Process, Thread; internal uint Pid, Tid; }
    [StructLayout(LayoutKind.Sequential)] internal struct BasicLimits
    {
        internal long ProcessTime, JobTime; internal uint Flags;
        internal UIntPtr MinimumWorkingSet, MaximumWorkingSet;
        internal uint ActiveProcesses; internal UIntPtr Affinity; internal uint Priority, Scheduling;
    }
    [StructLayout(LayoutKind.Sequential)] internal struct IoCounters { internal ulong A, B, C, D, E, F; }
    [StructLayout(LayoutKind.Sequential)] internal struct ExtendedLimits
    {
        internal BasicLimits Basic; internal IoCounters Io;
        internal UIntPtr ProcessMemory, JobMemory, PeakProcessMemory, PeakJobMemory;
    }
    [StructLayout(LayoutKind.Sequential)] internal struct Accounting
    {
        internal long UserTime, KernelTime, PeriodUserTime, PeriodKernelTime;
        internal uint PageFaults, TotalProcesses, ActiveProcesses, TerminatedProcesses;
    }
    internal static class Native
    {
        [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32.dll")] internal static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool TerminateProcess(IntPtr process, uint code);
        [DllImport("kernel32.dll", SetLastError = true)] internal static extern Handle OpenProcess(uint access, bool inherit, uint pid);
        [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool GetProcessTimes(Handle process, out long created, out long exited, out long kernel, out long user);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] internal static extern uint GetWindowsDirectoryW(StringBuilder buffer, uint size);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] internal static extern Handle CreateFileW(string name, uint access, uint share, IntPtr attributes, uint disposition, uint flags, IntPtr template);
        [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool CreatePipe(out Handle read, out Handle write, ref SecurityAttributes attributes, uint size);
        [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool SetHandleInformation(Handle handle, uint mask, uint flags);
        [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool PeekNamedPipe(Handle pipe, IntPtr buffer, uint size, IntPtr read, out uint available, IntPtr remaining);
        [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool ReadFile(Handle file, byte[] bytes, uint size, out uint read, IntPtr overlapped);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] internal static extern Handle CreateJobObjectW(IntPtr attributes, string name);
        [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool SetInformationJobObject(Handle job, int type, ref ExtendedLimits limits, uint size);
        [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool QueryInformationJobObject(Handle job, int type, out Accounting info, uint size, out uint returned);
        [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool IsProcessInJob(Handle process, Handle job, out bool inJob);
        [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool TerminateJobObject(Handle job, uint code);
        [DllImport("kernel32.dll", SetLastError = true)] internal static extern uint WaitForSingleObject(Handle handle, uint milliseconds);
        [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool GetExitCodeProcess(Handle process, out uint code);
        [DllImport("kernel32.dll", SetLastError = true)] internal static extern uint ResumeThread(Handle thread);
        [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, int flags, ref IntPtr size);
        [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, IntPtr attribute, IntPtr value, UIntPtr size, IntPtr previous, IntPtr returned);
        [DllImport("kernel32.dll")] internal static extern void DeleteProcThreadAttributeList(IntPtr list);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] internal static extern bool CreateProcessW(string app, StringBuilder command, IntPtr processAttributes, IntPtr threadAttributes, bool inherit, uint flags, IntPtr environment, string directory, ref StartupInfoEx startup, out ProcessInfo info);
        [DllImport("advapi32.dll", SetLastError = true)] internal static extern bool OpenProcessToken(IntPtr process, uint access, out Handle token);
        [DllImport("advapi32.dll", SetLastError = true)] internal static extern bool GetTokenInformation(Handle token, int type, IntPtr buffer, uint size, out uint returned);
    }
    internal sealed class Attributes : IDisposable
    {
        internal IntPtr Pointer; private bool initialized;
        private readonly List<IntPtr> storage = new List<IntPtr>();
        internal Attributes(IntPtr[] handles, Handle job)
        {
            try
            {
                IntPtr size = IntPtr.Zero;
                Native.InitializeProcThreadAttributeList(IntPtr.Zero, 2, 0, ref size);
                Program.Require(size.ToInt64() > 0 && size.ToInt64() <= 65536, "ATTRIBUTE_SIZE");
                Pointer = Marshal.AllocHGlobal(size);
                Program.Require(Native.InitializeProcThreadAttributeList(Pointer, 2, 0, ref size), "ATTRIBUTE_INIT");
                initialized = true;
                Add(0x20002, handles);
                Add(0x2000d, new IntPtr[] { job.DangerousGetHandle() });
            }
            catch { Dispose(); throw; }
        }
        private void Add(int attribute, IntPtr[] values)
        {
            int bytes = checked(values.Length * IntPtr.Size);
            IntPtr memory = Marshal.AllocHGlobal(bytes); storage.Add(memory);
            Marshal.Copy(values, 0, memory, values.Length);
            Program.Require(Native.UpdateProcThreadAttribute(Pointer, 0, new IntPtr(attribute), memory, new UIntPtr((uint)bytes), IntPtr.Zero, IntPtr.Zero), "ATTRIBUTE_UPDATE");
        }
        public void Dispose()
        {
            if (initialized) { Native.DeleteProcThreadAttributeList(Pointer); initialized = false; }
            foreach (IntPtr memory in storage) Marshal.FreeHGlobal(memory);
            storage.Clear();
            if (Pointer != IntPtr.Zero) { Marshal.FreeHGlobal(Pointer); Pointer = IntPtr.Zero; }
        }
    }
    internal sealed class Identity
    {
        internal string Sid; internal int Session; internal bool Elevated;
        private static IntPtr Query(Handle token, int type)
        {
            uint size;
            Native.GetTokenInformation(token, type, IntPtr.Zero, 0, out size);
            Program.Require(size > 0 && size <= 65536, "IDENTITY_SIZE");
            IntPtr memory = Marshal.AllocHGlobal(checked((int)size));
            if (!Native.GetTokenInformation(token, type, memory, size, out size))
            { Marshal.FreeHGlobal(memory); throw new Failure("IDENTITY_QUERY"); }
            return memory;
        }
        internal static Identity Read(IntPtr process)
        {
            Handle token;
            Program.Require(Native.OpenProcessToken(process, 8, out token), "IDENTITY_OPEN");
            using (token)
            {
                Identity value = new Identity();
                IntPtr memory = Query(token, 1);
                try { value.Sid = new SecurityIdentifier(Marshal.ReadIntPtr(memory)).Value; }
                finally { Marshal.FreeHGlobal(memory); }
                memory = Query(token, 12);
                try { value.Session = Marshal.ReadInt32(memory); } finally { Marshal.FreeHGlobal(memory); }
                memory = Query(token, 20);
                try { value.Elevated = Marshal.ReadInt32(memory) != 0; } finally { Marshal.FreeHGlobal(memory); }
                return value;
            }
        }
    }
    internal static class PrivateFiles
    {
        private static bool Trusted(string sid, string user)
        { return sid == user || sid == "S-1-5-18" || sid == "S-1-5-32-544"; }
        internal static void CheckAcl(FileSystemSecurity security, string user)
        {
            byte[] bytes = security.GetSecurityDescriptorBinaryForm();
            RawSecurityDescriptor descriptor = new RawSecurityDescriptor(bytes, 0);
            Program.Require(descriptor.DiscretionaryAcl != null && descriptor.Owner != null
                && Trusted(descriptor.Owner.Value, user), "PRIVATE_OWNER_OR_DACL");
            // Conservative allowlist; unknown sharing fails without repairing permissions.
            foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            {
                if (rule.AccessControlType == AccessControlType.Allow
                    && (rule.PropagationFlags & PropagationFlags.InheritOnly) == 0)
                    Program.Require(Trusted(rule.IdentityReference.Value, user), "PRIVATE_ACCESS");
            }
        }
        internal static void NoReparse(string path)
        {
            string full = Path.GetFullPath(path);
            Program.Require(full.Length < 240 && full.Length >= 3 && full[1] == ':'
                && full[2] == '\\' && full.IndexOf(':', 2) == -1, "LOCAL_PATH");
            string current = full;
            while (current != null)
            {
                Program.Require((File.GetAttributes(current) & FileAttributes.ReparsePoint) == 0, "REPARSE_PATH");
                current = Path.GetDirectoryName(current);
                if (current == "") break;
            }
            Program.Require(new DriveInfo(Path.GetPathRoot(full)).DriveType == DriveType.Fixed, "LOCAL_DRIVE");
        }
        internal static void DirectoryLock(Owned owned, string path, string user)
        {
            NoReparse(path);
            Program.Require(Directory.Exists(path), "DIRECTORY_REQUIRED");
            Handle locked = owned.Add(Native.CreateFileW(path, 0x20080, 3, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero));
            Program.Require(!locked.IsInvalid, "DIRECTORY_LOCK");
            CheckAcl(Directory.GetAccessControl(path, AccessControlSections.Owner | AccessControlSections.Access), user);
            NoReparse(path);
        }
        internal static FileStream ReadLocked(Owned owned, string path, string user)
        {
            NoReparse(path);
            FileStream file = owned.Add(new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read));
            CheckAcl(File.GetAccessControl(path, AccessControlSections.Owner | AccessControlSections.Access), user);
            NoReparse(path);
            return file;
        }
    }
    internal sealed class PipeBuffer
    {
        internal readonly Handle Pipe; internal readonly byte[] Bytes = new byte[4096];
        private readonly byte[] scratch = new byte[4096];
        private readonly bool stderr; internal int Length; internal bool Closed;
        internal PipeBuffer(Handle pipe, bool isError) { Pipe = pipe; stderr = isError; }
        internal void Drain()
        {
            if (Closed) return;
            // Alternate both streams each poll; neither can starve the deadline.
            uint available;
            if (!Native.PeekNamedPipe(Pipe, IntPtr.Zero, 0, IntPtr.Zero, out available, IntPtr.Zero))
            { if (Marshal.GetLastWin32Error() == 109) { Closed = true; return; } throw new Failure("PIPE_PEEK"); }
            if (available == 0) return;
            uint read;
            Program.Require(Native.ReadFile(Pipe, scratch, Math.Min(available, (uint)scratch.Length), out read, IntPtr.Zero), "PIPE_READ");
            Program.Require(!stderr || read == 0, "BACKEND_STDERR");
            Program.Require(read <= Bytes.Length - Length, "STDOUT_LIMIT");
            Buffer.BlockCopy(scratch, 0, Bytes, Length, checked((int)read)); Length += checked((int)read);
            Array.Clear(scratch, 0, scratch.Length);
        }
        internal void Clear() { Array.Clear(Bytes, 0, Bytes.Length); Array.Clear(scratch, 0, scratch.Length); Length = 0; }
    }
    internal sealed class Result
    {
        internal string RunId, Error = "NONE", Output = "";
        internal bool Created, Resumed, Exited, Empty, Pipes;
        internal uint? ExitCode; internal long Elapsed;
        internal bool Completed { get { return Error == "NONE" && Created && Resumed && Exited && Empty && Pipes && ExitCode == 0; } }
        private static string B(bool value) { return value ? "true" : "false"; }
        internal string Json()
        {
            return "{\"kind\":\"SecAppDefenderControlV1\",\"run_id\":\"" + RunId
                + "\",\"outcome\":\"" + (Completed ? "Completed" : "Failed") + "\",\"error\":\"" + Error
                + "\",\"backend_created\":" + B(Created) + ",\"backend_resumed\":" + B(Resumed)
                + ",\"backend_exit\":" + (ExitCode.HasValue ? ExitCode.Value.ToString(CultureInfo.InvariantCulture) : "null")
                + ",\"root_exited\":" + B(Exited) + ",\"job_empty\":" + B(Empty) + ",\"pipes_closed\":" + B(Pipes)
                + ",\"elapsed_ms\":" + Elapsed.ToString(CultureInfo.InvariantCulture)
                + ",\"stdout_base64\":\"" + (Completed ? Output : "") + "\"}\n";
        }
    }
    internal static class Program
    {
        internal const string BackendHash = "3d20a5a2d272e3eb2bccae4a80ebe469fc1a6f63eb4a8f8a586dbae356437d32";
        internal const long BackendSize = 73422840;
        internal const string Query = "SELECT AMRunningMode, RealTimeProtectionEnabled FROM wmi(query=\"SELECT AMRunningMode, RealTimeProtectionEnabled FROM MSFT_MpComputerStatus\", namespace=\"root/Microsoft/Windows/Defender\") LIMIT 2";
        internal static void Require(bool ok, string code) { if (!ok) throw new Failure(code); }
        private static string Quote(string value)
        {
            StringBuilder result = new StringBuilder("\""); int slashes = 0;
            foreach (char c in value)
            {
                if (c == '\\') { ++slashes; continue; }
                result.Append('\\', c == '"' ? slashes * 2 + 1 : slashes); slashes = 0; result.Append(c);
            }
            result.Append('\\', slashes * 2); return result.Append('"').ToString();
        }
        private static bool Exited(Handle process)
        {
            uint state = Native.WaitForSingleObject(process, 0);
            Require(state == 0 || state == 258, "PROCESS_WAIT"); return state == 0;
        }
        private static uint Active(Handle job)
        {
            Accounting info; uint returned;
            Require(Native.QueryInformationJobObject(job, 1, out info, (uint)Marshal.SizeOf(typeof(Accounting)), out returned), "JOB_QUERY");
            return info.ActiveProcesses;
        }
        private static void Pipe(Owned owned, bool parentReads, out Handle read, out Handle write)
        {
            SecurityAttributes attributes = new SecurityAttributes { Length = Marshal.SizeOf(typeof(SecurityAttributes)), Inherit = true };
            Require(Native.CreatePipe(out read, out write, ref attributes, 4096), "PIPE_CREATE");
            owned.Add(read); owned.Add(write);
            Require(Native.SetHandleInformation(parentReads ? read : write, 1, 0), "PIPE_INHERIT");
        }
        private static void CheckStop(Stopwatch watch, Handle parent, string directory)
        {
            Require(watch.ElapsedMilliseconds < 30000, "TIMEOUT");
            Require(!Exited(parent), "CONTROLLER_EXITED");
            Require(!File.Exists(Path.Combine(directory, "cancel.request")), "CANCELLED");
        }
        private static void Collect(Owned owned, Result result, string image, string directory, string windows, Identity self, Handle parent, Stopwatch watch)
        {
            Handle job = owned.Add(Native.CreateJobObjectW(IntPtr.Zero, null));
            Require(!job.IsInvalid, "JOB_CREATE");
            ExtendedLimits limits = new ExtendedLimits();
            limits.Basic.Flags = 0x2000 | 8 | 0x200; // kill-on-close, one process, job commit limit; no breakaway.
            limits.Basic.ActiveProcesses = 1; limits.JobMemory = new UIntPtr(536870912u);
            Require(Native.SetInformationJobObject(job, 9, ref limits, (uint)Marshal.SizeOf(typeof(ExtendedLimits))), "JOB_LIMITS");
            Handle process = null; PipeBuffer output = null, error = null;
            try
            {
                Handle inputRead, inputWrite, outputRead, outputWrite, errorRead, errorWrite;
                Pipe(owned, false, out inputRead, out inputWrite);
                Pipe(owned, true, out outputRead, out outputWrite);
                Pipe(owned, true, out errorRead, out errorWrite);
                inputWrite.Dispose(); // Child stdin is EOF, never an interactive prompt.
                output = new PipeBuffer(outputRead, false); error = new PipeBuffer(errorRead, true);
                using (Attributes attributes = new Attributes(new IntPtr[] { inputRead.DangerousGetHandle(), outputWrite.DangerousGetHandle(), errorWrite.DangerousGetHandle() }, job))
                {
                    StartupInfoEx startup = new StartupInfoEx();
                    startup.Startup.Size = Marshal.SizeOf(typeof(StartupInfoEx)); startup.Startup.Flags = 0x100;
                    startup.Startup.Input = inputRead.DangerousGetHandle(); startup.Startup.Output = outputWrite.DangerousGetHandle(); startup.Startup.Error = errorWrite.DangerousGetHandle();
                    startup.Attributes = attributes.Pointer;
                    IntPtr environment = Marshal.StringToHGlobalUni("SystemRoot=" + windows + "\0TEMP=" + directory + "\0TMP=" + directory + "\0WINDIR=" + windows + "\0\0");
                    ProcessInfo info;
                    try
                    {
                        CheckStop(watch, parent, directory);
                        StringBuilder command = new StringBuilder("velociraptor --config secapp-empty.config.yaml --nocolor query --format jsonl --timeout 15 " + Quote(Query));
                        Require(Native.CreateProcessW(image, command, IntPtr.Zero, IntPtr.Zero, true, 0x08080404, environment, directory, ref startup, out info), "PROCESS_CREATE");
                    }
                    finally { Marshal.FreeHGlobal(environment); }
                    process = owned.Add(new Handle(info.Process)); Handle thread = owned.Add(new Handle(info.Thread)); result.Created = true;
                    inputRead.Dispose(); outputWrite.Dispose(); errorWrite.Dispose();
                    bool inJob; Require(Native.IsProcessInJob(process, job, out inJob) && inJob, "JOB_MEMBERSHIP");
                    Identity child = Identity.Read(process.DangerousGetHandle());
                    Require(child.Elevated && child.Sid == self.Sid && child.Session == self.Session, "CHILD_IDENTITY");
                    CheckStop(watch, parent, directory);
                    Require(Native.ResumeThread(thread) == 1, "PROCESS_RESUME"); result.Resumed = true;
                }
                while (true)
                {
                    CheckStop(watch, parent, directory); output.Drain(); error.Drain();
                    result.Exited = Exited(process); result.Empty = Active(job) == 0;
                    result.Pipes = output.Closed && error.Closed;
                    if (result.Exited && result.Empty && result.Pipes) break;
                    Thread.Sleep(10);
                }
                uint code; Require(Native.GetExitCodeProcess(process, out code), "EXIT_QUERY"); result.ExitCode = code;
                Require(code == 0, "BACKEND_EXIT");
                result.Output = Convert.ToBase64String(output.Bytes, 0, output.Length);
            }
            catch (Failure failure) { result.Error = failure.Code; }
            catch { result.Error = "COLLECTION_ERROR"; }
            finally
            {
                if (process != null)
                {
                    try
                    {
                        if (!result.Exited || !result.Empty)
                        {
                            Require(Native.TerminateJobObject(job, 1), "JOB_TERMINATE");
                            Stopwatch grace = Stopwatch.StartNew();
                            do { result.Exited = Exited(process); result.Empty = Active(job) == 0; if (result.Exited && result.Empty) break; Thread.Sleep(10); }
                            while (grace.ElapsedMilliseconds < 3000);
                            Require(result.Exited && result.Empty, "CLEANUP_INCOMPLETE");
                        }
                    }
                    catch { result.Error = "CLEANUP_INCOMPLETE"; }
                }
                if (output != null) output.Clear(); if (error != null) error.Clear();
                // Closing the non-inherited Job is also the crash/last-resort kill boundary.
                job.Dispose();
            }
        }
        private static int Main(string[] args)
        {
            Stopwatch watch = Stopwatch.StartNew();
            using (ManualResetEvent finished = new ManualResetEvent(false))
            {
                // Self-only hard stop: ExitProcess can deadlock in DLL detach and
                // delay closure of the kill-on-close Job. No PID-based termination.
                Thread watchdog = new Thread(delegate() {
                    if (!finished.WaitOne(40000)) Native.TerminateProcess(Native.GetCurrentProcess(), 124);
                });
                watchdog.IsBackground = true; watchdog.Start();
                try
                {
                    Require(IntPtr.Size == 8 && args.Length == 6 && args[0] == "--run" && args[2] == "--parent" && args[4] == "--started", "ARGUMENTS");
                    Require(Regex.IsMatch(args[1], "\\A[0-9a-f]{32}\\z"), "RUN_ID");
                    uint parentId; long parentTime;
                    Require(UInt32.TryParse(args[3], NumberStyles.None, CultureInfo.InvariantCulture, out parentId) && parentId > 0, "PARENT_ID");
                    Require(Int64.TryParse(args[5], NumberStyles.None, CultureInfo.InvariantCulture, out parentTime) && parentTime > 0, "PARENT_TIME");
                    using (Owned owned = new Owned())
                    {
                        Handle parent = owned.Add(Native.OpenProcess(0x101000, false, parentId)); Require(!parent.IsInvalid, "PARENT_OPEN");
                        long created, exited, kernel, user;
                        Require(Native.GetProcessTimes(parent, out created, out exited, out kernel, out user) && created == parentTime, "PARENT_CHANGED");
                        Identity self = Identity.Read(Native.GetCurrentProcess()), caller = Identity.Read(parent.DangerousGetHandle());
                        Require(self.Elevated && !caller.Elevated && self.Sid == caller.Sid && self.Session == caller.Session && self.Session > 0, "CALLER_IDENTITY");
                        Require(!Exited(parent), "CONTROLLER_EXITED");
                        WorkspaceLease workspace = owned.Add(new WorkspaceLease(args[1], false));
                        string directory = workspace.DirectoryPath;
                        Require(String.Equals(Path.GetFullPath(typeof(Program).Assembly.Location), Path.Combine(directory, "SecAppDefenderControl.exe"), StringComparison.OrdinalIgnoreCase), "HELPER_LOCATION");
                        string image = Path.Combine(directory, "velociraptor.exe");
                        FileStream backend = PrivateFiles.ReadLocked(owned, image, self.Sid);
                        Require(backend.Length == BackendSize, "BACKEND_SIZE");
                        using (SHA256 sha = SHA256.Create()) Require(BitConverter.ToString(sha.ComputeHash(backend)).Replace("-", "").ToLowerInvariant() == BackendHash, "BACKEND_HASH");
                        CheckStop(watch, parent, directory);
                        // One fixed create-new config; retain a read-only handle while the backend runs.
                        string config = Path.Combine(directory, "secapp-empty.config.yaml");
                        using (FileStream file = new FileStream(config, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                        { byte[] bytes = Encoding.UTF8.GetBytes("{}\n"); file.Write(bytes, 0, bytes.Length); file.Flush(true); }
                        FileStream configLock = PrivateFiles.ReadLocked(owned, config, self.Sid);
                        Require(configLock.Length == 3 && configLock.ReadByte() == 123 && configLock.ReadByte() == 125 && configLock.ReadByte() == 10, "CONFIG_BYTES");
                        StringBuilder windows = new StringBuilder(260); uint count = Native.GetWindowsDirectoryW(windows, 260);
                        Require(count > 0 && count < 260, "WINDOWS_DIRECTORY"); PrivateFiles.NoReparse(windows.ToString());
                        Result result = new Result { RunId = args[1] };
                        Collect(owned, result, image, directory, windows.ToString(), self, parent, watch);
                        result.Elapsed = watch.ElapsedMilliseconds;
                        byte[] payload = Encoding.UTF8.GetBytes(result.Json()); Require(payload.Length <= 8192, "RESULT_LIMIT");
                        using (FileStream file = new FileStream(Path.Combine(directory, "result.json"), FileMode.CreateNew, FileAccess.Write, FileShare.None))
                        { file.Write(payload, 0, payload.Length); file.Flush(true); }
                        Array.Clear(payload, 0, payload.Length);
                        return result.Completed ? 0 : 1;
                    }
                }
                catch { return 1; } // No raw exception, SID, path, stderr or stack is logged.
                finally { finished.Set(); watchdog.Join(1000); }
            }
        }
    }
}
