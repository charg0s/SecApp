// Explicitly authorized, self-only lab. NOT an adapter or authenticated boundary.
// Reuses unchanged historical handle/Job/pipe/token helpers, never its old suite.
// No ACL writes, reparse probes, process injection, arbitrary executable or PID CLI.
using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using SecApp.SyntheticLaunch;

namespace SecApp.NativeBoundary
{
    internal static class Api
    {
        [DllImport("kernel32.dll", SetLastError=true)] internal static extern bool WriteFile(Handle h, byte[] b, uint n, out uint written, IntPtr ov);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] internal static extern bool QueryFullProcessImageNameW(Handle h, uint flags, StringBuilder name, ref uint size);
        [DllImport("kernel32.dll", SetLastError=true)] internal static extern Handle OpenProcess(uint rights, bool inherit, uint pid);
        [DllImport("kernel32.dll", SetLastError=true)] internal static extern bool GetProcessTimes(Handle h, out long created, out long exited, out long kernel, out long user);
        [DllImport("kernel32.dll", SetLastError=true)] internal static extern bool SetProcessMitigationPolicy(int policy, ref uint flags, UIntPtr size);
        [DllImport("kernel32.dll", SetLastError=true)] internal static extern bool GetProcessMitigationPolicy(IntPtr h, int policy, out uint flags, UIntPtr size);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] internal static extern IntPtr LoadLibraryExW(string file, IntPtr reserved, uint flags);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] internal static extern uint GetModuleFileNameW(IntPtr module, StringBuilder name, uint size);
        [DllImport("kernel32.dll", SetLastError=true)] internal static extern bool FreeLibrary(IntPtr module);
        [DllImport("kernel32.dll", EntryPoint="TerminateProcess", SetLastError=true)] internal static extern bool KillSelf(IntPtr h, uint code);
    }

    internal sealed class Child : IDisposable
    {
        private readonly Handles owned = new Handles();
        internal Handle Process, Job, Input;
        private Handle thread;
        internal PipeBuffer Output, Error;
        internal uint Pid;
        internal bool Resumed;
        internal Child(string mode)
        {
            try
            {
                Job=owned.Own(Native.CreateJobObjectW(IntPtr.Zero,null));
                Entry.Check(!Job.IsInvalid,"JOB_CREATE");
                ExtendedLimits limits=new ExtendedLimits();
                limits.Basic.Flags=0x2000|8; limits.Basic.ActiveProcesses=4;
                Entry.Check(Native.SetInformationJobObject(Job,9,ref limits,(uint)Marshal.SizeOf(typeof(ExtendedLimits))),"JOB_LIMITS");
                Handle ir,iw,orr,ow,er,ew;
                Pipe(false,out ir,out iw); Pipe(true,out orr,out ow); Pipe(true,out er,out ew);
                Input=iw; Output=new PipeBuffer(orr); Error=new PipeBuffer(er);
                using(Attributes attrs=new Attributes(new IntPtr[]{ir.DangerousGetHandle(),ow.DangerousGetHandle(),ew.DangerousGetHandle()},Job))
                {
                    StartupInfoEx si=new StartupInfoEx();
                    si.Startup.Size=Marshal.SizeOf(typeof(StartupInfoEx)); si.Startup.Flags=0x100;
                    si.Startup.Input=ir.DangerousGetHandle(); si.Startup.Output=ow.DangerousGetHandle(); si.Startup.Error=ew.DangerousGetHandle(); si.Attributes=attrs.Pointer;
                    string root=Environment.GetEnvironmentVariable("SystemRoot");
                    Entry.Check(!String.IsNullOrEmpty(root)&&Path.IsPathRooted(root),"SYSTEM_ROOT");
                    IntPtr env=Marshal.StringToHGlobalUni("SystemRoot="+root+"\0TEMP="+Entry.Root+"\0TMP="+Entry.Root+"\0WINDIR="+root+"\0\0");
                    ProcessInfo pi;
                    try { Entry.Check(Native.CreateProcessW(Entry.Image,new StringBuilder("\""+Entry.Image+"\" --worker "+mode),IntPtr.Zero,IntPtr.Zero,true,0x4|0x400|0x80000|0x08000000,env,Entry.Root,ref si,out pi),"CREATE"); }
                    finally { Marshal.FreeHGlobal(env); }
                    Process=owned.Own(new Handle(pi.Process)); thread=owned.Own(new Handle(pi.Thread)); Pid=pi.Pid;
                }
                ir.Dispose(); ow.Dispose(); ew.Dispose();
                bool member;
                Entry.Check(Native.IsProcessInJob(Process.DangerousGetHandle(),Job.DangerousGetHandle(),out member)&&member,"JOB_MEMBER");
                Entry.Check(Tokens.Inspect(Process.DangerousGetHandle()).EffectiveStandard,"CHILD_NOT_STANDARD");
            }
            catch { Dispose(); throw; }
        }
        private void Pipe(bool reads,out Handle r,out Handle w)
        {
            SecurityAttributes sa=new SecurityAttributes{Length=Marshal.SizeOf(typeof(SecurityAttributes)),Inherit=true};
            Entry.Check(Native.CreatePipe(out r,out w,ref sa,4096),"PIPE_CREATE"); owned.Own(r); owned.Own(w);
            Entry.Check(Native.SetHandleInformation(reads?r:w,1,0),"PIPE_INHERIT");
        }
        internal void Resume() { Entry.Check(!Resumed && Native.ResumeThread(thread)==1,"RESUME"); Resumed=true; }
        internal void Send(string frame)
        {
            byte[] bytes=Encoding.ASCII.GetBytes(frame+"\n"); uint n;
            Entry.Check(bytes.Length<=256,"FRAME_BOUND");
            Entry.Check(Api.WriteFile(Input,bytes,(uint)bytes.Length,out n,IntPtr.Zero)&&n==bytes.Length,"PIPE_WRITE");
        }
        internal void Drain() { Output.Drain(); Error.Drain(); Entry.Check(!Output.Exceeded&&!Error.Exceeded,"OUTPUT_BOUND"); }
        internal string FirstLine()
        {
            Stopwatch sw=Stopwatch.StartNew();
            while(sw.ElapsedMilliseconds<5000)
            {
                Drain(); int end=Output.Text.IndexOf('\n');
                if(end>=0) return Output.Text.Substring(0,end);
                Entry.Check(!Output.Closed,"EARLY_PIPE_CLOSE"); Thread.Sleep(5);
            }
            throw new Failure("FRAME_TIMEOUT",0);
        }
        internal uint Active()
        {
            Accounting a; uint n;
            Entry.Check(Native.QueryInformationJobObject(Job,1,out a,(uint)Marshal.SizeOf(typeof(Accounting)),out n),"JOB_QUERY");
            return a.ActiveProcesses;
        }
        internal void Finish(uint expected)
        {
            Stopwatch sw=Stopwatch.StartNew();
            while(sw.ElapsedMilliseconds<5000)
            {
                Drain();
                if(Native.WaitForSingleObject(Process,0)==0 && Active()==0 && Output.Closed && Error.Closed)
                {
                    uint code; Entry.Check(Native.GetExitCodeProcess(Process,out code),"EXIT_QUERY");
                    Entry.Check(code==expected&&Error.Text=="","CHILD_RESULT"); return;
                }
                Thread.Sleep(5);
            }
            throw new Failure("FINISH_TIMEOUT",0);
        }
        public void Dispose()
        {
            try
            {
                if(Process!=null)
                {
                    Native.TerminateJobObject(Job,125);
                    if(Native.WaitForSingleObject(Process,0)!=0) Native.TerminateProcess(Process,125);
                    Stopwatch sw=Stopwatch.StartNew();
                    while(sw.ElapsedMilliseconds<3000)
                    {
                        Drain();
                        if(Native.WaitForSingleObject(Process,0)==0&&Active()==0&&Output.Closed&&Error.Closed) return;
                        Thread.Sleep(5);
                    }
                    throw new Failure("CLEANUP_FAILED",0);
                }
            }
            finally { owned.Dispose(); }
        }
    }

    internal static class Entry
    {
        internal static string Image { get { return typeof(Entry).Assembly.Location; } }
        internal static string Root { get { return Path.GetDirectoryName(Image); } }
        internal static void Check(bool ok,string code) { if(!ok) throw Failure.Last(code); }
        private static string Name(Handle h)
        {
            StringBuilder text=new StringBuilder(32768); uint n=32768;
            Check(Api.QueryFullProcessImageNameW(h,0,text,ref n)&&n>0&&n<32768,"IMAGE_QUERY"); return text.ToString();
        }
        private static long Created(Handle h)
        {
            long c,e,k,u; Check(Api.GetProcessTimes(h,out c,out e,out k,out u),"CREATION_QUERY"); return c;
        }
        private static string Hash(Stream stream)
        { using(SHA256 sha=SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(stream)); }
        private static string ReadFrame()
        {
            // Bounded byte-at-a-time read from our sole inherited input; worker watchdog bounds blocking.
            using(Handle input=new Handle(Native.GetStdHandle(-10)))
            {
                StringBuilder s=new StringBuilder(); byte[] b=new byte[1];
                while(s.Length<256)
                {
                    uint n; Check(Native.ReadFile(input,b,1,out n,IntPtr.Zero)&&n==1,"FRAME_READ");
                    if(b[0]==10) return s.ToString();
                    Check(b[0]>=32&&b[0]<=126,"FRAME_ASCII"); s.Append((char)b[0]);
                }
                throw new Failure("FRAME_OVERSIZE",0);
            }
        }
        private static void Say(string value) { Console.WriteLine(value); Console.Out.Flush(); }
        private static bool Same(string a,string b) { return String.Equals(a,b,StringComparison.OrdinalIgnoreCase); }
        private static int Dll(string mode)
        {
            string fixture=Path.Combine(Root,"SyntheticFixture.dll");
            if(mode!="dll-control")
            {
                int type=mode=="dll-prefer"?10:8; uint flags=mode=="dll-prefer"?4u:1u, observed;
                Check(Api.SetProcessMitigationPolicy(type,ref flags,new UIntPtr(4)),"MITIGATION_SET");
                Check(Api.GetProcessMitigationPolicy(Native.GetCurrentProcess(),type,out observed,new UIntPtr(4))&&(observed&flags)==flags,"MITIGATION_QUERY");
            }
            // Only our locally built inert managed PE, with a fixed absolute name. No system DLL enumeration.
            IntPtr module=Api.LoadLibraryExW(fixture,IntPtr.Zero,0); int error=Marshal.GetLastWin32Error();
            if(module==IntPtr.Zero)
            {
                Check(mode=="dll-signature"&&error==577,"UNEXPECTED_LOAD_FAILURE"); Say("SIGNATURE_BLOCKED"); return 0;
            }
            try
            {
                StringBuilder name=new StringBuilder(32768); uint n=Api.GetModuleFileNameW(module,name,32768);
                Check(n>0&&n<32768&&Same(name.ToString(),fixture),"FIXTURE_IDENTITY");
                Say(mode=="dll-signature"?"SIGNATURE_MAPPING_ALLOWED":"FIXTURE_MAPPED"); return 0;
            }
            finally { Check(Api.FreeLibrary(module),"FIXTURE_UNLOAD"); }
        }
        private static int Worker(string mode)
        {
            bool member; Check(Native.IsProcessInJob(Native.GetCurrentProcess(),IntPtr.Zero,out member)&&member,"WORKER_JOB");
            Check(Tokens.Inspect(Native.GetCurrentProcess()).EffectiveStandard,"WORKER_NOT_STANDARD");
            using(Timer ceiling=new Timer(delegate { Api.KillSelf(Native.GetCurrentProcess(),124); },null,20000,Timeout.Infinite))
            {
                if(mode=="idle") { Say("READY"); Check(ReadFrame()=="STOP","STOP_FRAME"); return 0; }
                if(mode=="dll-control"||mode=="dll-prefer"||mode=="dll-signature") return Dll(mode);
                if(mode=="echo"||mode=="echo-wrong"||mode=="echo-replay")
                {
                    string s=ReadFrame(); Check(s.Length==32&&IsHex(s),"CHALLENGE_FORMAT");
                    if(mode=="echo-wrong") s=(s[0]=='0'?"1":"0")+s.Substring(1);
                    Say("ACK:"+s); if(mode=="echo-replay") Say("ACK:"+s); return 0;
                }
                if(mode=="peer")
                {
                    string[] parts=ReadFrame().Split(':'); uint pid; long stamp;
                    Check(parts.Length==2,"PEER_FRAME");
                    Check(UInt32.TryParse(parts[0],NumberStyles.None,CultureInfo.InvariantCulture,out pid)&&pid>0,"PEER_PID");
                    Check(Int64.TryParse(parts[1],NumberStyles.None,CultureInfo.InvariantCulture,out stamp)&&stamp>0,"PEER_STAMP");
                    // Internal parent pipe supplies only its still-live owned child's identity, never CLI input.
                    using(Handle inspect=Api.OpenProcess(0x1000|0x100000,false,pid))
                    {
                        Check(!inspect.IsInvalid&&Created(inspect)==stamp&&Same(Name(inspect),Image)&&Native.WaitForSingleObject(inspect,0)==258,"PEER_IDENTITY");
                        // Test access acquisition only. NEVER read/write remote memory, inject or duplicate a handle.
                        using(Handle access=Api.OpenProcess(0x2|0x8|0x20|0x40,false,pid))
                        {
                            int error=Marshal.GetLastWin32Error();
                            if(access.IsInvalid) { Check(error==5,"PEER_OPEN_ERROR"); Say("PEER_RIGHTS_DENIED"); }
                            else Say("PEER_RIGHTS_GRANTED");
                        }
                    }
                    return 0;
                }
                if(mode=="crash-supervisor")
                {
                    using(Child leaf=new Child("idle"))
                    {
                        leaf.Resume(); Check(leaf.FirstLine()=="READY","LEAF_READY");
                        Say("LEAF:"+leaf.Pid.ToString(CultureInfo.InvariantCulture)+":"+Created(leaf.Process).ToString(CultureInfo.InvariantCulture));
                        Check(ReadFrame()=="CRASH","CRASH_FRAME");
                        // Abrupt exit without finally/Dispose and without WER/FailFast dumps.
                        Check(Api.KillSelf(Native.GetCurrentProcess(),23),"SELF_TERMINATION"); return 95;
                    }
                }
                throw new Failure("FIXED_WORKER_REQUIRED",0);
            }
        }
        private static bool IsHex(string s) { foreach(char c in s) if(!((c>='0'&&c<='9')||(c>='a'&&c<='f'))) return false; return true; }
        private static string Nonce()
        {
            byte[] b=new byte[16]; using(RandomNumberGenerator rng=RandomNumberGenerator.Create()) rng.GetBytes(b);
            return BitConverter.ToString(b).Replace("-","").ToLowerInvariant();
        }
        private static bool Accept(string frame,string nonce,ref bool used)
        { if(used||frame!="ACK:"+nonce) return false; used=true; return true; }
        private static string Run(string id)
        {
            if(id=="NB-001")
            {
                using(FileStream held=new FileStream(Image,FileMode.Open,FileAccess.Read,FileShare.Read))
                {
                    string digest=Hash(held);
                    using(Child c=new Child("idle"))
                    {
                        Check(Same(Name(c.Process),Image),"IMAGE_NAME");
                        using(FileStream reopened=new FileStream(Name(c.Process),FileMode.Open,FileAccess.Read,FileShare.Read)) Check(Hash(reopened)==digest,"IMAGE_HASH");
                        bool denied=false;
                        try { using(FileStream writer=new FileStream(Image,FileMode.Open,FileAccess.Write,FileShare.ReadWrite|FileShare.Delete)) { } }
                        catch(IOException ex) { int code=ex.HResult&65535; Check(code==32||code==33,"WRITER_DENIAL_KIND"); denied=true; }
                        Check(denied,"WRITER_NOT_DENIED"); c.Resume(); Check(c.FirstLine()=="READY","READY"); c.Send("STOP"); c.Finish(0);
                    }
                }
                return "NameHashAgreeWriterDenied_NotMappedByteProof";
            }
            if(id=="NB-002"||id=="NB-003"||id=="NB-004")
            {
                string mode=id=="NB-002"?"dll-control":id=="NB-003"?"dll-prefer":"dll-signature";
                using(Child c=new Child(mode))
                {
                    c.Resume(); string line=c.FirstLine(); c.Finish(0);
                    if(id!="NB-004") { Check(line=="FIXTURE_MAPPED","MAPPING_CONTROL"); return id=="NB-002"?"InertManagedDllMapped":"PreferSystem32DidNotBlockExplicitLocalMapping"; }
                    Check(line=="SIGNATURE_BLOCKED"||line=="SIGNATURE_MAPPING_ALLOWED","SIGNATURE_OBSERVATION");
                    return line=="SIGNATURE_BLOCKED"?"MicrosoftOnlyBlockedFixtureAfterStartup":"MicrosoftOnlyAllowedFixtureMappingAfterStartup";
                }
            }
            if(id=="NB-005")
            {
                string outcome;
                using(Child victim=new Child("idle"))
                {
                    victim.Resume(); Check(victim.FirstLine()=="READY","VICTIM_READY");
                    using(Child peer=new Child("peer"))
                    {
                        peer.Resume(); peer.Send(victim.Pid.ToString(CultureInfo.InvariantCulture)+":"+Created(victim.Process).ToString(CultureInfo.InvariantCulture));
                        string line=peer.FirstLine(); peer.Finish(0);
                        Check(line=="PEER_RIGHTS_GRANTED"||line=="PEER_RIGHTS_DENIED","PEER_OBSERVATION");
                        outcome=line=="PEER_RIGHTS_GRANTED"?"SameUserPeerDangerousRightsGranted_NoInjection":"SameUserPeerRequestedRightsDenied";
                    }
                    victim.Send("STOP"); victim.Finish(0);
                }
                return outcome;
            }
            if(id=="NB-006")
            {
                foreach(string mode in new string[]{"echo","echo-wrong","echo-replay"})
                {
                    using(Child c=new Child(mode))
                    {
                        string nonce=Nonce(); c.Resume(); c.Send(nonce); c.FirstLine(); c.Finish(0);
                        string[] frames=c.Output.Text.Split('\n'); bool used=false;
                        Check(frames.Length==(mode=="echo-replay"?3:2)&&frames[frames.Length-1]=="","FRAME_COUNT");
                        if(mode=="echo-wrong") Check(!Accept(frames[0],nonce,ref used)&&!used,"WRONG_CHALLENGE");
                        else
                        {
                            Check(Accept(frames[0],nonce,ref used),"VALID_CHALLENGE");
                            if(mode=="echo-replay") Check(!Accept(frames[1],nonce,ref used),"REPLAY_RULE");
                        }
                    }
                }
                return "BoundedPipeRoundTripReplayDenied_NotPeerAuthentication";
            }
            if(id=="NB-007")
            {
                using(Child supervisor=new Child("crash-supervisor"))
                {
                    supervisor.Resume(); string[] parts=supervisor.FirstLine().Split(':'); uint pid; long stamp;
                    Check(parts.Length==3&&parts[0]=="LEAF","LEAF_FRAME");
                    Check(UInt32.TryParse(parts[1],NumberStyles.None,CultureInfo.InvariantCulture,out pid),"LEAF_PID");
                    Check(Int64.TryParse(parts[2],NumberStyles.None,CultureInfo.InvariantCulture,out stamp),"LEAF_STAMP");
                    using(Handle leaf=Api.OpenProcess(0x1000|0x100000,false,pid))
                    {
                        Check(!leaf.IsInvalid&&Created(leaf)==stamp&&Same(Name(leaf),Image)&&Native.WaitForSingleObject(leaf,0)==258,"LEAF_IDENTITY");
                        bool member; Check(Native.IsProcessInJob(leaf.DangerousGetHandle(),supervisor.Job.DangerousGetHandle(),out member)&&member,"LEAF_CONTAINMENT");
                        supervisor.Send("CRASH"); supervisor.Finish(23);
                        Check(Native.WaitForSingleObject(leaf,0)==0,"LEAF_SURVIVED");
                    }
                }
                return "AbruptSupervisorExitReapedObservedLeaf_NotLeaseAtomicity";
            }
            throw new Failure("FIXED_CASE_REQUIRED",0);
        }
        private static int Main(string[] args)
        {
            Console.Out.NewLine="\n"; Console.Error.NewLine="\n";
            try
            {
                Check(IntPtr.Size==8,"X64_REQUIRED");
                if(args.Length==2&&args[0]=="--worker") return Worker(args[1]);
                Check(args.Length==1&&args[0]=="--suite","FIXED_SUITE_REQUIRED");
                Check(Tokens.Inspect(Native.GetCurrentProcess()).EffectiveStandard,"PARENT_NOT_STANDARD");
                StringBuilder json=new StringBuilder("{\"stage\":\"NATIVE-BOUNDARY-EXPERIMENT1\",\"production_ready\":false,\"velociraptor_executed\":false,\"cases\":[");
                bool complete=true;
                for(int i=1;i<=7;i++)
                {
                    string id="NB-"+i.ToString("D3",CultureInfo.InvariantCulture); string observation="None",error="None"; int nativeError=0;
                    try { observation=Run(id); }
                    catch(Failure ex) { error=ex.Code; nativeError=ex.NativeError; complete=false; }
                    catch { error="INTERNAL_ERROR"; complete=false; }
                    if(i>1) json.Append(',');
                    json.Append("{\"id\":\"").Append(id).Append("\",\"status\":\"").Append(error=="None"?"Observed":"Failed").Append("\",\"observation\":\"").Append(observation).Append("\",\"error\":\"").Append(error).Append("\",\"native_error\":").Append(nativeError).Append('}');
                    // Stop after the first failed invariant; do not perform further host experiments.
                    if(!complete) break;
                }
                Console.WriteLine(json.Append("]}").ToString()); return complete?0:1;
            }
            catch(Failure ex) { Console.WriteLine("{\"error\":\""+ex.Code+"\",\"native_error\":"+ex.NativeError+"}"); return 2; }
            catch { Console.WriteLine("{\"error\":\"INTERNAL_ERROR\"}"); return 2; }
        }
    }
}
