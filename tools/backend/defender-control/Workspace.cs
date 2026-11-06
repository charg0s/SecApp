// Ordinary filesystem operations for the user-authorized NEW SecApp workspace.
// No setter for an existing ACL; no process/token/registry operations.
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;

namespace SecApp.ControlWorkspace
{
    [StructLayout(LayoutKind.Sequential)] internal struct Attributes
    { internal int Length; internal IntPtr Descriptor; [MarshalAs(UnmanagedType.Bool)] internal bool Inherit; }
    [StructLayout(LayoutKind.Sequential)] internal struct FileInfo
    {
        internal uint Attributes, CreatedLow, CreatedHigh, AccessLow, AccessHigh,
            WriteLow, WriteHigh, Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }
    internal static class Native
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] internal static extern bool CreateDirectoryW(string path, ref Attributes attributes);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] internal static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr attributes, uint disposition, uint flags, IntPtr template);
        [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInfo info);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] internal static extern uint GetFinalPathNameByHandleW(SafeFileHandle handle, StringBuilder path, uint size, uint flags);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] internal static extern bool GetVolumeInformationW(string root, StringBuilder name, uint nameSize, out uint serial, out uint componentLength, out uint flags, StringBuilder fileSystem, uint fileSystemSize);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] internal static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string text, uint revision, out IntPtr descriptor, out uint size);
        [DllImport("kernel32.dll")] internal static extern IntPtr LocalFree(IntPtr memory);
    }
    public sealed class DirectoryLease : IDisposable
    {
        private readonly List<SafeFileHandle> handles = new List<SafeFileHandle>();
        internal void Add(SafeFileHandle handle) { handles.Add(handle); }
        public void Dispose() { for (int i = handles.Count - 1; i >= 0; --i) handles[i].Dispose(); handles.Clear(); }
    }
    public sealed class WorkspaceLease : IDisposable
    {
        private readonly DirectoryLease parents, leaf;
        public string DirectoryPath { get; private set; }
        public WorkspaceLease(string runId, bool create)
        {
            FileSystem.Require(Regex.IsMatch(runId ?? "", "\\A[0-9a-f]{32}\\z"), "WORKSPACE_ID");
            // Fixed development location; no AppData/MSIX namespace redirection.
            const string root = @"C:\Dev";
            DirectoryPath = Path.Combine(root, "SecApp-Control-" + runId);
            parents = FileSystem.HoldDirectory(root);
            try
            {
                if (create) FileSystem.CreateNewPrivate(DirectoryPath);
                leaf = FileSystem.HoldDirectory(DirectoryPath);
                FileSystem.AssertPrivateDirectory(DirectoryPath);
                if (create) FileSystem.Require(Directory.GetFileSystemEntries(DirectoryPath).Length == 0, "WORKSPACE_NOT_EMPTY");
            }
            catch { Dispose(); throw; }
        }
        public void Dispose() { if (leaf != null) leaf.Dispose(); if (parents != null) parents.Dispose(); }
    }
    public static class FileSystem
    {
        internal static void Require(bool ok, string code) { if (!ok) throw new InvalidOperationException(code); }
        // Protect namespace without changing parent ACLs. Hold every ancestor
        // without FILE_SHARE_DELETE and verify the opened object's final path/type.
        public static DirectoryLease HoldDirectory(string directory)
        {
            string full = Path.GetFullPath(directory);
            Require(full.Length >= 3 && full.Length < 240 && full[1] == ':' && full[2] == '\\'
                && full.IndexOf(':', 2) == -1, "WORKSPACE_LOCAL_PATH");
            DriveInfo drive = new DriveInfo(Path.GetPathRoot(full));
            Require(drive.DriveType == DriveType.Fixed && drive.DriveFormat == "NTFS", "WORKSPACE_LOCAL_NTFS");
            uint serial, componentLength, flags;
            Require(Native.GetVolumeInformationW(Path.GetPathRoot(full), null, 0, out serial, out componentLength,
                out flags, null, 0) && (flags & 8) != 0, "WORKSPACE_PERSISTENT_ACLS");
            List<string> paths = new List<string>();
            for (string p = full; !String.IsNullOrEmpty(p); p = Path.GetDirectoryName(p)) paths.Add(p);
            paths.Reverse();
            DirectoryLease lease = new DirectoryLease();
            try
            {
                foreach (string p in paths)
                {
                    // LIST_DIRECTORY participates in sharing checks; attributes alone do not.
                    SafeFileHandle handle = Native.CreateFileW(p, 0x81, 3, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
                    lease.Add(handle); Require(!handle.IsInvalid, "WORKSPACE_NAMESPACE_LOCK");
                    FileInfo info;
                    Require(Native.GetFileInformationByHandle(handle, out info), "WORKSPACE_HANDLE_INFO");
                    Require((info.Attributes & 0x10) != 0 && (info.Attributes & 0x400) == 0, "WORKSPACE_REPARSE_OR_TYPE");
                    StringBuilder final = new StringBuilder(512);
                    uint length = Native.GetFinalPathNameByHandleW(handle, final, 512, 0);
                    Require(length > 0 && length < 512 && String.Equals(final.ToString().TrimEnd('\\'),
                        ("\\\\?\\" + p).TrimEnd('\\'), StringComparison.OrdinalIgnoreCase), "WORKSPACE_FINAL_PATH");
                }
                return lease;
            }
            catch { lease.Dispose(); throw; }
        }
        internal static void CreateNewPrivate(string path)
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                string user = identity.User.Value;
                string sddl = "O:" + user + "D:P(A;OICI;FA;;;" + user + ")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
                IntPtr descriptor; uint size;
                Require(Native.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, out descriptor, out size), "WORKSPACE_DESCRIPTOR");
                try
                {
                    Attributes attributes = new Attributes { Length = Marshal.SizeOf(typeof(Attributes)), Descriptor = descriptor, Inherit = false };
                    // Atomic create with final ACL. Existing name => failure, NEVER an ACL repair.
                    Require(Native.CreateDirectoryW(path, ref attributes), "WORKSPACE_CREATE_NEW");
                }
                finally { Native.LocalFree(descriptor); }
            }
        }
        public static void AssertPrivateDirectory(string path)
        {
            DirectorySecurity security = Directory.GetAccessControl(path, AccessControlSections.Owner | AccessControlSections.Access);
            Require(security.AreAccessRulesProtected, "WORKSPACE_INHERITANCE");
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                string user = identity.User.Value;
                Require(security.GetOwner(typeof(SecurityIdentifier)).Value == user, "WORKSPACE_OWNER");
                HashSet<string> expected = new HashSet<string>(new string[] { user, "S-1-5-18", "S-1-5-32-544" }, StringComparer.Ordinal);
                AuthorizationRuleCollection rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier));
                Require(rules.Count == 3, "WORKSPACE_ACL_COUNT");
                foreach (FileSystemAccessRule rule in rules)
                {
                    Require(!rule.IsInherited && rule.AccessControlType == AccessControlType.Allow
                        && rule.FileSystemRights == FileSystemRights.FullControl
                        && rule.InheritanceFlags == (InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit)
                        && rule.PropagationFlags == PropagationFlags.None
                        && expected.Remove(rule.IdentityReference.Value), "WORKSPACE_ACL");
                }
                Require(expected.Count == 0, "WORKSPACE_ACL");
            }
        }
    }
}
