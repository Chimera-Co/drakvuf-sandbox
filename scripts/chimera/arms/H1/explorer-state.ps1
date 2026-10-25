# Reports how explorer was started and what a process drakshell launches inherits from it.
# A clean snapshot has one explorer whose parent is winlogon.exe, and child_in_job=False with
# an empty child_dll_directory (see explorer-clean-restart.ps1).
Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices; using System.Text;
public static class ChimeraK {
  [DllImport("kernel32.dll")] public static extern bool IsProcessInJob(IntPtr p, IntPtr j, out bool r);
  [DllImport("kernel32.dll")] public static extern IntPtr GetCurrentProcess();
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode)] public static extern uint GetDllDirectory(uint n, StringBuilder b);
}
'@
$inJob = $false
[void][ChimeraK]::IsProcessInJob([ChimeraK]::GetCurrentProcess(), [IntPtr]::Zero, [ref]$inJob)
$dllDir = New-Object Text.StringBuilder 520
[void][ChimeraK]::GetDllDirectory(520, $dllDir)
$me = Get-CimInstance Win32_Process -Filter "ProcessId=$PID"
Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" | ForEach-Object {
    $parent = Get-CimInstance Win32_Process -Filter "ProcessId=$($_.ParentProcessId)"
    "explorer pid=$($_.ProcessId) cmd=$($_.CommandLine) parent=$($_.ParentProcessId)/$($parent.Name)"
}
"child_parent_pid=$($me.ParentProcessId) child_in_job=$inJob child_dll_directory=$($dllDir.ToString())"
