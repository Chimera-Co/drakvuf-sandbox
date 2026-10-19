# Installs the Visual C++ 2015-2022 x64 runtime uploaded by provision_guest.py --upload
# (many real samples need it). 3010 = installed, reboot pending; 1638 = same or newer already installed.
$installer = 'C:\Users\Public\vc_redist.x64.exe'
$p = Start-Process -FilePath $installer -ArgumentList '/install', '/quiet', '/norestart' -Wait -PassThru
Write-Output "vc_redist exit code: $($p.ExitCode)"
$key = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64' -ErrorAction SilentlyContinue
Write-Output "runtime registered: installed=$($key.Installed) version=$($key.Version)"
Remove-Item $installer -Force
if (($p.ExitCode -in 0, 1638, 3010) -and $key.Installed -eq 1) { exit 0 } else { exit 1 }
