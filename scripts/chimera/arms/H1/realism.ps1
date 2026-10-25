# CHIMERA H1 guest realism (wear-and-tear) — runs inside vm-0 during `drakrun modify-vm0`.
# Creates ordinary user documents with past timestamps so the profile doesn't look
# freshly installed (Miramirkhani et al., "Spotless Sandboxes", S&P 2017).
# Benign content only. Idempotent: re-running overwrites the same files.
$ErrorActionPreference = 'Stop'
$profileDir = [Environment]::GetFolderPath('UserProfile')
$rng = New-Object System.Random 20261019

$files = @(
    @{ Dir = 'Documents'; Name = 'Budget 2026.csv';          Days = 212; Body = "Month,Rent,Groceries,Travel`nJan,18000,6200,1500`nFeb,18000,5900,2100`nMar,18000,6400,900" },
    @{ Dir = 'Documents'; Name = 'Meeting notes - project.txt'; Days = 95; Body = "Agenda`n- timeline review`n- vendor follow-up`n- next steps for Q3" },
    @{ Dir = 'Documents'; Name = 'Recipes.txt';              Days = 301; Body = "Masala chai: water, milk, tea leaves, ginger, cardamom, sugar." },
    @{ Dir = 'Documents'; Name = 'Passport renewal checklist.txt'; Days = 160; Body = "Photos, old passport, address proof, appointment confirmation." },
    @{ Dir = 'Desktop';   Name = 'todo.txt';                 Days = 14;  Body = "call bank`nrenew insurance`nbook train tickets" },
    @{ Dir = 'Downloads'; Name = 'timetable_sem7.html';      Days = 48;  Body = "<html><body><table><tr><td>Mon</td><td>Networks</td></tr></table></body></html>" },
    @{ Dir = 'Downloads'; Name = 'invoice_0423.txt';         Days = 120; Body = "Invoice 0423 - Amount due: 2,499.00 - Paid" },
    @{ Dir = 'Pictures';  Name = 'wallpapers.txt';           Days = 250; Body = "favourite wallpapers list" }
)

foreach ($f in $files) {
    $dir = Join-Path $profileDir $f.Dir
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $path = Join-Path $dir $f.Name
    Set-Content -Path $path -Value $f.Body -Encoding UTF8
    $created = (Get-Date).AddDays(-$f.Days).AddMinutes(-$rng.Next(0, 600))
    $item = Get-Item $path
    $item.CreationTime = $created
    # Last edit stays at least 8 days in the past so every file counts as aged (> 7 days).
    $item.LastWriteTime = $created.AddDays($rng.Next(0, [Math]::Max(1, $f.Days - 8)))
    $item.LastAccessTime = (Get-Date).AddDays(-$rng.Next(0, 7))
}

$aged = Get-ChildItem -Path $profileDir -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-7) }
"realism: $($files.Count) documents written; files older than 7 days in profile: $($aged.Count)"
