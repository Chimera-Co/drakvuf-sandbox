# Benign egress-drop trigger (goal G3.3). Sends five GRE packets (IP protocol 47) to TEST-NET-1. Only TCP, UDP and
# ICMP are redirected to INetSim, so the host routes these toward the uplink, where CHIMERA_GUARD must log
# "CHIMERA-EGRESS-DROP" and drop them; a batch runner that sees the log line must stop. Needs an administrator
# (raw sockets), as samples run on A0 and H3. Waits afterwards so the run is still going when the drop is logged.
$socket = New-Object Net.Sockets.Socket([Net.Sockets.AddressFamily]::InterNetwork, [Net.Sockets.SocketType]::Raw,
    [Net.Sockets.ProtocolType]47)
$target = New-Object Net.IPEndPoint([Net.IPAddress]::Parse('192.0.2.1'), 0)
1..5 | ForEach-Object { [void]$socket.SendTo([byte[]](1..24), $target); Start-Sleep -Milliseconds 200 }
$socket.Close()
Start-Sleep -Seconds 30
