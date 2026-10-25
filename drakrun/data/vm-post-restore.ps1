# Suppress the "Networks: allow your PC to be discoverable?" flyout. A restored snapshot
# meets the sandbox network as a new network after the DHCP renew, and the flyout would
# otherwise cover a third of every screenshot and stay open on the sample's desktop.
New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Network\NewNetworkWindowOff' -Force -ErrorAction SilentlyContinue | Out-Null

if ( $DRAKVUF_NET_ENABLE )
{
    ipconfig /release
    ipconfig /renew
}
