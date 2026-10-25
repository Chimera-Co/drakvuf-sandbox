New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\Network\NewNetworkWindowOff' -Force -EA 0 | Out-Null
if ( $DRAKVUF_NET_ENABLE )
{
    ipconfig /release
    ipconfig /renew
}
