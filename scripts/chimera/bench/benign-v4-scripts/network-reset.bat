@echo off
rem Network troubleshooting report: show commands only, nothing is reset or changed
set OUT=%TEMP%\network-report.txt
ipconfig /all > "%OUT%"
ipconfig /displaydns >> "%OUT%"
netsh interface ipv4 show config >> "%OUT%"
netsh winhttp show proxy >> "%OUT%"
route print >> "%OUT%"
arp -a >> "%OUT%"
echo Report written to %OUT%
