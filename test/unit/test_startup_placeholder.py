"""{sample} in a user start command is replaced with the sample's guest path."""

from drakrun.analyzer.startup_command import fill_sample_placeholder


def test_string_command_gets_guest_path():
    cmd = fill_sample_placeholder('msiexec /i "{sample}" /qn', r"C:\Users\u\Desktop\vnc.msi")
    assert cmd == r'msiexec /i "C:\Users\u\Desktop\vnc.msi" /qn'


def test_list_command_gets_guest_path():
    cmd = fill_sample_placeholder(["{sample}", "lsf", ":http:"], "/home/user/work/rclone")
    assert cmd == ["/home/user/work/rclone", "lsf", ":http:"]


def test_command_without_placeholder_is_unchanged():
    assert fill_sample_placeholder("cmd.exe /c ver", "x.exe") == "cmd.exe /c ver"
