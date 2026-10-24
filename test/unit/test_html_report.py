import json

from drakrun.analyzer.postprocessing.plugins.generate_html_report import (
    script_safe_json,
)


def test_guest_strings_cannot_close_the_script_element():
    # A process name or URL is guest-controlled; it must not end <script> in report.html
    hostile = {
        "process": "a.exe</script><script>alert(1)</script>",
        "url": "http://x/?a=1&b=<!--",
        "nested": ["</SCRIPT >", "]]>"],
    }
    embedded = script_safe_json(hostile)
    assert "<" not in embedded and ">" not in embedded and "&" not in embedded
    assert json.loads(embedded) == hostile


def test_line_separators_stay_escaped():
    data = {"s": "a b c"}
    embedded = script_safe_json(data)
    assert " " not in embedded and " " not in embedded
    assert json.loads(embedded) == data
