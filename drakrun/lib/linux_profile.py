"""Expose members of anonymous unions/structs in a dwarf2json (Volatility ISF) Linux profile.

DRAKVUF/LibVMI look struct members up by name and do not descend into anonymous members, so a
member like iov_iter.iov (inside an anonymous union since Linux 5.x) is "missing" and the plugin
that needs it (unixsocketmon) silently disables itself. This adds each anonymous member's fields
to the parent at parent_offset + member_offset, without replacing any existing name.

Only the listed structs are changed (default: iov_iter). Flattening every struct (3035 members)
broke procmon's exec events: some lookup that failed and fell back before then found a member
it should not use.

    python3 flatten_profile.py IN.json OUT.json [STRUCT ...]
"""
import json
import sys


def flatten(profile, only):
    types = profile["user_types"]
    added = 0

    def anonymous_fields(type_name, base_offset, depth=0):
        inner = types.get(type_name)
        if inner is None or depth > 4:
            return
        for name, field in inner["fields"].items():
            offset = base_offset + field["offset"]
            if field.get("anonymous"):
                yield from anonymous_fields(field["type"].get("name"), offset, depth + 1)
            else:
                yield name, {**field, "offset": offset}

    for struct_name in only:
        struct = types[struct_name]
        fields = struct.get("fields", {})
        extra = {}
        for field in list(fields.values()):
            if field.get("anonymous") and field["type"].get("kind") in ("union", "struct"):
                for name, flat in anonymous_fields(field["type"]["name"], field["offset"]):
                    if name not in fields and name not in extra:
                        extra[name] = flat
        fields.update(extra)
        added += len(extra)
    return added


if __name__ == "__main__":
    with open(sys.argv[1]) as f:
        profile = json.load(f)
    n = flatten(profile, sys.argv[3:] or ["iov_iter"])
    with open(sys.argv[2], "w") as f:
        json.dump(profile, f)
    print(f"added {n} members")
