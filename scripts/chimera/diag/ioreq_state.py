"""Read-only dump of a domain's ioreq server pages (per-vCPU request state).
usage: sudo python3 -I ioreq_state.py <domid> [nvcpus]"""
import ctypes, struct, sys
domid = int(sys.argv[1]); nv = int(sys.argv[2]) if len(sys.argv) > 2 else 4
fm = ctypes.CDLL('/usr/local/lib/libxenforeignmemory.so')
fm.xenforeignmemory_open.restype = ctypes.c_void_p
fm.xenforeignmemory_map_resource.restype = ctypes.c_void_p
fm.xenforeignmemory_map_resource.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint, ctypes.c_uint,
    ctypes.c_ulong, ctypes.c_ulong, ctypes.POINTER(ctypes.c_void_p), ctypes.c_int, ctypes.c_int]
h = fm.xenforeignmemory_open(None, 0)
STATES = {0: 'NONE', 1: 'IOREQ_READY', 2: 'INPROCESS', 3: 'IORESP_READY'}
TYPES = {0: 'PIO', 1: 'COPY(MMIO)', 2: 'PCI_CONFIG', 3: 'TIMEOFFSET', 4: 'INVALIDATE'}
for sid in range(4):
    addr = ctypes.c_void_p(None)
    # XENMEM_resource_ioreq_server = 0, frame 1 = synchronous ioreq page; PROT_READ = 1
    res = fm.xenforeignmemory_map_resource(h, domid, 0, sid, 1, 1, ctypes.byref(addr), 1, 0)
    if not res:
        continue
    buf = ctypes.string_at(addr.value, 32 * nv)
    print(f'ioreq server {sid}:')
    for v in range(nv):
        a, d, cnt, size, port, _p, bits, typ = struct.unpack_from('<QQIIIHBB', buf, 32 * v)
        st = bits & 0xF; dir_ = (bits >> 5) & 1
        print(f'  vcpu{v}: state={STATES.get(st, st)} type={TYPES.get(typ, typ)} dir={"read" if dir_ else "write"} '
              f'addr={a:#x} size={size} count={cnt} data={d:#x} port={port}')
    fm.xenforeignmemory_unmap_resource(h, ctypes.c_void_p(res))
