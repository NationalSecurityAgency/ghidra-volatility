## ###
# IP: Volatility License
##
from contextlib import contextmanager
import inspect
import os.path
import socket
import time
from typing import Any, Dict

from ghidratrace import sch
from ghidratrace.client import Client, Address, AddressRange, Trace, TraceObject
import psutil # type: ignore
from ghidravol import volcmd


SUBMODEL_PATH = "Volatility"
PROCESSES_PATH = SUBMODEL_PATH + '.Processes'
PROCESS_KEY_PATTERN = '[{pid}]'
PROCESS_PATTERN = PROCESSES_PATH + PROCESS_KEY_PATTERN
PROC_BREAKS_PATTERN = PROCESS_PATTERN + '.Breakpoints'
PROC_BREAK_KEY_PATTERN = '[{breaknum}.{locnum}]'
THREADS_PATTERN = PROCESS_PATTERN + '.Threads'
THREAD_KEY_PATTERN = '[{tnum}]'
THREAD_PATTERN = THREADS_PATTERN + THREAD_KEY_PATTERN
MEMORY_PATTERN = PROCESS_PATTERN + '.Memory'
REGION_KEY_PATTERN = '[{start:08x}]'
REGION_PATTERN = MEMORY_PATTERN + REGION_KEY_PATTERN
KMODULES_PATH = SUBMODEL_PATH + '.Modules'
KMODULE_KEY_PATTERN = '[{modpath}]'
KMODULE_PATTERN = KMODULES_PATH + KMODULE_KEY_PATTERN
MODULES_PATTERN = PROCESS_PATTERN + '.Modules'
MODULE_KEY_PATTERN = '[{modpath}]'
MODULE_PATTERN = MODULES_PATTERN + MODULE_KEY_PATTERN
SECTIONS_ADD_PATTERN = '.Sections'
SECTION_KEY_PATTERN = '[{secname}]'
SECTION_ADD_PATTERN = SECTIONS_ADD_PATTERN + SECTION_KEY_PATTERN


PAGE_SIZE = 4096


def compute_inf_state(inf: Dict[str, Any]) -> str:
    return 'STOPPED'


def put_processes_vol_linux(trace: Trace, radix: int) -> None:
    args = ["linux.pslist.PsList"]
    keys = []
    res = volcmd.vol(args)
    if res is None:
        return
    for inf in res:
        pid = inf["PID"]
        pidstr = ('0x{:x}' if radix ==
                  16 else '0{:o}' if radix == 8 else '{}').format(pid)
        ipath = PROCESS_PATTERN.format(pid=pidstr)
        keys.append(PROCESS_KEY_PATTERN.format(pid=pidstr))
        infobj = trace.create_object(ipath)
        istate = compute_inf_state(inf)
        infobj.set_value('State', istate)
        infobj.set_value('PID', pid)
        ppid = inf["PPID"]
        ppidstr = ('0x{:x}' if radix ==
                   16 else '0{:o}' if radix == 8 else '{}').format(ppid)
        infobj.set_value('PPID', ppidstr)
        tid = inf["TID"]
        tidstr = ('0x{:x}' if radix ==
                  16 else '0{:o}' if radix == 8 else '{}').format(tid)
        infobj.set_value('TID', tidstr)
        infobj.set_value('Offset (V)', hex(inf["OFFSET (V)"]))
        infobj.set_value('Comm', inf["COMM"])
        infobj.insert()
    trace.proxy_object_path(
        PROCESSES_PATH).retain_values(keys)


def put_regions_vol_linux(trace: Trace, pid: str) -> None:
    args = ["linux.proc.Maps", f"--pid={pid}"]
    keys = []
    res = volcmd.vol(args)
    if res is None:
        return
    for r in res:
        rpath = REGION_PATTERN.format(pid=pid, start=r["Star"])
        keys.append(REGION_KEY_PATTERN.format(start=r["Start"]))
        regobj = trace.create_object(rpath)
        regobj.set_value('Start', hex(r["Start"]))
        regobj.set_value('End', hex(r["End"]))
        regobj.set_value('PgOff', hex(r["PgOff"]))
        regobj.set_value('Flags', r["Flags"])
        regobj.set_value('Process', r["Process"])
        regobj.set_value('Major', r["Major"])
        regobj.set_value('Minor', r["Minor"])
        regobj.set_value('Inode', r["Inode"])
        regobj.insert()
    trace.proxy_object_path(
        MEMORY_PATTERN.format(pid=pid)).retain_values(keys)


def put_kmodules_vol_linux(trace: Trace) -> None:
    args = ["linux.lsmod.Lsmod"]
    keys = []
    res = volcmd.vol(args)
    if res is None:
        return
    for mod in res:
        name = mod["Name"]
        mpath = KMODULE_PATTERN.format(modpath=name)
        keys.append(KMODULE_KEY_PATTERN.format(modpath=name))
        modobj = trace.create_object(mpath)
        modobj.set_value('Offset', hex(mod["Offset"]))
        modobj.set_value('Size', hex(mod["Size"]))
        modobj.insert()
    trace.proxy_object_path(
        KMODULES_PATH).retain_values(keys)


def put_modules_vol_linux(trace: Trace, pid: str) -> None:
    args = ["linux.elfs.Elfs", f"--pid={pid}"]
    keys = []
    res = volcmd.vol(args)
    if res is None:
        return
    for mod in res:
        name = mod["File Path"]
        mpath = MODULE_PATTERN.format(pid=pid, modpath=name)
        keys.append(MODULE_KEY_PATTERN.format(modpath=name))
        modobj = trace.create_object(mpath)
        modobj.set_value('Start', hex(mod["Start"]))
        modobj.set_value('End', hex(mod["End"]))
        modobj.insert()
    trace.proxy_object_path(
        MODULES_PATTERN).retain_values(keys)


def put_threads_vol_linux(trace: Trace, pid: str, radix: int) -> None:
    args = ["linux.pslist.PsList", "--threads",
            "--decorate-com", f"--pid={pid}"]
    keys = []
    res = volcmd.vol(args)
    if res is None:
        return
    for t in res:
        tid = t["TID"]
        tidstr = ('0x{:x}' if radix ==
                  16 else '0{:o}' if radix == 8 else '{}').format(tid)
        pid = t["PID"]
        pidstr = ('0x{:x}' if radix ==
                  16 else '0{:o}' if radix == 8 else '{}').format(pid)
        ppid = t["PPID"]
        ppidstr = ('0x{:x}' if radix ==
                   16 else '0{:o}' if radix == 8 else '{}').format(ppid)
        tpath = THREAD_PATTERN.format(pid=pidstr, tnum=tidstr)
        tobj = trace.create_object(tpath)
        keys.append(THREAD_KEY_PATTERN.format(tnum=tidstr))
        tobj = trace.create_object(tpath)
        tobj.set_value('TID', tidstr)
        tobj.set_value('PID', pidstr)
        tobj.set_value('PPID', ppidstr)
        tobj.set_value('OFFSET (V)', hex(t["OFFSET (V)"]))
        tobj.set_value('COMM', t["COMM"])
        tobj.insert()
    trace.proxy_object_path(
        THREADS_PATTERN.format(pid=pidstr)).retain_values(keys)
