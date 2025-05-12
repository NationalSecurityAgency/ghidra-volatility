## ###
# IP: Volatility License
##
from contextlib import contextmanager
import inspect
import os.path
import socket
import time
from typing import (Any, Dict)

from ghidratrace import sch
from ghidratrace.client import Client, Address, AddressRange, TraceObject
import psutil  # type: ignore

import lldb  # type: ignore

from ghidralldb import arch, commands, hooks, methods, util
from ghidralldb.commands import convert_errors


lldb.debugger.HandleCommand(
    'command script delete ghidra trace start')
lldb.debugger.HandleCommand(
    'command script add -f ghidravol.lldb_vol.ghidra_trace_start    ghidra trace start')


def compute_name() -> str:
    target = lldb.debugger.GetTargetAtIndex(0)
    progname = target.executable.basename
    if progname is None:
        return 'lldb_vol/noname'
    else:
        return 'lldb_vol/' + progname.split('/')[-1]


def start_trace(name: str) -> None:
    language, compiler = arch.compute_ghidra_lcsp()
    commands.STATE.trace = commands.STATE.require_client().create_trace(
        name, language, compiler, extra=commands.Extra())
    # TODO: Is adding an attribute like this recommended in Python?
    commands.STATE.trace.extra.memory_mapper = arch.compute_memory_mapper(
        language)
    commands.STATE.trace.extra.register_mapper = arch.compute_register_mapper(
        language)

    frame = inspect.currentframe()
    if frame is None:
        raise AssertionError("cannot locate schema.xml")
    parent = os.path.dirname(inspect.getfile(frame))
    schema_fn = os.path.join(parent, 'schema_vol_lldb.xml')
    with open(schema_fn, 'r') as schema_file:
        schema_xml = schema_file.read()
    with commands.STATE.trace.open_tx("Create Root Object"):
        root = commands.STATE.trace.create_root_object(schema_xml, 'Session')
        root.set_value('_display', 'lldb ' + util.LLDB_VERSION.full)
    util.set_convenience_variable('_ghidra_tracing', str(True))


@convert_errors
def ghidra_trace_start(debugger: lldb.SBDebugger, command: str,
                       result: lldb.SBCommandReturnObject,
                       internal_dict: Dict[str, Any]) -> None:
    """Start a Trace in Ghidra"""

    commands.STATE.require_client()
    name = command if len(command) > 0 else compute_name()
    commands.STATE.require_no_trace()
    start_trace(name)


def set_physical_memory(on: bool) -> None:
    val = "1" if on else "0"
    cmd = f"process plugin packet send Qqemu.PhyMemMode:{val}"
    res = lldb.SBCommandReturnObject()
    util.get_debugger().GetCommandInterpreter().HandleCommand(cmd, res)
    if res.Succeeded() == False:
        print(f"{res.GetError()}")


def is_linux() -> bool:
    osabi = util.get_convenience_variable("osabi")
    return osabi == "linux"


def is_macos() -> bool:
    osabi = util.get_convenience_variable("osabi")
    return osabi == "macosx" or osabi == "ios"


def is_windows() -> bool:
    osabi = util.get_convenience_variable("osabi")
    return osabi == "windows" or osabi == "Cygwin"
