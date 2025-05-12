## ###
# IP: Volatility License
##
from contextlib import contextmanager
import inspect
import os.path
import socket
import time

from ghidratrace import sch
from ghidratrace.client import Client, Address, AddressRange, TraceObject
import psutil  # type: ignore

import gdb  # type: ignore

from ghidragdb import arch, commands, hooks, methods, util
from ghidragdb.commands import cmd


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
    schema_fn = os.path.join(parent, 'schema_vol_gdb.xml')
    with open(schema_fn, 'r') as schema_file:
        schema_xml = schema_file.read()
    with commands.STATE.trace.open_tx("Create Root Object"):
        root = commands.STATE.trace.create_root_object(schema_xml, 'Session')
        root.set_value('_display', 'gdb_vol ' + util.GDB_VERSION.full)
    gdb.set_convenience_variable('_ghidra_tracing', True)


@cmd('ghidra trace connect', '-ghidra-trace-connect', gdb.COMMAND_SUPPORT,
     False)
def ghidra_trace_connect(address: str, *, is_mi: bool, **kwargs) -> None:
    """Start a Trace in Ghidra"""

    commands.STATE.require_client()
    if name is None:
        name = commands.compute_name()
    commands.STATE.require_no_trace()
    start_trace(name)


def set_physical_memory(on: bool) -> None:
    val = "1" if on else "0"
    cmd = f"maintenance packet Qqemu.PhyMemMode:{val}"
    gdb.execute(cmd)


def is_linux() -> bool:
    osabi = arch.get_osabi()
    return osabi == "GNU/Linux"


def is_macos() -> bool:
    osabi = arch.get_osabi()
    return osabi == "Darwin"


def is_windows() -> bool:
    osabi = arch.get_osabi()
    return osabi == "windows" or osabi == "Cygwin"
