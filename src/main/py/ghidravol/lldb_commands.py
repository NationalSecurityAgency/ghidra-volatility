## ###
# IP: Volatility License
##
import shlex
import lldb  # type: ignore

from ghidralldb import arch, commands, util
from ghidralldb.commands import convert_errors
from ghidravol.commands_linux import *
from ghidravol.commands_macos import *
from ghidravol.commands_windows import *
from ghidravol.lldb_vol import *

lldb.debugger.HandleCommand(
    'command script add -f ghidravol.lldb_commands.ghidra_trace_put_processes_vol   ghidra trace put-processes-vol')
lldb.debugger.HandleCommand(
    'command script add -f ghidravol.lldb_commands.ghidra_trace_put_regions_vol     ghidra trace put-regions-vol')
lldb.debugger.HandleCommand(
    'command script add -f ghidravol.lldb_commands.ghidra_trace_put_kmodules_vol    ghidra trace put-kmodules-vol')
lldb.debugger.HandleCommand(
    'command script add -f ghidravol.lldb_commands.ghidra_trace_put_modules_vol     ghidra trace put-modules-vol')
lldb.debugger.HandleCommand(
    'command script add -f ghidravol.lldb_commands.ghidra_trace_put_threads_vol     ghidra trace put-threads-vol')
lldb.debugger.HandleCommand(
    'command script add -f ghidravol.lldb_commands.ghidra_trace_put_all_vol         ghidra trace put-all-vol')


@convert_errors
def ghidra_trace_put_processes_vol(debugger: lldb.SBDebugger, command: str,
                               result: lldb.SBCommandReturnObject,
                               internal_dict: Dict[str, Any]) -> None:
    """
    Put the list of processes into the trace's Process list.
    """

    set_physical_memory(True)
    radix = util.get_convenience_variable('output-radix')
    if radix is None or radix == 'auto':
        radix = "16"
    radix = int(radix)

    trace, tx = commands.STATE.require_tx()
    with trace.client.batch() as b:
        if is_linux():
            put_processes_vol_linux(trace, radix)
        if is_macos():
            put_processes_vol_macos(trace, radix)
        if is_windows():
            put_processes_vol_win(trace, radix)
    set_physical_memory(False)


@convert_errors
def ghidra_trace_put_regions_vol(debugger: lldb.SBDebugger, command: str,
                             result: lldb.SBCommandReturnObject,
                             internal_dict: Dict[str, Any]) -> None:
    """
    Read the memory map, if applicable, and write to the trace's Regions
    """

    set_physical_memory(True)
    args = shlex.split(command)
    if len(args) != 1:
        raise RuntimeError(
            "ghidra trace put-regions: missing required argument 'pid'")
    pid = args[0]

    trace, tx = commands.STATE.require_tx()
    with trace.client.batch() as b:
        if is_linux():
            put_regions_vol_linux(trace, pid)
        if is_macos():
            put_regions_vol_macos(trace, pid)
        if is_windows():
            put_regions_vol_win(trace, pid)
    set_physical_memory(False)


@convert_errors
def ghidra_trace_put_kmodules_vol(debugger: lldb.SBDebugger, command: str,
                             result: lldb.SBCommandReturnObject,
                             internal_dict: Dict[str, Any]) -> None:
    """
    Gather object files, if applicable, and write to the trace's Modules
    """

    set_physical_memory(True)
    trace, tx = commands.STATE.require_tx()
    with trace.client.batch() as b:
        if is_linux():
            put_kmodules_vol_linux(trace)
        if is_macos():
            put_kmodules_vol_macos(trace)
        if is_windows():
            put_kmodules_vol_win(trace)
    set_physical_memory(False)


@convert_errors
def ghidra_trace_put_modules_vol(debugger: lldb.SBDebugger, command: str,
                             result: lldb.SBCommandReturnObject,
                             internal_dict: Dict[str, Any]) -> None:
    """
    Gather object files, if applicable, and write to the trace's Modules
    """

    set_physical_memory(True)
    args = shlex.split(command)
    if len(args) != 1:
        raise RuntimeError(
            "ghidra trace put-modules: missing required argument 'pid'")
    pid = args[0]

    trace, tx = commands.STATE.require_tx()
    with trace.client.batch() as b:
        if is_linux():
            put_modules_vol_linux(trace, pid)
        if is_macos():
            put_modules_vol_macos(trace, pid)
        if is_windows():
            put_modules_vol_win(trace, pid)
    set_physical_memory(False)


@convert_errors
def ghidra_trace_put_threads_vol(debugger: lldb.SBDebugger, command: str,
                             result: lldb.SBCommandReturnObject,
                             internal_dict: Dict[str, Any]) -> None:
    """
    Put the current process's threads into the Ghidra trace
    """

    set_physical_memory(True)
    args = shlex.split(command)
    if len(args) != 1:
        raise RuntimeError(
            "ghidra trace put-threads: missing required argument 'pid'")
    pid = args[0]
    radix = util.get_convenience_variable('output-radix')
    if radix is None or radix == 'auto':
        radix = "16"
    radix = int(radix)

    trace, tx = commands.STATE.require_tx()
    with trace.client.batch() as b:
        if is_linux():
            put_threads_vol_linux(trace, pid, radix)
        if is_macos():
            put_threads_vol_macos(trace, pid, radix)
        if is_windows():
            put_threads_vol_win(trace, pid, radix)
    set_physical_memory(False)


@convert_errors
def ghidra_trace_put_all_vol(debugger: lldb.SBDebugger, command: str,
                         result: lldb.SBCommandReturnObject,
                         internal_dict: Dict[str, Any]) -> None:
    """
    Put everything currently selected into the Ghidra trace
    """

    set_physical_memory(True)
    radix = util.get_convenience_variable('output-radix')
    if radix is None or radix == 'auto':
        radix = "16"
    radix = int(radix)

    trace, tx = commands.STATE.require_tx()
    with trace.client.batch() as b:
        if is_linux():
            put_processes_vol_linux(trace, radix)
            put_kmodules_vol_linux(trace)
        elif is_macos():
            put_processes_vol_macos(trace, radix)
            put_kmodules_vol_macos(trace)
        elif is_windows():
            put_processes_vol_win(trace, radix)
            put_kmodules_vol_win(trace)
        else:
            print("UNKNOWN OS {get_osabi()}")
    set_physical_memory(False)
