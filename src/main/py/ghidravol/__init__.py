## ###
# IP: Volatility License
##
from . import volcmd, tslist
from . import commands_linux, commands_macos, commands_windows
from typing import Optional, Type


def try_gdb():
    try:
        import gdb  # type: ignore
        return True
    except:
        return False


IS_GDB = try_gdb()

if IS_GDB:
    from ghidragdb import util, commands
    import ghidravol.gdb_volpatch as volpatch
    import ghidravol.gdb_vol as vol
else:
    from ghidralldb import util, commands
    import ghidravol.lldb_volpatch as volpatch
    import ghidravol.lldb_vol as vol


DebuggerLayer: Optional[Type] = None

if IS_GDB:
    from . import gdb_commands
    DebuggerLayer = volpatch.GdbLayer  # type: ignore
else:
    from . import lldb_commands
    DebuggerLayer = volpatch.LldbLayer  # type: ignore
