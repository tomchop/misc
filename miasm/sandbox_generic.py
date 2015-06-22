import os
from pdb import pm
from miasm2.analysis.sandbox import Sandbox_Win_x86_32
from miasm2.os_dep import win_api_x86_32, win_api_x86_32_seh
from miasm2.os_dep.common import *
from miasm2.jitter.csts import PAGE_READ, PAGE_WRITE, PAGE_EXEC
from miasm2.os_dep.win_api_x86_32 import winobjs
from miasm2.core.utils import hexdump

import logging

log = logging.getLogger("sandbox")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(levelname)-5s: %(message)s"))
log.addHandler(console_handler)
log.setLevel(logging.INFO)

logging.getLogger("win_api_x86_32").setLevel(logging.INFO)

# Python auto completion
filename = os.environ.get('PYTHONSTARTUP')
if filename and os.path.isfile(filename):
    execfile(filename)

# Parse arguments
parser = Sandbox_Win_x86_32.parser(description="PE sandboxer")
parser.add_argument("filename", help="PE Filename")
options = parser.parse_args()

# Create sandbox

Sandbox_Win_x86_32.ALL_IMP_DLL = [  #"shlwapi.dll",
                                    "ntdll.dll",
                                    "kernel32.dll",
                                    "user32.dll",
                                    "ole32.dll",
                                    "urlmon.dll",
                                    "ws2_32.dll",
                                    "advapi32.dll", # this one
                                    "psapi.dll",
                                    "setupapi.dll",
                                    "shell32.dll",
                                    "uxtheme.dll",
                                    "winhttp.dll",
                                 ]

sb = Sandbox_Win_x86_32(options.filename, options, globals())

def breakpoint(jitter):
    import pdb
    pdb.set_trace()
    return True

def pause(jitter):
    print "Hit breakpoint"
    raw_input()
    return True

def start_trace(jitter):
    jitter.jit.log_mn = True
    jitter.jit.log_regs = True
    # breakpoint(jitter)
    return True


# [DEBUG] the binary checks something near the base of the stack, which is not defined.
# this is a nasty hack so as not to raise an exception
# sb.jitter.vm.add_memory_page(sb.jitter.stack_base + sb.jitter.stack_size, PAGE_READ | PAGE_WRITE, "\x00"*10000)
# sb.jitter.add_breakpoint(0x402FE6, changenf)
# sb.jitter.add_breakpoint(0x402FEC, changenf)
# sb.jitter.add_breakpoint(0x2000125b, extract_urls)
sb.jitter.jit.log_mn = True
sb.jitter.jit.log_regs = True

# try:
sb.run()
# except Exception, e:
#     import pdb
#     pdb.set_trace()

assert(sb.jitter.run is False)

