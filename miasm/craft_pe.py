#! /usr/bin/env python

from elfesteem import pe #elfesteem.pe
from elfesteem.pe_init import PE
import rlcompleter, readline, pdb, sys
from pprint import pprint as pp
readline.parse_and_bind("tab: complete")


e_ = PE()
mysh = open(sys.argv[1], 'rb').read()

s_text = e_.SHList.add_section(name = "text", addr = 0x1000, rawsize = len(mysh)+0x1000, data = mysh)
e_.Opthdr.AddressOfEntryPoint = s_text.addr
# new_dll = [({"name":"kernel32.dll",
#              "firstthunk":s_text.addr+0x100},
#             ["CreateFileA", "SetFilePointer", "WriteFile", "CloseHandle"]
#             )
#            ,
#            ({"name":"USER32.dll",
#              "firstthunk":None},
#             ["SetDlgItemInt", "GetMenu", "HideCaret"]
#             )
#            ]
# e_.DirImport.add_dlldesc(new_dll)

# s_myimp = e_.SHList.add_section(name = "myimp", rawsize = 0x1000)
# e_.DirImport.set_rva(s_myimp.addr)
open(sys.argv[2], 'wb').write(str(e_))
