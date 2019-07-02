class rename(GenericCommand):
    """Dummy new command."""
    _cmdline_ = "rename"
    _syntax_  = "{:s}".format(_cmdline_)

    # @only_if_gdb_running         # not required, ensures that the debug session is started
    def do_invoke(self, argv):
        import subprocess
        import json

        def getbuf(addr):
            return gef_disassemble(addr,100)

        if len(argv)<2:
            print("[-] Usage: rename <base_address> <name>")
            return

        def to_int(val):
            """
            Convert a string to int number
            """
            try:
                return int(str(val), 16)
            except:
                return None

        addr=to_int(argv[0])
        name = argv[1]

        fp=None
        funcs={}
        try:
            fp=open(".func.json",'r')
            funcs=json.load(fp)
        except Exception:
            pass

        base=0
        if len(argv)>2:
            if argv[2]=='r':
                maps=get_process_maps()
                base=maps[0].page_start

        funcs[base+addr]=name

        with open(".func.json",'w') as dumps:
            json.dump(funcs,dumps)

        return

register_external_command(rename())
