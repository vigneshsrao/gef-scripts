class ctf(GenericCommand):
    """Dummy new command."""
    _cmdline_ = "ctf"
    _syntax_  = "{:s}".format(_cmdline_)

    # @only_if_gdb_running         # not required, ensures that the debug session is started
    def do_invoke(self, argv):
        # do anything allowed by gef, for example show the current running
        # architecture as Python object:
        # print(" = {}".format(current_arch) )
        # or showing the current $pc
        l=[]
        gdb.execute("b*0x555555555194")
        gdb.execute("c")
        while(True):
            ra=get_register("al")
            l.append(ra)
            print(l)
            gdb.execute("c")


        return

register_external_command(ctf())
