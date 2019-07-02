class code(GenericCommand):
    """Dummy new command."""
    _cmdline_ = "code"
    _syntax_  = "{:s}".format(_cmdline_)

    # @only_if_gdb_running         # not required, ensures that the debug session is started
    def do_invoke(self, argv):
        # do anything allowed by gef, for example show the current running
        # architecture as Python object:
        # print(" = {}".format(current_arch) )
        # or showing the current $pc
        maps=get_process_maps()
        path=maps[0].realpath
        path=path[path.rfind("/")+1:]
        print(Color.colorify(path+":","bold blue"),end='')
        print("\t"+hex(maps[0].page_start))

        return

register_external_command(code())
