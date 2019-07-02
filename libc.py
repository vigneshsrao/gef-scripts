class libc(GenericCommand):
    """Dummy new command."""
    _cmdline_ = "libc"
    _syntax_  = "{:s}".format(_cmdline_)

    @only_if_gdb_running         # not required, ensures that the debug session is started
    def do_invoke(self, argv):
        maps=get_process_maps()
        i=0
        for j in range(len(maps)):
            if "/libc" in maps[j].realpath.strip():
                i=j
                break
        path=maps[i].realpath
        print(Color.colorify(path+":\t","bold blue"),end='')
        print(hex(maps[i].page_start))

        return

register_external_command(libc())
