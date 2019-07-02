class aap(GenericCommand):
    """Dummy new command."""
    _cmdline_ = "aap"
    _syntax_  = "{:s}".format(_cmdline_)

    # @only_if_gdb_running         # not required, ensures that the debug session is started
    def do_invoke(self, argv):
        import subprocess
        import json

        def getbuf(addr):
            return gef_disassemble(addr,100)

        infofile = gdb.execute('i files', to_string=True)
        path = infofile[infofile.find('"')+1:infofile.rfind('"')]
        got = subprocess.Popen(["objdump", "-R",path], stdout=subprocess.PIPE)
        got=got.communicate()[0].decode('utf-8').strip()
        temp=got.splitlines()
        for i in range(len(temp)):
            line=temp[i]
            if "VALUE" in line:
                temp=temp[i+1:]
                break
        got={}
        base=0
        if checksec(get_filepath())["PIE"]:
            base=gdb.execute("code",to_string=True)
            base=int(base.strip().split("\t")[-1],16)

        for i in temp:
            line=i.strip().split(" ")
            got[int(line[0],16)+base]=line[-1][:line[-1].find("@")]

        plt_start=0
        plt_end=0
        infofile=infofile.strip().splitlines()
        for i in infofile:
            if "is .plt.got" in i:
                plt_start=int(i.strip().split(" - ")[0],16)
                plt_end=int(i.strip().split(" - ")[1].split(" ")[0],16)
                break

        plt={}
        pc=plt_start
        start=0
        flag=0
        while(flag==0):
            buf=gef_disassemble(pc,100)
            for i in buf:
                if i.address==plt_end:
                    flag=1
                    break
                if start!=0 and pc==i.address:
                    continue
                pc=i.address
                if "#" in i.operands[0]:
                    plt[i.address]=int((i.operands[0]).split("#")[-1].strip(),16)
        import cxxfilt
        for i in plt:
            if len(argv)>0:
                if argv[0]=="-d":
                    plt[i]=str(cxxfilt.demangle(got[plt[i]]))
            else:
                plt[i]=got[plt[i]]
        with open("data.json",'w') as dumps:
            json.dump(plt,dumps)
        return

register_external_command(aap())
