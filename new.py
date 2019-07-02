class pd(GenericCommand):
    """Dummy new command."""
    _cmdline_ = "pd"
    _syntax_  = "{:s}".format(_cmdline_)

    def do_invoke(self, argv=[]):

        def colorize(text, color=None, attrib=None):
            """
            Colorize text using ansicolor
            ref: https://github.com/hellman/libcolors/blob/master/libcolors.py
            """
            # ansicolor definitions
            COLORS = {"black": "30", "red": "31", "green": "32", "yellow": "33",
                        "blue": "34", "purple": "35", "cyan": "36", "white": "37"}
            CATTRS = {"regular": "0", "bold": "1", "underline": "4", "strike": "9",
                        "light": "1", "dark": "2", "invert": "7"}

            CPRE = '\033['
            CSUF = '\033[0m'

            # if config.Option.get("ansicolor") != "on":
            #     return text

            ccode = ""
            if attrib:
                for attr in attrib.lower().split():
                    attr = attr.strip(",+|")
                    if attr in CATTRS:
                        ccode += ";" + CATTRS[attr]
            if color in COLORS:
                ccode += ";" + COLORS[color]
            return CPRE + ccode + "m" + text + CSUF

        def gdb_get_addr(sym):
            res = gdb.execute("p "+sym, to_string=True)
            # print(res)
            res = res.split(" ")
            for i in range(len(res)):
                if "<"+sym in res[i]:
                    return int(res[i-1],16)

        def to_int(val):
            """
            Convert a string to int number
            """
            try:
                return int(str(val), 0)
            except:
                return None

        def get_disas(sym):
            res=gdb.execute("disas "+sym, to_string=True)
            return res

        def get_ins(sym,cnt=100):
            res=gdb.execute("x/"+str(cnt)+"i "+str(sym), to_string=True)
            return res

        def format_disasm_code(code, nearby=None):
            """
            Format output of disassemble command with colors to highlight:
                - dangerous functions (rats/flawfinder)
                - branching: jmp, call, ret
                - testing: cmp, test

            Args:
                - code: input asm code (String)
                - nearby: address for nearby style format (Int)

            Returns:
                - colorized text code (String)
            """
            VULN_FUNCTIONS = [
                "exec", "system", "gets", "popen", "getenv", "strcpy", "strncpy", "strcat", "strncat",
                "memcpy", "bcopy", "printf", "sprintf", "snprintf", "scanf",  "getchar", "getc", "read",
                "recv", "tmp", "temp"
            ]
            colorcodes = {
                "cmp": "red",
                "test": "red",
                "call": "green",
                "j": "yellow", # jump
                "ret": "blue",
            }
            result = ""

            if not code:
                return result

            if to_int(nearby) is not None:
                target = to_int(nearby)
            else:
                target = 0

            for line in code.splitlines():
                if ":" not in line: # not an assembly line
                    result += line + "\n"
                else:
                    color = style = None
                    m = re.search(".*(0x[^ ]*).*:\s*([^ ]*)", line)
                    if not m: # failed to parse
                        result += line + "\n"
                        continue
                    addr, opcode = to_int(m.group(1)), m.group(2)
                    for c in colorcodes:
                        if c in opcode:
                            color = colorcodes[c]
                            if c == "call":
                                for f in VULN_FUNCTIONS:
                                    if f in line.split(":\t", 1)[-1]:
                                        style = "bold, underline"
                                        color = "red"
                                        break
                            break

                    prefix = line.split(":\t")[0]
                    addr = re.search("(0x[^\s]*)", prefix)
                    if addr:
                        addr = to_int(addr.group(1))
                    else:
                        addr = -1
                    line = "\t" + line.split(":\t", 1)[-1]
                    if addr < target:
                        style = "dark"
                    elif addr == target:
                        style = "bold"
                        color = "green"

                    code = colorize(line.split(";")[0], color, style)
                    if ";" in line:
                        comment = colorize(";" + line.split(";", 1)[1], color, "dark")
                    else:
                        comment = ""
                    line = "%s:%s%s" % (prefix, code, comment)
                    result += line + "\n"
                    # print ("ASD => "+line)
            return result.rstrip()

        def parse(arg):
            m = re.search(".*(0x[^ ]*).*:\s*([^ ]*)", arg)
            addr, opcode = to_int(m.group(1)), m.group(2)
            return addr, opcode

        code=''
        if argv==[]:
            argv.append(hex(current_arch.pc))
        if to_int(argv[0]):
            code+="   "
            flag=0
            start=to_int(argv[0])
            buf=''
            while(flag==0):
                buf=get_ins(start)
                buf=buf.strip().splitlines()
                for i in range(len(buf)):
                    if (i==len(buf)-1) and (parse(buf[i])[1]!="ret"):
                        start=parse(buf[i])[0]
                        code+="   "
                    else:
                        code+=buf[i]+'\n'
                        if parse(buf[i])[1]=="ret" or parse(buf[i])[1]=="hlt":
                            flag=1
                            break
        elif argv[0].startswith("/"):
            code=get_ins(current_arch.pc,argv[0].strip()[1:])
        else:
            code=get_disas(argv[0])

        print(format_disasm_code(code))
        return


register_external_command(pd())
