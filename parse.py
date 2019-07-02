class parse(GenericCommand):
    """Dummy new command."""
    _cmdline_ = "parse"
    _syntax_  = "{:s}".format(_cmdline_)

    def do_invoke(self, argv):

        import re

        template="""from ctypes import *

class classnamehere(Structure):
    _fields_ = [
placeholder
    ]
        """

        interm = """       ("name", typeof),\n"""
        final=''

        valid={'db':'c_char','dw':'c_short','dd':'c_int','dq':'c_ulong'}

        def getname(inp):
            return re.findall("\w+",inp[0])[1]

        def getargs(inp):
            return re.findall("\w+|\?",inp)

        sentinel = ''
        data='\n'.join(iter(input, sentinel)).strip().splitlines()
        name=getname(data)
        print("Parsing "+name)
        data=data[1:]
        for i in data:
            args = getargs(i)
            if args[1]==name and args[2]=='ends':
                break
            elif len(args)<3 or args[2] not in valid:
                continue;
            else:
                if args[3] == "?":
                    final+=interm.replace("name",args[1]).replace("typeof",valid[args[2]])
                    print(args[1]+" => "+valid[args[2]])
                elif args[2] == "db":
                    final+=interm.replace("name",args[1]).replace("typeof",valid[args[2]]+"*"+args[3])
                    print(args[1]+" => "+valid[args[2]]+"*"+args[3])


        final=final[:-2]
        print()
        template=template.replace("placeholder",final).replace("classnamehere",name)
        open("/home/vignesh/gef/structs/"+name+".py",'w').write(template)
        print("[+] Done")
        # print(data[2].split(" "))
        return

register_external_command(parse())
