class graph(GenericCommand):
    """Dummy new command."""
    _cmdline_ = "graph"
    _syntax_  = "{:s}".format(_cmdline_)

    def endkeys(self,ins):
        keywords=["exit","stack_chk_fail","abort","assert_fail"]
        for i in keywords:
            if i in ins.operands[0]:
                return True
        return False

    def do_invoke(self, argv):
        from graphviz import Digraph
        import json
        append=1
        move=2
        isjmp=4

        def reducestr(ins):
            return "{:6} {:s}".format(ins.mnemonic,
                                      ", ".join(ins.operands))

        def to_int(val):
            """
            Convert a string to int number
            """
            try:
                return int(str(val), 16)
            except:
                return None

        def addnames(i):
            f=None
            f1=None
            funcs=None
            try:
                f=open("data.json")
                plt=json.load(f)
            except Exception:
                pass

            try:
                f1=open(".func.json")
                funcs=json.load(f1)
            except Exception:
                pass

            if i.mnemonic == "call" and to_int(i.operands[0]) is not None:
                if f is not None:
                    op=to_int(i.operands[0])
                    if str(op) in plt:
                        i.operands=[plt[str(op)]]
                if funcs is not None:
                    op=to_int(i.operands[0])
                    if str(op) in funcs:
                        i.operands=[hex(op)+" <"+funcs[str(op)]+">"]
            return i

        def pdisas(l):
            def colourstr(ins,col):
                # print(len(ins.location))
                if len(ins.location)>0:
                    return "{:#10x} {:16} {:6} {:s}".format(ins.address,
                                                        ins.location,
                                                        Color.colorify(ins.mnemonic,col),
                                                        Color.colorify(", ".join(ins.operands), col))
                else:
                    return "{:#10x}:\t{:6} {:s}".format(ins.address,
                                                        Color.colorify(ins.mnemonic,col),
                                                        Color.colorify(", ".join(ins.operands), col))
            def wrap(ins):
                if(len(ins.location)>0):
                    return "{:#10x} {:16} {:6} {:s}".format(ins.address,
                                                            ins.location,
                                                            ins.mnemonic,
                                                            ", ".join(ins.operands))
                else:
                    return "{:#10x}:\t{:6} {:s}".format(ins.address,
                                                            ins.mnemonic,
                                                            ", ".join(ins.operands))

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
                "syscall": "red bold"
            }
            f=None
            funcs=None
            plt=None
            try:
                f=open("data.json")
                plt=json.load(f)
            except Exception:
                pass

            try:
                f1=open(".func.json")
                funcs=json.load(f1)
            except Exception:
                pass

            res=''
            # print(plt)
            for i in l:
                # print(i)
                if i.mnemonic == "call" and to_int(i.operands[0]) is not None:
                    if f is not None:
                        op=to_int(i.operands[0])
                        if str(op) in plt:
                            i.operands=[plt[str(op)]]
                    if funcs is not None:
                        op=to_int(i.operands[0])
                        if str(op) in funcs:
                            i.operands=[hex(op)+" <"+funcs[str(op)]+">"]


                for c in colorcodes:
                    if c in i.mnemonic:

                        res+=colourstr(i,colorcodes[c])+"\n"
                        break
                else:
                    res+=wrap(i)+"\n"

                # if i.mnemonic in colorcodes:
            return res



        # import shutil
        #
        # def get_terminal_columns():
        #     return shutil.get_terminal_size().columns

        class node:
            def __init__(self,ins):
                self.start_addr=ins.address
                self.end_addr=ins.address
                self.inst=[ins]

            def insert(self,ins):
                if ins.address==self.start_addr:
                    return
                self.inst.append(ins)
                self.end_addr=ins.address

            def __str__(self):
                rep=""
                no,col=get_terminal_size()
                # print(col)
                # for i in self.inst:
                #     rep+=str(i)+"\n"
                rep=pdisas(self.inst)
                rep+=Color.colorify(HORIZONTAL_LINE * col, "red")+"\n"
                # rep+="\n"
                # print(rep)
                return rep

        class cfg:
            def __init__(self,init={}):
                self.gdict=init

            def addedge(self,ver,edge):
                self.gdict[ver].append(edge)

            def addvertex(self,ver):
                if ver in self.gdict:
                    return
                self.gdict[ver]=[]

            def makegraph(self,d):
                for i in self.gdict:
                    d.node(hex(i))
                for i in self.gdict:
                    for j in self.gdict[i]:
                        if j:
                            d.edge(hex(i),hex(j))


            def __str__(self):
                res=''
                for i in self.gdict:
                    res+=hex(i)+" => "
                    for j in self.gdict[i]:
                        res+=hex(j)+", "
                    # res=res[:-1]
                    res+="\n"
                return res

            def reduced(self):
                rep=""
                for i in self.inst:
                     rep+=reducestr(i)+"\n"
                return rep


        tails=["ret","hlt","jmp"]
        target=[-1]



        def getbuf(addr):
            return gef_disassemble(addr,100)


        def checkend(ins):
            flag=0
            val=None
            flag |= move
            if ins.mnemonic.startswith("j"):
                flag |= append
                flag |= move
                val=ins.operands[0].split(" ")[0]
            if ins.mnemonic.startswith("call"):
                ins=addnames(ins)
                if (self.endkeys(ins)):
                    leaders.sort()
                    target[0]=leaders[-1]
                    flag &= ~move
            if ins.mnemonic.strip() in tails:
                leaders.sort()
                target[0]=leaders[-1]
                flag &= ~move
                if ins.mnemonic == "jmp":
                    flag |= isjmp
                    if to_int(val)==None:
                        val = None
                        flag &= ~append
                    elif to_int(val)>ins.address:
                        target[0]=leaders[-1]
                        flag |= move
                    else:
                        leaders.sort()
                        if leaders[-1]>ins.address:
                            target[0]=leaders[-1]
                            flag |= move

            if target[0]!=-1 and target[0]>ins.address:
                flag |= move
            return [flag,val]

        # lookup()
        flag=False
        pc=int(argv[0],16)
        st=0
        node_start=pc
        leaders=[]
        ender=0
        control=cfg()
        # control.addvertex(node_start)
        iter=0
        cflag=0
        while(True):
            if flag:
                break
            buf=getbuf(pc)
            for i in buf:
                if iter!=0 and pc==i.address:
                    continue
                pc=i.address
                # print(i)
                if st==0:
                    # control.addedge(node_start,i.address)
                    # node_start=i.address
                    # control.addvertex(node_start)
                    st=1
                    if i.address not in leaders:
                            leaders.append(i.address)

                out=checkend(i)
                cflag=out[0]
                # print(out)
                if out[0] & append:
                    # control.addedge(node_start,int(out[1],16))
                    if int(out[1],16) not in leaders:
                        leaders.append(int(out[1],16))
                    st=0
                if cflag & isjmp:
                    st=0
                if not (out[0] & move):
                    flag=1
                    ender=i.address
                    break
            iter+=1

        leaders.sort()

        for i in leaders:
            control.addvertex(i)
        # print(hex(ender))
        flag=0
        node_start=leaders[0]
        nodes=[]
        pc=leaders[0]
        cnt=-1
        add=0
        iter=0
        # print(len(nodes))
        # print(len(leaders))
        while(flag==0):
            buf=getbuf(pc)
            for i in buf:
                # print(i)
                if iter!=0 and pc==i.address:
                    continue
                pc=i.address
                if cnt<len(leaders)-1:
                    # if cnt==0:
                    #     nodes.append(node(i))
                    if i.address == leaders[cnt+1]:
                        nodes.append(node(i))
                        if add==1:
                            add=0
                            if not (flags & isjmp):
                                control.addedge(node_start,i.address)
                        node_start=i.address
                        cnt+=1
                    out=checkend(i)
                    flags=out[0]
                    if (flags & append): #and (flags & move)
                        control.addedge(node_start,int(out[1],16))
                    if flags & move:
                        add=1
                    nodes[cnt].insert(i)

                else:
                    # print(hex(i.address))
                    if i.address == ender:
                        # print("aaaaaaaaaaaaaaaaaaaaaaaaaaa")
                        nodes[cnt].insert(i)
                        out=checkend(i)
                        flags=out[0]
                        if flags & append:
                            control.addedge(node_start,int(out[1],16))
                        flag=1
                        break
                    elif i.address>ender:
                        flag=1
                        break
                    nodes[cnt].insert(i)

            iter+=1

        def findnode(addr):
            for i in nodes:
                if i.start_addr==addr:
                    return node

        dot=Digraph(node_attr={'shape': 'box'})
        control.makegraph(dot)

        arg1=None
        if len(argv)!=1:
            arg1=argv[1]
        if len(argv)==1 or arg1!="func":
            print("")
            for i in nodes:
                print(i)
            print("node count = "+str(len(leaders)))

        if len(argv)==1:
            dot.render('/tmp/round-table.gv')#, view=True
        elif argv[1]=="-v":
            dot.render('/tmp/round-table.gv', view=True)

        return control.gdict

register_external_command(graph())
