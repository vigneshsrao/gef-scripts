class find(GenericCommand):
    """Dummy new command."""
    _cmdline_ = "find"
    _syntax_  = "{:s}".format(_cmdline_)

    # @only_if_gdb_running         # not required, ensures that the debug session is started
    def do_invoke(self, argv):
        # do anything allowed by gef, for example show the current running
        # architecture as Python object:
        # print(" = {}".format(current_arch) )
        # or showing the current $pc
        def is_readable_string(address):
            """Try to determine if the content pointed by `address` is
            a readable string by checking if:
            * it ends with a null byte (i.e. it is a C-string)
            * each byte is printable"""
            try:
                cstr = read_cstring_from_memory(address)
                return isinstance(cstr, unicode) and cstr and all([x in string.printable for x in cstr])
            except UnicodeDecodeError:
                return False

        def dereference_from(addr):
            if not is_alive():
                return [format_address(addr),]

            code_color = get_gef_setting("theme.dereference_code")
            string_color = get_gef_setting("theme.dereference_string")
            max_recursion = get_gef_setting("dereference.max_recursion") or 10
            addr = lookup_address(align_address(long(int(addr,16))))
            msg = [format_address(addr.value),]
            seen_addrs = set()

            while addr.section and max_recursion:
                if addr.value in seen_addrs:
                    msg.append("[loop detected]")
                    break
                seen_addrs.add(addr.value)

                max_recursion -= 1

                # Is this value a pointer or a value?
                # -- If it's a pointer, dereference
                deref = addr.dereference()
                if deref is None:
                    # if here, dereferencing addr has triggered a MemoryError, no need to go further
                    msg.append(str(addr))
                    break

                new_addr = lookup_address(deref)
                if new_addr.valid:
                    addr = new_addr
                    msg.append(str(addr))
                    continue

                # -- Otherwise try to parse the value
                if addr.section:
                    if addr.section.is_executable() and addr.is_in_text_segment() and not is_readable_string(addr.value):
                        insn = gef_current_instruction(addr.value)
                        insn_str = "{} {} {}".format(insn.location, insn.mnemonic, ", ".join(insn.operands))
                        msg.append(Color.colorify(insn_str, attrs=code_color))
                        break

                    elif addr.section.permission.value & Permission.READ:
                        if is_readable_string(addr.value):
                            s = read_cstring_from_memory(addr.value)
                            if len(s) < get_memory_alignment():
                                txt = '{:s} ("{:s}"?)'.format(format_address(deref), Color.colorify(s, attrs=string_color))
                            elif len(s) >= 50:
                                txt = Color.colorify('"{:s}[...]"'.format(s[:50]), attrs=string_color)
                            else:
                                txt = Color.colorify('"{:s}"'.format(s), attrs=string_color)

                            msg.append(txt)
                            break

                # if not able to parse cleanly, simply display and break
                val = "{:#0{ma}x}".format(long(deref & 0xFFFFFFFFFFFFFFFF), ma=(current_arch.ptrsize * 2 + 2))
                msg.append(val)
                break

            return msg

        def pprint(addr):
            addrs=dereference_from(addr)

            addr_l = format_address(long(addrs[0], 16))
            base_address_color = get_gef_setting("theme.dereference_base_address")
            sep = " {:s} ".format(RIGHT_ARROW)
            memalign = current_arch.ptrsize
            l = "{:s}{:s}+{:#04x}: {:{ma}s}".format(Color.colorify(addr_l, attrs=base_address_color),
                                                     VERTICAL_LINE, 0,
                                                     sep.join(addrs[1:]), ma=(memalign*2 + 2))
            return l

        tmp = argv[0].split("-")
        start_addr=int(tmp[0],16)
        end_addr=int(tmp[1],16)
        reg=argv[1]
        if reg=='code':
            reg=get_filepath()

        def check(addr,region):
            obj=lookup_address(addr)
            if obj.section:
                # print(obj.section)
                sect=lookup_address(addr).section.realpath
                if region in sect:
                    return True
            return False

        lst=[]

        for i in range(start_addr,end_addr,8):
            addr=read_int_from_memory(i)
            if check(addr,reg):
                lst.append(hex(i))

        if len(argv)==3 and argv[2]=='-t':
            for i in lst:
                gef_print(pprint(i))
        else:
            print(lst)



        return

register_external_command(find())
