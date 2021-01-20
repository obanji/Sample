import sys
sys.path.extend(['/home/admin1/Desktop/fuzzingbook/notebooks', '/home/admin1/anaconda3/lib/python37.zip', '/home/admin1/anaconda3/lib/python3.7', '/home/admin1/anaconda3/lib/python3.7/lib-dynload', '/home/admin1/.local/lib/python3.7/site-packages', '/home/admin1/anaconda3/lib/python3.7/site-packages', '/home/admin1/anaconda3/lib/python3.7/site-packages/pyelftools-0.25-py3.7.egg', '/home/admin1/anaconda3/lib/python3.7/site-packages/IPython/extensions', '/home/admin1/.ipython'])
sys.path.append('.')
import matplotlib.pyplot
matplotlib.pyplot._IP_REGISTERED = True # Hack
import fuzzingbook_utils
import fuzzingbook
from fuzzingbook.GrammarMiner import CallStack
import jsonpickle
import os, subprocess
import gdb
import re, json

CALL = 'callq'
RETURN = 'retq'
LINE = 'line'
ARG_REGISTERS = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9', 'edi', 'rbx']
REGISTERS = ARG_REGISTERS + ['rax', 'eax', 'edi' 'esi', 'edx', 'ecx', 'rsp', 'rbp']
UNWANTED = [
    'leaveq', 'retq', 'nop', 'je', 'jne', 'jmp', 'jle', 'jmpq', 'jae', 'jbe',
    'cltq', 'ja', 'jb', 'js'
]
FRAGMENT_LEN = 1

class Instruction:
    def __init__(self, instr):
        self.symbol_name = None
        self.pointed_address = None
        self.dest_reg = None
        self.instr_type = None
        self._parse(instr)
class Instruction(Instruction):
    def get_pointed_value(self, val):
        val = val.strip('%*')
        if val in REGISTERS:
            ptr_addr = gdb.execute('x/s $%s' % (val),
                                to_string=True).split(':')
            return ptr_addr[0]
        return val
class Instruction(Instruction):
    def resolve_addressing_mode(self, instr):
        str0 = instr.split(',')
        if len(str0) > 2:
            pass

        src = str0[-1]
        if '(' not in src:
            if src[1:] in REGISTERS:

                return '$%s' % src[1:]
        else:
            if src.startswith('-'):
                displacement, rest = tuple(src.split('(%'))
                return '$%s%s' % (rest[:-1], displacement)
            elif src.startswith('(') and src.endswith(')'):
                return '$%s' % src[2: -1]
            else:
                displacement, rest = tuple(src.split('(%'))
                return '$%s+%s' % (rest[:-1], displacement)

class Instruction(Instruction):
    def resolve_arithmetic_operations(self, instr, op):
        s, d = tuple(instr.split(','))

        if s[1:] in REGISTERS and d[1:] in REGISTERS:
            return '$%s+$%s' % (s[1:], d[1:]) if op.startswith('add') else \
                '$%s-$%s' % (s[1:], d[1:])
        elif s.startswith('-') and d[1:] in REGISTERS:
            s0 = self.resolve_addressing_mode(instr)
            return '%s+$%s' % (s0, d[1:]) if op.startswith('add') else \
                '%s-$%s' % (s0, d[1:])
        elif d.startswith('-') and s[1:] not in REGISTERS:
            s1 = '%s,%s' % (d, s)
            return self.resolve_addressing_mode(s1)
        else:
            return '$%s+%s' % (d[1:], s[1:]) if op.startswith('add') else \
                '$%s-%s' % (d[1:], s[1:])
class Instruction(Instruction):
    def _parse(self, instr):
        instr_list = instr.split()
        instr_list.pop(0)

        self.current_address = instr_list[0]
        if "<" in instr_list[1]:
            instr_list.pop(1)
        self.instr_type = instr_list[1]

        if self.instr_type == CALL:
            self.pointed_address = self.get_pointed_value(instr_list[2])
            if len(instr_list) > 3:
                self.symbol_name = instr_list[-1]

        elif self.instr_type.startswith('mov') or self.instr_type == 'push' or \
            self.instr_type == 'pop':
            self.dest_reg = self.resolve_addressing_mode(instr_list[2])

def get_names_from_symbols(objfile):
    names = []
    for name in objfile:
        name = name.split()
        name = name[-1].decode('utf-8')
        if '@@' in name:
            names.append(name.split('@@')[0])
            continue
        names.append(name)
    return names

def list_objfile_symbols():
    proc = subprocess.Popen(['nm', 'a.out'], stdout=subprocess.PIPE)
    output = proc.stdout.read()
    output = output.splitlines()
    return output

def get_function_names(inp, binary):
    fn_dict = {}
    fn_names = []

    symbols = list_objfile_symbols()
    functions = get_names_from_symbols(symbols)

    gdb.execute("set args '%s'" % inp)
    gdb.execute("file %s" % binary)
    gdb.execute('set confirm off')
    gdb.execute('run')
    for k in functions:
        try:
            s = gdb.execute('info address %s' % k,
            to_string=True).split(' ')
            if s[4].startswith('0x'):
                v = s[4].rstrip()
                u = v.strip('.')
                fn_dict[v] = k
            else:
                u = s[-1].rstrip()
                u = u.strip('.')
                fn_dict[u] = k
        except gdb.error:
            continue
    return fn_dict
class BinaryDebugger:
    def __init__(self, inp, binary, fn_list):
        self.inp = inp
        self.binary = binary
        self.functions = fn_list
        self._set_logger()
        self.tree = {}
        self.mid = None
class BinaryDebugger(BinaryDebugger):
    def break_at(self, address):
        gdb.execute("break *%s" % address)
    def finish(self):
        gdb.execute('finish')
    def get_instruction(self):
        return gdb.execute('x/i $rip', to_string=True)
    def nexti(self):
        gdb.execute('nexti')
    def resume(self):
        gdb.execute('continue')
    def run(self):
        gdb.execute('run')
    def step(self):
        gdb.execute('stepi')
    def start_program(self):
        gdb.execute("set args '%s'" % self.inp)
        gdb.execute("file %s" % self.binary)
    def in_scope(self, instr, addr_range):
        s1, e1, s2, e2 = addr_range
        instr = instr.split()
        instr.pop(0)

        current_addr = instr[0].strip(':')
        hex_val = int(current_addr, 16)
        if hex_val in range(int(s1, 16), int(e1, 16)) or \
            hex_val in range(int(s2, 16), int(e2, 16)):
            return True
        else:
            return False

class BinaryDebugger(BinaryDebugger):
    def get_entry_address(self):
        self.start_program()
        self.run()

        info_file = gdb.execute('info file', to_string=True)
        entry = None

        for line in info_file.splitlines():
            if 'Entry point' in line:
                entry = line.split(':')[1]
                break
        return entry
class BinaryDebugger(BinaryDebugger):
    def _set_logger(self):
        gdb.execute('set logging overwrite on')
        gdb.execute('set logging redirect on')
        gdb.execute('set logging on')

class BinaryDebugger(BinaryDebugger):
    def get_address_range(self):
        s1 = s2 = None
        e1 = e2 = None
        mappings = gdb.execute('info proc mappings', to_string=True)

        for i, line in enumerate(mappings.splitlines()):
            if i == 4:
                s1 = line.split()[0]
            elif i == 6:
                e1 = line.split()[1]
            elif i == 7:
                s2 = line.split()[0]
            elif i == 10:
                e2 = line.split()[1]
        return (s1, e1, s2, e2)

class BinaryDebugger(BinaryDebugger):
    def get_main_address(self):
        entry = self.get_entry_address()
        self.break_at(entry)
        gdb.execute('run')

        instr = []
        while True:
            next_i = self.get_instruction()
            if CALL in next_i:
                break
            instr.append(next_i)
            self.step()

        instr = instr[-1].split()
        if len(instr) == 6:
            s = instr[3]
        else:
            s = instr[4]

        reg = s[-3:]
        main_addr = gdb.execute('p/x $%s' % reg, to_string=True)
        main_addr = main_addr.partition("= ")
        main_addr = main_addr[-1]

        return main_addr
class BinaryDebugger(BinaryDebugger):
    def lookup_address(self, addr, symbol):
        addr = addr.rstrip("\n")
        if addr in self.functions.keys():
            return self.functions[addr]
        else:
            if symbol:
                s0 = symbol[1:-1].split('@')[0]
                return s0
            return None

trace = []
inp_arr = []
from collections import defaultdict
dictdict = defaultdict(set)
dd = defaultdict(set)

class BinaryDebugger(BinaryDebugger):
    def event_loop(self):
        main = self.get_main_address()
        mname = self.lookup_address(main, None)
        cs = CallStack()
        cs.enter(mname)

        method_map = {'0':[0, None, [1]], '1': [1, mname, []]}
        m_stack = ['0', '1']
        comparisons = []
        count = 0
        result = {'inputstr': self.inp}

        self.break_at(main)
        self.resume()
        addr_range = self.get_address_range()
        nexti = ''
        inp_arr = []
        val_tuple = []
        var_dict = []

        while True:
            try:
                nexti = self.get_instruction()
                if self.in_scope(nexti, addr_range):
                    h = Instruction(nexti)
                    if h.instr_type == CALL:
                        name = self.lookup_address(h.pointed_address, h.symbol_name)
                        if not name:
                            self.step()
                            self.finish()
                            continue
                        else:
                            self.step()
                            cs.enter(name)
                            x, self.mid = cs.method_id
                            method_map[m_stack[-1]][-1].append(self.mid)
                            method_map[str(self.mid)] = [self.mid, name, []]
                            m_stack.append(str(self.mid))
                    elif h.instr_type == RETURN:
                        self.step()
                        cs.leave()
                        if len(m_stack) > 1:
                            m_stack.pop()
                    else:
                        self.step()
                        val = read_register_val(h.dest_reg, self.inp)

                        if val and len(val) > 1 and self.mid != None and val != self.inp:
                            count = self.inp.count(val)
                            if count > 1:
                                dd[val].add(self.mid)
                            else:
                                idx = self.inp.index(val)
                                for idx in range(idx, idx + len(val)):
                                    comparisons.append([idx, self.inp[idx], self.mid])
                                    pass
                        elif val and len(val) == 1:
                            inp_arr.append(val)
                            x = ''.join(inp_arr)
                            if self.inp.startswith(x):
                                # print(x, self.mid)
                                idx = len(inp_arr) - 1
                                comparisons.append([idx, val, self.mid])
                            else:
                                inp_arr.pop()
                else:
                    self.finish()
            except gdb.error:
                break
        result['method_map'] = method_map
        result['comparisons'] =  process_fragment_gr_one(dd, self.inp, comparisons)
        trace.append(result)
        with open('tree', 'w+') as f:
            print(trace, file=f)


def read_reg(reg, inputstr):
    if not reg:
        return None

    str0 = gdb.execute('x/s %s' % (reg), to_string=True)
    
    if 'error' in str0:
        return None

    for idx, char in enumerate(str0):
        if str0[idx] == ':':
            str_val = str0[idx + 1:]
            str_val = str_val.strip()
            break
    
    if str_val in inputstr:
        return str_val
    return str_val[1:-1] if str_val[1:-1] in inputstr else None 
def read_register_val(reg, original):
    if not reg:
        return None

    val = read_as_string(reg)
    if not val:
        return None
    if val == '""':
        a = read_ptr_addr(reg)
        return read_register_val(a, original)
    elif val in original:
        return val
    else:
        x = val[1: -1] if val[0] == '"' and val[-1] == '"' else val
        return x if x in original else None
def read_ptr_addr(reg):
    try:
        str1 = gdb.execute('x/a %s' % (reg), to_string=True)
        for idx, char in enumerate(str1):
            if str1[idx] == ':':
                addr_val = str1[idx + 1:]
                addr_val = addr_val.strip()
                break
        return addr_val
    except Exception:
        return
def read_as_string(reg):
    try:
        str0 = gdb.execute('x/s %s' % (reg), to_string=True)
        if '<error:' in str0 and not reg.startswith('0x'):
            x = gdb.execute('p/c %s' % reg, to_string=True)
            x = x.split()
            x = x[-1]
            return x[1:-1]

        for idx, char in enumerate(str0):
            if str0[idx] == ':':
                str_val = str0[idx + 1:]
                str_val = str_val.strip()
                break
        return str_val
    except Exception:
        return
def is_fragment(val):
    return len(val) == FRAGMENT_LEN
def process_fragment_len_one(ddict, original):
    comparisons = []
    for key in ddict.keys():
        indexes = [i for i, c in enumerate(original) if c == key]
        x = len(list(ddict[key])) // len(indexes)
        
        mids = list(ddict[key])
        mids.sort(key= lambda x: x)

        start = 0
        for index in indexes: 
            if index == indexes[-1]:
                remainder = len(list(ddict[key])) % len(indexes)
                x += remainder
            
            for i in range(start, x + start):
                comparisons.append([index, key, mids[i]])

            start += x
    comparisons.sort(key= lambda x: x[0])
    return comparisons
def process_fragment_gr_one(ddict, original, comparisons):
   
    for key in ddict.keys():
        matches = re.finditer(key, original)
        indexes = [match.start() for match in matches]
        
        mids = list(ddict[key])
        mids.sort(key= lambda x: x)

        x = len(list(ddict[key])) // len(indexes)
        start = 0
        for index in indexes:
            if index == indexes[-1]:
                remainder = len(list(ddict[key])) % len(indexes)
                x += remainder
            
            for j in range(start, x + start):
                for i in range(index, index + len(key)):
                    comparisons.append([i, original[i], mids[j]])        
            start += x
    return comparisons
arg_0 = None
with open(f'inp.0.txt', 'r+') as f:
    arg_0 = f.read().strip()

fnames = get_function_names(arg_0, "a.out")
subprocess.call(['strip', '-s', "a.out"])

debugger = BinaryDebugger(arg_0, 'a.out', fnames)
debugger.event_loop()





