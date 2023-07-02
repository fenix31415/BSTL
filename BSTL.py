import clipboard
from ida_bytes import *
from ida_struct import *
import ida_hexrays
from idautils import *
from idaapi import *
from idc import *
import re

from Levenshtein import distance
from collections import defaultdict
from itertools import chain

## --- SETTINGS --- ##

name = 'BSTL'

## ^^^ SETTINGS ^^^ ##



## --- COMMON --- ##


def log(msg, error = False):
    print(f'[{name}] [{"ERROR" if error else "INFO"}]: {msg}')


def set_type(ea, type_str):
    _type = parse_decl(type_str, 0)  
    apply_type(ea, _type, idc.TINFO_DEFINITE)


def bigendian(val):
  little_hex = bytearray.fromhex(val)
  little_hex.reverse()
  str_little = ''.join(format(x, '02x') for x in little_hex)
  return str_little


def try_str2tif(type_str, silent=False):
    if type_str[-1] != ';':
        type_str = type_str + ';'

    tinfo = tinfo_t()
    if idaapi.parse_decl(tinfo, get_idati(), type_str, PT_SILENT if silent else 0) == None:
        return None
    return tinfo
    

def str2tif(type_str):
    tinfo = try_str2tif(type_str, True)
    assert tinfo != None and tinfo.is_correct(), f'Wrong type {type_str}'
    return tinfo


def append_member(sid, mem_name, mem_size, type_str):
    def set_member_type_str(strid, mem_name, tinfo):
        sptr = get_struc(strid)
        mptr = get_member_by_name(sptr, mem_name)
        if tinfo != None:
            assert tinfo.is_correct(), f'Wrong type {type_str}'
            set_member_tinfo(sptr, mptr, 0, tinfo, SET_MEMTI_COMPATIBLE | SET_MEMTI_MAY_DESTROY)
    
    pad = 1
    if mem_size % 2 == 0:
        pad = 2
    if mem_size % 4 == 0:
        pad = 4
    if mem_size % 8 == 0:
        pad = 8
    
    struc_size = get_struc_size(sid)
    needed_strict_size = ((struc_size - 1) // pad + 1) * pad
    rest = needed_strict_size - struc_size
    
    if rest > 0:
        idc.add_struc_member(sid, f'__pad{struc_size}', struc_size, FF_DATA, -1, rest)
    
    idc.add_struc_member(sid, mem_name, -1, FF_DATA, -1, mem_size)
    if type_str != '':
        set_member_type_str(sid, mem_name, str2tif(type_str))


## -- ASM -- ##


def get_func_bounds(funcea):
    for (startea, endea) in Chunks(funcea):
        return endea
    return None


def get_func_asm(startea):
    endea = get_func_bounds(startea)
    if endea:
        return get_bytes(startea, endea - startea, False).hex()
    else:
        return ''


def get_call_ea(ins):
    cmd = idc.GetDisasm(ins)
    if 'qword' in cmd:
        return None
    
    jmp_offset = None
    offset = None
    
    opcode = get_bytes(ins, get_item_size(ins), False).hex()
    if opcode.startswith('ff15'):
        jmp_offset = int(bigendian(opcode[4:]), 16)
        offset = 6
    
    if opcode.startswith('e8'):
        jmp_offset = int(bigendian(opcode[2:]), 16)
        offset = 5
    
    if jmp_offset != None:
        if jmp_offset > 0xf0000000:
            jmp_offset = -(0xffffffff - jmp_offset + 1)
        call_ea = ins + jmp_offset + offset
        return call_ea
    
    return None


def get_size(data):
    sizes_map = {
        '488d0c40': 3,
        '488d0c80': 5,
        '488d0cc0': 9,

        '488d0c48': 2,
        '488d0c88': 4,
        '488d0cc8': 8,
        
        '488d0c81': 4,
        '498d0488': 4,
        '498d04c8': 8,
        '488d0cc1': 8,
        
        '4d8d0489': 4,
        '4d8d04c9': 8,
        
        '4b8d04d2': 9,
        '4b8d0452': 3,
        
        '418b01': 4,
        '498b01': 8,
        
        '0fb708': 2,
        '0fb608': 1
    }

    assert data in sizes_map, f'unknown opcode {data}'
    
    return sizes_map[data]


## ^^ ASM ^^ ##


## ^^^ COMMON ^^^ ##


TYPES_BSTArray = 'BSTArray'
TYPES_BSScrapArray = 'BSScrapArray'
TYPES_BSTSmallArray = 'BSTSmallArray'
TYPES_BSTHashMap = 'BSTHashMap'
TYPES_BSTSet = 'BSTSet'
TYPES_BSTStaticHashMap = 'BSTStaticHashMap'
TYPES_BSTScrapHashMap = 'BSTScrapHashMap'
TYPES_None = 'TYPES_None'

FUNCT_begin = 'begin'
FUNCT_rend = 'rend'
FUNCT_rbegin = 'rbegin'
FUNCT_end = 'end'
FUNCT_resize = 'resize'
FUNCT_erase = 'eraseAt'
FUNCT_erase1 = 'eraseMany'
FUNCT_erase2 = 'eraseVal'
FUNCT_push_back = 'push_back'
FUNCT_reserve_push_backs = 'reserve_push_backs'
FUNCT_reserve_push_backs2 = 'reserve_push_backs2'
FUNCT_get_free_entry = 'get_free_entry'
FUNCT_insert = 'insert'
FUNCT_insert1 = 'insert1'
FUNCT_find = 'find'
FUNCT_find1 = 'find1'
FUNCT_find2 = 'find2'
FUNCT_double = 'double'
FUNCT_None = 'FUNCT_None'

ACTION_MODES_inplace = 'inplace'  # Use it while developing
ACTION_MODES_export = 'export'    # Create _data file
ACTION_MODES_import = 'import'    # Import _data file
ACTION_MODES_none = 'none'        # Run through all functions and do nothing (calc stats)

function_data = dict()
structs_data = set()

action_mode = ACTION_MODES_import


class Stats:
    def __init__(self):
        self.data = defaultdict(int)
    
    def __str__(self):
        return f'{self.detected}/{self.total}'
    
    def add(self, name):
        self.data[name] += 1
    
    def get_stats(self):
        print(f'STATS: ({sum(self.data.values())} total)')
        for k, v in sorted(self.data.items(), key=lambda x: -x[1]):
            print(f'  {k}: {v}')

stats = Stats()


class DebugInfo:
    def __init__(self, key):
        self.data = dict()
        self.key = key
    
    def add(self, startea, data):
        self.data[startea] = data
    
    def __str__(self):
        data_sorted = sorted(self.data.items(), key=self.key)
        return "\n".join(map(lambda var: f'({var[0]:x}, {var[1]})', data_sorted))


"""
Sets type and name for a function. Handles different modes.
"""
def set_type_name(startea, func_name, func_type, unique=True):
    if action_mode != ACTION_MODES_import:
        stats.add(func_name)
    
    if action_mode == ACTION_MODES_inplace or action_mode == ACTION_MODES_export:
        func_name = f'{func_name}_{hex(startea)[4:]}' if unique else func_name
    
    if action_mode == ACTION_MODES_inplace or action_mode == ACTION_MODES_import:
        set_name(startea, func_name)
        set_type(startea, func_type)
    elif action_mode == ACTION_MODES_export:
        function_data[startea] = (func_name, func_type)


## --- NAMES --- ##

"""
Returns ready-to-use item name. Creates structs, if needed.
E.g. uint32 or BSTStructs::Item12
"""
def get_struct_item_name(value_size):
    def get_field_type_by_size(size):
        assert size in [1,2,4,8]
        return f'uint{size * 8}'
    
    def get_struct_item_name_(size):
        return f'BSTStructs::Item{size}'
    
    """
    Returns name (and create struct) of custom size structs item
    """
    def create_struct_item(size):
        name = get_struct_item_name_(size)
        if get_struc_id(name) == 0xffffffffffffffff:
            struct_item, name = initialize_struct(name, False)
            append_member(struct_item, "data", size, '')
        return name
    
    if value_size == 0:
        return 'void'

    if value_size in [1,2,4,8]:
        return get_field_type_by_size(value_size)
    
    return create_struct_item(value_size)

"""
E.g. BSTArray5 or BSTSmallArray_4_8
"""
def get_array_name(struct_type, size):
    if type(size) == tuple:
        assert len(size) == 2
        size1, size2 = size
        return f'{struct_type}{size1}_{size2}'
    else:
        if size > 0:
            return f'{struct_type}{size}'
        else:
            return f'{struct_type}'

"""
Size also may be layout suffix.
E.g. BSTHashMap8 or BSTHashMapK4V8
"""
def get_map_name(struct_type, size):
    if type(size) == str:
        return f'{struct_type}{get_map_name_suff(size)}'
    elif type(size) == tuple:
        assert len(size) == 2
        size1, size2 = size
        return f'{struct_type}K{size1}V{size2}'
    else:
        return f'{struct_type}{size}'

"""
E.g. BSTHashMap8::Internal or BSTHashMapK4V8::Internal
"""
def get_map_internal_name(struct_type, size):
    return f'{get_map_name(struct_type, size)}::Internal'

"""
E.g. BSTHashMap8::entry_type or BSTHashMapK4V8::entry_type
"""
def get_map_entry_name(struct_type, size):
    return f'{get_map_name(struct_type, size)}::entry_type'

"""
E.g. BSTScatterTableHeapAllocator8::entry_type or BSTScatterTableHeapAllocatorK4V8::entry_type
"""
def get_map_allocator_name(name_struct_base, size):
    base_name = 'BSTScatterTableHeapAllocator'
    if name_struct_base == TYPES_BSTScrapHashMap:
        base_name = 'BSTScatterTableScrapAllocator'
    if type(size) == str:
        return f'{base_name}{get_map_name_suff(size)}'
    elif type(size) == tuple:
        assert len(size) == 2
        size1, size2 = size
        return f'{base_name}K{size1}V{size2}'
    else:
        return f'{base_name}{size}'

"""
E.g. BSTHashMap8::iterator or BSTHashMapK4V8::iterator
"""
def get_map_iterator_name(struct_type, size):
    return f'{get_map_name(struct_type, size)}::iterator'

LAYOUTS_KEYS = ['k', 'K', 'x', 'X', 'c', 'C', '!', '@', '#', '$', '%', '^']

def get_map_name_suff(layout):
    ans = ''
    def add_field(l, r, c):
        nonlocal ans
        
        size = r - l
        name = ''
        if c == '.':
            name = ''
        elif c in LAYOUTS_KEYS:
            name = 'K'
        elif c == 's':
            name = ''
        else:
            name = 'V'
        
        if name != '':
            ans = f'{ans}{name}{size}'
        
        return False
    
    maps_iterate_layout(layout, add_field)
    
    return ans

def get_map_key_name(struct_type, size):
    if type(size) == str:
        layout = size
        ind_key, _, _, _ = split_layout(layout)
        is_simple, size = is_simple_layout(layout[0:ind_key])
        if is_simple:
            return get_struct_item_name(size)
        else:
            return f'{get_map_name(struct_type, layout)}::key_t'
    else:
        if type(size) == tuple:
            assert len(size) == 2
            size, value_size = size
        return get_struct_item_name(size)

def get_map_val_name(struct_type, size):
    if type(size) == str:
        layout = size
        _, ind_key_pad, ind_val, _ = split_layout(layout)
        is_simple, size = is_simple_layout(layout[ind_key_pad:ind_val])
        if is_simple:
            return get_struct_item_name(size)
        else:
            return f'{get_map_name(struct_type, layout)}::val_t'
    else:
        if type(size) == tuple:
            assert len(size) == 2
            _, size = size
        return get_struct_item_name(size)


## ^^^ NAMES ^^^ ##



## --- CREATING STRUCTS --- ##

"""
if forceNew: create struct with unique name (add suffix)
else: clear current structure (if not exists) or create new one
returns (sid, name)
"""
def initialize_struct(name, forceNew, enum=0):
    def get_unique_name(name):
        prefix = name
        sid = get_struc_id(prefix)
        if sid == BADADDR:
            return prefix
        
        i = 0
        while sid != BADADDR:
            i += 1
            prefix = name + f'_{i}'
            sid = get_struc_id(prefix)
        return name + f'_{i}'

    sid = get_struc_id(name)
    if sid == BADADDR:
        return (add_struc(-1, name, enum), name)
    
    if forceNew:
        name = get_unique_name(name)
        return (add_struc(-1, name, enum), name)
    else:
        del_struc_members(get_struc(sid), 0, BADADDR)
        set_struc_align(get_struc(sid), 0)
        return (sid, name)
    

# - CREATING MAP ITEMS STRUCTS - #

def parse_layout_key(layout):
    fields = list()
    
    def add_field(l, r, c):
        size = r - l
        name = ''
        if c == '.':
            name = f'__pad{l}'
        elif c in LAYOUTS_KEYS:
            name = f'key_{l}'
        else:
            return True
        
        fields.append((name, size))
    
    maps_iterate_layout(layout, add_field)
    
    return fields

def parse_layout_val(layout):
    fields = list()

    def add_field(l, r, c):
        active = False
        
        size = r - l
        name = ''
        if c == '.':
            name = f'__pad{l}'
        elif c in LAYOUTS_KEYS:
            pass
        elif c == 's':
            return False
        else:
            active = True
            name = f'val_{l}'
        
        if active:
            fields.append((name, size))
        
        return False
    
    maps_iterate_layout(layout, add_field)
    
    return fields

"""
Calls `bool add_field(l, r, c)` function every field. If add_field returns True, iteration stops.
"""
def maps_iterate_layout(layout, add_field):
    l = 0
    size = len(layout)
    while l < size:
        r = l
        while r < size and layout[l] == layout[r]:
            r += 1
        add_field(l, r, layout[l])
        
        l = r

def split_layout(layout):
    ans_key = -1
    ans_val = -1
    ans_key_pad = -1
    ans_val_pad = -1
    
    state = 'k'
    
    def add_field(l, r, c):
        nonlocal ans_key, ans_val, ans_key_pad, ans_val_pad, state
        
        if c == '.':
            if state == 'k':
                state = 'k.'
            elif state == 'v':
                state = 'v.'
            else:
                state = '.'
        elif c in LAYOUTS_KEYS:
            ans_key = r
            ans_key_pad = ans_key
            state = 'k'
        elif c == 's':
            if state == 'v.':
                ans_val_pad = l
            state = 's'
        else:
            if state == 'k.':
                ans_key_pad = l
            
            ans_val = r
            ans_val_pad = ans_val
            state = 'v'
    
    maps_iterate_layout(layout, add_field)
    
    if ans_val == -1:
        ans_val = ans_key_pad
        ans_val_pad = ans_val
    
    #return f'{layout[0:ans_key]}-{layout[ans_key:ans_key_pad]}-{layout[ans_key_pad:ans_val]}-{layout[ans_val:ans_val_pad]}-{layout[ans_val_pad:]}'
    
    return (ans_key, ans_key_pad, ans_val, ans_val_pad)


def test_split_layout():
    def test_(layout, expected):
        ind_key, ind_key_pad, ind_val, ind_val_pad = split_layout(layout)
        actual = f'{layout[0:ind_key]}-{layout[ind_key:ind_key_pad]}-{layout[ind_key_pad:ind_val]}-{layout[ind_val:ind_val_pad]}-{layout[ind_val_pad:]}'
        assert expected == actual, f'{layout}: {expected} != {actual}'
        print(f'OK: {layout}')
    
    test_('kkkkkkkk11111111ssssssss', 'kkkkkkkk--11111111--ssssssss')
    test_('k.......11111111ssssssss', 'k-.......-11111111--ssssssss')
    test_('kkkkkkkk1.......ssssssss', 'kkkkkkkk--1-.......-ssssssss')
    
    test_('kkkkK...11111111ssssssss', 'kkkkK-...-11111111--ssssssss')
    test_('kkkkK...12......ssssssss', 'kkkkK-...-12-......-ssssssss')
    test_('kkkkkkkk1.22....ssssssss', 'kkkkkkkk--1.22-....-ssssssss')
    
    test_('k.......KKKKKKKK1.......ssssssss', 'k.......KKKKKKKK--1-.......-ssssssss')
    
    test_('kkkkkkkkssssssss', 'kkkkkkkk----ssssssss')
    test_('k.KK....xxxxxxxxX.......111111112...33334.......ssssssss', 'k.KK....xxxxxxxxX-.......-111111112...33334-.......-ssssssss')

"""
Has 1 entry with size of 1,2,4,8
"""
def is_simple_layout(layout):
    field_count = 0
    ok_size = True
    size = 0
    def add_field(l, r, c):
        nonlocal field_count, ok_size, size
        
        field_count += 1
        size = r - l
        ok_size = ok_size and size in [1,2,4,8]
        
    maps_iterate_layout(layout, add_field)
    
    return (ok_size and field_count == 1, size)

def create_map_entry_type_layout(name_struct, name_key, name_val, layout, forceNew):
    def creator_(name, layout, forceNew):
        sid, name = initialize_struct(name, forceNew)
        
        def add_field(l, r, c):
            size = r - l
            name = ''
            if c == '.':
                name = f'__pad{l:x}'
            elif c in LAYOUTS_KEYS:
                name = f'key_{l:x}'
            elif c == 's':
                return
            else:
                name = f'val_{l:x}'
            
            append_member(sid, name, 1, '' if name.startswith('__pad') else get_struct_item_name(size))
        
        maps_iterate_layout(layout, add_field)
        
        return name
    
    def creator(name, layout, forceNew):
        is_simple, size = is_simple_layout(layout)
        if is_simple:
            return get_struct_item_name(size)
        
        return creator_(name, layout, forceNew)
    
    ind_key, ind_key_pad, ind_val, ind_val_pad = split_layout(layout)
    
    name_key = creator(name_key, layout[0:ind_key], forceNew)
    if ind_key_pad != ind_val:
        name_val = creator(name_val, layout[ind_key_pad:ind_val], forceNew)
    
    sid, name_struct = initialize_struct(name_struct, forceNew)
    
    append_member(sid, 'key', 1, name_key)
    
    pad_size = ind_key_pad - ind_key
    if pad_size != 0:
        append_member(sid, f'__pad{ind_key:x}', pad_size, '')
    
    if ind_key_pad != ind_val:
        append_member(sid, 'val', 1, name_val)
    
    pad_size = ind_val_pad - ind_val
    if pad_size != 0:
        append_member(sid, f'__pad{ind_val:x}', pad_size, '')
    
    append_member(sid, "next", 8, f'{name_struct} *')
    
    return name_struct

# ^ CREATING MAP ITEMS STRUCTS ^ #


def create_typed_BSTArray(element_type = '', forceNew=True):
    def content_to_name(content):
        content = content.replace("const", "")
        content = content.strip()
        content = content.replace("*", "_")
        content = content.replace(" ", "")
        return content
    
    def check_allocator(sid, heap_tif):
        if get_struc_size(sid) != 0x10:
            log('wrong allocator size')
            return False
        
        if idc.get_member_size(sid, 0x8) != 0x4:
            log('wrong cap size')
            return False
        
        struc = get_struc(sid)
        memb = get_member(struc, 0x0)
        tif = tinfo_t()
        ida_hexrays.get_member_type(memb, tif)
        if str(heap_tif) != str(tif):
            log(f'bad heap type {str(heap_tif)} != {str(tif)}')
            return False
        
        return True

    def check_array(sid, heap_tif):
        size = get_struc_size(sid)
        if size != 0x18:
            log('wrong array size')
            return False
        
        if get_struc_name(get_member_strid(sid, 0x10)) != 'BSTArrayBase':
            log('bad array base')
            return False
        
        sid_allocator = get_member_strid(sid, 0x0)
        if not check_allocator(sid_allocator, heap_tif):
            return False
        
        return True

    
    if element_type == '':
        element_type = str(clipboard.paste())
    
    if try_str2tif(element_type) == None:
        log(f'unk element type "{element_type}", see message before', True)
        return
    
    name = content_to_name(element_type)
    name_array = f'BSTArray_{name}_'
    name_arraybase = f'BSTArrayHeapAllocator_{name}_'
    type_alloc_heap = f'{element_type} *'
    
    sid = get_struc_id(name_array)
    
    if sid != 0xffffffffffffffff:
        log(f'Found already defined struct {name_array}')
        if check_array(sid, str2tif(type_alloc_heap)):
            log(f'It is array, skipping')
            return
    
    log(f'Creating new {name_array}')
    
    array_base, name_arraybase = initialize_struct(name_arraybase, forceNew)
    append_member(array_base, "heap", 8, type_alloc_heap)
    append_member(array_base, "capacity", 4, 'uint32')
    append_member(array_base, "padC", 4, 'uint32')
    
    array, name_array = initialize_struct(name_array, forceNew)
    append_member(array, "allocator", 0x10, name_arraybase)
    append_member(array, "base", 4, 'BSTArrayBase')
    append_member(array, "pad14", 4, 'uint32')


def create_sized_BSTArray(size, forceNew=True):
    name_alloc = get_array_name('BSTArrayHeapAllocator', size)
    name_array = get_array_name('BSTArray', size)
    
    if not forceNew:
        if get_struc_id(name_array) != BADADDR:
            return
    
    array_alloc, name_alloc = initialize_struct(name_alloc, forceNew)
    append_member(array_alloc, "data", 8, f'{get_struct_item_name(size)} *')
    append_member(array_alloc, "capacity", 4, 'uint32')
    append_member(array_alloc, "padC", 4, 'uint32')
    
    array, name_array = initialize_struct(name_array, forceNew)
    append_member(array, "allocator", 0x10, name_alloc)
    append_member(array, "base", 4, 'BSTArrayBase')
    append_member(array, "pad14", 4, 'uint32')

def create_sized_ScrapArray(size, forceNew=True):
    name_alloc = get_array_name('BSScrapArrayAllocator', size)
    name_array = get_array_name('BSScrapArray', size)
    
    if not forceNew:
        if get_struc_id(name_array) != BADADDR:
            return
    
    array_alloc, name_alloc = initialize_struct(name_alloc, forceNew)
    append_member(array_alloc, "allocator", 8, 'ScrapHeap *')
    append_member(array_alloc, "data", 8, f'{get_struct_item_name(size)} *')
    append_member(array_alloc, "capacity", 4, 'uint32')
    append_member(array_alloc, "pad14", 4, 'uint32')
    
    array, name_array = initialize_struct(name_array, forceNew)
    append_member(array, "allocator", 0x18, name_alloc)
    append_member(array, "base", 4, 'BSTArrayBase')

def create_sized_SmallArray(size, forceNew=True):
    name_alloc = get_array_name('BSTSmallArrayHeapAllocator', size)
    name_data = f'{name_alloc}::Data'
    name_array = get_array_name('BSTSmallArray', size)
    
    if not forceNew:
        if get_struc_id(name_array) != BADADDR:
            return
    
    item_size, static_size = size
    name_item = get_struct_item_name(item_size)
    
    array_data, name_data = initialize_struct(name_data, forceNew, 1)
    append_member(array_data, "heap", 8, f'{name_item} *')
    append_member(array_data, "local", 1, f'{name_item} [{static_size // item_size}]')
    
    data_size = get_struc_size(array_data)
    
    array_alloc, name_alloc = initialize_struct(name_alloc, forceNew)
    append_member(array_alloc, "capacity_n_flag", 4, "uint32")
    append_member(array_alloc, "pad4", 4, "uint32")
    append_member(array_alloc, "data", data_size, name_data)
    set_struc_align(get_struc(array_alloc), 3)
    
    alloc_size = data_size + 0x8
    
    array, name_array = initialize_struct(name_array, forceNew)
    append_member(array, "allocator", alloc_size, name_alloc)
    append_member(array, "base", 4, "BSTArrayBase")
    append_member(array, "pad14", 4, "uint32")


def create_sized_BSTHashTable(name_struct_base, size, forceNew=True):
    name_map = get_map_name(name_struct_base, size)
    name_entry_type = get_map_entry_name(name_struct_base, size)
    
    if not forceNew:
        if get_struc_id(name_map) != BADADDR:
            return
    
    map_, name_map = initialize_struct(name_map, forceNew)
    
    def create2(size, forceNew):
        nonlocal name_entry_type
        
        key_size, value_size = size
        
        entry_type, name_entry_type = initialize_struct(name_entry_type, forceNew)
        append_member(entry_type, "key", key_size, get_struct_item_name(key_size))
        append_member(entry_type, "value", value_size, get_struct_item_name(value_size))
        append_member(entry_type, "next", 8, f'{name_entry_type} *')
        
        return name_entry_type
    
    def create(size, forceNew):
        nonlocal name_entry_type
        
        kv_size = size
        assert kv_size % 8 == 0, f'create BSTHashMap: {kv_size} % 8 != 0'

        name_keyvalue = f'{name_map}::keyvalue'
        
        keyvalue, name_keyvalue = initialize_struct(name_keyvalue, forceNew)
        append_member(keyvalue, "data", kv_size, '')
        
        entry_type, name_entry_type = initialize_struct(name_entry_type, forceNew)
        append_member(entry_type, "keyvalue", kv_size, name_keyvalue)
        append_member(entry_type, "next", 1, f'{name_entry_type} *')
        
        return name_entry_type
    
    def createLayout(size, forceNew):
        nonlocal name_entry_type
        
        layout = size
        
        name_entry_type = create_map_entry_type_layout(name_entry_type, get_map_key_name(name_struct_base, layout), get_map_val_name(name_struct_base, layout), layout, forceNew)
        
        return name_entry_type
    
    def createSet(size, forceNew):
        nonlocal name_entry_type
        
        entry_type, name_entry_type = initialize_struct(name_entry_type, forceNew)
        append_member(entry_type, "key", size, get_struct_item_name(size))
        append_member(entry_type, "next", 8, f'{name_entry_type} *')
        
        return name_entry_type
    
    def createSetLayout(size, forceNew):
        nonlocal name_entry_type
        
        layout = size
        
        name_entry_type = create_map_entry_type_layout(name_entry_type, get_map_key_name(name_struct_base, layout), get_map_val_name(name_struct_base, layout), layout, forceNew)
        
        return name_entry_type
    
    def createHeapAllocator(name_allocator, forceNew):
        allocator, name_allocator = initialize_struct(name_allocator, forceNew)
        append_member(allocator, "pad0", 8, '')
        append_member(allocator, "entries", 8, f'{name_entry_type} *')
        return name_allocator
    
    def createScatterAllocator(name_allocator, forceNew):
        allocator, name_allocator = initialize_struct(name_allocator, forceNew)
        append_member(allocator, "allocator", 8, 'ScrapHeap *')
        append_member(allocator, "entries", 8, f'{name_entry_type} *')
        return name_allocator
    
    if name_struct_base == TYPES_BSTSet:
        if type(size) == str:
            name_entry_type = createSetLayout(size, forceNew)
        else:
            name_entry_type = createSet(size, forceNew)
    else:
        if type(size) == tuple:
            assert len(size) == 2
            name_entry_type = create2(size, forceNew)
        elif type(size) == str:
            name_entry_type = createLayout(size, forceNew)
        else:
            name_entry_type = create(size, forceNew)
    
    name_iterator = get_map_iterator_name(name_struct_base, size)
    iterator, name_iterator = initialize_struct(name_iterator, forceNew)
    append_member(iterator, "first", 8, f'{name_entry_type} *')
    append_member(iterator, "last", 8, f'{name_entry_type} *')
    
    name_allocator = get_map_allocator_name(name_struct_base, size)
    if name_struct_base == TYPES_BSTScrapHashMap:
        name_allocator = createScatterAllocator(name_allocator, forceNew)
    else:
        name_allocator = createHeapAllocator(name_allocator, forceNew)
    
    name_map_internal = get_map_internal_name(name_struct_base, size)
    map_internal, name_map_internal = initialize_struct(name_map_internal, forceNew)
    append_member(map_internal, "pad0", 4, 'uint32')
    append_member(map_internal, "capacity", 4, 'uint32')
    append_member(map_internal, "free", 4, 'uint32')
    append_member(map_internal, "good", 4, 'uint32')
    append_member(map_internal, "sentinel", 8, f'{name_entry_type} *')
    append_member(map_internal, "allocator", 1, name_allocator)
    
    append_member(map_, "pad0", 8, 'uint64')
    append_member(map_, "internal", 8, name_map_internal)

def create_sized_BSTHashMap(size, forceNew=True):
    create_sized_BSTHashTable(TYPES_BSTHashMap, size, forceNew)

def create_sized_BSTSet(size, forceNew=True):
    create_sized_BSTHashTable(TYPES_BSTSet, size, forceNew)

def create_sized_BSTScrapHashMap(size, forceNew=True):
    create_sized_BSTHashTable(TYPES_BSTScrapHashMap, size, forceNew)


def create_struct(struct_type, size):
    if action_mode == ACTION_MODES_inplace or action_mode == ACTION_MODES_import:
        creators = {
            TYPES_BSTSmallArray: create_sized_SmallArray,
            TYPES_BSTArray: create_sized_BSTArray,
            TYPES_BSScrapArray: create_sized_ScrapArray,
            
            TYPES_BSTHashMap: create_sized_BSTHashMap,
            TYPES_BSTSet: create_sized_BSTSet,
            TYPES_BSTScrapHashMap: create_sized_BSTScrapHashMap
        }
        
        assert struct_type in creators, f'unk struct {struct_type}'
        creators[struct_type](size, False)
    elif action_mode == ACTION_MODES_export:
        structs_data.add((struct_type, size))

## ^^^ CREATING STRUCTS ^^^ ##


## --- GENERATORS --- ##


def generate_near(true_data, border=100):
    for segea in Segments():
        for startea in Functions(segea, get_segm_end(segea)):
            endea = get_func_bounds(startea)
            data = get_bytes(startea, endea - startea, False).hex()
            dist = distance(true_data, data)
            if dist > border:
                continue
            
            yield startea


def generate_near_func(startea, border=100):
    return generate_near(get_func_asm(startea), border)


def generate_xrefs(ea):
    for xref in XrefsTo(ea):
        func = ida_funcs.get_func(xref.frm)
        if func != None:
            yield func.start_ea


def generate_regexp(reg):
    for segea in Segments():
        for startea in Functions(segea, get_segm_end(segea)):
            endea = get_func_bounds(startea)
            data = get_bytes(startea, endea - startea, False).hex()
            if re.search(reg, data):
                yield startea


def generate_every():
    for segea in Segments():
        for startea in Functions(segea, get_segm_end(segea)):
            yield startea


def generate_current():
    yield ida_funcs.get_func(here()).start_ea

def generate_file(name):
    with open(name, 'r') as inp:
        for line in inp:
            line = line[:9]
            yield int(line, 16)

def iterate_all_funcs(gen, func):
    for startea in gen:
        func(startea)


def print_if_filter(gen, filter_func):
    def foo(ea):
        if filter_func(ea):
            print(f'{ea:x}')
    
    iterate_all_funcs(gen, foo)


## ^^^ GENERATORS ^^^ ##



## --- TRAITS --- ##

def how_many_calls(startea):
    ans = 0
    sleep = False
    for ins in FuncItems(startea):
        cmd = idc.GetDisasm(ins)
        if 'call' in cmd:
            ans += 1
        if 'Sleep' in cmd:
            sleep = True
    return (ans, sleep)

def has_crc(funcea):
    for ins in FuncItems(funcea):
        cmd = idc.GetDisasm(ins)
        if cmd.startswith('call'):
            call_ea = get_call_ea(ins)
            if call_ea == None:
                continue
            
            if is_crc_call(call_ea):
                return True
    
    return False

def is_useful_function(ea, depth=1):
    if depth == 5:
        return True
    
    ans = False
    
    for xref in XrefsTo(ea):
        func = ida_funcs.get_func(xref.frm)
        if func != None:
            ans = ans or is_useful_function(func.start_ea, depth + 1)
    
    return ans

def has_specific_call(funcea, specific_calls):
    for ins in FuncItems(funcea):
        cmd = idc.GetDisasm(ins)
        if cmd.startswith('call'):
            call_ea = get_call_ea(ins)
            if call_ea == None:
                continue
            
            if call_ea in specific_calls:
                return True
    
    return False

def has_filtered_call(funcea, is_filtered):
    for ins in FuncItems(funcea):
        cmd = idc.GetDisasm(ins)
        if cmd.startswith('call'):
            call_ea = get_call_ea(ins)
            if call_ea == None:
                continue
            
            if is_filtered(call_ea):
                return True
    
    return False

def number_of_calls(startea):
    ans = 0
    for ins in FuncItems(startea):
        cmd = idc.GetDisasm(ins)
        if cmd.startswith('call'):
            ans += 1
    return ans

def is_crc_call(ea):
    return ea in [0x140C064F0, 0x140C06570, 0x140C06490]

def get_crc_size(ins):
    call_ea = get_call_ea(ins)
    if call_ea == None:
        return None
    
    crcs = {0x140C064F0 : 4, 0x140C06570 : 8, 0x140C06490 : 0}
    if not call_ea in crcs:
        return None
    
    return crcs[call_ea]

def get_crc_size_withN(ea):
    ea = ida_funcs.get_func(ea).start_ea
    crcs = []
    for ins in FuncItems(ea):
        if idc.GetDisasm(ins).startswith('call'):
            size = get_crc_size(ins)
            if size != None:
                if size == 0:
                    crcs.append((0, ins))
                else:
                    crcs.append(size)
    
    # No hash function, seems always 4
    if len(crcs) == 0:
        return 4
    
    crcs = crcs[0]
    
    if type(crcs) == int:
        return crcs
    
    crcs = crcs[1]
    start = crcs - 16 * 2
    end = crcs
    data = get_bytes(start, end - start, False).hex()
    
    # dword
    ans = re.search('41b8....0000', data)
    if ans != None:
        return int(bigendian(data[ans.start() + 4:ans.end()]), 16)
    
    assert False, f'{ea:x}'

## ^^^ TRAITS ^^^ ##


## --- RUNNING --- ##

def run():
    def header():
        parse_decls('BSTL.h', PT_FILE)
    
    def prepare():
        log('Preparing...')
        
        # Heap
        set_type_name(0x140C04CC0, 'BSTArrayHeapAllocator::Allocate', 'bool f(BSTArrayHeapAllocator *allocator, uint32 num, uint32 elemSize)', False)
        set_type_name(0x1400FCEE0, 'BSTArrayAllocatorFunctor_BSTArrayHeapAllocator_::Allocate', 'bool f(BSTArrayAllocatorFunctor_BSTArrayHeapAllocator_ *functor, uint32 num, uint32 elemSize)', False)
        
        set_type_name(0x140C04D40, 'BSTArrayHeapAllocator::Reallocate', 'bool f(BSTArrayHeapAllocator *allocator, uint32 minNewSizeInItems, uint32 frontCopyCount, uint32 shiftCount, uint32 backCopyCount, uint32 elemSize)', False)
        set_type_name(0x1400FD050, 'BSTArrayAllocatorFunctor_BSTArrayHeapAllocator_::Reallocate', 'bool f(BSTArrayAllocatorFunctor_BSTArrayHeapAllocator_ *allocator, uint32 minNewSizeInItems, uint32 frontCopyCount, uint32 shiftCount, uint32 backCopyCount, uint32 elemSize)', False)
        
        set_type_name(0x140C04EC0, 'BSTArrayHeapAllocator::Free', 'void f(BSTArrayHeapAllocator *allocator)', False)
        set_type_name(0x1400FCF50, 'BSTArrayAllocatorFunctor_BSTArrayHeapAllocator_::Free', 'void f(BSTArrayAllocatorFunctor_BSTArrayHeapAllocator_ *allocator)', False)
    
        # Scrap
        set_type_name(0x140C05010, 'BSScrapArrayAllocator::Allocate', 'bool f(BSScrapArrayAllocator *allocator, uint32 num, uint32 elemSize)', False)
        set_type_name(0x14014E010, 'BSTArrayAllocatorFunctor_BSScrapArrayAllocator_::Allocate', 'bool f(BSTArrayAllocatorFunctor_BSScrapArrayAllocator_ *functor, uint32 num, uint32 elemSize)', False)
        
        set_type_name(0x140C050A0, 'BSScrapArrayAllocator::Reallocate', 'bool f(BSScrapArrayAllocator *allocator, uint32 minNewSizeInItems, uint32 frontCopyCount, uint32 shiftCount, uint32 backCopyCount, uint32 elemSize)', False)
        set_type_name(0x14014F7D0, 'BSTArrayAllocatorFunctor_BSScrapArrayAllocator_::Reallocate', 'bool f(BSTArrayAllocatorFunctor_BSScrapArrayAllocator_ *allocator, uint32 minNewSizeInItems, uint32 frontCopyCount, uint32 shiftCount, uint32 backCopyCount, uint32 elemSize)', False)
        
        set_type_name(0x140C051F0, 'BSScrapArrayAllocator::Free', 'void f(BSScrapArrayAllocator *allocator)', False)
        set_type_name(0x14014E5D0, 'BSTArrayAllocatorFunctor_BSScrapArrayAllocator_::Free', 'void f(BSTArrayAllocatorFunctor_BSScrapArrayAllocator_ *allocator)', False)
        
        # Small
        set_type_name(0x140C06640, 'BSTSmallArrayHeapAllocator::Allocate', 'bool f(BSTSmallArrayHeapAllocator *allocator, uint32 num, uint32 elemSize, uint32 staticSize)', False)
        set_type_name(0x140C06700, 'BSTSmallArrayHeapAllocator::Reallocate', 'bool f(BSTSmallArrayHeapAllocator *allocator, uint32 minNewSizeInItems, uint32 frontCopyCount, uint32 shiftCount, uint32 backCopyCount, uint32 elemSize)', False)
        set_type_name(0x140C06880, 'BSTSmallArrayHeapAllocator::Free', 'void f(BSTSmallArrayHeapAllocator *allocator)', False)
        
        # BSTArrayBase
        set_type_name(0x140C04A20, 'BSTArrayBase::reserve_push_back', 'int           f(BSTArrayBase *array, BSTArrayBase::IAllocatorFunctor *allocator, uint32 capacity, uint32 elemSize)', False)
        set_type_name(0x140C04AB0, 'BSTArrayBase::prepare_insert'   , 'bool          f(BSTArrayBase *array, BSTArrayBase::IAllocatorFunctor *allocator, char *data, uint32 capacity, uint32 pos, uint32 elemSize)', False)
        set_type_name(0x140C04980, 'BSTArrayBase::erase'            , 'void          f(BSTArrayBase *array, char *data, int32 ind_from, int32 ind_to, int32 keepBackCount, int32 elemSize)', False)
        set_type_name(0x140C049F0, 'BSTArrayBase::ctor'             , 'bool          f(BSTArrayBase *array, BSTArrayBase::IAllocatorFunctor *allocator, uint32 count, uint32 elemSize)', False)
        set_type_name(0x140C04970, 'BSTArrayBase::clear'            , 'BSTArrayBase *f(BSTArrayBase *array)', False)
        set_type_name(0x140C04C10, 'BSTArrayBase::reserve'          , 'bool          f(BSTArrayBase *array, BSTArrayBase::IAllocatorFunctor *allocator, uint32 capacity, uint32 size, uint32 elemSize)', False)
        
        log('DONE')
    
    def run_Arrays():
        
        def get_func_signature(type_, funct, size):
            functors = {
                FUNCT_erase:  lambda arr_t, val_t: f'{val_t} **__fastcall f({arr_t} *array, {val_t} **ans, {val_t} **it)',
                FUNCT_erase1: lambda arr_t, val_t: f'void __fastcall f({arr_t} *array, int32 from, int32 count)',
                FUNCT_erase2: lambda arr_t, val_t: f'bool __fastcall f({arr_t} *array, {val_t} *val)',
                
                FUNCT_push_back:           lambda arr_t, val_t: f'void __fastcall f({arr_t} *array, {val_t} *val)',
                FUNCT_reserve_push_backs:  lambda arr_t, val_t: f'bool __fastcall f({arr_t} *array, uint32 count)',
                FUNCT_reserve_push_backs2: lambda arr_t, val_t: f'void __fastcall f({arr_t} *array, uint32 count)',
                
                FUNCT_insert: lambda arr_t, val_t: f'bool __fastcall f({arr_t} *array, uint32 pos, {val_t} *val)',
                FUNCT_resize: lambda arr_t, val_t: f'bool f({arr_t} *array, uint32 size)',
                
                FUNCT_begin:  lambda arr_t, val_t: f'{val_t} **__fastcall f({arr_t} *array, {val_t} **ans)',
                FUNCT_end:    lambda arr_t, val_t: f'{val_t} **__fastcall f({arr_t} *array, {val_t} **ans)',
                FUNCT_rbegin: lambda arr_t, val_t: f'{val_t} **__fastcall f({arr_t} *array, {val_t} **ans)',
                FUNCT_rend:   lambda arr_t, val_t: f'{val_t} **__fastcall f({arr_t} *array, {val_t} **ans)'
            }
            
            assert funct in functors, f'Cannot get signature for {funct}: {type_} {size}'
            
            struct_name = get_array_name(type_, size)
            value_type = get_struct_item_name(size if type(size) != tuple else size[0])
            return functors[funct](struct_name, value_type)
        
        """
        Iterate all `*Array::Allocate` xref functs and detect functions `resize`
        """
        def detect_resizes():
            log('Detecting Array::resize...')
            
            debuginfo = DebugInfo(lambda item: item[1][1])
            
            array_allocates = [0x140C04CC0, 0x140C05010, 0x140C06640]
            array_reallocates = [0x140C04D40, 0x140C050A0, 0x140C06700]
            
            """
            Returns size of array for `resize` function
            """
            def detect_function(startea):
                data = get_func_asm(startea)
                
                match = re.match('^48895c2408574883ec308bfa488bd9b00185d27517488339007461895110895110488b5c24404883c4305fc3448b4110413bd07510b001897b10488b5c24404883c4305fc38b49083bd1763085c9488bcb750d41b8(?P<size>........)', data)
                if match:
                    return int(bigendian(match.group('size')), 16)
                
                match = re.match('^48895c2408574883ec308bfa488bd9b00185d2751848837908007461895118895118488b5c24404883c4305fc3448b4118413bd07510b001897b18488b5c24404883c4305fc38b49103bd1763085c9488bcb750d41b8(?P<size>........)', data)
                if match:
                    return int(bigendian(match.group('size')), 16)
                
                match = re.match('^48895c2408574883ec408bfa488bd9b00185d2....f7010000008074064883c108eb04488b49084885c9....c743........00897b..488b5c24504883c4405fc3448b41..413bd07510b001897b..488b5c24504883c4405fc38b090fbaf11f3bd1....85c9488bcb....41b9(?P<size>........)', data)
                if match:
                    static_size = int(bigendian(match.group('size')), 16)
                    item_size = -1
                    
                    sub_data = data[226:]
                    if re.match('^458bc1', sub_data):
                        item_size = static_size
                    elif re.match('^458d41f8', sub_data):
                        item_size = static_size - 8
                    
                    if item_size != -1:
                        return (item_size, static_size)
                
                match = re.match('^48895c2408574883ec408bfa488bd9b00185d2....f7010000008074064883c108eb04488b49084885c90f..........c783........0000000089bb........488b5c24504883c4405fc3448b8180000000413bd0....b00189bb80000000488b5c24504883c4405fc38b090fbaf11f3bd1....85c9488bcb....41b9(?P<size>........)458d4194e8', data)
                if match:
                    static_size = int(bigendian(match.group('size')), 16)
                    item_size = static_size - 0x6C
                    return (item_size, static_size)

                match = re.match('^48895c2408488974241.574883ec308b.a488b.940b60185d2750.(48833900|4883790800)....8951......8b51..3b.a750540b601....8b41..3b.8....85c0....(448d40(?P<size1>..)8bd.|41b8(?P<size2>........)8bd7)e8', data)
                if match:
                    size = match.group('size1')
                    if size == None:
                        size = match.group('size2')
                    return int(bigendian(size), 16)
                
                match = re.match('^48895c24084889742410574883ec408bfa488bd940b60185d2751ef70100000080488d41087504488b41084885c07477c741........00eb6e8b51..3bfa750540b601eb628b010fbaf01f3bf8764985c07511448d48(?P<static_size>..)8bd7448d40(?P<item_size>..)e8', data)
                if match:
                    static_size = int(bigendian(match.group('static_size')), 16)
                    item_size = int(bigendian(match.group('item_size')), 16)
                    return (item_size, static_size)

                match = re.match('^48895c24084889742410574883ec308bf2488bf941b00185d27514488339000f84ac00000033db895910e9a20000008b41103bd0750841b001e9930000008b49083bd1765e33db85c9488bcf750b448d43(?P<size>..)e8', data)
                if match:
                    size = match.group('size')
                    
                    return int(bigendian(size), 16)
                
                return None
            
            def process(startea, type_):
                if not has_specific_call(startea, array_allocates):
                    return
                
                if not has_specific_call(startea, array_reallocates):
                    return
                
                if how_many_calls(startea)[0] > 3:
                    return
                
                size = detect_function(startea)
                
                if size == None:
                    name = get_name(startea)
                    debuginfo.add(startea, (get_func_asm(startea), len(get_func_asm(startea)), how_many_calls(startea)[0]))
                    return
                
                create_struct(type_, size)
                
                func_signature = get_func_signature(type_, FUNCT_resize, size)
                
                func_name = f'{type_}::Resize'
                
                set_type_name(startea, func_name, func_signature)
            
            def test():
                total = 0
                
                def test_(startea, size_expected):
                    nonlocal total
                    
                    size_actual = detect_function(startea)
                    assert size_expected == size_actual, f'{startea:x}: {size_expected} != {size_actual}'
                    total += 1
            
                test_(0x140133ad0, 8)
                test_(0x140133EA0, 4)
                test_(0x1402C0240, 8)
                test_(0x14045D110, 12)
                test_(0x140501A30, 8)
                test_(0x1406CC210, 16)
                test_(0x140e18e40, 48)
                
                test_(0x140133C80, 16)
                test_(0x1406ECBB0, 44)
                test_(0x140774240, 168)
                test_(0x1402bac20, 16)
                test_(0x1406cc170, 4)
                test_(0x14134a160, 12)
                test_(0x140133d20, 8)
                test_(0x140166420, 4)
                
                test_(0x1406cc010, (16, 32))
                test_(0x140bf8aa0, (4, 8))
                test_(0x140545550, (4, 4))
                test_(0x14056be00, (8, 16))
                test_(0x141132830, (12, 0x78))
                test_(0x14045cdc0, 2)
                test_(0x1410b6040, 56)
                
                print(f'TESTING Arrays_Allocate_xrefs: OK {total}')
            
            #test()
            
            iterate_all_funcs(generate_xrefs(0x140C04CC0), lambda x: process(x, TYPES_BSTArray))
            iterate_all_funcs(generate_xrefs(0x140C05010), lambda x: process(x, TYPES_BSScrapArray))
            iterate_all_funcs(generate_xrefs(0x140C06640), lambda x: process(x, TYPES_BSTSmallArray))
            log('DONE')
            
            #print(debuginfo)
        
        """
        Iterate all functions and detect `begin`, `rbegin`, `end`, `rend`, `erase`
        """
        def detect_beginrbeginendrenderases():
            log('Detecting Array::begin, rbegin, end, rend, erase...')
            
            debuginfo = DebugInfo(lambda item: f'{item[1][1]}')
            
            """
            Reads code and returns array type, function name, array size(s). Works for `begin`, `rbegin`, `end`, `rend`, `erase`
            """
            def detect_function(startea):
                data = get_func_asm(startea)
                
                if data == '83791000750b48c70200000000488bc2c3488b01488902488bc2c3':
                    return (TYPES_BSTArray, FUNCT_begin, 0)
                
                if re.search('^83791000750b48c70200000000488bc2c3488b014883e8..488902488bc2c3$', data):
                    return (TYPES_BSTArray, FUNCT_rend, int(data[46:48], 16))
                
                if re.search('^8b41104c8bc185c0750b48c70200000000488bc2c38d48ff498b00488d0c..488bc248890ac3$', data):
                    return (TYPES_BSTArray, FUNCT_rbegin, get_size(data[54:62]))  # lea
                
                if re.search('^8b41104c8bc185c0750b48c70200000000488bc2c38d48ff488bc248c1e1..49030848890ac3$', data):
                    return (TYPES_BSTArray, FUNCT_rbegin, 2 ** int(data[60:62], 16))  # shl
                
                if re.search('^8b41104c8bc185c0750b48c70200000000488bc2c3486bc8..488bc249030848890ac3$', data):
                    return (TYPES_BSTArray, FUNCT_end, int(data[48:50], 16))  # imul byte
                
                if re.search('^8b41104c8bc185c0750b48c70200000000488bc2c34869c8........488bc249030848890ac3$', data):
                    return (TYPES_BSTArray, FUNCT_end, int(bigendian(data[48:56]), 16))  # imul dword
                
                if re.search('^488bc18b491085c9750b48c70200000000488bc2c3488b00488d0c..488bc248890ac3$', data):
                    return (TYPES_BSTArray, FUNCT_end, get_size(data[48:56]))  # lea
                               
                if re.search('^8b411085c0750b48c70200000000488bc2c348c1e0..480301488902488bc2c3$', data):
                    return (TYPES_BSTArray, FUNCT_end, 2 ** int(data[42:44], 16))  # shl
                
                if re.search('^8b41104c8bc185c0750b48c70200000000488bc2c3488d0c..498b00488d0c..488bc248890ac3$', data):
                    return (TYPES_BSTArray, FUNCT_end, get_size(data[42:50]) * get_size(data[56:64]))  # lea lea
                
                if re.search('^8b41104c8bc185c0750b48c70200000000488bc2c3488d0c..488bc248c1e1..49030848890ac3$', data):
                    return (TYPES_BSTArray, FUNCT_end, get_size(data[42:50]) * (2 ** int(data[62:64], 16)))  # lea shl
                               
                if re.search('^48895c2410488974241848897c242041564883ec30498b18488bf.488b114c8bf18b4110482bda48c1fb..83f801750e4885d2742dc7411000000000eb242bc3c7442428......00ffc8448d4b01448bc3894424204883c110e8........41ff4e1041837e1000750d488bd.498bcee8........eb0c', data):
                    return (TYPES_BSTArray, FUNCT_erase, int(bigendian(data[136:144]), 16))  # sar
                
                if re.search('^48895c2410488974241848897c242041564883ec30448b49104c8bf1498b18418bc1488bf2c7442428......00488b11b901000000482bda48c1fb..2bc3448bc3ffc83bc10f42c8442bc9894c2420498d4e10e8........41834610ff750d488bd6498bcee8........', data):
                    return (TYPES_BSTArray, FUNCT_erase, int(bigendian(data[82:90]), 16))  # sar
                
                if re.search('^48895c2408574883ec30448b4910488d5910418bc1c7442428......002bc2458bd0412bc0418bf8413bc0448bc2488b11488bcb440f42d0452bca4489542420e8........293b488b5c24404883c4305fc3$', data):
                    return (TYPES_BSTArray, FUNCT_erase1, int(bigendian(data[50:58]), 16))
                
                if re.search('^48895c2408574883ec308b4110488d5910418bf8443bc07517488339007436c70300000000488b5c24404883c4305fc32bc2c7442428......00412bc0468d0c02448bc289442420488b11488bcbe8........293b488b5c24404883c4305fc3$', data):
                    return (TYPES_BSTArray, FUNCT_erase1, int(bigendian(data[108:116]), 16))
                
                match = re.match('^4056574154415641574883ec4048c7442430feffffff48895c24704889ac2480000000418be8448bfa4c8be18b41102bc2412bc0458bf0413bc0440f42f04c8b014b8d1cf885ed742d8bfd0f1f440000488b0b4885c9741483c8fff00fc1410883f8017507488b01ff5008904883c3084883ef0175da458b4c2410452bcec7442428(?P<size>......00)4489742420458bc7498b1424498d4c2410e8........41296c2410488b5c2470488bac24800000004883c440415f415e415c5f5ec3$', data)
                if match:
                    return (TYPES_BSTArray, FUNCT_erase1, int(bigendian(match.group('size')), 16))  # lea
                
                match = re.match('^4056574155415641574883ec4048c7442430feffffff48895c24704889ac2480000000418be8448bfa4c8be98b41182bc2412bc0458bf0413bc0440f42f08bda48c1e304480359084585c074298bfd90488b0b4885c9741483c8fff00fc1410883f8017507488b01ff5008904883c3104883ef0175da458b4d18452bcec7442428(?P<size>......00)4489742420458bc7498b5508498d4d18e8........41296d18488b5c2470488bac24800000004883c440415f415e415d5f5ec3$', data)
                if match:
                    return (TYPES_BSTArray, FUNCT_erase1, int(bigendian(match.group('size')), 16))  # shl
                
                match = re.match('^48895c24084889742410574883ec30448b4910488d711033ff83cbff4c8bda4c8bd1448bc74585c9....660f1f44000083fbff....498b0a4.8b03418bd0(390491|483904d1)410f44d841ffc0453bc1....83fbff7433498b12418bc12bc3c7442428(?P<size>......00)ffc8b9010000003bc1448bc30f42c8442bc9894c2420488bcee8........ff0e83fbff488b5c24400f95c0488b7424484883c4305fc3$', data)
                if match:
                    return (TYPES_BSTArray, FUNCT_erase2, int(bigendian(match.group('size')), 16))
                
                match = re.match('^48895c24084889742410574883ec30448b5110488d711033ff83cbff4c8bca4c8bd9448bc74585d2....660f1f44000083fbff....498b0b4.8b01418bd0(390491|483904d1)410f44d841ffc0453bc2....83fbff74394183fa01750949393b742b893eeb27498b13448d4b01442bd3c7442428(?P<size>......00)41ffca448bc3488bce4489542420e8........ff0e83fbff488b5c24400f95c0488b7424484883c4305fc3$', data)
                if match:
                    return (TYPES_BSTArray, FUNCT_erase2, int(bigendian(match.group('size')), 16))
                
                # TODO mb bad tail
                match = re.match('^40574883ec4048c7442420feffffff(48895c2450(8bfa|488b.a)|48895c2458488bfa)488b.9..............488944242848894c24304883c11041b9(?P<size>......00)448b4.08488d542428e8........', data)
                if match:
                    return (TYPES_BSTArray, FUNCT_push_back, int(bigendian(match.group('size')), 16))
                
                match = re.match('^4883ec5848c7442430feffffff488bc148............48894c24384889442440488d4810c7442420(?P<size>......00)448bca448b4008488d542438e8........904883c458c3$', data)
                if match:
                    return (TYPES_BSTArray, FUNCT_reserve_push_backs, int(bigendian(match.group('size')), 16))
                
                match = re.match('^40574883ec5048c7442430feffffff48895c24604889742468498b..8bf.488b.9488d..........488944243848894c24404883c110c7442428(?P<size>......00)897.2420448b4.084c8b0.488d542438e8........(440fb6c084c0|9084c0)', data)
                if match:
                    return (TYPES_BSTArray, FUNCT_insert, int(bigendian(match.group('size')), 16))
                
                
                if data == '83791800750b48c70200000000488bc2c3488b4108488902488bc2c3':
                    return (TYPES_BSScrapArray, FUNCT_begin, 0)
                
                if re.search('^8b41184c8bc185c0750b48c70200000000488bc2c3486bc8..488bc24903480848890ac3$', data):
                    return (TYPES_BSScrapArray, FUNCT_end, int(data[48:50], 16))  # imul byte
                
                if re.search('^488bc18b491885c9750b48c70200000000488bc2c3488b4008488d0c..488bc248890ac3$', data):
                    return (TYPES_BSScrapArray, FUNCT_end, get_size(data[50:58]))  # lea
                               
                if re.search('^8b411885c0750b48c70200000000488bc2c348c1e0..48034108488902488bc2c3$', data):
                    return (TYPES_BSScrapArray, FUNCT_end, 2 ** int(data[42:44], 16))  # shl
                
                if re.search('^8b41184c8bc185c0750b48c70200000000488bc2c3488d0c..498b4008488d0c..488bc248890ac3$', data):
                    return (TYPES_BSScrapArray, FUNCT_end, get_size(data[42:50]) * get_size(data[58:66]))  # lea lea
                               
                if re.search('^8b41184c8bc185c0750b48c70200000000488bc2c3488d0c..488bc248c1e1..4903480848890ac3$', data):
                    return (TYPES_BSScrapArray, FUNCT_end, get_size(data[42:50]) * (2 ** int(data[62:64], 16)))  # lea shl
                
                if re.search('^48895c241048896c24184889742420574883ec30498b18488bfa488b5108488be98b4118482bda48c1fb0383f801750e4885d2742cc7411800000000eb232bc3c7442428......00ffc8448d4b01448bc3894424204883c118e8c2532500ff4d18837d1800750d488bd7488bcde89e080000eb0d488b45088bcb488d0cc848890f488b5c2448488bc7488b6c2450488b7424584883c4305fc3$', data):
                    return (TYPES_BSScrapArray, FUNCT_erase, int(bigendian(data[136:144]), 16))
                
                if re.search('^48895c2408574883ec308b4118488d5918418bf8443bc0751848837908007437c70300000000488b5c24404883c4305fc32bc2c7442428......00412bc0468d0c02448bc289442420488b5108488bcbe8........293b488b5c24404883c4305fc3$', data):
                    return (TYPES_BSScrapArray, FUNCT_erase1, int(bigendian(data[110:118]), 16))
                
                # TODO: mb end check if many things
                match = re.match('^40574883ec4048c7442420feffffff48895c2450488b.a488b.9..............488944242848894c24304883c11841b9(?P<size>......00)448b4.10488d542428e8........', data)
                if match:
                    return (TYPES_BSScrapArray, FUNCT_push_back, int(bigendian(match.group('size')), 16))
                
                match = re.match('^4883ec5848c7442430feffffff448b4918448b4110418d0411413bc0762b..............488944243848894c24404403cac7442420(?P<size>......00)488d5424384883c118e8........904883c458c3$', data)
                if match:
                    return (TYPES_BSScrapArray, FUNCT_reserve_push_backs2, int(bigendian(match.group('size')), 16))
                
                match = re.match('^4883ec5848c7442430feffffff488bc1488d0d89c52d0048894c24384889442440488d4818c7442420(?P<size>......00)448bca448b4010488d542438e8c2f39aff904883c458c3$', data)
                if match:
                    return (TYPES_BSScrapArray, FUNCT_reserve_push_backs, int(bigendian(match.group('size')), 16))
                
                match = re.match('^40574883ec5048c7442430feffffff48895c24604889742468498b..8bf.488b.9488d..........488944243848894c24404883c118c7442428(?P<size>......00)897.2420448b4.104c8b4.08488d542438e8........(440fb6c084c0|9084c0)', data)
                if match:
                    return (TYPES_BSScrapArray, FUNCT_insert, int(bigendian(match.group('size')), 16))
                
                
                if re.search('^8379..00750b48c70200000000488bc2c3f70100000080488d41087504488b4108488902488bc2c3$', data):
                    return (TYPES_BSTSmallArray, FUNCT_begin, ( 8, int(data[4:6], 16) - 8 ))  # char
                
                if re.search('^83b9..........750b48c70200000000488bc2c3f70100000080488d41087504488b4108488902488bc2c3$', data):
                    return (TYPES_BSTSmallArray, FUNCT_begin, ( 8, int(bigendian(data[4:14]), 16) - 8 ))  # dword
                
                if re.search('^8b41..85c0750b48c70200000000488bc2c3f70100000080740f4883c108488d0c..488bc248890ac3488b4908488d0c..488bc248890ac3$', data):
                    return (TYPES_BSTSmallArray, FUNCT_end, ( get_size(data[60:68]), int(data[4:6], 16) - 8 ))  # lea char
                
                if re.search('^8b81........85c0750b48c70200000000488bc2c3f70100000080740f4883c108488d0c..488bc248890ac3488b4908488d0c..488bc248890ac3$', data):
                    return (TYPES_BSTSmallArray, FUNCT_end, ( get_size(data[66:74]), int(bigendian(data[4:12]), 16) - 8 ))  # lea dword
                
                if re.search('^8b41..85c0750b48c70200000000488bc2c3f701000000804c8d410875044c8b4108488d0c..498d04..488902488bc2c3$', data):
                    return (TYPES_BSTSmallArray, FUNCT_end, ( get_size(data[68:76]) * get_size(data[76:84]), int(data[4:6], 16) - 8 ))  # lea lea char
                
                if re.search('^8b81........85c0750b48c70200000000488bc2c3f701000000804c8d410875044c8b4108488d0c..498d04..488902488bc2c3$', data):
                    return (TYPES_BSTSmallArray, FUNCT_end, ( get_size(data[74:82]) * get_size(data[82:90]), int(bigendian(data[4:12]), 16) - 8 ))  # lea lea dword
                
                if re.search('^8b41..85c0750b48c70200000000488bc2c3f70100000080741248c1e0..4883c1084803c1488902488bc2c3488b490848c1e0..4803c1488902488bc2c3$', data):
                    return (TYPES_BSTSmallArray, FUNCT_end, ( (2 ** int(data[58:60], 16)), int(data[4:6], 16) - 8 ))  # shl char
                
                if re.search('^8b81........85c0750b48c70200000000488bc2c3f70100000080741248c1e0..4883c1084803c1488902488bc2c3488b490848c1e0..4803c1488902488bc2c3$', data):
                    return (TYPES_BSTSmallArray, FUNCT_end, ( (2 ** int(data[64:66], 16)), int(bigendian(data[4:12]), 16) - 8 ))  # shl word
                
                if re.search('^8b41..85c0750b48c70200000000488bc2c3f701000000804c8d410875044c8b4108486bc8..488bc24903c848890ac3$', data):
                    return (TYPES_BSTSmallArray, FUNCT_end, ( int(data[74:76], 16), int(data[4:6], 16) - 8 ))  # imul char
                
                if re.search('^8b81........85c0750b48c70200000000488bc2c3f701000000804c8d410875044c8b41084869c8........488bc24903c848890ac3$', data):
                    return (TYPES_BSTSmallArray, FUNCT_end, ( int(bigendian(data[80:88]), 16), int(bigendian(data[4:12]), 16) - 8 ))  # imul dword
                
                
                return (TYPES_None, FUNCT_None, 0)
            
            def process(startea):
                def process_j(startea, func_signature, func_name):
                    """
                    Check if function is j_begin for table or array
                    """
                    def isj_function(startea):
                        func = ida_funcs.get_func(startea)
                        if func != None:
                            start_ea = func.start_ea
                            data = get_func_asm(start_ea)
                            regex = '^40534883ec20488bdae8........488bc34883c4205bc3'
                            if re.search(regex, data):
                                return start_ea
                        
                        return 0
                    
                    startea = isj_function(startea)
                    if startea == 0:
                        return
                    
                    func_name = f'j_{func_name}'
                    set_type_name(startea, func_name, func_signature)
                
                
                (type_, funct, size) = detect_function(startea)
                
                if type_ == TYPES_None:
                    return
                
                create_struct(type_, size)
                
                func_signature = get_func_signature(type_, funct, size)
                
                func_name = f'{type_}::{funct}'
                
                set_type_name(startea, func_name, func_signature)
                
                iterate_all_funcs(generate_xrefs(startea), lambda ea: process_j(ea, func_signature, func_name))
            
            def test():
                total = 0
                
                def test_(startea, expected):
                    nonlocal total
                    
                    expected_type, expected_funct, expected_size = expected
                    actual_type, actual_funct, actual_size = detect_function(startea)
                    
                    assert expected_type == actual_type, f'{startea:x}: types {expected_type} != {actual_type}'
                    assert expected_funct == actual_funct, f'{startea:x}: funcs {expected_funct} != {actual_funct}'
                    assert expected_size == actual_size, f'{startea:x}: sizes {expected_size} != {actual_size}'
                    
                    total += 1
                
                test_(0x140103a00, (TYPES_BSTArray, FUNCT_begin, 0))
                test_(0x1412df220, (TYPES_BSTArray, FUNCT_begin, 0))
                test_(0x141342170, (TYPES_BSTArray, FUNCT_begin, 0))
                
                test_(0x140103a20, (TYPES_BSTArray, FUNCT_end, 8))
                test_(0x140134140, (TYPES_BSTArray, FUNCT_end, 16))
                test_(0x1401432f0, (TYPES_BSTArray, FUNCT_end, 24))
                test_(0x14022fd00, (TYPES_BSTArray, FUNCT_end, 4))
                test_(0x14045d4a0, (TYPES_BSTArray, FUNCT_end, 12))
                test_(0x14116f2e0, (TYPES_BSTArray, FUNCT_end, 48))
                test_(0x140bf8d20, (TYPES_BSTArray, FUNCT_end, 64))
                test_(0x140844c30, (TYPES_BSTArray, FUNCT_end, 32))
                test_(0x140887360, (TYPES_BSTArray, FUNCT_end, 96))
                test_(0x14051f830, (TYPES_BSTArray, FUNCT_end, 264))
                test_(0x1404554d0, (TYPES_BSTArray, FUNCT_end, 56))
                test_(0x1405383f0, (TYPES_BSTArray, FUNCT_end, 88))
                test_(0x1408bd480, (TYPES_BSTArray, FUNCT_end, 312))
                test_(0x14045d3d0, (TYPES_BSTArray, FUNCT_end, 2))
                
                test_(0x1401334e0, (TYPES_BSTArray, FUNCT_erase, 16))
                test_(0x1404be6d0, (TYPES_BSTArray, FUNCT_erase, 16))
                test_(0x140142bd0, (TYPES_BSTArray, FUNCT_erase, 8))
                test_(0x140856c70, (TYPES_BSTArray, FUNCT_erase, 8))
                test_(0x140c14c40, (TYPES_BSTArray, FUNCT_erase, 4))
                test_(0x140756a50, (TYPES_BSTArray, FUNCT_erase, 4))
                test_(0x1401b0bf0, (TYPES_BSTArray, FUNCT_erase, 8))
                test_(0x141311660, (TYPES_BSTArray, FUNCT_erase, 8))
                test_(0x140756b50, (TYPES_BSTArray, FUNCT_erase, 4))
                test_(0x140886840, (TYPES_BSTArray, FUNCT_erase, 4))
                
                test_(0x1406cb060, (TYPES_BSTArray, FUNCT_erase1, 16))
                test_(0x140381410, (TYPES_BSTArray, FUNCT_erase1, 32))
                test_(0x1406e4920, (TYPES_BSTArray, FUNCT_erase1, 4))
                test_(0x1401661f0, (TYPES_BSTArray, FUNCT_erase1, 8))
                test_(0x140132fc0, (TYPES_BSTArray, FUNCT_erase1, 16))
                test_(0x140133020, (TYPES_BSTArray, FUNCT_erase1, 4))
                
                test_(0x1401b0d00, (TYPES_BSTArray, FUNCT_erase1, 8))
                test_(0x140432240, (TYPES_BSTArray, FUNCT_erase1, 16))
                
                test_(0x1402cee50, (TYPES_BSTArray, FUNCT_erase2, 4))
                test_(0x14012e370, (TYPES_BSTArray, FUNCT_erase2, 8))
                test_(0x140281e10, (TYPES_BSTArray, FUNCT_erase2, 4))
                test_(0x140281eb0, (TYPES_BSTArray, FUNCT_erase2, 4))
                
                test_(0x1408d4d00, (TYPES_BSTArray, FUNCT_rbegin, 4))
                test_(0x1401b09c0, (TYPES_BSTArray, FUNCT_rbegin, 8))
                test_(0x1404be620, (TYPES_BSTArray, FUNCT_rbegin, 16))
                
                test_(0x140c33000, (TYPES_BSTArray, FUNCT_push_back, 4))
                test_(0x140c33070, (TYPES_BSTArray, FUNCT_push_back, 8))
                test_(0x140173f40, (TYPES_BSTArray, FUNCT_push_back, 8))
                test_(0x1401317b0, (TYPES_BSTArray, FUNCT_push_back, 8))
                test_(0x14045c280, (TYPES_BSTArray, FUNCT_push_back, 2))
                test_(0x14037f650, (TYPES_BSTArray, FUNCT_push_back, 0x20))
                test_(0x1403b8910, (TYPES_BSTArray, FUNCT_push_back, 8))
                test_(0x140131820, (TYPES_BSTArray, FUNCT_push_back, 8))
                test_(0x1401af8f0, (TYPES_BSTArray, FUNCT_push_back, 8))
                test_(0x140830b50, (TYPES_BSTArray, FUNCT_push_back, 0x24))
                test_(0x14093a640, (TYPES_BSTArray, FUNCT_push_back, 16))
                test_(0x1406e3d40, (TYPES_BSTArray, FUNCT_push_back, 0x18))
                test_(0x140493d30, (TYPES_BSTArray, FUNCT_push_back, 12))
                test_(0x140836320, (TYPES_BSTArray, FUNCT_push_back, 0x28))
                test_(0x140487ca0, (TYPES_BSTArray, FUNCT_push_back, 0x20))
                test_(0x141271150, (TYPES_BSTArray, FUNCT_push_back, 0x18))
                test_(0x1401b0710, (TYPES_BSTArray, FUNCT_push_back, 8))
                test_(0x140773b00, (TYPES_BSTArray, FUNCT_push_back, 12))
                
                test_(0x141154110, (TYPES_BSTArray, FUNCT_reserve_push_backs, 16))
                test_(0x140180fe0, (TYPES_BSTArray, FUNCT_reserve_push_backs, 12))
                
                test_(0x1406782e0, (TYPES_BSTArray, FUNCT_insert, 16))
                test_(0x1403f0d80, (TYPES_BSTArray, FUNCT_insert, 0x30))
                test_(0x1407b4860, (TYPES_BSTArray, FUNCT_insert, 4))
                test_(0x140177a30, (TYPES_BSTArray, FUNCT_insert, 8))
                
                test_(0x1404e0560, (TYPES_BSScrapArray, FUNCT_begin, 0))
                test_(0x1412c4930, (TYPES_BSScrapArray, FUNCT_begin, 0))
                test_(0x140179ad0, (TYPES_BSScrapArray, FUNCT_begin, 0))
                
                test_(0x140179b90, (TYPES_BSScrapArray, FUNCT_end, 4))
                test_(0x140179bf0, (TYPES_BSScrapArray, FUNCT_end, 8))
                test_(0x14045d3a0, (TYPES_BSScrapArray, FUNCT_end, 2))
                test_(0x140471880, (TYPES_BSScrapArray, FUNCT_end, 32))
                test_(0x14048f1a0, (TYPES_BSScrapArray, FUNCT_end, 48))
                test_(0x1406ecc70, (TYPES_BSScrapArray, FUNCT_end, 44))
                test_(0x1410b65a0, (TYPES_BSScrapArray, FUNCT_end, 72))
                test_(0x14131b7c0, (TYPES_BSScrapArray, FUNCT_end, 12))
                
                test_(0x1409AF560, (TYPES_BSScrapArray, FUNCT_erase, 8))
                
                test_(0x1409af4f0, (TYPES_BSScrapArray, FUNCT_erase1, 8))
                test_(0x14050d2b0, (TYPES_BSScrapArray, FUNCT_erase1, 12))
                
                test_(0x140617ef0, (TYPES_BSScrapArray, FUNCT_push_back, 4))
                test_(0x14064a500, (TYPES_BSScrapArray, FUNCT_push_back, 8))
                test_(0x1401cc370, (TYPES_BSScrapArray, FUNCT_push_back, 8))
                test_(0x141126710, (TYPES_BSScrapArray, FUNCT_push_back, 0x18))
                test_(0x1406f2380, (TYPES_BSScrapArray, FUNCT_push_back, 8))
                test_(0x1404856f0, (TYPES_BSScrapArray, FUNCT_push_back, 0x20))
                
                test_(0x141255810, (TYPES_BSScrapArray, FUNCT_reserve_push_backs, 4))
                
                test_(0x140484760, (TYPES_BSScrapArray, FUNCT_reserve_push_backs2, 0x20))
                test_(0x140b03420, (TYPES_BSScrapArray, FUNCT_reserve_push_backs2, 8))
                
                test_(0x14045f9f0, (TYPES_BSScrapArray, FUNCT_insert, 4))
                test_(0x14047b6e0, (TYPES_BSScrapArray, FUNCT_insert, 8))
                test_(0x1407b9cf0, (TYPES_BSScrapArray, FUNCT_insert, 8))
                
                test_(0x1401340e0, (TYPES_BSTSmallArray, FUNCT_begin, (16, 8)))
                test_(0x1403108d0, (TYPES_BSTSmallArray, FUNCT_begin, (1024, 8)))
                test_(0x1404ef970, (TYPES_BSTSmallArray, FUNCT_begin, (72, 8)))
                
                test_(0x140134190, (TYPES_BSTSmallArray, FUNCT_end, (16, 16)))
                test_(0x1402a27e0, (TYPES_BSTSmallArray, FUNCT_end, (8, 8)))
                test_(0x1404c09b0, (TYPES_BSTSmallArray, FUNCT_end, (112, 12)))
                test_(0x1406ce5f0, (TYPES_BSTSmallArray, FUNCT_end, (32, 16)))
                test_(0x1406f3350, (TYPES_BSTSmallArray, FUNCT_end, (8, 8)))
                test_(0x141132980, (TYPES_BSTSmallArray, FUNCT_end, (120, 12)))
                test_(0x140310940, (TYPES_BSTSmallArray, FUNCT_end, (1024, 8)))
                test_(0x141119370, (TYPES_BSTSmallArray, FUNCT_end, (672, 168)))
                test_(0x1410ca2c0, (TYPES_BSTSmallArray, FUNCT_end, (112, 56)))
                test_(0x140bfcc40, (TYPES_BSTSmallArray, FUNCT_end, (128, 16)))
                test_(0x140134190, (TYPES_BSTSmallArray, FUNCT_end, (16, 16)))
                test_(0x141132980, (TYPES_BSTSmallArray, FUNCT_end, (120, 12)))
                test_(0x140c008a0, (TYPES_BSTSmallArray, FUNCT_end, (40, 12)))
                
                print(f'TESTING Arrays_Allocate_xrefs: OK {total}')
            
            def testt(startea):
                type_, funct, size = detect_function(startea)
                if type_ == TYPES_None:
                    #if number_of_calls(startea) == 1:
                    if is_useful_function(startea):
                        data = get_func_asm(startea)
                        len_ = len(data)
                        if len_ <= 400:
                            debuginfo.add(startea, (len_, data))
                        #print(f'{startea:x} {get_func_asm(startea)}')
            
            
            #test()
            
            #print(debuginfo)
            
            iterate_all_funcs(generate_every(), process)
            log('DONE')
        
        
        detect_resizes()
        detect_beginrbeginendrenderases()
    
    def run_Tables():
        debuginfo = DebugInfo(lambda item: f'{item[1]}')
        
        def get_func_signature(type_, funct, size, is_j=False):
            functors = {
                FUNCT_get_free_entry: lambda map_t, entry_t, key_t, val_t, iter_t: f'{entry_t} *__fastcall f({map_t} *map, {entry_t} *data)',
                
                FUNCT_insert:  lambda map_t, entry_t, key_t, val_t, iter_t: f'bool __fastcall f({map_t} *map, {entry_t} *data, unsigned int hash, {key_t} *key, {val_t} *val)',
                FUNCT_insert1: lambda map_t, entry_t, key_t, val_t, iter_t: f'bool __fastcall f({map_t} *map, {entry_t} *data, unsigned int hash, {entry_type} *val_data)',
                
                FUNCT_begin: lambda map_t, entry_t, key_t, val_t, iter_t: f'{iter_t} *__fastcall f({map_t} *map, {iter_t} *ans)',
                FUNCT_end:   lambda map_t, entry_t, key_t, val_t, iter_t: f'{iter_t} *__fastcall f({map_t} *map, {iter_t} *ans)',
                
                FUNCT_find:   lambda map_t, entry_t, key_t, val_t, iter_t: f'bool __fastcall f({map_t} *map, {key_t} *key, {val_t} *ans)',
                FUNCT_find1:  lambda map_t, entry_t, key_t, val_t, iter_t: f'{val_t} __fastcall f(void *map_container, {key_t} *key)',
                FUNCT_find2:  lambda map_t, entry_t, key_t, val_t, iter_t: f'{val_t} __fastcall f(void *map_container, {key_t} key)',
                
                FUNCT_double: lambda map_t, entry_t, key_t, val_t, iter_t: f'void __fastcall f({map_t} *map)'
            }
            
            assert funct in functors, f'Cannot get signature for {funct}: {type_} {size}'
            
            map_internal_name = get_map_internal_name(type_, size)
            entry_type = get_map_entry_name(type_, size)
            key_type = get_map_key_name(type_, size)
            value_type = get_map_val_name(type_, size)
            iterator_type = get_map_iterator_name(type_, size)
            
            #get_map_iterator_name(type_, size)
            #is_j: (get_map_iterator_name(type_, size), get_map_name(type_, size))
            
            if type_ == TYPES_BSTSet and funct == FUNCT_insert:
                return f'bool __fastcall f({map_internal_name} *set, {entry_type} *data, unsigned int hash, {key_type} *key)'
            
            if is_j:
                map_name = get_map_name(type_, size)
                return f'{iterator_type} *__fastcall f({map_name} *map, {iterator_type} *ans)'
            
            return functors[funct](map_internal_name, entry_type, key_type, value_type, iterator_type)
        
        def detected_function(startea, type_, funct, layout):
            func_signature = get_func_signature(type_, funct, layout)
            func_name = f'{type_}::{funct}'
            set_type_name(startea, func_name, func_signature)
        
        """
        With creating structs
        """
        def detected_function_safe(startea, type_, funct, layout):
            create_struct(type_, layout)
            detected_function(startea, type_, funct, layout)
        
        """
        Reads code and returns table type, function name, key/value layout (inserts)
        """
        def detect_function_table_insert(ea, write_any = False):
            def parse_mov(cmd):
                cmd = cmd[3 + 5:]
                cmnt = cmd.find(";")
                if cmnt != -1:
                    cmd = cmd[:cmnt]
                cmd = cmd.strip()
                sep_pos = cmd.find(",")
                return (cmd[:sep_pos], cmd[sep_pos + 2:])
            
            def is_reg(s):
                return (not s.startswith('[')) and (not 'ptr' in s) and (not is_const(s))
            
            def is_mem(s):
                return 'ptr' in s or (s.startswith('[') and s.endswith(']'))
            
            def is_integral(s):
                if s.endswith('h'):
                    s = s[:-1]
                if s.startswith('+') or s.startswith('-'):
                    s = s[1:]
                for ch in s:
                    if (ch < '0' or ch > '9') and (ch < 'A' or ch > 'F') and (ch < 'a' or ch > 'f'):
                        return False
                
                return True
            
            def is_const(s):
                if s.startswith('gs:') or s.startswith('cs:'):
                    return True
                
                return is_integral(s)
            
            def exstract_from_mem(s):
                size = -1
                if 'ptr' in s:
                    if 'xmmword' in s:
                        size = 16
                    elif 'qword' in s:
                        size = 8
                    elif 'dword' in s:
                        size = 4
                    elif 'word' in s:
                        size = 2
                    elif 'byte' in s:
                        size = 1
                    pos = s.find("ptr")
                    s = s[pos + 3 + 1:]
                
                if s.startswith('[') and s.endswith(']'):
                    s = s[1:-1]
                
                if s.startswith('rsp'):
                    return ('rsp', -1, -1)
                
                if '+' in s or '-' in s:
                    pos = s.find("+") if '+' in s else (s.find("-") - 1)
                    offset = s[pos + 1:]
                    if offset.endswith('h'):
                        offset = offset[:-1]
                    
                    s = s[:pos]
                    val = -1
                    if not '+' in offset:
                        if is_integral(offset):
                            offset = int(offset, 16)
                    return (s, offset, size)
                
                return (s, 0, size)
            
            def get_reg_size(reg):
                if reg.startswith('xmm'):
                    return 16
                elif reg.startswith('r'):
                    # r9w
                    if reg.endswith('d'):
                        return 4
                    if reg.endswith('w'):
                        return 2
                    if reg.endswith('b'):
                        return 1
                    else:
                        return 8
                elif reg.startswith('e'):  # eax
                    return 4
                elif reg.endswith('h') or reg.endswith('l'):
                    return 1
                else:
                    return 2
            
            def simplify_reg(reg):
                if reg.startswith('xmm'):
                    return reg
                elif reg.startswith('r'):
                    # r9w
                    if reg.endswith('d') or reg.endswith('w') or reg.endswith('b'):
                        return reg[:-1]
                    else:
                        return reg
                elif reg.startswith('e'):
                    return f'r{reg[1:]}'
                elif reg.endswith('h') or reg.endswith('l'):
                    reg = reg[:-1]
                    if len(reg) == 2:  # sil
                        return f'r{reg}'
                    elif len(reg) == 1:
                        return f'r{reg}x'
                    else:
                        assert False, reg
                else:
                    return f'r{reg}'  # ax
            
            # mov rdx, [rcx+10h]
            def is_read_from_mem(dst, src, off, where):
                if is_reg(dst) and is_mem(src):
                    src, offset, size = exstract_from_mem(src)
                    
                    if size == -1:
                        size = get_reg_size(dst)
                    if off == -1 or offset == off:
                        key = simplify_reg(src)
                        if key in where:
                            return (src, size)
                
                return None
            
            # mov [rbx], eax
            def is_write_to_mem(dst, src, where):
                if is_mem(dst) and is_reg(src):
                    dst, offset, size = exstract_from_mem(dst)
                    if size == -1:
                        size = get_reg_size(src)
                    key = simplify_reg(src)
                    if key in where:
                        if offset != -1:
                            assert where[key] == size, (size, dst, src, where)
                        return (dst, offset, size)
                
                return None
            
            def is_read_from_stack(opcode, dst):
                if re.search('^4.8b(4.24..|8.24....0000)$', opcode):
                    return (dst, get_reg_size(dst))
                
                return None
            
            def check_copy(cmd, dst, src, where):
                if is_reg(src) and is_reg(dst):
                    key = simplify_reg(src)
                    if key in where:
                        where[simplify_reg(dst)] = where[key]
                        comment(cmd, 'copy')
            
            def on_read_reg(reg, where):
                if is_reg(reg):
                    key = simplify_reg(reg)
                    if key in where:
                        where.pop(key)
            
            def on_call(where):
                on_read_reg('rcx', where)
                on_read_reg('rdx', where)
                on_read_reg('r8', where)
                on_read_reg('r9', where)
                on_read_reg('rax', where)
            
            entry_type = ''
            data_symb = 1
            key_symb = 0
            key_symbs = LAYOUTS_KEYS
            
            def on_write_(offset, size, c):
                nonlocal data_symb, entry_type, key_symbs, key_symb
                
                if c == 'd':
                    c = str(data_symb)
                    data_symb += 1
                
                if c == 'k':
                    assert(len(key_symbs) > key_symb)
                    c = key_symbs[key_symb]
                    key_symb += 1
                
                if len(entry_type) < offset:
                    entry_type = entry_type + '.' * (offset - len(entry_type))
                entry_type = entry_type[:offset] + c * size + entry_type[offset + size:]
            
            def comment(cmd, comm):
                nonlocal write_any
                
                comments = False
                comments = True
                
                if write_any:
                    if comments:
                        print(f'{cmd}  ; {comm}')
                    else:
                        print(cmd)
            
            def report(reason):
                return (TYPES_None, FUNCT_None, f'FAIL: {reason}')
            
            def is_red_sub(data):
                sub_140177400 = '48894c2408574883ec3048c7442420feffffff48895c24484889742450498bf9488bf2488bd948894c24284885c97436498bd0e84818ab00488b07488943084c8b074d85c0741b418b400c0f1f4400008bd08d8800100000f0410fb1480c3bc275ee48897310488b5c2448488b7424504883c4305fc3'
                sub_14038C880 = '48894c2408574883ec..48c7442420feffffff48895c24..48897424..498bf9488bf2488bd948894c24284885c9....498bd0..........488b0748894308488b074885c0....f0ff40084889430848897310488b5c24..488b7424..4883c4..5fc3'
                sub_1404DEB60 = '48894c2408574883ec..48c7442420feffffff48895c24..48897424..498bf1488bfa488bd948894c24284885c9....498bd0..........488b0648894308488b064885c0....f0ff....(48897b10|897b10)488b5c24..488b7424..4883c4..5fc3'
                
                # void __fastcall sub_140177400(BSTHashMap_String_8::entry_type *entry, BSTHashMap_String_8::entry_type *sentinel, BSFixedString *key, uint64 *val)
                red_subs1 = [sub_140177400, sub_14038C880, sub_1404DEB60]
                
                # BSTHashMap4_24_1::entry_type *__fastcall sub_1409000E0(BSTHashMap4_24_1::entry_type *entry, uint32 *key, struc_411 *val)
                sub_1409000e0 = '48894c2408574883ec3048c7442420feffffff48895c24504889742458498bd8488bf18b028901488d790848897c2440498b00488907498b004885c07403f0ff00488d4f0848894c2448498d5008e84d8b320090488d4f1048894c2448488d5310e83a8b320090488bc6488b5c2450488b7424584883c4305fc3'
                
                red_subs2 = [sub_1409000e0]
                
                for r in red_subs1:
                    if re.search(r, data):
                        return 1
                
                for r in red_subs2:
                    if re.search(r, data):
                        return 2
                
                return 0
            
            def check_rbx_reg_isok(reg, msg):
                nonlocal rbx_reg
                if rbx_reg == None:
                    comment('', f'rbx_reg is None')
                    return False
                
                if reg != rbx_reg:
                    comment('', f'Not {rbx_reg} used as {msg}')
                    return False
                else:
                    return True
            
            def get_ans_insert1(ea, size):
                def get_ans(ea, kv_size):
                    key_size = get_crc_size_withN(ea)
                    val_size = kv_size - key_size
                    pad = 0
                    if val_size > 8 and key_size % 8 != 0:
                        pad = 8 - (key_size % 8)
                    return (val_size == 0, 'k' * key_size + '.' * pad + (val_size - pad) * '1' + 'ssssssss')
                
                def is_scrap(ea):
                    ans = False
                    
                    def process(ea):
                        nonlocal ans
                        
                        if has_specific_call(ea, [0x140C034A0]):
                            ans = True
                    
                    iterate_all_funcs(generate_xrefs(ea), process)
                    
                    return ans
                
                isSet, size = get_ans(ea, size)
                type_ = ''
                if isSet:
                    type_ = TYPES_BSTSet
                elif is_scrap(ea):
                    type_ = TYPES_BSTScrapHashMap
                else:
                    type_ = TYPES_BSTHashMap
                
                return (type_, FUNCT_insert1, size)
            
            ea = ida_funcs.get_func(ea).start_ea
            data = get_func_asm(ea)
            
            # invalid calls, insert1
            # key have size of crc, value is rest
            
            match = re.match('^4055415641574883ec204.8b..4c8bfa4.8b..4885d20f84........8b510448895c2440ffca8bda418bc04823d848c1e3..4903df48837b(?P<size>..)00....4d85c9....410f10010f1103', data)
            if match:  # shl
                return get_ans_insert1(ea, int(match.group('size'), 16))
            
            match = re.match('^40555641564883ec20498be9488bf24c8bf14885d20f..........448b510441ffca418bc04c23d048895c24404b8d045248837cc2(?P<size>..)00488d1cc275544d85c97414410f10010f1103f2410f104910f20f114b10eb1f', data)
            if match:  # lea
                return get_ans_insert1(ea, int(match.group('size'), 16))
            
            match = re.match('^4056415641574883ec20498bf14c8bfa4c8bf14885d20f8.........448b510441ffca418bc04c23d048895c24404b8d04.248837cc2(?P<size>..)00488d1cc2', data)
            if match:
                return get_ans_insert1(ea, int(match.group('size'), 16))
            
            
            if ea in [0x14110c0b0, 0x14110b7a0]:
                return (TYPES_BSTHashMap, FUNCT_insert, 'k.......11111111ssssssss')
                
            if ea in [0x14058d260, 0x1403942b0, 0x140b03800, 0x14126d8f0, 0x14100b070]:
                return (TYPES_BSTHashMap, FUNCT_insert, 'kkkkkkkk11111111ssssssss')
            
            if ea in [0x14058d3c0, 0x14058d110, 0x14126d8f0]:
                return (TYPES_BSTHashMap, FUNCT_insert, 'kkkk....11111111ssssssss')
            
            if has_specific_call(ea, [0x141509D20]):
                return report('invalid calls undetected')
            
            arg_key_regs = dict()
            arg_key_regs[simplify_reg('r9')] = 8
            key_regs = dict()
            val_regs = dict()
            val_data_regs = dict()
            arg_map_regs = dict()
            arg_map_regs[simplify_reg('rcx')] = 8
            sentinel_regs = dict()
            rbx_regs = dict()
            
            written_key = False
            written_sentinel = False
            written_data = False
            
            kv_size = None
            rbx_reg = 'rbx'
            call_was = False
            
            ins = ea
            while True:
                cmd = idc.GetDisasm(ins)
                opcode = get_bytes(ins, get_item_size(ins), False).hex()
                
                if cmd.startswith('nop'):
                    comment(cmd, 'skipping')
                    ins += get_item_size(ins)
                    continue
                
                if cmd.startswith('cmp'):
                    dst, src = parse_mov(cmd)
                    if src != '0' or not is_mem(dst):
                        ins += get_item_size(ins)
                        continue
                    
                    dst, offset, _ = exstract_from_mem(dst)
                    if type(offset) == int:
                        kv_size = offset
                        rbx_reg = dst
                        rbx_regs[rbx_reg] = 8
                        comment(cmd, f'rbx_reg={rbx_reg}, kv_size={kv_size}')
                    else:
                        offset = offset[offset.find('+') + 1:]
                        if offset.endswith('h'):
                            offset = offset[:-1]
                        
                        if not is_integral(offset):
                            comment(cmd, 'strange src {offset}')
                            return report('strange src')
                        
                        comment(cmd, f'get kv_size')
                        kv_size = int(offset, 16)
                    
                
                if cmd.startswith('jmp'):
                    if opcode[:2] != 'eb' and opcode[:2] != 'e9':
                        comment(cmd, f'strange jmp from {ins:x}')
                        return report('strange jmp')
                    
                    jmp_offset = int(bigendian(opcode[2:]), 16)
                    jmp_ea = ins + 0x5 + jmp_offset
                    
                    if jmp_offset > 0x10000:
                        comment(cmd, f'far jmp {ins:x} -> {jmp_ea:x}')
                        return report('far jmp')
                    
                    comment(cmd, f'jmp {ins:x} -> {jmp_ea:x}')
                    ins = jmp_ea
                    continue
                
                
                if cmd.startswith('call'):
                    call_ea = get_call_ea(ins)
                    if call_ea == None:
                        comment(cmd, f'strange call')
                        return report('strange call')
                    
                    if call_ea == 0x140C28C80:
                        if 'rcx' in rbx_regs:
                            on_call(arg_key_regs)
                            on_call(key_regs)
                            on_call(val_regs)
                            on_call(val_data_regs)
                            on_call(arg_map_regs)
                            on_call(sentinel_regs)
                            on_call(rbx_regs)
                            
                            comment(cmd, f'calling BSFixedString::Set on key')
                            on_write_(0, 8, 'k')
                            written_key = True
                            
                            ins += get_item_size(ins)
                            continue
                        
                        comment(cmd, f'Another case of 0x140C28C80 at {ins:x}')
                        return report(f'unk 0x140C28C80 usage')
                    
                    call_data = get_func_asm(call_ea)
                    
                    is_red = is_red_sub(call_data)
                    if is_red == 1:
                        return (TYPES_BSTHashMap, FUNCT_insert, 'kkkkkkkk11111111ssssssss')
                    if is_red == 2:
                        return (TYPES_BSTHashMap, FUNCT_insert, 'kkkkkkkk111111112222222233333333ssssssss')
                    
                    if call_was:
                        comment(cmd, '2nd call')
                        return report(f'2 calls {ea:x}')
                    
                    comment(cmd, '1st call')
                    call_was = True
                
                
                if cmd.startswith('mov'):
                    dst, src = parse_mov(cmd)
                    is_useful = False
                    
                    arg_map_regs_readed = is_read_from_mem(dst, src, 0x10, arg_map_regs)
                    arg_key_regs_readed = is_read_from_mem(dst, src, -1, arg_key_regs)
                    key_regs_writed = is_write_to_mem(dst, src, key_regs)
                    stack_readed = is_read_from_stack(opcode, dst)
                    val_regs_readed = is_read_from_mem(dst, src, -1, val_regs)
                    val_data_regs_writed = is_write_to_mem(dst, src, val_data_regs)
                    sentinel_regs_writed = is_write_to_mem(dst, src, sentinel_regs)
                    
                    on_read_reg(dst, arg_key_regs)
                    on_read_reg(dst, key_regs)
                    on_read_reg(dst, val_regs)
                    on_read_reg(dst, val_data_regs)
                    on_read_reg(dst, arg_map_regs)
                    on_read_reg(dst, sentinel_regs)
                    on_read_reg(dst, rbx_regs)
                    
                    check_copy(cmd, dst, src, arg_key_regs)
                    check_copy(cmd, dst, src, key_regs)
                    check_copy(cmd, dst, src, val_regs)
                    check_copy(cmd, dst, src, val_data_regs)
                    check_copy(cmd, dst, src, arg_map_regs)
                    check_copy(cmd, dst, src, sentinel_regs)
                    check_copy(cmd, dst, src, rbx_regs)
                    
                    
                    if arg_map_regs_readed != None:
                        _, size = arg_map_regs_readed
                        if size != 8:
                            comment(cmd, f'sentinel size != 8 ({size})')
                            return report('wrong sentinel size')
                        sentinel_regs[simplify_reg(dst)] = 8
                        comment(cmd, f'read sentinel to {dst} {arg_map_regs_readed}')
                    
                    if arg_key_regs_readed != None:
                        _, size = arg_key_regs_readed
                        key_regs[simplify_reg(dst)] = size
                        comment(cmd, f'read key size of {size} to {dst}')
                    
                    if key_regs_writed != None:
                        written_key = True
                        is_useful = True
                        reg, offset, size = key_regs_writed
                        if type(offset) != int:
                            comment(cmd, f'bad key write {offset}')
                            return report('bad key write')
                        comment(cmd, f'writing key size of {size}')
                        on_write_(offset, size, 'k')
                        
                        if not check_rbx_reg_isok(reg[0:3], f'key dst: {cmd}'):
                            return report('rbx key')
                    
                    if stack_readed != None:
                        _, size = stack_readed
                        val_regs[simplify_reg(dst)] = size
                        comment(cmd, f'val size of {size} in {dst}')
                    
                    if val_regs_readed != None:
                        _, size = val_regs_readed
                        val_data_regs[simplify_reg(dst)] = size
                        comment(cmd, f'read part of value data size of {size} to {dst}')
                    
                    if val_data_regs_writed != None:
                        written_data = True
                        is_useful = True
                        reg, offset, size = val_data_regs_writed
                        if type(offset) != int:
                            comment(cmd, f'bad data write {offset}')
                            return report('bad data write')
                        
                        comment(cmd, f'write part of value data size of {size} at +{offset:x}')
                        on_write_(offset, size, 'd')
                        if not check_rbx_reg_isok(reg[0:3], f'data dst: {cmd}'):
                            return report('rbx data')
                    
                    if sentinel_regs_writed != None:
                        written_sentinel = True
                        is_useful = True
                        reg, offset, size = sentinel_regs_writed
                        comment(cmd, f'write sentinel size of {size} at +{offset}')
                        on_write_(offset, size, 's')
                        if not check_rbx_reg_isok(reg[0:3], f'sentinel dst: {cmd}'):
                            return report('rbx sentinel')
                    
                    
                    if is_mem(dst):
                        reg, off, _ = exstract_from_mem(dst)
                        if reg in rbx_regs and not is_const(src) and not 'rsp' in cmd:
                            if not is_useful:
                                comment(cmd, 'I missed this')
                                return report('missed cmd')
                    
                if cmd == 'retn':
                    break
                
                ins += get_item_size(ins)
            
            if call_was:
                crc_size = get_crc_size_withN(ea)
                key_size = 8
                if kv_size != None:
                    return (TYPES_BSTHashMap, FUNCT_insert, 'kkkkkkkk' + '1' * (kv_size - key_size) + 'ssssssss')
                
                comment('', 'kv_size in undefined')
                return report('kv_size in undefined')
            
            if not (written_key and written_sentinel):
                comment('', f'not all parts here: written_key={written_key} written_sentinel={written_sentinel}')
                return report('some parts missed')
            
            if not written_data:
                return (TYPES_BSTSet, FUNCT_insert, entry_type)
            
            return (TYPES_BSTHashMap, FUNCT_insert, entry_type)

        """
        Reads code and returns table type, function name, key/value layout (other than inserts)
        """
        def detect_function_table(startea):
            data = get_func_asm(startea)
            
            if re.search('^4c8b492033c0448bc04d85c97424448b4104498bc149c1e0..4d03c10f1f4000493bc0730d488378..0075064883c0..ebee488902488bc24c894208c3$', data):
                return (TYPES_BSTHashMap, FUNCT_begin, int(data[80:82], 16))
            
            if re.search('^4c8b492033c0448bc04d85c974248b4104488d0c..498bc14d8d04..0f1f4000493bc0730d488378..0075064883c0..ebee488902488bc24c894208c3$', data):
                return (TYPES_BSTHashMap, FUNCT_begin, int(data[80:82], 16) )
            
            if re.search('^4c8b492033c0448bc04d85c974248b41044c8d04..498bc149c1e0044d03c190493bc0730d488378..0075064883c0..ebee488902488bc24c894208c3$', data):
                return (TYPES_BSTHashMap, FUNCT_begin, int(data[80:82], 16) )
            
            
            if re.search('^4c8b41204d85c074158b410448c1e0..4903c048890248894208488bc2c333c048890248894208488bc2c3$', data):
                return (TYPES_BSTHashMap, FUNCT_end, 2 ** int(data[30:32], 16) - 8 )  # shl
            
            if re.search('^4c8b41204d85c074168b4104488d0c..498d04c848890248894208488bc2c333c048890248894208488bc2c3$', data):
                return (TYPES_BSTHashMap, FUNCT_end, get_size(data[24:32]) * get_size(data[32:40]) - 8 )  # lea lea
            
            if re.search('^4c8b41204d85c074198b4104488d0c..488bc248c1e1..4903c848890a48894a08c333c9488bc248890a48894a08c3$', data):
                return (TYPES_BSTHashMap, FUNCT_end, get_size(data[24:32]) * (2 ** int(data[44:46], 16)) - 8 )  # lea shl
            
            
            if re.search('^448b590833c04c8bc14585db....448b5104448b490c41ffca0f1f8000000000418d49ff4123ca448bc948c1e1..4803ca4589480c488379..00480f44c14885c074dd418d4bff41894808c3$', data):
                return (TYPES_BSTHashMap, FUNCT_get_free_entry, int(data[112:114], 16) )  # shl
            
            if re.search('^448b590833c04c8bc14585db....448b5104448b490c41ffca0f1f800000000041ffc94523ca4969c9........4589480c4803ca4883b9..........480f44c14885c0....418d4bff41894808c3$', data):
                return (TYPES_BSTHashMap, FUNCT_get_free_entry, int(bigendian(data[110:118]), 16) )  # imul
            
            if re.search('^448b590833c04c8bc14585db....448b5104448b490c41ffca0f1f8000000000418d49ff4123ca448bc94589480c488d0c..48c1e1..4803ca488379..00480f44c14885c074d9418d4bff41894808c3$', data):
                return (TYPES_BSTHashMap, FUNCT_get_free_entry, int(data[120:122], 16) )  # lea shl
            
            if re.search('^48895c2408448b590833c0488bda4c8bc94585db....448b5104448b410c41ffca418d48ff4123ca448bc14589410c488d0c..48837c....00488d14cb480f44c24885c074db418d4bff41894908488b5c2408c3$', data):
                return (TYPES_BSTHashMap, FUNCT_get_free_entry, int(data[110:112], 16) )  # lea shl 2
            
            # bool find(Map *map, key_t* key, val_t* a3)
            match = re.match('^48895c24104889742418574883ec20488bfa488bd9(48)?8b12488d4c2430498bf0e8........(488b..(?P<entries_offset1>..)|488b8b(?P<entries_offset2>......)00)(4532d2|(45)?32c9)(4885c9|4885d2)....(448b4b04|8b430444)(8b44243041ffc94c23c84b8d04.9|8b442430ffc84923c048c1e00.4803c.)(48837cc.(?P<cmp_size1>..)00|488378(?P<cmp_size2>..)00)', data)
            if match:
                entries_offset = match.group('entries_offset1')
                if entries_offset == None:
                    entries_offset = match.group('entries_offset2')
                
                kv_size = match.group('cmp_size1')
                if kv_size == None:
                    kv_size = match.group('cmp_size2')
                
                assert kv_size != None
                assert entries_offset != None
                
                #print(entries_offset)
                
                key_size = get_crc_size_withN(startea)
                kv_size = int(bigendian(kv_size), 16)
                return (TYPES_BSTHashMap, FUNCT_find, ( key_size, kv_size - key_size ) )
            
            # val_t find(Map*, key_t* key)
            match = re.match('^48895c24104889742418574883ec20488bf2488bd9488b12488d4c243033ffe8........(488b..(?P<entries_offset1>..)|488b8b(?P<entries_offset2>......)00)4885c9....448b430c8b44243041ffc84c23c04b8d044048397cc1(?P<cmp_size1>..)', data)
            if match:
                entries_offset = match.group('entries_offset1')
                if entries_offset == None:
                    entries_offset = match.group('entries_offset2')
                
                kv_size = match.group('cmp_size1')
                
                assert kv_size != None
                assert entries_offset != None
                
                #print(entries_offset)
                
                key_size = get_crc_size_withN(startea)
                kv_size = int(bigendian(kv_size), 16)
                return (TYPES_BSTHashMap, FUNCT_find1, ( key_size, kv_size - key_size ) )
            
            # val_t find(Map*, key_t key)  // key by value
            match = re.match('^48895c2410(4889742418)?574883ec20488bd9(48)?8bf2488d4c2430(33ff)?e8........(488b..(?P<entries_offset1>..)|488b8b(?P<entries_offset2>......)00)4885c9....448b43..8b44243041ffc84c23c04b8d0440(48397cc1(?P<cmp_size1>..)|48837cc1(?P<cmp_size2>..)00)', data)
            if match:
                entries_offset = match.group('entries_offset1')
                if entries_offset == None:
                    entries_offset = match.group('entries_offset2')
                
                kv_size = match.group('cmp_size1')
                if kv_size == None:
                    kv_size = match.group('cmp_size2')
                
                assert kv_size != None
                assert entries_offset != None
                
                #print(entries_offset)
                
                key_size = get_crc_size_withN(startea)
                kv_size = int(bigendian(kv_size), 16)
                return (TYPES_BSTHashMap, FUNCT_find2, ( key_size, kv_size - key_size ) )
            
            return (TYPES_None, FUNCT_None, 0)
        
        def process_double(startea, type_, layout):
            detected_function(startea, type_, FUNCT_double, layout)
        
        """
        Get function type and, if it is get_free_entry, process it, all xrefs to detect inserts
        """
        def process_get_free_entry(startea):
            xrefs = list()
            """
            Get function type and, if it is `insert`(s), return type.
            """
            def check_is_insert(startea):
                (type_, funct, size) = detect_function_table_insert(startea)
                
                if type_ == TYPES_None:
                    return None
                
                if funct != FUNCT_insert and funct != FUNCT_insert1:
                    return None
                
                return (type_, funct, size)

            def xrefs_set(startea, type_, layout):
                ans = check_is_insert(startea)
                if ans != None:
                    _, funct, _ = ans
                    detected_function(startea, type_, funct, layout)
                    
                    if funct == FUNCT_insert1:
                        iterate_all_funcs(generate_xrefs(startea), lambda ea: process_double(ea, type_, layout))
            
            def xrefs_collect(startea):
                ans = check_is_insert(startea)
                if ans != None:
                    xrefs.append(ans)
            
            (type_, funct, size) = detect_function_table(startea)
            
            if type_ == TYPES_None:
                return
            
            if funct != FUNCT_get_free_entry:
                return
            
            iterate_all_funcs(generate_xrefs(startea), xrefs_collect)
            
            # some get_free_entry functions have 2 xrefs -- insert & insert1
            # some have only one
            # 14058f110 has 3 xrefs: insert1, insert, insert (same layout)
            
            # insert is more informative
            xrefs = set(xrefs)
            if len(xrefs) == 0:
                # one case here
                # 0x1412324a0
                return
            
            xrefs_insert = list(filter(lambda x: x[1] == FUNCT_insert, xrefs))
            assert len(xrefs_insert) <= 1, f'{startea:x}: {xrefs_insert}'
            
            xrefs_insert1 = list(filter(lambda x: x[1] == FUNCT_insert1, xrefs))
            assert len(xrefs_insert1) <= 1, f'{startea:x}: {xrefs_insert1}'
            
            layout = ''
            if len(xrefs_insert) == 1:
                type_, _, layout = xrefs_insert[0]
            else:
                assert len(xrefs) == 1, f'{startea:x}: {xrefs}'
                type_, _, layout = list(xrefs)[0]
            
            if len(xrefs_insert1) == 1 and type_ == TYPES_BSTHashMap:
                type_, _, _ = xrefs_insert1[0]
            
            detected_function_safe(startea, type_, funct, layout)
            
            iterate_all_funcs(generate_xrefs(startea), lambda ea: xrefs_set(ea, type_, layout))
        
        def test_inserts():
            def test_(ea, expected, canfail = False, insert1 = False, isSet = False):
                print(f'Testing {ea:x}')
                
                type_, func, actual = detect_function_table_insert(ea)
                if canfail and actual.startswith('FAIL'):
                    print(f'Failed, self report')
                else:
                    assert (type_ == TYPES_BSTHashMap and not isSet) or (type_ == TYPES_BSTSet and isSet), f'{ea:x} isSet is {isSet}, but {type_}'
                    assert (func == FUNCT_insert and not insert1) or (func == FUNCT_insert1 and insert1), f'{ea:x} insert1 is {insert1}, but {func}'
                    assert actual == expected, f'{ea:x} {expected} != {actual}'
                    print(f'OK')
            
            test_(0x140596130, 'kkkkkkkk111111111111111122222222ssssssss')
            test_(0x14014b730, 'kkkk....22222222ssssssss')
            test_(0x14036a880, 'kkkkkkkk22222222ssssssss')
            test_(0x1408305c0, 'kkkkkkkk111111112222222233333333ssssssss')
            test_(0x140174e20, 'kkkk....11111111ssssssss')
            test_(0x1401aaf40, 'kkkkkkkk11111111ssssssss')
            test_(0x14045bbe0, 'kk......22222222ssssssss')
            test_(0x140334550, 'kkkkkkkk1111....ssssssss')
            test_(0x14023c1a0, 'kkkk11111111....ssssssss')
            test_(0x140244d60, 'kkkk11112.......ssssssss')
            test_(0x1404e94e0, 'kkkkkkkk11112222ssssssss')
            test_(0x1406bda60, 'kkkkkkkk11223344ssssssss')
            test_(0x1403a32a0, 'kkkkkkkk11......ssssssss')
            test_(0x1409043c0, 'kkkkkkkk1.......ssssssss')
            test_(0x140596130, 'kkkkkkkk111111111111111122222222ssssssss')
            test_(0x140c80e90, 'kkkk111111112222ssssssss')
            test_(0x140245050, 'kkkk1111ssssssss')
            test_(0x140174cd0, 'kkkk1...ssssssss')
            test_(0x1407ebf00, 'kkkk12..ssssssss')
            test_(0x140578950, 'kkkk....1111....22222222ssssssss')
            test_(0x1404f88e0, 'kkkk....1111111111111111ssssssss')
            test_(0x1407e3290, 'kkkk....1111111122......333344445555....ssssssss')
            
            # no crc
            test_(0x140dd3db0, 'kkkkkkkk22222222ssssssss')
            
            
            def gen_ans4(size):
                return 'kkkk....' + '1' * (size - 8) + 'ssssssss'
            
            def gen_ans8(size):
                return 'kkkkkkkk' + '1' * (size - 8) + 'ssssssss'
            
            # invalid functions
            test_(0x140dc5310, 'kkkkkkkk111111111111111111111111111111111111111111111111ssssssss', insert1 = True)
            test_(0x140596f20, 'kkkk....1111111111111111ssssssss', insert1 = True)
            test_(0x140580490, 'kkkk1111ssssssss', insert1 = True)
            test_(0x1402409b0, 'kkkk1111ssssssss', insert1 = True)
            test_(0x140bf8290, 'kkkk....11111111ssssssss', insert1 = True)
            test_(0x14110c5a0, 'k.......11111111ssssssss', insert1 = True)
            test_(0x140f46230, 'kkkk....111111111111111111111111ssssssss', insert1 = True)
            test_(0x140afd460, 'kkkkkkkk11111111111111111111111111111111111111111111111111111111ssssssss', insert1 = True)
            
            test_(0x14047fdb0, 'kkkk....11111111ssssssss', insert1 = True)
            test_(0x14023DB60, 'kkkk....11111111ssssssss', insert1 = True)
            test_(0x1401A6F90, 'kkkkkkkk11111111ssssssss', insert1 = True)
            test_(0x140599180, 'kkkkkkkk11111111ssssssss', insert1 = True)
            
            
            test_(0x1401002C0, 'kkkkkkkkssssssss', insert1 = True)
            test_(0x140178e50, 'kkkk1111ssssssss', insert1 = True)
            
            test_(0x140831200, gen_ans8(32), insert1 = True)
            
            # jumps
            test_(0x1408ff9d0, 'kkkk....11111111ssssssss')
            test_(0x1408FFD50, 'kkkk....11111111ssssssss')
            test_(0x14126e060, 'kkkkkkkk11111111ssssssss')
            
            # no rbx
            test_(0x140C6A2F0, 'kkkkkkkk1111....ssssssss')
            test_(0x140935640, 'kkkkkkkk11111111ssssssss')
            test_(0x14128be30, 'kkkkkkkk1.......ssssssss')
            
            test_(0x1403942b0, 'kkkkkkkk11111111ssssssss', True)  # call string::set to value
            
            
            # calls: string, 8
            test_(0x140174F90, 'kkkkkkkk11111111ssssssss')
            test_(0x14038b550, 'kkkkkkkk11111111ssssssss')
            test_(0x1403d59e0, 'kkkkkkkk11111111ssssssss')
            test_(0x1404DE1C0, 'kkkkkkkk11111111ssssssss')
            
            # calls: other
            test_(0x1408FF2C0, 'kkkkkkkk111111112222222233333333ssssssss')
            
            # calls: key 8, value rest
            test_(0x140af6c50, gen_ans8(160))
            test_(0x140af6950, gen_ans8(72))
            test_(0x140af6e70, gen_ans8(64))
            test_(0x140ec0820, gen_ans8(24))
            test_(0x141231540, gen_ans8(24))
            test_(0x14124dcf0, gen_ans8(24))
            test_(0x14126df10, gen_ans8(24))
            test_(0x14126e3f0, gen_ans8(24))
            test_(0x1409093a0, gen_ans8(24))
            test_(0x141254750, gen_ans8(16))
            test_(0x1409093a0, gen_ans8(24))
            
            # calls: string::set, key 8, value rest
            test_(0x140af6800, gen_ans8(0x10))
            test_(0x1410c29f0, gen_ans8(0x10))
            test_(0x1408d6280, gen_ans8(0x10))
            test_(0x140909500, gen_ans8(40))
            
            test_(0x140af6ad0, 'kkkkkkkk11111111111111112222....ssssssss')
            
            # calls: 2 calls
            test_(0x1412316c0, gen_ans8(0x20))  # set on key + smth
            test_(0x14128c2b0, gen_ans8(0x48))  # set on key + smth
            test_(0x14100B070, gen_ans8(0x10), True)
            
            # key is pair
            test_(0x14047a570, 'kkkkKKKK11111111ssssssss')
            test_(0x14059BC30, 'kkkkKKKKxxxx1111ssssssss')
            
            test_(0x1401a55a0, 'KKKKKKKK11111111ssssssss')  # double key write
            test_(0x140F45C90, 'kkkk....111111112222222233333333ssssssss', True)  # cmp lea
            test_(0x141231830, 'kkkkkkkk1111....22222222ssssssss', True) # alias for rbx+0x10
            
            #test_detect_function_table_(0x1400FF350, '', True)  # inlined with global
            test_(0x140D37950, '', True)  # too many rax
            
            # set
            test_(0x140244c40, 'kkkk....ssssssss', isSet = True)
            test_(0x1405a1140, 'kkkkkkkkssssssss', isSet = True)
            test_(0x14077b640, 'kkkkkkkkssssssss', isSet = True)
            test_(0x1403243f0, 'kkkkkkkkssssssss', isSet = True)
            test_(0x14059bdc0, 'kkkkKKKKxxxx....ssssssss', isSet = True)
        
        def process_inserts_other(startea):
            if not has_crc(startea):
                return
            
            (type_, funct, layout) = detect_function_table_insert(startea)

            if type_ == TYPES_None:
                return
            
            if funct != FUNCT_insert1 and funct != FUNCT_insert:
                return
            
            detected_function_safe(startea, type_, funct, layout)
            
            if funct == FUNCT_insert1:
                iterate_all_funcs(generate_xrefs(startea), lambda ea: process_double(ea, type_, layout))
        
        def process_other(startea):
            def process_j(startea, func_signature, func_name):
                if re.search('^40534883ec204883c108488bdae8........488bc34883c4205bc3$', get_func_asm(startea)):
                    set_type_name(startea, func_name, func_signature)
            
            (type_, funct, size) = detect_function_table(startea)
            if type_ == TYPES_None or funct == FUNCT_get_free_entry:
                return
            
            
            detected_function_safe(startea, type_, funct, size)
            
            if funct == FUNCT_begin or FUNCT_end:
                iterate_all_funcs(generate_xrefs(startea), lambda ea: process_j(ea, get_func_signature(type_, funct, size, True), f'j_{type_}::{funct}'))
        
        def find_inlined_get_free_entry():
            def gen(data, true_data):
                true_len = len(true_data)
                data_len = len(data)
                for l in range(0, data_len - true_len, 2):
                    dist = distance(true_data, data[l:l + true_len])
                    if 2 * dist <= true_len:
                        yield (dist, l // 2)
            
            def merger(data):
                for ans in gen(data, '418d49ff4123ca448bc948c1e1044803ca4589480c4883790800480f44c14885c074dd418d4bff'):  # shl
                    yield ans
                
                for ans in gen(data, '418d49ff4123ca448bc94589480c488d0c8948c1e1044803ca4883794800480f44c14885c074d9418d4bff'):  # lea shl
                    yield ans
                
                for ans in gen(data, '48895c2408448b590833c0488bda4c8bc94585db....448b5104448b410c41ffca418d48ff4123ca448bc14589410c488d0c..48837c....00488d14cb480f44c24885c074db418d4bff41894908488b5c2408c3'):  # lea shl 2
                    yield ans
                
                for ans in gen(data, '41ffc94523ca4969c9a80000004589480c4803ca4883b9a000000000480f44c14885c074db418d4bff41894808c3'):  # imul dword
                    yield ans
                
                for ans in gen(data, '41ffc94523ca4969c9a84589480c4803ca4883b9a000480f44c14885c074db418d4bff41894808c3'):  # imul char
                    yield ans
                
                return
            
            def process(startea):
                data = get_func_asm(startea)
                ans = min(merger(data), key = lambda x: x[0], default=None)
                if ans:
                    (type_, funct, size) = detect_function_table(startea)
                    if funct == FUNCT_get_free_entry:
                        return
                    
                    if type_ == TYPES_None:
                        dist, l = ans
                        name = get_name(startea)
                        if re.search('^sub_14[0-9a-fA-F]{7}$', name):
                            name = ''
                        else:
                            name = f' (aka {name})'
                        print(f'{startea:x} at {startea+l:x}. Origin size={len(data):x}{name}')

            print('Finding inlined "get_free_entry" functions. It likely "insert" functions.')
            
            iterate_all_funcs(generate_every(), process)
        
        def testt(startea):
            type_, funct, size = detect_function_table(startea)
            if type_ == TYPES_None:
                #if number_of_calls(startea) == 1:
                if is_useful_function(startea):
                    data = get_func_asm(startea)
                    len_ = len(data)
                    if len_ <= 400:
                        debuginfo.add(startea, (len_, data))
        
        #find_inlined_get_free_entry()
        
        #test_inserts()
        
        log("Maps: get_free_entry -> insert")
        iterate_all_funcs(generate_every(), process_get_free_entry)
        log("DONE")
        
        log("Maps: inlined get_free_entry -> insert")
        iterate_all_funcs(generate_file('inlined_getfreeentry.txt'), process_inserts_other)
        log("DONE")
        
        log("Maps: other")
        iterate_all_funcs(generate_every(), process_other)
        log("DONE")
        
        #print(debuginfo)
    
    
    if action_mode == ACTION_MODES_import or action_mode == ACTION_MODES_inplace:
        header()
    
    if action_mode != ACTION_MODES_import:
        prepare()
        run_Arrays()
        run_Tables()
    
    if action_mode == ACTION_MODES_export:
        with open('BSTL_data.py', 'w') as out:
            print()
            for type_, size in structs_data:
                if type(size) == str:
                    size = f'"{size}"'
                out.write(f'create_struct("{type_}", {size})\n')
            
            out.write(f'\n')
            
            for ea, (name, func_type) in function_data.items():
                out.write(f'set_type_name(0x{ea:x}, "{name}", "{func_type}")\n')
    
    if action_mode == ACTION_MODES_import:
        with open("BSTL_data.py") as f:
            code = compile(f.read(), "BSTL_data.py", 'exec')
            exec(code)
    
    stats.get_stats()


## ^^^ RUNNING ^^^ ##
