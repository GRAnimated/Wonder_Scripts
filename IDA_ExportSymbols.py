import idaapi
import ida_kernwin
import idautils
import csv

global_offset = 0x7100000000

def is_user_defined_symbol(ea):
    label = ida_bytes.get_flags(ea) & ida_bytes.FF_LABL # FF_LABL checks for a non-auto-generated symbol, but it does miss some that IDA generates
    flags = ida_bytes.get_flags(ea) & ida_bytes.FF_NAME # FF_NAME checks for user defined names, but seems to do almost nothing?
    return flags and not label

def should_exclude_symbol(name):
    # stupid system, probably missing some
    exclusions = ["nullsub", "Zdl", "def_", "j_", "jpt", "_0"]
    return any(exclusion in name for exclusion in exclusions)

def export_filtered_user_defined_symbols_to_csv(csv_filename):
    data = []
    
    for name in idautils.Names():
        ea = name[0]
        symbol_name = name[1]
        if is_user_defined_symbol(ea) and not should_exclude_symbol(symbol_name):
            last_updated = str(int(time.time()))
            last_updated_user = "0"

            data.append([f'{ea-global_offset:08X}', symbol_name, last_updated, last_updated_user])
    
    data.sort(key=lambda x: int(x[0], 16))
    
    with open(csv_filename, mode='w', newline='') as file:
        csv_writer = csv.writer(file, quoting=csv.QUOTE_ALL)
        csv_writer.writerow(["Address", "Name", "Last Updated", "Last Updated User"])
        csv_writer.writerows(data)

def export_symbols():
    csv_filename = ida_kernwin.ask_file(True, "*.txt", "Save symbols", "symbols.txt")
    if csv_filename:
        export_filtered_user_defined_symbols_to_csv(csv_filename)
        print(f"Symbols exported to {csv_filename}!")
    else:
        print("Could not export symbols!")

export_symbols()