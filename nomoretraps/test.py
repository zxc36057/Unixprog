count = 0
with open("no_more_traps", "rb") as f:
    byte = f.read(1)
    while byte != "":
        # Do stuff with byte.
        byte = f.read(1)
        if(byte == b'\xcc'):
            count +=1
print count