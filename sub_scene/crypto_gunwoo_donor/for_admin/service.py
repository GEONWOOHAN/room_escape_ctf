import asyncio, hashlib, os, struct, zlib
from Crypto.Cipher import AES

N, BS = 64, 16
WRITE_LIMIT = 3
KINDS = (1, 2, 3)
POLICY_CLASSES = (3, 8, 13)
ADMIN_VALUES = (0xA11D0001, 0, 0x5641554C54000001)
GUEST_VALUES = (0x4755455354, 10001337, 0)
FLAG = os.getenv("FLAG", "SHA_local_development_flag")

CLASS_CODE = bytes((1,2,5,0,0,0,5,2,3,0,0,0,4,1,6,2,4,2,15,0,0,0,8,255))
STEP_CODE = bytes((1,3,7,7,4,3,6,9,4,3,7,13,4,255))
LAYOUT_SEED_CODE = bytes((1,2,0x63,0x7c,0xa5,0x6d,4,255))
POLICY_SEED_CODE = bytes((1,2,0x91,0xe1,0x0b,0xc4,4,255))

def vm(code,value):
    stack=[]; pc=0
    while True:
        op=code[pc]; pc+=1
        if op==1: stack.append(value&0xffffffff)
        elif op==2: stack.append(int.from_bytes(code[pc:pc+4],"little")); pc+=4
        elif op==3: stack.append(stack[-1])
        elif op==4: stack.append((stack.pop()^stack.pop())&0xffffffff)
        elif op==5: stack.append((stack.pop()*stack.pop())&0xffffffff)
        elif op==6: stack.append(stack.pop()>>code[pc]); pc+=1
        elif op==7: stack.append((stack.pop()<<code[pc])&0xffffffff); pc+=1
        elif op==8: stack.append(stack.pop()&stack.pop())
        elif op==255: return stack[-1]
        else: raise ValueError("invalid policy opcode")

def tweak_class(i): return vm(CLASS_CODE,i)
def step(x): return vm(STEP_CODE,x)
def layout(epoch):
    state, result = vm(LAYOUT_SEED_CODE,epoch), list(range(N))
    for group in range(16):
        logical = [i for i in range(N) if tweak_class(i) == group]; physical = logical[:]
        for i in range(len(physical) - 1, 0, -1):
            state = step(state); j = state % (i + 1); physical[i], physical[j] = physical[j], physical[i]
        for src, dst in zip(logical, physical): result[src] = dst
    return result
def generation(epoch): return ((epoch >> 16) ^ epoch ^ 0x5243) & 0xffff
def rotate_left(value,count): return ((value<<count)|(value>>(32-count)))&0xffffffff
def routed_epoch(epoch,route): return epoch^rotate_left(route,11)^0x51a7c3d9
def session_stamp(epoch): return step((epoch*0x9e3779b1+0x7f4a7c15)&0xffffffff)
def route_seal(epoch,route): return step(route^rotate_left(epoch,7)^0xa5c31f27)
def policy_positions(epoch):
    state = vm(POLICY_SEED_CODE,epoch)
    donors, targets, decoys = [], [], []
    for group in POLICY_CLASSES:
        members = [i for i in range(N) if tweak_class(i) == group]
        state = step(state); donor_at = state % len(members)
        state = step(state); target_at = (donor_at + 1 + state % (len(members) - 1)) % len(members)
        remaining = [i for i in range(len(members)) if i not in (donor_at, target_at)]
        state = step(state); decoy_at = remaining[state % len(remaining)]
        donors.append(members[donor_at]); targets.append(members[target_at]); decoys.append(members[decoy_at])
    return tuple(donors), tuple(targets), tuple(decoys)
def active_positions(epoch,route):
    public=policy_positions(epoch); private=policy_positions(routed_epoch(epoch,route))
    return tuple((public[column][0],private[column][1],private[column][2]) for column in range(3))
def record(kind, gen, value):
    head = struct.pack("<BBHQ", 0xd7, kind, gen, value)
    return head + struct.pack("<I", zlib.crc32(head) & 0xffffffff)
def gf_double(block):
    value=int.from_bytes(block,"big"); carry=value>>127
    return (((value<<1)&((1<<128)-1))^(0x87 if carry else 0)).to_bytes(BS,"big")
def tweak(index,key,epoch):
    mask=AES.new(key,AES.MODE_ECB).encrypt(struct.pack("<I",epoch)+b"DONOR-XEX-v6")
    for _ in range(tweak_class(index)): mask=gf_double(mask)
    return mask
def xex(block, index, key, epoch, decrypt=False):
    mask=tweak(index,key,epoch); mixed=bytes(a^b for a,b in zip(block,mask)); aes=AES.new(key,AES.MODE_ECB)
    core=aes.decrypt(mixed) if decrypt else aes.encrypt(mixed)
    return bytes(a^b for a,b in zip(core,mask))
def expected(epoch): return tuple(record(k,generation(epoch),v) for k,v in zip(KINDS,ADMIN_VALUES))
def fresh_memory(key, epoch, route):
    plain=[hashlib.sha256(f"padding:{i}:{epoch}".encode()).digest()[:BS] for i in range(N)]; good=expected(epoch)
    donors,targets,decoys=active_positions(epoch,route)
    for i,b in zip(donors,good): plain[i]=b
    for i,k,v in zip(targets,KINDS,GUEST_VALUES): plain[i]=record(k,generation(epoch),v)
    for i,k,v in zip(decoys,KINDS,ADMIN_VALUES): plain[i]=record(k,(generation(epoch)+1)&0xffff,v)
    order=layout(epoch); memory=[b""]*N
    for logical,physical in enumerate(order): memory[physical]=xex(plain[logical],physical,key,epoch)
    return memory
async def send(w,s=""): w.write((s+"\n").encode()); await w.drain()
async def handle(r,w):
    key=os.urandom(32); epoch,route=struct.unpack("<II",os.urandom(8)); memory=fresh_memory(key,epoch,route)
    writes_left = WRITE_LIMIT
    try:
        await send(w,"DONOR Secure Processor / build 6.2"); await send(w,f"session stamp:{session_stamp(epoch):08x}")
        await send(w,f"write budget:{writes_left}")
        await send(w,"commands: sheath | diagnose | transplant <index> <32-hex> | attest | quit")
        while True:
            w.write(b"donor> "); await w.drain(); line=await r.readline()
            if not line: break
            p=line.decode(errors="replace").strip().split(); cmd=p[0].lower() if p else ""
            if cmd=="sheath" and len(p)==1:
                for i,b in enumerate(memory): await send(w,f"{i:02d}:{b.hex()}")
            elif cmd=="diagnose" and len(p)==1:
                order=layout(epoch); target=active_positions(epoch,route)[1][0]
                plain=xex(memory[order[target]],order[target],key,epoch,True)
                await send(w,f"routing capsule:{route_seal(epoch,route):08x}" if plain==expected(epoch)[0] else "diagnostic access denied")
            elif cmd=="transplant" and len(p)==3:
                try:
                    i=int(p[1]); b=bytes.fromhex(p[2])
                    if not 0 <= i < N or len(b) != BS:
                        raise ValueError
                    if not writes_left:
                        await send(w,"error: write budget exhausted")
                        continue
                    memory[i]=b; writes_left -= 1
                    await send(w,f"accepted ({writes_left} writes left)")
                except ValueError: await send(w,"error: expected block index and exactly 16 bytes")
            elif cmd=="attest" and len(p)==1:
                order=layout(epoch); targets=active_positions(epoch,route)[1]
                got=tuple(xex(memory[order[i]],order[i],key,epoch,True) for i in targets)
                await send(w,FLAG if got==expected(epoch) else "access denied")
            elif cmd=="quit": break
            else: await send(w,"unknown command")
    except (ConnectionError,asyncio.IncompleteReadError,ValueError): pass
    finally:
        w.close()
        try: await w.wait_closed()
        except ConnectionError: pass
async def main():
    server=await asyncio.start_server(handle,"0.0.0.0",31345,limit=4096,backlog=256)
    async with server: await server.serve_forever()
if __name__=="__main__": asyncio.run(main())
