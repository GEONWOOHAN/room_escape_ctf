#!/usr/bin/env python3
import argparse, hashlib, hmac, json, mmap, struct, time, zlib
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.PublicKey import ECC

CURVE="P-256"; ORDER=0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551; MASK=(1<<64)-1
T={"version":1,"context":2,"file":3,"volume":4,"ephemeral":5,"operator":6,"wrap":7,"manifest_nonce":8,"manifest":9,"manifest_tag":10,"region":11,"body_size":12,"digest":13,"checksum":14}
RECORD=struct.Struct("<Q16sQQIHHQ"); PAGE=struct.Struct("<QBBH64sQ"); REGISTRATION=struct.Struct("<8sII40s16s24s24sHHHHIQQQII"); DIRECTORY=struct.Struct("<8sIIQQI"); SESSION=struct.Struct("<8sQ16sQQII"); VTABLE=struct.Struct("<8sIQI"); CHECKPOINT=struct.Struct("<8s7H4HI"); MREC=struct.Struct("<IIIII16s"); JHEADER=struct.Struct("<8sHHII16s"); JREC=struct.Struct("<QIHHIIQ"); JCOMMIT=struct.Struct("<QI32s"); CACHE_HEADER=struct.Struct("<8s32s32sQ32s"); CACHE_RECORD=struct.Struct("<64s32s"); CACHE_MAGIC=b"KMITM2\0\0"
FRAGMENT_HEADER=struct.Struct("<QQIHHI"); PROVIDER_INTERFACE=struct.Struct("<5I4x4Q")
CONTRACT_PREFIX=struct.Struct("<8sHH10B5H11Q"); CRYPTO_BINDING=struct.Struct("<BBB6sQ"); CONTRACT_SIZE=CONTRACT_PREFIX.size+8*CRYPTO_BINDING.size+4*8+4

def rol(x,n): return ((x<<n)|(x>>(64-n)))&MASK
def next64(state):
    state^=state>>12; state^=(state<<25)&MASK; state^=state>>27; state&=MASK
    return state,(state*2685821657736338717)&MASK
def derive(context,file_token,volume,domain): return hashlib.blake2s(struct.pack("<QQ",context,file_token)+volume+domain).digest()
def hkdf(ikm,salt,info,n=32):
    prk=hmac.new(salt,ikm,hashlib.sha256).digest(); out=b""; prev=b""; i=1
    while len(out)<n: prev=hmac.new(prk,prev+info+bytes([i]),hashlib.sha256).digest(); out+=prev; i+=1
    return out[:n]
def point(raw):
    if len(raw)!=65 or raw[0]!=4:raise ValueError("invalid uncompressed EC point")
    return ECC.EccPoint(int.from_bytes(raw[1:33],"big"),int.from_bytes(raw[33:],"big"),curve=CURVE)
def pkey(p): return int(p.x).to_bytes(32,"big")+int(p.y).to_bytes(32,"big")
def file_sha(path,offset=0):
    digest=hashlib.sha256()
    with Path(path).open("rb") as stream:
        stream.seek(offset)
        for chunk in iter(lambda:stream.read(1<<20),b""):digest.update(chunk)
    return digest.digest()

def siphash24(data,k0,k1):
    def r(x,n):return ((x<<n)|(x>>(64-n)))&MASK
    v0=0x736f6d6570736575^k0;v1=0x646f72616e646f6d^k1;v2=0x6c7967656e657261^k0;v3=0x7465646279746573^k1
    def rnd(v0,v1,v2,v3):
        v0=(v0+v1)&MASK;v1=r(v1,13)^v0;v0=r(v0,32);v2=(v2+v3)&MASK;v3=r(v3,16)^v2;v0=(v0+v3)&MASK;v3=r(v3,21)^v0;v2=(v2+v1)&MASK;v1=r(v1,17)^v2;v2=r(v2,32);return v0,v1,v2,v3
    offset=0
    while offset+8<=len(data):
        word=int.from_bytes(data[offset:offset+8],"little");offset+=8;v3^=word;v0,v1,v2,v3=rnd(v0,v1,v2,v3);v0,v1,v2,v3=rnd(v0,v1,v2,v3);v0^=word
    tail=len(data)<<56
    for i,b in enumerate(data[offset:]):tail|=b<<(8*i)
    v3^=tail;v0,v1,v2,v3=rnd(v0,v1,v2,v3);v0,v1,v2,v3=rnd(v0,v1,v2,v3);v0^=tail;v2^=0xff
    for _ in range(4):v0,v1,v2,v3=rnd(v0,v1,v2,v3)
    return v0^v1^v2^v3

def decode_payload(kind,ordinal,page_type,used,payload):
    expected=(ordinal+kind)&0xff
    raw=payload[:used]
    if page_type==0:return raw
    if page_type==1:return raw[::-1]
    even=(used+1)//2;out=bytearray(used)
    for i in range(used):out[i]=raw[i//2 if i%2==0 else even+i//2]
    return bytes(out)

def footer(blob):
    length=struct.unpack("<I",blob[-4:])[0]; start=len(blob)-4-length
    if start<0 or length>0x10000: raise ValueError("bad footer length")
    raw=blob[start:-4]; fields={}; cursor=0; checksum_at=None; digest_at=None
    while cursor<len(raw):
        at=cursor; kind,size=struct.unpack_from("<BH",raw,cursor); cursor+=3
        if cursor+size>len(raw):raise ValueError("truncated footer")
        if kind in fields:raise ValueError("duplicate footer field")
        fields[kind]=raw[cursor:cursor+size]
        if kind==T["digest"]:digest_at=at
        if kind==T["checksum"]:checksum_at=at
        cursor+=size
    if set(fields)!=set(T.values()):raise ValueError("invalid footer field set")
    sizes={T["version"]:2,T["context"]:8,T["file"]:8,T["volume"]:16,T["ephemeral"]:65,T["operator"]:65,T["wrap"]:40,T["manifest_nonce"]:12,T["manifest_tag"]:16,T["region"]:4,T["body_size"]:8,T["digest"]:32,T["checksum"]:4}
    if any(len(fields[kind])!=size for kind,size in sizes.items()) or len(fields[T["manifest"]])<16:raise ValueError("invalid footer field length")
    if struct.unpack("<H",fields[T["version"]])[0]!=3 or digest_at+35!=checksum_at or checksum_at+7!=len(raw):raise ValueError("invalid footer field order")
    if zlib.crc32(raw[:checksum_at])&0xffffffff!=struct.unpack("<I",fields[T["checksum"]])[0]:raise ValueError("footer CRC mismatch")
    if hashlib.blake2s(raw[:digest_at],person=b"KPSKv3").digest()!=fields[T["digest"]]:raise ValueError("footer digest mismatch")
    return blob[:start],fields

class Dump:
    def __init__(self,path):
        self.file=Path(path).open("rb"); self.data=mmap.mmap(self.file.fileno(),0,access=mmap.ACCESS_READ); self.ranges=[]
        if self.data[:4]!=b"MDMP":raise ValueError("not a minidump")
        streams,table=struct.unpack_from("<II",self.data,8)
        for i in range(streams):
            kind,size,rva=struct.unpack_from("<III",self.data,table+i*12)
            if kind==9:
                count,base=struct.unpack_from("<QQ",self.data,rva); offset=base
                for j in range(count):
                    va,length=struct.unpack_from("<QQ",self.data,rva+16+j*16); self.ranges.append((va,va+length,offset)); offset+=length
        if not self.ranges:raise ValueError("Memory64List stream missing")
    def read(self,va,size):
        for start,end,offset in self.ranges:
            if start<=va and va+size<=end:return self.data[offset+va-start:offset+va-start+size]
        raise ValueError(f"unmapped address 0x{va:x}")
    def va_for_offset(self,file_offset):
        for start,end,offset in self.ranges:
            if offset<=file_offset<offset+end-start:return start+file_offset-offset
        raise ValueError(f"dump offset 0x{file_offset:x} is outside memory ranges")
    def range_for(self,va):
        for start,end,_ in self.ranges:
            if start<=va<end:return start,end
        raise ValueError(f"unmapped address 0x{va:x}")
    def cstring(self,va,limit=256):
        raw=bytearray()
        for index in range(limit):
            value=self.read(va+index,1)
            if value==b"\0":return bytes(raw)
            raw+=value
        raise ValueError(f"unterminated string at 0x{va:x}")
    def close(self):self.data.close();self.file.close()

def validate_provider_fragments(dump,provider_address):
    address_mask=0xD6E8FEB86659FD93;link_mask=0x94D049BB133111EB;fragments=[];alignment=dump.ranges[0][2]&7
    for offset in range(alignment,len(dump.data)-FRAGMENT_HEADER.size-4096,8):
        encoded,nxt,size,index,total,checksum=FRAGMENT_HEADER.unpack_from(dump.data,offset)
        if not 0<size<=4096 or not 0<total<128 or index>=total:continue
        original=encoded^address_mask^rol(index+1,19)
        if original&0xfff:continue
        payload=dump.data[offset+FRAGMENT_HEADER.size:offset+FRAGMENT_HEADER.size+size]
        if (zlib.crc32(dump.data[offset:offset+24])^zlib.crc32(payload))&0xffffffff!=checksum:continue
        fragments.append({"index":index,"total":total,"offset":offset,"allocation":dump.va_for_offset(offset),"original":original,"encoded":encoded,"next":nxt,"size":size,"payload":bytes(payload)})
    if not fragments:raise ValueError("provider fragments missing")
    totals={fragment["total"] for fragment in fragments}
    if len(totals)!=1:raise ValueError("provider fragment totals disagree")
    total=totals.pop();by_index={fragment["index"]:fragment for fragment in fragments}
    if len(fragments)!=total or len(by_index)!=total or set(by_index)!=set(range(total)):raise ValueError("provider fragment sequence incomplete")
    ordered=[by_index[index] for index in range(total)]
    for index,fragment in enumerate(ordered):
        expected=0 if index+1==total else ordered[index+1]["allocation"]^fragment["encoded"]^link_mask
        if fragment["next"]!=expected:raise ValueError("provider fragment link mismatch")
    def image_read(address,size):
        output=bytearray()
        while len(output)<size:
            fragment=next((item for item in ordered if item["original"]<=address<item["original"]+item["size"]),None)
            if fragment is None:raise ValueError(f"provider image gap at 0x{address:x}")
            take=min(size-len(output),fragment["original"]+fragment["size"]-address);start=address-fragment["original"];output+=fragment["payload"][start:start+take];address+=take
        return bytes(output)
    version,width,digits,damaged,suspicious,*functions=PROVIDER_INTERFACE.unpack(image_read(provider_address,PROVIDER_INTERFACE.size))
    if (version,width,digits,damaged,suspicious)!=(4,5,257,24,32):raise ValueError("provider interface metadata mismatch")
    for function in functions:
        if not any(fragment["original"]<=function<fragment["original"]+fragment["size"] for fragment in ordered):raise ValueError("provider interface function is outside reconstructed image")
    return total

def validate_recovery_contract(dump,address,recovery_status):
    raw=dump.read(address,CONTRACT_SIZE);prefix=CONTRACT_PREFIX.unpack_from(raw);magic,version,size=prefix[:3]
    if magic!=b"RARC5\0\0\0" or version!=5 or size!=CONTRACT_SIZE or zlib.crc32(raw[:-4])&0xffffffff!=struct.unpack_from("<I",raw,CONTRACT_SIZE-4)[0]:raise ValueError("invalid recovery contract")
    if prefix[3:13]!=(1,2,3,4,4,5,1,2,3,4) or prefix[13:18]!=(MREC.size,JHEADER.size,JREC.size,JCOMMIT.size,56):raise ValueError("recovery contract format mismatch")
    expected_strings=(b"KMAP4",b"KJNL5",b"KRCPT3",b"BLAKE2S-256|CRC32|AES-KWP|AES-256-GCM|SHAKE-256|HKDF-SHA256|CONCAT",b"none|shared_x|master|volume|context|file_token|logical|generation|pdf|ephemeral_point|document_id|length|footer_body|domain",b"KPSKv3",b"envelope-v3",b"manifest-v3",b"region-v3",b"KPSKreg",b"receipt-v3")
    pointers=prefix[18:29]
    if tuple(dump.cstring(pointer) for pointer in pointers)!=expected_strings:raise ValueError("recovery contract strings mismatch")
    expected_bindings=((1,32,(12,),b"KPSKv3"),(6,32,(1,3,13,4,5),b"envelope-v3"),(6,32,(2,3,13),b"manifest-v3"),(6,32,(2,3,13,6,7),b"region-v3"),(1,12,(3,6,7),b"KPSKreg"),(5,0,(8,3,9,10,13),b"receipt-v3"),(7,0,(4,5,9),None),(7,0,(4,5,6,7,11),None));cursor=CONTRACT_PREFIX.size
    for expected in expected_bindings:
        primitive,output_size,input_count,inputs,domain=CRYPTO_BINDING.unpack_from(raw,cursor);cursor+=CRYPTO_BINDING.size;decoded=tuple(inputs[:input_count]);decoded_domain=dump.cstring(domain) if domain else None
        if (primitive,output_size,decoded,decoded_domain)!=expected:raise ValueError("recovery contract binding mismatch")
    image_start,image_end=dump.range_for(address);functions=struct.unpack_from("<4Q",raw,cursor)
    if any(not image_start<=function<image_end for function in functions):raise ValueError("recovery parser function is outside service image")
    checksum=struct.unpack_from("<I",raw,CONTRACT_SIZE-4)[0]
    if recovery_status!=(checksum^CONTRACT_SIZE^1)&0xffffffff:raise ValueError("recovery contract self-test mismatch")

def record_and_pages(dump,context,file_token,volume):
    tag=derive(context,file_token,volume,b"trace-v3")[:16]; hits=[]; cursor=0
    while True:
        hit=dump.data.find(tag,cursor)
        if hit<0:break
        cursor=hit+1; start=hit-8
        if start<0 or start+RECORD.size>len(dump.data):continue
        raw=dump.data[start:start+RECORD.size]; provider,candidate,digit_head,reliability_head,state,digit_count,reliability_count,record_tag=RECORD.unpack(raw)
        chain=int.from_bytes(derive(context,file_token,volume,b"chain-v3")[:8],"little") or 0xA0761D6478BD642F;k0=chain;k1=chain^context^file_token
        if candidate==tag and state in (2,3) and digit_count==5 and reliability_count==2 and siphash24(raw[:-8],k0,k1)==record_tag:hits.append((start,provider,digit_head,reliability_head,state,chain))
    if len(hits)!=1:raise ValueError(f"expected one context, found {len(hits)}")
    offset,provider_cookie,digit_cookie,reliability_cookie,state,chain=hits[0];k0=chain;k1=chain^context^file_token
    def read_chain(address,count,kind):
        blob=bytearray()
        for ordinal in range(count):
            raw=dump.read(address,PAGE.size);nxt,ordinal_code,type_code,used,payload,page_tag=PAGE.unpack(raw);page_type=type_code&0xf
            if ordinal_code!=(ordinal^(ordinal>>1)) or type_code>>4!=kind or page_type>2 or used>64 or siphash24(raw[:-8],k0,k1)!=page_tag:raise ValueError("broken keyed residue page")
            blob+=decode_payload(kind,ordinal,page_type,used,payload)
            if ordinal<count-1:
                if not nxt:raise ValueError("truncated residue chain")
                address=nxt^chain^rol(context,ordinal+9+kind*3)
            elif nxt:raise ValueError("residue chain has a tail")
        return bytes(blob)
    digit_address=digit_cookie^chain^rol(file_token,23);reliability_address=reliability_cookie^chain^rol(context^file_token,31);digits=read_chain(digit_address,5,0);reliability=read_chain(reliability_address,2,1)
    if len(digits)!=290 or len(reliability)!=128:raise ValueError("bad residue chain length")
    provider=provider_cookie^context^rol(file_token,17)
    return offset,provider,digits,reliability,state

def decode_digits(blob,reliability,context,file_token,volume):
    state=int.from_bytes(derive(context,file_token,volume,b"shuffle-v3")[:8],"little") or 0x8EBC6AF09C88C6E3; permutation=list(range(257))
    for i in range(256,0,-1):state,value=next64(state);j=value%(i+1);permutation[i],permutation[j]=permutation[j],permutation[i]
    observed=[None]*257; damaged=[False]*257;suspicious=[False]*257; suspicious_bitmap=blob[257:290];correction_bitmap=reliability[:33]
    for stored in range(257):
        state,value=next64(state); logical=permutation[stored]; observed[logical]=blob[stored]^(value&0xff); suspicious[logical]=bool(suspicious_bitmap[stored>>3]&(1<<(stored&7)));damaged[logical]=bool(correction_bitmap[stored>>3]&(1<<(stored&7)))
    candidates=[]
    valid=[0]+list(range(-15,16,2))
    for i,(code,bad) in enumerate(zip(observed,damaged)):
        if bad:
            choices=[d for d in valid if (((d+16)&31)&code)==code and ((((d+16)&31)^code).bit_count()==1)]
        else:choices=[d for d in valid if ((d+16)&31)==code]
        if not choices:raise ValueError(f"invalid digit residue at {i}")
        candidates.append(choices)
    return candidates,sum(suspicious)

def recovery_checkpoint(dump,context,file_token,volume):
    registrations=[];cursor=0
    while True:
        hit=dump.data.find(b"CPERF4\0",cursor)
        if hit<0:break
        cursor=hit+1
        if hit+REGISTRATION.size>len(dump.data):continue
        raw=dump.data[hit:hit+REGISTRATION.size];values=REGISTRATION.unpack(raw)
        if values[1]==REGISTRATION.size and values[2]==4 and zlib.crc32(raw[:-4])&0xffffffff==values[-1]:registrations.append(values)
    if len(registrations)!=1:raise ValueError(f"expected one provider registration, found {len(registrations)}")
    reg=registrations[0];active_session,dir_cookie,encoded_directory=reg[12],reg[13],reg[14];expected_session=context^rol(file_token,29)
    text=lambda value:value.rstrip(b"\0")
    if (text(reg[3]),text(reg[4]),text(reg[5]),text(reg[6]),reg[7],reg[8],reg[9],reg[10],reg[11])!=(b"Records Archive Crypto Telemetry",b"ECDH",b"transition samples",b"sample confidence",5,257,5,2,3):raise ValueError("provider registration metadata mismatch")
    if active_session!=expected_session:raise ValueError("registration session mismatch")
    directory_address=encoded_directory^dir_cookie^rol(active_session,11);directory_raw=dump.read(directory_address,DIRECTORY.size);directory=DIRECTORY.unpack(directory_raw)
    if directory[0]!=b"RDIR5\0\0\0" or directory[1]!=5 or directory[2]!=1 or directory[3]!=dir_cookie or zlib.crc32(directory_raw[:-4])&0xffffffff!=directory[-1]:raise ValueError("invalid recovery directory")
    session_address=directory[4]^dir_cookie^rol(active_session,17);session_raw=dump.read(session_address,SESSION.size);session=SESSION.unpack(session_raw)
    if session[0]!=b"RSES5\0\0\0" or session[1]!=active_session or session[2]!=volume or session[5]!=3 or zlib.crc32(session_raw[:-4])&0xffffffff!=session[-1]:raise ValueError("invalid recovery session")
    vtable_raw=dump.read(session[3],VTABLE.size);vtable=VTABLE.unpack(vtable_raw)
    if vtable[0]!=b"RVTB5\0\0\0" or vtable[1]!=5 or zlib.crc32(vtable_raw[:-4])&0xffffffff!=vtable[-1] or dump.read(vtable[2],8)!=b"RARC5\0\0\0":raise ValueError("invalid recovery vtable")
    validate_recovery_contract(dump,vtable[2],reg[15])
    raw=dump.read(session[4],CHECKPOINT.size);values=CHECKPOINT.unpack(raw)
    if values[0]!=b"KCHK2\0\0\0" or zlib.crc32(raw[:-4])&0xffffffff!=values[-1]:raise ValueError("invalid session checkpoint")
    _,boundary,ma,mb,mula,adda,mulb,addb,low_a,low_b,high_a,high_b,_=values
    if not 0<boundary<257 or ma<17 or mb<17:raise ValueError("invalid recovery checkpoint")
    return {"boundary":boundary,"moduli":(ma,mb),"coefficients":((mula,adda),(mulb,addb)),"targets":((low_a,low_b),(high_a,high_b))}

def candidate_stats(candidates):
    unknown=[i for i,c in enumerate(candidates) if len(c)>1];products=[1]
    for i in unknown:products.append(products[-1]*len(candidates[i]))
    split=min(range(1,len(unknown)),key=lambda cut:max(products[cut],products[-1]//products[cut]));return unknown,split,products[split],products[-1]//products[split]

def recover_scalar(candidates,Q,checkpoint,cache_path=None,artifact_identity=None):
    unknown=[i for i,c in enumerate(candidates) if len(c)>1]; known=sum(c[0]*(1<<i) for i,c in enumerate(candidates) if len(c)==1)%ORDER; G=ECC.construct(curve=CURVE,d=1).pointQ
    boundary=checkpoint["boundary"];left_i=[i for i in unknown if i<boundary];right_i=[i for i in unknown if i>=boundary];target=Q+(-(G*known));table={};artifact_identity=artifact_identity or bytes(32)
    def adjusted(group,indices):
        targets=list(checkpoint["targets"][group]);mods=checkpoint["moduli"]
        for i,c in enumerate(candidates):
            if len(c)==1 and ((i<boundary)==(group==0)):
                for k,(mul,add) in enumerate(checkpoint["coefficients"]):targets[k]=(targets[k]-c[0]*((i*mul+add)%mods[k]))%mods[k]
        return tuple(targets)
    def states(indices,group):
        if len(indices)<2:raise ValueError("checkpoint group has too few uncertain digits")
        active,pivots=indices[:-2],indices[-2:];mods=checkpoint["moduli"];targets=adjusted(group,indices);choices=[candidates[i] for i in active];weights=[1<<i for i in active];digits=[0]*len(active);scalar=sum(c[0]*w for c,w in zip(choices,weights))%ORDER;point=G*scalar;residues=[sum(c[0]*((i*checkpoint["coefficients"][k][0]+checkpoint["coefficients"][k][1])%mods[k]) for i,c in zip(active,choices))%mods[k] for k in range(2)];steps=[];residue_steps=[]
        pivot_map={}
        for a in candidates[pivots[0]]:
            for b in candidates[pivots[1]]:
                key=(a*((pivots[0]*checkpoint["coefficients"][0][0]+checkpoint["coefficients"][0][1])%mods[0])+b*((pivots[1]*checkpoint["coefficients"][0][0]+checkpoint["coefficients"][0][1])%mods[0]))%mods[0]
                pivot_scalar=(a*(1<<pivots[0])+b*(1<<pivots[1]))%ORDER;pivot_map.setdefault(key,[]).append((pivot_scalar,G*pivot_scalar))
        for index,choice,weight in zip(active,choices,weights):
            row=[]
            residue_row=[]
            for j,value in enumerate(choice):
                following=choice[j+1] if j+1<len(choice) else choice[0];delta=(following-value)*weight;row.append(G*(delta%ORDER))
                residue_row.append(tuple((following-value)*((index*checkpoint["coefficients"][k][0]+checkpoint["coefficients"][k][1])%mods[k])%mods[k] for k in range(2)))
            steps.append(row);residue_steps.append(residue_row)
        while True:
            need=(targets[0]-residues[0])%mods[0]
            for pivot_scalar,pivot_point in pivot_map.get(need,[]):yield (scalar+pivot_scalar)%ORDER,point+pivot_point
            for j in range(len(active)-1,-1,-1):
                old=digits[j];following=choices[j][old+1] if old+1<len(choices[j]) else choices[j][0];scalar=(scalar+(following-choices[j][old])*weights[j])%ORDER;point=point+steps[j][old]
                for k in range(2):residues[k]=(residues[k]+residue_steps[j][old][k])%mods[k]
                if old+1<len(choices[j]):digits[j]=old+1;break
                digits[j]=0
            else:return
    left_total=1;right_total=1
    for i in left_i[:-2]:left_total*=len(candidates[i])
    for i in right_i[:-2]:right_total*=len(candidates[i])
    fingerprint=hashlib.sha256(repr([(i,candidates[i]) for i in unknown]).encode()+repr(checkpoint).encode()+pkey(Q)).digest()
    def checkpoint_valid(scalar):
        value=scalar;digits=[]
        for _ in range(257):
            digit=0
            if value&1:
                digit=value&31
                if digit>=16:digit-=32
                value-=digit
            digits.append(digit);value>>=1
        sums=[[0,0],[0,0]]
        for i,digit in enumerate(digits):
            group=0 if i<boundary else 1
            for k,(mul,add) in enumerate(checkpoint["coefficients"]):sums[group][k]=(sums[group][k]+digit*((i*mul+add)%checkpoint["moduli"][k]))%checkpoint["moduli"][k]
        return tuple(map(tuple,sums))==tuple(map(tuple,checkpoint["targets"]))
    cache=Path(cache_path) if cache_path else None
    if cache and cache.exists():
        try:
            with cache.open("rb") as stream:
                header=stream.read(CACHE_HEADER.size)
                if len(header)!=CACHE_HEADER.size:raise ValueError("truncated cache header")
                magic,cached_fingerprint,cached_identity,count,checksum=CACHE_HEADER.unpack(header)
                if magic!=CACHE_MAGIC or cached_fingerprint!=fingerprint or cached_identity!=artifact_identity:raise ValueError("cache identity mismatch")
                if cache.stat().st_size!=CACHE_HEADER.size+count*CACHE_RECORD.size:raise ValueError("cache length mismatch")
                if file_sha(cache,CACHE_HEADER.size)!=checksum:raise ValueError("cache checksum mismatch")
                for _ in range(count):
                    key,encoded_scalar=CACHE_RECORD.unpack(stream.read(CACHE_RECORD.size))
                    scalar=int.from_bytes(encoded_scalar,"little")
                    if scalar>=ORDER or key in table:raise ValueError("invalid cache record")
                    table[key]=scalar
            if table:print(f"[mitm] loaded {len(table):,} left states from {cache}",flush=True)
        except (OSError,ValueError,struct.error):table={}
    if not table:
        started=time.monotonic()
        for count,(scalar,point) in enumerate(states(left_i,0),1):
            table.setdefault(pkey(point),scalar)
            if count%100000==0:print(f"[mitm] left {count:,}/{left_total:,} ({time.monotonic()-started:.0f}s)",flush=True)
        if cache:
            cache.parent.mkdir(parents=True,exist_ok=True);temporary=cache.with_suffix(cache.suffix+".tmp")
            with temporary.open("wb") as stream:
                stream.write(CACHE_HEADER.pack(CACHE_MAGIC,fingerprint,artifact_identity,len(table),bytes(32)))
                for key,scalar in table.items():stream.write(CACHE_RECORD.pack(key,scalar.to_bytes(32,"little")))
            checksum=file_sha(temporary,CACHE_HEADER.size)
            with temporary.open("r+b") as stream:stream.write(CACHE_HEADER.pack(CACHE_MAGIC,fingerprint,artifact_identity,len(table),checksum))
            temporary.replace(cache);print(f"[mitm] cached {len(table):,} left states at {cache}",flush=True)
    started=time.monotonic()
    for count,(right,right_point) in enumerate(states(right_i,1),1):
        if count%100000==0:print(f"[mitm] right {count:,}/{right_total:,} ({time.monotonic()-started:.0f}s)",flush=True)
        need=target+(-right_point);left=table.get(pkey(need))
        if left is not None:
            scalar=(known+left+right)%ORDER
            if pkey(G*scalar)==pkey(Q) and checkpoint_valid(scalar):return scalar,len(unknown),len(table),left_total,right_total
    raise ValueError("wNAF residue has no scalar satisfying Q=eG")

def decrypt_volume(body,fields,master,context,file_token,volume,ephemeral):
    mkey=hkdf(master,volume,b"manifest-v3"); cipher=AES.new(mkey,AES.MODE_GCM,nonce=fields[T["manifest_nonce"]]); cipher.update(struct.pack("<QQ",context,file_token)+ephemeral); manifest=cipher.decrypt_and_verify(fields[T["manifest"]],fields[T["manifest_tag"]])
    if manifest[:5]!=b"KMAP4":raise ValueError("bad manifest")
    count,total=struct.unpack_from("<II",manifest,5);transaction_id=manifest[13:29];expected_generation_sum=struct.unpack_from("<I",manifest,29)[0];region_size=struct.unpack("<I",fields[T["region"]])[0]
    if not count or not total or not region_size or len(manifest)!=33+count*MREC.size or count!=(total+region_size-1)//region_size or len(body)!=total:raise ValueError("invalid manifest geometry")
    output=bytearray(total);cursor=33;generation_sum=0;slots=set();logicals=set();physical_ranges=[]
    for _ in range(count):
        slot,logical,generation,length,physical,tag=MREC.unpack_from(manifest,cursor);cursor+=MREC.size;expected_length=min(region_size,total-logical*region_size)
        if slot>=count or logical>=count or slot in slots or logical in logicals or length!=expected_length or physical+length>len(body):raise ValueError("invalid manifest record")
        slots.add(slot);logicals.add(logical);physical_ranges.append((physical,physical+length));generation_sum=(generation_sum+generation)&0xffffffff; key=hkdf(master,volume,b"region-v3"+struct.pack("<II",logical,generation)); nonce=hashlib.blake2s(volume+struct.pack("<II",logical,generation),person=b"KPSKreg").digest()[:12]; aad=struct.pack("<QQIII",context,file_token,logical,generation,length); cipher=AES.new(key,AES.MODE_GCM,nonce=nonce); cipher.update(aad); chunk=cipher.decrypt_and_verify(body[physical:physical+length],tag); output[logical*region_size:logical*region_size+length]=chunk
    physical_cursor=0
    for start,end in sorted(physical_ranges):
        if start!=physical_cursor:raise ValueError("manifest physical coverage mismatch")
        physical_cursor=end
    if physical_cursor!=total:raise ValueError("manifest physical coverage mismatch")
    if generation_sum!=expected_generation_sum:raise ValueError("manifest generation checkpoint mismatch")
    return bytes(output),transaction_id

def validate_vhd(volume):
    if len(volume)<4096 or len(volume)%512:raise ValueError("invalid VHD length")
    disk_size=len(volume)-512;vhd=bytearray(volume[-512:])
    if vhd[:8]!=b"conectix" or struct.unpack_from(">Q",vhd,40)[0]!=disk_size or struct.unpack_from(">Q",vhd,48)[0]!=disk_size or struct.unpack_from(">I",vhd,60)[0]!=2:raise ValueError("invalid fixed VHD footer")
    expected=struct.unpack_from(">I",vhd,64)[0];vhd[64:68]=b"\0"*4
    if (~sum(vhd))&0xffffffff!=expected:raise ValueError("VHD footer checksum mismatch")
    if volume[510:512]!=b"\x55\xaa":raise ValueError("invalid MBR signature")
    part=struct.unpack_from("<I",volume,454)[0];sectors=struct.unpack_from("<I",volume,458)[0]
    if part<1 or (part+sectors)*512!=disk_size:raise ValueError("invalid partition boundary")
    boot=part*512
    if volume[boot+510:boot+512]!=b"\x55\xaa" or volume[boot+54:boot+62]!=b"FAT16   ":raise ValueError("invalid FAT16 boot sector")
    bps=struct.unpack_from("<H",volume,boot+11)[0];spc=volume[boot+13];reserved=struct.unpack_from("<H",volume,boot+14)[0];fats=volume[boot+16];spf=struct.unpack_from("<H",volume,boot+22)[0]
    if bps!=512 or not spc or spc&(spc-1) or fats!=2 or not reserved or not spf:raise ValueError("invalid FAT16 geometry")
    fat_start=boot+reserved*bps;fat_size=spf*bps
    if volume[fat_start:fat_start+fat_size]!=volume[fat_start+fat_size:fat_start+2*fat_size]:raise ValueError("FAT copies disagree")

def recover_flag(volume,volume_id,ephemeral,manifest_transaction):
    validate_vhd(volume)
    part=struct.unpack_from("<I",volume,454)[0]; boot=part*512; bps=struct.unpack_from("<H",volume,boot+11)[0];spc=volume[boot+13];reserved=struct.unpack_from("<H",volume,boot+14)[0];fats=volume[boot+16];roots=struct.unpack_from("<H",volume,boot+17)[0];spf=struct.unpack_from("<H",volume,boot+22)[0];root_secs=(roots*32+bps-1)//bps;fat_start=boot+reserved*bps;root_start=fat_start+fats*spf*bps;data_start=root_start+root_secs*bps;csize=bps*spc;fat=volume[fat_start:fat_start+spf*bps];deleted=None;journal_entry=None
    for off in range(root_start,root_start+roots*32,32):
        e=volume[off:off+32]
        if e[0]==0:break
        if e[0]==0xe5 and e[8:11]==b"PDF":deleted=e
        if e[:8]==b"SYSJRN~1" and e[8:11]==b"BIN":journal_entry=e
    if deleted is None or journal_entry is None:raise ValueError("filesystem evidence missing")
    def chain(entry):
        cluster=struct.unpack_from("<H",entry,26)[0]; size=struct.unpack_from("<I",entry,28)[0]; out=bytearray()
        while 2<=cluster<0xfff8 and len(out)<size:
            off=data_start+(cluster-2)*csize;out+=volume[off:off+csize];cluster=struct.unpack_from("<H",fat,cluster*2)[0]
        return bytes(out[:size])
    journal=chain(journal_entry)
    if len(journal)<JHEADER.size:raise ValueError("truncated journal")
    magic,record_size,commit_size,number,commit_count,transaction_id=JHEADER.unpack_from(journal)
    if magic!=b"KJNL5\0\0\0" or record_size!=JREC.size or commit_size!=JCOMMIT.size:raise ValueError("bad journal header")
    if transaction_id!=manifest_transaction:raise ValueError("manifest and journal transaction mismatch")
    if number>4096 or commit_count>256 or JHEADER.size+number*record_size+commit_count*commit_size>len(journal):raise ValueError("invalid journal bounds")
    file_id=struct.unpack_from("<Q",deleted,12)[0];size=struct.unpack_from("<I",deleted,28)[0];all_records=[];cursor=JHEADER.size
    for i in range(number):all_records.append((journal[cursor:cursor+JREC.size],JREC.unpack_from(journal,cursor)));cursor+=JREC.size
    commits=[JCOMMIT.unpack_from(journal,cursor+i*JCOMMIT.size) for i in range(commit_count)];valid=[]
    for fid,revision,digest in commits:
        if fid!=file_id:continue
        records=[(raw,rec) for raw,rec in all_records if rec[0]==file_id and rec[1]==revision];records.sort(key=lambda item:item[1][2]);previous=0;chain_ok=True
        if not records or records[0][1][3]!=len(records) or [rec[2] for _,rec in records]!=list(range(len(records))) or any(rec[3]!=len(records) for _,rec in records):continue
        for raw,rec in records:
            if rec[6]!=previous:chain_ok=False;break
            previous=int.from_bytes(hashlib.sha256(raw).digest()[:8],"little")
        if chain_ok and hashlib.sha256(b"".join(raw for raw,_ in records)).digest()==digest:valid.append((revision,[rec for _,rec in records]))
    if not valid:raise ValueError("no committed journal revision")
    revision,fragments=max(valid,key=lambda item:item[0]);document=bytearray()
    for fid,rev,seq,total,cluster,crc,previous in fragments:
        take=min(csize,size-len(document));chunk=volume[data_start+(cluster-2)*csize:data_start+(cluster-2)*csize+take]
        if zlib.crc32(chunk)&0xffffffff!=crc:raise ValueError("journal fragment CRC mismatch")
        document+=chunk
    if len(document)!=size:raise ValueError("incomplete deleted document")
    first_eof=document.find(b"%%EOF\n")
    if first_eof<0:raise ValueError("base PDF revision missing")
    base=bytes(document[:first_eof+6]);recovery_object=document.find(b"/Type /RecordsRecovery",first_eof)
    if recovery_object<0:raise ValueError("incremental recovery object missing")
    stream_at=document.find(b"stream\n",recovery_object);stream_end=document.find(b"\nendstream",stream_at)
    if stream_at<0 or stream_end<0:raise ValueError("recovery object stream missing")
    encoded=bytes(document[stream_at+7:stream_end]).strip().rstrip(b">")
    try:receipt=bytes.fromhex(encoded.decode())
    except (ValueError,UnicodeDecodeError):raise ValueError("invalid recovery object encoding")
    if len(receipt)<56 or receipt[:6]!=b"KRCPT3":raise ValueError("bad recovery receipt")
    doc_id=receipt[6:22];expected=receipt[22:54];length=struct.unpack_from("<H",receipt,54)[0];sealed=receipt[56:56+length]
    if len(receipt)!=56+length:raise ValueError("invalid recovery receipt length")
    if int.from_bytes(doc_id[:8],"little")!=file_id:raise ValueError("FAT and receipt document id mismatch")
    if hashlib.sha256(base).digest()!=expected:raise ValueError("document receipt mismatch")
    mask=hashlib.shake_256(base+volume_id+ephemeral+doc_id+b"receipt-v3").digest(length);flag=bytes(a^b for a,b in zip(sealed,mask)).decode()
    if not flag.startswith("SHA{") or not flag.endswith("}"):raise ValueError("invalid flag receipt")
    return flag,len(fragments),bytes(document)

def solve(a):
    locked=Path(a.locked).read_bytes();body,fields=footer(locked)
    if len(fields[T["body_size"]])!=8 or struct.unpack("<Q",fields[T["body_size"]])[0]!=len(body):raise ValueError("footer body size mismatch")
    context=struct.unpack("<Q",fields[T["context"]])[0];file_token=struct.unpack("<Q",fields[T["file"]])[0];volume_id=fields[T["volume"]];ephemeral=fields[T["ephemeral"]];Q=point(ephemeral);dump=Dump(a.memory)
    try:record_offset,provider,residue,reliability,state=record_and_pages(dump,context,file_token,volume_id);provider_fragments=validate_provider_fragments(dump,provider);checkpoint=recovery_checkpoint(dump,context,file_token,volume_id)
    finally:dump.close()
    candidates,suspicious=decode_digits(residue,reliability,context,file_token,volume_id);artifact_identity=hashlib.sha256(residue+reliability+pkey(Q)).digest();scalar,uncertain,left_states,left_total,right_total=recover_scalar(candidates,Q,checkpoint,a.mitm_cache,artifact_identity);A=point(fields[T["operator"]]);shared=A*scalar;kek=hkdf(int(shared.x).to_bytes(32,"big"),volume_id,b"envelope-v3"+struct.pack("<QQ",context,file_token));master=AES.new(kek,AES.MODE_KWP).unseal(fields[T["wrap"]]);plain,manifest_transaction=decrypt_volume(body,fields,master,context,file_token,volume_id,ephemeral);flag,fragments,document=recover_flag(plain,volume_id,ephemeral,manifest_transaction);doc_size=len(document);out=Path(a.output);out.parent.mkdir(parents=True,exist_ok=True);out.write_bytes(plain)
    if a.pdf_output:
        pdf=Path(a.pdf_output);pdf.parent.mkdir(parents=True,exist_ok=True);pdf.write_bytes(document)
    regions=(len(plain)+0xfffff)//0x100000
    print(f"[1] context record   : 0x{record_offset:x}\n[2] provider address : 0x{provider:016x}\n[3] provider fragments: {provider_fragments}\n[4] suspicious digits: {suspicious}\n[5] corrected digits : {uncertain}\n[6] checkpoint search: {left_total:,} / {right_total:,}\n[7] MITM left states : {left_states}\n[8] scalar verified  : Q = eG\n[9] envelope unwrap  : valid\n[10] regions verified: {regions}\n[11] file fragments  : {fragments} ({doc_size} bytes)\n[12] output SHA-256  : {hashlib.sha256(plain).hexdigest()}\n[13] flag            : {flag}\n[+] wrote {out}")
    if a.pdf_output:print(f"[+] wrote {pdf}")

def main():
    p=argparse.ArgumentParser();p.add_argument("--memory",required=True);p.add_argument("--locked",required=True);p.add_argument("--output");p.add_argument("--pdf-output");p.add_argument("--mitm-cache");p.add_argument("--inspect",action="store_true");a=p.parse_args()
    if a.inspect:
        locked=Path(a.locked).read_bytes();_,fields=footer(locked);context=struct.unpack("<Q",fields[T["context"]])[0];file_token=struct.unpack("<Q",fields[T["file"]])[0];volume=fields[T["volume"]];dump=Dump(a.memory)
        try:_,provider,digits,reliability,_=record_and_pages(dump,context,file_token,volume);provider_fragments=validate_provider_fragments(dump,provider);checkpoint=recovery_checkpoint(dump,context,file_token,volume)
        finally:dump.close()
        candidates,suspicious=decode_digits(digits,reliability,context,file_token,volume);unknown=[i for i,c in enumerate(candidates) if len(c)>1];left=[i for i in unknown if i<checkpoint["boundary"]];right=[i for i in unknown if i>=checkpoint["boundary"]];ls=1;rs=1
        for i in left[:-2]:ls*=len(candidates[i])
        for i in right[:-2]:rs*=len(candidates[i])
        print(json.dumps({"suspicious":suspicious,"damaged":len(unknown),"left_states":ls,"right_states":rs,"boundary":checkpoint["boundary"],"provider_fragments":provider_fragments},sort_keys=True));return
    if not a.output:p.error("--output is required unless --inspect is used")
    solve(a)
if __name__=="__main__":main()
