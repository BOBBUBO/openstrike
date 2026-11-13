#!/usr/bin/env python3
"""Bit-masked salt solver: allows the 6 UUID version/variant bits to be forced."""
import hashlib, json, re
from collections import Counter

PATCHLIST='stock-files/com.netease.newspike/files/LocalData/Patch/spike_patchlist_android_astc_512_py3.txt'
pl=json.load(open(PATCHLIST))
pairs=[]
for k,v in pl.items():
    if not isinstance(v,list): continue
    for item in v:
        if isinstance(item,str) and re.fullmatch(r'[0-9a-f]{2}/[0-9a-fA-F-]{36}(\.\d+)?',item):
            guid=item.split('/')[1].split('.')[0]
            pairs.append((k,guid.replace('-','').lower()))
# dedupe
seen=set(); P=[]
for k,g in pairs:
    if (k,g) in seen: continue
    seen.add((k,g)); P.append((k,g))
pairs=P
print('unique pairs',len(pairs))

def dash(h): return '%s-%s-%s-%s-%s'%(h[0:8],h[8:12],h[12:16],h[16:20],h[20:32])

NAMEFNS={
 'dlcid':        lambda k,g:k,
 'dlcid.lower':  lambda k,g:k.lower(),
 'guid_nodash':  lambda k,g:g,
 'guid_dash':    lambda k,g:dash(g),
 'dir_dash':     lambda k,g:g[:2]+'/'+dash(g),
 'dir_nodash':   lambda k,g:g[:2]+'/'+g,
 'dir_dash_nodir':lambda k,g:dash(g),
}
def dvals(dg):
    b=dg.digest()
    return {'d0_8_le':int.from_bytes(b[0:8],'little'),'d0_8_be':int.from_bytes(b[0:8],'big'),
            'd8_16_le':int.from_bytes(b[8:16],'little'),'d8_16_be':int.from_bytes(b[8:16],'big')}
def gvals(g):
    bb=bytes.fromhex(g)
    return {'g_all_be':int(g,16),'g_all_le':int.from_bytes(bb,'little'),
            'g_first16_be':int(g[:16],16),'g_first16_le':int.from_bytes(bb[:8],'little'),
            'g_last16_be':int(g[16:],16),'g_last16_le':int.from_bytes(bb[8:],'little')}

N=4000
sub=pairs[:N]
best=[]
for nname,nfn in NAMEFNS.items():
    names=[nfn(k,g) for k,g in sub]
    dcache={n:dvals(hashlib.md5(n.encode())) for n in set(names)}
    for dk in dcache[list(dcache)[0]]:
        for gk in ('g_all_be','g_all_le','g_first16_be','g_first16_le','g_last16_be','g_last16_le'):
            cands=[dcache[n][dk]^gvals(g)[gk] for n,g in zip(names,(x[1] for x in sub))]
            # bits that vary across all candidates
            allv=cands[0]
            anyv=cands[0]
            for c in cands:
                allv&=c; anyv|=c
            varying=allv^anyv
            fixedmask=(1<<64)-1 ^ varying
            # pick reference = mode on fixed bits
            key=lambda c:c&fixedmask
            mode,cnt=Counter(key(c) for c in cands).most_common(1)[0]
            best.append((cnt,len(cands),nname,dk,gk,varying,mode,fixedmask))
best.sort(key=lambda r:-r[0])
for r in best[:10]:
    cnt,tot,nn,dk,gk,varying,mode,fm=r
    print('agree=%5d/%d  name=%-13s dig=%-8s guid=%-13s varying_bits=0x%016x'%(cnt,tot,nn,dk,gk,varying))
    if cnt>tot*0.9:
        print('    FIXED MASK salt = 0x%016x  (variable bits must be the uuid version/variant nibbles)'%mode)
