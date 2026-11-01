#!/usr/bin/env python3
"""Assemble full OpenWrt userspace + separate initrd for the proven LK2ND.

The complete runtime trial never installs the unconfigured system.img.
Input producer bytes and hashes remain in the output as provenance.
"""
import argparse,gzip,hashlib,json,struct,sys,zipfile,zlib,subprocess
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools/termux'))
sys.path.insert(0,str(ROOT/'ci'))
from bootlib import FDT,boot_image
from cpio import entries,rewrite
from audit_initramfs_cpio import audit
from verify_jz08_bundle import REQUIRED

def sha(b):return hashlib.sha256(b).hexdigest()
def require(ok,text):
    if not ok:raise ValueError(text)

def assemble(archive,init,output):
    with zipfile.ZipFile(archive) as z:
        require(len(z.namelist())==len(set(z.namelist())),'duplicate input ZIP members')
        require(set(z.namelist())==REQUIRED,'unexpected input bundle members')
        require(sum(i.file_size for i in z.infolist())<512*1024**2,'oversized input bundle')
        source={n:z.read(n) for n in z.namelist()}
    meta=json.loads(source['MANIFEST.json'])
    require(meta['flash_allowed'] is False and meta['hardware_tested'] is False,'untrusted producer status')
    for name,record in meta['files'].items():
        require(len(source[name])==record['bytes'] and sha(source[name])==record['sha256'],'producer member changed: '+name)
    for row in source['SHA256SUMS'].decode().splitlines():
        digest,name=row.split('  ',1);require(sha(source[name])==digest,'producer SHA256SUMS mismatch')
    decompressor=zlib.decompressobj(31)
    kernel=decompressor.decompress(source['images/kernel-from-boot.bin'])
    require(decompressor.eof,'truncated producer kernel gzip')
    require(decompressor.unused_data==source['images/msm8916-generic-jz08-3000-nkv.dtb'],
            'producer kernel has a different appended DTB')
    require(kernel[56:60]==b'ARMd','not ARM64 Linux Image')
    offset,size=struct.unpack_from('<QQ',kernel,8)
    require(len(kernel)<=size and offset+size<30*1024**2,'kernel overlaps actual LK2ND tags address')
    original_dtb=source['images/msm8916-generic-jz08-3000-nkv.dtb']
    dt=FDT(original_dtb)
    # Only USB and eMMC are exercised first. The full matched driver/module
    # set remains present, with radio and guessed external GPIO consumers off.
    disabled=[]
    for path,props in dt.nodes.items():
        compatible=props.get('compatible',b'')
        if (path in ('/leds','/gpio-keys') or 'remoteproc@' in path or
                b'wcnss' in compatible or b'gpio-keys' in compatible or b'gpio-leds' in compatible):
            props['status']=b'disabled\0';disabled.append(path)
    for path,props in dt.nodes.items():
        if '/usb@78d9000' in path and path.count('/')==2:
            props['status']=b'okay\0';props['dr_mode']=b'peripheral\0'
    original=source['images/initrd.cpio'];members={n:(f,b) for n,f,b in entries(original)}
    require(members['init'][1].startswith(b'#!/bin/sh'),'unexpected upstream init')
    init_bytes=init.read_bytes()
    require(init_bytes[:4]==b'\x7fELF' and struct.unpack_from('<H',init_bytes,18)[0]==183,'init is not AArch64 ELF')
    changes={
        'init.openwrt':(0o100755,members['init'][1]),
        'init':(0o100755,init_bytes),
        'etc/uci-defaults/99-default-config':None,
        'etc/uci-defaults/10-fstab':None,
        'etc/uci-defaults/99-jz08':(0o100755,(ROOT/'runtime/99-jz08-defaults').read_bytes()),
        'etc/init.d/jz08-usb':(0o100755,(ROOT/'runtime/jz08-usb.init').read_bytes()),
        'etc/rc.d/S98jz08-usb':(0o100755,b'#!/bin/sh\nexec /etc/init.d/jz08-usb boot\n'),
    }
    cpio=rewrite(original,changes)
    output.mkdir(parents=True,exist_ok=True)
    tmp=output/'full-initrd.cpio';tmp.write_bytes(cpio)
    report=audit(tmp);tmp.unlink()
    require(report['known_dangerous_startup_paths_absent'],'RAM rootfs failed startup audit')
    # Legacy gadget modules match the exact producer kernel (no ABI mixing).
    for module in ('libcomposite','u_ether','usb_f_ecm','usb_f_ecm_subset','usb_f_rndis','g_ether'):
        require(any(n.endswith('/'+module+'.ko') for n in members),'missing USB module: '+module)
    ram=gzip.compress(cpio,9,mtime=0)
    banks=[(0x80000000,256*1024**2)]
    probe=FDT(dt.encode());probe.set_memory(banks)
    boot_image(kernel,ram,probe.encode(),'a'*32,banks) # size/overlap gate only; OEM RAM is runtime data
    assets={n.relative_to(ROOT/'tools/termux').as_posix():n.read_bytes()
            for n in (ROOT/'tools/termux').glob('*.py')}
    assets['factory_layout.json']=(ROOT/'tools/termux/factory_layout.json').read_bytes()
    assets.update({'bin/linux_Image':kernel,'bin/initramfs.cpio.gz':ram,'bin/jz08.dtb':dt.encode(),
                   'images/system-UNCONFIGURED-NOT-FLASHABLE.img':source['images/system.img'],
                   'audit/PRODUCER_MANIFEST.json':source['MANIFEST.json'],
                   'audit/PACKAGES.manifest':source['audit/JZ08_PACKAGES.manifest'],
                   'audit/FULL_INITRD_AUDIT.json':json.dumps(report,indent=2).encode(),
                   'README_RU.md':(ROOT/'docs/FULL_TRIAL_RU.md').read_bytes(),
                   'LICENSE.GPL-2.0':(ROOT/'LICENSE.GPL-2.0').read_bytes()})
    from io import BytesIO
    rec=BytesIO()
    with zipfile.ZipFile(rec,'w',zipfile.ZIP_DEFLATED) as z:
        for p in sorted((ROOT/'tools/recovery').rglob('*')):
            if p.is_file() and '__pycache__' not in p.parts:z.writestr(p.relative_to(ROOT/'tools/recovery').as_posix(),p.read_bytes())
    assets['legacy/v32-guarded.zip']=rec.getvalue()
    record={'status':'FULL_OPENWRT_RAM_TRIAL_BUILT','producer_archive_sha256':sha(archive.read_bytes()),
            'hardware_tested':False,'persistent_install_allowed':False,
            'kernel_bytes':len(kernel),'kernel_image_size':size,'initrd_gzip_bytes':len(ram),
            'kernel_address':'0x80000000','dtb_address':'0x81e00000','initrd_address':'0x82000000',
            'memory_size_source':'live OEM DTB, never guessed','disabled_nodes':disabled,
            'driver_abi':'same producer kernel and module files','runtime_proof':'fresh nonce + USB + HTTP',
            'system_image':'unconfigured source artifact; never installed by this tool'}
    record['bundle_version']=2
    record['packager_source_commit']=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
    record['packager_tracked_source_dirty']=bool(subprocess.check_output(['git','status','--porcelain','--untracked-files=no'],cwd=ROOT,text=True).strip())
    record['memory_fixup_contract']='live verified SMEM version; 32-bit root/reserved-memory/ranges for version 0'
    record['init_heartbeat']='legacy USB gadget loaded by PID 1 before rcS'
    # Keep build metadata and the manifest in sync with the final record.
    assets['audit/FULL_BUILD.json']=json.dumps(record,indent=2).encode()
    assets['MANIFEST_SHA256.json']=json.dumps({'version':2,'files':{n:sha(b) for n,b in sorted(assets.items()) if n!='MANIFEST_SHA256.json'}},indent=2).encode()
    dest=output/'INFEND_JZ08_OPENWRT_FULL_TRIAL_V2.zip'
    with zipfile.ZipFile(dest,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as z:
        for n,b in sorted(assets.items()):
            info=zipfile.ZipInfo(n,(2026,11,1,0,0,0));info.compress_type=zipfile.ZIP_DEFLATED;info.external_attr=0o100644<<16
            z.writestr(info,b)
    (output/(dest.name+'.sha256')).write_text(sha(dest.read_bytes())+'  '+dest.name+'\n')
    (output/'FULL_BUILD.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(record,indent=2));print(dest)

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--archive',type=Path,required=True);p.add_argument('--init',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();assemble(a.archive,a.init,a.output)
