"""Verified, atomic selective extraction; never visit URLs from dataset content."""
import bz2
import json
from pathlib import Path, PurePosixPath
import sys
import tarfile
from download_cert import checksum, FILES

def extract(root):
    archive = root/'r4.2.tar.bz2'
    if checksum(archive) != FILES[archive.name][2]:
        raise ValueError('Archive SHA256 mismatch')
    destination = root/'multichannel'
    destination.mkdir(parents=True, exist_ok=True)
    members = []
    with bz2.open(archive,'rb') as compressed, tarfile.open(fileobj=compressed,mode='r|') as bundle:
        for member in bundle:
            name = PurePosixPath(member.name)
            if not member.isfile():
                continue
            if name.name in ('device.csv','logon.csv','http.csv','file.csv'):
                relative = Path(name.name)
            elif 'ldap' in [p.lower() for p in name.parts] and name.suffix.lower()=='.csv':
                relative = Path('LDAP')/name.name
            elif name.name.lower().startswith(('readme','license')):
                relative = Path(name.name)
            else:
                continue
            target = destination/relative
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists():
                raise ValueError(f'Refusing to replace existing source: {target}')
            partial = target.with_suffix(target.suffix+'.part')
            source = bundle.extractfile(member)
            import hashlib
            digest = hashlib.sha256()
            size = 0
            with source, partial.open('wb') as out:
                for block in iter(lambda: source.read(4*1024*1024),b''):
                    out.write(block)
                    digest.update(block)
                    size += len(block)
            if size != member.size:
                raise ValueError('Extracted length mismatch')
            partial.replace(target)
            members.append({'archive_member':member.name,'path':str(relative),'bytes':size,'sha256':digest.hexdigest()})
            print(f'Extracted {relative}: {size:,} bytes',flush=True)
    required = {'device.csv','logon.csv','http.csv','file.csv'}
    if not required <= {Path(m['path']).name for m in members}:
        raise ValueError('Missing required channels')
    result = {'archive_sha256':FILES[archive.name][2], 'members':members, 'status':'verified_complete'}
    (destination/'extraction_manifest.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print('All selected channels extracted and verified.',flush=True)

if __name__=='__main__':
    extract(Path(sys.argv[1] if len(sys.argv)>1 else 'data/cert'))
