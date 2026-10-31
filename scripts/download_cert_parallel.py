"""Resume the official archive using validated HTTP ranges and final SHA-256.

Range chunks are private intake scratch files. No dataset content is uploaded.
Run after stopping any other writer to the same .part file.
"""
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import argparse
import os
import shutil
import time
import urllib.request
from download_cert import FILES, checksum

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workers',type=int,default=8)
    parser.add_argument('--chunk-mib',type=int,default=8)
    args=parser.parse_args()
    if not 1<=args.workers<=16 or not 1<=args.chunk_mib<=64:
        parser.error('Use 1–16 workers and 1–64 MiB chunks')
    root = Path('data/cert'); root.mkdir(parents=True,exist_ok=True)
    name='r4.2.tar.bz2'; url,size,expected=FILES[name]
    archive=root/name
    if archive.exists():
        if archive.stat().st_size==size and checksum(archive)==expected:
            print('Existing official archive verified.',flush=True); return
        raise ValueError('Existing archive invalid; preserve and inspect')
    prefix=root/(name+'.part')
    offset=prefix.stat().st_size if prefix.exists() else 0
    chunk_size=args.chunk_mib*1024*1024
    scratch=root/'range_chunks'; scratch.mkdir(exist_ok=True)
    def fetch(start):
        end=min(size-1,start+chunk_size-1)
        target=scratch/f'{start:012d}-{end:012d}.chunk'
        if target.exists() and target.stat().st_size==end-start+1:
            return target
        for attempt in range(4):
            partial=target.with_suffix('.partial')
            try:
                req=urllib.request.Request(url,headers={'Range':f'bytes={start}-{end}',
                    'User-Agent':'SEDRA-hackathon-verified-intake/2'})
                with urllib.request.urlopen(req,timeout=40) as response, partial.open('wb') as out:
                    if response.status!=206 or response.headers.get('Content-Range')!=f'bytes {start}-{end}/{size}':
                        raise ValueError('Range response does not match requested bounds')
                    shutil.copyfileobj(response,out,128*1024)
                if partial.stat().st_size!=end-start+1:
                    raise ValueError('Incomplete range response')
                partial.replace(target)
                return target
            except Exception:
                if attempt==3:
                    raise
                time.sleep(1+attempt)
    ranges=list(range(offset,size,chunk_size))
    print(f'Resuming verified ranges after {offset:,} bytes, {len(ranges)} chunks, {args.workers} workers.',flush=True)
    began=time.monotonic();done=0
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures=[pool.submit(fetch,start) for start in ranges]
        try:
            for future in as_completed(futures):
                target=future.result();done+=target.stat().st_size
                print(f'Intake {offset+done:,}/{size:,} bytes; {done/max(1,time.monotonic()-began)/1024**2:.2f} MiB/s',flush=True)
        except BaseException:
            for future in futures:
                future.cancel()
            print('Intake interrupted; verified completed ranges preserved for resume.',flush=True)
            raise
    assembly=root/(name+'.assembling')
    with assembly.open('wb') as out:
        if offset:
            with prefix.open('rb') as src:
                shutil.copyfileobj(src,out,4*1024*1024)
        for start in ranges:
            end=min(size-1,start+chunk_size-1)
            with (scratch/f'{start:012d}-{end:012d}.chunk').open('rb') as src:
                shutil.copyfileobj(src,out,4*1024*1024)
    observed=checksum(assembly)
    if assembly.stat().st_size!=size or observed!=expected:
        raise ValueError('Final official SHA256/length mismatch; all parts preserved')
    assembly.replace(archive)
    print(f'Official archive verified: {observed}',flush=True)

if __name__=='__main__':
    main()

