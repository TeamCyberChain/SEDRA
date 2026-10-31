"""V2 feature and exact-observable contract tests with invented source rows."""
import copy
from datetime import date, timedelta
import io
import csv
import hashlib
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from cert_multichannel import features, load_labels, aggregate, CHANNELS

def source_fixture(root, mismatch=False):
    source=root/'sources';source.mkdir();(source/'LDAP').mkdir()
    (source/'LDAP/2010-01.csv').write_text('user_id,role\nACTOR,Engineering\nOTHER,Engineering\n')
    members=[]
    for channel in CHANNELS:
        headers=['id','date','user','pc']+(['activity'] if channel in ('device','logon') else ['url' if channel=='http' else 'filename','content'])
        path=source/f'{channel}.csv'
        with path.open('w',newline='') as stream:
            writer=csv.writer(stream);writer.writerow(headers)
            for i,day in enumerate((1,31)):
                extra=['Connect' if channel=='device' else 'Logon'] if channel in ('device','logon') else ['http://never-request.invalid/' if channel=='http' else 'file.txt','discard content']
                writer.writerow([f'{channel}-{i}',f'01/{day:02d}/2010 09:00:00','ACTOR','PC',*extra])
            if channel=='device':
                writer.writerow(['device-positive','01/15/2010 10:00:00','OTHER' if mismatch else 'ACTOR','PC','Connect'])
        members.append({'path':path.name,'bytes':path.stat().st_size,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
    # An intentionally invented, isolated extractor fixture. It never becomes a
    # published benchmark: run_benchmark separately enforces official answers.
    (source/'extraction_manifest.json').write_text(json.dumps({'status':'verified_complete',
        'archive_sha256':'586446b00e83ce5cdabf9dc889b0b6e7a9f44556cee3c03d39445d790122556c','members':members}))
    answers=root/'answers.tar.bz2'
    contents={'insiders.csv':'dataset,details,user,scenario,start,end\n4.2,episode.csv,ACTOR,1,01/15/2010 10:00:00,01/15/2010 10:00:00\n',
              'episode.csv':'device,device-positive,01/15/2010 10:00:00,ACTOR,PC,Connect\n'}
    with tarfile.open(answers,'w:bz2') as bundle:
        for name,text in contents.items():
            raw=text.encode();member=tarfile.TarInfo(name);member.size=len(raw);bundle.addfile(member,io.BytesIO(raw))
    return source,answers

def rows():
    output=[]
    for i in range(40):
        for user in range(8):
            output.append({'subject_id':f'user{user}','date':(date(2010,1,1)+timedelta(days=i)).isoformat(),
                'role':'Engineering','counts':[0,0,2,0,20,1,0,0],
                'workstations':[f'pc{user}'],'label':0,'episode_ids':[]})
    return output

class MultichannelContractTests(unittest.TestCase):
    def test_calendar_ingest_retains_zero_days_and_exact_source_evidence(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);source,answers=source_fixture(root)
            output=root/'days.jsonl'
            with patch('urllib.request.urlopen',side_effect=AssertionError('No network allowed')):
                metadata=aggregate(source,answers,output)
            records=[json.loads(line) for line in output.read_text().splitlines()]
            self.assertEqual(len(records),58)
            self.assertEqual(sum(r['label'] for r in records),1)
            self.assertEqual(metadata['matched_official_observables'],1)
            positive=next(r for r in records if r['label'])
            self.assertEqual(positive['evidence'][0]['channel'],'device')
            self.assertTrue(any(sum(r['counts'])==0 for r in records))
            self.assertNotIn('never-request.invalid',output.read_text())

    def test_official_id_actor_mismatch_is_rejected_before_publication(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);source,answers=source_fixture(root,mismatch=True)
            output=root/'days.jsonl'
            with self.assertRaisesRegex(ValueError,'join mismatch'):
                aggregate(source,answers,output)
            self.assertFalse(output.exists())

    def test_labels_and_future_do_not_enter_features(self):
        original=rows()
        a=features(original)
        changed=copy.deepcopy(original)
        for row in changed:
            row['label']=1
            row['episode_ids']=['must-not-be-feature']
            if row['date']>'2010-01-25':
                row['counts']=[10000]*8
                row['workstations']=['future-host']
        b=features(changed)
        self.assertEqual([r['vector'] for r in a if r['date']<='2010-01-25'],
                         [r['vector'] for r in b if r['date']<='2010-01-25'])

    def test_first_device_use_after_zero_calendar_days_is_scoreable(self):
        fixture=rows()
        target=next(r for r in fixture if r['subject_id']=='user0' and r['date']=='2010-01-25')
        target['counts'][0]=5
        result=next(r for r in features(fixture) if r['subject_id']=='user0' and r['date']=='2010-01-25')
        self.assertEqual(result['baseline']['sufficiency'],'personal_14d')
        self.assertGreater(result['rules_peer'],0)
        early=features(fixture)[0]
        self.assertEqual(early['baseline']['sufficiency'],'limited_population_fallback')

    def test_same_day_peer_changes_do_not_change_other_users_reference(self):
        fixture=rows()
        a=features(fixture)
        changed=copy.deepcopy(fixture)
        for row in changed:
            if row['date']=='2010-01-25' and row['subject_id']!='user0':
                row['counts']=[200]*8
        b=features(changed)
        selector=lambda rs:next(r['vector'] for r in rs if r['subject_id']=='user0' and r['date']=='2010-01-25')
        self.assertEqual(selector(a),selector(b))

    def test_channel_qualified_labels_exclude_other_actor_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive=Path(tmp)/'answers.tar.bz2'
            content={
                'insiders.csv':'dataset,details,user,scenario,start,end\n4.2,episode.csv,ACTOR,1,01/01/2010 09:00:00,01/02/2010 12:00:00\n',
                'episode.csv':'device,same-id,01/01/2010 10:00:00,ACTOR,PC,Connect\nlogon,same-id,01/01/2010 11:00:00,ACTOR,PC,Logon\nhttp,context-id,01/01/2010 11:00:00,OTHER,PC,http://never-visit.invalid\n'
            }
            with tarfile.open(archive,'w:bz2') as bundle:
                for name,text in content.items():
                    raw=text.encode(); info=tarfile.TarInfo(name);info.size=len(raw);bundle.addfile(info,io.BytesIO(raw))
            labels,incidents,skipped=load_labels(archive)
            self.assertEqual(len(labels),2)
            self.assertIn(('device','same-id'),labels)
            self.assertIn(('logon','same-id'),labels)
            self.assertEqual(skipped,1)

if __name__=='__main__':
    unittest.main()
