"""Adversarial representations, parser boundaries and checksum counterexamples."""
import base64
from hashlib import sha256
import json
from pathlib import Path
import sys
import time
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from structured_cases import FIN,AZ_IBAN,positive_cases,negative_cases,make_iban
from sedra.content_security import structured_findings,iban_registry,iban_valid,STRUCTURED_PROFILE
from sedra.data_types import detector_catalog
from sedra.gateway import Gateway
from sedra.unicode_profile import IGNORABLES


class StructuredDataTypeTests(unittest.TestCase):
    def test_all_expanded_positive_cases_detect_the_expected_type(self):
        for name,(kind,text) in positive_cases().items():
            with self.subTest(name=name):
                self.assertIn(kind,[f['type'] for f in structured_findings(text)])

    def test_all_negative_controls_have_no_structured_block(self):
        for name,text in negative_cases().items():
            with self.subTest(name=name):
                self.assertEqual(structured_findings(text),[])

    def test_all_89_pinned_registry_examples_pass_structure_length_and_mod97(self):
        registry=iban_registry()
        self.assertEqual(registry['source_release'],'103')
        self.assertEqual(len(registry['countries']),89)
        for country,entry in registry['countries'].items():
            with self.subTest(country=country):
                self.assertTrue(iban_valid(entry['public_registry_example']))
                types=[f['type'] for f in structured_findings(entry['public_registry_example'])]
                self.assertIn('AZ_IBAN_MOD97' if country=='AZ' else 'IBAN_MOD97',types)

    def test_corrupted_check_digits_do_not_become_iban_findings(self):
        for country,entry in iban_registry()['countries'].items():
            text=entry['public_registry_example']
            corrupted=text[:3]+str((int(text[3])+1)%10)+text[4:]
            with self.subTest(country=country):
                self.assertFalse(iban_valid(corrupted))
                self.assertFalse(any('IBAN' in f['type'] for f in structured_findings(corrupted)))

    def test_checksum_cannot_override_wrong_country_structure_or_length(self):
        for text in [make_iban('ZZ','A'*20),make_iban('GB','0'*18),make_iban('DE','1'*17),make_iban('AZ','1234'+'1'*20)]:
            self.assertFalse(iban_valid(text))
            self.assertEqual(structured_findings(text),[])

    def test_canonical_hash_is_stable_across_supported_fin_representations(self):
        expected=sha256(FIN.encode()).hexdigest()
        for name,(kind,text) in positive_cases().items():
            if kind=='AZ_FIN_CONTEXTUAL' and name!='fin_numeric_json':
                with self.subTest(name=name):
                    self.assertTrue(any(f['value_sha256']==expected for f in structured_findings(text)))

    def test_evidence_retains_checks_and_normalization_without_raw_values(self):
        evidence=structured_findings('FİN: А1В2С3D')
        serialized=json.dumps(evidence)
        self.assertNotIn('А1В2С3D',serialized)
        self.assertNotIn(FIN,serialized)
        self.assertIn('TR39_script_lookalike',evidence[0]['normalization_steps'])
        self.assertIn('7_character_format',evidence[0]['validation_checks'])
        self.assertEqual(evidence[0]['detector_profile'],STRUCTURED_PROFILE)

    def test_base64_json_composition_is_supported_but_double_base64_is_not_claimed(self):
        value=json.dumps({'fin':FIN}).encode()
        once=base64.b64encode(value).decode()
        twice=base64.b64encode(once.encode()).decode()
        self.assertTrue(any(f['type']=='AZ_FIN_CONTEXTUAL' for f in structured_findings(once)))
        self.assertEqual(structured_findings(twice),[])

    def test_csv_fields_are_not_joined_and_context_does_not_cross_columns(self):
        controls=['fin_code,extra\nA1B,2C3D','order_id,card\n4111111111111111,public training',
                  'fin_code,order_id\n,A1B2C3D']
        for text in controls:self.assertEqual(structured_findings(text),[])
        # Explicit sensitive text in another column is still inspected on its own.
        self.assertTrue(structured_findings('fin_code,notes\n,"Card number: 4111 1111 1111 1111"'))

    def test_csv_rows_beyond_1024_are_not_silently_skipped(self):
        text='name,fin_code\n'+('Synthetic,\n'*1100)+'Synthetic,'+FIN
        self.assertTrue(any(f['type']=='AZ_FIN_CONTEXTUAL' for f in structured_findings(text)))

    def test_json_depth_overflow_fails_closed(self):
        text='['*1200+'0'+']'*1200
        self.assertIn('STRUCTURED_INSPECTION_LIMIT',[f['type'] for f in structured_findings(text)])
        self.assertEqual(structured_findings(json.dumps({'description':'['*1200})),[])

    def test_finding_cap_preserves_block_and_marks_omitted_evidence(self):
        text='\n'.join(f'password: SyntheticPass{i:04d}!' for i in range(80))
        findings=structured_findings(text)
        self.assertEqual(len(findings),64)
        self.assertTrue(findings[-1]['additional_findings_omitted'])
        self.assertTrue(all(f['action']=='BLOCK' for f in findings))

    def test_maximum_input_and_pinned_ignorables_are_enforced(self):
        self.assertEqual(len(IGNORABLES),4174)
        with self.assertRaises(ValueError):structured_findings('x'*65537)
        # Coarse stall guard, not a claimed throughput benchmark.
        started=time.monotonic()
        self.assertEqual(structured_findings('x'*65536),[])
        self.assertLess(time.monotonic()-started,5)

    def test_gateway_enforces_every_positive_and_preserves_original_digest(self):
        g=Gateway(':memory:',[])
        for i,(name,(kind,text)) in enumerate(positive_cases().items()):
            with self.subTest(name=name):
                result=g.evaluate('synthetic-actor',f'structured-{i}',text,0)
                self.assertEqual(result['decision'],'BLOCK')
                self.assertEqual(result['body_sha256'],sha256(text.encode()).hexdigest())
                self.assertIn(kind,result['security_tags']['detector_tags'])
                self.assertEqual(result['model_profiles']['structured'],STRUCTURED_PROFILE)

    def test_ui_catalog_examples_correspond_to_actual_rules(self):
        catalog=detector_catalog()
        self.assertEqual(catalog['iban_registry']['country_count'],89)
        for name,entry in catalog['examples'].items():
            with self.subTest(name=name):
                self.assertEqual(bool(structured_findings(entry['text'])),entry['expected']=='BLOCK')
