"""Governed catalog metadata. No raw detector values or caller supplied verdicts."""
from .content_security import structured_findings

PROFILE = 'sedra-governed-labels-v1'
BUSINESS_TAGS = ('research', 'finance', 'operations', 'engineering', 'public-communications',
                 'intellectual-property', 'credentials', 'demo-synthetic')
OWNERS = ('Research', 'Finance', 'Security', 'Communications')
DEFAULTS = {
    'araz-plan': ('Research', ['research', 'finance', 'intellectual-property', 'demo-synthetic']),
    'isiq-research': ('Research', ['research', 'engineering', 'demo-synthetic']),
    'restricted-runbook': ('Security', ['operations', 'credentials', 'demo-synthetic']),
    'public-note': ('Communications', ['public-communications', 'demo-synthetic']),
}


def base_label(doc):
    return {'public': 'public', 'controlled_excerpt': 'confidential', 'restricted': 'restricted'}[doc['classification']]


def default_control(doc):
    owner, tags = DEFAULTS.get(doc['id'], ('Security', ['demo-synthetic']))
    return {'sensitivity': base_label(doc), 'owner': owner, 'business_tags': tags,
            'revision': 0, 'updated_at': None, 'updated_by': 'registered-corpus', 'change_reason': 'INITIAL_REGISTRATION'}


def validate_control(doc, body):
    allowed = {'doc_id', 'expected_revision', 'sensitivity', 'owner', 'business_tags', 'change_reason'}
    if set(body) != allowed:
        raise ValueError('Provide exactly the governed label fields')
    if type(body['expected_revision']) is not int or body['expected_revision'] < 0:
        raise ValueError('expected_revision must be a nonnegative integer')
    permitted = {'confidential', 'restricted'} if doc['classification'] == 'controlled_excerpt' else {base_label(doc)}
    if body['sensitivity'] not in permitted:
        raise ValueError('Cannot weaken a registered sensitivity floor or relabel public exclusions')
    if body['owner'] not in OWNERS:
        raise ValueError('Choose a declared data owner')
    tags = body['business_tags']
    if not isinstance(tags, list) or len(tags) > 8 or any(not isinstance(t, str) or t not in BUSINESS_TAGS for t in tags):
        raise ValueError('Use at most eight declared business tags')
    if len(set(tags)) != len(tags):
        raise ValueError('Duplicate business tags are not accepted')
    if body['change_reason'] not in ('DATA_OWNER_REVIEW', 'POLICY_REVIEW', 'DEMO_VALIDATION'):
        raise ValueError('Choose a declared change reason')
    return {k: body[k] for k in ('sensitivity', 'owner', 'change_reason')} | {'business_tags': sorted(tags)}


def catalog_metadata(doc, control):
    findings = structured_findings(doc['text'])
    return {**control, 'profile': PROFILE, 'registered_sensitivity_floor': base_label(doc),
            'label_source': 'analyst-governed' if control['revision'] else 'registered-corpus',
            'source_system': 'Registered synthetic corpus', 'synthetic': True,
            'media_type': 'text/plain; charset=utf-8', 'utf8_bytes': len(doc['text'].encode('utf-8')),
            'source_sha256': doc['source_sha256'],
            'detector_tags': sorted({f['type'] for f in findings}),
            'handling': 'Block recognized protected matches' if control['sensitivity'] == 'restricted'
                else '24h / 30d cumulative disclosure limits' if control['sensitivity'] == 'confidential'
                else 'Excluded from protected matching',
            'discovery_scope': 'Registered text only; no endpoint, cloud-drive or filesystem discovery',
            'content_version': doc['version']}


def request_labels(matches, findings):
    protected = [m for m in matches if m.get('confirmed') and m.get('effective_sensitivity') in ('confidential', 'restricted')]
    sensitivity = 'restricted' if findings or any(m['effective_sensitivity'] == 'restricted' for m in protected) else 'confidential' if protected else 'unclassified'
    return {'profile': PROFILE, 'sensitivity': sensitivity,
            'detector_tags': sorted({f['type'] for f in findings}),
            'business_tags': sorted({t for m in protected for t in m['label_snapshot']['business_tags']}),
            'document_ids': sorted({m['doc_id'] for m in protected}),
            'basis': 'structured-detector' if findings else 'registered-content-match' if protected else 'no-protected-match',
            'scope_note': 'Unclassified means no eligible protected match or structured finding; it is not a public-data certification.'}
