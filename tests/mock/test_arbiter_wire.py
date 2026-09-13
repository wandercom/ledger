"""The Ledger adapter uses Arbiter's published fingerprint registration wire format."""
from unittest.mock import Mock, patch

import pytest

from mock import CanaryValue, register_canary_with_arbiter


def canaries():
    return [CanaryValue(field_name='email', row_index=0,
                        raw_fingerprint='ledger-canary-pii-abcd1234',
                        shaped_value='ledger-canary-pii-abcd1234@canary.invalid')]


def test_fingerprint_route_payload_and_run_receipt():
    response = Mock(status_code=200)
    response.json.return_value = {'status': 'ok', 'registered': 1}
    with patch('httpx.Client.post', return_value=response) as post:
        result = register_canary_with_arbiter('https://arbiter.example/', canaries(), 'PII', 'users-db', 'users')
    assert result.success
    assert post.call_args.args == ('https://arbiter.example/canary/register-fingerprint',)
    assert post.call_args.kwargs['json'] == {
        'run_id': result.registration_id,
        'fingerprints': [{'fingerprint': 'ledger-canary-pii-abcd1234', 'category': 'PII', 'tier': 'PII'}],
    }


@pytest.mark.parametrize('ack', [
    {'status': 'ok', 'registered': 0}, {'status': 'ok', 'registered': True},
    {'status': 'ok', 'registered': '1'}, {'status': 'error', 'registered': 1},
])
def test_incomplete_or_invalid_ack_is_failure(ack):
    response = Mock(status_code=200)
    response.json.return_value = ack
    with patch('httpx.Client.post', return_value=response):
        result = register_canary_with_arbiter('https://arbiter.example', canaries(), 'PII', 'users-db', 'users')
    assert result.success is False
    assert result.registration_id is None
