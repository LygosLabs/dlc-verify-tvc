"""Exercise rollout verification offline; never invoke Turnkey or a real health endpoint."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

HELPER = Path(__file__).resolve().parents[1] / 'tvc-wait-live.sh'
FAKE = r'''#!/usr/bin/env python3
import json, os, pathlib, sys
root = pathlib.Path(os.environ['ROLLOUT_FIXTURE'])
cfg = json.loads((root / 'case.json').read_text())
name = pathlib.Path(sys.argv[0]).name
with (root / 'calls').open('a') as log:
    log.write(name + ' ' + ' '.join(sys.argv[1:]) + '\n')
if name == 'sleep':
    sys.exit(0)
if name == 'curl':
    print(cfg.get('body', '{"status":"healthy"}'))
    sys.exit(cfg.get('curl_exit', 0))
count_path = root / 'attempt'
if sys.argv[1:3] == ['app', 'list']:
    attempt = int(count_path.read_text()) + 1 if count_path.exists() else 1
    count_path.write_text(str(attempt))
    if attempt <= cfg.get('api_errors', 0):
        sys.exit(1)
    print(json.dumps({'apps': [{'id': 'app', 'liveDeploymentId':
        'previous' if attempt <= cfg.get('metadata_delay', 0) else 'new'}]}))
elif sys.argv[1:3] == ['deploy', 'get-status']:
    attempt = int(count_path.read_text())
    print(json.dumps({'appId': cfg.get('app_id', 'app'),
        'deploymentId': cfg.get('deploy_id', 'new'),
        'isTargeted': attempt > cfg.get('routing_delay', 0),
        'replicas': {'ready': cfg.get('ready', 3), 'desired': cfg.get('desired', 3)}}))
else:
    sys.exit('unexpected fake CLI command')
'''


class LiveRolloutTests(unittest.TestCase):
    def run_case(self, **case):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'case.json').write_text(json.dumps(case))
            for name in ['tvc', 'curl', 'sleep']:
                path = root / name
                path.write_text(FAKE)
                path.chmod(0o755)
            env = os.environ.copy()
            env['PATH'] = str(root) + os.pathsep + env['PATH']
            env['ROLLOUT_FIXTURE'] = str(root)
            result = subprocess.run(
                ['bash', '-c', 'set -euo pipefail; source "$1"; '
                 'tvc_json() { tvc "$@"; }; '
                 'wait_for_live_deployment app new https://staging.invalid/health',
                 'test', str(HELPER)], env=env, capture_output=True, text=True, timeout=20)
            return result, (root / 'calls').read_text(), int((root / 'attempt').read_text())

    def test_success_requires_matching_live_metadata_and_runtime(self):
        result, calls, attempts = self.run_case(metadata_delay=2, routing_delay=4)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(attempts, 5)
        self.assertEqual(calls.count('curl '), 1)
        self.assertIn('all replicas are ready', result.stdout)

    def test_old_healthy_endpoint_cannot_pass_while_routing_is_stale(self):
        result, calls, attempts = self.run_case(routing_delay=99)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(attempts, 30)
        self.assertNotIn('curl ', calls)

    def test_transient_api_failure_is_retried(self):
        result, _, attempts = self.run_case(api_errors=2)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(attempts, 3)

    def test_incomplete_or_wrong_deployment_is_never_accepted(self):
        for case in [dict(ready=0, desired=0), dict(ready=1, desired=3),
                     dict(app_id='other-app'), dict(deploy_id='other-deploy')]:
            with self.subTest(case=case):
                result, calls, _ = self.run_case(**case)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('curl ', calls)

    def test_health_requires_successful_http_and_healthy_json(self):
        for case in [dict(curl_exit=22), dict(body='not JSON'),
                     dict(body='{"status":"starting"}'), dict(body='{}')]:
            with self.subTest(case=case):
                result, _, attempts = self.run_case(**case)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(attempts, 30)

    def test_uses_runtime_replica_count_including_single_replica_staging(self):
        result, _, attempts = self.run_case(ready=1, desired=1)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(attempts, 1)


if __name__ == '__main__':
    unittest.main()
