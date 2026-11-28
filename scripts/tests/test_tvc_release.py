"""Run the whole auto-live release against a fake tvc and curl; never touches Turnkey."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

RELEASE = Path(__file__).resolve().parents[1] / 'tvc-release.sh'

# sleep is a no-op shell stub. tvc and curl share one stateful Python fake, started with -I -S
# to keep per-call startup low. Traffic follows the live deployment unless the case pins it to the
# previous one, and the health endpoint answers for whichever deployment traffic reaches.
SLEEP = '#!/bin/sh\nexit 0\n'
FAKE = r'''#!/usr/bin/env -S python3 -I -S
import json, os, pathlib, sys
root = pathlib.Path(os.environ['RELEASE_FIXTURE'])
cfg = json.loads((root / 'case.json').read_text())
state_path = root / 'state.json'
state = json.loads(state_path.read_text())
name = pathlib.Path(sys.argv[0]).name
args = [a for a in sys.argv[1:] if a not in ('--non-interactive', '--message-format', 'json')]
with (root / 'calls').open('a') as log:
    log.write(name + ' ' + ' '.join(args) + '\n')

def opt(flag):
    return args[args.index(flag) + 1]

def routed():
    return 'previous' if cfg.get('routing_stuck') else state['live']

def out(obj):
    print(json.dumps(obj))

if name == 'curl':
    if routed() == 'new' and cfg.get('new_unhealthy'):
        out({'status': 'starting'})
    else:
        out({'status': 'healthy'})
    sys.exit(0)

cmd = args[:2]
if cmd == ['app', 'list']:
    out({'apps': [{'id': 'app', 'liveDeploymentId': state['live']}]})
elif cmd == ['deploy', 'create']:
    out({'deploymentId': 'new'})
elif cmd == ['deploy', 'status']:
    out({'manifestId': 'manifest'})
elif cmd in (['deploy', 'approve'], ['deploy', 'provision'], ['deploy', 'delete']):
    out({})
elif cmd == ['app', 'status']:
    out({'deployments': [{'deploymentId': 'new', 'replicas': {'ready': 1, 'desired': 1}}]})
elif cmd == ['app', 'set-live-deploy']:
    target = opt('--deploy-id')
    if target == 'previous' and cfg.get('rollback_fails'):
        out({'error': 'set-live-deploy refused'})
        sys.exit(1)
    state['live'] = target
    state_path.write_text(json.dumps(state))
    out({})
elif cmd == ['deploy', 'get-status']:
    target = opt('--deploy-id')
    out({'appId': 'app', 'deploymentId': target, 'isTargeted': routed() == target,
         'replicas': {'ready': 1, 'desired': 1}})
else:
    sys.exit('unexpected fake CLI command: ' + ' '.join(args))
'''


class ReleaseRolloutTests(unittest.TestCase):
    def run_release(self, **case):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'case.json').write_text(json.dumps(case))
            (root / 'state.json').write_text(json.dumps({'live': 'previous'}))
            for name, body in [('tvc', FAKE), ('curl', FAKE), ('sleep', SLEEP)]:
                path = root / 'bin' / name
                path.parent.mkdir(exist_ok=True)
                path.write_text(body)
                path.chmod(0o755)
            configs = root / 'tvc-configs'
            configs.mkdir()
            (configs / 'deploy.json').write_text(json.dumps({'appId': 'app', 'replicas': 1}))
            (configs / 'release.mint-attester.test.json').write_text(json.dumps({
                'deployConfig': 'tvc-configs/deploy.json', 'autoLive': True,
                'approvers': ['operator'], 'provisioners': ['operator']}))
            turnkey = root / 'home' / '.config' / 'turnkey'
            turnkey.mkdir(parents=True)
            (turnkey / 'tvc.config.toml').write_text('')
            env = {k: v for k, v in os.environ.items() if not k.startswith(('TVC_', 'GITHUB_'))}
            env.update(PATH=str(root / 'bin') + os.pathsep + env['PATH'], HOME=str(root / 'home'),
                       TMPDIR=temp, RELEASE_FIXTURE=temp,
                       GITHUB_STEP_SUMMARY=str(root / 'summary.md'))
            result = subprocess.run(
                ['bash', str(RELEASE), 'test', 'ghcr.io/example@sha256:' + '0' * 64, '1' * 64],
                cwd=root, env=env, capture_output=True, text=True, timeout=60)
            calls = (root / 'calls').read_text().splitlines()
            live = json.loads((root / 'state.json').read_text())['live']
            summary = (root / 'summary.md').read_text() if (root / 'summary.md').exists() else ''
            return result, calls, live, summary

    def assert_rolled_back(self, result, calls, live, summary):
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(live, 'previous')
        self.assertIn('tvc app set-live-deploy --deploy-id new', calls)
        self.assertIn('tvc app set-live-deploy --deploy-id previous', calls)
        self.assertFalse([c for c in calls if c.startswith('tvc deploy delete')])
        self.assertIn('rollback to previous accepted', result.stdout)
        self.assertIn('failed live routing/health verification', summary)

    def test_healthy_release_goes_live_and_deletes_previous(self):
        result, calls, live, summary = self.run_release()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(live, 'new')
        self.assertIn('tvc deploy delete --deploy-id previous', calls)
        self.assertNotIn('tvc app set-live-deploy --deploy-id previous', calls)
        self.assertIn('## test: live', summary)

    def test_traffic_stuck_on_previous_rolls_back_and_keeps_it(self):
        self.assert_rolled_back(*self.run_release(routing_stuck=True))

    def test_unhealthy_new_deployment_rolls_back_and_keeps_previous(self):
        result, calls, live, summary = self.run_release(new_unhealthy=True)
        self.assert_rolled_back(result, calls, live, summary)
        self.assertIn('last state seen: health body {"status": "starting"}', result.stdout)

    def test_failed_rollback_is_reported_and_still_writes_summary(self):
        result, calls, live, summary = self.run_release(new_unhealthy=True, rollback_fails=True)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(live, 'new')
        self.assertIn('::error::rollback to previous failed; new is still live', result.stdout)
        self.assertNotIn('rollback to previous accepted', result.stdout)
        self.assertFalse([c for c in calls if c.startswith('tvc deploy delete')])
        self.assertIn('failed live routing/health verification', summary)


if __name__ == '__main__':
    unittest.main()
