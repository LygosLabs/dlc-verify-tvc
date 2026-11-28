"""Run the whole auto-live release against a fake tvc and curl; never touches Turnkey."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

RELEASE = Path(__file__).resolve().parents[1] / 'tvc-release.sh'

# sleep is a no-op shell stub. tvc and curl share one stateful Python fake, started with -I -S
# to keep per-call startup low. Traffic follows the live deployment unless the case pins it to one
# deployment (routing_stuck), and the health endpoint answers for whichever deployment traffic
# reaches. tvc refuses calls without the JSON flags the script must always pass.
SLEEP = '#!/bin/sh\nexit 0\n'
FAKE = r'''#!/usr/bin/env -S python3 -I -S
import json, os, pathlib, sys
root = pathlib.Path(os.environ['RELEASE_FIXTURE'])
cfg = json.loads((root / 'case.json').read_text())
state_path = root / 'state.json'
state = json.loads(state_path.read_text())
name = pathlib.Path(sys.argv[0]).name
raw = sys.argv[1:]
args = [a for a in raw if a not in ('--non-interactive', '--message-format', 'json')]
with (root / 'calls').open('a') as log:
    log.write(name + ' ' + ' '.join(args) + '\n')
if name == 'tvc' and not ('--non-interactive' in raw and raw[-2:] == ['--message-format', 'json']):
    sys.exit('fake tvc: missing --non-interactive --message-format json')

def opt(flag):
    return args[args.index(flag) + 1]

def routed():
    return cfg.get('routing_stuck') or state['live']

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
    hang = cfg.get('hang_set_live')
    if target == 'new' and hang:
        # Stand-in for a request Turnkey may or may not have applied before the client hung.
        if hang.get('applied'):
            state['live'] = target
            state_path.write_text(json.dumps(state))
        if hang.get('ignore_term'):
            import signal
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
        import time
        time.sleep(120)
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
    def run_release(self, extra_env=None, **case):
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
            env.update(extra_env or {})
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
        self.assertIn('tvc deploy get-status --deploy-id previous', calls)
        self.assertIn('previous is live, all replicas are ready', result.stdout)
        self.assertNotIn('rollback health could not be verified', result.stdout)
        self.assertIn('failed live routing/health verification', summary)

    def no_calls(self, calls, prefix):
        return not [c for c in calls if c.startswith(prefix)]

    def test_healthy_release_goes_live_and_deletes_previous(self):
        result, calls, live, summary = self.run_release()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(live, 'new')
        self.assertIn('tvc deploy create --config-file tvc-configs/deploy.json '
                      '--pivot-image-url ghcr.io/example@sha256:' + '0' * 64 +
                      ' --expected-pivot-digest ' + '1' * 64, calls)
        self.assertIn('tvc deploy approve --deploy-id new --operator-id operator '
                      '--dangerous-skip-interactive', calls)
        self.assertIn('tvc deploy provision --deploy-id new --operator-id operator', calls)
        self.assertIn('tvc deploy delete --deploy-id previous', calls)
        self.assertNotIn('tvc app set-live-deploy --deploy-id previous', calls)
        self.assertIn('## test: live', summary)

    def test_traffic_stuck_on_previous_rolls_back_and_keeps_it(self):
        self.assert_rolled_back(*self.run_release(routing_stuck='previous'))

    def test_unhealthy_new_deployment_rolls_back_and_keeps_previous(self):
        result, calls, live, summary = self.run_release(new_unhealthy=True)
        self.assert_rolled_back(result, calls, live, summary)
        self.assertIn('last state seen: health body {"status": "starting"}', result.stdout)

    def test_failed_rollback_is_reported_and_still_writes_summary(self):
        result, calls, live, summary = self.run_release(new_unhealthy=True, rollback_fails=True)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(live, 'new')
        self.assertIn('::error::rollback to previous failed; Turnkey reports live deployment new',
                      result.stdout)
        self.assertNotIn('rollback to previous accepted', result.stdout)
        self.assertFalse([c for c in calls if c.startswith('tvc deploy delete')])
        self.assertIn('failed live routing/health verification', summary)

    def test_rollback_that_never_verifies_is_reported(self):
        result, calls, live, summary = self.run_release(new_unhealthy=True, routing_stuck='new')
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(live, 'previous')
        self.assertIn('rollback to previous accepted', result.stdout)
        self.assertIn('::error::rollback health could not be verified', result.stdout)
        self.assertTrue(self.no_calls(calls, 'tvc deploy delete'))
        self.assertIn('failed live routing/health verification', summary)

    def test_hung_switch_that_never_landed_is_killed_and_leaves_previous_live(self):
        # The fake ignores SIGTERM, so only timeout's -k follow-up SIGKILL can end the call.
        result, calls, live, summary = self.run_release(
            extra_env={'TVC_CALL_TIMEOUT': '2'},
            hang_set_live={'applied': False, 'ignore_term': True})
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(live, 'previous')
        self.assertIn('tvc app set-live-deploy timed out after 2s', result.stderr)
        self.assertIn('::error::set-live-deploy for new failed; live deployment previous untouched',
                      result.stdout)
        self.assertNotIn('tvc app set-live-deploy --deploy-id previous', calls)
        self.assertTrue(self.no_calls(calls, 'tvc deploy delete'))
        self.assertIn('failed to switch traffic', summary)

    def test_hung_switch_that_landed_is_verified_and_completes(self):
        result, calls, live, summary = self.run_release(
            extra_env={'TVC_CALL_TIMEOUT': '2'}, hang_set_live={'applied': True})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(live, 'new')
        self.assertIn('reported failure, but the live deployment is new', result.stdout)
        self.assertIn('tvc deploy delete --deploy-id previous', calls)
        self.assertIn('## test: live', summary)

    def test_past_switch_deadline_never_moves_traffic(self):
        result, calls, live, summary = self.run_release(extra_env={'RELEASE_SWITCH_DEADLINE': '0'})
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(live, 'previous')
        self.assertTrue(self.no_calls(calls, 'tvc app set-live-deploy'))
        self.assertIn('not switched: ran past the switch deadline', summary)


if __name__ == '__main__':
    unittest.main()
