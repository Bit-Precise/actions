import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


AUTH = load('authorize', 'authorize.py')
MAC = load('macos_artifacts', 'macos-artifacts.py')


class AuthorizationTest(unittest.TestCase):
    def env(self, **updates):
        return dict(CALLER_OWNER_ID='295183371', CALLER_EVENT='push', CALLER_REF='refs/tags/v1.2.3',
                    SIGN_PLATFORM='windows', SIGN_STAGE='exe', INPUT_ARTIFACT='windows-amd64') | updates

    def test_tag_and_manual_main_only_with_default_or_explicit_output(self):
        self.assertEqual(AUTH.authorize(self.env()), 'windows-amd64-signed')
        self.assertEqual(AUTH.authorize(self.env(CALLER_EVENT='workflow_dispatch', CALLER_REF='refs/heads/main',
                                                OUTPUT_ARTIFACT='verified-exe')), 'verified-exe')
        self.assertEqual(AUTH.authorize(self.env(SIGN_PLATFORM='macos', SIGN_STAGE='pkg')), 'windows-amd64-signed')

    def test_rejects_other_owner_all_pr_events_and_untrusted_refs(self):
        cases = [dict(CALLER_OWNER_ID='1'), dict(CALLER_EVENT='pull_request'),
                 dict(CALLER_EVENT='pull_request_target'), dict(CALLER_EVENT='workflow_run'),
                 dict(CALLER_REF='refs/heads/main'), dict(CALLER_REF='refs/tags/release'),
                 dict(CALLER_EVENT='workflow_dispatch', CALLER_REF='refs/heads/feature')]
        for change in cases:
            with self.subTest(change=change), self.assertRaises(ValueError):
                AUTH.authorize(self.env(**change))

    def test_rejects_mixed_stages_artifact_path_and_output_injection(self):
        for change in (dict(SIGN_STAGE='cli'), dict(SIGN_PLATFORM='other'), dict(INPUT_ARTIFACT='../artifact'),
                       dict(INPUT_ARTIFACT=''), dict(OUTPUT_ARTIFACT='windows-amd64'),
                       dict(OUTPUT_ARTIFACT='artifact\nx=y'), dict(OUTPUT_ARTIFACT='*')):
            with self.subTest(change=change), self.assertRaises(ValueError):
                AUTH.authorize(self.env(**change))


class MacArtifactsTest(unittest.TestCase):
    def env(self, temp):
        return dict(RUNNER_TEMP=temp, APPLE_TEAM_ID='ABCDE12345', APPLE_NOTARY_KEY_ID='key-id',
                    APPLE_NOTARY_ISSUER_ID='issuer', APPLE_NOTARY_KEY_P8_BASE64=base64.b64encode(b'fake-p8').decode(),
                    APPLE_APPLICATION_IDENTITY='Developer ID Application: Example (ABCDE12345)',
                    APPLE_APPLICATION_P12_BASE64=base64.b64encode(b'fake-p12').decode(),
                    APPLE_APPLICATION_P12_PASSWORD='test-password')

    def fixture(self, root):
        source = root / 'input'
        source.mkdir()
        (source / 'agentd').write_bytes(bytes.fromhex('cffaedfe') + b'mock-mach-o')
        return argparse.Namespace(stage='cli', input_directory=str(source), output_directory=str(root / 'output'))

    def test_accepts_only_flat_native_cli_or_pkg(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            args = self.fixture(root)
            self.assertEqual(len(MAC.checked_files(args.input_directory, 'cli')), 1)
            with self.assertRaisesRegex(ValueError, 'PKG'):
                MAC.checked_files(args.input_directory, 'pkg')
            source = Path(args.input_directory)
            (source / 'agentd').unlink()
            (source / 'agentd.pkg').write_bytes(b'xar!fake-package')
            self.assertEqual(len(MAC.checked_files(source, 'pkg')), 1)
            with self.assertRaisesRegex(ValueError, 'Mach-O'):
                MAC.checked_files(source, 'cli')

    def test_rejects_subdirectory_link_reserved_names_and_bad_magic(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            args = self.fixture(root)
            source = Path(args.input_directory)
            (source / 'bundle.app').mkdir()
            with self.assertRaises(ValueError): MAC.checked_files(source, 'cli')
            (source / 'bundle.app').rmdir()
            try:
                (source / 'link').symlink_to(source / 'agentd')
            except OSError:
                pass
            else:
                with self.assertRaises(ValueError): MAC.checked_files(source, 'cli')
                (source / 'link').unlink()
            (source / 'agentd').rename(source / 'signinginfo.json')
            with self.assertRaisesRegex(ValueError, 'reserved'): MAC.checked_files(source, 'cli')
            (source / 'signinginfo.json').unlink()
            (source / 'archive').write_bytes(b'PK-zip-archive')
            with self.assertRaisesRegex(ValueError, 'Mach-O'): MAC.checked_files(source, 'cli')

    def test_configuration_requires_only_selected_certificate_but_requires_team_match(self):
        env = self.env('unused')
        self.assertEqual(MAC.configuration(env, 'cli'), 'APPLICATION')
        with self.assertRaisesRegex(ValueError, 'APPLE_INSTALLER'):
            MAC.configuration(env, 'pkg')
        env['APPLE_APPLICATION_IDENTITY'] = 'Developer ID Application: Other (ABCDE99999)'
        with self.assertRaisesRegex(ValueError, 'type/team'):
            MAC.configuration(env, 'cli')

    def test_private_files_are_exclusive_and_no_secret_in_failure_message(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'key.p8'
            MAC.private_file(path, base64.b64encode(b'private-material').decode())
            if os.name != 'nt': self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            with self.assertRaises(FileExistsError): MAC.private_file(path, base64.b64encode(b'replace').decode())
        failed = subprocess.CompletedProcess([], 1, 'private-key', 'private-password')
        with mock.patch.object(MAC.subprocess, 'run', return_value=failed), mock.patch('sys.stderr') as stderr:
            with self.assertRaisesRegex(ValueError, 'security import failed') as error:
                MAC.command(['security', 'import', '-P', 'private-password'], sensitive=True)
            self.assertNotIn('private-password', str(error.exception))
            stderr.write.assert_not_called()

    def test_notary_failure_cleans_keychain_and_produces_no_checksums(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            args = self.fixture(root)
            calls = []
            def command(argv, **kwargs):
                calls.append([str(arg) for arg in argv])
                return '"/original/login.keychain-db"' if argv == ['security', 'list-keychains', '-d', 'user'] else ''
            with mock.patch.object(MAC.sys, 'platform', 'darwin'), mock.patch.object(MAC, 'command', side_effect=command), \
                    mock.patch.object(MAC, 'notarize', side_effect=ValueError('not Accepted')):
                with self.assertRaisesRegex(ValueError, 'not Accepted'):
                    MAC.sign(args, self.env(temp))
            self.assertEqual(calls[-2], ['security', 'list-keychains', '-d', 'user', '-s', '/original/login.keychain-db'])
            self.assertEqual(calls[-1][:2], ['security', 'delete-keychain'])
            self.assertEqual(list(root.glob('bit-precise-signing-*')), [])
            self.assertFalse((root / 'output/SHA256SUMS').exists())

    def test_accepted_cli_creates_final_hashes_after_cleanup_and_never_executes_cli(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            args = self.fixture(root)
            calls = []
            def command(argv, **kwargs):
                calls.append([str(arg) for arg in argv])
                if argv[:2] == ['security', 'delete-keychain']:
                    self.assertFalse((root / 'output/SHA256SUMS').exists())
                return ''
            receipt = {'id': 'test-submission', 'status': 'Accepted', 'submittedSHA256': 'test-zip-hash'}
            with mock.patch.object(MAC.sys, 'platform', 'darwin'), mock.patch.object(MAC, 'command', side_effect=command), \
                    mock.patch.object(MAC, 'notarize', return_value=receipt):
                MAC.sign(args, self.env(temp))
            output = root / 'output'
            records = json.loads((output / 'SIGNINGINFO.json').read_text())
            self.assertFalse(records['files'][0]['stapled'])
            self.assertEqual(records['files'][0]['notarization']['status'], 'Accepted')
            for line in (output / 'SHA256SUMS').read_text().splitlines():
                expected, name = line.split('  ')
                self.assertEqual(hashlib.sha256((output / name).read_bytes()).hexdigest(), expected)
            self.assertTrue(all(call[0] in ('security', 'codesign', 'ditto') for call in calls))

    def test_notary_requires_accepted_and_receipt_id(self):
        for result in ({'status': 'Invalid', 'id': 'x'}, {'status': 'In Progress', 'id': 'x'}, {'status': 'Accepted'}):
            with mock.patch.object(MAC, 'command', return_value=json.dumps(result)), self.assertRaises(ValueError):
                MAC.notarize(Path('input.zip'), Path('key.p8'), self.env('unused'))

    def test_pkg_is_notarized_then_stapled_and_final_checksum_covers_stapled_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, output = root / 'input', root / 'output'
            source.mkdir()
            unsigned = b'xar!unsigned-installer'
            (source / 'test.pkg').write_bytes(unsigned)
            args = argparse.Namespace(stage='pkg', input_directory=str(source), output_directory=str(output))
            env = self.env(temp) | dict(APPLE_INSTALLER_IDENTITY='Developer ID Installer: Example (ABCDE12345)',
                APPLE_INSTALLER_P12_BASE64=base64.b64encode(b'fake-installer-p12').decode(),
                APPLE_INSTALLER_P12_PASSWORD='installer-password')
            sequence = []
            def command(argv, **kwargs):
                if argv[0] == 'productsign':
                    sequence.append('sign')
                    Path(argv[-1]).write_bytes(Path(argv[-2]).read_bytes() + b'-signed')
                if argv[:3] == ['xcrun', 'stapler', 'staple']:
                    sequence.append('staple')
                    path = Path(argv[-1])
                    path.write_bytes(path.read_bytes() + b'-stapled')
                if argv[:3] == ['xcrun', 'stapler', 'validate']:
                    sequence.append('validate')
                return ''
            def notarize(path, key, env):
                sequence.append('notarize')
                return {'id': 'pkg-receipt', 'status': 'Accepted', 'submittedSHA256': MAC.digest(path)}
            with mock.patch.object(MAC.sys, 'platform', 'darwin'), mock.patch.object(MAC, 'command', side_effect=command), \
                    mock.patch.object(MAC, 'notarize', side_effect=notarize):
                MAC.sign(args, env)
            self.assertEqual(sequence, ['sign', 'notarize', 'staple', 'validate'])
            self.assertEqual((source / 'test.pkg').read_bytes(), unsigned)
            record = json.loads((output / 'SIGNINGINFO.json').read_text())['files'][0]
            self.assertTrue(record['stapled'])
            self.assertNotEqual(record['sha256'], record['notarization']['submittedSHA256'])
            self.assertEqual(record['sha256'], MAC.digest(output / 'test.pkg'))


@unittest.skipUnless(os.name == 'nt' and shutil.which('pwsh'), 'native Windows PowerShell required')
class WindowsArtifactsTest(unittest.TestCase):
    def run_stage(self, phase, stage, source, output):
        return subprocess.run(['pwsh', '-NoProfile', '-File', str(ROOT / 'scripts/windows-artifacts.ps1'),
            '-Phase', phase, '-Stage', stage, '-InputDirectory', str(source), '-OutputDirectory', str(output)],
            text=True, capture_output=True)

    def test_prepare_copies_only_valid_stage_and_verification_rejects_unsigned_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, output = root / 'input', root / 'output'
            source.mkdir()
            (source / 'test.exe').write_bytes(b'MZ-test-input')
            result = self.run_stage('Prepare', 'exe', source, output)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((output / 'test.exe').read_bytes(), b'MZ-test-input')
            result = self.run_stage('Verify', 'exe', source, output)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((output / 'SHA256SUMS').exists())

    def test_prepare_rejects_directory_or_wrong_stage(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / 'input'
            source.mkdir()
            (source / 'test.exe').write_bytes(b'MZ-test-input')
            result = self.run_stage('Prepare', 'msi', source, root / 'wrong-stage')
            self.assertNotEqual(result.returncode, 0)
            (source / 'nested').mkdir()
            result = self.run_stage('Prepare', 'exe', source, root / 'directory')
            self.assertNotEqual(result.returncode, 0)


if __name__ == '__main__':
    unittest.main()
