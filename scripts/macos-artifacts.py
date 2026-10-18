#!/usr/bin/env python3
"""Sign flat CLI Mach-O files or flat installer PKGs, never run their contents."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile

MACHO = {bytes.fromhex(value) for value in ('feedface', 'cefaedfe', 'feedfacf', 'cffaedfe',
                                         'cafebabe', 'bebafeca', 'cafebabf', 'bfbafeca')}


def digest(path):
    sha = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            sha.update(block)
    return sha.hexdigest()


def checked_files(directory, stage):
    if stage not in ('cli', 'pkg'):
        raise ValueError('unsupported signing stage')
    root = Path(directory)
    if root.is_symlink() or not root.is_dir():
        raise ValueError('artifact root must be a regular directory')
    files = sorted(root.iterdir())
    if not 1 <= len(files) <= 32:
        raise ValueError('expected 1-32 flat signing inputs')
    names, total = set(), 0
    for path in files:
        if path.is_symlink() or not path.is_file() or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*', path.name):
            raise ValueError('input must contain only safely named regular files, not directories or symlinks')
        if path.name.casefold() in names or path.name.casefold() in ('signinginfo.json', 'sha256sums'):
            raise ValueError('input contains a duplicate or reserved filename')
        names.add(path.name.casefold())
        size = path.stat().st_size
        if not 8 <= size <= 512 * 1024 * 1024:
            raise ValueError('each signing input must be 8 bytes to 512 MiB')
        total += size
        with path.open('rb') as stream:
            header = stream.read(4)
        if stage == 'cli' and header not in MACHO:
            raise ValueError('CLI stage accepts only Mach-O executables, not archives or app bundles')
        if stage == 'pkg' and (path.suffix != '.pkg' or header != b'xar!'):
            raise ValueError('PKG stage accepts only flat XAR .pkg installers')
    if total > 2 * 1024 * 1024 * 1024:
        raise ValueError('input exceeds the 2 GiB batch limit')
    return files


def command(args, sensitive=False):
    result = subprocess.run([str(a) for a in args], text=True, capture_output=True)
    if result.returncode:
        if not sensitive:
            print(result.stderr, file=sys.stderr)
        # security import/unlock use passwords in argv. Never echo argv.
        raise ValueError(f'{Path(str(args[0])).name} {args[1]} failed (exit {result.returncode})')
    return result.stdout


def configuration(env, stage):
    kind = 'APPLICATION' if stage == 'cli' else 'INSTALLER'
    required = ('APPLE_TEAM_ID', 'APPLE_NOTARY_KEY_ID', 'APPLE_NOTARY_ISSUER_ID',
                'APPLE_NOTARY_KEY_P8_BASE64', f'APPLE_{kind}_P12_BASE64',
                f'APPLE_{kind}_P12_PASSWORD', f'APPLE_{kind}_IDENTITY')
    missing = [name for name in required if not env.get(name)]
    if missing:
        raise ValueError('missing signing configuration: ' + ', '.join(missing))
    team = env['APPLE_TEAM_ID']
    if not re.fullmatch(r'[A-Z0-9]{10}', team):
        raise ValueError('APPLE_TEAM_ID must be the 10-character developer team ID')
    identity = env[f'APPLE_{kind}_IDENTITY']
    expected = 'Developer ID Application: ' if stage == 'cli' else 'Developer ID Installer: '
    if not identity.startswith(expected) or not identity.endswith('(' + team + ')'):
        raise ValueError('Developer ID identity type/team does not match the selected signing stage')
    return kind


def private_file(path, encoded):
    # Exclusive create and restrictive mode apply before any private bytes land.
    data = base64.b64decode(encoded, validate=True)
    with open(path, 'xb', opener=lambda name, flags: os.open(name, flags, 0o600)) as stream:
        stream.write(data)


def notarize(path, key_path, env):
    result = command(['xcrun', 'notarytool', 'submit', path, '--key', key_path,
                      '--key-id', env['APPLE_NOTARY_KEY_ID'], '--issuer', env['APPLE_NOTARY_ISSUER_ID'],
                      '--wait', '--timeout', '25m', '--output-format', 'json'])
    receipt = json.loads(result)
    if receipt.get('status') != 'Accepted' or not receipt.get('id'):
        raise ValueError('Apple notarization was not Accepted; inspect its submission history')
    print(f"Apple accepted {path.name}: {receipt['id']}")
    return {'id': receipt['id'], 'status': 'Accepted', 'submittedSHA256': digest(path)}


def sign(args, env):
    files = checked_files(args.input_directory, args.stage)
    kind = configuration(env, args.stage)
    if sys.platform != 'darwin':
        raise ValueError('Apple signing requires native macOS and Xcode tools')
    output = Path(args.output_directory)
    if output.exists():
        raise ValueError('signing output directory must not exist')
    output.mkdir(parents=True)
    for source in files:
        shutil.copyfile(source, output / source.name)
        (output / source.name).chmod(0o755 if args.stage == 'cli' else 0o644)
    original_keychains = shlex.split(command(['security', 'list-keychains', '-d', 'user']))
    receipts = {}
    with tempfile.TemporaryDirectory(prefix='bit-precise-signing-', dir=env.get('RUNNER_TEMP')) as temp:
        temporary = Path(temp)
        temporary.chmod(0o700)
        keychain, password = temporary / 'signing.keychain-db', secrets.token_urlsafe(32)
        created, search_changed = False, False
        try:
            command(['security', 'create-keychain', '-p', password, keychain], sensitive=True)
            created = True
            command(['security', 'set-keychain-settings', '-lut', '21600', keychain])
            command(['security', 'unlock-keychain', '-p', password, keychain], sensitive=True)
            certificate = temporary / 'identity.p12'
            private_file(certificate, env[f'APPLE_{kind}_P12_BASE64'])
            command(['security', 'import', certificate, '-k', keychain,
                     '-P', env[f'APPLE_{kind}_P12_PASSWORD'], '-T', '/usr/bin/codesign',
                     '-T', '/usr/bin/productsign'], sensitive=True)
            certificate.unlink()
            command(['security', 'set-key-partition-list', '-S', 'apple-tool:,apple:,codesign:',
                     '-s', '-k', password, keychain], sensitive=True)
            search_changed = True
            command(['security', 'list-keychains', '-d', 'user', '-s', *original_keychains, keychain])
            key = temporary / 'notary-key.p8'
            private_file(key, env['APPLE_NOTARY_KEY_P8_BASE64'])
            identity = env[f'APPLE_{kind}_IDENTITY']
            for source in files:
                path = output / source.name
                if args.stage == 'cli':
                    command(['codesign', '--force', '--options', 'runtime', '--timestamp',
                             '--sign', identity, '--keychain', keychain, path])
                    command(['codesign', '--verify', '--strict', path])
                else:
                    signed = temporary / source.name
                    command(['productsign', '--sign', identity, '--keychain', keychain, '--timestamp', path, signed])
                    os.replace(signed, path)
                    command(['pkgutil', '--check-signature', path])
            if args.stage == 'cli':
                signed_hashes = {p.name: digest(output / p.name) for p in files}
                archive = temporary / 'signed-cli.zip'
                command(['ditto', '-c', '-k', output, archive])
                receipt = notarize(archive, key, env)
                for source in files:
                    path = output / source.name
                    command(['codesign', '--verify', '--strict', path])
                    if digest(path) != signed_hashes[path.name]:
                        raise ValueError('CLI changed during notarization')
                    receipts[path.name] = receipt
            else:
                for source in files:
                    path = output / source.name
                    receipts[path.name] = notarize(path, key, env)
                    command(['xcrun', 'stapler', 'staple', path])
                    command(['xcrun', 'stapler', 'validate', path])
                    command(['spctl', '--assess', '--type', 'install', '--verbose=2', path])
        finally:
            try:
                if search_changed:
                    command(['security', 'list-keychains', '-d', 'user', '-s', *original_keychains])
            finally:
                if created:
                    command(['security', 'delete-keychain', keychain], sensitive=True)
    # Checksums are written only after all signing/notary/cleanup steps succeed.
    records = [{'name': source.name, 'sha256': digest(output / source.name),
                'notarization': receipts[source.name], 'stapled': args.stage == 'pkg'} for source in files]
    metadata = {'provider': 'Apple Developer ID', 'stage': args.stage, 'signed': True,
                'notarized': True, 'files': records}
    (output / 'SIGNINGINFO.json').write_text(json.dumps(metadata, indent=2, sort_keys=True) + '\n')
    (output / 'SHA256SUMS').write_text(''.join(f'{digest(p)}  {p.name}\n' for p in sorted(output.iterdir()) if p.is_file()))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage', required=True, choices=('cli', 'pkg'))
    parser.add_argument('--input-directory', required=True)
    parser.add_argument('--output-directory', required=True)
    args = parser.parse_args()
    def terminate(signum, frame):
        raise SystemExit(128 + signum)
    signal.signal(signal.SIGTERM, terminate)
    try:
        sign(args, os.environ)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, f'macOS signing: {error}\n')


if __name__ == '__main__':
    main()
