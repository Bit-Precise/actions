#!/usr/bin/env python3
"""Validate the caller and artifact contract before a signing job can start."""
import os
import re
import sys

OWNER_ID = '295183371'
STAGES = {'windows': {'exe', 'msi'}, 'macos': {'cli', 'pkg'}}


def authorize(env):
    if env.get('CALLER_OWNER_ID') != OWNER_ID:
        raise ValueError('signing is restricted to the Bit-Precise organization ID')
    event, ref = env.get('CALLER_EVENT'), env.get('CALLER_REF', '')
    if not ((event == 'push' and ref.startswith('refs/tags/v')) or
            (event == 'workflow_dispatch' and ref == 'refs/heads/main')):
        raise ValueError('signing requires a v* tag push or manual dispatch on main; PR events cannot sign')
    platform, stage = env.get('SIGN_PLATFORM'), env.get('SIGN_STAGE')
    if stage not in STAGES.get(platform, set()):
        raise ValueError('unsupported signing platform/stage')
    source = env.get('INPUT_ARTIFACT', '')
    destination = env.get('OUTPUT_ARTIFACT') or source + '-signed'
    for value in (source, destination):
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', value):
            raise ValueError('artifact names must contain 1-128 letters, digits, dots, underscores or hyphens')
    if source == destination:
        raise ValueError('signed artifact name must differ from the input artifact name')
    return destination


def main():
    try:
        destination = authorize(os.environ)
        with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
            output.write(f'signed-artifact-name={destination}\n')
    except (KeyError, OSError, ValueError) as error:
        sys.exit(f'signing authorization: {error}')


if __name__ == '__main__':
    main()
