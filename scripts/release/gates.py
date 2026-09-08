"""Read-only candidate/CI gates and authenticated evidence retrieval."""
import hashlib
import io
import json
import os
import re
import urllib.error
import urllib.request
import zipfile

REPOSITORY = 'biulight/age-plugin-phone'
CI_PATH = '.github/workflows/ci.yml'
RELEASE_PATH = '.github/workflows/crates-release.yml'


class Stop(Exception):
    """Only fixed, credential-free diagnostic codes cross the logging boundary."""


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected is not None:
            redirected.remove_header('Authorization')
        return redirected


def require(condition, code):
    if not condition:
        raise Stop(code)


def request(url, token=None, missing=False):
    headers = {'User-Agent': 'age-plugin-phone-release', 'Accept': 'application/json'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    try:
        with urllib.request.build_opener(SafeRedirect()).open(
                urllib.request.Request(url, headers=headers), timeout=30) as response:
            return response.read()
    except urllib.error.HTTPError as error:
        if error.code == 404 and missing:
            return None
        raise Stop('http-status-' + str(error.code)) from None
    except (OSError, TimeoutError):
        raise Stop('network-error') from None


class GitHub:
    def get(self, path):
        return json.loads(request('https://api.github.com/repos/' + REPOSITORY + path,
                                  os.environ.get('GH_TOKEN')))

    def pages(self, path, key):
        result = []
        for page in range(1, 101):
            data = self.get(path + ('&' if '?' in path else '?') + f'per_page=100&page={page}')[key]
            result.extend(data)
            if len(data) < 100:
                return result
        raise Stop('github-pagination-limit')


def validate_run(run, workflow, sha, event, path):
    require(workflow['path'] == path and workflow['state'] == 'active', 'workflow-identity')
    require(run['workflow_id'] == workflow['id'] and run['path'] == path, 'run-workflow-identity')
    require(run['repository']['full_name'] == REPOSITORY
            and run['head_repository']['full_name'] == REPOSITORY, 'run-repository')
    require(run['head_sha'] == sha and run['event'] == event
            and run['head_branch'] == 'main', 'run-source')


def ci_gate(api, sha):
    workflow = api.get('/actions/workflows/ci.yml')
    runs = api.pages('/actions/workflows/ci.yml/runs?head_sha=' + sha + '&event=push', 'workflow_runs')
    require(bool(runs), 'ci-missing')
    # Latest run for this exact SHA: an old success cannot hide a newer failure/rerun.
    run = api.get('/actions/runs/' + str(max(runs, key=lambda r: r['id'])['id']))
    validate_run(run, workflow, sha, 'push', CI_PATH)
    require(run['status'] == 'completed' and run['conclusion'] == 'success', 'ci-not-successful')
    return {'run_id': run['id'], 'attempt': run['run_attempt'], 'workflow_id': workflow['id'],
            'head_sha': sha, 'event': 'push', 'conclusion': 'success'}


def candidate_gate(sha, actual, version, expected_version, context, protected):
    require(re.fullmatch('[0-9a-f]{40}', sha) is not None, 'invalid-sha')
    require(sha == actual == context['sha'], 'candidate-sha-mismatch')
    require(version == expected_version and re.fullmatch(r'\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?', version),
            'candidate-version-mismatch')
    require(context['repository'] == REPOSITORY and context['event'] == 'workflow_dispatch'
            and context['ref'] == 'refs/heads/main', 'untrusted-dispatch')
    require(protected, 'main-not-protected')


def recovery(api, run_id, sha):
    """Download only evidence from the same repo/workflow/SHA, never caller URLs."""
    if not run_id:
        return []
    require(re.fullmatch('[0-9]+', run_id) is not None, 'invalid-recovery-run')
    run = api.get('/actions/runs/' + run_id)
    validate_run(run, api.get('/actions/workflows/crates-release.yml'), sha,
                 'workflow_dispatch', RELEASE_PATH)
    require(run['status'] == 'completed', 'recovery-run-incomplete')
    artifacts = api.pages('/actions/runs/' + run_id + '/artifacts', 'artifacts')
    evidence = []
    for artifact in artifacts:
        if not artifact['name'].startswith('crates-evidence-'):
            continue
        require(not artifact['expired'], 'recovery-evidence-expired')
        # GitHub's redirect handler strips Authorization on the signed blob URL.
        blob = request('https://api.github.com/repos/' + REPOSITORY + '/actions/artifacts/'
                       + str(artifact['id']) + '/zip', os.environ.get('GH_TOKEN'))
        require(artifact.get('digest') == 'sha256:' + hashlib.sha256(blob).hexdigest(),
                'recovery-artifact-digest')
        with zipfile.ZipFile(io.BytesIO(blob)) as archive:
            for name in archive.namelist():
                if name.endswith('result.json'):
                    evidence.append(json.loads(archive.read(name)))
    require(bool(evidence), 'recovery-evidence-missing')
    return evidence


def prior_publications(api, version, explicit_run=''):
    """Omitting recovery_run_id must never turn an uncertain upload into a retry.

    The immutable run title identifies the version before downloading evidence.
    Scan all matching publication runs, not just the most recent success.
    """
    runs = api.pages('/actions/workflows/crates-release.yml/runs?event=workflow_dispatch&branch=main',
                     'workflow_runs')
    previous = []
    found = not explicit_run
    for run in runs:
        if str(run['id']) == os.environ.get('GITHUB_RUN_ID'):
            continue
        if run['display_title'] != f'crates.io {version} (publish)' and str(run['id']) != explicit_run:
            continue
        found = found or str(run['id']) == explicit_run
        previous.extend(recovery(api, str(run['id']), run['head_sha']))
    require(found, 'recovery-run-not-found')
    return previous
