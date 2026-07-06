"""
Client-side orchestrated micro-scan API (serverless / Vercel native).

The old monolithic POST /scan ran every check in one synchronous request and
blew past Vercel's 60s function budget; the SEO crawler relied on in-memory
threads that don't survive across ephemeral Lambda instances. This blueprint
replaces both with small, independent workers:

    POST /api/scan/init            -> create a ScanResult (status PROCESSING),
                                      return an unguessable public_id
    POST /api/scan/worker/ssl      -> TLS group      -> writes ssl_result
    POST /api/scan/worker/headers  -> headers group  -> writes headers_result
    POST /api/scan/worker/ports    -> ports/discovery-> writes ports_result
    POST /api/scan/worker/seo      -> single-page SEO-> writes seo_result
    POST /api/scan/worker/threat   -> threat intel   -> writes threat_result
    GET  /api/scan/status/<pid>    -> poll; aggregates + scores once all 5 land

The browser fires the five workers in parallel and polls status until COMPLETED.
Each worker writes ONLY its own column, so concurrent workers never clobber one
another. Workers take only the public_id and read the (already-validated) target
from the DB, so a client can't smuggle a different target past init's SSRF check.
"""
import json
import logging

from flask import Blueprint, request, jsonify, session, url_for
from flask_login import current_user

from app import db, rate_limit
from models import ScanResult
from validators import AdvancedValidator, clean_target
from scanner import SecurityScanner
from seo_analyzer import SEOAnalyzer
from threat_intel import ThreatIntelAnalyzer
from utils.secure_http import SSRFSecurityError

api_scan_bp = Blueprint('api_scan', __name__, url_prefix='/api/scan')
logger = logging.getLogger(__name__)

# column name -> the runner that produces its JSON payload from (target, scan_type)
_WORKERS = {
    'ssl':     ('ssl_result',     lambda t, st: SecurityScanner().scan_group_ssl(t)),
    'headers': ('headers_result', lambda t, st: SecurityScanner().scan_group_headers(t)),
    'ports':   ('ports_result',   lambda t, st: SecurityScanner().scan_group_discovery(t)),
    'seo':     ('seo_result',     lambda t, st: SEOAnalyzer().analyze(t) if st == 'domain'
                                                else {'skipped': 'SEO analysis applies to domains only'}),
    'threat':  ('threat_result',  lambda t, st: ThreatIntelAnalyzer().search(t)),
}


def _remember_guest_scan(scan_id):
    """Track guest scan IDs in the session so only the creator can view the report."""
    ids = session.get('guest_scans', [])
    ids.append(scan_id)
    session['guest_scans'] = ids[-50:]


def _payload_from_request():
    return request.get_json(silent=True) or request.form


def _load_col(raw):
    if not raw:
        return None
    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        return {'error': 'corrupt result'}


# ── Init ────────────────────────────────────────────────────────────────────
@api_scan_bp.route('/init', methods=['POST'])
@rate_limit(max_calls=5, window_seconds=60)
def scan_init():
    """Validate the target, create the scan row, return the public handle."""
    data = _payload_from_request()
    target = (data.get('target') or '').strip()
    if not target:
        return jsonify({'error': 'Please enter a domain or IP address to scan.'}), 400

    target = clean_target(target)
    is_valid, error_msg = AdvancedValidator().validate_target(target)
    if not is_valid:
        return jsonify({'error': f'Invalid target: {error_msg}'}), 400

    scan_type = 'ip' if SecurityScanner()._is_ip_address(target) else 'domain'
    scan = ScanResult(
        target=target,
        scan_type=scan_type,
        status='PROCESSING',
        user_id=current_user.id if current_user.is_authenticated else None,
    )
    db.session.add(scan)
    db.session.commit()

    if not current_user.is_authenticated:
        _remember_guest_scan(scan.id)

    return jsonify({
        'public_id': scan.public_id,
        'target': target,
        'scan_type': scan_type,
        'live_url': url_for('scan_live', public_id=scan.public_id),
        'status_url': url_for('api_scan.scan_status', public_id=scan.public_id),
    }), 201


# ── Workers ─────────────────────────────────────────────────────────────────
def _run_worker(module):
    """Shared worker body: load scan by public_id, run the module, store its column.

    Errors are captured into the module's own column so one failing module never
    crashes the scan or blocks the others — the report just shows that module as
    errored.
    """
    column, runner = _WORKERS[module]
    data = _payload_from_request()
    public_id = (data.get('public_id') or '').strip()
    if not public_id:
        return jsonify({'error': 'Missing public_id'}), 400

    scan = ScanResult.query.filter_by(public_id=public_id).first()
    if not scan:
        return jsonify({'error': 'Unknown scan'}), 404
    if scan.status == 'COMPLETED':
        return jsonify({'ok': True, 'module': module, 'note': 'already complete'}), 200

    try:
        payload = runner(scan.target, scan.scan_type)
    except SSRFSecurityError:
        payload = {'error': 'Target or a redirect resolved to a blocked address.'}
    except Exception as e:  # noqa: BLE001 — never let one module take down the scan
        logger.warning("Worker %s failed for %s: %s", module, scan.target, e)
        payload = {'error': str(e)[:200]}

    # Single-column UPDATE: no read-modify-write, so parallel workers can't
    # clobber each other's columns.
    ScanResult.query.filter_by(public_id=public_id).update(
        {getattr(ScanResult, column): json.dumps(payload)}
    )
    db.session.commit()
    return jsonify({'ok': True, 'module': module}), 200


@api_scan_bp.route('/worker/ssl', methods=['POST'])
@rate_limit(max_calls=30, window_seconds=60)
def worker_ssl():
    return _run_worker('ssl')


@api_scan_bp.route('/worker/headers', methods=['POST'])
@rate_limit(max_calls=30, window_seconds=60)
def worker_headers():
    return _run_worker('headers')


@api_scan_bp.route('/worker/ports', methods=['POST'])
@rate_limit(max_calls=30, window_seconds=60)
def worker_ports():
    return _run_worker('ports')


@api_scan_bp.route('/worker/seo', methods=['POST'])
@rate_limit(max_calls=30, window_seconds=60)
def worker_seo():
    return _run_worker('seo')


@api_scan_bp.route('/worker/threat', methods=['POST'])
@rate_limit(max_calls=30, window_seconds=60)
def worker_threat():
    return _run_worker('threat')


# ── Aggregation + status polling ─────────────────────────────────────────────
def _module_state(name, payload):
    """Compact per-module state for the polling UI (avoids shipping full check
    payloads on every poll — the full detail lives in the final report)."""
    if payload is None:
        return {'state': 'pending'}
    if isinstance(payload, dict) and payload.get('error'):
        return {'state': 'error', 'message': payload['error']}
    if isinstance(payload, dict) and payload.get('skipped'):
        return {'state': 'skipped', 'message': payload['skipped']}
    state = {'state': 'done'}
    if isinstance(payload, dict):
        if 'checks' in payload:
            issues = sum(len(c.get('issues', [])) for c in payload['checks'].values()
                         if isinstance(c, dict))
            state['checks'] = len(payload['checks'])
            state['issues'] = issues
        elif 'score' in payload:            # SEO
            state['score'] = payload.get('score')
        elif 'verdict' in payload:          # threat intel
            state['verdict'] = payload.get('verdict')
    return state


def _aggregate(scan, modules):
    """Once every module has landed, merge the security checks, compute the
    overall score, and persist the full result. Guarded so only the first
    concurrent poll performs the transition."""
    merged, spa = {}, False
    for key in ('ssl', 'headers', 'ports'):
        payload = modules.get(key)
        if isinstance(payload, dict) and isinstance(payload.get('checks'), dict):
            merged.update(payload['checks'])
        if key == 'ports' and isinstance(payload, dict):
            spa = bool(payload.get('spa_detected'))

    scanner = SecurityScanner()
    score = scanner.score(merged)
    risk = scanner.risk_level(score)

    seo = modules.get('seo')
    if isinstance(seo, dict) and seo.get('skipped'):
        seo = None  # match legacy behaviour: no SEO section for IP scans
    threat = modules.get('threat') if isinstance(modules.get('threat'), dict) else None

    results = {
        'target': scan.target,
        'scan_time': scan.created_at.isoformat() if scan.created_at else None,
        'scan_type': scan.scan_type,
        'spa_detected': spa,
        'checks': merged,
        'overall_score': score,
        'risk_level': risk,
        'seo': seo,
        'threat': threat,
    }

    # Conditional UPDATE (status still PROCESSING) makes the flip idempotent:
    # only the first poll that sees all modules done writes the aggregate.
    ScanResult.query.filter_by(public_id=scan.public_id, status='PROCESSING').update({
        ScanResult.results: json.dumps(results),
        ScanResult.security_score: score,
        ScanResult.status: 'COMPLETED',
    })
    db.session.commit()
    db.session.refresh(scan)


@api_scan_bp.route('/status/<public_id>', methods=['GET'])
def scan_status(public_id):
    """Poll the current state of every module. Read-only (GET), so it is exempt
    from the rate limiter and safe to hit every couple of seconds."""
    scan = ScanResult.query.filter_by(public_id=public_id).first()
    if not scan:
        return jsonify({'error': 'Unknown scan'}), 404

    modules = {
        'ssl': _load_col(scan.ssl_result),
        'headers': _load_col(scan.headers_result),
        'ports': _load_col(scan.ports_result),
        'seo': _load_col(scan.seo_result),
        'threat': _load_col(scan.threat_result),
    }

    if scan.modules_done() and scan.status != 'COMPLETED':
        _aggregate(scan, modules)

    resp = {
        'public_id': public_id,
        'target': scan.target,
        'scan_type': scan.scan_type,
        'status': scan.status,
        'modules': {name: _module_state(name, payload) for name, payload in modules.items()},
        'overall_score': scan.security_score,
    }
    if scan.status == 'COMPLETED':
        try:
            resp['risk_level'] = json.loads(scan.results).get('risk_level')
        except (ValueError, TypeError):
            resp['risk_level'] = None
        resp['report_url'] = url_for('view_scan', scan_id=scan.id)
    return jsonify(resp)
