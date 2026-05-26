"""
REST API endpoints for Security Buddy
Provides programmatic access to security scanning functionality
"""
import json
import ipaddress
import socket
from datetime import datetime, timedelta
from urllib.parse import urlparse
from flask import Blueprint, request, jsonify, current_app
from flask_login import current_user, login_required
from functools import wraps
import secrets
import hashlib
from models import User, ScanResult, APIKey
from app import db
from scanner import SecurityScanner
from validators import AdvancedValidator, clean_target
def _is_safe_webhook_url(url):
    """Validate webhook URL to prevent SSRF: must be http/https and not target private IPs."""
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ('http', 'https'):
            return False
        hostname = parsed.hostname
        if not hostname:
            return False
        # Block localhost and loopback
        if hostname in ('localhost', '127.0.0.1', '::1'):
            return False
        # Resolve and check for private/reserved ranges
        try:
            addr = ipaddress.ip_address(hostname)
        except ValueError:
            try:
                addr = ipaddress.ip_address(socket.gethostbyname(hostname))
            except Exception:
                return False
        if addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_link_local:
            return False
        return True
    except Exception:
        return False

api_bp = Blueprint('api', __name__, url_prefix='/api/v1')

def require_api_key(f):
    """Decorator to require valid API key for endpoints"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')

        if not api_key:
            return jsonify({
                'error': 'API key required',
                'message': 'Please provide API key in X-API-Key header'
            }), 401
        
        # Validate API key
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        api_key_obj = APIKey.query.filter_by(key_hash=key_hash, active=True).first()
        
        if not api_key_obj:
            return jsonify({
                'error': 'Invalid API key',
                'message': 'The provided API key is invalid or inactive'
            }), 401
        
        # Check rate limits
        if api_key_obj.is_rate_limited():
            return jsonify({
                'error': 'Rate limit exceeded',
                'message': 'API rate limit exceeded. Please try again later.',
                'reset_time': api_key_obj.rate_limit_reset.isoformat() if api_key_obj.rate_limit_reset else None
            }), 429
        
        # Update usage
        api_key_obj.increment_usage()
        
        # Add user to request context
        request.api_user = api_key_obj.user
        request.api_key = api_key_obj
        
        return f(*args, **kwargs)
    return decorated_function

@api_bp.route('/scan', methods=['POST'])
@require_api_key
def api_scan():
    """
    Perform security scan via API
    
    POST /api/v1/scan
    {
        "target": "example.com",
        "advanced": false,
        "include_pdf": false
    }
    """
    try:
        data = request.get_json()
        
        if not data or 'target' not in data:
            return jsonify({
                'error': 'Missing target',
                'message': 'Please provide target domain or IP address'
            }), 400
        
        target = clean_target(data['target'])
        advanced = data.get('advanced', False)
        include_pdf = data.get('include_pdf', False)
        
        # Validate target
        validator = AdvancedValidator()
        is_valid, error_msg = validator.validate_target(target)
        
        if not is_valid:
            return jsonify({
                'error': 'Invalid target',
                'message': error_msg
            }), 400
        
        # Perform scan
        scanner = SecurityScanner()
        results = scanner.scan_target(target)
        
        # Save scan result
        scan_result = ScanResult(
            target=target,
            scan_type=results.get('scan_type', 'domain'),
            results=json.dumps(results),
            security_score=results.get('overall_score', 0),
            user_id=request.api_user.id
        )
        db.session.add(scan_result)
        db.session.commit()
        
        response_data = {
            'scan_id': scan_result.id,
            'target': target,
            'security_score': results.get('overall_score', 0),
            'risk_level': results.get('risk_level', 'unknown'),
            'scan_time': results.get('scan_time'),
            'results': results
        }
        
        return jsonify(response_data), 200
        
    except Exception as e:
        current_app.logger.error(f"API scan error: {str(e)}")
        return jsonify({
            'error': 'Scan failed',
            'message': 'An error occurred during scanning'
        }), 500

@api_bp.route('/scan/<int:scan_id>', methods=['GET'])
@require_api_key
def api_get_scan(scan_id):
    """Get scan results by ID"""
    try:
        scan_result = ScanResult.query.get_or_404(scan_id)
        
        # Check ownership
        if scan_result.user_id != request.api_user.id:
            return jsonify({
                'error': 'Access denied',
                'message': 'You do not have access to this scan result'
            }), 403
        
        # Parse results
        if isinstance(scan_result.results, str):
            results = json.loads(scan_result.results)
        else:
            results = scan_result.results
        
        return jsonify({
            'scan_id': scan_result.id,
            'target': scan_result.target,
            'security_score': scan_result.security_score,
            'scan_type': scan_result.scan_type,
            'created_at': scan_result.created_at.isoformat(),
            'results': results
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"API get scan error: {str(e)}")
        return jsonify({
            'error': 'Failed to retrieve scan',
            'message': 'An error occurred while retrieving scan results'
        }), 500

@api_bp.route('/scans', methods=['GET'])
@require_api_key
def api_list_scans():
    """List user's scan history with pagination"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 20, type=int), 100)
        
        scans = ScanResult.query.filter_by(user_id=request.api_user.id)\
                               .order_by(ScanResult.created_at.desc())\
                               .paginate(page=page, per_page=per_page, error_out=False)
        
        return jsonify({
            'scans': [{
                'scan_id': scan.id,
                'target': scan.target,
                'security_score': scan.security_score,
                'scan_type': scan.scan_type,
                'created_at': scan.created_at.isoformat()
            } for scan in scans.items],
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': scans.total,
                'pages': scans.pages,
                'has_next': scans.has_next,
                'has_prev': scans.has_prev
            }
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"API list scans error: {str(e)}")
        return jsonify({
            'error': 'Failed to retrieve scans',
            'message': 'An error occurred while retrieving scan history'
        }), 500

@api_bp.route('/webhook', methods=['POST'])
@require_api_key
def api_webhook():
    """Webhook endpoint for CI/CD integration"""
    try:
        data = request.get_json()
        
        if not data or 'targets' not in data:
            return jsonify({
                'error': 'Missing targets',
                'message': 'Please provide array of targets to scan'
            }), 400
        
        targets = data['targets']
        webhook_url = data.get('webhook_url')
        fail_threshold = data.get('fail_threshold', 60)
        
        results = []
        failed_targets = []
        
        scanner = SecurityScanner()
        validator = AdvancedValidator()
        
        for target in targets:
            try:
                clean_target_name = clean_target(target)
                
                # Validate target
                is_valid, error_msg = validator.validate_target(clean_target_name)
                if not is_valid:
                    results.append({
                        'target': target,
                        'error': error_msg,
                        'success': False
                    })
                    continue
                
                # Perform scan
                scan_results = scanner.scan_target(clean_target_name)
                score = scan_results.get('overall_score', 0)
                
                # Save to database
                scan_result = ScanResult(
                    target=clean_target_name,
                    scan_type=scan_results.get('scan_type', 'domain'),
                    results=json.dumps(scan_results),
                    security_score=score,
                    user_id=request.api_user.id
                )
                db.session.add(scan_result)
                
                result_data = {
                    'target': target,
                    'scan_id': None,  # Will be set after commit
                    'security_score': score,
                    'risk_level': scan_results.get('risk_level'),
                    'passed': score >= fail_threshold,
                    'success': True
                }
                
                if score < fail_threshold:
                    failed_targets.append(target)
                
                results.append(result_data)
                
            except Exception as e:
                results.append({
                    'target': target,
                    'error': str(e),
                    'success': False
                })
        
        db.session.commit()
        
        # Update scan IDs
        for i, result in enumerate(results):
            if result.get('success') and 'scan_id' in result:
                # Get the scan ID from the database
                latest_scan = ScanResult.query.filter_by(
                    user_id=request.api_user.id,
                    target=clean_target(result['target'])
                ).order_by(ScanResult.created_at.desc()).first()
                if latest_scan:
                    result['scan_id'] = latest_scan.id
        
        response_data = {
            'webhook_id': secrets.token_urlsafe(16),
            'timestamp': datetime.utcnow().isoformat(),
            'total_scans': len(targets),
            'successful_scans': len([r for r in results if r.get('success')]),
            'failed_scans': len([r for r in results if not r.get('success')]),
            'security_failures': len(failed_targets),
            'overall_passed': len(failed_targets) == 0,
            'results': results
        }
        
        # Send to webhook URL if provided
        if webhook_url:
            if not _is_safe_webhook_url(webhook_url):
                return jsonify({
                    'error': 'Invalid webhook_url',
                    'message': 'webhook_url must be a public HTTP/HTTPS URL'
                }), 400
            try:
                import requests as req_lib
                req_lib.post(webhook_url, json=response_data, timeout=10)
            except Exception as webhook_err:
                current_app.logger.warning(f"Webhook delivery failed to {webhook_url}: {webhook_err}")
        
        return jsonify(response_data), 200
        
    except Exception as e:
        current_app.logger.error(f"API webhook error: {str(e)}")
        return jsonify({
            'error': 'Webhook processing failed',
            'message': 'An error occurred while processing the webhook'
        }), 500

@api_bp.route('/status', methods=['GET'])
@require_api_key
def api_status():
    """Get API status and user information"""
    try:
        user = request.api_user
        api_key = request.api_key
        
        return jsonify({
            'status': 'active',
            'timestamp': datetime.utcnow().isoformat(),
            'user': {
                'id': user.id,
                'username': user.username,
                'created_at': user.created_at.isoformat()
            },
            'api_key': {
                'name': api_key.name,
                'usage_count': api_key.usage_count,
                'rate_limit': api_key.rate_limit,
                'created_at': api_key.created_at.isoformat()
            },
            'features': {
                'basic_scanning': True,
                'webhook_integration': True
            }
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"API status error: {str(e)}")
        return jsonify({
            'error': 'Status check failed',
            'message': 'An error occurred while checking API status'
        }), 500

@api_bp.errorhandler(404)
def api_not_found(error):
    return jsonify({
        'error': 'Endpoint not found',
        'message': 'The requested API endpoint does not exist'
    }), 404

@api_bp.errorhandler(405)
def api_method_not_allowed(error):
    return jsonify({
        'error': 'Method not allowed',
        'message': 'The HTTP method is not allowed for this endpoint'
    }), 405

@api_bp.errorhandler(500)
def api_internal_error(error):
    return jsonify({
        'error': 'Internal server error',
        'message': 'An unexpected error occurred'
    }), 500