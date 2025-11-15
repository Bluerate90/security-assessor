#!/usr/bin/env python3
"""
Flask Web Server - Serves index.html from security_assessor/index.html
Place in: security_assessor/web_server.py
"""

import sys
import json
import traceback
from pathlib import Path
from datetime import datetime

# Setup paths
sys.path.insert(0, str(Path(__file__).parent / 'Configuration'))
sys.path.insert(0, str(Path(__file__).parent / 'Python-Modules-Backend'))

from config import config, Config
from flask import Flask, send_from_directory, jsonify, request
from flask_cors import CORS

# Import assessment modules
try:
    from entity_resolver import EntityResolver
    from taxonomy_classifier import EnhancedEntityResolver, TaxonomyClassifier
    from alternative_suggester import AlternativesSuggester, CompleteAssessmentPipeline
    print("✓ All modules imported successfully")
except ImportError as e:
    print(f"❌ Error importing modules: {e}")
    traceback.print_exc()
    sys.exit(1)

# Create Flask app
app = Flask(__name__)
CORS(app)

# Flask configuration
app.config['SECRET_KEY'] = config.SECRET_KEY
app.config['DEBUG'] = config.DEBUG
app.config['ENV'] = config.FLASK_ENV

# Setup directories
config.CACHE_DIR.mkdir(parents=True, exist_ok=True)
Path('./logs').mkdir(exist_ok=True)

# Path to HTML file - CHANGED TO ROOT: security_assessor/index.html
HTML_FILE_PATH = Path(__file__).parent / 'index.html'
STATIC_DIR = HTML_FILE_PATH.parent

print("\n🔧 Initializing Security Assessor Pipeline...")

try:
    entity_resolver = EntityResolver(cache_dir=config.CACHE_DIR)
    enhanced_resolver = EnhancedEntityResolver(entity_resolver)
    pipeline = CompleteAssessmentPipeline(enhanced_resolver)
    suggester = AlternativesSuggester()
    classifier = TaxonomyClassifier()
    print("✓ Pipeline initialized successfully\n")
except Exception as e:
    print(f"❌ Pipeline initialization failed: {e}")
    traceback.print_exc()
    sys.exit(1)

Config.display()


# ============================================================================
# API ROUTES
# ============================================================================

@app.route('/api/assess', methods=['POST'])
def assess():
    """Assess a software product"""
    try:
        data = request.json or {}
        target = data.get('target', '').strip()
        force_refresh = data.get('force_refresh', False)
        
        if not target:
            return jsonify({
                'error': 'Target required',
                'message': 'Please provide a product name, vendor, or URL'
            }), 400
        
        print(f"\n📋 API Request: Assess '{target}'")
        
        result = pipeline.assess_with_alternatives(target, force_refresh)
        result['api_metadata'] = {
            'assessed_via': 'api',
            'timestamp': datetime.now().isoformat(),
            'force_refresh': force_refresh
        }
        
        print(f"✓ Assessment complete")
        return jsonify(result)
        
    except Exception as e:
        print(f"✗ Assessment error: {e}")
        traceback.print_exc()
        return jsonify({
            'error': 'Assessment failed',
            'message': str(e),
            'type': type(e).__name__
        }), 500


@app.route('/api/compare', methods=['POST'])
def compare():
    """Compare two software products"""
    try:
        data = request.json or {}
        target1 = data.get('target1', '').strip()
        target2 = data.get('target2', '').strip()
        
        if not target1 or not target2:
            return jsonify({
                'error': 'Both targets required',
                'message': 'Please provide two products to compare'
            }), 400
        
        print(f"\n⚖️  API Request: Compare '{target1}' vs '{target2}'")
        
        result1 = pipeline.assess_with_alternatives(target1)
        result2 = pipeline.assess_with_alternatives(target2)
        
        comparison = {
            'product1': result1,
            'product2': result2,
            'comparison_metadata': {
                'compared_at': datetime.now().isoformat(),
                'target1': target1,
                'target2': target2
            }
        }
        
        print(f"✓ Comparison complete")
        return jsonify(comparison)
        
    except Exception as e:
        print(f"✗ Comparison error: {e}")
        traceback.print_exc()
        return jsonify({
            'error': 'Comparison failed',
            'message': str(e),
            'type': type(e).__name__
        }), 500


@app.route('/api/cache', methods=['GET'])
def list_cache():
    """List all cached assessments"""
    try:
        cache_dir = config.CACHE_DIR
        items = []
        
        if not cache_dir.exists():
            return jsonify({'items': [], 'count': 0})
        
        cache_files = sorted(cache_dir.glob('*.json'), 
                           key=lambda f: f.stat().st_mtime, 
                           reverse=True)
        
        for cache_file in cache_files:
            try:
                with open(cache_file, 'r') as f:
                    data = json.load(f)
                
                cached_at = data.get('cached_at')
                age_str = 'unknown'
                if cached_at:
                    try:
                        dt = datetime.fromisoformat(cached_at)
                        age = datetime.now() - dt
                        if age.days > 0:
                            age_str = f"{age.days}d ago"
                        else:
                            hours = age.seconds // 3600
                            age_str = f"{hours}h ago" if hours > 0 else "< 1h ago"
                    except:
                        pass
                
                items.append({
                    'cache_key': cache_file.stem,
                    'product_name': data.get('resolution', {}).get('product_name', 'Unknown'),
                    'vendor_name': data.get('resolution', {}).get('vendor_name', 'Unknown'),
                    'category': data.get('classification', {}).get('primary_subcategory', 'Unknown'),
                    'cached_at': cached_at,
                    'age': age_str,
                    'evidence_quality': data.get('evidence_quality', {}).get('quality', 'unknown')
                })
            except Exception as e:
                print(f"⚠️  Error reading {cache_file.name}: {e}")
                continue
        
        return jsonify({'items': items, 'count': len(items)})
        
    except Exception as e:
        print(f"✗ Cache list error: {e}")
        return jsonify({'error': 'Failed to list cache', 'message': str(e)}), 500


@app.route('/api/cache/<cache_key>', methods=['GET'])
def get_cache_item(cache_key):
    """Get specific cached assessment"""
    try:
        cache_file = config.CACHE_DIR / f"{cache_key}.json"
        
        if not cache_file.exists():
            return jsonify({'error': 'Cache item not found'}), 404
        
        with open(cache_file, 'r') as f:
            data = json.load(f)
        
        return jsonify(data)
        
    except Exception as e:
        print(f"✗ Cache get error: {e}")
        return jsonify({'error': 'Failed to get cache item', 'message': str(e)}), 500


@app.route('/api/cache', methods=['DELETE'])
def clear_cache():
    """Clear all cached assessments"""
    try:
        cache_dir = config.CACHE_DIR
        
        if not cache_dir.exists():
            return jsonify({'deleted': 0, 'message': 'Cache directory does not exist'})
        
        cache_files = list(cache_dir.glob('*.json'))
        deleted_count = 0
        
        for cache_file in cache_files:
            try:
                cache_file.unlink()
                deleted_count += 1
            except Exception as e:
                print(f"⚠️  Error deleting {cache_file.name}: {e}")
        
        return jsonify({
            'deleted': deleted_count,
            'message': f'Cleared {deleted_count} cached assessments'
        })
        
    except Exception as e:
        print(f"✗ Cache clear error: {e}")
        return jsonify({'error': 'Failed to clear cache', 'message': str(e)}), 500


@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    try:
        cache_dir = config.CACHE_DIR
        cache_exists = cache_dir.exists()
        cache_count = len(list(cache_dir.glob('*.json'))) if cache_exists else 0
        
        return jsonify({
            'status': 'healthy',
            'environment': config.FLASK_ENV,
            'api_key_configured': bool(config.GEMINI_API_KEY),
            'cache': {
                'exists': cache_exists,
                'item_count': cache_count
            },
            'modules': {
                'entity_resolver': 'loaded',
                'taxonomy_classifier': 'loaded',
                'alternative_suggester': 'loaded'
            },
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'status': 'unhealthy', 'error': str(e)}), 500


@app.route('/api/config', methods=['GET'])
def get_config():
    """Get current configuration (non-sensitive)"""
    return jsonify({
        'environment': config.FLASK_ENV,
        'debug': config.DEBUG,
        'port': config.PORT,
        'cache_dir': str(config.CACHE_DIR),
        'cache_ttl_days': config.CACHE_TTL_DAYS,
        'gemini_model': config.GEMINI_MODEL,
        'log_level': config.LOG_LEVEL
    })


# ============================================================================
# SERVE HTML AND STATIC FILES
# ============================================================================

@app.route('/')
def serve_index():
    """Serve the main HTML file"""
    if HTML_FILE_PATH.exists():
        return send_from_directory(STATIC_DIR, 'index.html')
    
    return jsonify({
        'error': 'HTML file not found',
        'expected_path': str(HTML_FILE_PATH),
        'check': 'Ensure index.html exists in security_assessor/ folder'
    }), 404


@app.route('/<path:path>')
def serve_static(path):
    """Serve static files"""
    
    if path.startswith('api/'):
        return jsonify({'error': 'API endpoint not found'}), 404
    
    file_path = STATIC_DIR / path
    if file_path.exists() and file_path.is_file():
        return send_from_directory(STATIC_DIR, path)
    
    if HTML_FILE_PATH.exists():
        return send_from_directory(STATIC_DIR, 'index.html')
    
    return jsonify({'error': 'File not found'}), 404


# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def not_found(e):
    """Handle 404 errors"""
    if request.path.startswith('/api/'):
        return jsonify({
            'error': 'API endpoint not found',
            'available_endpoints': [
                'POST /api/assess',
                'POST /api/compare',
                'GET /api/cache',
                'GET /api/cache/<cache_key>',
                'DELETE /api/cache',
                'GET /api/health',
                'GET /api/config'
            ]
        }), 404
    
    if HTML_FILE_PATH.exists():
        return send_from_directory(STATIC_DIR, 'index.html')
    
    return jsonify({'error': 'Not found'}), 404


@app.errorhandler(500)
def internal_error(e):
    """Handle 500 errors"""
    return jsonify({
        'error': 'Internal server error',
        'message': str(e)
    }), 500


@app.after_request
def after_request(response):
    """Add CORS headers"""
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response


# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    print("\n" + "="*70)
    print("🔒 SECURITY ASSESSOR - WEB SERVER")
    print("="*70)
    
    if not HTML_FILE_PATH.exists():
        print(f"\n⚠️  HTML file not found!")
        print(f"   Expected: {HTML_FILE_PATH}")
        print(f"   Please ensure index.html is in security_assessor/ folder")
        sys.exit(1)
    
    port = config.PORT
    debug = config.DEBUG
    
    print(f"\n{'='*70}")
    print(f"🚀 Starting Web Server")
    print(f"{'='*70}")
    print(f"📍 Open: http://localhost:{port}")
    print(f"🔧 Debug Mode: {debug}")
    print(f"📦 Environment: {config.FLASK_ENV}")
    print(f"📂 Cache Dir: {config.CACHE_DIR}")
    print(f"📄 HTML File: {HTML_FILE_PATH}")
    
    print(f"\nAPI Endpoints:")
    print(f"  POST   /api/assess        - Assess a product")
    print(f"  POST   /api/compare       - Compare two products")
    print(f"  GET    /api/cache         - List cached assessments")
    print(f"  GET    /api/cache/<key>   - Get cached assessment")
    print(f"  DELETE /api/cache         - Clear cache")
    print(f"  GET    /api/health        - Health check")
    print(f"  GET    /api/config        - Get configuration")
    
    print(f"\nWeb UI:")
    print(f"  GET    /                  - HTML interface at http://localhost:{port}")
    
    print(f"\nPress CTRL+C to stop")
    print(f"{'='*70}\n")
    
    app.run(debug=debug, host='0.0.0.0', port=port, threaded=True)