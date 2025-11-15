"""
Entity Resolution Module for Security Assessor
Uses configuration from config.py which loads .env file
"""

import json
import hashlib
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
from typing import Dict, List, Optional, Tuple

import requests
import google.generativeai as genai

# Add Configuration to path and import config
import sys
sys.path.insert(0, str(Path(__file__).parent.parent / 'Configuration'))
from config import config


class EntityResolver:
    """Resolves and enriches entity information with persistent caching"""
    
    def __init__(self, cache_dir: Path = None):
        """
        Initialize the resolver with cache and API configuration
        
        Args:
            cache_dir: Directory for persistent cache storage (uses config if None)
        """
        self.cache_dir = cache_dir or config.CACHE_DIR
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize Gemini with config API key
        if not config.GEMINI_API_KEY:
            raise ValueError("Gemini API key required. Set GEMINI_API_KEY in Configuration/.env")
        
        genai.configure(api_key=config.GEMINI_API_KEY)
        self.model = genai.GenerativeModel(config.GEMINI_MODEL)
        
        print(f"✓ Entity Resolver initialized with cache at {self.cache_dir}")
    
    def _get_cache_key(self, input_text: str) -> str:
        """Generate consistent cache key from input"""
        return hashlib.sha256(input_text.lower().strip().encode()).hexdigest()[:16]
    
    def _load_from_cache(self, cache_key: str) -> Optional[Dict]:
        """Load cached entity data if it exists and is recent"""
        cache_file = self.cache_dir / f"{cache_key}.json"
        
        if not cache_file.exists():
            return None
        
        try:
            with open(cache_file, 'r') as f:
                data = json.load(f)
            
            cached_time = datetime.fromisoformat(data.get('cached_at', '2000-01-01'))
            age_days = (datetime.now() - cached_time).days
            
            if age_days > config.CACHE_TTL_DAYS:
                print(f"  ⚠ Cache stale ({age_days} days old), will refresh")
                return None
            
            print(f"  ✓ Using cached data ({age_days} days old)")
            return data
            
        except Exception as e:
            print(f"  ⚠ Cache read error: {e}")
            return None
    
    def _save_to_cache(self, cache_key: str, data: Dict):
        """Save entity data to persistent cache"""
        cache_file = self.cache_dir / f"{cache_key}.json"
        data['cached_at'] = datetime.now().isoformat()
        
        try:
            with open(cache_file, 'w') as f:
                json.dump(data, f, indent=2)
            print(f"  ✓ Cached to {cache_file.name}")
        except Exception as e:
            print(f"  ⚠ Cache write error: {e}")
    
    def _extract_domain_from_input(self, user_input: str) -> Optional[str]:
        """Extract domain from URL or return None"""
        user_input = user_input.strip()
        
        if '://' in user_input or user_input.startswith('www.'):
            if not user_input.startswith('http'):
                user_input = 'https://' + user_input
            
            parsed = urlparse(user_input)
            domain = parsed.netloc or parsed.path
            domain = domain.replace('www.', '')
            return domain if domain else None
        
        return None
    
    def _resolve_entity_with_gemini(self, user_input: str, domain: Optional[str]) -> Dict:
        """Use Gemini to resolve entity identity from minimal input"""
        
        prompt = f"""Given this input: "{user_input}"
{f'Extracted domain: {domain}' if domain else ''}

Your task: Identify the SOFTWARE PRODUCT and VENDOR company.

Respond ONLY with valid JSON (no markdown, no extra text):
{{
  "product_name": "Official product name",
  "vendor_name": "Company that makes it",
  "vendor_website": "Primary vendor website URL",
  "confidence": 0.0-1.0,
  "reasoning": "Brief explanation of identification",
  "alternative_names": ["alias1", "alias2"]
}}

If you cannot identify it confidently, set confidence < 0.5 and explain why.
"""
        
        try:
            response = self.model.generate_content(prompt)
            text = response.text.strip()
            
            if text.startswith('```'):
                text = text.split('```')[1]
                if text.startswith('json'):
                    text = text[4:]
                text = text.strip()
            
            entity_data = json.loads(text)
            return entity_data
            
        except Exception as e:
            print(f"  ✗ Gemini resolution failed: {e}")
            return {
                "product_name": "Unknown",
                "vendor_name": "Unknown",
                "vendor_website": domain or "Unknown",
                "confidence": 0.0,
                "reasoning": f"Resolution failed: {str(e)}",
                "alternative_names": []
            }
    
    def _fetch_url_safely(self, url: str, timeout: int = None) -> Tuple[Optional[str], str]:
        """Fetch URL content with error handling"""
        timeout = timeout or config.REQUEST_TIMEOUT
        
        try:
            headers = {
                'User-Agent': config.USER_AGENT,
                'Accept': 'text/html,application/json'
            }
            
            response = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
            response.raise_for_status()
            
            parsed = urlparse(url)
            source_type = "vendor-stated"
            
            if any(ind in parsed.netloc for ind in ['cve.mitre.org', 'nvd.nist.gov', 'cisa.gov', 
                                                      'cert.org', 'kb.cert.org', 'securityscorecard']):
                source_type = "independent"
            
            return response.text, source_type
            
        except requests.exceptions.Timeout:
            print(f"    ⏱ Timeout fetching {url}")
            return None, "error"
        except requests.exceptions.RequestException as e:
            print(f"    ✗ Error fetching {url}: {e}")
            return None, "error"
    
    def _find_high_signal_sources(self, vendor_website: str, product_name: str, vendor_name: str) -> Dict[str, Dict]:
        """Discover and fetch high-signal security sources"""
        sources = {}
        
        if not vendor_website or vendor_website == "Unknown":
            return sources
        
        base_domain = vendor_website.replace('https://', '').replace('http://', '').split('/')[0]
        
        patterns = {
            'security_page': [
                f'https://{base_domain}/security',
                f'https://{base_domain}/trust',
                f'https://{base_domain}/compliance',
                f'https://{base_domain}/trust-center'
            ],
            'terms_of_service': [
                f'https://{base_domain}/terms',
                f'https://{base_domain}/tos',
                f'https://{base_domain}/legal/terms'
            ],
            'privacy_policy': [
                f'https://{base_domain}/privacy',
                f'https://{base_domain}/legal/privacy'
            ],
            'psirt_page': [
                f'https://{base_domain}/psirt',
                f'https://{base_domain}/security/advisories'
            ]
        }
        
        print(f"\n  🔍 Searching for high-signal sources...")
        
        for source_type, urls in patterns.items():
            sources[source_type] = {'found': False, 'url': None, 'content': None, 'source_label': None}
            
            for url in urls:
                print(f"    Trying {source_type}: {url}")
                content, source_label = self._fetch_url_safely(url)
                
                if content and len(content) > 500 and '404' not in content[:1000].lower():
                    sources[source_type] = {
                        'found': True,
                        'url': url,
                        'content': content[:5000],
                        'source_label': source_label,
                        'fetched_at': datetime.now().isoformat()
                    }
                    print(f"      ✓ Found {source_type}")
                    break
        
        print(f"    Checking CISA KEV catalog...")
        sources['cisa_kev'] = self._check_cisa_kev(vendor_name, product_name)
        
        return sources
    
    def _check_cisa_kev(self, vendor_name: str, product_name: str) -> Dict:
        """Check CISA Known Exploited Vulnerabilities catalog"""
        kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        
        content, _ = self._fetch_url_safely(kev_url, timeout=config.CISA_KEV_TIMEOUT)
        
        if not content:
            return {'found': False, 'source_label': 'independent'}
        
        try:
            kev_data = json.loads(content)
            vulnerabilities = kev_data.get('vulnerabilities', [])
            
            matches = []
            for vuln in vulnerabilities:
                vendor_match = vendor_name.lower() in vuln.get('vendorProject', '').lower()
                product_match = product_name.lower() in vuln.get('product', '').lower()
                
                if vendor_match or product_match:
                    matches.append({
                        'cve_id': vuln.get('cveID'),
                        'vulnerability_name': vuln.get('vulnerabilityName'),
                        'date_added': vuln.get('dateAdded'),
                        'required_action': vuln.get('requiredAction')
                    })
            
            if matches:
                print(f"      ⚠ Found {len(matches)} CISA KEV entries")
                return {
                    'found': True,
                    'url': kev_url,
                    'matches': matches[:5],
                    'total_matches': len(matches),
                    'source_label': 'independent'
                }
            else:
                print(f"      ✓ No CISA KEV entries (good sign)")
                return {'found': False, 'source_label': 'independent', 'note': 'No known exploited vulnerabilities'}
                
        except Exception as e:
            print(f"      ✗ CISA KEV parse error: {e}")
            return {'found': False, 'source_label': 'independent', 'error': str(e)}
    
    def resolve(self, user_input: str, force_refresh: bool = False) -> Dict:
        """Main resolution method"""
        print(f"\n{'='*60}")
        print(f"🔎 Resolving: {user_input}")
        print(f"{'='*60}")
        
        cache_key = self._get_cache_key(user_input)
        
        if not force_refresh:
            cached = self._load_from_cache(cache_key)
            if cached:
                return cached
        
        domain = self._extract_domain_from_input(user_input)
        
        print(f"\n📋 Step 1: Identifying product and vendor...")
        entity = self._resolve_entity_with_gemini(user_input, domain)
        
        confidence = entity.get('confidence', 0)
        print(f"  Product: {entity.get('product_name')}")
        print(f"  Vendor: {entity.get('vendor_name')}")
        print(f"  Confidence: {confidence:.1%}")
        
        if confidence >= 0.5:
            print(f"\n📡 Step 2: Fetching high-signal sources...")
            sources = self._find_high_signal_sources(
                entity.get('vendor_website', ''),
                entity.get('product_name', ''),
                entity.get('vendor_name', '')
            )
        else:
            print(f"\n⚠ Low confidence resolution - skipping source fetch")
            sources = {}
        
        result = {
            'input': user_input,
            'resolution': entity,
            'sources': sources,
            'evidence_quality': self._assess_evidence_quality(sources),
            'resolved_at': datetime.now().isoformat(),
            'cache_key': cache_key
        }
        
        self._save_to_cache(cache_key, result)
        
        print(f"\n{'='*60}")
        print(f"✓ Resolution complete")
        print(f"{'='*60}\n")
        
        return result
    
    def _assess_evidence_quality(self, sources: Dict) -> Dict:
        """Assess quality and completeness of gathered evidence"""
        
        found_count = sum(1 for s in sources.values() if s.get('found', False))
        total_sources = len(sources)
        
        independent_count = sum(1 for s in sources.values() 
                               if s.get('found') and s.get('source_label') == 'independent')
        
        vendor_count = sum(1 for s in sources.values() 
                          if s.get('found') and s.get('source_label') == 'vendor-stated')
        
        quality = "insufficient"
        if found_count >= 3 and independent_count >= 1:
            quality = "good"
        elif found_count >= 2:
            quality = "moderate"
        elif found_count == 1:
            quality = "limited"
        
        return {
            'quality': quality,
            'sources_found': found_count,
            'sources_attempted': total_sources,
            'independent_sources': independent_count,
            'vendor_sources': vendor_count,
            'note': 'Good' if quality == 'good' else 'Insufficient public evidence' if quality == 'insufficient' else 'Limited evidence'
        }