"""
Safer Alternatives Suggester
Uses configuration from config.py which loads .env file
"""

import json
from datetime import datetime
from typing import Dict, List, Optional
import google.generativeai as genai

# Add Configuration to path and import config
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / 'Configuration'))
from config import config


class AlternativesSuggester:
    """Suggests safer alternatives based on category and security posture"""
    
    def __init__(self, gemini_model=None):
        """
        Initialize suggester
        
        Args:
            gemini_model: Existing Gemini model instance (or creates new one with config)
        """
        if gemini_model:
            self.model = gemini_model
        else:
            genai.configure(api_key=config.GEMINI_API_KEY)
            self.model = genai.GenerativeModel(config.GEMINI_MODEL)
        
        print("✓ Alternatives Suggester initialized")
    
    def _build_alternatives_prompt(self, 
                                   product_name: str,
                                   vendor_name: str,
                                   classification: Dict,
                                   sources: Dict,
                                   current_risk_level: str = "unknown") -> str:
        """Build prompt for finding safer alternatives"""
        
        category = classification.get('primary_subcategory', 'Unknown')
        key_functions = classification.get('key_functions', [])
        deployment = classification.get('deployment_model', 'Unknown')
        
        risk_signals = []
        if sources.get('cisa_kev', {}).get('found'):
            kev_count = sources['cisa_kev'].get('total_matches', 0)
            risk_signals.append(f"Found in CISA KEV with {kev_count} exploited vulnerabilities")
        
        risk_text = "\n".join(risk_signals) if risk_signals else "No critical risk signals detected"
        
        functions_text = ", ".join(key_functions) if key_functions else "general software functionality"
        
        prompt = f"""You are a cybersecurity advisor recommending safer alternatives for enterprise software.

CURRENT PRODUCT: {product_name} by {vendor_name}
CATEGORY: {category}
KEY FUNCTIONS: {functions_text}
DEPLOYMENT: {deployment}
RISK SIGNALS: {risk_text}

Your task: Recommend 1-2 SAFER alternatives in the same category that:
- Provide similar functionality
- Have better security posture (based on public evidence)
- Are enterprise-ready and reputable
- Have good compliance/certification track record

For each alternative, provide:
1. Product name and vendor
2. Why it's safer (specific security advantages with evidence)
3. Key differences from current product
4. Any trade-offs (cost, features, complexity)

IMPORTANT RULES:
- Only recommend if you have HIGH confidence based on public security reputation
- Prefer alternatives with: SOC 2, ISO 27001, transparent security practices, good vulnerability disclosure
- Do NOT recommend if insufficient evidence exists
- Be honest about confidence level
- Cite specific security advantages (e.g., "Has SOC 2 Type II", "Zero CISA KEV entries", "Open source with security audits")

Respond ONLY with valid JSON (no markdown):
{{
  "alternatives": [
    {{
      "product_name": "Alternative Product",
      "vendor_name": "Vendor Name",
      "vendor_website": "https://example.com",
      "why_safer": "Specific security advantages with evidence",
      "security_highlights": ["advantage1", "advantage2", "advantage3"],
      "key_differences": ["difference1", "difference2"],
      "trade_offs": ["tradeoff1", "tradeoff2"],
      "confidence": 0.0-1.0,
      "evidence_basis": "Has SOC 2, ISO 27001, etc."
    }}
  ],
  "recommendation_confidence": 0.0-1.0,
  "rationale": "Overall reasoning for recommendations",
  "note": "Any important caveats or disclaimers"
}}

If you cannot confidently recommend safer alternatives, return:
{{
  "alternatives": [],
  "recommendation_confidence": 0.0,
  "rationale": "Insufficient public evidence to recommend alternatives",
  "note": "More research needed or current product may be appropriate choice"
}}
"""
        return prompt
    
    def suggest_alternatives(self,
                           product_name: str,
                           vendor_name: str, 
                           classification: Dict,
                           sources: Dict,
                           current_risk_level: str = "unknown") -> Dict:
        """
        Suggest safer alternatives with evidence-based rationale
        
        Args:
            product_name: Current product name
            vendor_name: Current vendor name
            classification: Taxonomy classification data
            sources: High-signal sources from entity resolution
            current_risk_level: Optional risk assessment of current product
            
        Returns:
            Alternatives with rationale and comparison data
        """
        print(f"\n{'='*60}")
        print(f"🔄 Finding Safer Alternatives")
        print(f"{'='*60}")
        
        prompt = self._build_alternatives_prompt(
            product_name, vendor_name, classification, sources, current_risk_level
        )
        
        try:
            print(f"  🤖 Searching for alternatives with better security posture...")
            response = self.model.generate_content(prompt)
            text = response.text.strip()
            
            if text.startswith('```'):
                text = text.split('```')[1]
                if text.startswith('json'):
                    text = text[4:]
                text = text.strip()
            
            alternatives_data = json.loads(text)
            alternatives_data['suggested_at'] = datetime.now().isoformat()
            alternatives_data['for_product'] = product_name
            
            self._validate_alternatives(alternatives_data)
            
            alt_count = len(alternatives_data.get('alternatives', []))
            confidence = alternatives_data.get('recommendation_confidence', 0)
            
            print(f"\n  ✓ Found {alt_count} alternative(s)")
            print(f"    Confidence: {confidence:.1%}")
            
            for i, alt in enumerate(alternatives_data.get('alternatives', []), 1):
                print(f"    {i}. {alt['product_name']} by {alt['vendor_name']}")
                print(f"       Confidence: {alt['confidence']:.1%}")
            
            if alt_count == 0:
                print(f"    Note: {alternatives_data.get('note', 'No alternatives found')}")
            
            return alternatives_data
            
        except json.JSONDecodeError as e:
            print(f"  ✗ JSON parse error: {e}")
            return self._fallback_alternatives(str(e))
        except Exception as e:
            print(f"  ✗ Alternatives suggestion error: {e}")
            return self._fallback_alternatives(str(e))
    
    def _validate_alternatives(self, data: Dict):
        """Validate alternatives data structure"""
        
        if 'alternatives' not in data:
            data['alternatives'] = []
        
        if 'recommendation_confidence' not in data:
            data['recommendation_confidence'] = 0.0
        
        for alt in data['alternatives']:
            required = ['product_name', 'vendor_name', 'why_safer', 'confidence']
            for field in required:
                if field not in alt:
                    raise ValueError(f"Alternative missing required field: {field}")
            
            if not 0 <= alt['confidence'] <= 1:
                alt['confidence'] = 0.5
    
    def _fallback_alternatives(self, error_msg: str) -> Dict:
        """Fallback when alternative suggestion fails"""
        return {
            'alternatives': [],
            'recommendation_confidence': 0.0,
            'rationale': f'Alternative suggestion failed: {error_msg}',
            'note': 'Unable to recommend alternatives at this time',
            'suggested_at': datetime.now().isoformat(),
            'error': error_msg
        }
    
    def compare_with_alternatives(self,
                                 current_product: Dict,
                                 alternatives_data: Dict) -> Dict:
        """
        Create detailed comparison between current product and alternatives
        
        Args:
            current_product: Full assessment data for current product
            alternatives_data: Alternatives suggestion data
            
        Returns:
            Comparison matrix with side-by-side analysis
        """
        print(f"\n{'='*60}")
        print(f"📊 Building Comparison Matrix")
        print(f"{'='*60}")
        
        alternatives = alternatives_data.get('alternatives', [])
        
        if not alternatives:
            print("  ℹ No alternatives to compare")
            return {
                'comparison_available': False,
                'note': 'No alternatives available for comparison'
            }
        
        current = {
            'product_name': current_product['resolution']['product_name'],
            'vendor_name': current_product['resolution']['vendor_name'],
            'category': current_product.get('classification', {}).get('primary_subcategory', 'Unknown'),
            'deployment': current_product.get('classification', {}).get('deployment_model', 'Unknown'),
            'evidence_quality': current_product.get('evidence_quality', {}).get('quality', 'unknown'),
            'cisa_kev_entries': current_product.get('sources', {}).get('cisa_kev', {}).get('total_matches', 0),
            'has_security_page': current_product.get('sources', {}).get('security_page', {}).get('found', False),
            'has_terms': current_product.get('sources', {}).get('terms_of_service', {}).get('found', False)
        }
        
        comparison = {
            'current_product': current,
            'alternatives': [],
            'comparison_dimensions': [
                'Security Posture',
                'Evidence Quality', 
                'Known Vulnerabilities',
                'Public Security Docs',
                'Deployment Model'
            ],
            'recommendation': None,
            'compared_at': datetime.now().isoformat()
        }
        
        for alt in alternatives:
            alt_summary = {
                'product_name': alt['product_name'],
                'vendor_name': alt['vendor_name'],
                'confidence': alt['confidence'],
                'security_highlights': alt.get('security_highlights', []),
                'key_differences': alt.get('key_differences', []),
                'trade_offs': alt.get('trade_offs', []),
                'why_safer': alt['why_safer'],
                'evidence_basis': alt.get('evidence_basis', 'Not specified')
            }
            comparison['alternatives'].append(alt_summary)
        
        comparison['recommendation'] = self._generate_comparison_recommendation(
            current, alternatives, alternatives_data
        )
        
        print(f"  ✓ Comparison matrix built with {len(alternatives)} alternative(s)")
        
        return comparison
    
    def _generate_comparison_recommendation(self,
                                          current: Dict,
                                          alternatives: List[Dict],
                                          alternatives_data: Dict) -> str:
        """Generate recommendation based on comparison"""
        
        confidence = alternatives_data.get('recommendation_confidence', 0)
        
        if confidence < 0.5:
            return "Insufficient evidence to recommend switching. Current product may be appropriate."
        
        cisa_kev = current.get('cisa_kev_entries', 0)
        
        if cisa_kev > 0:
            top_alt = alternatives[0] if alternatives else None
            if top_alt:
                return f"⚠️ Consider switching to {top_alt['product_name']} - Current product has {cisa_kev} CISA KEV entries. Alternative shows stronger security posture."
        
        if len(alternatives) > 0 and alternatives[0]['confidence'] > 0.7:
            top_alt = alternatives[0]
            return f"✓ {top_alt['product_name']} recommended - Better security track record with {top_alt.get('evidence_basis', 'strong evidence basis')}."
        
        return "Review alternatives carefully. Both current and suggested products have trade-offs."
    
    def format_alternatives_report(self,
                                  current_product: Dict,
                                  alternatives_data: Dict,
                                  include_comparison: bool = True) -> str:
        """Format alternatives into readable report"""
        
        current_name = current_product['resolution']['product_name']
        alternatives = alternatives_data.get('alternatives', [])
        confidence = alternatives_data.get('recommendation_confidence', 0)
        
        report = f"""
SAFER ALTERNATIVES ANALYSIS
{'='*60}

Current Product: {current_name}
Alternatives Found: {len(alternatives)}
Recommendation Confidence: {confidence:.1%}

Overall Rationale:
{alternatives_data.get('rationale', 'No rationale provided')}
"""
        
        if alternatives:
            report += f"\n{'='*60}\n"
            for i, alt in enumerate(alternatives, 1):
                report += f"""
ALTERNATIVE {i}: {alt['product_name']}
{'-'*60}

Vendor:           {alt['vendor_name']}
Website:          {alt.get('vendor_website', 'N/A')}
Confidence:       {alt['confidence']:.1%}

Why Safer:
{alt['why_safer']}

Security Highlights:
{self._format_list(alt.get('security_highlights', []))}

Key Differences:
{self._format_list(alt.get('key_differences', []))}

Trade-offs to Consider:
{self._format_list(alt.get('trade_offs', []))}

Evidence Basis:
{alt.get('evidence_basis', 'Not specified')}

"""
        else:
            report += f"\n\nNo alternatives recommended.\n"
            report += f"Note: {alternatives_data.get('note', 'Insufficient evidence')}\n"
        
        if include_comparison and alternatives:
            comparison = self.compare_with_alternatives(current_product, alternatives_data)
            report += f"\n{'='*60}\n"
            report += f"COMPARISON MATRIX\n"
            report += f"{'='*60}\n"
            report += f"\nRecommendation: {comparison.get('recommendation', 'N/A')}\n"
        
        return report
    
    def _format_list(self, items: List[str]) -> str:
        """Format list with bullets"""
        if not items:
            return "  • None specified"
        return "\n".join([f"  • {item}" for item in items])
    
    def get_quick_compare_view(self,
                               current_product: Dict,
                               alternatives_data: Dict) -> Dict:
        """Generate quick comparison view for UI display"""
        
        alternatives = alternatives_data.get('alternatives', [])
        
        if not alternatives:
            return {
                'available': False,
                'message': 'No alternatives available'
            }
        
        current_name = current_product['resolution']['product_name']
        current_cisa = current_product.get('sources', {}).get('cisa_kev', {}).get('total_matches', 0)
        current_quality = current_product.get('evidence_quality', {}).get('quality', 'unknown')
        
        quick_view = {
            'available': True,
            'current': {
                'name': current_name,
                'cisa_kev_count': current_cisa,
                'evidence_quality': current_quality,
                'status': '⚠️ Has concerns' if current_cisa > 0 else '✓ No critical issues'
            },
            'alternatives': [],
            'recommendation': alternatives_data.get('rationale', '')
        }
        
        for alt in alternatives[:2]:
            quick_view['alternatives'].append({
                'name': alt['product_name'],
                'vendor': alt['vendor_name'],
                'confidence': f"{alt['confidence']:.0%}",
                'top_advantage': alt.get('security_highlights', ['Better security posture'])[0],
                'main_tradeoff': alt.get('trade_offs', ['Review full details'])[0] if alt.get('trade_offs') else 'Review full details'
            })
        
        return quick_view


class CompleteAssessmentPipeline:
    """Complete pipeline: Resolution → Classification → Alternatives"""
    
    def __init__(self, enhanced_resolver, alternatives_suggester=None):
        """
        Args:
            enhanced_resolver: EnhancedEntityResolver instance
            alternatives_suggester: AlternativesSuggester instance (optional)
        """
        self.resolver = enhanced_resolver
        
        if alternatives_suggester:
            self.suggester = alternatives_suggester
        else:
            self.suggester = AlternativesSuggester(self.resolver.resolver.model)
        
        print("✓ Complete Assessment Pipeline initialized")
    
    def assess_with_alternatives(self, user_input: str, force_refresh: bool = False) -> Dict:
        """
        Complete assessment: resolve, classify, and suggest alternatives
        
        Args:
            user_input: Product name, vendor, or URL
            force_refresh: Skip cache
            
        Returns:
            Complete assessment with alternatives
        """
        assessment = self.resolver.resolve_and_classify(user_input, force_refresh)
        
        print(f"\n🎯 Generating alternatives recommendations...")
        
        alternatives = self.suggester.suggest_alternatives(
            assessment['resolution']['product_name'],
            assessment['resolution']['vendor_name'],
            assessment.get('classification', {}),
            assessment.get('sources', {})
        )
        
        assessment['alternatives'] = alternatives
        
        self._save_complete_cache(assessment)
        
        return assessment
    
    def _save_complete_cache(self, data: Dict):
        """Save complete assessment to cache"""
        cache_key = data.get('cache_key')
        if cache_key:
            # cache_file = self.resolver.resolver.cache_dir / f"{cache_key}.json"
            self.resolver.resolver.cache.set(cache_key, data)
            data['cached_at'] = datetime.now().isoformat()
            
            try:
                with open(cache_file, 'w') as f:
                    json.dump(data, f, indent=2)
                print(f"\n  ✓ Complete assessment cached")
            except Exception as e:
                print(f"  ⚠ Cache save error: {e}")