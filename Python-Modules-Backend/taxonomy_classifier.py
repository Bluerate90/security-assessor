"""
Software Taxonomy Classifier
Uses CacheManager through entity_resolver
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
import google.generativeai as genai

# Add Configuration to path and import config
import sys
sys.path.insert(0, str(Path(__file__).parent.parent / 'Configuration'))
from config import config


class TaxonomyClassifier:
    """Classifies software into security-relevant categories"""
    
    TAXONOMY_CATEGORIES = {
        "Communication & Collaboration": [
            "Team Chat/Messaging",
            "Video Conferencing", 
            "Email Service",
            "Project Management"
        ],
        "Data & Storage": [
            "File Sharing/Storage",
            "Database Service",
            "Backup/Archive",
            "Content Management"
        ],
        "Development & DevOps": [
            "Code Repository",
            "CI/CD Pipeline",
            "Container/Orchestration",
            "API Management",
            "Development Tool"
        ],
        "AI & Machine Learning": [
            "GenAI Tool/Assistant",
            "ML Platform",
            "AI API Service"
        ],
        "Business Applications": [
            "CRM System",
            "ERP System",
            "HR/Payroll",
            "Marketing Automation",
            "Analytics/BI"
        ],
        "Security & Infrastructure": [
            "Endpoint Agent/EDR",
            "Identity/SSO",
            "Network Security",
            "Cloud Infrastructure",
            "Monitoring/Observability"
        ],
        "Productivity": [
            "Document Editor",
            "Calendar/Scheduling",
            "Note-taking",
            "Form/Survey"
        ]
    }
    
    def __init__(self, gemini_model=None):
        """
        Initialize classifier
        
        Args:
            gemini_model: Existing Gemini model instance (or creates new one with config)
        """
        if gemini_model:
            self.model = gemini_model
        else:
            genai.configure(api_key=config.GEMINI_API_KEY)
            self.model = genai.GenerativeModel(config.GEMINI_MODEL)
        
        print("✓ Taxonomy Classifier initialized")
    
    def _build_taxonomy_prompt(self, entity_data: Dict, sources: Dict) -> str:
        """Build structured prompt for classification"""
        
        product_name = entity_data.get('product_name', 'Unknown')
        vendor_name = entity_data.get('vendor_name', 'Unknown')
        
        evidence_snippets = []
        
        for source_type, source_data in sources.items():
            if source_data.get('found'):
                label = source_data.get('source_label', 'unknown')
                
                if source_type == 'cisa_kev' and source_data.get('matches'):
                    evidence_snippets.append(
                        f"[INDEPENDENT - CISA KEV] Product found in Known Exploited Vulnerabilities catalog"
                    )
                else:
                    content = source_data.get('content', '')[:500]
                    if content:
                        evidence_snippets.append(
                            f"[{label.upper()} - {source_type}] {content}..."
                        )
        
        evidence_text = "\n".join(evidence_snippets) if evidence_snippets else "No source evidence available"
        
        taxonomy_text = "\n".join([
            f"  {category}:\n" + "\n".join([f"    - {subcat}" for subcat in subcats])
            for category, subcats in self.TAXONOMY_CATEGORIES.items()
        ])
        
        prompt = f"""You are a cybersecurity expert classifying software for risk assessment.

PRODUCT: {product_name}
VENDOR: {vendor_name}

EVIDENCE FROM SOURCES:
{evidence_text}

AVAILABLE TAXONOMY CATEGORIES:
{taxonomy_text}

Your task:
1. Classify this software into ONE primary category and subcategory
2. Identify up to 2 secondary categories if product has multiple functions
3. Provide confidence score (0.0-1.0) based on evidence quality
4. Cite which sources informed your classification
5. Note if classification is based on vendor claims vs independent evidence

Respond ONLY with valid JSON (no markdown, no extra text):
{{
  "primary_category": "Category",
  "primary_subcategory": "Subcategory",
  "secondary_categories": [
    {{"category": "Category", "subcategory": "Subcategory"}}
  ],
  "confidence": 0.0-1.0,
  "reasoning": "Clear explanation citing sources",
  "evidence_basis": "vendor-stated | mixed | independent | insufficient",
  "source_citations": ["source_type that informed classification"],
  "key_functions": ["function1", "function2", "function3"],
  "deployment_model": "SaaS | On-premise | Hybrid | Client-side | API",
  "data_access_level": "high | medium | low | none"
}}

CRITICAL: If evidence is insufficient or contradictory, set confidence < 0.5 and note "Insufficient public evidence" in reasoning.
"""
        return prompt
    
    def classify(self, entity_data: Dict, sources: Dict) -> Dict:
        """
        Classify software into taxonomy using entity data and sources
        
        Args:
            entity_data: Resolved entity information from EntityResolver
            sources: High-signal sources from EntityResolver
            
        Returns:
            Classification result with confidence and citations
        """
        print(f"\n{'='*60}")
        print(f"🏷️  Classifying Software Taxonomy")
        print(f"{'='*60}")
        
        product_name = entity_data.get('product_name', 'Unknown')
        confidence = entity_data.get('confidence', 0)
        
        if confidence < 0.5:
            return {
                'primary_category': 'Unknown',
                'primary_subcategory': 'Unknown',
                'secondary_categories': [],
                'confidence': 0.0,
                'reasoning': 'Cannot classify - entity resolution confidence too low',
                'evidence_basis': 'insufficient',
                'source_citations': [],
                'key_functions': [],
                'deployment_model': 'Unknown',
                'data_access_level': 'unknown',
                'classified_at': datetime.now().isoformat()
            }
        
        prompt = self._build_taxonomy_prompt(entity_data, sources)
        
        try:
            print(f"  🤖 Analyzing {product_name} with Gemini...")
            response = self.model.generate_content(prompt)
            text = response.text.strip()
            
            if text.startswith('```'):
                text = text.split('```')[1]
                if text.startswith('json'):
                    text = text[4:]
                text = text.strip()
            
            classification = json.loads(text)
            classification['classified_at'] = datetime.now().isoformat()
            
            self._validate_classification(classification)
            
            print(f"\n  ✓ Classification complete:")
            print(f"    Primary: {classification['primary_category']} → {classification['primary_subcategory']}")
            print(f"    Confidence: {classification['confidence']:.1%}")
            print(f"    Evidence Basis: {classification['evidence_basis']}")
            print(f"    Deployment: {classification['deployment_model']}")
            print(f"    Data Access: {classification['data_access_level']}")
            
            if classification.get('secondary_categories'):
                print(f"    Secondary: {len(classification['secondary_categories'])} additional categories")
            
            return classification
            
        except json.JSONDecodeError as e:
            print(f"  ✗ JSON parse error: {e}")
            return self._fallback_classification(entity_data, str(e))
        except Exception as e:
            print(f"  ✗ Classification error: {e}")
            return self._fallback_classification(entity_data, str(e))
    
    def _validate_classification(self, classification: Dict):
        """Validate classification structure and values"""
        
        required = ['primary_category', 'primary_subcategory', 'confidence', 
                   'reasoning', 'evidence_basis']
        
        for field in required:
            if field not in classification:
                raise ValueError(f"Missing required field: {field}")
        
        confidence = classification['confidence']
        if not 0 <= confidence <= 1:
            raise ValueError(f"Confidence must be 0-1, got {confidence}")
        
        valid_basis = ['vendor-stated', 'mixed', 'independent', 'insufficient']
        if classification['evidence_basis'] not in valid_basis:
            print(f"  ⚠️ Invalid evidence_basis, defaulting to 'insufficient'")
            classification['evidence_basis'] = 'insufficient'
    
    def _fallback_classification(self, entity_data: Dict, error_msg: str) -> Dict:
        """Provide fallback classification when AI fails"""
        return {
            'primary_category': 'Unknown',
            'primary_subcategory': 'Unclassified',
            'secondary_categories': [],
            'confidence': 0.0,
            'reasoning': f'Classification failed: {error_msg}',
            'evidence_basis': 'insufficient',
            'source_citations': [],
            'key_functions': [],
            'deployment_model': 'Unknown',
            'data_access_level': 'unknown',
            'classified_at': datetime.now().isoformat(),
            'error': error_msg
        }
    
    def get_category_risk_profile(self, primary_category: str, primary_subcategory: str) -> Dict:
        """Get typical risk profile for a category"""
        
        risk_profiles = {
            "File Sharing/Storage": {
                "typical_risks": [
                    "Data exfiltration",
                    "Unauthorized sharing",
                    "Compliance violations (GDPR, HIPAA)",
                    "Shadow IT proliferation"
                ],
                "data_sensitivity": "high",
                "common_controls": ["DLP", "Access controls", "Encryption at rest/transit"]
            },
            "GenAI Tool/Assistant": {
                "typical_risks": [
                    "Data leakage to training",
                    "Prompt injection attacks",
                    "Intellectual property exposure",
                    "Hallucination/accuracy issues"
                ],
                "data_sensitivity": "high",
                "common_controls": ["Data residency", "Terms review", "Input filtering"]
            },
            "Endpoint Agent/EDR": {
                "typical_risks": [
                    "Privileged access abuse",
                    "Performance impact",
                    "Single point of failure",
                    "Supply chain compromise"
                ],
                "data_sensitivity": "high",
                "common_controls": ["Vendor security audit", "Least privilege", "Monitoring"]
            },
            "Team Chat/Messaging": {
                "typical_risks": [
                    "Data retention issues",
                    "Insider threats",
                    "Third-party app risks",
                    "Compliance gaps"
                ],
                "data_sensitivity": "medium-high",
                "common_controls": ["Message retention policies", "App approval process", "E2E encryption"]
            },
            "CRM System": {
                "typical_risks": [
                    "Customer data breach",
                    "Integration vulnerabilities",
                    "Access control failures",
                    "GDPR/privacy violations"
                ],
                "data_sensitivity": "high",
                "common_controls": ["Role-based access", "Audit logging", "Data encryption"]
            }
        }
        
        profile = risk_profiles.get(primary_subcategory, {
            "typical_risks": ["General software risks apply"],
            "data_sensitivity": "medium",
            "common_controls": ["Standard security controls"]
        })
        
        return profile
    
    def format_classification_summary(self, classification: Dict) -> str:
        """Format classification into readable summary"""
        
        confidence = classification.get('confidence', 0)
        evidence = classification.get('evidence_basis', 'unknown')
        
        summary = f"""
TAXONOMY CLASSIFICATION
{'='*60}

Primary Category:     {classification.get('primary_category', 'Unknown')}
Subcategory:          {classification.get('primary_subcategory', 'Unknown')}
Confidence:           {confidence:.1%}

Evidence Basis:       {evidence.upper()}
Deployment Model:     {classification.get('deployment_model', 'Unknown')}
Data Access Level:    {classification.get('data_access_level', 'Unknown')}

Key Functions:
{self._format_list(classification.get('key_functions', []))}

Reasoning:
{classification.get('reasoning', 'No reasoning provided')}

Source Citations:
{self._format_list(classification.get('source_citations', []))}
"""
        
        secondary = classification.get('secondary_categories', [])
        if secondary:
            summary += f"\nSecondary Categories:\n"
            for sec in secondary:
                summary += f"  • {sec.get('category')} → {sec.get('subcategory')}\n"
        
        risk_profile = self.get_category_risk_profile(
            classification.get('primary_category', ''),
            classification.get('primary_subcategory', '')
        )
        
        if risk_profile.get('typical_risks'):
            summary += f"\nTypical Risks for This Category:\n"
            summary += self._format_list(risk_profile['typical_risks'])
        
        return summary
    
    def _format_list(self, items: List[str]) -> str:
        """Format list with bullets"""
        if not items:
            return "  • None"
        return "\n".join([f"  • {item}" for item in items])


class EnhancedEntityResolver:
    """Enhanced resolver that includes taxonomy classification"""
    
    def __init__(self, entity_resolver, taxonomy_classifier=None):
        """
        Args:
            entity_resolver: EntityResolver instance (with CacheManager)
            taxonomy_classifier: TaxonomyClassifier instance (optional)
        """
        self.resolver = entity_resolver
        
        if taxonomy_classifier:
            self.classifier = taxonomy_classifier
        else:
            self.classifier = TaxonomyClassifier(self.resolver.model)
        
        print("✓ Enhanced Entity Resolver initialized")
    
    def resolve_and_classify(self, user_input: str, force_refresh: bool = False) -> Dict:
        """
        Complete resolution: entity + taxonomy classification
        
        Args:
            user_input: Product name, vendor, or URL
            force_refresh: Skip cache and fetch fresh data
            
        Returns:
            Complete entity data with classification
        """
        # Get resolution (uses CacheManager internally)
        entity_result = self.resolver.resolve(user_input, force_refresh)
        
        print(f"\n📊 Adding taxonomy classification...")
        
        # Add classification
        classification = self.classifier.classify(
            entity_result['resolution'],
            entity_result['sources']
        )
        
        entity_result['classification'] = classification
        entity_result['evidence_quality']['classification_confidence'] = classification['confidence']
        
        # Save enhanced result (uses CacheManager)
        self._save_enhanced_cache(entity_result)
        
        return entity_result
    
    def _save_enhanced_cache(self, data: Dict):
        """Save enhanced data using CacheManager"""
        cache_key = data.get('cache_key')
        if cache_key:
            # Use the resolver's cache manager
            success = self.resolver.cache.set(cache_key, data)
            if success:
                print(f"  ✓ Enhanced assessment cached")
            else:
                print(f"  ⚠️ Enhanced cache save failed")