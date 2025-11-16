#!/usr/bin/env python3
"""
Security Assessor CLI
Command-line interface for CISO-ready trust briefs
Uses configuration from config.py which loads .env file
"""

import sys
import json
import argparse
from pathlib import Path
from datetime import datetime
from typing import Optional

# Add Configuration to path and import config
sys.path.insert(0, str(Path(__file__).parent.parent / 'Configuration'))
from config import config

# Import all modules (ensure they're in the same directory)
try:
    from entity_resolver import EntityResolver
    from taxonomy_classifier import EnhancedEntityResolver, TaxonomyClassifier
    from alternative_suggester import AlternativesSuggester, CompleteAssessmentPipeline
except ImportError as e:
    print(f"❌ Error importing modules: {e}")
    print("Ensure all module files are in the same directory:")
    print("  - entity_resolver.py")
    print("  - taxonomy_classifier.py")
    print("  - alternative_suggester.py")
    sys.exit(1)


class AssessorCLI:
    """Command-line interface for Security Assessor"""
    
    def __init__(self, cache_dir: Path = None):
        """Initialize CLI with cache directory"""
        self.cache_dir = cache_dir or config.CACHE_DIR
        
        # Check for API key
        if not config.GEMINI_API_KEY:
            print("❌ GEMINI_API_KEY not set")
            print("\nSet it in Configuration/.env file:")
            print("  GEMINI_API_KEY=AIza[your-key-here]")
            sys.exit(1)
        
        # Initialize pipeline
        try:
            print("🔧 Initializing Security Assessor...")
            entity_resolver = EntityResolver()
            enhanced_resolver = EnhancedEntityResolver(entity_resolver)
            self.pipeline = CompleteAssessmentPipeline(enhanced_resolver)
            self.suggester = AlternativesSuggester()
            self.classifier = TaxonomyClassifier()
            print("✓ Ready\n")
        except Exception as e:
            print(f"❌ Initialization failed: {e}")
            sys.exit(1)
    
    def assess(self, target: str, force_refresh: bool = False, output_format: str = "text"):
        """
        Assess a software product
        
        Args:
            target: Product name, vendor, or URL
            force_refresh: Skip cache and fetch fresh data
            output_format: 'text', 'json', or 'brief'
        """
        print(f"{'='*70}")
        print(f"🔒 SECURITY ASSESSMENT")
        print(f"{'='*70}")
        print(f"Target: {target}")
        print(f"{'='*70}\n")
        
        try:
            # Run complete assessment
            assessment = self.pipeline.assess_with_alternatives(target, force_refresh)
            
            # Format and display output
            if output_format == "json":
                self._output_json(assessment)
            elif output_format == "brief":
                self._output_brief(assessment)
            else:
                self._output_full(assessment)
            
            return assessment
            
        except Exception as e:
            print(f"\n❌ Assessment failed: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def _output_full(self, assessment: dict):
        """Output full detailed assessment"""
        
        resolution = assessment['resolution']
        classification = assessment.get('classification', {})
        alternatives = assessment.get('alternatives', {})
        evidence = assessment.get('evidence_quality', {})
        
        print(f"\n{'='*70}")
        print(f"📋 ENTITY INFORMATION")
        print(f"{'='*70}")
        print(f"Product:          {resolution['product_name']}")
        print(f"Vendor:           {resolution['vendor_name']}")
        print(f"Website:          {resolution.get('vendor_website', 'N/A')}")
        print(f"Confidence:       {resolution['confidence']:.1%}")
        print(f"\nReasoning:")
        print(f"  {resolution.get('reasoning', 'N/A')}")
        
        # Classification
        if classification:
            print(f"\n{'='*70}")
            print(f"🏷️  SOFTWARE TAXONOMY")
            print(f"{'='*70}")
            print(f"Primary Category: {classification.get('primary_category', 'Unknown')}")
            print(f"Subcategory:      {classification.get('primary_subcategory', 'Unknown')}")
            print(f"Deployment:       {classification.get('deployment_model', 'Unknown')}")
            print(f"Data Access:      {classification.get('data_access_level', 'Unknown')}")
            print(f"Confidence:       {classification.get('confidence', 0):.1%}")
            
            functions = classification.get('key_functions', [])
            if functions:
                print(f"\nKey Functions:")
                for func in functions:
                    print(f"  • {func}")
            
            print(f"\nEvidence Basis:   {classification.get('evidence_basis', 'unknown').upper()}")
        
        # Evidence Quality
        print(f"\n{'='*70}")
        print(f"📊 EVIDENCE QUALITY")
        print(f"{'='*70}")
        print(f"Overall Quality:  {evidence.get('quality', 'unknown').upper()}")
        print(f"Sources Found:    {evidence.get('sources_found', 0)}/{evidence.get('sources_attempted', 0)}")
        print(f"Independent:      {evidence.get('independent_sources', 0)}")
        print(f"Vendor-Stated:    {evidence.get('vendor_sources', 0)}")
        
        # Sources
        sources = assessment.get('sources', {})
        print(f"\n{'='*70}")
        print(f"🔍 HIGH-SIGNAL SOURCES")
        print(f"{'='*70}")
        
        for source_type, source_data in sources.items():
            if source_data.get('found'):
                label = source_data.get('source_label', 'unknown')
                url = source_data.get('url', 'N/A')
                
                if source_type == 'cisa_kev':
                    matches = source_data.get('total_matches', 0)
                    status = "⚠️ FOUND" if matches > 0 else "✓ CLEAR"
                    print(f"\n{source_type.upper()}: {status}")
                    if matches > 0:
                        print(f"  Entries: {matches}")
                        print(f"  Source:  {label.upper()}")
                        for vuln in source_data.get('matches', [])[:3]:
                            print(f"  • {vuln['cve_id']}: {vuln['vulnerability_name']}")
                else:
                    print(f"\n{source_type.upper()}: ✓ Found")
                    print(f"  URL:    {url}")
                    print(f"  Source: {label.upper()}")
            else:
                if source_type == 'cisa_kev' and source_data.get('note'):
                    print(f"\n{source_type.upper()}: ✓ CLEAR")
                    print(f"  Note: {source_data['note']}")
                else:
                    print(f"\n{source_type.upper()}: ✗ Not found")
        
        # Alternatives
        if alternatives and alternatives.get('alternatives'):
            print(f"\n{'='*70}")
            print(f"🔄 SAFER ALTERNATIVES")
            print(f"{'='*70}")
            print(f"Recommendation Confidence: {alternatives.get('recommendation_confidence', 0):.1%}")
            print(f"\nRationale:")
            print(f"  {alternatives.get('rationale', 'N/A')}")
            
            for i, alt in enumerate(alternatives['alternatives'], 1):
                print(f"\n{'-'*70}")
                print(f"ALTERNATIVE {i}: {alt['product_name']} by {alt['vendor_name']}")
                print(f"{'-'*70}")
                print(f"Confidence:  {alt['confidence']:.1%}")
                print(f"Website:     {alt.get('vendor_website', 'N/A')}")
                
                print(f"\nWhy Safer:")
                print(f"  {alt['why_safer']}")
                
                highlights = alt.get('security_highlights', [])
                if highlights:
                    print(f"\nSecurity Highlights:")
                    for h in highlights:
                        print(f"  ✓ {h}")
                
                tradeoffs = alt.get('trade_offs', [])
                if tradeoffs:
                    print(f"\nTrade-offs:")
                    for t in tradeoffs:
                        print(f"  ⚠ {t}")
        else:
            print(f"\n{'='*70}")
            print(f"🔄 SAFER ALTERNATIVES")
            print(f"{'='*70}")
            print(f"No alternatives recommended")
            print(f"Note: {alternatives.get('note', 'Insufficient evidence')}")
        
        # Footer
        print(f"\n{'='*70}")
        print(f"Assessed at: {assessment.get('resolved_at', 'N/A')}")
        print(f"Cache key:   {assessment.get('cache_key', 'N/A')}")
        print(f"{'='*70}\n")
    
    def _output_brief(self, assessment: dict):
        """Output brief summary"""
        resolution = assessment['resolution']
        classification = assessment.get('classification', {})
        evidence = assessment.get('evidence_quality', {})
        alternatives = assessment.get('alternatives', {})
        
        cisa_kev = assessment.get('sources', {}).get('cisa_kev', {})
        kev_count = cisa_kev.get('total_matches', 0)
        
        print(f"\n📋 BRIEF ASSESSMENT SUMMARY")
        print(f"{'='*70}")
        print(f"Product:     {resolution['product_name']} by {resolution['vendor_name']}")
        print(f"Category:    {classification.get('primary_subcategory', 'Unknown')}")
        print(f"Deployment:  {classification.get('deployment_model', 'Unknown')}")
        print(f"Evidence:    {evidence.get('quality', 'unknown').upper()} ({evidence.get('sources_found', 0)} sources)")
        
        print(f"\n🚨 RISK INDICATORS:")
        if kev_count > 0:
            print(f"  ⚠️  CISA KEV: {kev_count} known exploited vulnerabilities")
        else:
            print(f"  ✓  CISA KEV: No known exploited vulnerabilities")
        
        print(f"  {'⚠️ ' if evidence.get('independent_sources', 0) == 0 else '✓ '} Independent Evidence: {evidence.get('independent_sources', 0)} sources")
        
        alts = alternatives.get('alternatives', [])
        if alts:
            top_alt = alts[0]
            print(f"\n💡 TOP ALTERNATIVE:")
            print(f"  {top_alt['product_name']} by {top_alt['vendor_name']} ({top_alt['confidence']:.0%} confidence)")
            print(f"  Why: {top_alt.get('security_highlights', ['Better security posture'])[0]}")
        
        print(f"{'='*70}\n")
    
    def _output_json(self, assessment: dict):
        """Output JSON format"""
        print(json.dumps(assessment, indent=2))
    
    def compare(self, target1: str, target2: str):
        """
        Compare two software products side-by-side
        
        Args:
            target1: First product
            target2: Second product
        """
        print(f"{'='*70}")
        print(f"⚖️  SECURITY COMPARISON")
        print(f"{'='*70}\n")
        
        print(f"Assessing: {target1}")
        assessment1 = self.pipeline.assess_with_alternatives(target1)
        
        print(f"\n{'='*70}\n")
        print(f"Assessing: {target2}")
        assessment2 = self.pipeline.assess_with_alternatives(target2)
        
        print(f"\n{'='*70}")
        print(f"📊 COMPARISON MATRIX")
        print(f"{'='*70}\n")
        
        col1_width = 30
        col2_width = 35
        col3_width = 35
        
        print(f"{'Dimension':<{col1_width}} | {target1[:33]:<{col2_width}} | {target2[:33]:<{col3_width}}")
        print(f"{'-'*col1_width}-+-{'-'*col2_width}-+-{'-'*col3_width}")
        
        v1 = assessment1['resolution']['vendor_name'][:33]
        v2 = assessment2['resolution']['vendor_name'][:33]
        print(f"{'Vendor':<{col1_width}} | {v1:<{col2_width}} | {v2:<{col3_width}}")
        
        c1 = assessment1.get('classification', {}).get('primary_subcategory', 'Unknown')[:33]
        c2 = assessment2.get('classification', {}).get('primary_subcategory', 'Unknown')[:33]
        print(f"{'Category':<{col1_width}} | {c1:<{col2_width}} | {c2:<{col3_width}}")
        
        d1 = assessment1.get('classification', {}).get('deployment_model', 'Unknown')[:33]
        d2 = assessment2.get('classification', {}).get('deployment_model', 'Unknown')[:33]
        print(f"{'Deployment':<{col1_width}} | {d1:<{col2_width}} | {d2:<{col3_width}}")
        
        e1 = assessment1.get('evidence_quality', {}).get('quality', 'unknown').upper()[:33]
        e2 = assessment2.get('evidence_quality', {}).get('quality', 'unknown').upper()[:33]
        print(f"{'Evidence Quality':<{col1_width}} | {e1:<{col2_width}} | {e2:<{col3_width}}")
        
        i1 = str(assessment1.get('evidence_quality', {}).get('independent_sources', 0))
        i2 = str(assessment2.get('evidence_quality', {}).get('independent_sources', 0))
        print(f"{'Independent Sources':<{col1_width}} | {i1:<{col2_width}} | {i2:<{col3_width}}")
        
        k1 = assessment1.get('sources', {}).get('cisa_kev', {}).get('total_matches', 0)
        k2 = assessment2.get('sources', {}).get('cisa_kev', {}).get('total_matches', 0)
        k1_str = f"⚠️  {k1} entries" if k1 > 0 else "✓ None"
        k2_str = f"⚠️  {k2} entries" if k2 > 0 else "✓ None"
        print(f"{'CISA KEV Status':<{col1_width}} | {k1_str:<{col2_width}} | {k2_str:<{col3_width}}")
        
        s1 = "✓ Found" if assessment1.get('sources', {}).get('security_page', {}).get('found') else "✗ Not found"
        s2 = "✓ Found" if assessment2.get('sources', {}).get('security_page', {}).get('found') else "✗ Not found"
        print(f"{'Security Page':<{col1_width}} | {s1:<{col2_width}} | {s2:<{col3_width}}")
        
        print(f"\n{'='*70}\n")
        
        if k1 < k2:
            print(f"✓ {target1} appears safer (fewer CISA KEV entries)")
        elif k2 < k1:
            print(f"✓ {target2} appears safer (fewer CISA KEV entries)")
        else:
            print(f"ℹ️  Both products show similar risk profiles")
            if e1 > e2:
                print(f"   {target1} has better evidence quality")
            elif e2 > e1:
                print(f"   {target2} has better evidence quality")
        
        print()
    
    def list_cache(self):
        """List all cached assessments"""
        print(f"{'='*70}")
        print(f"📦 CACHED ASSESSMENTS")
        print(f"{'='*70}\n")
        
        if not self.cache_dir.exists():
            print("No cache directory found")
            return
        
        cache_files = list(self.cache_dir.glob("*.json"))
        
        if not cache_files:
            print("No cached assessments")
            return
        
        print(f"Found {len(cache_files)} cached assessments:\n")
        
        for cache_file in sorted(cache_files, key=lambda f: f.stat().st_mtime, reverse=True):
            try:
                with open(cache_file, 'r') as f:
                    data = json.load(f)
                
                product = data.get('resolution', {}).get('product_name', 'Unknown')
                cached_at = data.get('cached_at', 'Unknown')
                cache_key = cache_file.stem
                
                try:
                    dt = datetime.fromisoformat(cached_at)
                    age = datetime.now() - dt
                    age_str = f"{age.days}d ago" if age.days > 0 else f"{age.seconds//3600}h ago"
                except:
                    age_str = "unknown age"
                
                print(f"• {product}")
                print(f"  Key: {cache_key}")
                print(f"  Cached: {age_str} ({cached_at})")
                print()
                
            except Exception as e:
                print(f"⚠️  Error reading {cache_file.name}: {e}\n")
    
    def clear_cache(self, confirm: bool = False):
        """Clear all cached assessments"""
        if not self.cache_dir.exists():
            print("No cache directory found")
            return
        
        cache_files = list(self.cache_dir.glob("*.json"))
        
        if not cache_files:
            print("Cache is already empty")
            return
        
        if not confirm:
            print(f"⚠️  This will delete {len(cache_files)} cached assessments")
            response = input("Are you sure? (yes/no): ")
            if response.lower() != 'yes':
                print("Cancelled")
                return
        
        for cache_file in cache_files:
            try:
                cache_file.unlink()
            except Exception as e:
                print(f"⚠️  Error deleting {cache_file.name}: {e}")
        
        print(f"✓ Cleared {len(cache_files)} cached assessments")


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="Security Assessor - CISO-ready trust briefs for software",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s assess "Slack"
  %(prog)s assess "https://github.com" --refresh
  %(prog)s assess "Zoom" --format brief
  %(prog)s compare "Zoom" "Microsoft Teams"
  %(prog)s list-cache
  %(prog)s clear-cache
        """
    )
    
    parser.add_argument('command', 
                       choices=['assess', 'compare', 'list-cache', 'clear-cache'],
                       help='Command to execute')
    
    parser.add_argument('targets', nargs='*',
                       help='Product name(s), vendor, or URL(s)')
    
    parser.add_argument('--refresh', action='store_true',
                       help='Force refresh (skip cache)')
    
    parser.add_argument('--format', choices=['text', 'json', 'brief'],
                       default='text',
                       help='Output format (default: text)')
    
    parser.add_argument('--cache-dir', default=None,
                       help='Cache directory (default: from config)')
    
    args = parser.parse_args()
    
    # Initialize CLI
    cache_dir = Path(args.cache_dir) if args.cache_dir else None
    cli = AssessorCLI(cache_dir=cache_dir)
    
    # Execute command
    if args.command == 'assess':
        if not args.targets:
            print("❌ Error: 'assess' requires a target")
            print("Usage: assessor_cli.py assess <product|vendor|url>")
            sys.exit(1)
        
        cli.assess(args.targets[0], force_refresh=args.refresh, output_format=args.format)
    
    elif args.command == 'compare':
        if len(args.targets) < 2:
            print("❌ Error: 'compare' requires two targets")
            print("Usage: assessor_cli.py compare <product1> <product2>")
            sys.exit(1)
        
        cli.compare(args.targets[0], args.targets[1])
    
    elif args.command == 'list-cache':
        cli.list_cache()
    
    elif args.command == 'clear-cache':
        cli.clear_cache()


if __name__ == "__main__":
    main()