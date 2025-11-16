"""
Google Cloud Storage Cache Manager
Handles reading/writing cache files to GCS bucket
"""

import json
import os
from datetime import datetime
from typing import Optional, Dict
from pathlib import Path

try:
    from google.cloud import storage
    GCS_AVAILABLE = True
except ImportError:
    GCS_AVAILABLE = False
    print("⚠️  google-cloud-storage not installed - using local cache only")


class CacheManager:
    """Manages cache storage - either GCS or local filesystem"""
    
    def __init__(self, bucket_name: str = None, use_gcs: bool = False, local_cache_dir: Path = None):
        """
        Initialize cache manager
        
        Args:
            bucket_name: GCS bucket name (required if use_gcs=True)
            use_gcs: Whether to use GCS (True) or local storage (False)
            local_cache_dir: Local cache directory (fallback or primary storage)
        """
        self.use_gcs = use_gcs and GCS_AVAILABLE
        self.bucket_name = bucket_name
        self.local_cache_dir = local_cache_dir or Path('./Runtime/assessor_cache')
        
        # Always ensure local cache exists (as fallback)
        self.local_cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize GCS if requested
        self.bucket = None
        self.storage_client = None
        
        if self.use_gcs:
            if not bucket_name:
                print("⚠️  GCS enabled but no bucket name provided - falling back to local cache")
                self.use_gcs = False
            else:
                try:
                    self.storage_client = storage.Client()
                    self.bucket = self.storage_client.bucket(bucket_name)
                    print(f"✓ GCS cache enabled: gs://{bucket_name}/")
                except Exception as e:
                    print(f"⚠️  GCS initialization failed: {e}")
                    print("   Falling back to local cache")
                    self.use_gcs = False
        
        if not self.use_gcs:
            print(f"✓ Local cache enabled: {self.local_cache_dir}")
    
    def get(self, cache_key: str) -> Optional[Dict]:
        """
        Load cached data by key
        
        Args:
            cache_key: Cache file identifier
            
        Returns:
            Cached data dict or None if not found
        """
        if self.use_gcs:
            return self._get_from_gcs(cache_key)
        else:
            return self._get_from_local(cache_key)
    
    def set(self, cache_key: str, data: Dict) -> bool:
        """
        Save data to cache
        
        Args:
            cache_key: Cache file identifier
            data: Data to cache
            
        Returns:
            True if successful, False otherwise
        """
        # Add cache metadata
        data['cached_at'] = datetime.now().isoformat()
        
        if self.use_gcs:
            return self._set_to_gcs(cache_key, data)
        else:
            return self._set_to_local(cache_key, data)
    
    def list_keys(self) -> list:
        """
        List all cache keys
        
        Returns:
            List of cache keys (without .json extension)
        """
        if self.use_gcs:
            return self._list_gcs_keys()
        else:
            return self._list_local_keys()
    
    def delete(self, cache_key: str) -> bool:
        """
        Delete a cache entry
        
        Args:
            cache_key: Cache file identifier
            
        Returns:
            True if successful, False otherwise
        """
        if self.use_gcs:
            return self._delete_from_gcs(cache_key)
        else:
            return self._delete_from_local(cache_key)
    
    def clear_all(self) -> int:
        """
        Clear all cache entries
        
        Returns:
            Number of entries deleted
        """
        if self.use_gcs:
            return self._clear_gcs()
        else:
            return self._clear_local()
    
    # ========================================================================
    # GCS OPERATIONS
    # ========================================================================
    
    def _get_from_gcs(self, cache_key: str) -> Optional[Dict]:
        """Load from GCS bucket"""
        try:
            blob = self.bucket.blob(f"{cache_key}.json")
            
            if not blob.exists():
                return None
            
            content = blob.download_as_text()
            data = json.loads(content)
            
            return data
            
        except Exception as e:
            print(f"  ⚠️ GCS read error for {cache_key}: {e}")
            return None
    
    def _set_to_gcs(self, cache_key: str, data: Dict) -> bool:
        """Save to GCS bucket"""
        try:
            blob = self.bucket.blob(f"{cache_key}.json")
            blob.upload_from_string(
                json.dumps(data, indent=2),
                content_type='application/json'
            )
            return True
            
        except Exception as e:
            print(f"  ⚠️ GCS write error for {cache_key}: {e}")
            return False
    
    def _list_gcs_keys(self) -> list:
        """List all cache keys in GCS"""
        try:
            blobs = self.bucket.list_blobs()
            keys = [blob.name.replace('.json', '') for blob in blobs if blob.name.endswith('.json')]
            return keys
            
        except Exception as e:
            print(f"  ⚠️ GCS list error: {e}")
            return []
    
    def _delete_from_gcs(self, cache_key: str) -> bool:
        """Delete from GCS bucket"""
        try:
            blob = self.bucket.blob(f"{cache_key}.json")
            blob.delete()
            return True
            
        except Exception as e:
            print(f"  ⚠️ GCS delete error for {cache_key}: {e}")
            return False
    
    def _clear_gcs(self) -> int:
        """Clear all entries from GCS"""
        try:
            blobs = list(self.bucket.list_blobs())
            count = 0
            
            for blob in blobs:
                if blob.name.endswith('.json'):
                    blob.delete()
                    count += 1
            
            return count
            
        except Exception as e:
            print(f"  ⚠️ GCS clear error: {e}")
            return 0
    
    # ========================================================================
    # LOCAL OPERATIONS
    # ========================================================================
    
    def _get_from_local(self, cache_key: str) -> Optional[Dict]:
        """Load from local filesystem"""
        cache_file = self.local_cache_dir / f"{cache_key}.json"
        
        if not cache_file.exists():
            return None
        
        try:
            with open(cache_file, 'r') as f:
                data = json.load(f)
            return data
            
        except Exception as e:
            print(f"  ⚠️ Local read error for {cache_key}: {e}")
            return None
    
    def _set_to_local(self, cache_key: str, data: Dict) -> bool:
        """Save to local filesystem"""
        cache_file = self.local_cache_dir / f"{cache_key}.json"
        
        try:
            with open(cache_file, 'w') as f:
                json.dump(data, f, indent=2)
            return True
            
        except Exception as e:
            print(f"  ⚠️ Local write error for {cache_key}: {e}")
            return False
    
    def _list_local_keys(self) -> list:
        """List all cache keys in local storage"""
        try:
            keys = [f.stem for f in self.local_cache_dir.glob('*.json')]
            return keys
            
        except Exception as e:
            print(f"  ⚠️ Local list error: {e}")
            return []
    
    def _delete_from_local(self, cache_key: str) -> bool:
        """Delete from local filesystem"""
        cache_file = self.local_cache_dir / f"{cache_key}.json"
        
        try:
            if cache_file.exists():
                cache_file.unlink()
                return True
            return False
            
        except Exception as e:
            print(f"  ⚠️ Local delete error for {cache_key}: {e}")
            return False
    
    def _clear_local(self) -> int:
        """Clear all entries from local storage"""
        try:
            cache_files = list(self.local_cache_dir.glob('*.json'))
            count = 0
            
            for cache_file in cache_files:
                try:
                    cache_file.unlink()
                    count += 1
                except Exception as e:
                    print(f"  ⚠️ Error deleting {cache_file.name}: {e}")
            
            return count
            
        except Exception as e:
            print(f"  ⚠️ Local clear error: {e}")
            return 0
    
    def get_storage_info(self) -> Dict:
        """Get information about current storage configuration"""
        return {
            'storage_type': 'gcs' if self.use_gcs else 'local',
            'location': f"gs://{self.bucket_name}/" if self.use_gcs else str(self.local_cache_dir),
            'bucket_name': self.bucket_name if self.use_gcs else None,
            'local_cache_dir': str(self.local_cache_dir),
            'gcs_available': GCS_AVAILABLE
        }