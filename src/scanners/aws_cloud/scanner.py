"""
AWS Cloud misconfiguration scanner for Argus.

Scans AWS accounts for security misconfigurations across multiple services
including S3, EC2, IAM, RDS, Lambda, VPC, and more.

Features:
- Parallel region scanning with asyncio
- LRU caching for repeated API calls
- Progress tracking with Rich
- Comprehensive security checks
"""

import asyncio
from datetime import datetime, timedelta
from functools import lru_cache
from typing import Any, Callable, Optional

from src.config import get_settings
from src.core.exceptions import AWSError, CloudScanError
from src.core.logger import ScanLogger, get_logger
from src.scanners.base import BaseScanner, Finding, Severity
from src.utils.aws_boto_helper import AWSClient
from src.utils.progress import ScanProgress

logger = get_logger(__name__)

# Cache TTL in seconds
CACHE_TTL = 300  # 5 minutes


class AWSCloudScanner(BaseScanner):
    """
    AWS Cloud misconfiguration scanner.
    
    Scans AWS resources for security issues including:
    - S3: Public buckets, encryption, versioning, logging
    - EC2: Security groups, EBS encryption, public AMIs
    - IAM: MFA, access keys, password policies
    - RDS: Public access, encryption, backup retention
    - Lambda: DLQ, timeout, runtime versions
    - VPC: Flow logs, default security groups
    """
    
    scanner_type = "aws_cloud"
    
    # Available service scanners
    AVAILABLE_SERVICES = ["s3", "ec2", "iam", "rds", "lambda", "vpc", "cloudtrail"]
    
    def __init__(
        self,
        profile: Optional[str] = None,
        regions: Optional[list[str]] = None,
        services: Optional[list[str]] = None,
        debug: bool = False,
        parallel: bool = True,
        max_concurrent_regions: int = 5,
        show_progress: bool = True,
        use_cache: bool = True,
    ):
        """
        Initialize the AWS Cloud scanner.
        
        Args:
            profile: AWS profile name
            regions: List of regions to scan (None = all regions)
            services: List of services to scan (None = all services)
            debug: Enable debug mode
            parallel: Enable parallel region scanning (default: True)
            max_concurrent_regions: Maximum concurrent region scans
            show_progress: Show progress bar during scanning
            use_cache: Cache API responses to reduce calls
        """
        super().__init__()
        
        settings = get_settings()
        
        self.profile = profile
        self.regions = regions
        self.services = services or self.AVAILABLE_SERVICES
        self.debug = debug or settings.debug
        
        # Parallel scanning settings
        self.parallel = parallel
        self.max_concurrent_regions = max_concurrent_regions
        self.show_progress = show_progress
        self.use_cache = use_cache
        self._progress: Optional[ScanProgress] = None
        self._lock = asyncio.Lock()
        
        # Cache for API responses
        self._cache: dict[str, tuple[Any, datetime]] = {}
        
        self._aws_client: Optional[AWSClient] = None
        self._scan_logger: Optional[ScanLogger] = None
        self._stats = {
            "regions_scanned": 0,
            "resources_scanned": 0,
            "services_scanned": 0,
            "cache_hits": 0,
            "api_calls": 0,
        }

    @property
    def aws(self) -> AWSClient:
        """Get AWS client."""
        if self._aws_client is None:
            self._aws_client = AWSClient(profile=self.profile)
        return self._aws_client

    def _get_cached(self, key: str, fetcher: Callable[[], Any]) -> Any:
        """
        Get cached value or fetch and cache.
        
        Args:
            key: Cache key
            fetcher: Function to fetch value if not cached
            
        Returns:
            Cached or fetched value
        """
        if self.use_cache and key in self._cache:
            value, cached_at = self._cache[key]
            if (datetime.utcnow() - cached_at).seconds < CACHE_TTL:
                self._stats["cache_hits"] += 1
                return value
        
        self._stats["api_calls"] += 1
        value = fetcher()
        
        if self.use_cache:
            self._cache[key] = (value, datetime.utcnow())
        
        return value

    def clear_cache(self) -> None:
        """Clear the API response cache."""
        self._cache.clear()

    async def scan(self) -> dict[str, Any]:
        """
        Scan AWS account for misconfigurations.
        
        Uses parallel region scanning for improved performance.
        
        Returns:
            Dictionary containing scan results
        """
        started_at = datetime.utcnow()
        self.clear_findings()
        self.clear_cache()
        
        target = f"AWS Account (Profile: {self.profile or 'default'})"
        self._scan_logger = ScanLogger("cloud", target)
        self._scan_logger.start()
        
        try:
            # Get account ID
            account_id = self.aws.get_account_id()
            self._debug_log(f"Scanning AWS account: {account_id}")
            
            # Determine regions to scan
            scan_regions = self.regions or self._get_enabled_regions()
            self._debug_log(f"Regions to scan: {scan_regions}")
            
            # Setup progress tracking
            if self.show_progress:
                self._progress = ScanProgress(description="AWS Cloud Scan")
                self._progress.__enter__()
                self._progress.add_task("services", total=len(self.services), description="Scanning services")
            
            try:
                # Run service-specific scans
                for service in self.services:
                    async with self._lock:
                        self._stats["services_scanned"] += 1
                    
                    if service == "s3":
                        await self._scan_s3()
                    elif service == "ec2":
                        await self._scan_ec2_parallel(scan_regions)
                    elif service == "iam":
                        await self._scan_iam()
                    elif service == "rds":
                        await self._scan_rds_parallel(scan_regions)
                    elif service == "lambda":
                        await self._scan_lambda_parallel(scan_regions)
                    elif service == "vpc":
                        await self._scan_vpc_parallel(scan_regions)
                    elif service == "cloudtrail":
                        await self._scan_cloudtrail(scan_regions)
                    
                    if self._progress:
                        self._progress.update("services", advance=1)
                        
            finally:
                if self._progress:
                    self._progress.__exit__(None, None, None)
                    if self.show_progress:
                        self._progress.print_summary()
                    self._progress = None
            
            # Create result
            result = self.create_result(
                target=target,
                started_at=started_at,
                metadata={
                    "account_id": account_id,
                    "regions": scan_regions,
                    "services": self.services,
                    **self._stats,
                },
            )
            
            self._scan_logger.end(len(self._findings))
            return result.to_dict()
            
        except AWSError:
            raise
        except Exception as e:
            self._scan_logger.error(f"Scan failed: {e}", e)
            raise CloudScanError(f"AWS Cloud scan failed: {e}")

    def _debug_log(self, message: str) -> None:
        """Log debug message if debug mode enabled."""
        if self.debug:
            logger.debug(f"[AWS SCAN] {message}")

    def _get_enabled_regions(self) -> list[str]:
        """Get list of enabled regions."""
        return self._get_cached(
            "enabled_regions",
            lambda: self.aws.get_available_regions("ec2")
        )

    # =========================================================================
    # PARALLEL REGION SCANNING HELPERS
    # =========================================================================
    
    async def _scan_regions_parallel(
        self,
        regions: list[str],
        scanner: Callable[[str], Any],
        service_name: str,
    ) -> None:
        """
        Scan multiple regions in parallel.
        
        Args:
            regions: List of regions to scan
            scanner: Coroutine function to scan a single region
            service_name: Name of service being scanned
        """
        if not self.parallel or len(regions) <= 1:
            # Sequential fallback
            for region in regions:
                await scanner(region)
                async with self._lock:
                    self._stats["regions_scanned"] += 1
            return
        
        # Parallel scanning with semaphore for rate limiting
        semaphore = asyncio.Semaphore(self.max_concurrent_regions)
        
        async def scan_with_semaphore(region: str):
            async with semaphore:
                try:
                    await scanner(region)
                    async with self._lock:
                        self._stats["regions_scanned"] += 1
                except Exception as e:
                    self._debug_log(f"Error scanning {service_name} in {region}: {e}")
        
        tasks = [scan_with_semaphore(region) for region in regions]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _scan_ec2_parallel(self, regions: list[str]) -> None:
        """Scan EC2 resources across regions in parallel."""
        self._debug_log("Scanning EC2 resources (parallel)...")
        await self._scan_regions_parallel(regions, self._scan_ec2_region, "EC2")

    async def _scan_rds_parallel(self, regions: list[str]) -> None:
        """Scan RDS instances across regions in parallel."""
        self._debug_log("Scanning RDS instances (parallel)...")
        await self._scan_regions_parallel(regions, self._scan_rds_region, "RDS")

    async def _scan_lambda_parallel(self, regions: list[str]) -> None:
        """Scan Lambda functions across regions in parallel."""
        self._debug_log("Scanning Lambda functions (parallel)...")
        await self._scan_regions_parallel(regions, self._scan_lambda_region, "Lambda")

    async def _scan_vpc_parallel(self, regions: list[str]) -> None:
        """Scan VPCs across regions in parallel."""
        self._debug_log("Scanning VPCs (parallel)...")
        await self._scan_regions_parallel(regions, self._scan_vpc_region, "VPC")

    # =========================================================================
    # S3 SCANNING
    # =========================================================================
    
    async def _scan_s3(self) -> None:
        """Scan S3 buckets for misconfigurations."""
        self._debug_log("Scanning S3 buckets...")
        
        s3 = self.aws.get_client("s3")
        
        try:
            buckets = s3.list_buckets().get("Buckets", [])
        except Exception as e:
            self._scan_logger.warning(f"Failed to list S3 buckets: {e}")
            return
        
        for bucket in buckets:
            bucket_name = bucket["Name"]
            self._stats["resources_scanned"] += 1
            
            # Check public access
            await self._check_s3_public_access(s3, bucket_name)
            
            # Check encryption
            await self._check_s3_encryption(s3, bucket_name)
            
            # Check versioning
            await self._check_s3_versioning(s3, bucket_name)
            
            # Check logging
            await self._check_s3_logging(s3, bucket_name)

    async def _check_s3_public_access(self, s3, bucket_name: str) -> None:
        """Check if S3 bucket has public access."""
        try:
            # Check public access block
            try:
                pab = s3.get_public_access_block(Bucket=bucket_name)
                config = pab.get("PublicAccessBlockConfiguration", {})
                
                if not all([
                    config.get("BlockPublicAcls", False),
                    config.get("IgnorePublicAcls", False),
                    config.get("BlockPublicPolicy", False),
                    config.get("RestrictPublicBuckets", False),
                ]):
                    self.add_finding(Finding(
                        rule_id="S3-PUBLIC-ACCESS-BLOCK",
                        severity=Severity.HIGH,
                        title="S3 Bucket Public Access Block Not Fully Enabled",
                        description=f"Bucket {bucket_name} does not have all public access block settings enabled",
                        resource_id=bucket_name,
                        resource_type="AWS::S3::Bucket",
                        resource_arn=f"arn:aws:s3:::{bucket_name}",
                        suggestion="Enable all public access block settings to prevent unintended public access",
                    ))
                    self._scan_logger.finding("high", "S3 Public Access Block", bucket_name)
                    
            except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
                self.add_finding(Finding(
                    rule_id="S3-NO-PUBLIC-ACCESS-BLOCK",
                    severity=Severity.HIGH,
                    title="S3 Bucket Missing Public Access Block",
                    description=f"Bucket {bucket_name} has no public access block configuration",
                    resource_id=bucket_name,
                    resource_type="AWS::S3::Bucket",
                    resource_arn=f"arn:aws:s3:::{bucket_name}",
                    suggestion="Configure public access block to prevent public access",
                ))
                self._scan_logger.finding("high", "Missing Public Access Block", bucket_name)
                
        except Exception as e:
            self._debug_log(f"Error checking public access for {bucket_name}: {e}")

    async def _check_s3_encryption(self, s3, bucket_name: str) -> None:
        """Check if S3 bucket has encryption enabled."""
        try:
            s3.get_bucket_encryption(Bucket=bucket_name)
        except s3.exceptions.ClientError as e:
            if "ServerSideEncryptionConfigurationNotFoundError" in str(e):
                self.add_finding(Finding(
                    rule_id="S3-NO-ENCRYPTION",
                    severity=Severity.MEDIUM,
                    title="S3 Bucket Without Default Encryption",
                    description=f"Bucket {bucket_name} does not have default encryption enabled",
                    resource_id=bucket_name,
                    resource_type="AWS::S3::Bucket",
                    resource_arn=f"arn:aws:s3:::{bucket_name}",
                    suggestion="Enable default encryption using SSE-S3 or SSE-KMS",
                ))
                self._scan_logger.finding("medium", "S3 No Encryption", bucket_name)

    async def _check_s3_versioning(self, s3, bucket_name: str) -> None:
        """Check if S3 bucket has versioning enabled."""
        try:
            versioning = s3.get_bucket_versioning(Bucket=bucket_name)
            status = versioning.get("Status", "Disabled")
            
            if status != "Enabled":
                self.add_finding(Finding(
                    rule_id="S3-NO-VERSIONING",
                    severity=Severity.LOW,
                    title="S3 Bucket Versioning Not Enabled",
                    description=f"Bucket {bucket_name} does not have versioning enabled",
                    resource_id=bucket_name,
                    resource_type="AWS::S3::Bucket",
                    resource_arn=f"arn:aws:s3:::{bucket_name}",
                    suggestion="Enable versioning for data protection and recovery",
                ))
        except Exception as e:
            self._debug_log(f"Error checking versioning for {bucket_name}: {e}")

    async def _check_s3_logging(self, s3, bucket_name: str) -> None:
        """Check if S3 bucket has access logging enabled."""
        try:
            logging_config = s3.get_bucket_logging(Bucket=bucket_name)
            
            if not logging_config.get("LoggingEnabled"):
                self.add_finding(Finding(
                    rule_id="S3-NO-LOGGING",
                    severity=Severity.LOW,
                    title="S3 Bucket Access Logging Not Enabled",
                    description=f"Bucket {bucket_name} does not have access logging enabled",
                    resource_id=bucket_name,
                    resource_type="AWS::S3::Bucket",
                    resource_arn=f"arn:aws:s3:::{bucket_name}",
                    suggestion="Enable access logging for audit and security monitoring",
                ))
        except Exception as e:
            self._debug_log(f"Error checking logging for {bucket_name}: {e}")

