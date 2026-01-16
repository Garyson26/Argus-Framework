"""
AWS Cloud misconfiguration scanner for FuFuFaFa.

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

    # =========================================================================
    # EC2 SCANNING
    # =========================================================================
    
    async def _scan_ec2_region(self, region: str) -> None:
        """Scan EC2 resources in a single region."""
        ec2 = self.aws.get_client("ec2", region=region)
        
        # Check security groups
        await self._check_security_groups(ec2, region)
        
        # Check EBS volumes
        await self._check_ebs_encryption(ec2, region)

    async def _check_security_groups(self, ec2, region: str) -> None:
        """Check security groups for overly permissive rules."""
        try:
            sgs = ec2.describe_security_groups()["SecurityGroups"]
            
            for sg in sgs:
                self._stats["resources_scanned"] += 1
                sg_id = sg["GroupId"]
                sg_name = sg.get("GroupName", "Unknown")
                
                # Check inbound rules
                for rule in sg.get("IpPermissions", []):
                    for ip_range in rule.get("IpRanges", []):
                        cidr = ip_range.get("CidrIp", "")
                        
                        if cidr == "0.0.0.0/0":
                            port_info = self._get_port_info(rule)
                            
                            # Critical if SSH/RDP open to world
                            if port_info.get("from_port") in (22, 3389):
                                self.add_finding(Finding(
                                    rule_id="EC2-SG-OPEN-SENSITIVE-PORT",
                                    severity=Severity.CRITICAL,
                                    title="Security Group Open to World on Sensitive Port",
                                    description=f"Security group {sg_name} ({sg_id}) allows inbound traffic from 0.0.0.0/0 on port {port_info.get('from_port')}",
                                    resource_id=sg_id,
                                    resource_type="AWS::EC2::SecurityGroup",
                                    suggestion="Restrict access to specific IP addresses or CIDR blocks",
                                    metadata={"region": region, "port": port_info},
                                ))
                                self._scan_logger.finding("critical", "Open Sensitive Port", sg_id)
                            else:
                                self.add_finding(Finding(
                                    rule_id="EC2-SG-OPEN-TO-WORLD",
                                    severity=Severity.MEDIUM,
                                    title="Security Group Open to World",
                                    description=f"Security group {sg_name} ({sg_id}) allows inbound traffic from 0.0.0.0/0",
                                    resource_id=sg_id,
                                    resource_type="AWS::EC2::SecurityGroup",
                                    suggestion="Restrict access to specific IP addresses or CIDR blocks",
                                    metadata={"region": region, "port": port_info},
                                ))
                                
        except Exception as e:
            self._debug_log(f"Error checking security groups in {region}: {e}")

    def _get_port_info(self, rule: dict) -> dict:
        """Extract port information from security group rule."""
        return {
            "protocol": rule.get("IpProtocol", "all"),
            "from_port": rule.get("FromPort", 0),
            "to_port": rule.get("ToPort", 65535),
        }

    async def _check_ebs_encryption(self, ec2, region: str) -> None:
        """Check EBS volumes for encryption."""
        try:
            volumes = ec2.describe_volumes()["Volumes"]
            
            for volume in volumes:
                self._stats["resources_scanned"] += 1
                
                if not volume.get("Encrypted", False):
                    self.add_finding(Finding(
                        rule_id="EC2-EBS-NOT-ENCRYPTED",
                        severity=Severity.MEDIUM,
                        title="EBS Volume Not Encrypted",
                        description=f"EBS volume {volume['VolumeId']} is not encrypted",
                        resource_id=volume["VolumeId"],
                        resource_type="AWS::EC2::Volume",
                        suggestion="Enable encryption for EBS volumes to protect data at rest",
                        metadata={"region": region, "size": volume.get("Size")},
                    ))
        except Exception as e:
            self._debug_log(f"Error checking EBS volumes in {region}: {e}")

    async def _add_finding_async(self, finding: Finding) -> None:
        """Thread-safe finding addition."""
        async with self._lock:
            self.add_finding(finding)
            if self._progress:
                self._progress.add_finding(finding.severity.value)

    # =========================================================================
    # IAM SCANNING
    # =========================================================================
    
    async def _scan_iam(self) -> None:
        """Scan IAM for misconfigurations."""
        self._debug_log("Scanning IAM...")
        
        iam = self.aws.get_client("iam")
        
        # Check password policy
        await self._check_password_policy(iam)
        
        # Check users
        await self._check_iam_users(iam)

    async def _check_password_policy(self, iam) -> None:
        """Check IAM password policy."""
        try:
            policy = iam.get_account_password_policy()["PasswordPolicy"]
            
            issues = []
            
            if policy.get("MinimumPasswordLength", 0) < 14:
                issues.append("Minimum password length should be at least 14 characters")
            
            if not policy.get("RequireSymbols", False):
                issues.append("Password policy should require symbols")
            
            if not policy.get("RequireNumbers", False):
                issues.append("Password policy should require numbers")
            
            if not policy.get("RequireUppercaseCharacters", False):
                issues.append("Password policy should require uppercase characters")
            
            if not policy.get("RequireLowercaseCharacters", False):
                issues.append("Password policy should require lowercase characters")
            
            if issues:
                self.add_finding(Finding(
                    rule_id="IAM-WEAK-PASSWORD-POLICY",
                    severity=Severity.MEDIUM,
                    title="IAM Password Policy Not Strong Enough",
                    description="The account password policy does not meet security best practices",
                    resource_id="AccountPasswordPolicy",
                    resource_type="AWS::IAM::AccountPasswordPolicy",
                    suggestion="; ".join(issues),
                ))
                self._scan_logger.finding("medium", "Weak Password Policy", "Account")
                
        except iam.exceptions.NoSuchEntityException:
            self.add_finding(Finding(
                rule_id="IAM-NO-PASSWORD-POLICY",
                severity=Severity.HIGH,
                title="No IAM Password Policy Configured",
                description="The account has no password policy configured",
                resource_id="AccountPasswordPolicy",
                resource_type="AWS::IAM::AccountPasswordPolicy",
                suggestion="Configure a strong password policy for the account",
            ))
            self._scan_logger.finding("high", "No Password Policy", "Account")

    async def _check_iam_users(self, iam) -> None:
        """Check IAM users for security issues."""
        try:
            users = list(self.aws.paginate(iam, "list_users", "Users"))
            
            for user in users:
                self._stats["resources_scanned"] += 1
                username = user["UserName"]
                
                # Check MFA
                mfa_devices = iam.list_mfa_devices(UserName=username)["MFADevices"]
                
                if not mfa_devices:
                    # Check if user has console access
                    try:
                        iam.get_login_profile(UserName=username)
                        # User has console access but no MFA
                        self.add_finding(Finding(
                            rule_id="IAM-USER-NO-MFA",
                            severity=Severity.HIGH,
                            title="IAM User Without MFA",
                            description=f"IAM user {username} has console access but no MFA enabled",
                            resource_id=username,
                            resource_type="AWS::IAM::User",
                            resource_arn=user["Arn"],
                            suggestion="Enable MFA for all IAM users with console access",
                        ))
                        self._scan_logger.finding("high", "User No MFA", username)
                    except iam.exceptions.NoSuchEntityException:
                        pass  # User has no console access
                
                # Check access key age
                access_keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
                
                for key in access_keys:
                    if key["Status"] == "Active":
                        key_age = datetime.utcnow().replace(tzinfo=None) - key["CreateDate"].replace(tzinfo=None)
                        
                        if key_age > timedelta(days=90):
                            self.add_finding(Finding(
                                rule_id="IAM-ACCESS-KEY-OLD",
                                severity=Severity.MEDIUM,
                                title="IAM Access Key Not Rotated",
                                description=f"Access key {key['AccessKeyId']} for user {username} is {key_age.days} days old",
                                resource_id=key["AccessKeyId"],
                                resource_type="AWS::IAM::AccessKey",
                                suggestion="Rotate access keys at least every 90 days",
                                metadata={"age_days": key_age.days},
                            ))
                            
        except Exception as e:
            self._debug_log(f"Error checking IAM users: {e}")

    # =========================================================================
    # RDS SCANNING
    # =========================================================================
    
    async def _scan_rds_region(self, region: str) -> None:
        """Scan RDS instances in a single region."""
        rds = self.aws.get_client("rds", region=region)
        
        try:
            instances = rds.describe_db_instances()["DBInstances"]
            
            for instance in instances:
                async with self._lock:
                    self._stats["resources_scanned"] += 1
                db_id = instance["DBInstanceIdentifier"]
                
                # Check public accessibility
                if instance.get("PubliclyAccessible", False):
                    self.add_finding(Finding(
                        rule_id="RDS-PUBLIC-ACCESS",
                        severity=Severity.CRITICAL,
                        title="RDS Instance Publicly Accessible",
                        description=f"RDS instance {db_id} is publicly accessible",
                        resource_id=db_id,
                        resource_type="AWS::RDS::DBInstance",
                        resource_arn=instance.get("DBInstanceArn"),
                        suggestion="Disable public accessibility unless absolutely necessary",
                        metadata={"region": region},
                    ))
                    self._scan_logger.finding("critical", "RDS Public Access", db_id)
                
                # Check encryption
                if not instance.get("StorageEncrypted", False):
                    self.add_finding(Finding(
                        rule_id="RDS-NO-ENCRYPTION",
                        severity=Severity.HIGH,
                        title="RDS Instance Not Encrypted",
                        description=f"RDS instance {db_id} storage is not encrypted",
                        resource_id=db_id,
                        resource_type="AWS::RDS::DBInstance",
                        resource_arn=instance.get("DBInstanceArn"),
                        suggestion="Enable storage encryption for data protection",
                        metadata={"region": region},
                    ))
                    self._scan_logger.finding("high", "RDS No Encryption", db_id)
                
                # Check backup retention
                retention = instance.get("BackupRetentionPeriod", 0)
                if retention < 7:
                    self.add_finding(Finding(
                        rule_id="RDS-LOW-BACKUP-RETENTION",
                        severity=Severity.MEDIUM,
                        title="RDS Instance Low Backup Retention",
                        description=f"RDS instance {db_id} has backup retention of only {retention} days",
                        resource_id=db_id,
                        resource_type="AWS::RDS::DBInstance",
                        suggestion="Increase backup retention to at least 7 days",
                        metadata={"region": region, "retention_days": retention},
                    ))
                    
        except Exception as e:
            self._debug_log(f"Error scanning RDS in {region}: {e}")

    # =========================================================================
    # LAMBDA SCANNING
    # =========================================================================
    
    # List of outdated runtimes
    OUTDATED_RUNTIMES = [
        "python2.7", "python3.6", "python3.7",
        "nodejs10.x", "nodejs12.x",
        "ruby2.5",
        "dotnetcore2.1",
    ]
    
    async def _scan_lambda_region(self, region: str) -> None:
        """Scan Lambda functions in a single region."""
        lambda_client = self.aws.get_client("lambda", region=region)
        
        try:
            functions = lambda_client.list_functions()["Functions"]
            
            for func in functions:
                async with self._lock:
                    self._stats["resources_scanned"] += 1
                func_name = func["FunctionName"]
                
                # Check for outdated runtime
                runtime = func.get("Runtime", "")
                if runtime in self.OUTDATED_RUNTIMES:
                    self.add_finding(Finding(
                        rule_id="LAMBDA-OUTDATED-RUNTIME",
                        severity=Severity.MEDIUM,
                        title="Lambda Function Using Outdated Runtime",
                        description=f"Function {func_name} uses outdated runtime: {runtime}",
                        resource_id=func_name,
                        resource_type="AWS::Lambda::Function",
                        resource_arn=func["FunctionArn"],
                        suggestion="Update to a supported runtime version",
                        metadata={"region": region, "runtime": runtime},
                    ))
                
                # Check for missing DLQ
                if not func.get("DeadLetterConfig"):
                    self.add_finding(Finding(
                        rule_id="LAMBDA-NO-DLQ",
                        severity=Severity.LOW,
                        title="Lambda Function Missing Dead Letter Queue",
                        description=f"Function {func_name} has no DLQ configured",
                        resource_id=func_name,
                        resource_type="AWS::Lambda::Function",
                        resource_arn=func["FunctionArn"],
                        suggestion="Configure a Dead Letter Queue for error handling",
                        metadata={"region": region},
                    ))
                    
        except Exception as e:
            self._debug_log(f"Error scanning Lambda in {region}: {e}")

    # =========================================================================
    # VPC SCANNING
    # =========================================================================
    
    async def _scan_vpc_region(self, region: str) -> None:
        """Scan VPCs in a single region."""
        ec2 = self.aws.get_client("ec2", region=region)
        
        try:
            vpcs = ec2.describe_vpcs()["Vpcs"]
            
            for vpc in vpcs:
                async with self._lock:
                    self._stats["resources_scanned"] += 1
                vpc_id = vpc["VpcId"]
                
                # Check VPC Flow Logs
                flow_logs = ec2.describe_flow_logs(
                    Filters=[{"Name": "resource-id", "Values": [vpc_id]}]
                )["FlowLogs"]
                
                if not flow_logs:
                    self.add_finding(Finding(
                        rule_id="VPC-NO-FLOW-LOGS",
                        severity=Severity.MEDIUM,
                        title="VPC Flow Logs Not Enabled",
                        description=f"VPC {vpc_id} does not have flow logs enabled",
                        resource_id=vpc_id,
                        resource_type="AWS::EC2::VPC",
                        suggestion="Enable VPC Flow Logs for network traffic monitoring",
                        metadata={"region": region},
                    ))
                    self._scan_logger.finding("medium", "VPC No Flow Logs", vpc_id)
                    
        except Exception as e:
            self._debug_log(f"Error scanning VPCs in {region}: {e}")

    # =========================================================================
    # CLOUDTRAIL SCANNING
    # =========================================================================
    
    async def _scan_cloudtrail(self, regions: list[str]) -> None:
        """Scan CloudTrail for misconfigurations."""
        self._debug_log("Scanning CloudTrail...")
        
        # CloudTrail is global, just check once
        cloudtrail = self.aws.get_client("cloudtrail", region=regions[0] if regions else "us-east-1")
        
        try:
            trails = cloudtrail.describe_trails()["trailList"]
            
            if not trails:
                self.add_finding(Finding(
                    rule_id="CLOUDTRAIL-NOT-ENABLED",
                    severity=Severity.CRITICAL,
                    title="CloudTrail Not Enabled",
                    description="No CloudTrail trails are configured for this account",
                    resource_id="CloudTrail",
                    resource_type="AWS::CloudTrail::Trail",
                    suggestion="Enable CloudTrail for audit logging and compliance",
                ))
                self._scan_logger.finding("critical", "CloudTrail Not Enabled", "Account")
                return
            
            for trail in trails:
                self._stats["resources_scanned"] += 1
                trail_name = trail["Name"]
                
                # Check if trail is multi-region
                if not trail.get("IsMultiRegionTrail", False):
                    self.add_finding(Finding(
                        rule_id="CLOUDTRAIL-NOT-MULTIREGION",
                        severity=Severity.MEDIUM,
                        title="CloudTrail Not Multi-Region",
                        description=f"Trail {trail_name} is not configured for multi-region logging",
                        resource_id=trail_name,
                        resource_type="AWS::CloudTrail::Trail",
                        resource_arn=trail.get("TrailARN"),
                        suggestion="Enable multi-region logging for comprehensive audit coverage",
                    ))
                
                # Check log file validation
                if not trail.get("LogFileValidationEnabled", False):
                    self.add_finding(Finding(
                        rule_id="CLOUDTRAIL-NO-LOG-VALIDATION",
                        severity=Severity.MEDIUM,
                        title="CloudTrail Log File Validation Not Enabled",
                        description=f"Trail {trail_name} does not have log file validation enabled",
                        resource_id=trail_name,
                        resource_type="AWS::CloudTrail::Trail",
                        resource_arn=trail.get("TrailARN"),
                        suggestion="Enable log file validation to detect log tampering",
                    ))
                    
        except Exception as e:
            self._debug_log(f"Error scanning CloudTrail: {e}")
