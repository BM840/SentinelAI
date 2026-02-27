"""
SentinelAI - Agent H: Weak Cryptography Detector
Detects use of deprecated, broken, or weak cryptographic algorithms
and insecure random number generation.
"""
import ast
import re
from typing import List
from core.models import Finding, Severity
from core.ingestion import FileAnalysis


# Weak hash algorithms
WEAK_HASH_ALGORITHMS = {
    "md5":    (Severity.HIGH,   "MD5 is cryptographically broken and should not be used for security purposes.", "CWE-327"),
    "sha1":   (Severity.HIGH,   "SHA-1 is deprecated and collision attacks have been demonstrated.", "CWE-327"),
    "sha":    (Severity.HIGH,   "SHA (SHA-0) is cryptographically broken.", "CWE-327"),
    "md4":    (Severity.CRITICAL,"MD4 is completely broken.", "CWE-327"),
    "rc4":    (Severity.CRITICAL,"RC4 has multiple critical vulnerabilities and is banned by RFC 7465.", "CWE-327"),
    "des":    (Severity.CRITICAL,"DES uses a 56-bit key which is trivially brute-forceable.", "CWE-326"),
    "3des":   (Severity.HIGH,   "Triple DES (3DES) is deprecated and vulnerable to Sweet32 attacks.", "CWE-326"),
    "blowfish":(Severity.MEDIUM, "Blowfish has a 64-bit block size making it vulnerable to birthday attacks.", "CWE-326"),
}

# Weak random patterns (non-cryptographic)
WEAK_RANDOM_PATTERNS = [
    (r'\brandom\.random\(\)',
     "Insecure Random - random.random()",
     "random.random() is not cryptographically secure. Predictable in security contexts.",
     Severity.MEDIUM, "CWE-338"),
    (r'\brandom\.randint\b',
     "Insecure Random - random.randint()",
     "random.randint() is not cryptographically secure. Do not use for tokens, keys, or passwords.",
     Severity.MEDIUM, "CWE-338"),
    (r'\brandom\.choice\b',
     "Insecure Random - random.choice()",
     "random.choice() is not cryptographically secure. Use secrets.choice() instead.",
     Severity.MEDIUM, "CWE-338"),
    (r'\brandom\.shuffle\b',
     "Insecure Random - random.shuffle()",
     "random.shuffle() is not cryptographically secure for security-sensitive shuffling.",
     Severity.LOW, "CWE-338"),
    (r'\bnumpy\.random\b',
     "Insecure Random - numpy.random",
     "numpy.random is not cryptographically secure. Use secrets module instead.",
     Severity.MEDIUM, "CWE-338"),
]

# Weak cipher mode patterns
WEAK_CIPHER_PATTERNS = [
    (r'AES\.new\(.*MODE_ECB',
     "AES-ECB Mode Used",
     "ECB (Electronic Codebook) mode is insecure. It does not provide semantic security — identical plaintext blocks produce identical ciphertext.",
     Severity.HIGH, "CWE-327"),
    (r'(?i)mode\s*=\s*["\']?ecb["\']?',
     "ECB Cipher Mode",
     "ECB mode is deterministic and reveals patterns in plaintext. Use CBC, GCM, or CTR mode.",
     Severity.HIGH, "CWE-327"),
    (r'Cipher\.new\(.*DES\b',
     "DES Cipher Used",
     "DES is cryptographically broken with a 56-bit key size.",
     Severity.CRITICAL, "CWE-326"),
    (r'padding\s*=\s*PKCS1v15|PKCS1_v1_5',
     "Weak RSA Padding (PKCS#1 v1.5)",
     "PKCS#1 v1.5 padding is vulnerable to Bleichenbacher attacks. Use OAEP padding.",
     Severity.HIGH, "CWE-780"),
]

# Insecure SSL/TLS patterns
TLS_PATTERNS = [
    (r'ssl\.PROTOCOL_SSLv2',
     "SSLv2 Protocol Used",
     "SSLv2 is completely broken and deprecated. Use TLS 1.2 or higher.",
     Severity.CRITICAL, "CWE-326"),
    (r'ssl\.PROTOCOL_SSLv3',
     "SSLv3 Protocol Used",
     "SSLv3 is vulnerable to the POODLE attack. Use TLS 1.2 or higher.",
     Severity.CRITICAL, "CWE-326"),
    (r'ssl\.PROTOCOL_TLSv1\b',
     "TLS 1.0 Protocol Used",
     "TLS 1.0 is deprecated and vulnerable to BEAST and POODLE attacks.",
     Severity.HIGH, "CWE-326"),
    (r'verify\s*=\s*False',
     "SSL Certificate Verification Disabled",
     "Disabling SSL certificate verification exposes the app to man-in-the-middle attacks.",
     Severity.CRITICAL, "CWE-295"),
    (r'check_hostname\s*=\s*False',
     "SSL Hostname Verification Disabled",
     "Disabling hostname verification allows connections to servers with invalid certificates.",
     Severity.HIGH, "CWE-295"),
    (r'CERT_NONE',
     "SSL Certificate Validation Disabled (CERT_NONE)",
     "ssl.CERT_NONE disables all certificate validation, enabling MITM attacks.",
     Severity.CRITICAL, "CWE-295"),
]


class WeakCryptographyDetector:
    """Agent H: Detects weak or broken cryptographic implementations."""

    AGENT_NAME = "Agent H - Cryptography Auditor"

    def analyze(self, analyses: List[FileAnalysis]) -> List[Finding]:
        findings = []
        for analysis in analyses:
            findings.extend(self._scan_weak_hashes(analysis))
            findings.extend(self._scan_weak_random(analysis))
            findings.extend(self._scan_weak_ciphers(analysis))
            findings.extend(self._scan_tls_issues(analysis))
            findings.extend(self._scan_hardcoded_iv_key(analysis))
        return findings

    def _scan_weak_hashes(self, analysis: FileAnalysis) -> List[Finding]:
        findings = []
        lines = analysis.source_code.splitlines()

        for lineno, line in enumerate(lines, 1):
            # Check hashlib usage: hashlib.md5(), hashlib.sha1()
            match = re.search(r'hashlib\.(\w+)\s*\(', line, re.IGNORECASE)
            if match:
                algo = match.group(1).lower()
                if algo in WEAK_HASH_ALGORITHMS:
                    severity, desc, cwe = WEAK_HASH_ALGORITHMS[algo]
                    findings.append(Finding(
                        agent=self.AGENT_NAME,
                        title=f"Weak Hash Algorithm: {algo.upper()}",
                        description=desc,
                        severity=severity,
                        filepath=analysis.filepath,
                        lineno=lineno,
                        code_snippet=line.strip(),
                        recommendation=(
                            f"Replace {algo.upper()} with SHA-256 or SHA-3 for general hashing.\n"
                            f"For passwords, use bcrypt, argon2, or PBKDF2 via passlib:\n"
                            f"  from passlib.hash import bcrypt\n"
                            f"  hashed = bcrypt.hash(password)"
                        ),
                        cwe_id=cwe
                    ))

            # Check use_md5, md5_hash style calls
            for algo, (severity, desc, cwe) in WEAK_HASH_ALGORITHMS.items():
                if re.search(rf'\b{algo}\b', line, re.IGNORECASE):
                    if "hashlib" not in line:  # avoid double reporting
                        findings.append(Finding(
                            agent=self.AGENT_NAME,
                            title=f"Possible Weak Hash: {algo.upper()}",
                            description=f"Reference to '{algo}' detected. {desc}",
                            severity=Severity.LOW,
                            filepath=analysis.filepath,
                            lineno=lineno,
                            code_snippet=line.strip(),
                            recommendation=f"Verify this is not used for security-sensitive hashing. Replace with SHA-256 or better.",
                            cwe_id=cwe
                        ))
                    break

        return findings

    def _scan_weak_random(self, analysis: FileAnalysis) -> List[Finding]:
        findings = []
        lines = analysis.source_code.splitlines()

        # Only flag if random is imported
        if "import random" not in analysis.source_code:
            return findings

        # Check if used near security-sensitive context
        security_context = any(kw in analysis.source_code.lower() for kw in
                               ["token", "password", "secret", "key", "auth", "session", "otp"])

        for lineno, line in enumerate(lines, 1):
            for pattern, title, desc, severity, cwe in WEAK_RANDOM_PATTERNS:
                if re.search(pattern, line):
                    # Elevate severity if in security context
                    actual_severity = Severity.HIGH if security_context else severity
                    findings.append(Finding(
                        agent=self.AGENT_NAME,
                        title=title,
                        description=desc + (" [[!] Security-sensitive context detected]" if security_context else ""),
                        severity=actual_severity,
                        filepath=analysis.filepath,
                        lineno=lineno,
                        code_snippet=line.strip(),
                        recommendation=(
                            "Use the 'secrets' module for cryptographically secure randomness:\n"
                            "  import secrets\n"
                            "  token = secrets.token_hex(32)       # random hex string\n"
                            "  token = secrets.token_urlsafe(32)   # URL-safe token\n"
                            "  choice = secrets.choice(my_list)    # secure random choice"
                        ),
                        cwe_id=cwe
                    ))
                    break

        return findings

    def _scan_weak_ciphers(self, analysis: FileAnalysis) -> List[Finding]:
        findings = []
        lines = analysis.source_code.splitlines()

        for lineno, line in enumerate(lines, 1):
            for pattern, title, desc, severity, cwe in WEAK_CIPHER_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        agent=self.AGENT_NAME,
                        title=title,
                        description=desc,
                        severity=severity,
                        filepath=analysis.filepath,
                        lineno=lineno,
                        code_snippet=line.strip(),
                        recommendation=(
                            "Use AES-256 in GCM mode for authenticated encryption:\n"
                            "  from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
                            "  key = AESGCM.generate_key(bit_length=256)\n"
                            "  aesgcm = AESGCM(key)\n"
                            "  ciphertext = aesgcm.encrypt(nonce, data, aad)"
                        ),
                        cwe_id=cwe
                    ))
                    break

        return findings

    def _scan_tls_issues(self, analysis: FileAnalysis) -> List[Finding]:
        findings = []
        lines = analysis.source_code.splitlines()

        for lineno, line in enumerate(lines, 1):
            for pattern, title, desc, severity, cwe in TLS_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        agent=self.AGENT_NAME,
                        title=title,
                        description=desc,
                        severity=severity,
                        filepath=analysis.filepath,
                        lineno=lineno,
                        code_snippet=line.strip(),
                        recommendation=(
                            "Use ssl.PROTOCOL_TLS_CLIENT with ssl.create_default_context():\n"
                            "  import ssl\n"
                            "  ctx = ssl.create_default_context()\n"
                            "  # This enforces TLS 1.2+, certificate verification, and hostname checking"
                        ),
                        cwe_id=cwe
                    ))
                    break

        return findings

    def _scan_hardcoded_iv_key(self, analysis: FileAnalysis) -> List[Finding]:
        """Detect hardcoded IVs and encryption keys."""
        findings = []
        lines = analysis.source_code.splitlines()

        iv_key_patterns = [
            (r'(?i)iv\s*=\s*b?["\'][^"\']{8,}["\']',
             "Hardcoded Initialization Vector (IV)",
             "Hardcoded IVs are reused across encryptions, making ciphertext predictable.",
             Severity.HIGH, "CWE-329"),
            (r'(?i)nonce\s*=\s*b?["\'][^"\']{8,}["\']',
             "Hardcoded Nonce",
             "Nonces must be unique per encryption. Hardcoded nonces defeat this requirement.",
             Severity.HIGH, "CWE-329"),
            (r'(?i)(encryption_key|enc_key|aes_key|cipher_key)\s*=\s*b?["\'][^"\']{8,}["\']',
             "Hardcoded Encryption Key",
             "Hardcoded encryption keys in source code are exposed to anyone with code access.",
             Severity.CRITICAL, "CWE-321"),
        ]

        for lineno, line in enumerate(lines, 1):
            for pattern, title, desc, severity, cwe in iv_key_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        agent=self.AGENT_NAME,
                        title=title,
                        description=desc,
                        severity=severity,
                        filepath=analysis.filepath,
                        lineno=lineno,
                        code_snippet=line.strip(),
                        recommendation=(
                            "Generate IVs/nonces randomly for each encryption:\n"
                            "  import os\n"
                            "  iv = os.urandom(16)    # 128-bit random IV\n"
                            "  nonce = os.urandom(12) # 96-bit random nonce for GCM\n"
                            "Store encryption keys in environment variables or a key management service."
                        ),
                        cwe_id=cwe
                    ))
                    break

        return findings
