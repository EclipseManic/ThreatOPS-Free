# ThreatOps SIEM - Complete Troubleshooting & Solutions Guide

**Project:** ThreatOps SIEM (5-File Architecture)  
**Entry Point:** `run.py` (Single command for everything)  
**Last Deep Analysis:** November 6, 2025

**IMPORTANT:** This guide provides DETAILED, step-by-step solutions for EVERY issue found through deep code analysis.

---

## 📋 TABLE OF CONTENTS

### CRITICAL ISSUES - FIX IMMEDIATELY
1. [Hardcoded Windows Paths in run.py](#1-hardcoded-windows-paths-in-runpy)
2. [Missing models/ Directory](#2-missing-models-directory)
3. [OpenSearch Security Configuration Mismatch](#3-opensearch-security-configuration-mismatch)
4. [No Error Handling in OpenSearch Connections](#4-no-error-handling-in-opensearch-connections)
5. [Platform-Specific Code (Windows Only)](#5-platform-specific-code-windows-only)

### CONFIGURATION ISSUES
6. [Missing .env File or Empty API Keys](#6-missing-env-file-or-empty-api-keys)
7. [OpenSearch Not Running](#7-opensearch-not-running)
8. [Filebeat Not Configured Properly](#8-filebeat-not-configured-properly)
9. [Missing Python Dependencies](#9-missing-python-dependencies)
10. [Data Directories Not Created](#10-data-directories-not-created)

### CODE-LEVEL ISSUES  
11. [Async/Await Without Proper Error Handling](#11-asyncawait-without-proper-error-handling)
12. [Memory Leaks in Continuous Mode](#12-memory-leaks-in-continuous-mode)
13. [No Input Validation](#13-no-input-validation)
14. [Hardcoded Timeouts and Intervals](#14-hardcoded-timeouts-and-intervals)
15. [Missing Type Hints](#15-missing-type-hints)

### EXTERNAL SERVICES ISSUES
16. [OpenSearch Index Templates Missing](#16-opensearch-index-templates-missing)
17. [Filebeat Data Stream Issues](#17-filebeat-data-stream-issues)
18. [OpenSearch Dashboards Login Loop](#18-opensearch-dashboards-login-loop)
19. [Port Conflicts (8501, 9200, 5601)](#19-port-conflicts-8501-9200-5601)
20. [Java Heap Size Too Small for OpenSearch](#20-java-heap-size-too-small-for-opensearch)

### RUNTIME & PERFORMANCE
21. [Dashboard Loading Very Slow](#21-dashboard-loading-very-slow)
22. [No Logs Appearing in OpenSearch](#22-no-logs-appearing-in-opensearch)
23. [No Alerts Being Generated](#23-no-alerts-being-generated)
24. [ML Model Not Training](#24-ml-model-not-training)
25. [Threat Intel APIs Rate Limited](#25-threat-intel-apis-rate-limited)

### TESTING & DEPLOYMENT
26. [Tests Failing - Import Errors](#26-tests-failing---import-errors)
27. [Tests Failing - Fixtures Not Found](#27-tests-failing---fixtures-not-found)
28. [Log Files Growing Too Large](#28-log-files-growing-too-large)
30. [Dependencies Version Conflicts](#30-dependencies-version-conflicts)

---

# CRITICAL ISSUES - FIX IMMEDIATELY

## 1. Hardcoded Windows Paths in run.py

### ❌ Problem (CRITICAL - BREAKS ON MAC/LINUX)

**File:** `run.py`  
**Lines:** 183-185

The code has hardcoded Windows paths:

```python
OPENSEARCH_BIN = Path(r"D:\Cusor AI\opensearch-3.3.1-windows-x64\opensearch-3.3.1\bin\opensearch.bat")
FILEBEAT_EXE = Path(r"D:\Cusor AI\filebeat-9.2.0-windows-x86_64\filebeat-9.2.0-windows-x86_64\filebeat.exe")
DASHBOARDS_BIN = Path(r"D:\Cusor AI\opensearch-dashboards-3.3.0\bin\opensearch-dashboards.bat")
```

**Impact:**
- ❌ Code ONLY works on ONE specific Windows machine
- ❌ Completely broken on Mac/Linux
- ❌ Broken on different Windows installations
- ❌ Won't work after moving to different directory

### ✅ Solution - DETAILED FIX

#### Option A: Use Environment Variables (RECOMMENDED)

**Step 1:** Create environment variables file

Edit your `.env` file (in project root):

```bash
# Add these lines to .env
OPENSEARCH_HOME=/path/to/opensearch-3.3.1
FILEBEAT_HOME=/path/to/filebeat-9.2.0
DASHBOARDS_HOME=/path/to/opensearch-dashboards-3.3.0
```

**Example for Windows:**
```env
OPENSEARCH_HOME=D:\Cusor AI\opensearch-3.3.1-windows-x64\opensearch-3.3.1
FILEBEAT_HOME=D:\Cusor AI\filebeat-9.2.0-windows-x86_64\filebeat-9.2.0-windows-x86_64
DASHBOARDS_HOME=D:\Cusor AI\opensearch-dashboards-3.3.0
```

**Example for Mac/Linux:**
```env
OPENSEARCH_HOME=/Users/username/opensearch-3.3.1
FILEBEAT_HOME=/Users/username/filebeat-9.2.0-darwin-x86_64
DASHBOARDS_HOME=/Users/username/opensearch-dashboards-3.3.0
```

**Step 2:** Modify `run.py`

Open `run.py` and find lines 183-185. Replace this section:

```python
# OLD CODE (LINES 183-185) - DELETE THIS:
OPENSEARCH_BIN = Path(r"D:\Cusor AI\opensearch-3.3.1-windows-x64\opensearch-3.3.1\bin\opensearch.bat")
FILEBEAT_EXE = Path(r"D:\Cusor AI\filebeat-9.2.0-windows-x86_64\filebeat-9.2.0-windows-x86_64\filebeat.exe")
DASHBOARDS_BIN = Path(r"D:\Cusor AI\opensearch-dashboards-3.3.0\bin\opensearch-dashboards.bat")
```

With this new code:

```python
# NEW CODE - PASTE THIS:
import os
import platform

# Detect operating system
IS_WINDOWS = platform.system() == "Windows"
IS_MAC = platform.system() == "Darwin"
IS_LINUX = platform.system() == "Linux"

# Get installation paths from environment variables
OPENSEARCH_HOME = os.getenv("OPENSEARCH_HOME")
FILEBEAT_HOME = os.getenv("FILEBEAT_HOME")
DASHBOARDS_HOME = os.getenv("DASHBOARDS_HOME")

# Build platform-specific paths
if OPENSEARCH_HOME:
    opensearch_base = Path(OPENSEARCH_HOME)
    if IS_WINDOWS:
        OPENSEARCH_BIN = opensearch_base / "bin" / "opensearch.bat"
    else:
        OPENSEARCH_BIN = opensearch_base / "bin" / "opensearch"
else:
    OPENSEARCH_BIN = None
    logger.warning("OPENSEARCH_HOME not set in environment")

if FILEBEAT_HOME:
    filebeat_base = Path(FILEBEAT_HOME)
    if IS_WINDOWS:
        FILEBEAT_EXE = filebeat_base / "filebeat.exe"
    else:
        FILEBEAT_EXE = filebeat_base / "filebeat"
else:
    FILEBEAT_EXE = None
    logger.warning("FILEBEAT_HOME not set in environment")

if DASHBOARDS_HOME:
    dashboards_base = Path(DASHBOARDS_HOME)
    if IS_WINDOWS:
        DASHBOARDS_BIN = dashboards_base / "bin" / "opensearch-dashboards.bat"
    else:
        DASHBOARDS_BIN = dashboards_base / "bin" / "opensearch-dashboards"
else:
    DASHBOARDS_BIN = None
    logger.warning("DASHBOARDS_HOME not set in environment")
```

**Step 3:** Update the service startup code

Find lines 191-210 in `run.py` and update the error checking:

```python
# OLD CODE - Around line 191
if OPENSEARCH_BIN.exists():

# NEW CODE - Replace with better checking:
if OPENSEARCH_BIN and OPENSEARCH_BIN.exists():
    try:
        # Platform-specific process creation
        if IS_WINDOWS:
            proc = subprocess.Popen(
                [str(OPENSEARCH_BIN)],
                cwd=str(OPENSEARCH_BIN.parent),
                creationflags=subprocess.CREATE_NEW_CONSOLE
            )
        else:
            # Mac/Linux: Run in background
            proc = subprocess.Popen(
                [str(OPENSEARCH_BIN)],
                cwd=str(OPENSEARCH_BIN.parent),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        processes.append(('OpenSearch', proc))
        logger.info("✓ OpenSearch started")
    except Exception as e:
        logger.error(f"✗ Failed to start OpenSearch: {e}")
else:
    logger.error("✗ OpenSearch binary not found or OPENSEARCH_HOME not set")
    logger.error("  Set OPENSEARCH_HOME in .env file")
```

Do the same for Filebeat and Dashboards sections.

**Step 4:** Test the fix

```bash
# Set environment variables
export OPENSEARCH_HOME=/path/to/opensearch
export FILEBEAT_HOME=/path/to/filebeat
export DASHBOARDS_HOME=/path/to/dashboards

# Or on Windows:
set OPENSEARCH_HOME=C:\path\to\opensearch
set FILEBEAT_HOME=C:\path\to\filebeat
set DASHBOARDS_HOME=C:\path\to\dashboards

# Run the application
python run.py --all
```

#### Option B: Auto-Detect Installation (ADVANCED)

Add this function to `run.py` before `start_services()`:

```python
def find_service_binary(service_name: str) -> Optional[Path]:
    """Auto-detect service installation location"""
    import platform
    import shutil
    
    system = platform.system()
    
    # Common installation paths by OS
    if system == "Windows":
        search_paths = [
            Path("C:/Program Files"),
            Path("D:/"),
            Path.home() / "Downloads",
            Path(__file__).parent.parent
        ]
        if service_name == "opensearch":
            patterns = ["opensearch*/bin/opensearch.bat"]
        elif service_name == "filebeat":
            patterns = ["filebeat*/filebeat.exe"]
        elif service_name == "dashboards":
            patterns = ["opensearch-dashboards*/bin/opensearch-dashboards.bat"]
    else:  # Mac/Linux
        search_paths = [
            Path("/usr/local"),
            Path("/opt"),
            Path.home(),
            Path(__file__).parent.parent
        ]
        if service_name == "opensearch":
            patterns = ["opensearch*/bin/opensearch"]
        elif service_name == "filebeat":
            patterns = ["filebeat*/filebeat"]
        elif service_name == "dashboards":
            patterns = ["opensearch-dashboards*/bin/opensearch-dashboards"]
    
    # Search for binary
    for base_path in search_paths:
        if not base_path.exists():
            continue
        for pattern in patterns:
            matches = list(base_path.glob(pattern))
            if matches:
                return matches[0]
    
    return None

# Then use it in start_services():
OPENSEARCH_BIN = find_service_binary("opensearch")
FILEBEAT_EXE = find_service_binary("filebeat")
DASHBOARDS_BIN = find_service_binary("dashboards")
```

### ✅ Verification

After applying the fix:

```bash
# Test that paths are detected
python -c "from run import OPENSEARCH_BIN, FILEBEAT_EXE, DASHBOARDS_BIN; print(f'OpenSearch: {OPENSEARCH_BIN}'); print(f'Filebeat: {FILEBEAT_EXE}'); print(f'Dashboards: {DASHBOARDS_BIN}')"

# Should output actual paths, not "None"
```

---

## 2. Missing models/ Directory

### ❌ Problem (CRITICAL - CAUSES CRASHES)

**Files Affected:**
- `core_detection.py` (lines 815-816, 847-850, 956-958)
- `utilities.py` (lines 508, 612)

The code tries to load ML models from `models/` directory:

```python
self.model_path = self.models_dir / "model.joblib"
self.scaler_path = self.models_dir / "scaler.joblib"
```

But this directory **DOES NOT EXIST** in the project!

**Impact:**
- ❌ `FileNotFoundError` when trying to run detection
- ❌ ML anomaly detection completely broken
- ❌ Application crashes on startup if ML is enabled

### ✅ Solution - DETAILED FIX

#### Step 1: Create the models/ directory

```bash
cd "/Users/kaushalyadav/Desktop/Cusor AI/threat_ops"
mkdir -p models
chmod 755 models
```

#### Step 2: Add model directory creation to application startup

Edit `application.py`, find the `create_directories()` function (around line 290) and add:

```python
def create_directories():
    """Create required directories if they don't exist"""
    directories = [
        'data',
        'data/logs',
        'data/alerts',
        'data/simulations',
        'data/sample_logs',
        'data/reports',  
        'logs',
        'models',  # <-- ADD THIS LINE
        'reports'
    ]
    
    for directory in directories:
        path = Path(directory)
        if not path.exists():
            path.mkdir(parents=True, exist_ok=True)
            logger.info(f"✓ Created directory: {directory}")
```

#### Step 3: Add model existence checking

Edit `core_detection.py`, find the `MLDetector` class initialization (around line 820):

```python
# ADD THIS METHOD to MLDetector class (around line 850):
def _check_model_exists(self) -> bool:
    """Check if trained model exists"""
    if self.model_path.exists() and (not self.use_scaler or self.scaler_path.exists()):
        return True
    return False

# MODIFY the initialize method (around line 860):
async def initialize(self):
    """Initialize the ML detector"""
    self.models_dir.mkdir(parents=True, exist_ok=True)  # <-- ADD THIS LINE
    
    # Load model if exists
    if self._check_model_exists():  # <-- CHANGE THIS LINE
        try:
            import joblib
            self.model = joblib.load(self.model_path)
            logger.info(f"✓ Loaded ML model from {self.model_path}")
            if self.use_scaler and self.scaler_path.exists():
                self.scaler = joblib.load(self.scaler_path)
                logger.info(f"✓ Loaded scaler from {self.scaler_path}")
        except Exception as e:
            logger.error(f"✗ Failed to load model: {e}")
            logger.warning("  Will train new model on first detection run")
            self.model = None  # <-- ADD THIS LINE
    else:
        logger.warning(f"✗ No trained model found at {self.model_path}")
        logger.warning("  Run 'python run.py --train' to train the model")
        logger.warning("  ML detection will be disabled until model is trained")
        self.model = None  # <-- ADD THIS LINE
```

#### Step 4: Train the initial model

```bash
# Train the ML model
python run.py --train

# Verify model was created
ls -lh models/
# Should show: model.joblib and scaler.joblib
```

#### Step 5: Add automatic training on first run (OPTIONAL)

Edit `core_detection.py`, add this to `MLDetector` class:

```python
async def auto_train_if_needed(self, logs: List[LogEntry]):
    """Automatically train model if it doesn't exist"""
    if self.model is None and len(logs) >= self.min_training_samples:
        logger.info(f"Auto-training model with {len(logs)} samples...")
        await self.train(logs)
        logger.info("✓ Model auto-trained successfully")
        return True
    elif self.model is None:
        logger.warning(f"Not enough samples for training (need {self.min_training_samples}, got {len(logs)})")
        return False
    return True
```

### ✅ Verification

```bash
# Check directory exists
ls -ld models/

# Train model
python run.py --train

# Check model files
ls -lh models/
# Should show:
# -rw-r--r--  1 user  staff  XXX model.joblib
# -rw-r--r--  1 user  staff  XXX scaler.joblib

# Test detection
python run.py --detect
# Should NOT crash with FileNotFoundError
```

---

## 3. OpenSearch Security Configuration Mismatch

### ❌ Problem (CRITICAL - CONNECTION FAILURES)

**Files Affected:**
- `core_detection.py` (lines 829, 1166, 1850, 2689)
- `application.py` (line 527)
- `utilities.py` (lines in setup functions)

All OpenSearch client connections are created WITHOUT authentication:

```python
self.opensearch_client = OpenSearch(
    [{'host': 'localhost', 'port': 9200}],
    timeout=30
)
```

But OpenSearch might have security ENABLED, causing:
```
opensearchpy.exceptions.AuthenticationException: [401] Unauthorized
```

### ✅ Solution - DETAILED FIX (TWO OPTIONS)

#### Option A: Disable OpenSearch Security (RECOMMENDED FOR DEVELOPMENT)

**Step 1:** Find your OpenSearch installation directory

```bash
# Find OpenSearch
find ~ -name "opensearch.yml" 2>/dev/null | head -1
# Or on Windows:
# dir opensearch.yml /s
```

**Step 2:** Edit opensearch.yml

```bash
# Mac/Linux
nano /path/to/opensearch-3.3.1/config/opensearch.yml

# Windows
notepad C:\path\to\opensearch-3.3.1\config\opensearch.yml
```

**Step 3:** Find and modify security settings

Look for lines like these:

```yaml
# OLD - Security ENABLED (causing issues):
plugins.security.disabled: false
plugins.security.ssl.http.enabled: true
plugins.security.ssl.transport.enabled: true
```

**Replace with:**

```yaml
# NEW - Security DISABLED (works with our code):
plugins.security.disabled: true

# IMPORTANT: Comment out or delete ALL other security lines:
# plugins.security.ssl.http.enabled: false
# plugins.security.ssl.transport.enabled: false
# plugins.security.allow_default_init_securityindex: false
# plugins.security.allow_unsafe_democertificates: false
```

Also ensure these settings exist:

```yaml
network.host: 0.0.0.0
http.port: 9200
discovery.type: single-node
```

**Step 4:** Restart OpenSearch

```bash
# Stop OpenSearch
# On Mac/Linux:
pkill -f opensearch

# On Windows:
# Find and kill OpenSearch process in Task Manager

# Start OpenSearch
# Mac/Linux:
/path/to/opensearch-3.3.1/bin/opensearch

# Windows:
C:\path\to\opensearch-3.3.1\bin\opensearch.bat
```

**Step 5:** Verify security is disabled

```bash
# Test connection without auth
curl http://localhost:9200

# Should return something like:
# {
#   "name" : "node-1",
#   "cluster_name" : "opensearch",
#   ...
# }

# NOT:
# {"error":"Unauthorized"}
```

**Step 6:** Also disable security in OpenSearch Dashboards

Edit `opensearch_dashboards.yml`:

```bash
# Find and edit
nano /path/to/opensearch-dashboards-3.3.0/config/opensearch_dashboards.yml
```

Comment out authentication:

```yaml
# OLD - With authentication:
opensearch.username: "admin"
opensearch.password: "admin"
opensearch.ssl.verificationMode: none

# NEW - No authentication:
opensearch.hosts: [http://localhost:9200]
# opensearch.username: "admin"  # <-- Comment out
# opensearch.password: "admin"  # <-- Comment out
opensearch.ssl.verificationMode: none
```

#### Option B: Add Authentication to Code (FOR PRODUCTION)

If you MUST keep security enabled, update ALL OpenSearch clients in the code:

**Step 1:** Set credentials in .env

```bash
# Add to .env file:
OPENSEARCH_USER=admin
OPENSEARCH_PASSWORD=admin
```

**Step 2:** Update `core_detection.py`

Find ALL OpenSearch client creations (lines 829, 1166, 1850, 2689) and replace:

```python
# OLD CODE:
self.opensearch_client = OpenSearch(
    [{'host': 'localhost', 'port': 9200}],
    timeout=30
)

# NEW CODE:
import os
self.opensearch_client = OpenSearch(
    [{'host': 'localhost', 'port': 9200}],
    http_auth=(
        os.getenv('OPENSEARCH_USER', 'admin'),
        os.getenv('OPENSEARCH_PASSWORD', 'admin')
    ),
    use_ssl=False,
    verify_certs=False,
    ssl_show_warn=False,
    timeout=30
)
```

**Step 3:** Update `application.py`

Find line 527 and update similarly:

```python
# Around line 527
client = OpenSearch(
    [{'host': settings.opensearch_host, 'port': settings.opensearch_port}],
    http_auth=(
        os.getenv('OPENSEARCH_USER', 'admin'),
        os.getenv('OPENSEARCH_PASSWORD', 'admin')
    ),
    use_ssl=False,
    verify_certs=False,
    ssl_show_warn=False
)
```

**Step 4:** Update `utilities.py`

Find the `check_connection()` function and update:

```python
def check_connection() -> bool:
    """Test connection to OpenSearch cluster."""
    try:
        import os
        auth = (
            os.getenv('OPENSEARCH_USER', 'admin'),
            os.getenv('OPENSEARCH_PASSWORD', 'admin')
        )
        response = session.get(
            f"{OPENSEARCH_HOST}/",
            auth=auth
        )
        response.raise_for_status()
        # rest of function...
```

### ✅ Verification

```bash
# Test connection
curl http://localhost:9200

# Should work without 401 error

# Test from Python
python -c "from opensearchpy import OpenSearch; es=OpenSearch([{'host':'localhost','port':9200}]); print(es.info())"

# Should NOT raise AuthenticationException
```

---

## 4. No Error Handling in OpenSearch Connections

### ❌ Problem (CAUSES CRASHES)

**Files Affected:** ALL files that use OpenSearch

The code creates OpenSearch clients but doesn't handle connection failures properly:

```python
# This will crash if OpenSearch is not running!
self.opensearch_client = OpenSearch([{'host': 'localhost', 'port': 9200}])
```

**Impact:**
- ❌ Application crashes immediately if OpenSearch is down
- ❌ No helpful error message
- ❌ Can't gracefully degrade or retry

### ✅ Solution - DETAILED FIX

#### Step 1: Create a connection helper function

Add this to `core_detection.py` at the top (after imports, around line 110):

```python
def create_opensearch_client(retries=3, retry_delay=5) -> Optional[OpenSearch]:
    """
    Create OpenSearch client with error handling and retries
    
    Args:
        retries: Number of connection attempts
        retry_delay: Seconds to wait between retries
        
    Returns:
        OpenSearch client or None if connection fails
    """
    import os
    import time
    
    host = os.getenv('OPENSEARCH_HOST', 'localhost')
    port = int(os.getenv('OPENSEARCH_PORT', '9200'))
    user = os.getenv('OPENSEARCH_USER')
    password = os.getenv('OPENSEARCH_PASSWORD')
    
    # Build connection parameters
    conn_params = {
        'hosts': [{'host': host, 'port': port}],
        'timeout': 30,
        'max_retries': 3,
        'retry_on_timeout': True
    }
    
    # Add auth if credentials provided
    if user and password:
        conn_params['http_auth'] = (user, password)
        conn_params['use_ssl'] = False
        conn_params['verify_certs'] = False
        conn_params['ssl_show_warn'] = False
    
    # Attempt connection with retries
    for attempt in range(1, retries + 1):
        try:
            client = OpenSearch(**conn_params)
            # Test connection
            info = client.info()
            logger.info(f"✓ Connected to OpenSearch cluster: {info.get('cluster_name')}")
            return client
            
        except Exception as e:
            if attempt < retries:
                logger.warning(f"Connection attempt {attempt}/{retries} failed: {e}")
                logger.info(f"Retrying in {retry_delay} seconds...")
                time.sleep(retry_delay)
            else:
                logger.error(f"✗ Failed to connect to OpenSearch after {retries} attempts")
                logger.error(f"  Error: {e}")
                logger.error(f"  Make sure OpenSearch is running on {host}:{port}")
                return None
    
    return None
```

#### Step 2: Replace all OpenSearch client creations

In `core_detection.py`, find the `MLDetector` class `__init__` method (around line 820):

```python
# OLD CODE (line ~829):
self.opensearch_client = OpenSearch(
    [{'host': 'localhost', 'port': 9200}],
    timeout=30
)

# NEW CODE:
self.opensearch_client = create_opensearch_client()
if self.opensearch_client is None:
    logger.warning("OpenSearch connection failed - ML detection may not work properly")
```

Do the same for:
- `IntelEnricher` class (around line 1166)
- `RiskScorer` class (around line 1850)
- Any other OpenSearch client creation

#### Step 3: Add connection checking before operations

In each class that uses OpenSearch, add a connection check method:

```python
def _check_opensearch_connection(self) -> bool:
    """Check if OpenSearch connection is alive"""
    try:
        if self.opensearch_client is None:
            return False
        self.opensearch_client.ping()
        return True
    except Exception as e:
        logger.error(f"OpenSearch connection check failed: {e}")
        return False

# Then use it before operations:
async def detect(self, index_pattern="filebeat-*", max_logs=1000):
    """Detect threats from OpenSearch"""
    if not self._check_opensearch_connection():
        logger.error("Cannot detect threats - OpenSearch connection not available")
        return []
    
    # ... rest of detection code
```

#### Step 4: Add reconnection logic

Add this method to classes that use OpenSearch:

```python
def _reconnect_opensearch(self):
    """Attempt to reconnect to OpenSearch"""
    logger.info("Attempting to reconnect to OpenSearch...")
    self.opensearch_client = create_opensearch_client(retries=3, retry_delay=5)
    return self.opensearch_client is not None
```

#### Step 5: Wrap operations in try/except

Example for the `detect` method:

```python
async def detect(self, index_pattern="filebeat-*", max_logs=1000):
    """Detect threats from OpenSearch with error handling"""
    try:
        if not self._check_opensearch_connection():
            # Try to reconnect
            if not self._reconnect_opensearch():
                logger.error("Cannot detect threats - OpenSearch unavailable")
                return []
        
        # Query OpenSearch
        query = {
            "size": max_logs,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {"match_all": {}}
        }
        
        response = self.opensearch_client.search(
            index=index_pattern,
            body=query
        )
        
        # Process results...
        
    except opensearchpy.exceptions.ConnectionError as e:
        logger.error(f"OpenSearch connection error: {e}")
        logger.error("Make sure OpenSearch is running and accessible")
        return []
    except opensearchpy.exceptions.RequestError as e:
        logger.error(f"OpenSearch request error: {e}")
        logger.error("Check if the index exists and query is valid")
        return []
    except Exception as e:
        logger.error(f"Unexpected error during detection: {e}")
        logger.exception("Full traceback:")
        return []
```

### ✅ Verification

```bash
# Test with OpenSearch running
python run.py --detect
# Should work normally

# Test with OpenSearch stopped
# Stop OpenSearch first
python run.py --detect
# Should show graceful error, NOT crash with traceback

# Check logs
tail -f logs/threat_ops.log
# Should show clear error messages, not crash dumps
```

---

## 5. Platform-Specific Code (Windows Only)

### ❌ Problem (BREAKS ON MAC/LINUX)

**File:** `run.py`  
**Lines:** 196, 219, 242, 285

The code uses Windows-specific flags:

```python
creationflags=subprocess.CREATE_NEW_CONSOLE  # Only works on Windows!
```

**Impact:**
- ❌ Crashes on Mac/Linux with AttributeError
- ❌ Code won't run on non-Windows systems
- ❌ Hard to test in cross-platform environments

### ✅ Solution - DETAILED FIX

Replace ALL subprocess.Popen calls with platform detection:

```python
import platform
import subprocess

IS_WINDOWS = platform.system() == "Windows"

# When starting processes, use this pattern:
if IS_WINDOWS:
    proc = subprocess.Popen(
        [str(binary_path)],
        cwd=str(working_dir),
        creationflags=subprocess.CREATE_NEW_CONSOLE
    )
else:
    # Mac/Linux: Run in background
    proc = subprocess.Popen(
        [str(binary_path)],
        cwd=str(working_dir),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True  # Unix equivalent
    )
```

Apply this to lines:
- 196 (OpenSearch startup)
- 219 (Filebeat startup) 
- 242 (Dashboards startup)
- 285 (Streamlit dashboard startup)

---

# CONFIGURATION ISSUES

## 6. Missing .env File or Empty API Keys

### ❌ Problem (LIMITS FUNCTIONALITY)

**File:** `application.py` (lines 169, 174, 179)

The code expects API keys from environment variables:

```python
api_key=os.getenv("VIRUSTOTAL_API_KEY")
api_key=os.getenv("ABUSEIPDB_API_KEY")
api_key=os.getenv("OTX_API_KEY")
```

But .env file might not exist or keys might be empty.

**Impact:**
- ⚠️ Threat intelligence enrichment won't work
- ⚠️ Limited detection capabilities
- ⚠️ No external reputation checks

### ✅ Solution - DETAILED FIX

#### Step 1: Create .env file template

```bash
cd "/Users/kaushalyadav/Desktop/Cusor AI/threat_ops"
cat > .env << 'EOF'
# ThreatOps SIEM - Environment Configuration
# Copy this template and fill in your actual values

# ============================================================================
# OPENSEARCH CONFIGURATION
# ============================================================================
OPENSEARCH_HOST=localhost
OPENSEARCH_PORT=9200
# Leave empty if security is disabled:
OPENSEARCH_USER=
OPENSEARCH_PASSWORD=

# ============================================================================
# SERVICE LOCATIONS
# ============================================================================
# Update these paths to match your installation
# Windows example: D:\Cusor AI\opensearch-3.3.1
# Mac/Linux example: /Users/username/opensearch-3.3.1

OPENSEARCH_HOME=
FILEBEAT_HOME=
DASHBOARDS_HOME=

# ============================================================================
# THREAT INTELLIGENCE APIs (Optional but Recommended)
# ============================================================================

# VirusTotal API Key
# Get free key at: https://www.virustotal.com/gui/join-us
# Free tier: 4 requests/minute, 500/day
VIRUSTOTAL_API_KEY=

# AbuseIPDB API Key  
# Get free key at: https://www.abuseipdb.com/register
# Free tier: 1000 checks/day
ABUSEIPDB_API_KEY=

# AlienVault OTX API Key
# Get free key at: https://otx.alienvault.com/
# Free tier: Unlimited
OTX_API_KEY=

# ============================================================================
# EMAIL NOTIFICATIONS (Optional)
# ============================================================================
EMAIL_ENABLED=false
EMAIL_FROM=threatops@yourcompany.com
EMAIL_TO=security@yourcompany.com
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USE_TLS=true
SMTP_USER=
SMTP_PASSWORD=

# ============================================================================
# SLACK NOTIFICATIONS (Optional)
# ============================================================================
SLACK_ENABLED=false
# Create webhook at: https://api.slack.com/messaging/webhooks
SLACK_WEBHOOK_URL=

# ============================================================================
# PAGERDUTY INTEGRATION (Optional)
# ============================================================================
PAGERDUTY_ENABLED=false
PAGERDUTY_INTEGRATION_KEY=

# ============================================================================
# ADVANCED SETTINGS
# ============================================================================
DEBUG_MODE=false
LOG_LEVEL=INFO  # DEBUG, INFO, WARNING, ERROR, CRITICAL
MAX_LOG_SIZE_MB=100
LOG_RETENTION_DAYS=30

# ML Model Settings
ML_ENABLED=true
ML_CONTAMINATION=0.1
ML_MIN_SAMPLES=1000

# Detection Settings
DETECTION_INTERVAL=60  # seconds
ALERT_THRESHOLD=5  # minimum severity
AUTO_RESPONSE_ENABLED=false

EOF
```

#### Step 2: Update application.py to handle missing keys

Edit `application.py`, find the APIConfig section (around line 165) and add validation:

```python
# Add this new function before Settings class:
def validate_api_config(config: APIConfig) -> APIConfig:
    """Validate and warn about missing API keys"""
    if config.enabled and not config.api_key:
        logger.warning(f"API {config.name} is enabled but API key is missing")
        logger.warning(f"  Set {config.name.upper()}_API_KEY in .env file")
        logger.warning(f"  Or disable with: {config.name}_ENABLED=false")
        config.enabled = False  # Auto-disable if no key
    return config

# Then in Settings class (around line 165):
apis: List[APIConfig] = Field(default_factory=lambda: [
    validate_api_config(APIConfig(
        name="virustotal",
        enabled=os.getenv("VIRUSTOTAL_ENABLED", "true").lower() == "true",
        api_key=os.getenv("VIRUSTOTAL_API_KEY")
    )),
    validate_api_config(APIConfig(
        name="abuseipdb",
        enabled=os.getenv("ABUSEIPDB_ENABLED", "true").lower() == "true",
        api_key=os.getenv("ABUSEIPDB_API_KEY")
    )),
    validate_api_config(APIConfig(
        name="otx",
        enabled=os.getenv("OTX_ENABLED", "true").lower() == "true",
        api_key=os.getenv("OTX_API_KEY")
    ))
])
```

#### Step 3: Add startup check for environment variables

Add this to `run.py` at the beginning of `main()`:

```python
def check_environment():
    """Check environment variables and warn about missing ones"""
    from dotenv import load_dotenv
    import os
    
    # Load .env
    env_path = Path(__file__).parent / ".env"
    if not env_path.exists():
        logger.warning("=" * 70)
        logger.warning("NO .env FILE FOUND!")
        logger.warning("=" * 70)
        logger.warning("Create .env file in project root with:")
        logger.warning("  OPENSEARCH_HOME=/path/to/opensearch")
        logger.warning("  FILEBEAT_HOME=/path/to/filebeat")
        logger.warning("  VIRUSTOTAL_API_KEY=your_key")
        logger.warning("  (See .env.template for full example)")
        logger.warning("=" * 70)
        return False
    
    load_dotenv(env_path)
    
    # Check critical variables
    critical = ['OPENSEARCH_HOME']
    missing = [var for var in critical if not os.getenv(var)]
    
    if missing:
        logger.warning(f"Missing critical environment variables: {missing}")
        logger.warning("Update your .env file")
        return False
    
    # Check optional but recommended
    optional = ['VIRUSTOTAL_API_KEY', 'ABUSEIPDB_API_KEY', 'OTX_API_KEY']
    missing_optional = [var for var in optional if not os.getenv(var)]
    
    if missing_optional:
        logger.info(f"Optional API keys not set: {missing_optional}")
        logger.info("Threat intelligence enrichment will be limited")
    
    return True

# Add to main():
def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(...)
    args = parser.parse_args()
    
    # Setup logging
    _setup_logging()
    global logger
    logger = logging.getLogger("run")
    
    # Check environment - ADD THIS
    check_environment()
    
    # Rest of main()...
```

### ✅ Verification

```bash
# Check .env exists
ls -la .env

# Test loading
python -c "from dotenv import load_dotenv; load_dotenv('.env'); import os; print('VT:', os.getenv('VIRUSTOTAL_API_KEY', 'NOT SET'))"

# Run with environment check
python run.py --all
# Should show clear warnings about missing keys
```

---

## 7. OpenSearch Not Running

### ❌ Problem (MOST COMMON ISSUE)

Application can't connect because OpenSearch isn't started.

**Impact:**
- ❌ Complete failure to start
- ❌ Connection refused errors
- ❌ No data storage

### ✅ Solution - DETAILED FIX

#### Option A: Auto-start with the application

Already implemented in `run.py --all` mode!

#### Option B: Manual startup

**Mac/Linux:**
```bash
# Navigate to OpenSearch directory
cd /path/to/opensearch-3.3.1

# Start OpenSearch
./bin/opensearch

# Or run in background:
./bin/opensearch -d

# Check if running:
curl http://localhost:9200

# View logs:
tail -f logs/opensearch.log
```

**Windows:**
```cmd
REM Navigate to OpenSearch directory
cd C:\path\to\opensearch-3.3.1

REM Start OpenSearch
bin\opensearch.bat

REM Check if running (in new terminal):
curl http://localhost:9200
```

#### Common Startup Issues:

**Issue 1: Java not found**
```bash
# Install Java 11 or higher
# Mac:
brew install openjdk@11

# Ubuntu/Debian:
sudo apt-get install openjdk-11-jdk

# Windows:
# Download from: https://adoptium.net/
```

**Issue 2: Port 9200 already in use**
```bash
# Find what's using port 9200
# Mac/Linux:
lsof -i :9200

# Windows:
netstat -ano | findstr :9200

# Kill the process or use different port
# Edit opensearch.yml:
http.port: 9201  # Use different port
```

**Issue 3: Insufficient memory**
```bash
# Edit jvm.options
nano config/jvm.options

# Reduce heap size if you have < 8GB RAM:
-Xms2g  # Minimum heap (was 4g)
-Xmx2g  # Maximum heap (was 4g)
```

#### Create a startup script:

```bash
# Create start-opensearch.sh (Mac/Linux)
cat > start-opensearch.sh << 'EOF'
#!/bin/bash
OPENSEARCH_HOME="${OPENSEARCH_HOME:-/path/to/opensearch-3.3.1}"

cd "$OPENSEARCH_HOME"

# Check if already running
if curl -s http://localhost:9200 > /dev/null; then
    echo "OpenSearch is already running"
    exit 0
fi

# Start OpenSearch
echo "Starting OpenSearch..."
./bin/opensearch -d

# Wait for startup
echo "Waiting for OpenSearch to start..."
for i in {1..30}; do
    if curl -s http://localhost:9200 > /dev/null; then
        echo "OpenSearch started successfully!"
        exit 0
    fi
    sleep 2
done

echo "OpenSearch failed to start"
exit 1
EOF

chmod +x start-opensearch.sh
```

### ✅ Verification

```bash
# Check if running
curl http://localhost:9200

# Should return cluster info JSON, not "Connection refused"

# Check health
curl http://localhost:9200/_cluster/health?pretty

# Check processes
# Mac/Linux:
ps aux | grep opensearch

# Windows:
tasklist | findstr opensearch
```

---

## 8. Filebeat Not Configured Properly

### ❌ Problem (NO LOGS COLLECTED)

**Filebeat Configuration Issues:**
- Path to log files doesn't match actual location
- Output to OpenSearch not configured correctly
- Index name pattern conflicts with OpenSearch templates
- Filebeat service not starting

**Impact:**
- ❌ No logs reach OpenSearch
- ❌ Detection engine has nothing to analyze
- ❌ Dashboard shows empty data

### ✅ Solution - DETAILED FIX

#### Step 1: Locate Filebeat configuration

```bash
# Find filebeat.yml
find ~ -name "filebeat.yml" 2>/dev/null | grep -v ".venv"

# Typical locations:
# Windows: C:\path\to\filebeat-9.2.0\filebeat.yml
# Mac/Linux: /path/to/filebeat-9.2.0/filebeat.yml
```

#### Step 2: Configure complete filebeat.yml

Create or update `filebeat.yml`:

```yaml
# ============================================================================
# Filebeat Configuration for ThreatOps SIEM
# ============================================================================

# ============================================================================
# FILEBEAT INPUTS - Log Collection
# ============================================================================
filebeat.inputs:

# Simulated Attack Logs
- type: log
  enabled: true
  paths:
    # UPDATE THIS PATH to match your installation
    - /Users/kaushalyadav/Desktop/Cusor AI/threat_ops/data/sim_attacks.log
    # Windows example: D:\Cusor AI\threat_ops\data\sim_attacks.log
  
  fields:
    log_type: simulated_attack
    environment: lab
    source: threatops_simulator
  fields_under_root: true
  
  # Parse JSON logs
  json.keys_under_root: true
  json.add_error_key: true
  json.message_key: message
  
  # Multiline support for stack traces
  multiline.pattern: '^[[:space:]]'
  multiline.negate: false
  multiline.match: after

# Real Windows Security Logs (if available)
- type: log
  enabled: true
  paths:
    - /Users/kaushalyadav/Desktop/Cusor AI/threat_ops/data/sample_logs/*.log
    - /Users/kaushalyadav/Desktop/Cusor AI/threat_ops/data/sample_logs/*.json
  
  fields:
    log_type: system_logs
    environment: production
  fields_under_root: true
  
  json.keys_under_root: true
  json.add_error_key: true

# ============================================================================
# FILEBEAT PROCESSORS - Data Enrichment
# ============================================================================
processors:
  # Add timestamp
  - add_host_metadata:
      when.not.contains.tags: forwarded
  
  # Add cloud metadata if running in cloud
  - add_cloud_metadata: ~
  
  # Add Docker metadata if running in containers
  - add_docker_metadata: ~
  
  # Add custom fields
  - add_fields:
      target: ''
      fields:
        project: threatops_siem
        version: 1.0.0

# ============================================================================
# OPENSEARCH OUTPUT - Send to OpenSearch
# ============================================================================
output.opensearch:
  # OpenSearch connection
  hosts: ["localhost:9200"]
  
  # Protocol
  protocol: "http"
  
  # Authentication (if security is enabled - comment out if disabled)
  # username: "admin"
  # password: "admin"
  
  # Index settings
  index: "filebeat-%{[agent.version]}-%{+yyyy.MM.dd}"
  
  # Pipeline for log enrichment (optional)
  # pipeline: "filebeat-threatops"
  
  # Bulk settings for performance
  bulk_max_size: 50
  worker: 2
  compression_level: 3
  
  # SSL settings (if security is enabled)
  # ssl.enabled: false
  # ssl.verification_mode: none

# ============================================================================
# INDEX TEMPLATE - Schema Definition
# ============================================================================
setup.template.settings:
  index.number_of_shards: 1
  index.number_of_replicas: 0
  index.codec: best_compression

# Template name
setup.template.name: "filebeat"
setup.template.pattern: "filebeat-*"

# Overwrite existing template
setup.template.overwrite: true

# ============================================================================
# KIBANA/OPENSEARCH DASHBOARDS (Optional)
# ============================================================================
# setup.dashboards.enabled: false
# setup.kibana:
#   host: "localhost:5601"

# ============================================================================
# FILEBEAT MODULES (Optional)
# ============================================================================
filebeat.config.modules:
  path: ${path.config}/modules.d/*.yml
  reload.enabled: false

# ============================================================================
# LOGGING
# ============================================================================
logging.level: info
logging.to_files: true
logging.files:
  path: /tmp/filebeat
  name: filebeat
  keepfiles: 7
  permissions: 0644

# ============================================================================
# QUEUE SETTINGS
# ============================================================================
queue.mem:
  events: 4096
  flush.min_events: 512
  flush.timeout: 1s
```

#### Step 3: Update paths in filebeat.yml

**Find and replace paths in filebeat.yml:**

```bash
# Mac/Linux
nano /path/to/filebeat-9.2.0/filebeat.yml

# Update this section:
paths:
  - /Users/kaushalyadav/Desktop/Cusor AI/threat_ops/data/sim_attacks.log

# Windows
# notepad C:\path\to\filebeat-9.2.0\filebeat.yml
# Update:
paths:
  - D:\Cusor AI\threat_ops\data\sim_attacks.log
```

#### Step 4: Test Filebeat configuration

```bash
# Navigate to Filebeat directory
cd /path/to/filebeat-9.2.0

# Test configuration
./filebeat test config -c filebeat.yml
# Should output: Config OK

# Test output to OpenSearch
./filebeat test output -c filebeat.yml
# Should output: opensearch: http://localhost:9200...
#   parse url... OK
#   connection... OK

# Windows:
# filebeat.exe test config -c filebeat.yml
# filebeat.exe test output -c filebeat.yml
```

#### Step 5: Create systemd service (Linux) or Task Scheduler (Windows)

**Linux systemd service:**

```bash
# Create service file
sudo nano /etc/systemd/system/filebeat.service

# Add this content:
[Unit]
Description=Filebeat Log Shipper
After=network.target

[Service]
Type=simple
User=root
ExecStart=/path/to/filebeat-9.2.0/filebeat -e -c /path/to/filebeat-9.2.0/filebeat.yml
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable filebeat
sudo systemctl start filebeat

# Check status
sudo systemctl status filebeat
```

**Windows Task Scheduler:**

```powershell
# Create scheduled task (run as Administrator)
$action = New-ScheduledTaskAction -Execute 'C:\path\to\filebeat-9.2.0\filebeat.exe' -Argument '-e -c C:\path\to\filebeat-9.2.0\filebeat.yml'
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

Register-ScheduledTask -TaskName "Filebeat-ThreatOps" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "Filebeat log collection for ThreatOps SIEM"

# Start the task
Start-ScheduledTask -TaskName "Filebeat-ThreatOps"

# Check status
Get-ScheduledTask -TaskName "Filebeat-ThreatOps"
```

#### Step 6: Start Filebeat manually (for testing)

```bash
# Mac/Linux
cd /path/to/filebeat-9.2.0
./filebeat -e -c filebeat.yml

# Windows
cd C:\path\to\filebeat-9.2.0
filebeat.exe -e -c filebeat.yml

# Run in background:
# Mac/Linux
nohup ./filebeat -e -c filebeat.yml > filebeat.log 2>&1 &

# Windows (run as service or use Task Scheduler above)
```

#### Step 7: Verify Filebeat is collecting logs

```bash
# Check Filebeat logs
tail -f /path/to/filebeat-9.2.0/logs/filebeat
# Windows: type C:\path\to\filebeat-9.2.0\logs\filebeat

# Should see:
# "Harvester started for file"
# "Non-zero metrics in the last 30s"

# Check OpenSearch indices
curl "http://localhost:9200/_cat/indices?v" | grep filebeat

# Should show:
# filebeat-9.2.0-2025.11.06  ...

# Count documents
curl "http://localhost:9200/filebeat-*/_count?pretty"

# Should show increasing count
```

### ✅ Verification

```bash
# 1. Config is valid
filebeat test config -c filebeat.yml

# 2. Can connect to OpenSearch
filebeat test output -c filebeat.yml

# 3. Filebeat is running
# Mac/Linux:
ps aux | grep filebeat

# Windows:
tasklist | findstr filebeat

# 4. Logs are being collected
curl "http://localhost:9200/filebeat-*/_search?size=1&pretty"

# Should return actual log entries
```

---

## 9. Missing Python Dependencies

### ❌ Problem (IMPORT ERRORS)

**Common errors:**
```python
ModuleNotFoundError: No module named 'opensearchpy'
ModuleNotFoundError: No module named 'streamlit'
ModuleNotFoundError: No module named 'sklearn'
```

**Impact:**
- ❌ Application won't start
- ❌ Import errors on every component
- ❌ Features disabled

### ✅ Solution - DETAILED FIX

#### Step 1: Check what's missing

```bash
cd "/Users/kaushalyadav/Desktop/Cusor AI/threat_ops"

# Check installed packages
pip list

# Check specific packages
pip show opensearch-py streamlit scikit-learn pandas
```

#### Step 2: Install ALL dependencies

```bash
# Install from requirements.txt
pip install -r requirements.txt

# If you get SSL errors:
pip install --trusted-host pypi.org --trusted-host files.pythonhosted.org -r requirements.txt

# If specific packages fail, install manually:
pip install opensearch-py==2.4.0
pip install streamlit==1.28.0
pip install scikit-learn==1.3.2
pip install pandas==2.1.3
pip install numpy==1.26.2
pip install plotly==5.18.0
pip install python-dotenv==1.0.0
pip install pydantic==2.5.0
pip install requests==2.31.0
pip install aiohttp==3.9.1
pip install asyncio==3.4.3
```

#### Step 3: Verify critical dependencies

```bash
# Test imports
python << 'EOF'
try:
    import opensearchpy
    print("✓ opensearch-py:", opensearchpy.__version__)
except ImportError as e:
    print("✗ opensearch-py:", e)

try:
    import streamlit
    print("✓ streamlit:", streamlit.__version__)
except ImportError as e:
    print("✗ streamlit:", e)

try:
    import sklearn
    print("✓ scikit-learn:", sklearn.__version__)
except ImportError as e:
    print("✗ scikit-learn:", e)

try:
    import pandas
    print("✓ pandas:", pandas.__version__)
except ImportError as e:
    print("✗ pandas:", e)

try:
    import numpy
    print("✓ numpy:", numpy.__version__)
except ImportError as e:
    print("✗ numpy:", e)
EOF
```

#### Step 4: Fix version conflicts

If you see version conflicts:

```bash
# Create fresh virtual environment
python -m venv .venv_new

# Activate it
# Mac/Linux:
source .venv_new/bin/activate

# Windows:
.venv_new\Scripts\activate

# Install dependencies fresh
pip install --upgrade pip
pip install -r requirements.txt

# Test
python run.py --help
```

#### Step 5: Common dependency issues

**Issue 1: numpy/pandas incompatibility**
```bash
# Uninstall conflicting versions
pip uninstall numpy pandas -y

# Install compatible versions
pip install numpy==1.26.2
pip install pandas==2.1.3
```

**Issue 2: scikit-learn compilation errors**
```bash
# Install pre-built wheel
pip install --only-binary :all: scikit-learn
```

**Issue 3: OpenSearch SSL issues**
```bash
# Install with specific SSL library
pip install 'opensearch-py[async]'
```

#### Step 6: Create dependency check script

Create `check_dependencies.py`:

```python
#!/usr/bin/env python3
"""Check all ThreatOps dependencies"""

import sys

REQUIRED_PACKAGES = {
    'opensearchpy': 'opensearch-py',
    'streamlit': 'streamlit',
    'sklearn': 'scikit-learn',
    'pandas': 'pandas',
    'numpy': 'numpy',
    'plotly': 'plotly',
    'dotenv': 'python-dotenv',
    'pydantic': 'pydantic',
    'requests': 'requests',
    'aiohttp': 'aiohttp'
}

missing = []
installed = []

for module_name, package_name in REQUIRED_PACKAGES.items():
    try:
        __import__(module_name)
        installed.append(package_name)
    except ImportError:
        missing.append(package_name)

print("=" * 70)
print("DEPENDENCY CHECK")
print("=" * 70)

if installed:
    print(f"\n✓ Installed ({len(installed)}):")
    for pkg in installed:
        print(f"  - {pkg}")

if missing:
    print(f"\n✗ Missing ({len(missing)}):")
    for pkg in missing:
        print(f"  - {pkg}")
    print("\nInstall missing packages:")
    print(f"  pip install {' '.join(missing)}")
    sys.exit(1)
else:
    print("\n✓ All dependencies installed!")
    sys.exit(0)
```

Run it:
```bash
python check_dependencies.py
```

### ✅ Verification

```bash
# All imports should work
python -c "from opensearchpy import OpenSearch; from streamlit import __version__; from sklearn.ensemble import IsolationForest; print('All imports OK')"

# Run dependency check
python check_dependencies.py

# Try starting application
python run.py --help
# Should show help without import errors
```

---

## 10. Data Directories Not Created

### ❌ Problem (FILE NOT FOUND ERRORS)

**Code expects these directories:**
```
data/
data/logs/
data/alerts/
data/simulations/
data/sample_logs/
logs/
models/
reports/
```

But they don't exist!

**Impact:**
- ❌ `FileNotFoundError` when writing logs
- ❌ Can't save alerts or reports
- ❌ Simulation fails

### ✅ Solution - DETAILED FIX

#### Step 1: Create all required directories

```bash
cd "/Users/kaushalyadav/Desktop/Cusor AI/threat_ops"

# Create directory structure
mkdir -p data/logs
mkdir -p data/alerts
mkdir -p data/simulations
mkdir -p data/sample_logs
mkdir -p data/reports
mkdir -p logs
mkdir -p models
mkdir -p reports

# Set permissions
chmod -R 755 data logs models reports
```

#### Step 2: Add directory creation to application startup

This should already be in `application.py` (around line 290), but verify:

```python
def create_directories():
    """Create required directories if they don't exist"""
    from pathlib import Path
    import logging
    
    logger = logging.getLogger(__name__)
    
    directories = [
        'data',
        'data/logs',
        'data/alerts',
        'data/simulations',
        'data/sample_logs',
        'data/reports',
        'logs',
        'models',
        'reports'
    ]
    
    for directory in directories:
        path = Path(directory)
        try:
            if not path.exists():
                path.mkdir(parents=True, exist_ok=True)
                logger.info(f"✓ Created directory: {directory}")
            else:
                logger.debug(f"  Directory exists: {directory}")
        except Exception as e:
            logger.error(f"✗ Failed to create directory {directory}: {e}")
            raise

# Make sure this is called in run.py
# It should be around line 421:
create_directories()
```

#### Step 3: Add directory structure validation

Create `validate_structure.py`:

```python
#!/usr/bin/env python3
"""Validate ThreatOps directory structure"""

from pathlib import Path
import sys

REQUIRED_DIRS = [
    'data',
    'data/logs',
    'data/alerts',
    'data/simulations',
    'data/sample_logs',
    'logs',
    'models',
    'reports'
]

REQUIRED_FILES = [
    'run.py',
    'core_detection.py',
    'reporting.py',
    'simulation.py',
    'utilities.py',
    'application.py',
    'requirements.txt',
    'README.md',
    'TROUBLESHOOTING.md'
]

def validate_structure():
    """Validate directory structure"""
    project_root = Path(__file__).parent
    
    print("=" * 70)
    print("VALIDATING PROJECT STRUCTURE")
    print("=" * 70)
    
    # Check directories
    missing_dirs = []
    existing_dirs = []
    
    for dir_path in REQUIRED_DIRS:
        full_path = project_root / dir_path
        if full_path.exists() and full_path.is_dir():
            existing_dirs.append(dir_path)
        else:
            missing_dirs.append(dir_path)
    
    if existing_dirs:
        print(f"\n✓ Directories ({len(existing_dirs)}):")
        for d in existing_dirs:
            print(f"  - {d}")
    
    if missing_dirs:
        print(f"\n✗ Missing Directories ({len(missing_dirs)}):")
        for d in missing_dirs:
            print(f"  - {d}")
    
    # Check files
    missing_files = []
    existing_files = []
    
    for file_path in REQUIRED_FILES:
        full_path = project_root / file_path
        if full_path.exists() and full_path.is_file():
            existing_files.append(file_path)
        else:
            missing_files.append(file_path)
    
    if existing_files:
        print(f"\n✓ Core Files ({len(existing_files)}):")
        for f in existing_files:
            print(f"  - {f}")
    
    if missing_files:
        print(f"\n✗ Missing Files ({len(missing_files)}):")
        for f in missing_files:
            print(f"  - {f}")
    
    # Summary
    print("\n" + "=" * 70)
    if missing_dirs or missing_files:
        print("✗ VALIDATION FAILED")
        if missing_dirs:
            print(f"\nCreate missing directories:")
            for d in missing_dirs:
                print(f"  mkdir -p {d}")
        return False
    else:
        print("✓ VALIDATION PASSED")
        return True

if __name__ == "__main__":
    success = validate_structure()
    sys.exit(0 if success else 1)
```

Run it:
```bash
python validate_structure.py
```

#### Step 4: Add .gitkeep files to preserve empty directories

```bash
# Add .gitkeep to empty directories so they're tracked in git
touch data/logs/.gitkeep
touch data/alerts/.gitkeep
touch data/simulations/.gitkeep
touch data/sample_logs/.gitkeep
touch logs/.gitkeep
touch models/.gitkeep
touch reports/.gitkeep
```

### ✅ Verification

```bash
# Check all directories exist
ls -ld data/ data/*/ logs/ models/ reports/

# Run validation
python validate_structure.py

# Test writing to directories
echo "test" > data/logs/test.log
echo "test" > logs/test.log
rm data/logs/test.log logs/test.log

# Should not get "Permission denied" or "No such file or directory"
```

---

# CODE-LEVEL ISSUES

## 11. Async/Await Without Proper Error Handling

### ❌ Problem (SILENT FAILURES)

**Files Affected:** `run.py`, `core_detection.py`, `simulation.py`

Async functions lack try/except blocks:

```python
async def detect(self):
    # No error handling!
    alerts = await self.threat_detector.ml_detector.detect(...)
```

**Impact:**
- ❌ Errors silently swallowed
- ❌ No logs when async operations fail
- ❌ Difficult to debug

### ✅ Solution - Add proper error handling:

```python
async def detect(self) -> List[Alert]:
    """Run threat detection with error handling"""
    try:
        logger.info("Starting detection...")
        
        alerts = await asyncio.wait_for(
            self.threat_detector.ml_detector.detect(...),
            timeout=120.0
        )
        
        return alerts
        
    except asyncio.TimeoutError:
        logger.error("Detection timed out")
        return []
    except ConnectionError as e:
        logger.error(f"OpenSearch error: {e}")
        return []
    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
        return []
```

Apply to ALL async functions.

---

## 12. Memory Leaks in Continuous Mode

### ❌ Problem: Memory grows indefinitely

**File:** `run.py` line 156

```python
while True:
    await self.run_pipeline()  # No cleanup!
```

### ✅ Solution - Add cleanup:

```python
import gc

while True:
    await self.run_pipeline()
    
    # Clear caches
    if hasattr(self, 'threat_detector'):
        self.threat_detector._clear_cache()
    
    # Garbage collect every 10 iterations
    if iteration % 10 == 0:
        gc.collect()
```

---

## 13. No Input Validation

### ❌ Problem: Security risk - no validation

### ✅ Solution: Create `validators.py`:

```python
def validate_ip_address(ip: str) -> str:
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(ipv4_pattern, ip):
        raise ValidationError(f"Invalid IP: {ip}")
    return ip

def sanitize_string(text: str, max_length: int = 1000) -> str:
    text = text.replace('\x00', '')
    return text[:max_length]
```

Use in all user input handling.

---

## 14. Hardcoded Timeouts and Intervals

### ❌ Problem (NOT CONFIGURABLE)

**Files Affected:** `run.py`, `core_detection.py`, `application.py`, `utilities.py`

**Hardcoded values throughout the code:**

```python
# run.py line 203
if check_opensearch_health(timeout=5, max_retries=12, retry_interval=10):

# run.py line 224
time.sleep(10)  # Fixed 10 second wait

# run.py line 442
time.sleep(15)  # Fixed 15 second indexing delay

# run.py line 455
time.sleep(30)  # Fixed 30 second dashboard wait

# core_detection.py (multiple locations)
timeout=30  # All OpenSearch clients use 30s timeout

# run.py line 410
parser.add_argument('--interval', type=int, default=60)  # Fixed default
```

**Impact:**
- ❌ Can't adjust for slow systems/networks
- ❌ Wastes time on fast systems
- ❌ Timeouts on slow connections
- ❌ Not suitable for production tuning

### ✅ Solution - DETAILED FIX

#### Step 1: Add timeout configurations to .env

```bash
# Add to .env file:

# ============================================================================
# TIMING AND PERFORMANCE SETTINGS
# ============================================================================

# OpenSearch Connection
OPENSEARCH_CONNECT_TIMEOUT=30
OPENSEARCH_REQUEST_TIMEOUT=120
OPENSEARCH_MAX_RETRIES=3
OPENSEARCH_RETRY_INTERVAL=5

# Service Startup Wait Times (seconds)
OPENSEARCH_STARTUP_WAIT=30
OPENSEARCH_HEALTH_CHECK_TIMEOUT=5
OPENSEARCH_HEALTH_CHECK_RETRIES=12
OPENSEARCH_HEALTH_CHECK_INTERVAL=10

FILEBEAT_STARTUP_WAIT=10
DASHBOARDS_STARTUP_WAIT=30
STREAMLIT_STARTUP_WAIT=5

# Log Processing
LOG_INDEXING_DELAY=15  # Time to wait for logs to be indexed

# Detection Intervals
DETECTION_INTERVAL=60
ENRICHMENT_INTERVAL=120
SCORING_INTERVAL=180
CONTINUOUS_INTERVAL=60

# ML Model Training
ML_TRAIN_TIMEOUT=300
ML_MIN_SAMPLES=1000
ML_MAX_FEATURES=100

# API Rate Limits
API_REQUEST_TIMEOUT=30
API_MAX_RETRIES=3
API_RETRY_DELAY=5
API_RATE_LIMIT_DELAY=1

# Dashboard Performance
DASHBOARD_QUERY_SIZE=100
DASHBOARD_REFRESH_INTERVAL=30
DASHBOARD_MAX_RESULTS=10000
```

#### Step 2: Create timeout configuration class

Create or update `application.py`, add this class:

```python
import os
from typing import Optional

class TimeoutConfig:
    """Centralized timeout and interval configuration"""
    
    @staticmethod
    def _get_env_int(key: str, default: int) -> int:
        """Get integer from environment with fallback"""
        try:
            return int(os.getenv(key, str(default)))
        except ValueError:
            logger.warning(f"Invalid value for {key}, using default: {default}")
            return default
    
    # OpenSearch timeouts
    @staticmethod
    def opensearch_connect_timeout() -> int:
        return TimeoutConfig._get_env_int('OPENSEARCH_CONNECT_TIMEOUT', 30)
    
    @staticmethod
    def opensearch_request_timeout() -> int:
        return TimeoutConfig._get_env_int('OPENSEARCH_REQUEST_TIMEOUT', 120)
    
    @staticmethod
    def opensearch_max_retries() -> int:
        return TimeoutConfig._get_env_int('OPENSEARCH_MAX_RETRIES', 3)
    
    @staticmethod
    def opensearch_retry_interval() -> int:
        return TimeoutConfig._get_env_int('OPENSEARCH_RETRY_INTERVAL', 5)
    
    # Service startup waits
    @staticmethod
    def opensearch_startup_wait() -> int:
        return TimeoutConfig._get_env_int('OPENSEARCH_STARTUP_WAIT', 30)
    
    @staticmethod
    def filebeat_startup_wait() -> int:
        return TimeoutConfig._get_env_int('FILEBEAT_STARTUP_WAIT', 10)
    
    @staticmethod
    def dashboards_startup_wait() -> int:
        return TimeoutConfig._get_env_int('DASHBOARDS_STARTUP_WAIT', 30)
    
    # Processing intervals
    @staticmethod
    def log_indexing_delay() -> int:
        return TimeoutConfig._get_env_int('LOG_INDEXING_DELAY', 15)
    
    @staticmethod
    def detection_interval() -> int:
        return TimeoutConfig._get_env_int('DETECTION_INTERVAL', 60)
    
    @staticmethod
    def continuous_interval() -> int:
        return TimeoutConfig._get_env_int('CONTINUOUS_INTERVAL', 60)
    
    # ML settings
    @staticmethod
    def ml_train_timeout() -> int:
        return TimeoutConfig._get_env_int('ML_TRAIN_TIMEOUT', 300)
    
    @staticmethod
    def ml_min_samples() -> int:
        return TimeoutConfig._get_env_int('ML_MIN_SAMPLES', 1000)
    
    # API settings
    @staticmethod
    def api_request_timeout() -> int:
        return TimeoutConfig._get_env_int('API_REQUEST_TIMEOUT', 30)
    
    @staticmethod
    def api_max_retries() -> int:
        return TimeoutConfig._get_env_int('API_MAX_RETRIES', 3)
    
    @staticmethod
    def api_retry_delay() -> int:
        return TimeoutConfig._get_env_int('API_RETRY_DELAY', 5)
```

#### Step 3: Update run.py to use TimeoutConfig

Replace hardcoded values in `run.py`:

```python
# Add import at top
from application import TimeoutConfig

# Replace line 203:
# OLD:
if check_opensearch_health(timeout=5, max_retries=12, retry_interval=10):

# NEW:
if check_opensearch_health(
    timeout=TimeoutConfig.opensearch_health_check_timeout(),
    max_retries=TimeoutConfig.opensearch_max_retries(),
    retry_interval=TimeoutConfig.opensearch_retry_interval()
):

# Replace line 224:
# OLD:
time.sleep(10)

# NEW:
wait_time = TimeoutConfig.filebeat_startup_wait()
logger.info(f"  Waiting {wait_time} seconds for Filebeat connection...")
time.sleep(wait_time)

# Replace line 442:
# OLD:
logger.info("\nWaiting 15 seconds for log indexing...")
time.sleep(15)

# NEW:
indexing_delay = TimeoutConfig.log_indexing_delay()
logger.info(f"\nWaiting {indexing_delay} seconds for log indexing...")
time.sleep(indexing_delay)

# Replace line 455:
# OLD:
logger.info("\nWaiting for OpenSearch Dashboards...")
time.sleep(30)

# NEW:
dashboard_wait = TimeoutConfig.dashboards_startup_wait()
logger.info(f"\nWaiting {dashboard_wait} seconds for OpenSearch Dashboards...")
time.sleep(dashboard_wait)

# Replace line 410 (argparse default):
# OLD:
parser.add_argument('--interval', type=int, default=60)

# NEW:
parser.add_argument('--interval', type=int, 
                   default=TimeoutConfig.continuous_interval(),
                   help=f'Interval for continuous mode (default: {TimeoutConfig.continuous_interval()}s)')
```

#### Step 4: Update OpenSearch client creation

In `core_detection.py`, update the `create_opensearch_client` helper:

```python
def create_opensearch_client(retries=None, retry_delay=None) -> Optional[OpenSearch]:
    """Create OpenSearch client with configurable timeouts"""
    from application import TimeoutConfig
    
    # Use environment config if not specified
    if retries is None:
        retries = TimeoutConfig.opensearch_max_retries()
    if retry_delay is None:
        retry_delay = TimeoutConfig.opensearch_retry_interval()
    
    timeout = TimeoutConfig.opensearch_request_timeout()
    
    conn_params = {
        'hosts': [{'host': host, 'port': port}],
        'timeout': timeout,
        'max_retries': retries,
        'retry_on_timeout': True
    }
    
    # ... rest of function
```

#### Step 5: Update application.py Settings class

```python
# In Settings class (around line 97):
class Settings(BaseModel):
    """Main settings configuration with timeout support"""
    
    # Add timeout fields
    opensearch_timeout: int = Field(default_factory=TimeoutConfig.opensearch_request_timeout)
    detection_interval: int = Field(default_factory=TimeoutConfig.detection_interval)
    continuous_interval: int = Field(default_factory=TimeoutConfig.continuous_interval)
    
    # ... rest of settings
```

#### Step 6: Add command-line overrides

Update `run.py` to allow command-line timeout overrides:

```python
# Add these arguments to parser:
parser.add_argument('--opensearch-timeout', type=int,
                   help='OpenSearch request timeout in seconds')
parser.add_argument('--indexing-delay', type=int,
                   help='Delay for log indexing in seconds')
parser.add_argument('--startup-wait', type=int,
                   help='Service startup wait time in seconds')

# After parsing:
args = parser.parse_args()

# Override environment variables if CLI args provided
if args.opensearch_timeout:
    os.environ['OPENSEARCH_REQUEST_TIMEOUT'] = str(args.opensearch_timeout)
if args.indexing_delay:
    os.environ['LOG_INDEXING_DELAY'] = str(args.indexing_delay)
if args.startup_wait:
    os.environ['OPENSEARCH_STARTUP_WAIT'] = str(args.startup_wait)
```

### ✅ Verification

```bash
# Test with default timeouts
python run.py --all

# Test with custom timeout
python run.py --all --opensearch-timeout 60

# Test with reduced delays (for fast systems)
python run.py --all --indexing-delay 5 --startup-wait 10

# Check what values are being used
python -c "from application import TimeoutConfig; print('OpenSearch timeout:', TimeoutConfig.opensearch_request_timeout())"

# Test environment variable override
OPENSEARCH_REQUEST_TIMEOUT=180 python run.py --detect
```

---

## 15. Missing Type Hints

### ❌ Problem (POOR CODE QUALITY)

**Files Affected:** ALL Python files

**Most functions lack type hints:**

```python
# core_detection.py - no types!
def detect(self, index_pattern="filebeat-*", max_logs=1000):
    alerts = []
    # What types? What returns?
    return alerts

# run.py - unclear parameters
def start_services():
    processes = []
    # Returns what?
    return processes

# simulation.py - ambiguous
def generate_attack_logs(self):
    # Returns list? dict? something else?
    pass
```

**Impact:**
- ❌ IDE can't provide proper autocomplete
- ❌ No static type checking
- ❌ Harder to understand code
- ❌ More runtime errors
- ❌ Difficult to refactor safely

### ✅ Solution - DETAILED FIX

#### Step 1: Install type checking tools

```bash
pip install mypy types-requests types-python-dateutil

# Create mypy.ini configuration
cat > mypy.ini << 'EOF'
[mypy]
python_version = 3.10
warn_return_any = True
warn_unused_configs = True
disallow_untyped_defs = False  # Start lenient
check_untyped_defs = True
warn_redundant_casts = True
warn_unused_ignores = True
warn_no_return = True
warn_unreachable = True
strict_optional = True

# Per-module options
[mypy-opensearchpy.*]
ignore_missing_imports = True

[mypy-streamlit.*]
ignore_missing_imports = True

[mypy-sklearn.*]
ignore_missing_imports = True

[mypy-plotly.*]
ignore_missing_imports = True
EOF
```

#### Step 2: Add type hints to core_detection.py

```python
# Add comprehensive imports at top
from typing import (
    List, Dict, Optional, Union, Tuple, Any,
    Set, Callable, TypeVar, Generic, Protocol
)
from datetime import datetime
from pathlib import Path

# Update LogEntry class
class LogEntry:
    """Standardized log entry format"""
    
    def __init__(self, **kwargs: Any) -> None:
        self.timestamp: datetime = kwargs.get('timestamp', datetime.now(timezone.utc))
        self.host: str = kwargs.get('host', 'unknown')
        self.user: str = kwargs.get('user', 'unknown')
        self.event_id: int = kwargs.get('event_id', 0)
        self.ip: str = kwargs.get('ip', 'unknown')
        self.message: str = kwargs.get('message', '')
        self.process_name: str = kwargs.get('process_name', '')
        self.command_line: str = kwargs.get('command_line', '')
        self.event_type: str = kwargs.get('event_type', 'unknown')
        self.severity: str = kwargs.get('severity', 'info')
        self.source: str = kwargs.get('source', 'unknown')
        self.raw_data: Dict[str, Any] = kwargs.get('raw_data', {})
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'timestamp': self.timestamp.isoformat(),
            'host': self.host,
            'user': self.user,
            'event_id': self.event_id,
            'ip': self.ip,
            'message': self.message,
            'process_name': self.process_name,
            'command_line': self.command_line,
            'event_type': self.event_type,
            'severity': self.severity,
            'source': self.source,
            'raw_data': self.raw_data
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'LogEntry':
        """Create LogEntry from dictionary"""
        if isinstance(data.get('timestamp'), str):
            data['timestamp'] = datetime.fromisoformat(
                data['timestamp'].replace('Z', '+00:00')
            )
        return cls(**data)

# Update Alert class
class Alert:
    """Standardized alert format"""
    
    def __init__(self, **kwargs: Any) -> None:
        self.id: str = kwargs.get('id', '')
        self.timestamp: datetime = kwargs.get('timestamp', datetime.now(timezone.utc))
        self.rule_name: str = kwargs.get('rule_name', '')
        self.severity: str = kwargs.get('severity', 'Medium')
        self.description: str = kwargs.get('description', '')
        self.host: str = kwargs.get('host', 'unknown')
        self.user: str = kwargs.get('user', 'unknown')
        self.ip: str = kwargs.get('ip', 'unknown')
        self.event_ids: List[int] = kwargs.get('event_ids', [])
        self.mitre_technique: str = kwargs.get('mitre_technique', '')
        self.confidence: float = kwargs.get('confidence', 0.0)
        self.raw_events: List[LogEntry] = kwargs.get('raw_events', [])
        self.tags: List[str] = kwargs.get('tags', [])
        self.status: str = kwargs.get('status', 'open')
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        # ... implementation with proper types

# Update ThreatDetector methods
class ThreatDetector:
    """Threat detection engine"""
    
    def __init__(self, settings: Settings) -> None:
        self.settings: Settings = settings
        self.opensearch_client: Optional[OpenSearch] = None
        # ... rest of init
    
    async def initialize(self) -> None:
        """Initialize detector"""
        pass
    
    async def detect(
        self,
        index_pattern: str = "filebeat-*",
        max_logs: int = 1000
    ) -> List[Alert]:
        """
        Detect threats from OpenSearch logs.
        
        Args:
            index_pattern: OpenSearch index pattern to query
            max_logs: Maximum number of logs to analyze
            
        Returns:
            List of Alert objects detected
            
        Raises:
            ConnectionError: If OpenSearch is unavailable
            ValueError: If max_logs is invalid
        """
        alerts: List[Alert] = []
        # ... implementation
        return alerts
    
    def _check_opensearch_connection(self) -> bool:
        """Check if OpenSearch connection is alive"""
        try:
            if self.opensearch_client is None:
                return False
            self.opensearch_client.ping()
            return True
        except Exception as e:
            logger.error(f"OpenSearch connection check failed: {e}")
            return False

# Update IntelEnricher class
class IntelEnricher:
    """Threat intelligence enricher"""
    
    def __init__(self, settings: Settings) -> None:
        self.settings: Settings = settings
        self.cache: Dict[str, Dict[str, Any]] = {}
    
    async def enrich_alert(
        self,
        alert: Alert,
        use_cache: bool = True
    ) -> Optional[Alert]:
        """
        Enrich alert with threat intelligence.
        
        Args:
            alert: Alert to enrich
            use_cache: Whether to use cached intelligence data
            
        Returns:
            Enriched Alert or None if enrichment fails
        """
        pass
    
    async def check_ip_reputation(
        self,
        ip_address: str
    ) -> Dict[str, Any]:
        """
        Check IP reputation from threat intel sources.
        
        Args:
            ip_address: IP address to check
            
        Returns:
            Dictionary with reputation data
        """
        result: Dict[str, Any] = {
            'ip': ip_address,
            'reputation': 'unknown',
            'sources': [],
            'last_updated': datetime.now().isoformat()
        }
        return result

# Update RiskScorer class
class RiskScorer:
    """Risk scoring engine"""
    
    def __init__(self, settings: Settings) -> None:
        self.settings: Settings = settings
    
    def calculate_risk(
        self,
        alert: Alert,
        severity_weight: float = 1.0,
        intel_weight: float = 1.5
    ) -> Tuple[Alert, float]:
        """
        Calculate risk score for alert.
        
        Args:
            alert: Alert to score
            severity_weight: Weight for severity component
            intel_weight: Weight for threat intel component
            
        Returns:
            Tuple of (scored_alert, risk_score)
        """
        risk_score: float = 0.0
        # ... calculation
        return (alert, risk_score)
```

#### Step 3: Add type hints to run.py

```python
from typing import List, Optional, Tuple, Any
from pathlib import Path
import subprocess

def start_services() -> List[Tuple[str, subprocess.Popen]]:
    """
    Start OpenSearch, Filebeat, and OpenSearch Dashboards.
    
    Returns:
        List of tuples containing (service_name, process)
    """
    processes: List[Tuple[str, subprocess.Popen]] = []
    # ... implementation
    return processes

def start_dashboard() -> Optional[subprocess.Popen]:
    """
    Start Streamlit dashboard.
    
    Returns:
        Process object or None if failed to start
    """
    proc: Optional[subprocess.Popen] = None
    # ... implementation
    return proc

def open_dashboards() -> None:
    """Open all dashboards in browser"""
    dashboards: List[Tuple[str, str]] = [
        ("ThreatOps Dashboard", "http://localhost:8501"),
        ("OpenSearch Dashboards", "http://localhost:5601"),
        ("OpenSearch API", "http://localhost:9200")
    ]
    # ... implementation

def main() -> int:
    """
    Main entry point.
    
    Returns:
        Exit code (0 for success, non-zero for failure)
    """
    try:
        # ... implementation
        return 0
    except KeyboardInterrupt:
        logger.info("\n\nInterrupted by user")
        return 130
    except Exception as e:
        logger.exception(f"Fatal error: {e}")
        return 1
```

#### Step 4: Add type hints to simulation.py

```python
from typing import List, Dict, Optional, Any
from datetime import datetime

class AttackScenario:
    """Attack scenario definition"""
    
    def __init__(
        self,
        name: str,
        mitre_technique: str,
        description: str,
        severity: str,
        indicators: List[str]
    ) -> None:
        self.name: str = name
        self.mitre_technique: str = mitre_technique
        self.description: str = description
        self.severity: str = severity
        self.indicators: List[str] = indicators

class AttackSimulator:
    """Attack simulation engine"""
    
    def __init__(self, settings: Settings) -> None:
        self.settings: Settings = settings
        self.scenarios: List[AttackScenario] = []
    
    async def initialize(self) -> None:
        """Initialize simulator"""
        pass
    
    async def generate_attack_logs(
        self,
        scenario: Optional[AttackScenario] = None
    ) -> List[LogEntry]:
        """
        Generate simulated attack logs.
        
        Args:
            scenario: Specific scenario to simulate, or None for all
            
        Returns:
            List of simulated LogEntry objects
        """
        logs: List[LogEntry] = []
        # ... implementation
        return logs
    
    def get_scenarios(self) -> List[AttackScenario]:
        """
        Get available attack scenarios.
        
        Returns:
            List of AttackScenario objects
        """
        return self.scenarios
```

#### Step 5: Run type checker

```bash
# Check all files
mypy run.py core_detection.py reporting.py simulation.py utilities.py application.py

# Check specific file with verbose output
mypy --verbose core_detection.py

# Generate type coverage report
mypy --html-report mypy-report/ run.py core_detection.py

# Fix reported issues iteratively
```

#### Step 6: Add type stubs for missing libraries

If mypy complains about missing types:

```bash
# Install type stubs
pip install types-requests
pip install types-python-dateutil
pip install types-PyYAML

# Or add # type: ignore comments temporarily
from sklearn.ensemble import IsolationForest  # type: ignore
```

### ✅ Verification

```bash
# Run mypy
mypy run.py
# Should show fewer errors after adding types

# Check type coverage
mypy --html-report mypy-report/ *.py
# Open mypy-report/index.html to see coverage

# Run tests to ensure types don't break functionality
pytest tests/ -v

# Use IDE type checking
# VS Code: Install Pylance extension
# PyCharm: Built-in type checking should now work better
```

---

## 16. OpenSearch Index Templates Missing

### ❌ Problem (DATA LOSS RISK)

**Files Affected:** `utilities.py`, `run.py`

**No index templates or mappings configured:**

```python
# utilities.py - setup_opensearch() function
# Missing:
# - Field type mappings
# - Index template definitions
# - Data retention policies  
# - Sharding configuration
```

**What happens:**
1. OpenSearch uses dynamic mapping (guesses field types)
2. IP addresses stored as text (can't do IP range queries)
3. Timestamps might be strings (can't sort chronologically)
4. No control over analyzers (full-text search broken)
5. Performance issues with large indices

**Impact:**
- ❌ Inefficient queries
- ❌ Can't use IP range filters
- ❌ Timestamp sorting breaks
- ❌ Excessive disk usage
- ❌ Slow searches

### ✅ Solution - DETAILED FIX

#### Step 1: Create index template JSON file

Create `config/opensearch_templates.json`:

```json
{
  "threatops_logs_template": {
    "index_patterns": ["filebeat-*", "logs-*"],
    "priority": 100,
    "template": {
      "settings": {
        "number_of_shards": 2,
        "number_of_replicas": 0,
        "refresh_interval": "5s",
        "index.max_result_window": 50000,
        "index.lifecycle.name": "threatops_policy",
        "index.lifecycle.rollover_alias": "filebeat"
      },
      "mappings": {
        "properties": {
          "@timestamp": {
            "type": "date",
            "format": "strict_date_optional_time||epoch_millis"
          },
          "event_id": {
            "type": "integer"
          },
          "source_ip": {
            "type": "ip"
          },
          "destination_ip": {
            "type": "ip"
          },
          "host": {
            "type": "keyword"
          },
          "user": {
            "type": "keyword"
          },
          "process_name": {
            "type": "keyword"
          },
          "command_line": {
            "type": "text",
            "fields": {
              "keyword": {
                "type": "keyword",
                "ignore_above": 512
              }
            }
          },
          "message": {
            "type": "text",
            "analyzer": "standard"
          },
          "severity": {
            "type": "keyword"
          },
          "event_type": {
            "type": "keyword"
          },
          "mitre_technique": {
            "type": "keyword"
          },
          "tags": {
            "type": "keyword"
          },
          "geo": {
            "type": "geo_point"
          }
        }
      }
    }
  },
  "threatops_alerts_template": {
    "index_patterns": ["security-alerts-*", "alerts-*"],
    "priority": 100,
    "template": {
      "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0,
        "refresh_interval": "1s"
      },
      "mappings": {
        "properties": {
          "alert_id": {
            "type": "keyword"
          },
          "timestamp": {
            "type": "date"
          },
          "rule_name": {
            "type": "keyword"
          },
          "severity": {
            "type": "keyword"
          },
          "risk_score": {
            "type": "float"
          },
          "mitre_technique": {
            "type": "keyword"
          },
          "mitre_tactic": {
            "type": "keyword"
          },
          "confidence": {
            "type": "float"
          },
          "status": {
            "type": "keyword"
          },
          "source_ip": {
            "type": "ip"
          },
          "host": {
            "type": "keyword"
          },
          "user": {
            "type": "keyword"
          },
          "description": {
            "type": "text"
          },
          "event_ids": {
            "type": "integer"
          },
          "tags": {
            "type": "keyword"
          },
          "threat_intel": {
            "type": "object",
            "properties": {
              "malicious": {
                "type": "boolean"
              },
              "reputation_score": {
                "type": "integer"
              },
              "sources": {
                "type": "keyword"
              }
            }
          }
        }
      }
    }
  },
  "threatops_enriched_template": {
    "index_patterns": ["enriched-alerts-*"],
    "priority": 100,
    "template": {
      "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0
      },
      "mappings": {
        "properties": {
          "alert_id": {
            "type": "keyword"
          },
          "enrichment_timestamp": {
            "type": "date"
          },
          "virustotal": {
            "type": "object"
          },
          "abuseipdb": {
            "type": "object"
          },
          "otx": {
            "type": "object"
          },
          "local_intel": {
            "type": "object"
          }
        }
      }
    }
  }
}
```

#### Step 2: Update utilities.py setup function

Add template creation to `setup_opensearch()` in `utilities.py`:

```python
import json
from pathlib import Path

def setup_opensearch() -> bool:
    """
    Set up OpenSearch indices, templates, and lifecycle policies
    """
    try:
        from opensearchpy import OpenSearch
        
        client = OpenSearch(
            hosts=[{'host': 'localhost', 'port': 9200}],
            timeout=30
        )
        
        if not client.ping():
            logger.error("Cannot connect to OpenSearch")
            return False
        
        logger.info("Setting up OpenSearch index templates...")
        
        # Load template configuration
        template_file = Path(__file__).parent / 'config' / 'opensearch_templates.json'
        
        if not template_file.exists():
            logger.warning(f"Template file not found: {template_file}")
            logger.info("Creating default templates programmatically...")
            templates = get_default_templates()
        else:
            with open(template_file, 'r') as f:
                templates = json.load(f)
        
        # Create each template
        for template_name, template_body in templates.items():
            try:
                client.indices.put_index_template(
                    name=template_name,
                    body=template_body
                )
                logger.info(f"✓ Created template: {template_name}")
            except Exception as e:
                logger.error(f"✗ Failed to create template {template_name}: {e}")
        
        # Create initial indices if they don't exist
        indices_to_create = [
            'security-alerts',
            'enriched-alerts',
            'threat-intel'
        ]
        
        for index_name in indices_to_create:
            try:
                if not client.indices.exists(index=index_name):
                    client.indices.create(index=index_name)
                    logger.info(f"✓ Created index: {index_name}")
                else:
                    logger.info(f"  Index already exists: {index_name}")
            except Exception as e:
                logger.error(f"✗ Failed to create index {index_name}: {e}")
        
        # Create Index Lifecycle Management (ILM) policy
        create_lifecycle_policy(client)
        
        logger.info("OpenSearch setup completed successfully!")
        return True
        
    except Exception as e:
        logger.exception(f"Error setting up OpenSearch: {e}")
        return False


def get_default_templates() -> dict:
    """Return default template definitions if file not found"""
    return {
        "threatops_logs_template": {
            "index_patterns": ["filebeat-*", "logs-*"],
            "priority": 100,
            "template": {
                "settings": {
                    "number_of_shards": 2,
                    "number_of_replicas": 0,
                    "refresh_interval": "5s"
                },
                "mappings": {
                    "properties": {
                        "@timestamp": {"type": "date"},
                        "event_id": {"type": "integer"},
                        "source_ip": {"type": "ip"},
                        "host": {"type": "keyword"},
                        "user": {"type": "keyword"},
                        "message": {"type": "text"},
                        "severity": {"type": "keyword"}
                    }
                }
            }
        },
        "threatops_alerts_template": {
            "index_patterns": ["security-alerts-*", "alerts-*"],
            "priority": 100,
            "template": {
                "settings": {
                    "number_of_shards": 1,
                    "number_of_replicas": 0
                },
                "mappings": {
                    "properties": {
                        "alert_id": {"type": "keyword"},
                        "timestamp": {"type": "date"},
                        "severity": {"type": "keyword"},
                        "risk_score": {"type": "float"},
                        "source_ip": {"type": "ip"}
                    }
                }
            }
        }
    }


def create_lifecycle_policy(client: OpenSearch) -> None:
    """Create Index Lifecycle Management policy"""
    policy_name = "threatops_policy"
    
    # Check if policy already exists
    try:
        client.transport.perform_request('GET', f'/_plugins/_ism/policies/{policy_name}')
        logger.info(f"  ILM policy already exists: {policy_name}")
        return
    except:
        pass  # Policy doesn't exist, create it
    
    policy_body = {
        "policy": {
            "description": "ThreatOps log retention policy",
            "default_state": "hot",
            "states": [
                {
                    "name": "hot",
                    "actions": [],
                    "transitions": [
                        {
                            "state_name": "warm",
                            "conditions": {
                                "min_index_age": "7d"
                            }
                        }
                    ]
                },
                {
                    "name": "warm",
                    "actions": [
                        {
                            "read_only": {}
                        }
                    ],
                    "transitions": [
                        {
                            "state_name": "delete",
                            "conditions": {
                                "min_index_age": "30d"
                            }
                        }
                    ]
                },
                {
                    "name": "delete",
                    "actions": [
                        {
                            "delete": {}
                        }
                    ],
                    "transitions": []
                }
            ]
        }
    }
    
    try:
        client.transport.perform_request(
            'PUT',
            f'/_plugins/_ism/policies/{policy_name}',
            body=policy_body
        )
        logger.info(f"✓ Created ILM policy: {policy_name}")
    except Exception as e:
        logger.error(f"✗ Failed to create ILM policy: {e}")
```

#### Step 3: Create config directory structure

```bash
# Create config directory if it doesn't exist
mkdir -p config

# Create the template file
# (Use the JSON from Step 1)
```

#### Step 4: Verify templates via CLI

```bash
# List all index templates
curl -X GET "localhost:9200/_index_template?pretty"

# Get specific template
curl -X GET "localhost:9200/_index_template/threatops_logs_template?pretty"

# Check which template applies to an index
curl -X GET "localhost:9200/filebeat-*/_mapping?pretty"

# Verify field types
curl -X GET "localhost:9200/filebeat-*/_mapping/field/source_ip?pretty"
```

#### Step 5: Reindex existing data (if needed)

If you already have data with wrong mappings:

```python
# Add to utilities.py

def reindex_with_template(client: OpenSearch, old_index: str, new_index: str) -> bool:
    """Reindex data from old index to new index with proper mappings"""
    try:
        reindex_body = {
            "source": {
                "index": old_index
            },
            "dest": {
                "index": new_index
            }
        }
        
        logger.info(f"Reindexing {old_index} -> {new_index}...")
        response = client.reindex(body=reindex_body, wait_for_completion=False)
        task_id = response['task']
        
        logger.info(f"Reindex task started: {task_id}")
        logger.info("Monitor progress: curl -X GET 'localhost:9200/_tasks/{task_id}'")
        
        return True
    except Exception as e:
        logger.error(f"Reindex failed: {e}")
        return False
```

### ✅ Verification

```bash
# Run setup
python run.py --setup

# Verify templates created
curl "localhost:9200/_index_template/threatops_logs_template?pretty"

# Test that IP field works correctly
curl -X GET "localhost:9200/filebeat-*/_search?pretty" -H 'Content-Type: application/json' -d'
{
  "query": {
    "range": {
      "source_ip": {
        "gte": "192.168.1.0",
        "lte": "192.168.1.255"
      }
    }
  }
}'

# Check index settings
curl "localhost:9200/security-alerts/_settings?pretty"

# Monitor ILM policy
curl "localhost:9200/_plugins/_ism/explain/filebeat-*?pretty"
```

---

## 17. Filebeat Data Stream Issues

### ❌ Problem (LOGS NOT APPEARING)

**Files Affected:** Filebeat configuration (`filebeat.yml`)

**Filebeat 8.x+ uses data streams by default, but:**
- OpenSearch doesn't fully support Elasticsearch data streams
- Results in index creation failures
- Logs never appear in OpenSearch

**Error in Filebeat logs:**
```
failed to create data_stream: illegal_argument_exception
```

**Impact:**
- ❌ No logs ingested
- ❌ Filebeat keeps retrying
- ❌ Detection pipeline has no data
- ❌ Silent failure (hard to debug)

### ✅ Solution - DETAILED FIX

#### Step 1: Locate Filebeat configuration

```bash
# Find your filebeat.yml
# Windows:
# D:\Cusor AI\filebeat-9.2.0-windows-x86_64\filebeat.yml

# Linux/Mac:
# /etc/filebeat/filebeat.yml
# OR
# ~/filebeat-9.2.0/filebeat.yml
```

#### Step 2: Disable ILM and data streams

Edit `filebeat.yml`:

```yaml
# ============================================================================
# DATA STREAM AND ILM SETTINGS - DISABLE FOR OPENSEARCH
# ============================================================================

setup.ilm.enabled: false
setup.ilm.check_exists: false
setup.ilm.overwrite: false

# Use traditional indices instead of data streams
output.elasticsearch:
  hosts: ["localhost:9200"]
  
  # CRITICAL: Specify index pattern
  index: "filebeat-%{[agent.version]}-%{+yyyy.MM.dd}"
  
  # Disable data stream mode
  allow_older_versions: true
  
  # If OpenSearch security is disabled:
  # username: ""
  # password: ""
  # protocol: "http"
  
  # If OpenSearch security is enabled:
  # username: "admin"
  # password: "admin"
  # protocol: "https"
  # ssl.verification_mode: none

# Template settings
setup.template.name: "filebeat"
setup.template.pattern: "filebeat-*"
setup.template.enabled: true
setup.template.overwrite: false
setup.template.settings:
  index.number_of_shards: 2
  index.number_of_replicas: 0
```

#### Step 3: Configure file input properly

In `filebeat.yml`, configure the filebeat.inputs section:

```yaml
# ============================================================================
# FILE INPUTS - WHERE TO READ LOGS FROM
# ============================================================================

filebeat.inputs:
- type: log
  enabled: true
  
  # Path to your simulated attack logs
  paths:
    # Windows:
    - D:/Cusor AI/threat_ops/data/sim_attacks.log
    # Linux/Mac:
    # - /Users/kaushalyadav/Desktop/Cusor AI/threat_ops/data/sim_attacks.log
  
  # Parse JSON logs
  json.keys_under_root: true
  json.add_error_key: true
  json.message_key: message
  
  # Add fields for identification
  fields:
    log_source: "threatops_simulation"
    environment: "development"
  fields_under_root: true
  
  # Multiline handling (if needed)
  multiline.type: pattern
  multiline.pattern: '^\{'
  multiline.negate: true
  multiline.match: after

# ============================================================================
# PROCESSORS - DATA TRANSFORMATION
# ============================================================================

processors:
  # Add host metadata
  - add_host_metadata:
      when.not.contains.tags: forwarded
  
  # Add timestamp if missing
  - timestamp:
      field: "@timestamp"
      layouts:
        - '2006-01-02T15:04:05Z'
        - '2006-01-02T15:04:05.999Z'
        - '2006-01-02T15:04:05.999999Z'
  
  # Rename fields for consistency
  - rename:
      fields:
        - from: "log.file.path"
          to: "source_file"
      ignore_missing: true
  
  # Drop empty fields
  - drop_fields:
      fields: ["agent.ephemeral_id", "agent.hostname"]
      ignore_missing: true

# ============================================================================
# OUTPUT - WHERE TO SEND LOGS
# ============================================================================

output.elasticsearch:
  hosts: ["localhost:9200"]
  index: "filebeat-%{[agent.version]}-%{+yyyy.MM.dd}"
  
  # Bulk settings for performance
  bulk_max_size: 50
  worker: 1
  
  # Timeout settings
  timeout: 90
  
  # Retry settings
  max_retries: 3
  backoff.init: 1s
  backoff.max: 60s

# ============================================================================
# LOGGING - FILEBEAT INTERNAL LOGS
# ============================================================================

logging.level: info
logging.to_files: true
logging.files:
  path: logs  # Relative to Filebeat directory
  name: filebeat
  keepfiles: 7
  permissions: 0644

# ============================================================================
# MONITORING
# ============================================================================

# Disable X-Pack monitoring (not compatible with OpenSearch)
monitoring.enabled: false
xpack.monitoring.enabled: false
```

#### Step 4: Test Filebeat configuration

```bash
# Navigate to Filebeat directory
cd /path/to/filebeat

# Test configuration
./filebeat test config
# Should show: Config OK

# Test output (OpenSearch connection)
./filebeat test output
# Should show: elasticsearch: http://localhost:9200...
#   parse url... OK
#   connection... OK

# Run Filebeat in debug mode (see what's happening)
./filebeat -e -d "*"
```

#### Step 5: Restart Filebeat

```bash
# Windows:
# 1. Stop Filebeat process in Task Manager
# 2. Or use: taskkill /F /IM filebeat.exe
# 3. Start again: run.py will restart it

# Linux/Mac:
# Find Filebeat process
ps aux | grep filebeat

# Kill it
kill -9 <PID>

# Restart via run.py
python run.py --all
```

#### Step 6: Monitor log ingestion

```bash
# Watch Filebeat logs
tail -f /path/to/filebeat/logs/filebeat

# Should see:
# "Publish event" messages (logs being sent)
# NOT see: "data_stream" errors

# Check OpenSearch indices
curl "localhost:9200/_cat/indices?v"
# Should see: filebeat-X.X.X-YYYY.MM.DD

# Count documents
curl "localhost:9200/filebeat-*/_count?pretty"
# Should show increasing count

# Search for recent logs
curl -X GET "localhost:9200/filebeat-*/_search?pretty" -H 'Content-Type: application/json' -d'
{
  "size": 5,
  "sort": [{"@timestamp": "desc"}],
  "query": {"match_all": {}}
}'
```

### ✅ Verification

```bash
# 1. Generate test logs
python run.py --simulate

# 2. Check file was created
ls -lh data/sim_attacks.log
# Should show file size > 0

# 3. Check Filebeat is reading
tail -f <filebeat_path>/logs/filebeat
# Look for: "Harvester started for file"

# 4. Wait 10 seconds, then check OpenSearch
sleep 10
curl "localhost:9200/filebeat-*/_count?pretty"
# Should show documents

# 5. Verify in dashboard
# Open: http://localhost:8501
# "Recent Detections" should show data
```

---

## 18. OpenSearch Dashboards Login Loop

### ❌ Problem (CAN'T ACCESS DASHBOARDS)

**Symptom:** When accessing http://localhost:5601:
1. Shows login page
2. Enter username/password (admin/admin)
3. Redirects back to login page
4. Infinite loop - never gets in

**Root Cause:**
- Security plugin is enabled in OpenSearch
- But not properly configured in Dashboards
- OR: Security disabled in OpenSearch but enabled in Dashboards
- Mismatch causes authentication failures

**Impact:**
- ❌ Can't access OpenSearch Dashboards UI
- ❌ Can't create visualizations
- ❌ Can't explore data graphically
- ❌ Frustrating user experience

### ✅ Solution - DETAILED FIX

#### Option 1: Disable Security Completely (Development Mode)

**Step 1: Disable in OpenSearch**

Edit `opensearch-3.3.1/config/opensearch.yml`:

```yaml
# Find and modify these lines:

plugins.security.disabled: true

# Comment out or remove all other security settings:
# plugins.security.ssl.transport.enforce_hostname_verification: false
# plugins.security.ssl.http.enabled: false
# ... (comment out ALL security lines)
```

**Step 2: Disable in OpenSearch Dashboards**

Edit `opensearch-dashboards-3.3.0/config/opensearch_dashboards.yml`:

```yaml
# Comment out or remove these lines:
# opensearch.username: "admin"
# opensearch.password: "admin"
# opensearch.ssl.verificationMode: none

# Add this:
opensearch.hosts: ["http://localhost:9200"]

# NOT https, use http when security is disabled
```

**Step 3: Restart both services**

```bash
# Stop everything
# Windows: Task Manager -> End Process for opensearch.bat and opensearch-dashboards.bat

# Linux/Mac:
pkill -f opensearch
pkill -f opensearch-dashboards

# Start again
python run.py --all
```

#### Option 2: Properly Configure Security (Production Mode)

**Step 1: Enable security in OpenSearch**

Edit `opensearch-3.3.1/config/opensearch.yml`:

```yaml
plugins.security.disabled: false

# SSL for HTTP (API)
plugins.security.ssl.http.enabled: true
plugins.security.ssl.http.pemcert_filepath: esnode.pem
plugins.security.ssl.http.pemkey_filepath: esnode-key.pem
plugins.security.ssl.http.pemtrustedcas_filepath: root-ca.pem

# SSL for Transport (node-to-node)
plugins.security.ssl.transport.enabled: true
plugins.security.ssl.transport.pemcert_filepath: esnode.pem
plugins.security.ssl.transport.pemkey_filepath: esnode-key.pem
plugins.security.ssl.transport.pemtrustedcas_filepath: root-ca.pem
plugins.security.ssl.transport.enforce_hostname_verification: false

# Authentication
plugins.security.authcz.admin_dn:
  - CN=kirk,OU=client,O=client,L=test, C=de

plugins.security.nodes_dn:
  - CN=node,OU=node,O=node,L=test, C=de

# Basic authentication
plugins.security.allow_default_init_securityindex: true
plugins.security.audit.type: internal_opensearch
```

**Step 2: Configure Dashboards for security**

Edit `opensearch-dashboards-3.3.0/config/opensearch_dashboards.yml`:

```yaml
# Connect to OpenSearch with HTTPS
opensearch.hosts: ["https://localhost:9200"]

# Credentials
opensearch.username: "admin"
opensearch.password: "admin"

# SSL Settings
opensearch.ssl.verificationMode: none

# OR use certificates:
# opensearch.ssl.verificationMode: full
# opensearch.ssl.certificateAuthorities: ["/path/to/root-ca.pem"]

# Session settings
opensearch_security.cookie.secure: false
opensearch_security.cookie.password: "min-32-character-password-change-me-please"

# Multi-tenancy
opensearch_security.multitenancy.enabled: false

# Session timeout
opensearch_security.session.ttl: 3600000  # 1 hour in milliseconds
opensearch_security.session.keepalive: true
```

**Step 3: Initialize security**

```bash
# Navigate to OpenSearch directory
cd opensearch-3.3.1

# Run security admin script
# Windows:
plugins\opensearch-security\tools\securityadmin.bat ^
  -cd config\opensearch-security\ ^
  -icl -nhnv ^
  -cacert config\root-ca.pem ^
  -cert config\kirk.pem ^
  -key config\kirk-key.pem

# Linux/Mac:
./plugins/opensearch-security/tools/securityadmin.sh \
  -cd config/opensearch-security/ \
  -icl -nhnv \
  -cacert config/root-ca.pem \
  -cert config/kirk.pem \
  -key config/kirk-key.pem
```

#### Option 3: Quick Fix - Reset Dashboard State

Sometimes the dashboard just needs a state reset:

```bash
# Delete Dashboards data directory
# Windows:
rmdir /s /q "D:\Cusor AI\opensearch-dashboards-3.3.0\data"

# Linux/Mac:
rm -rf ~/opensearch-dashboards-3.3.0/data

# Clear browser data
# 1. Open browser DevTools (F12)
# 2. Application tab -> Clear storage
# 3. Clear all site data for localhost:5601

# Restart Dashboards
python run.py --all
```

### ✅ Verification

```bash
# Test OpenSearch API directly
curl -X GET "http://localhost:9200" -u admin:admin
# OR without auth if security disabled:
curl -X GET "http://localhost:9200"

# Should return cluster info, NOT authentication error

# Test Dashboards health
curl -X GET "http://localhost:5601/api/status"

# Open Dashboards in browser
open http://localhost:5601

# Should either:
# - Load directly (if security disabled)
# - Show login page, accept admin/admin, and STAY logged in (if security enabled)
```

---

## 19. Port Conflicts (8501, 9200, 5601)

### ❌ Problem (SERVICES WON'T START)

**Symptom:** One or more services fail to start with error:
```
Address already in use: 0.0.0.0:8501
```

**Common port conflicts:**
- **Port 9200**: OpenSearch (conflicts with Elasticsearch, other OpenSearch instances)
- **Port 5601**: OpenSearch Dashboards (conflicts with Kibana, other Dashboards)
- **Port 8501**: Streamlit (conflicts with other Streamlit apps)

**Impact:**
- ❌ Services fail to start silently
- ❌ Connection errors throughout application
- ❌ Confusing error messages
- ❌ System appears broken

### ✅ Solution - DETAILED FIX

#### Step 1: Identify what's using the ports

**Windows:**

```powershell
# Check port 9200 (OpenSearch)
netstat -ano | findstr :9200
#   TCP    0.0.0.0:9200           0.0.0.0:0              LISTENING       12345
# The last number (12345) is the PID

# Check port 5601 (Dashboards)
netstat -ano | findstr :5601

# Check port 8501 (Streamlit)
netstat -ano | findstr :8501

# Find what program is using that PID
tasklist | findstr 12345
#   java.exe                     12345 Console                    1    512,345 K

# Kill the process
taskkill /F /PID 12345
```

**Linux/Mac:**

```bash
# Check port 9200
lsof -i :9200
# COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
# java    12345 user   45u  IPv6 123456      0t0  TCP *:9200 (LISTEN)

# Check port 5601
lsof -i :5601

# Check port 8501
lsof -i :8501

# Kill the process
kill -9 12345

# Or kill by port (requires sudo)
sudo lsof -t -i :9200 | xargs kill -9
```

#### Step 2: Change ports in configuration (if needed)

**Option A: Change OpenSearch port**

Edit `opensearch-3.3.1/config/opensearch.yml`:

```yaml
# Change from default 9200
http.port: 9201

# Transport port (also change to avoid conflicts)
transport.port: 9301
```

Then update `run.py` and all Python files:

```python
# In run.py, core_detection.py, utilities.py, application.py
# OLD:
OPENSEARCH_PORT = 9200

# NEW:
OPENSEARCH_PORT = int(os.getenv('OPENSEARCH_PORT', '9201'))
```

Add to `.env`:
```bash
OPENSEARCH_PORT=9201
```

**Option B: Change Streamlit port**

Edit `application.py` or use command line:

```python
# In run.py, update start_dashboard function:
def start_dashboard() -> Optional[subprocess.Popen]:
    """Start Streamlit dashboard on custom port"""
    dashboard_port = int(os.getenv('STREAMLIT_PORT', '8502'))
    
    cmd = [
        sys.executable, "-m", "streamlit", "run",
        "application.py",
        "--server.port", str(dashboard_port),
        "--server.headless", "true",
        "--browser.serverAddress", "localhost",
        "--server.maxUploadSize", "200"
    ]
    # ... rest of function
```

Add to `.env`:
```bash
STREAMLIT_PORT=8502
```

**Option C: Change OpenSearch Dashboards port**

Edit `opensearch-dashboards-3.3.0/config/opensearch_dashboards.yml`:

```yaml
# Change from default 5601
server.port: 5602

# Also update OpenSearch host if you changed that port
opensearch.hosts: ["http://localhost:9201"]
```

Update `run.py`:

```python
# In open_dashboards function:
dashboard_port = int(os.getenv('OPENSEARCH_DASHBOARDS_PORT', '5602'))
webbrowser.open(f"http://localhost:{dashboard_port}")
```

#### Step 3: Add port availability check to run.py

Add this helper function to `run.py`:

```python
import socket

def is_port_available(port: int, host: str = 'localhost') -> bool:
    """Check if a port is available"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            s.bind((host, port))
            return True
    except OSError:
        return False


def check_port_or_fail(port: int, service_name: str) -> bool:
    """Check if port is available, warn if not"""
    if not is_port_available(port):
        logger.warning(f"⚠️  Port {port} is already in use!")
        logger.warning(f"   {service_name} may fail to start.")
        
        # Try to identify what's using it
        try:
            import psutil
            for conn in psutil.net_connections():
                if conn.laddr.port == port and conn.status == 'LISTEN':
                    try:
                        proc = psutil.Process(conn.pid)
                        logger.warning(f"   Used by: {proc.name()} (PID: {conn.pid})")
                        logger.warning(f"   To kill: kill -9 {conn.pid}  (Mac/Linux)")
                        logger.warning(f"            taskkill /F /PID {conn.pid}  (Windows)")
                    except:
                        logger.warning(f"   PID: {conn.pid}")
        except ImportError:
            logger.warning("   Install 'psutil' to identify the process: pip install psutil")
        
        # Ask user what to do
        response = input(f"   Try to start {service_name} anyway? (y/n): ")
        return response.lower() == 'y'
    return True


def start_services() -> List[Tuple[str, subprocess.Popen]]:
    """Start all services with port checks"""
    processes = []
    
    # Check ports before starting
    if not check_port_or_fail(9200, "OpenSearch"):
        logger.error("Cannot start OpenSearch - port conflict")
        return processes
    
    if not check_port_or_fail(5601, "OpenSearch Dashboards"):
        logger.warning("OpenSearch Dashboards may have issues")
    
    # ... continue with service startup
    return processes
```

#### Step 4: Create port configuration in .env

Add to `.env`:

```bash
# ============================================================================
# PORT CONFIGURATION
# ============================================================================

# OpenSearch
OPENSEARCH_PORT=9200
OPENSEARCH_TRANSPORT_PORT=9300

# OpenSearch Dashboards
OPENSEARCH_DASHBOARDS_PORT=5601

# Streamlit Dashboard
STREAMLIT_PORT=8501

# Future: Add monitoring/metrics ports
# PROMETHEUS_PORT=9090
# GRAFANA_PORT=3000
```

#### Step 5: Automated port conflict resolution

Add smart port selection to `run.py`:

```python
def find_available_port(start_port: int, max_attempts: int = 10) -> int:
    """Find an available port starting from start_port"""
    for port in range(start_port, start_port + max_attempts):
        if is_port_available(port):
            logger.info(f"Found available port: {port}")
            return port
    raise RuntimeError(f"No available ports in range {start_port}-{start_port + max_attempts}")


def start_dashboard_smart() -> Optional[subprocess.Popen]:
    """Start Streamlit with automatic port selection"""
    preferred_port = int(os.getenv('STREAMLIT_PORT', '8501'))
    
    if not is_port_available(preferred_port):
        logger.warning(f"Port {preferred_port} in use, finding alternative...")
        try:
            port = find_available_port(preferred_port + 1)
            logger.info(f"Using alternative port: {port}")
        except RuntimeError as e:
            logger.error(f"Cannot find available port: {e}")
            return None
    else:
        port = preferred_port
    
    cmd = [
        sys.executable, "-m", "streamlit", "run",
        "application.py",
        "--server.port", str(port),
        "--server.headless", "true"
    ]
    
    try:
        proc = subprocess.Popen(cmd, creationflags=subprocess.CREATE_NEW_CONSOLE)
        logger.info(f"✓ Streamlit dashboard started on http://localhost:{port}")
        return proc
    except Exception as e:
        logger.error(f"Failed to start Streamlit: {e}")
        return None
```

### ✅ Verification

```bash
# Check all required ports are free
lsof -i :9200,5601,8501  # Mac/Linux
netstat -ano | findstr "9200 5601 8501"  # Windows

# Should return empty (all ports free)

# Start services
python run.py --all

# Verify each service is listening
curl http://localhost:9200  # OpenSearch
curl http://localhost:5601/api/status  # Dashboards
curl http://localhost:8501  # Streamlit

# All should respond (not connection refused)
```

---

## 20. Java Heap Size Too Small for OpenSearch

### ❌ Problem (OPENSEARCH CRASHES)

**Symptom:**
```
OpenSearch died during startup
OutOfMemoryError: Java heap space
```

**Default heap size:** 512MB - 1GB (too small for real workloads)

**Impact:**
- ❌ OpenSearch crashes under load
- ❌ Slow query performance
- ❌ Index operations fail
- ❌ Data loss risk

### ✅ Solution - DETAILED FIX

#### Step 1: Check current heap size

```bash
# Windows:
type "D:\Cusor AI\opensearch-3.3.1\config\jvm.options" | findstr "Xm"

# Linux/Mac:
grep "^-Xm" ~/opensearch-3.3.1/config/jvm.options

# Should show:
# -Xms512m
# -Xmx512m
```

#### Step 2: Determine appropriate heap size

**Rule of thumb:**
- Development/Testing: 2-4 GB
- Small production: 8 GB
- Medium production: 16-32 GB
- Never exceed 50% of system RAM
- Never exceed 31 GB (compressed oops limit)

**Check system RAM:**

```bash
# Linux:
free -g

# Mac:
sysctl hw.memsize

# Windows:
systeminfo | findstr "Total Physical Memory"
```

**Recommended settings:**
- 8 GB system RAM → 2 GB heap (25%)
- 16 GB system RAM → 4 GB heap (25%)
- 32 GB system RAM → 16 GB heap (50%)
- 64+ GB system RAM → 26-31 GB heap (max 31 GB)

#### Step 3: Edit JVM options file

Edit `opensearch-3.3.1/config/jvm.options`:

```bash
# Find these lines (near the top):
-Xms512m
-Xmx512m

# Change to (for 8 GB heap):
-Xms8g
-Xmx8g

# Or for 4 GB:
-Xms4g
-Xmx4g

# Or for 2 GB (minimum recommended):
-Xms2g
-Xmx2g
```

**Important rules:**
- `-Xms` (min heap) and `-Xmx` (max heap) should be THE SAME
- This prevents heap resizing (which causes pauses)

#### Step 4: Add additional JVM tuning options

While editing `jvm.options`, also optimize:

```bash
## HEAP SIZE (SET BASED ON YOUR SYSTEM)
-Xms4g
-Xmx4g

## GC CONFIGURATION (G1GC - best for OpenSearch)
-XX:+UseG1GC
-XX:G1ReservePercent=25
-XX:InitiatingHeapOccupancyPercent=30

## GC LOGGING
-Xlog:gc*,gc+age=trace,safepoint:file=logs/gc.log:utctime,pid,tags:filecount=32,filesize=64m

## HEAP DUMPS ON OOM (for debugging)
-XX:+HeapDumpOnOutOfMemoryError
-XX:HeapDumpPath=data
-XX:ErrorFile=logs/hs_err_pid%p.log

## PERFORMANCE TUNING
-XX:+AlwaysPreTouch
-Djava.awt.headless=true
-Dfile.encoding=UTF-8

## TEMPORARY DIRECTORY
-Djava.io.tmpdir=${OPENSEARCH_TMPDIR}

## DNS CACHE (important for cloud deployments)
-Dnetworkaddress.cache.ttl=60
-Dnetworkaddress.cache.negative.ttl=10
```

#### Step 5: Set environment variable (alternative method)

Instead of editing `jvm.options`, you can use environment variables:

**Windows (PowerShell):**
```powershell
$env:OPENSEARCH_JAVA_OPTS="-Xms4g -Xmx4g"
./opensearch-3.3.1/bin/opensearch.bat
```

**Windows (.env file for persistence):**
```bash
# Add to .env:
OPENSEARCH_JAVA_OPTS=-Xms4g -Xmx4g
```

**Linux/Mac (.bashrc or .zshrc):**
```bash
export OPENSEARCH_JAVA_OPTS="-Xms4g -Xmx4g"
```

**In run.py:**
```python
def start_opensearch() -> Optional[subprocess.Popen]:
    """Start OpenSearch with custom heap size"""
    heap_size = os.getenv('OPENSEARCH_HEAP_SIZE', '4g')
    
    # Set JVM options
    os.environ['OPENSEARCH_JAVA_OPTS'] = f"-Xms{heap_size} -Xmx{heap_size}"
    
    # ... rest of start function
```

Add to `.env`:
```bash
OPENSEARCH_HEAP_SIZE=4g
```

#### Step 6: Verify heap settings after restart

```bash
# Start OpenSearch
python run.py --all

# Check heap usage via API
curl "http://localhost:9200/_nodes/stats/jvm?pretty" | grep heap

# Output should show:
# "heap_init_in_bytes": 4294967296,  (4 GB)
# "heap_max_in_bytes": 4294967296,   (4 GB)

# Monitor heap usage over time
curl "http://localhost:9200/_cat/nodes?v&h=heap.percent,heap.current,heap.max"
# heap.percent heap.current heap.max
#           45        1.8gb     4gb
```

#### Step 7: Monitor GC activity

```bash
# View GC log
tail -f opensearch-3.3.1/logs/gc.log

# Look for:
# - GC pause times (should be < 1 second)
# - GC frequency (shouldn't be constant)
# - Heap usage patterns

# Check GC stats via API
curl "http://localhost:9200/_nodes/stats/jvm?pretty" | grep -A 10 "\"gc\""

# Healthy indicators:
# - collection_time_in_millis: low
# - collection_count: low frequency
# - heap usage: stays below 75%
```

#### Step 8: Set up heap monitoring in dashboard

Add to `application.py` dashboard:

```python
def display_opensearch_health():
    """Display OpenSearch cluster health including heap"""
    try:
        client = create_opensearch_client()
        
        # Get node stats
        stats = client.nodes.stats(metric='jvm')
        
        for node_id, node in stats['nodes'].items():
            jvm = node['jvm']
            heap = jvm['mem']['heap']
            
            heap_used_gb = heap['used_in_bytes'] / (1024**3)
            heap_max_gb = heap['max_in_bytes'] / (1024**3)
            heap_percent = heap['used_percent']
            
            st.metric(
                "Heap Usage",
                f"{heap_used_gb:.2f} GB / {heap_max_gb:.2f} GB",
                f"{heap_percent}%"
            )
            
            # Warn if heap usage is high
            if heap_percent > 85:
                st.error("⚠️ Heap usage critical! Consider increasing heap size.")
            elif heap_percent > 75:
                st.warning("⚠️ Heap usage high. Monitor for OOM errors.")
            
            # GC stats
            gc = jvm['gc']['collectors']
            young_gc = gc['young']
            old_gc = gc['old']
            
            col1, col2 = st.columns(2)
            with col1:
                st.metric("Young GC Count", young_gc['collection_count'])
            with col2:
                st.metric("Old GC Count", old_gc['collection_count'])
    
    except Exception as e:
        st.error(f"Cannot fetch OpenSearch health: {e}")
```

### ✅ Verification

```bash
# Restart OpenSearch with new heap settings
python run.py --all

# Verify heap size
curl "http://localhost:9200/_nodes/stats/jvm?pretty" | grep -E "heap_max_in_bytes|heap_init"

# Should match your settings (4 GB = 4,294,967,296 bytes)

# Load test to ensure no OOM
python run.py --simulate  # Generate logs
python run.py --detect    # Process them

# Monitor heap during load
watch -n 5 'curl -s "http://localhost:9200/_cat/nodes?v&h=heap.percent,heap.current"'

# Heap should stay below 75% even under load
```

---

## 21. Dashboard Loading Very Slow

### ❌ Problem (POOR UX)

**Symptom:**
- Opening http://localhost:8501 takes 30+ seconds
- Widgets freeze
- Spinner never stops
- Browser becomes unresponsive

**Causes:**
1. Loading ALL data from OpenSearch (no pagination)
2. Complex visualizations with too many data points
3. Streamlit reruns entire script on every interaction
4. No caching of expensive operations
5. OpenSearch queries not optimized

**Impact:**
- ❌ Unusable dashboard
- ❌ Timeout errors
- ❌ Browser crashes
- ❌ Poor user experience

### ✅ Solution - DETAILED FIX

#### Step 1: Add caching to expensive operations

Edit `application.py`:

```python
import streamlit as st
from functools import lru_cache
import time

# Enable Streamlit caching
@st.cache_data(ttl=60)  # Cache for 60 seconds
def fetch_recent_alerts(limit: int = 100):
    """Fetch recent alerts with caching"""
    try:
        client = create_opensearch_client()
        response = client.search(
            index="security-alerts",
            body={
                "size": limit,  # LIMIT results
                "sort": [{"timestamp": "desc"}],
                "query": {"match_all": {}}
            }
        )
        return response['hits']['hits']
    except Exception as e:
        logger.error(f"Error fetching alerts: {e}")
        return []

@st.cache_data(ttl=300)  # Cache for 5 minutes
def fetch_mitre_stats():
    """Fetch MITRE technique statistics"""
    try:
        client = create_opensearch_client()
        response = client.search(
            index="security-alerts",
            body={
                "size": 0,  # Don't return documents
                "aggs": {
                    "techniques": {
                        "terms": {
                            "field": "mitre_technique.keyword",
                            "size": 20  # Top 20 only
                        }
                    }
                }
            }
        )
        return response['aggregations']['techniques']['buckets']
    except Exception as e:
        logger.error(f"Error fetching MITRE stats: {e}")
        return []

@st.cache_resource  # Cache forever (for database connections)
def get_opensearch_client():
    """Get cached OpenSearch client"""
    return OpenSearch(
        hosts=[{'host': 'localhost', 'port': 9200}],
        timeout=30
    )
```

#### Step 2: Implement pagination

```python
def display_alerts_paginated():
    """Display alerts with pagination"""
    # Session state for pagination
    if 'page' not in st.session_state:
        st.session_state.page = 0
    
    page_size = 20
    from_index = st.session_state.page * page_size
    
    # Fetch one page of data
    @st.cache_data(ttl=30)
    def fetch_alert_page(page_num: int, size: int):
        client = get_opensearch_client()
        response = client.search(
            index="security-alerts",
            body={
                "from": page_num * size,
                "size": size,
                "sort": [{"timestamp": "desc"}],
                "query": {"match_all": {}}
            }
        )
        total = response['hits']['total']['value']
        hits = response['hits']['hits']
        return hits, total
    
    alerts, total = fetch_alert_page(st.session_state.page, page_size)
    
    # Display alerts
    for alert in alerts:
        source = alert['_source']
        with st.expander(f"{source['rule_name']} - {source['severity']}"):
            st.json(source)
    
    # Pagination controls
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col1:
        if st.button("⬅️ Previous") and st.session_state.page > 0:
            st.session_state.page -= 1
            st.rerun()
    
    with col2:
        max_pages = (total + page_size - 1) // page_size
        st.write(f"Page {st.session_state.page + 1} of {max_pages} ({total} total)")
    
    with col3:
        if st.button("Next ➡️") and (st.session_state.page + 1) * page_size < total:
            st.session_state.page += 1
            st.rerun()
```

#### Step 3: Optimize OpenSearch queries

```python
def fetch_alerts_optimized():
    """Fetch alerts with field filtering and source filtering"""
    client = get_opensearch_client()
    
    response = client.search(
        index="security-alerts",
        body={
            "size": 50,
            "_source": [  # Only fetch needed fields
                "alert_id",
                "timestamp",
                "rule_name",
                "severity",
                "risk_score",
                "host",
                "user"
            ],
            "sort": [{"timestamp": "desc"}],
            "query": {
                "bool": {
                    "must": [
                        {"range": {"timestamp": {"gte": "now-24h"}}}  # Last 24h only
                    ]
                }
            }
        }
    )
    return response['hits']['hits']


def get_alert_count_fast():
    """Get alert count without fetching documents"""
    client = get_opensearch_client()
    
    # Use count API (much faster than search)
    response = client.count(
        index="security-alerts",
        body={
            "query": {"match_all": {}}
        }
    )
    return response['count']
```

#### Step 4: Reduce visualization complexity

```python
def create_severity_chart_optimized():
    """Create severity chart with limited data points"""
    
    # Use aggregations instead of fetching all documents
    @st.cache_data(ttl=60)
    def fetch_severity_agg():
        client = get_opensearch_client()
        response = client.search(
            index="security-alerts",
            body={
                "size": 0,  # No documents needed
                "aggs": {
                    "by_severity": {
                        "terms": {
                            "field": "severity.keyword",
                            "size": 5
                        }
                    }
                }
            }
        )
        return response['aggregations']['by_severity']['buckets']
    
    buckets = fetch_severity_agg()
    
    # Create simple bar chart
    data = {
        'Severity': [b['key'] for b in buckets],
        'Count': [b['doc_count'] for b in buckets]
    }
    
    import plotly.express as px
    fig = px.bar(
        data,
        x='Severity',
        y='Count',
        color='Severity',
        title="Alerts by Severity"
    )
    
    # Optimize rendering
    fig.update_layout(
        showlegend=False,
        height=300,  # Fixed height
        margin=dict(l=20, r=20, t=40, b=20)
    )
    
    st.plotly_chart(fig, use_container_width=True)
```

#### Step 5: Add loading indicators

```python
def dashboard_main():
    """Main dashboard with loading indicators"""
    
    st.title("ThreatOps SIEM Dashboard")
    
    # Show loading spinner for expensive operations
    with st.spinner("Loading alerts..."):
        alerts = fetch_recent_alerts(limit=50)
    
    with st.spinner("Loading statistics..."):
        stats = fetch_mitre_stats()
    
    # Display data
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Total Alerts", len(alerts))
    
    with col2:
        high_alerts = [a for a in alerts if a['_source'].get('severity') == 'High']
        st.metric("High Severity", len(high_alerts))
    
    with col3:
        critical_alerts = [a for a in alerts if a['_source'].get('severity') == 'Critical']
        st.metric("Critical", len(critical_alerts))
    
    # Use tabs to lazy-load sections
    tab1, tab2, tab3 = st.tabs(["Recent Alerts", "MITRE Map", "Threat Intel"])
    
    with tab1:
        display_alerts_paginated()
    
    with tab2:
        # Only loads when tab is clicked
        with st.spinner("Loading MITRE ATT&CK map..."):
            display_mitre_heatmap(stats)
    
    with tab3:
        with st.spinner("Loading threat intelligence..."):
            display_threat_intel()
```

#### Step 6: Configure Streamlit performance settings

Create `.streamlit/config.toml`:

```toml
[server]
# Enable file watcher caching
runOnSave = false
maxUploadSize = 200

# Performance settings
enableCORS = false
enableXsrfProtection = true

[browser]
# Prevent automatic browser opening
gatherUsageStats = false
serverAddress = "localhost"

[theme]
# Use default theme (faster rendering)
base = "light"

[runner]
# Reduce reruns
fastReruns = true
postScriptGC = true

[client]
# Toolbox visibility
toolbarMode = "minimal"
showErrorDetails = false

[logger]
# Reduce logging overhead
level = "warning"
```

#### Step 7: Add auto-refresh control

```python
def add_refresh_control():
    """Add auto-refresh toggle"""
    col1, col2 = st.columns([3, 1])
    
    with col1:
        st.write("")  # Spacer
    
    with col2:
        auto_refresh = st.checkbox("Auto-refresh", value=False)
        
        if auto_refresh:
            refresh_interval = st.slider("Interval (seconds)", 10, 300, 60)
            # Auto-refresh
            import time
            time.sleep(refresh_interval)
            st.rerun()
```

### ✅ Verification

```bash
# Start dashboard
python run.py --dashboard

# Test loading time
time curl -s http://localhost:8501/_stcore/health
# Should respond in < 2 seconds

# Open in browser and check:
# 1. Initial load < 5 seconds
# 2. Subsequent page changes < 1 second
# 3. No browser freezing
# 4. Smooth scrolling

# Check Streamlit logs for performance warnings
# Look in logs/threat_ops.log for slow query warnings
```

---

## 22. No Logs Appearing in OpenSearch

### ❌ Problem (EMPTY PIPELINE)

**Symptom:**
- `curl "http://localhost:9200/filebeat-*/_count"` returns `"count": 0`
- No data appears in dashboard
- Detection finds nothing
- OpenSearch indices exist but are empty

**Possible causes:**
1. Filebeat not running
2. Filebeat not configured correctly
3. Log file doesn't exist or is empty
4. Filebeat can't access the log file (permissions)
5. OpenSearch rejecting logs (mapping errors)

**Impact:**
- ❌ Entire detection pipeline is useless
- ❌ No alerts generated
- ❌ System appears broken

### ✅ Solution - DETAILED FIX

#### Step 1: Verify log file exists and has content

```bash
# Check if simulation generated logs
ls -lh data/sim_attacks.log

# Should show:
# -rw-r--r-- 1 user group 12345 Nov 6 10:30 data/sim_attacks.log
#                           ^^^^^ size should be > 0

# If file doesn't exist, generate logs:
python run.py --simulate

# View log file content
head -10 data/sim_attacks.log

# Should show JSON log entries like:
# {"timestamp": "2024-11-06T10:30:00Z", "event_id": 4624, ...}

# If file is empty, check simulation.py for errors:
tail -50 logs/threat_ops.log
```

#### Step 2: Verify Filebeat is running

```bash
# Check Filebeat process
ps aux | grep filebeat
# Mac/Linux: should show filebeat process

# Windows:
tasklist | findstr filebeat
# Should show: filebeat.exe     12345 Console     1    45,678 K

# If not running, check why it failed to start:
# View Filebeat logs
tail -100 <filebeat_dir>/logs/filebeat

# Common errors:
# - "config file not found": wrong path in run.py
# - "permission denied": can't access log file
# - "output not reachable": OpenSearch not running
```

#### Step 3: Test Filebeat configuration

```bash
# Navigate to Filebeat directory
cd /path/to/filebeat

# Test configuration syntax
./filebeat test config -c filebeat.yml
# Should show: Config OK

# Test output (OpenSearch connection)
./filebeat test output -c filebeat.yml
# Should show:
#   elasticsearch: http://localhost:9200...
#     parse host... OK
#     dns lookup... OK
#     connection...
#       talk to server... OK

# If "connection failed":
# 1. Check OpenSearch is running: curl http://localhost:9200
# 2. Check firewall isn't blocking port 9200
# 3. Check filebeat.yml has correct host/port
```

#### Step 4: Check Filebeat can read the log file

```bash
# Check file permissions
ls -l data/sim_attacks.log
# Should be readable by Filebeat user

# If permission denied, fix it:
chmod 644 data/sim_attacks.log

# On Windows, check file isn't locked:
# 1. Close any programs that might have it open
# 2. Check file properties -> Security tab
# 3. Ensure "Users" group has Read permission

# Test Filebeat can see the file:
# Add to filebeat.yml temporarily for testing:
# logging.level: debug
# logging.to_stderr: true

# Run Filebeat manually and check output
./filebeat -e -c filebeat.yml -d "*"

# Look for:
# "Harvester started for file: /path/to/sim_attacks.log"

# If you see:
# "ERR file is not readable": fix permissions
# "ERR file does not exist": check path in filebeat.yml
```

#### Step 5: Verify logs are being sent to OpenSearch

```bash
# Watch Filebeat logs in real-time
tail -f <filebeat_dir>/logs/filebeat

# Look for:
# "Publish event: {...}" - means logs are being sent
# "PublishEvents: N events have been published" - success!

# If you see:
# "Failed to connect": OpenSearch not reachable
# "4xx error": authentication/authorization issue
# "5xx error": OpenSearch is having problems

# Check OpenSearch is accepting writes
curl -X POST "http://localhost:9200/filebeat-test/_doc" -H 'Content-Type: application/json' -d'
{
  "test": "data",
  "timestamp": "2024-11-06T10:00:00Z"
}'

# Should return: {"result": "created", ...}
# If error, OpenSearch has problems (check logs)
```

#### Step 6: Check OpenSearch indices

```bash
# List all indices
curl "http://localhost:9200/_cat/indices?v"

# Look for indices matching filebeat-*
# If you don't see any filebeat indices:
# 1. Filebeat never successfully sent data
# 2. Index pattern in filebeat.yml doesn't match

# If index exists but document count is 0:
curl "http://localhost:9200/filebeat-*/_count?pretty"
# {"count": 0}

# This means:
# - Index was created (filebeat connected)
# - But no documents were indexed

# Check for indexing errors:
curl "http://localhost:9200/filebeat-*/_search?pretty" -H 'Content-Type: application/json' -d'
{
  "query": {"match_all": {}},
  "size": 1
}'

# If no results, check OpenSearch error log:
tail -100 <opensearch_dir>/logs/<cluster_name>.log
```

#### Step 7: Check for mapping conflicts

```bash
# Get index mapping
curl "http://localhost:9200/filebeat-*/_mapping?pretty"

# Look for type conflicts, e.g.:
# Field 'event_id' has different types:
#   - integer in one document
#   - string in another

# This causes silent drop of documents!

# Check for rejected documents:
curl "http://localhost:9200/_nodes/stats/indices/indexing?pretty" | grep -A 5 "index_failed"

# If index_failed > 0, there's a problem

# To fix mapping conflicts:
# 1. Delete the index: curl -X DELETE "http://localhost:9200/filebeat-*"
# 2. Create proper index template (see Issue #16)
# 3. Restart Filebeat
```

#### Step 8: Force Filebeat to resend data

Sometimes Filebeat's registry gets confused:

```bash
# Stop Filebeat
# Windows: taskkill /F /IM filebeat.exe
# Linux/Mac: pkill filebeat

# Delete Filebeat registry (forces it to re-read from start)
# Windows:
rm <filebeat_dir>/data/registry/*

# Linux/Mac:
rm -rf <filebeat_dir>/data/registry/*

# CAUTION: This will cause Filebeat to re-send ALL logs!
# Only do this if you're sure logs aren't appearing

# Restart Filebeat
python run.py --all

# Check if logs now appear:
sleep 15
curl "http://localhost:9200/filebeat-*/_count?pretty"
# Should now show count > 0
```

#### Step 9: Add debugging to run.py

Update `run.py` to automatically diagnose this issue:

```python
def diagnose_log_pipeline():
    """Diagnose why logs aren't appearing"""
    print("\n=== LOG PIPELINE DIAGNOSTICS ===\n")
    
    # Check 1: Log file exists
    log_file = Path("data/sim_attacks.log")
    if not log_file.exists():
        print("❌ Log file doesn't exist: data/sim_attacks.log")
        print("   Run: python run.py --simulate")
        return False
    
    file_size = log_file.stat().st_size
    if file_size == 0:
        print("❌ Log file is empty")
        print("   Run: python run.py --simulate")
        return False
    
    print(f"✓ Log file exists ({file_size / 1024:.2f} KB)")
    
    # Check 2: Filebeat is running
    try:
        import psutil
        filebeat_running = any('filebeat' in p.name().lower() for p in psutil.process_iter(['name']))
        if filebeat_running:
            print("✓ Filebeat is running")
        else:
            print("❌ Filebeat is NOT running")
            print("   Run: python run.py --all")
            return False
    except:
        print("⚠️  Cannot check if Filebeat is running (install psutil)")
    
    # Check 3: OpenSearch is reachable
    try:
        response = requests.get("http://localhost:9200", timeout=5)
        if response.status_code == 200:
            print("✓ OpenSearch is reachable")
        else:
            print(f"❌ OpenSearch returned error: {response.status_code}")
            return False
    except:
        print("❌ Cannot connect to OpenSearch")
        print("   Ensure OpenSearch is running on port 9200")
        return False
    
    # Check 4: Filebeat indices exist
    try:
        response = requests.get("http://localhost:9200/_cat/indices/filebeat-*", timeout=5)
        if response.status_code == 200 and response.text.strip():
            print("✓ Filebeat indices exist")
            
            # Check 5: Documents in indices
            count_response = requests.get("http://localhost:9200/filebeat-*/_count", timeout=5)
            count = count_response.json().get('count', 0)
            
            if count > 0:
                print(f"✓ {count} documents indexed")
                return True
            else:
                print("❌ Indices exist but have 0 documents")
                print("   Filebeat connected but isn't indexing logs")
                print("   Check Filebeat logs for errors")
                return False
        else:
            print("❌ No filebeat indices found")
            print("   Filebeat hasn't successfully connected to OpenSearch")
            return False
    except Exception as e:
        print(f"❌ Error checking indices: {e}")
        return False

# Add to argparse
parser.add_argument('--diagnose', action='store_true',
                   help='Diagnose why logs aren\'t appearing')

# In main:
if args.diagnose:
    diagnose_log_pipeline()
    return
```

### ✅ Verification

```bash
# Run complete diagnostic
python run.py --diagnose

# Should show all ✓ checks passing

# Manual verification:
# 1. Generate fresh logs
python run.py --simulate

# 2. Wait for indexing (15 seconds)
sleep 15

# 3. Count documents
curl "http://localhost:9200/filebeat-*/_count?pretty"
# Should show: "count": <number > 0>

# 4. Search for recent logs
curl -X GET "http://localhost:9200/filebeat-*/_search?pretty" -H 'Content-Type: application/json' -d'
{
  "size": 3,
  "sort": [{"@timestamp": "desc"}],
  "query": {"match_all": {}}
}'

# Should return actual log documents

# 5. Verify in dashboard
# Open: http://localhost:8501
# Should show alerts/detections
```

---

## 23. No Alerts Generated by Detection Engine

### ❌ Problem (DETECTION NOT WORKING)

**Symptom:**
- Logs exist in OpenSearch (verified)
- Run detection: `python run.py --detect`
- Output shows: "0 alerts generated"
- `security-alerts` index is empty

**Possible causes:**
1. Detection rules are too strict (nothing matches)
2. ML model not trained or missing
3. Log format doesn't match what detector expects
4. Detector code has bugs
5. OpenSearch query returning no results

**Impact:**
- ❌ Threats go undetected
- ❌ System provides no value
- ❌ False sense of security

### ✅ Solution - DETAILED FIX

#### Step 1: Verify logs exist and are queryable

```bash
# Count logs
curl "http://localhost:9200/filebeat-*/_count?pretty"
# Should show count > 0

# Search for any logs
curl -X GET "http://localhost:9200/filebeat-*/_search?pretty" -H 'Content-Type: application/json' -d'
{
  "size": 1,
  "query": {"match_all": {}}
}'

# Should return at least one document

# Check log structure
curl -X GET "http://localhost:9200/filebeat-*/_search?pretty" -H 'Content-Type: application/json' -d'
{
  "size": 1,
  "_source": true
}'

# Note the field names:
# - Is it "event_id" or "event.id"?
# - Is it "process_name" or "process.name"?
# - Field names must match what core_detection.py expects
```

#### Step 2: Test detection with verbose logging

Edit `core_detection.py` to add debug output:

```python
class ThreatDetector:
    async def detect(self, index_pattern="filebeat-*", max_logs=1000):
        """Detect threats with verbose logging"""
        logger.info(f"Starting detection on index: {index_pattern}")
        
        try:
            # Fetch logs
            response = self.opensearch_client.search(
                index=index_pattern,
                body={
                    "size": max_logs,
                    "sort": [{"@timestamp": "desc"}],
                    "query": {"match_all": {}}
                }
            )
            
            logs = response['hits']['hits']
            logger.info(f"Fetched {len(logs)} logs from OpenSearch")
            
            if len(logs) == 0:
                logger.warning("No logs found! Check index pattern and date range")
                return []
            
            # Log first entry for debugging
            if logs:
                logger.debug(f"Sample log entry: {logs[0]['_source']}")
            
            # Convert to LogEntry objects
            log_entries = []
            for hit in logs:
                try:
                    entry = self._normalize_log(hit['_source'])
                    log_entries.append(entry)
                except Exception as e:
                    logger.error(f"Failed to normalize log: {e}")
                    logger.error(f"Problematic log: {hit['_source']}")
            
            logger.info(f"Normalized {len(log_entries)} log entries")
            
            # Run detection rules
            alerts = []
            
            for rule in self.detection_rules:
                logger.info(f"Running rule: {rule.get('name', 'Unknown')}")
                rule_alerts = self._apply_rule(rule, log_entries)
                logger.info(f"  -> {len(rule_alerts)} alerts generated")
                alerts.extend(rule_alerts)
            
            logger.info(f"Total alerts generated: {len(alerts)}")
            return alerts
            
        except Exception as e:
            logger.exception(f"Detection failed: {e}")
            return []
```

Run detection:

```bash
python run.py --detect

# Check logs/threat_ops.log for detailed output:
tail -100 logs/threat_ops.log

# Look for:
# - "Fetched X logs" - should be > 0
# - "Normalized Y entries" - should be > 0
# - "Running rule: <name>" - for each rule
# - Any errors or warnings
```

#### Step 3: Test individual detection rules

Create a test script `test_detection.py`:

```python
import asyncio
from core_detection import ThreatDetector, LogEntry
from application import Settings
from datetime import datetime, timezone

async def test_detection():
    """Test detection engine with known malicious logs"""
    
    # Create detector
    settings = Settings()
    detector = ThreatDetector(settings)
    await detector.initialize()
    
    # Create test log entries that SHOULD trigger alerts
    test_logs = [
        # Brute force attempt (multiple failed logins)
        LogEntry(
            timestamp=datetime.now(timezone.utc),
            event_id=4625,  # Failed login
            host="test-host",
            user="admin",
            ip="192.168.1.100",
            message="Failed login attempt",
            severity="warning",
            source="test"
        ),
        LogEntry(
            timestamp=datetime.now(timezone.utc),
            event_id=4625,
            host="test-host",
            user="admin",
            ip="192.168.1.100",
            message="Failed login attempt",
            severity="warning",
            source="test"
        ),
        LogEntry(
            timestamp=datetime.now(timezone.utc),
            event_id=4625,
            host="test-host",
            user="admin",
            ip="192.168.1.100",
            message="Failed login attempt",
            severity="warning",
            source="test"
        ),
        LogEntry(
            timestamp=datetime.now(timezone.utc),
            event_id=4625,
            host="test-host",
            user="admin",
            ip="192.168.1.100",
            message="Failed login attempt",
            severity="warning",
            source="test"
        ),
        LogEntry(
            timestamp=datetime.now(timezone.utc),
            event_id=4625,
            host="test-host",
            user="admin",
            ip="192.168.1.100",
            message="Failed login attempt",
            severity="warning",
            source="test"
        ),
        # Mimikatz execution
        LogEntry(
            timestamp=datetime.now(timezone.utc),
            event_id=4688,  # Process creation
            host="test-host",
            user="user1",
            process_name="mimikatz.exe",
            command_line="mimikatz.exe privilege::debug sekurlsa::logonpasswords",
            ip="192.168.1.50",
            message="Process created",
            severity="info",
            source="test"
        )
    ]
    
    print(f"\nTesting with {len(test_logs)} synthetic log entries...")
    
    # Apply rules
    for rule in detector.detection_rules:
        print(f"\nTesting rule: {rule['name']}")
        alerts = detector._apply_rule(rule, test_logs)
        
        if alerts:
            print(f"  ✓ Generated {len(alerts)} alerts")
            for alert in alerts:
                print(f"    - {alert.rule_name}: {alert.description}")
        else:
            print(f"  ✗ No alerts (rule may be too strict or not matching)")
    
    print("\n" + "="*60)
    print("If NO alerts were generated, detection rules need adjustment")
    print("="*60)

if __name__ == "__main__":
    asyncio.run(test_detection())
```

Run test:

```bash
python test_detection.py

# Should show alerts for:
# - Brute force (5 failed logins from same IP)
# - Mimikatz detection

# If no alerts:
# 1. Detection rules are broken
# 2. Rule conditions are too strict
# 3. Code logic errors
```

#### Step 4: Check ML model

```bash
# Check if model exists
ls -l models/

# Should show: isolation_forest_model.joblib

# If missing, train model:
python run.py --train

# Verify model works:
python -c "
from joblib import load
model = load('models/isolation_forest_model.joblib')
print('Model loaded successfully')
print(f'Model type: {type(model)}')
"

# If error, model is corrupted - retrain:
rm models/isolation_forest_model.joblib
python run.py --train
```

#### Step 5: Adjust detection rule sensitivity

If rules are too strict, lower thresholds in `core_detection.py`:

```python
# In ThreatDetector.__init__
self.detection_rules = [
    {
        "name": "Multiple Failed Logins (Brute Force)",
        "event_id": 4625,
        "threshold": 3,  # LOWER from 5 to 3
        "time_window": 300,
        "severity": "High",
        "mitre": "T1110",
        "description": "Multiple failed login attempts detected"
    },
    {
        "name": "Suspicious Process Execution",
        "indicators": ["mimikatz", "psexec", "powershell -enc"],
        "event_id": 4688,
        "severity": "Critical",
        "mitre": "T1059",
        "description": "Execution of known malicious process"
    },
    # Add more lenient rules
    {
        "name": "Any Failed Login",
        "event_id": 4625,
        "threshold": 1,  # Alert on ANY failed login
        "severity": "Low",
        "mitre": "T1110",
        "description": "Failed login attempt detected"
    }
]
```

#### Step 6: Add catch-all rule for testing

Add a rule that matches EVERYTHING (for testing):

```python
{
    "name": "TEST - All Events",
    "match_all": True,  # Special flag
    "severity": "Info",
    "description": "Test rule - matches all events"
}

# In _apply_rule method:
def _apply_rule(self, rule, log_entries):
    """Apply detection rule to log entries"""
    
    # Test rule - matches everything
    if rule.get('match_all'):
        alerts = []
        for entry in log_entries[:5]:  # Just first 5
            alert = Alert(
                id=str(uuid.uuid4()),
                timestamp=entry.timestamp,
                rule_name=rule['name'],
                severity=rule['severity'],
                description=f"{rule['description']}: {entry.message}",
                host=entry.host,
                user=entry.user,
                ip=entry.ip,
                event_ids=[entry.event_id],
                mitre_technique=rule.get('mitre', ''),
                raw_events=[entry]
            )
            alerts.append(alert)
        return alerts
    
    # Normal rule processing...
```

Run detection again:

```bash
python run.py --detect

# Should now generate TEST alerts
# If still nothing, detector isn't running at all (check for exceptions)
```

#### Step 7: Verify alerts are being indexed

Even if alerts are generated, they might not be indexed:

```python
# Add to core_detection.py after generating alerts:

async def detect(self, index_pattern="filebeat-*", max_logs=1000):
    # ... detect logic ...
    alerts = []
    # ... generate alerts ...
    
    logger.info(f"Generated {len(alerts)} alerts")
    
    # Index alerts to OpenSearch
    if alerts:
        try:
            for alert in alerts:
                self.opensearch_client.index(
                    index="security-alerts",
                    body=alert.to_dict(),
                    refresh=True  # Force immediate visibility
                )
            logger.info(f"Successfully indexed {len(alerts)} alerts")
        except Exception as e:
            logger.error(f"Failed to index alerts: {e}")
    
    return alerts
```

Verify alerts appear:

```bash
# Run detection
python run.py --detect

# Check alert index
curl "http://localhost:9200/security-alerts/_count?pretty"
# Should show count > 0

# View alerts
curl -X GET "http://localhost:9200/security-alerts/_search?pretty" -H 'Content-Type: application/json' -d'
{
  "size": 5,
  "sort": [{"timestamp": "desc"}]
}'
```

### ✅ Verification

```bash
# Complete test workflow:

# 1. Generate simulated attacks
python run.py --simulate

# 2. Wait for indexing
sleep 15

# 3. Run detection with verbose output
python run.py --detect | tee detection_output.txt

# 4. Check alerts were created
curl "http://localhost:9200/security-alerts/_count?pretty"
# Should show count > 0

# 5. View alerts
curl -X GET "http://localhost:9200/security-alerts/_search?pretty&size=5"

# 6. Verify in dashboard
# Open: http://localhost:8501
# Should display alerts in "Recent Alerts" section
```

---

## 24. ML Model Not Training or Missing

### ❌ Problem (ANOMALY DETECTION BROKEN)

**Symptom:**
- `models/isolation_forest_model.joblib` doesn't exist
- `python run.py --train` fails with error
- Anomaly detection always returns empty results

**Possible causes:**
1. scikit-learn not installed
2. Not enough training data
3. Training timeout
4. Disk full (can't write model file)
5. Code bugs in training logic

**Impact:**
- ❌ Anomaly-based detection doesn't work
- ❌ Only rule-based detection available
- ❌ Miss zero-day attacks

### ✅ Solution - DETAILED FIX

#### Step 1: Install ML dependencies

```bash
# Check if scikit-learn is installed
python -c "import sklearn; print(f'scikit-learn version: {sklearn.__version__}')"

# If not installed:
pip install scikit-learn==1.3.0
pip install numpy pandas

# Verify installation
python -c "
from sklearn.ensemble import IsolationForest
print('✓ IsolationForest imported successfully')
from joblib import dump, load
print('✓ joblib available')
import numpy as np
print('✓ numpy available')
"
```

#### Step 2: Ensure sufficient training data

```bash
# Check how many logs exist
curl "http://localhost:9200/filebeat-*/_count?pretty"

# Need at least 1000 logs for meaningful training
# If count < 1000, generate more:
python run.py --simulate
python run.py --simulate
python run.py --simulate

# Wait for indexing
sleep 20

# Verify count increased
curl "http://localhost:9200/filebeat-*/_count?pretty"
```

#### Step 3: Test model training manually

Create `test_training.py`:

```python
import asyncio
from utilities import train_anomaly_model
import logging

logging.basicConfig(level=logging.INFO)

async def test_training():
    """Test ML model training"""
    try:
        print("Starting model training...")
        print("This may take 1-5 minutes depending on data volume...")
        
        success = await train_anomaly_model(
            min_samples=100,  # Lower threshold for testing
            max_samples=5000
        )
        
        if success:
            print("\n✓ Model trained successfully!")
            print("  Model saved to: models/isolation_forest_model.joblib")
            
            # Test loading the model
            from joblib import load
            model = load('models/isolation_forest_model.joblib')
            print(f"✓ Model loaded successfully")
            print(f"  Model type: {type(model)}")
            print(f"  Estimators: {model.n_estimators}")
        else:
            print("\n✗ Training failed - check logs for details")
    
    except Exception as e:
        print(f"\n✗ Training error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_training())
```

Run test:

```bash
python test_training.py

# Should show:
# - Fetching training data...
# - Training model...
# - ✓ Model trained successfully!

# If fails with "not enough samples":
# - Generate more logs (see Step 2)

# If fails with memory error:
# - Reduce max_samples in training function
```

#### Step 4: Fix training function in utilities.py

Update `train_anomaly_model()` with better error handling:

```python
async def train_anomaly_model(min_samples=1000, max_samples=10000):
    """
    Train Isolation Forest model for anomaly detection
    
    Args:
        min_samples: Minimum samples required for training
        max_samples: Maximum samples to use (prevent OOM)
    """
    try:
        from sklearn.ensemble import IsolationForest
        from joblib import dump
        import numpy as np
        
        logger.info("Starting ML model training...")
        
        # Create OpenSearch client
        client = OpenSearch(
            hosts=[{'host': 'localhost', 'port': 9200}],
            timeout=60
        )
        
        # Fetch training data
        logger.info(f"Fetching up to {max_samples} logs for training...")
        
        response = client.search(
            index="filebeat-*",
            body={
                "size": max_samples,
                "query": {
                    "range": {
                        "@timestamp": {
                            "gte": "now-7d"  # Last 7 days
                        }
                    }
                }
            }
        )
        
        logs = response['hits']['hits']
        logger.info(f"Fetched {len(logs)} logs")
        
        if len(logs) < min_samples:
            logger.error(f"Not enough training data: {len(logs)} < {min_samples}")
            logger.error("Generate more logs: python run.py --simulate")
            return False
        
        # Extract features
        logger.info("Extracting features from logs...")
        features = []
        
        for hit in logs:
            source = hit['_source']
            
            # Extract numeric features
            feature_vector = [
                source.get('event_id', 0),
                hash(source.get('host', '')) % 10000,
                hash(source.get('user', '')) % 10000,
                len(source.get('message', '')),
                len(source.get('process_name', '')),
                1 if source.get('severity') == 'critical' else 0,
                1 if source.get('severity') == 'high' else 0
            ]
            
            features.append(feature_vector)
        
        X = np.array(features)
        logger.info(f"Feature matrix shape: {X.shape}")
        
        # Train model
        logger.info("Training Isolation Forest model...")
        model = IsolationForest(
            n_estimators=100,
            max_samples='auto',
            contamination=0.1,  # Expect 10% anomalies
            random_state=42,
            verbose=1
        )
        
        model.fit(X)
        logger.info("Training completed")
        
        # Save model
        models_dir = Path("models")
        models_dir.mkdir(exist_ok=True)
        
        model_path = models_dir / "isolation_forest_model.joblib"
        dump(model, model_path)
        logger.info(f"Model saved to: {model_path}")
        
        # Save feature names for consistency
        feature_info = {
            'features': ['event_id', 'host_hash', 'user_hash', 'msg_len', 
                        'proc_len', 'is_critical', 'is_high'],
            'trained_on': len(X),
            'trained_at': datetime.now().isoformat()
        }
        
        info_path = models_dir / "model_info.json"
        with open(info_path, 'w') as f:
            json.dump(feature_info, f, indent=2)
        
        logger.info("✓ Model training successful!")
        return True
        
    except ImportError as e:
        logger.error(f"Missing ML dependencies: {e}")
        logger.error("Install: pip install scikit-learn numpy")
        return False
        
    except MemoryError:
        logger.error("Out of memory during training")
        logger.error(f"Try reducing max_samples (current: {max_samples})")
        return False
        
    except Exception as e:
        logger.exception(f"Training failed: {e}")
        return False
```

#### Step 5: Add model validation

Create validation function in `utilities.py`:

```python
def validate_model():
    """Validate trained model works correctly"""
    try:
        from joblib import load
        import numpy as np
        
        model_path = Path("models/isolation_forest_model.joblib")
        
        if not model_path.exists():
            logger.error("Model file not found")
            return False
        
        # Load model
        model = load(model_path)
        logger.info("✓ Model loaded successfully")
        
        # Test prediction
        test_data = np.array([[
            4624,  # event_id
            1234,  # host_hash
            5678,  # user_hash
            50,    # msg_len
            10,    # proc_len
            0,     # is_critical
            0      # is_high
        ]])
        
        prediction = model.predict(test_data)
        score = model.score_samples(test_data)
        
        logger.info(f"✓ Test prediction successful")
        logger.info(f"  Prediction: {prediction[0]} (1=normal, -1=anomaly)")
        logger.info(f"  Anomaly score: {score[0]:.4f}")
        
        return True
        
    except Exception as e:
        logger.error(f"Model validation failed: {e}")
        return False


# Add to run.py argparse:
parser.add_argument('--validate-model', action='store_true',
                   help='Validate trained ML model')

# In main():
if args.validate_model:
    validate_model()
    return
```

#### Step 6: Automate model training

Add automatic training if model is missing:

```python
# In run.py, before starting detection:

def ensure_model_trained():
    """Ensure ML model exists, train if needed"""
    model_path = Path("models/isolation_forest_model.joblib")
    
    if model_path.exists():
        logger.info("✓ ML model found")
        return True
    
    logger.warning("ML model not found - training now...")
    logger.info("This will take a few minutes...")
    
    success = asyncio.run(train_anomaly_model(min_samples=100))
    
    if success:
        logger.info("✓ Model trained successfully")
        return True
    else:
        logger.error("✗ Model training failed")
        logger.warning("Anomaly detection will be disabled")
        return False

# In main():
if args.detect or args.all:
    ensure_model_trained()
    # ... continue with detection
```

### ✅ Verification

```bash
# Test complete training workflow:

# 1. Remove existing model
rm -f models/isolation_forest_model.joblib

# 2. Ensure training data exists
python run.py --simulate
sleep 15

# 3. Train model
python run.py --train

# Should show:
# - Fetching logs...
# - Training model...
# - ✓ Model saved

# 4. Verify model file
ls -lh models/
# Should show: isolation_forest_model.joblib (size > 0)

# 5. Validate model
python run.py --validate-model

# Should show:
# - ✓ Model loaded
# - ✓ Test prediction successful

# 6. Test in detection
python run.py --detect

# Should work without model errors
```

---

## 25. Threat Intel APIs Rate Limited or Not Working

### ❌ Problem (ENRICHMENT FAILS)

**Symptom:**
- Alerts are generated but never enriched
- `enriched-alerts` index empty
- Logs show "API rate limit exceeded"
- Threat intel lookups timeout

**Possible causes:**
1. No API keys configured (.env missing)
2. API keys invalid or expired
3. Rate limits exceeded
4. Network/firewall blocking API requests
5. API endpoints changed/deprecated

**Impact:**
- ❌ No threat context for alerts
- ❌ Can't differentiate false positives
- ❌ Miss known malicious IPs
- ❌ Poor incident response

### ✅ Solution - DETAILED FIX

#### Step 1: Configure API keys in .env

Create or update `.env` file:

```bash
# ============================================================================
# THREAT INTELLIGENCE API KEYS
# ============================================================================

# VirusTotal (FREE: 4 requests/minute, 500/day)
# Get key: https://www.virustotal.com/gui/join-us
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here

# AbuseIPDB (FREE: 1,000 requests/day)
# Get key: https://www.abuseipdb.com/register
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here

# AlienVault OTX (FREE: unlimited with account)
# Get key: https://otx.alienvault.com/api
OTX_API_KEY=your_otx_api_key_here

# Shodan (PAID: various plans)
# Get key: https://account.shodan.io/
SHODAN_API_KEY=your_shodan_api_key_here

# ============================================================================
# API RATE LIMITING SETTINGS
# ============================================================================

# Delay between API requests (seconds)
API_REQUEST_DELAY=1

# Max retries for failed requests
API_MAX_RETRIES=3

# Request timeout (seconds)
API_REQUEST_TIMEOUT=30

# Enable/disable specific sources
ENABLE_VIRUSTOTAL=true
ENABLE_ABUSEIPDB=true
ENABLE_OTX=true
ENABLE_SHODAN=false

# Use local threat intel DB as fallback
USE_LOCAL_INTEL_DB=true
LOCAL_INTEL_DB_PATH=data/threat_intel.db
```

#### Step 2: Test API connectivity

Create `test_threat_intel.py`:

```python
import os
import requests
from dotenv import load_dotenv

load_dotenv()

def test_virustotal():
    """Test VirusTotal API"""
    api_key = os.getenv('VIRUSTOTAL_API_KEY')
    
    if not api_key or api_key == 'your_virustotal_api_key_here':
        print("❌ VirusTotal: No API key configured")
        return False
    
    # Test with known malicious IP
    test_ip = "8.8.8.8"
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{test_ip}"
    headers = {"x-apikey": api_key}
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            print("✓ VirusTotal: API working")
            data = response.json()
            print(f"  Reputation: {data.get('data', {}).get('attributes', {}).get('reputation', 'N/A')}")
            return True
        elif response.status_code == 401:
            print("❌ VirusTotal: Invalid API key")
            return False
        elif response.status_code == 429:
            print("⚠️  VirusTotal: Rate limit exceeded")
            return False
        else:
            print(f"❌ VirusTotal: HTTP {response.status_code}")
            return False
    
    except requests.RequestException as e:
        print(f"❌ VirusTotal: Connection error - {e}")
        return False


def test_abuseipdb():
    """Test AbuseIPDB API"""
    api_key = os.getenv('ABUSEIPDB_API_KEY')
    
    if not api_key or api_key == 'your_abuseipdb_api_key_here':
        print("❌ AbuseIPDB: No API key configured")
        return False
    
    test_ip = "8.8.8.8"
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": test_ip}
    
    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        
        if response.status_code == 200:
            print("✓ AbuseIPDB: API working")
            data = response.json()
            abuse_score = data.get('data', {}).get('abuseConfidenceScore', 0)
            print(f"  Abuse Score: {abuse_score}%")
            return True
        elif response.status_code == 401:
            print("❌ AbuseIPDB: Invalid API key")
            return False
        elif response.status_code == 429:
            print("⚠️  AbuseIPDB: Rate limit exceeded")
            return False
        else:
            print(f"❌ AbuseIPDB: HTTP {response.status_code}")
            return False
    
    except requests.RequestException as e:
        print(f"❌ AbuseIPDB: Connection error - {e}")
        return False


def test_otx():
    """Test AlienVault OTX API"""
    api_key = os.getenv('OTX_API_KEY')
    
    if not api_key or api_key == 'your_otx_api_key_here':
        print("❌ AlienVault OTX: No API key configured")
        return False
    
    test_ip = "8.8.8.8"
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{test_ip}/general"
    headers = {"X-OTX-API-KEY": api_key}
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            print("✓ AlienVault OTX: API working")
            data = response.json()
            pulse_count = data.get('pulse_info', {}).get('count', 0)
            print(f"  Pulse Count: {pulse_count}")
            return True
        elif response.status_code == 403:
            print("❌ AlienVault OTX: Invalid API key")
            return False
        else:
            print(f"❌ AlienVault OTX: HTTP {response.status_code}")
            return False
    
    except requests.RequestException as e:
        print(f"❌ AlienVault OTX: Connection error - {e}")
        return False


if __name__ == "__main__":
    print("\n=== THREAT INTELLIGENCE API TESTS ===\n")
    
    results = {
        "VirusTotal": test_virustotal(),
        "AbuseIPDB": test_abuseipdb(),
        "AlienVault OTX": test_otx()
    }
    
    print("\n" + "="*40)
    working = sum(results.values())
    total = len(results)
    print(f"Working APIs: {working}/{total}")
    
    if working == 0:
        print("\n⚠️  WARNING: No threat intelligence APIs configured!")
        print("   Enrichment will rely only on local database")
    
    print("="*40)
```

Run test:

```bash
python test_threat_intel.py

# Should show status of each API
# Fix any that show ❌ or ⚠️
```

#### Step 3: Implement rate limiting in core_detection.py

Update `IntelEnricher` class:

```python
import time
from collections import deque
from datetime import datetime, timedelta

class IntelEnricher:
    """Threat intelligence enricher with rate limiting"""
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.cache: Dict[str, Dict[str, Any]] = {}
        
        # Rate limiting queues (track recent requests)
        self.vt_requests = deque()  # VirusTotal: 4 requests/minute
        self.abuseipdb_requests = deque()  # AbuseIPDB: 1000/day
        self.otx_requests = deque()  # OTX: unlimited
        
        # Rate limits
        self.vt_limit = 4  # per minute
        self.vt_window = 60  # seconds
        self.abuseipdb_limit = 1000  # per day
        self.abuseipdb_window = 86400  # seconds
        
        # Delays
        self.request_delay = int(os.getenv('API_REQUEST_DELAY', '1'))
    
    def _check_rate_limit(self, service: str) -> bool:
        """Check if we can make a request without exceeding rate limit"""
        now = time.time()
        
        if service == 'virustotal':
            # Remove old requests outside the window
            while self.vt_requests and self.vt_requests[0] < now - self.vt_window:
                self.vt_requests.popleft()
            
            # Check if we're at limit
            if len(self.vt_requests) >= self.vt_limit:
                wait_time = self.vt_window - (now - self.vt_requests[0])
                logger.warning(f"VirusTotal rate limit reached. Wait {wait_time:.0f}s")
                return False
            
            self.vt_requests.append(now)
            return True
        
        elif service == 'abuseipdb':
            while self.abuseipdb_requests and self.abuseipdb_requests[0] < now - self.abuseipdb_window:
                self.abuseipdb_requests.popleft()
            
            if len(self.abuseipdb_requests) >= self.abuseipdb_limit:
                logger.warning("AbuseIPDB daily limit reached")
                return False
            
            self.abuseipdb_requests.append(now)
            return True
        
        return True  # OTX has no rate limit
    
    async def check_ip_reputation(self, ip_address: str) -> Dict[str, Any]:
        """Check IP reputation with rate limiting"""
        # Check cache first
        cache_key = f"ip:{ip_address}"
        if cache_key in self.cache:
            cache_age = time.time() - self.cache[cache_key].get('cached_at', 0)
            if cache_age < 3600:  # Cache for 1 hour
                logger.debug(f"Using cached result for {ip_address}")
                return self.cache[cache_key]
        
        result = {
            'ip': ip_address,
            'malicious': False,
            'reputation_score': 0,
            'sources': [],
            'details': {}
        }
        
        # VirusTotal
        if os.getenv('ENABLE_VIRUSTOTAL', 'true').lower() == 'true':
            if self._check_rate_limit('virustotal'):
                vt_result = await self._check_virustotal(ip_address)
                if vt_result:
                    result['sources'].append('virustotal')
                    result['details']['virustotal'] = vt_result
                    if vt_result.get('malicious', False):
                        result['malicious'] = True
                time.sleep(self.request_delay)
        
        # AbuseIPDB
        if os.getenv('ENABLE_ABUSEIPDB', 'true').lower() == 'true':
            if self._check_rate_limit('abuseipdb'):
                abuseipdb_result = await self._check_abuseipdb(ip_address)
                if abuseipdb_result:
                    result['sources'].append('abuseipdb')
                    result['details']['abuseipdb'] = abuseipdb_result
                    abuse_score = abuseipdb_result.get('abuseConfidenceScore', 0)
                    if abuse_score > 75:
                        result['malicious'] = True
                    result['reputation_score'] = max(result['reputation_score'], abuse_score)
                time.sleep(self.request_delay)
        
        # AlienVault OTX
        if os.getenv('ENABLE_OTX', 'true').lower() == 'true':
            otx_result = await self._check_otx(ip_address)
            if otx_result:
                result['sources'].append('otx')
                result['details']['otx'] = otx_result
                if otx_result.get('pulse_count', 0) > 0:
                    result['malicious'] = True
            time.sleep(self.request_delay)
        
        # Local DB fallback
        if not result['sources'] or os.getenv('USE_LOCAL_INTEL_DB', 'true').lower() == 'true':
            local_result = await self._check_local_db(ip_address)
            if local_result:
                result['sources'].append('local_db')
                result['details']['local_db'] = local_result
                if local_result.get('malicious', False):
                    result['malicious'] = True
        
        # Cache result
        result['cached_at'] = time.time()
        self.cache[cache_key] = result
        
        return result
    
    async def _check_virustotal(self, ip_address: str) -> Optional[Dict]:
        """Query VirusTotal API"""
        api_key = os.getenv('VIRUSTOTAL_API_KEY')
        if not api_key or api_key == 'your_virustotal_api_key_here':
            return None
        
        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
            headers = {"x-apikey": api_key}
            
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                last_analysis = attributes.get('last_analysis_stats', {})
                
                malicious_count = last_analysis.get('malicious', 0)
                
                return {
                    'malicious': malicious_count > 0,
                    'malicious_count': malicious_count,
                    'reputation': attributes.get('reputation', 0),
                    'last_seen': attributes.get('last_analysis_date')
                }
            else:
                logger.warning(f"VirusTotal API error: {response.status_code}")
                return None
        
        except Exception as e:
            logger.error(f"VirusTotal lookup failed: {e}")
            return None
```

#### Step 4: Create local threat intel database

Create `utilities.py` function to build local DB:

```python
async def update_threat_intel_db():
    """Update local threat intelligence database"""
    import sqlite3
    
    try:
        db_path = Path(os.getenv('LOCAL_INTEL_DB_PATH', 'data/threat_intel.db'))
        db_path.parent.mkdir(exist_ok=True)
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Create tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS malicious_ips (
                ip TEXT PRIMARY KEY,
                first_seen TIMESTAMP,
                last_seen TIMESTAMP,
                source TEXT,
                confidence INTEGER,
                description TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS malicious_domains (
                domain TEXT PRIMARY KEY,
                first_seen TIMESTAMP,
                last_seen TIMESTAMP,
                source TEXT,
                confidence INTEGER,
                description TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS malicious_hashes (
                hash TEXT PRIMARY KEY,
                hash_type TEXT,
                first_seen TIMESTAMP,
                malware_family TEXT,
                source TEXT,
                description TEXT
            )
        ''')
        
        conn.commit()
        
        # Import known malicious IPs (example - you'd fetch from threat feeds)
        known_malicious = [
            ('203.0.113.1', 'tor_exit_node', 90, 'Known Tor exit node'),
            ('198.51.100.1', 'c2_server', 95, 'Command and control server'),
            ('192.0.2.1', 'scanner', 70, 'Known port scanner')
        ]
        
        for ip, source, confidence, description in known_malicious:
            cursor.execute('''
                INSERT OR REPLACE INTO malicious_ips 
                (ip, first_seen, last_seen, source, confidence, description)
                VALUES (?, datetime('now'), datetime('now'), ?, ?, ?)
            ''', (ip, source, confidence, description))
        
        conn.commit()
        conn.close()
        
        logger.info(f"✓ Local threat intel DB updated: {db_path}")
        return True
    
    except Exception as e:
        logger.exception(f"Failed to update threat intel DB: {e}")
        return False


# Add to run.py argparse:
parser.add_argument('--update-intel', action='store_true',
                   help='Update local threat intelligence database')

# In main():
if args.update_intel:
    asyncio.run(update_threat_intel_db())
    return
```

#### Step 5: Add fallback for API failures

Update enrichment to gracefully handle API failures:

```python
async def enrich_alert(self, alert: Alert, use_cache: bool = True) -> Optional[Alert]:
    """Enrich alert with threat intelligence (with fallbacks)"""
    try:
        enrichment = {
            'enriched_at': datetime.now().isoformat(),
            'sources_queried': [],
            'sources_succeeded': [],
            'threat_intel': {}
        }
        
        # Try to enrich with IP reputation
        if alert.ip and alert.ip != 'unknown':
            enrichment['sources_queried'].append('ip_reputation')
            
            try:
                ip_intel = await self.check_ip_reputation(alert.ip)
                if ip_intel and ip_intel.get('sources'):
                    enrichment['threat_intel']['ip'] = ip_intel
                    enrichment['sources_succeeded'].append('ip_reputation')
                    
                    # Update alert if malicious
                    if ip_intel.get('malicious'):
                        alert.tags.append('known_malicious_ip')
                        if alert.severity != 'Critical':
                            alert.severity = 'High'
            except Exception as e:
                logger.error(f"IP reputation check failed: {e}")
        
        # Add enrichment metadata to alert
        alert.raw_events[0].raw_data['enrichment'] = enrichment
        
        # Index enriched alert
        if self.opensearch_client:
            try:
                self.opensearch_client.index(
                    index='enriched-alerts',
                    body={
                        'alert_id': alert.id,
                        'enrichment': enrichment,
                        'timestamp': datetime.now().isoformat()
                    }
                )
            except Exception as e:
                logger.error(f"Failed to index enriched alert: {e}")
        
        return alert
    
    except Exception as e:
        logger.exception(f"Alert enrichment failed completely: {e}")
        return alert  # Return un-enriched alert rather than None
```

### ✅ Verification

```bash
# Test API connectivity
python test_threat_intel.py

# Should show working APIs

# Test enrichment
python run.py --simulate
sleep 15
python run.py --detect

# Check enriched alerts index
curl "http://localhost:9200/enriched-alerts/_search?pretty&size=5"

# Should show enrichment data

# Monitor rate limiting
tail -f logs/threat_ops.log | grep -i "rate limit"

# Should not see constant rate limit warnings
```

---

## 26. Tests Failing - Import Errors

### ❌ Problem (TESTS DON'T RUN)

**Symptom:**
```bash
$ pytest tests/
ERROR: Import error: cannot import name 'ThreatDetector'
ModuleNotFoundError: No module named 'core_detection'
```

**Causes:**
1. PYTHONPATH not set correctly
2. Running pytest from wrong directory
3. `__init__.py` files missing
4. Relative imports broken

**Impact:**
- ❌ Can't run tests
- ❌ Can't verify code quality
- ❌ Risky deployments

### ✅ Solution - DETAILED FIX

#### Step 1: Fix directory structure

```bash
# Ensure __init__.py exists in tests/
touch tests/__init__.py

# Verify structure
tree -L 2
# Should show:
# threat_ops/
# ├── core_detection.py
# ├── reporting.py
# ├── simulation.py
# ├── utilities.py
# ├── application.py
# ├── run.py
# └── tests/
#     ├── __init__.py
#     ├── conftest.py
#     ├── test_core_detection.py
#     └── ...
```

#### Step 2: Add sys.path manipulation to conftest.py

Edit `tests/conftest.py`:

```python
import sys
from pathlib import Path

# Add parent directory to Python path
# This allows: from core_detection import ThreatDetector
project_root = Path(__file__).parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

import pytest
from unittest.mock import Mock, MagicMock
import asyncio

# Rest of conftest.py...
```

#### Step 3: Run tests from correct directory

```bash
# CORRECT - from project root:
cd /Users/kaushalyadav/Desktop/Cusor\ AI/threat_ops
pytest tests/ -v

# WRONG - from tests directory:
cd tests
pytest .  # Will fail with import errors
```

#### Step 4: Set PYTHONPATH environment variable

**Temporary (current shell):**

```bash
# Mac/Linux:
export PYTHONPATH="/Users/kaushalyadav/Desktop/Cusor AI/threat_ops:$PYTHONPATH"

# Windows (PowerShell):
$env:PYTHONPATH="D:\Cusor AI\threat_ops;$env:PYTHONPATH"

# Windows (CMD):
set PYTHONPATH=D:\Cusor AI\threat_ops;%PYTHONPATH%

# Then run tests:
pytest tests/ -v
```

**Permanent (add to shell profile):**

```bash
# Mac/Linux - add to ~/.bashrc or ~/.zshrc:
echo 'export PYTHONPATH="/Users/kaushalyadav/Desktop/Cusor AI/threat_ops:$PYTHONPATH"' >> ~/.zshrc

# Reload:
source ~/.zshrc

# Windows - set system environment variable:
# 1. Win + R -> sysdm.cpl
# 2. Advanced -> Environment Variables
# 3. Add PYTHONPATH with project path
```

#### Step 5: Use pytest.ini for configuration

Create `pytest.ini` in project root:

```ini
[pytest]
# Python path
pythonpath = .

# Test discovery
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*

# Output options
addopts = 
    -v
    --tb=short
    --strict-markers
    --disable-warnings
    -p no:cacheprovider

# Markers
markers =
    slow: marks tests as slow (deselect with '-m "not slow"')
    integration: marks tests as integration tests
    unit: marks tests as unit tests

# Minimum version
minversion = 7.0

# Asyncio mode
asyncio_mode = auto
```

#### Step 6: Fix imports in test files

Update test files to use absolute imports:

```python
# test_core_detection.py

# GOOD - absolute imports:
from core_detection import ThreatDetector, LogEntry, Alert
from application import Settings

# BAD - relative imports (will break):
from ..core_detection import ThreatDetector  # Don't do this

import pytest
import asyncio
from datetime import datetime, timezone

class TestThreatDetector:
    """Test suite for ThreatDetector"""
    
    @pytest.mark.asyncio
    async def test_detector_initialization(self, mock_settings):
        """Test detector can be initialized"""
        detector = ThreatDetector(mock_settings)
        await detector.initialize()
        
        assert detector is not None
        assert detector.settings == mock_settings
        assert len(detector.detection_rules) > 0
    
    # More tests...
```

#### Step 7: Create run_tests.py wrapper

Update `tests/run_tests.py`:

```python
#!/usr/bin/env python3
"""
Test runner with automatic path configuration
"""
import sys
from pathlib import Path
import subprocess

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

def main():
    """Run pytest with correct configuration"""
    # Change to project root
    import os
    os.chdir(project_root)
    
    # Build pytest command
    pytest_args = [
        sys.executable, "-m", "pytest",
        "tests/",
        "-v",
        "--tb=short",
        "--color=yes"
    ]
    
    # Add any command-line arguments passed to this script
    pytest_args.extend(sys.argv[1:])
    
    print(f"Running tests from: {project_root}")
    print(f"Python path: {sys.path[0]}")
    print(f"Command: {' '.join(pytest_args)}\n")
    
    # Run pytest
    result = subprocess.run(pytest_args)
    sys.exit(result.returncode)

if __name__ == "__main__":
    main()
```

Make it executable:

```bash
chmod +x tests/run_tests.py

# Now you can run from anywhere:
python tests/run_tests.py
# OR
./tests/run_tests.py
```

#### Step 8: Add IDE-specific configurations

**VS Code** - Create `.vscode/settings.json`:

```json
{
    "python.testing.pytestEnabled": true,
    "python.testing.unittestEnabled": false,
    "python.testing.pytestArgs": [
        "tests",
        "-v"
    ],
    "python.testing.cwd": "${workspaceFolder}",
    "python.analysis.extraPaths": [
        "${workspaceFolder}"
    ],
    "python.envFile": "${workspaceFolder}/.env"
}
```

**PyCharm** - Mark directory as source root:
1. Right-click on `threat_ops` folder
2. Mark Directory as → Sources Root
3. Tests should now work

### ✅ Verification

```bash
# Test from project root
cd /Users/kaushalyadav/Desktop/Cusor\ AI/threat_ops

# Run all tests
pytest tests/ -v

# Should show:
# tests/test_core_detection.py::TestThreatDetector::test_detector_initialization PASSED
# tests/test_simulation.py::TestAttackSimulator::test_simulator_init PASSED
# ...

# Run specific test file
pytest tests/test_core_detection.py -v

# Run specific test
pytest tests/test_core_detection.py::TestThreatDetector::test_detector_initialization -v

# Run with coverage
pytest tests/ --cov=. --cov-report=html

# All should pass without import errors
```

---

Before running ThreatOps SIEM, verify:

### Environment Setup
- [ ] `.env` file exists with all paths set
- [ ] OPENSEARCH_HOME, FILEBEAT_HOME, DASHBOARDS_HOME configured
- [ ] API keys added (optional but recommended)

### Dependencies
- [ ] `pip install -r requirements.txt` completed
- [ ] `python check_dependencies.py` passes
- [ ] `pytest` and `pytest-cov` installed

### Services
- [ ] OpenSearch running: `curl http://localhost:9200`
- [ ] Security disabled in opensearch.yml
- [ ] Filebeat configured with correct paths

---

## 27. Tests Failing - Fixtures Not Found

### ❌ Problem (FIXTURES BROKEN)

**Symptom:**
```bash
$ pytest tests/test_core_detection.py
ERROR: fixture 'mock_settings' not found
ERROR: fixture 'mock_opensearch_client' not found
```

**Causes:**
1. `conftest.py` missing or incorrectly configured
2. Fixture names don't match usage
3. Fixture scope issues
4. Import errors in `conftest.py`

**Impact:**
- ❌ Tests can't run
- ❌ Duplicate test setup code
- ❌ Inconsistent test behavior

### ✅ Solution - DETAILED FIX

#### Step 1: Create comprehensive conftest.py

Create or update `tests/conftest.py`:

```python
"""
Pytest configuration and shared fixtures for ThreatOps SIEM tests
"""
import sys
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

import pytest
from unittest.mock import Mock, MagicMock, patch, AsyncMock
import asyncio
from datetime import datetime, timezone
import os
import tempfile

# Import project modules
from core_detection import ThreatDetector, LogEntry, Alert, IntelEnricher, RiskScorer
from simulation import AttackSimulator, AttackScenario
from reporting import ReportGenerator, AlertNotifier, SOARIntegrator
from utilities import setup_opensearch, train_anomaly_model
from application import Settings


# ==============================================================================
# PYTEST CONFIGURATION
# ==============================================================================

def pytest_configure(config):
    """Configure pytest"""
    # Set test environment
    os.environ['TESTING'] = 'true'
    os.environ['LOG_LEVEL'] = 'DEBUG'


@pytest.fixture(scope="session")
def event_loop():
    """Create an event loop for async tests"""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


# ==============================================================================
# SETTINGS FIXTURES
# ==============================================================================

@pytest.fixture
def mock_settings():
    """Mock Settings object with test configuration"""
    settings = Settings()
    settings.opensearch_host = 'localhost'
    settings.opensearch_port = 9200
    settings.log_level = 'DEBUG'
    
    return settings


@pytest.fixture
def mock_settings_no_opensearch():
    """Mock Settings with OpenSearch disabled"""
    settings = Settings()
    settings.opensearch_enabled = False
    return settings


# ==============================================================================
# OPENSEARCH FIXTURES
# ==============================================================================

@pytest.fixture
def mock_opensearch_client():
    """Mock OpenSearch client"""
    client = Mock()
    
    # Mock search response
    client.search.return_value = {
        'hits': {
            'total': {'value': 10},
            'hits': [
                {
                    '_id': '1',
                    '_source': {
                        'timestamp': datetime.now(timezone.utc).isoformat(),
                        'event_id': 4624,
                        'host': 'test-host',
                        'user': 'testuser',
                        'ip': '192.168.1.100',
                        'message': 'Successful login'
                    }
                }
            ]
        }
    }
    
    # Mock index operation
    client.index.return_value = {'result': 'created', '_id': '12345'}
    
    # Mock ping
    client.ping.return_value = True
    
    # Mock count
    client.count.return_value = {'count': 100}
    
    # Mock cluster health
    client.cluster.health.return_value = {
        'status': 'green',
        'number_of_nodes': 1
    }
    
    return client


@pytest.fixture
def mock_opensearch_client_failing():
    """Mock OpenSearch client that always fails"""
    client = Mock()
    client.search.side_effect = Exception("Connection refused")
    client.ping.return_value = False
    return client


# ==============================================================================
# LOG ENTRY FIXTURES
# ==============================================================================

@pytest.fixture
def sample_log_entry():
    """Sample log entry for testing"""
    return LogEntry(
        timestamp=datetime.now(timezone.utc),
        host='test-host',
        user='testuser',
        event_id=4624,
        ip='192.168.1.100',
        message='Successful login attempt',
        process_name='winlogon.exe',
        command_line='',
        event_type='authentication',
        severity='info',
        source='windows_security'
    )


@pytest.fixture
def malicious_log_entries():
    """Collection of malicious log entries for testing detection"""
    entries = []
    
    # Failed login attempts (brute force)
    for i in range(5):
        entries.append(LogEntry(
            timestamp=datetime.now(timezone.utc),
            host='test-host',
            user='admin',
            event_id=4625,
            ip='192.168.1.100',
            message=f'Failed login attempt {i+1}',
            severity='warning',
            source='test'
        ))
    
    # Mimikatz execution
    entries.append(LogEntry(
        timestamp=datetime.now(timezone.utc),
        host='test-host',
        user='user1',
        event_id=4688,
        process_name='mimikatz.exe',
        command_line='mimikatz.exe privilege::debug sekurlsa::logonpasswords',
        ip='192.168.1.50',
        message='Process created',
        severity='info',
        source='test'
    ))
    
    return entries


# ==============================================================================
# ALERT FIXTURES
# ==============================================================================

@pytest.fixture
def sample_alert():
    """Sample alert for testing"""
    return Alert(
        id='test-alert-001',
        timestamp=datetime.now(timezone.utc),
        rule_name='Test Rule',
        severity='High',
        description='Test alert description',
        host='test-host',
        user='testuser',
        ip='192.168.1.100',
        event_ids=[4624, 4625],
        mitre_technique='T1110',
        confidence=0.85,
        raw_events=[],
        tags=['test'],
        status='open'
    )


@pytest.fixture
def critical_alert():
    """Critical severity alert for testing"""
    return Alert(
        id='test-alert-critical',
        timestamp=datetime.now(timezone.utc),
        rule_name='Critical Security Event',
        severity='Critical',
        description='Mimikatz detected',
        host='prod-server',
        user='admin',
        ip='10.0.0.50',
        event_ids=[4688],
        mitre_technique='T1003',
        confidence=0.95,
        raw_events=[],
        tags=['credential_access', 'mimikatz'],
        status='open'
    )


# ==============================================================================
# DETECTOR FIXTURES
# ==============================================================================

@pytest.fixture
async def threat_detector(mock_settings):
    """Initialized threat detector"""
    detector = ThreatDetector(mock_settings)
    await detector.initialize()
    return detector


@pytest.fixture
async def threat_detector_with_mock_client(mock_settings, mock_opensearch_client):
    """Threat detector with mocked OpenSearch client"""
    detector = ThreatDetector(mock_settings)
    detector.opensearch_client = mock_opensearch_client
    await detector.initialize()
    return detector


# ==============================================================================
# SIMULATION FIXTURES
# ==============================================================================

@pytest.fixture
def attack_simulator(mock_settings):
    """Attack simulator instance"""
    return AttackSimulator(mock_settings)


@pytest.fixture
def sample_attack_scenario():
    """Sample attack scenario"""
    return AttackScenario(
        name="Test Brute Force",
        mitre_technique="T1110",
        description="Simulated brute force attack",
        severity="High",
        indicators=["multiple_failed_logins", "rapid_auth_attempts"]
    )


# ==============================================================================
# REPORTING FIXTURES
# ==============================================================================

@pytest.fixture
def report_generator(mock_settings):
    """Report generator instance"""
    return ReportGenerator(mock_settings)


@pytest.fixture
def alert_notifier(mock_settings):
    """Alert notifier instance"""
    return AlertNotifier(mock_settings)


# ==============================================================================
# TEMPORARY DIRECTORY FIXTURES
# ==============================================================================

@pytest.fixture
def temp_data_dir():
    """Temporary data directory for test artifacts"""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def temp_report_dir():
    """Temporary directory for report generation tests"""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


# ==============================================================================
# ENVIRONMENT FIXTURES
# ==============================================================================

@pytest.fixture
def mock_env_vars(monkeypatch):
    """Mock environment variables for testing"""
    test_vars = {
        'OPENSEARCH_HOST': 'localhost',
        'OPENSEARCH_PORT': '9200',
        'VIRUSTOTAL_API_KEY': 'test_vt_key',
        'ABUSEIPDB_API_KEY': 'test_abuseipdb_key',
        'OTX_API_KEY': 'test_otx_key',
        'ENABLE_VIRUSTOTAL': 'true',
        'ENABLE_ABUSEIPDB': 'true',
        'ENABLE_OTX': 'true',
        'USE_LOCAL_INTEL_DB': 'true'
    }
    
    for key, value in test_vars.items():
        monkeypatch.setenv(key, value)
    
    return test_vars


@pytest.fixture
def mock_env_vars_no_apis(monkeypatch):
    """Mock environment with no API keys configured"""
    test_vars = {
        'OPENSEARCH_HOST': 'localhost',
        'OPENSEARCH_PORT': '9200',
        'ENABLE_VIRUSTOTAL': 'false',
        'ENABLE_ABUSEIPDB': 'false',
        'ENABLE_OTX': 'false',
        'USE_LOCAL_INTEL_DB': 'true'
    }
    
    for key, value in test_vars.items():
        monkeypatch.setenv(key, value)
    
    return test_vars


# ==============================================================================
# HELPER FIXTURES
# ==============================================================================

@pytest.fixture
def mock_requests():
    """Mock requests library"""
    with patch('requests.get') as mock_get, \
         patch('requests.post') as mock_post:
        
        # Mock successful response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'status': 'success'}
        
        mock_get.return_value = mock_response
        mock_post.return_value = mock_response
        
        yield {'get': mock_get, 'post': mock_post}


@pytest.fixture
def capture_logs(caplog):
    """Capture log output for testing"""
    import logging
    caplog.set_level(logging.DEBUG)
    return caplog


# ==============================================================================
# CLEANUP FIXTURES
# ==============================================================================

@pytest.fixture(autouse=True)
def cleanup_test_data():
    """Automatically cleanup test data after each test"""
    yield
    # Cleanup code runs after test
    test_files = [
        'test_alerts.json',
        'test_report.html',
        'test_report.pdf'
    ]
    for filename in test_files:
        path = Path(filename)
        if path.exists():
            path.unlink()
```

#### Step 2: Verify fixture discovery

```bash
# List all available fixtures
pytest --fixtures tests/

# Should show all fixtures from conftest.py:
# - mock_settings
# - mock_opensearch_client
# - sample_log_entry
# - malicious_log_entries
# - sample_alert
# - threat_detector
# etc.

# List fixtures used by specific test
pytest --setup-show tests/test_core_detection.py::TestThreatDetector::test_detector_initialization
```

#### Step 3: Update test files to use fixtures

```python
# test_core_detection.py

import pytest
from datetime import datetime, timezone

class TestThreatDetector:
    """Test suite for ThreatDetector"""
    
    @pytest.mark.asyncio
    async def test_detector_initialization(self, mock_settings):
        """Test detector can be initialized with mocked settings"""
        from core_detection import ThreatDetector
        
        detector = ThreatDetector(mock_settings)
        await detector.initialize()
        
        assert detector is not None
        assert detector.settings == mock_settings
        assert len(detector.detection_rules) > 0
    
    @pytest.mark.asyncio
    async def test_detect_with_mock_client(
        self, 
        threat_detector_with_mock_client,
        malicious_log_entries
    ):
        """Test detection using mocked OpenSearch client"""
        detector = threat_detector_with_mock_client
        
        # Mock will return predefined data
        alerts = await detector.detect()
        
        # Verify detector called OpenSearch
        assert detector.opensearch_client.search.called
        assert isinstance(alerts, list)
    
    def test_log_entry_creation(self, sample_log_entry):
        """Test LogEntry can be created"""
        assert sample_log_entry.host == 'test-host'
        assert sample_log_entry.user == 'testuser'
        assert sample_log_entry.event_id == 4624
    
    def test_log_entry_to_dict(self, sample_log_entry):
        """Test LogEntry serialization"""
        data = sample_log_entry.to_dict()
        
        assert isinstance(data, dict)
        assert data['host'] == 'test-host'
        assert 'timestamp' in data
```

#### Step 4: Add fixture debugging

Create `tests/test_fixtures.py` to test fixtures themselves:

```python
"""
Test that all fixtures work correctly
"""
import pytest

class TestFixtures:
    """Verify all fixtures are working"""
    
    def test_mock_settings_fixture(self, mock_settings):
        """Test mock_settings fixture"""
        assert mock_settings is not None
        assert mock_settings.opensearch_host == 'localhost'
    
    def test_mock_opensearch_client_fixture(self, mock_opensearch_client):
        """Test mock_opensearch_client fixture"""
        assert mock_opensearch_client is not None
        assert mock_opensearch_client.ping() is True
        
        # Test search mock
        result = mock_opensearch_client.search(index="test")
        assert 'hits' in result
    
    def test_sample_log_entry_fixture(self, sample_log_entry):
        """Test sample_log_entry fixture"""
        assert sample_log_entry is not None
        assert sample_log_entry.host == 'test-host'
    
    def test_malicious_log_entries_fixture(self, malicious_log_entries):
        """Test malicious_log_entries fixture"""
        assert len(malicious_log_entries) == 6  # 5 failed logins + 1 mimikatz
        assert malicious_log_entries[0].event_id == 4625
        assert malicious_log_entries[-1].process_name == 'mimikatz.exe'
    
    def test_sample_alert_fixture(self, sample_alert):
        """Test sample_alert fixture"""
        assert sample_alert is not None
        assert sample_alert.severity == 'High'
        assert sample_alert.rule_name == 'Test Rule'
    
    @pytest.mark.asyncio
    async def test_threat_detector_fixture(self, threat_detector):
        """Test threat_detector fixture"""
        assert threat_detector is not None
        assert len(threat_detector.detection_rules) > 0
    
    def test_temp_data_dir_fixture(self, temp_data_dir):
        """Test temp_data_dir fixture"""
        assert temp_data_dir.exists()
        assert temp_data_dir.is_dir()
        
        # Create a file in temp dir
        test_file = temp_data_dir / "test.txt"
        test_file.write_text("test content")
        assert test_file.exists()
    
    def test_mock_env_vars_fixture(self, mock_env_vars):
        """Test mock_env_vars fixture"""
        import os
        assert os.getenv('OPENSEARCH_HOST') == 'localhost'
        assert os.getenv('VIRUSTOTAL_API_KEY') == 'test_vt_key'
```

Run fixture tests:

```bash
pytest tests/test_fixtures.py -v

# All should pass
# If any fail, there's an issue with conftest.py
```

#### Step 5: Add fixture scope examples

```python
# In conftest.py, add different scopes:

@pytest.fixture(scope="session")
def expensive_setup():
    """Session-scoped fixture - runs once for entire test session"""
    print("\nExpensive setup running...")
    # Expensive operation here
    yield "session_data"
    print("\nExpensive cleanup running...")

@pytest.fixture(scope="module")
def module_level_data():
    """Module-scoped fixture - runs once per test module"""
    return {"module": "data"}

@pytest.fixture(scope="function")  # default scope
def test_level_data():
    """Function-scoped fixture - runs for each test"""
    return {"test": "data"}
```

#### Step 6: Handle fixture dependencies

```python
# Fixtures can depend on other fixtures:

@pytest.fixture
def configured_detector(mock_settings, mock_opensearch_client):
    """Detector configured with multiple fixtures"""
    detector = ThreatDetector(mock_settings)
    detector.opensearch_client = mock_opensearch_client
    return detector

@pytest.fixture
def enricher_with_mocks(mock_settings, mock_requests):
    """Enricher with mocked API requests"""
    enricher = IntelEnricher(mock_settings)
    # enricher will use mocked requests
    return enricher
```

### ✅ Verification

```bash
# Run all tests
pytest tests/ -v

# Should show fixture usage:
# tests/test_core_detection.py::TestThreatDetector::test_detector_initialization[mock_settings] PASSED

# Run with fixture setup details
pytest tests/ --setup-show

# Should show:
# SETUP    F mock_settings
# tests/test_core_detection.py::test_something (fixtures used: mock_settings)
# TEARDOWN F mock_settings

# List all fixtures
pytest --fixtures tests/

# Should show all available fixtures with descriptions

# Run single test with verbose fixture info
pytest tests/test_core_detection.py::TestThreatDetector::test_detector_initialization -vv --setup-show
```

---

## 28. Log Files Growing Too Large

### ❌ Problem (DISK FULL)

**Symptom:**
- `logs/threat_ops.log` grows to GB sizes
- Disk space warnings
- Application slows down
- Old logs never deleted

**Impact:**
- ❌ Disk fills up
- ❌ System crashes
- ❌ Log files unreadable (too big to open)
- ❌ Wasted storage

### ✅ Solution - DETAILED FIX

#### Step 1: Implement log rotation in application.py

Update logging configuration in `application.py`:

```python
import logging
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler
from pathlib import Path

def setup_logging(log_level: str = 'INFO'):
    """
    Configure logging with rotation
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR)
    """
    # Create logs directory
    log_dir = Path('logs')
    log_dir.mkdir(exist_ok=True)
    
    # Main application log (size-based rotation)
    main_log_file = log_dir / 'threat_ops.log'
    main_handler = RotatingFileHandler(
        main_log_file,
        maxBytes=10 * 1024 * 1024,  # 10 MB per file
        backupCount=5,               # Keep 5 old files
        encoding='utf-8'
    )
    main_handler.setLevel(logging.DEBUG)
    main_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    ))
    
    # Error log (separate file for errors only)
    error_log_file = log_dir / 'errors.log'
    error_handler = RotatingFileHandler(
        error_log_file,
        maxBytes=5 * 1024 * 1024,   # 5 MB per file
        backupCount=3,               # Keep 3 old files
        encoding='utf-8'
    )
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    ))
    
    # Daily rotating log (time-based rotation)
    daily_log_file = log_dir / 'daily.log'
    daily_handler = TimedRotatingFileHandler(
        daily_log_file,
        when='midnight',     # Rotate at midnight
        interval=1,          # Every 1 day
        backupCount=30,      # Keep 30 days of logs
        encoding='utf-8'
    )
    daily_handler.setLevel(logging.INFO)
    daily_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    ))
    
    # Console handler (for interactive use)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(logging.Formatter(
        '%(levelname)s - %(message)s'
    ))
    
    # Root logger configuration
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    
    # Remove existing handlers to avoid duplicates
    root_logger.handlers.clear()
    
    # Add all handlers
    root_logger.addHandler(main_handler)
    root_logger.addHandler(error_handler)
    root_logger.addHandler(daily_handler)
    root_logger.addHandler(console_handler)
    
    # Set level for specific loggers to reduce noise
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('opensearchpy').setLevel(logging.WARNING)
    logging.getLogger('elasticsearch').setLevel(logging.WARNING)
    
    logging.info(f"Logging configured with level: {log_level}")
    logging.info(f"Main log: {main_log_file}")
    logging.info(f"Error log: {error_log_file}")
    logging.info(f"Daily log: {daily_log_file}")


# Call this early in application startup
if __name__ == "__main__":
    setup_logging(log_level=os.getenv('LOG_LEVEL', 'INFO'))
```

#### Step 2: Add log compression

```python
import gzip
import shutil
from pathlib import Path
from datetime import datetime, timedelta

def compress_old_logs(log_dir: Path = Path('logs'), days_old: int = 7):
    """
    Compress log files older than specified days
    
    Args:
        log_dir: Directory containing log files
        days_old: Compress files older than this many days
    """
    cutoff_date = datetime.now() - timedelta(days=days_old)
    
    for log_file in log_dir.glob('*.log.*'):  # Match .log.1, .log.2, etc.
        if log_file.suffix == '.gz':
            continue  # Already compressed
        
        # Check file age
        file_time = datetime.fromtimestamp(log_file.stat().st_mtime)
        if file_time < cutoff_date:
            # Compress the file
            compressed_file = log_file.with_suffix(log_file.suffix + '.gz')
            
            with open(log_file, 'rb') as f_in:
                with gzip.open(compressed_file, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            
            # Remove original file
            log_file.unlink()
            
            logging.info(f"Compressed old log: {log_file} -> {compressed_file}")


def delete_old_logs(log_dir: Path = Path('logs'), days_to_keep: int = 30):
    """
    Delete compressed logs older than specified days
    
    Args:
        log_dir: Directory containing log files
        days_to_keep: Delete files older than this many days
    """
    cutoff_date = datetime.now() - timedelta(days=days_to_keep)
    
    for log_file in log_dir.glob('*.gz'):
        file_time = datetime.fromtimestamp(log_file.stat().st_mtime)
        if file_time < cutoff_date:
            log_file.unlink()
            logging.info(f"Deleted old compressed log: {log_file}")


# Add to run.py scheduled tasks or cron job
def maintain_logs():
    """Maintain log files - compress and delete old ones"""
    try:
        compress_old_logs(days_old=7)   # Compress logs older than 7 days
        delete_old_logs(days_to_keep=30)  # Delete compressed logs older than 30 days
        logging.info("Log maintenance completed")
    except Exception as e:
        logging.error(f"Log maintenance failed: {e}")


# Add to argparse in run.py:
parser.add_argument('--maintain-logs', action='store_true',
                   help='Compress and clean up old log files')

# In main():
if args.maintain_logs:
    maintain_logs()
    return
```

#### Step 3: Monitor log file sizes

Create `check_log_sizes.py`:

```python
#!/usr/bin/env python3
"""
Monitor log file sizes and warn if they're too large
"""
from pathlib import Path

def check_log_sizes(log_dir: Path = Path('logs'), warn_mb: int = 50):
    """
    Check log file sizes and warn if any exceed threshold
    
    Args:
        log_dir: Directory to check
        warn_mb: Warn if file exceeds this size in MB
    """
    total_size = 0
    large_files = []
    
    print(f"\n{'='*60}")
    print(f"LOG FILE SIZE REPORT")
    print(f"{'='*60}\n")
    
    print(f"{'File':<40} {'Size':>15}")
    print(f"{'-'*40} {'-'*15}")
    
    for log_file in sorted(log_dir.glob('**/*.log*')):
        size_bytes = log_file.stat().st_size
        size_mb = size_bytes / (1024 * 1024)
        total_size += size_bytes
        
        # Format size
        if size_mb >= 1:
            size_str = f"{size_mb:.2f} MB"
        elif size_bytes >= 1024:
            size_str = f"{size_bytes/1024:.2f} KB"
        else:
            size_str = f"{size_bytes} B"
        
        # Print with warning if large
        if size_mb > warn_mb:
            print(f"{log_file.name:<40} {size_str:>15} ⚠️  LARGE")
            large_files.append((log_file, size_mb))
        else:
            print(f"{log_file.name:<40} {size_str:>15}")
    
    # Total size
    total_mb = total_size / (1024 * 1024)
    print(f"{'-'*40} {'-'*15}")
    print(f"{'TOTAL':<40} {total_mb:>13.2f} MB\n")
    
    # Warnings
    if large_files:
        print(f"⚠️  {len(large_files)} file(s) exceed {warn_mb} MB:")
        for file, size in large_files:
            print(f"   {file}: {size:.2f} MB")
        print("\nConsider running: python run.py --maintain-logs")
    else:
        print(f"✓ All log files are within acceptable size limits")
    
    print(f"{'='*60}\n")
    
    return total_mb

if __name__ == "__main__":
    check_log_sizes()
```

Run monitoring:

```bash
python check_log_sizes.py

# Output:
# ============================================================
# LOG FILE SIZE REPORT
# ============================================================
#
# File                                              Size
# ---------------------------------------- ---------------
# threat_ops.log                             12.45 MB ⚠️  LARGE
# errors.log                                  1.23 MB
# daily.log                                   5.67 MB
# threat_ops.log.1                            9.87 MB
# ---------------------------------------- ---------------
# TOTAL                                      29.22 MB
```

#### Step 4: Add automatic log rotation to systemd/cron

**Linux/Mac - Cron Job:**

```bash
# Edit crontab
crontab -e

# Add daily log maintenance at 2 AM
0 2 * * * cd /path/to/threat_ops && python run.py --maintain-logs >> logs/maintenance.log 2>&1

# Add weekly size check
0 3 * * 0 cd /path/to/threat_ops && python check_log_sizes.py >> logs/size_report.log 2>&1
```

**Windows - Task Scheduler:**

```powershell
# Create scheduled task for log maintenance
$action = New-ScheduledTaskAction -Execute "python" -Argument "run.py --maintain-logs" -WorkingDirectory "D:\Cusor AI\threat_ops"
$trigger = New-ScheduledTaskTrigger -Daily -At 2am
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount
Register-ScheduledTask -TaskName "ThreatOps-LogMaintenance" -Action $action -Trigger $trigger -Principal $principal
```

#### Step 5: Configure logrotate (Linux)

Create `/etc/logrotate.d/threatops`:

```bash
/path/to/threat_ops/logs/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0640 your_user your_group
    sharedscripts
    postrotate
        # Optional: restart application if needed
        # systemctl reload threatops || true
    endscript
}
```

Test logrotate:

```bash
# Test configuration
sudo logrotate -d /etc/logrotate.d/threatops

# Force rotation
sudo logrotate -f /etc/logrotate.d/threatops
```

#### Step 6: Add .gitignore for log files

Update `.gitignore`:

```bash
# Logs
logs/*.log
logs/*.log.*
logs/*.gz
*.log
*.log.*

# But keep directory structure
!logs/.gitkeep
!logs/README.md
```

Create `logs/.gitkeep`:

```bash
touch logs/.gitkeep
```

### ✅ Verification

```bash
# Check current log sizes
python check_log_sizes.py

# Run log maintenance
python run.py --maintain-logs

# Verify rotation happened
ls -lh logs/
# Should show:
# threat_ops.log (current, smaller)
# threat_ops.log.1 (older)
# threat_ops.log.2.gz (compressed old)

# Generate lots of logs to test rotation
python run.py --simulate
python run.py --detect
python run.py --simulate
python run.py --detect

# Check sizes again
python check_log_sizes.py

# Verify rotation works automatically
ls -lh logs/threat_ops.log*
```

---

## 29. No .gitignore File

### ❌ Problem (VERSION CONTROL MESS)

**Symptom:**
- Git tracking huge log files
- API keys committed to repo (security risk!)
- Cache files, compiled bytecode in repo
- `.env` file committed (CRITICAL SECURITY ISSUE)

**Impact:**
- ❌ **SECURITY BREACH** - API keys exposed
- ❌ Repository bloat (GB sizes)
- ❌ Slow git operations
- ❌ Merge conflicts on generated files

### ✅ Solution - DETAILED FIX

#### Step 1: Create comprehensive .gitignore

Create `.gitignore` in project root:

```bash
# ============================================================================
# PYTHON
# ============================================================================

# Byte-compiled / optimized / DLL files
__pycache__/
*.py[cod]
*$py.class

# C extensions
*.so

# Distribution / packaging
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
share/python-wheels/
*.egg-info/
.installed.cfg
*.egg
MANIFEST

# PyInstaller
*.manifest
*.spec

# Installer logs
pip-log.txt
pip-delete-this-directory.txt

# Unit test / coverage reports
htmlcov/
.tox/
.nox/
.coverage
.coverage.*
.cache
nosetests.xml
coverage.xml
*.cover
*.py,cover
.hypothesis/
.pytest_cache/
cover/

# Translations
*.mo
*.pot

# Django stuff:
*.log
local_settings.py
db.sqlite3
db.sqlite3-journal

# Flask stuff:
instance/
.webassets-cache

# Scrapy stuff:
.scrapy

# Sphinx documentation
docs/_build/

# PyBuilder
.pybuilder/
target/

# Jupyter Notebook
.ipynb_checkpoints

# IPython
profile_default/
ipython_config.py

# pyenv
.python-version

# pipenv
Pipfile.lock

# poetry
poetry.lock

# pdm
.pdm.toml

# PEP 582
__pypackages__/

# Celery stuff
celerybeat-schedule
celerybeat.pid

# SageMath parsed files
*.sage.py

# Environments
.env
.env.local
.env.*.local
.venv
env/
venv/
ENV/
env.bak/
venv.bak/

# Spyder project settings
.spyderproject
.spyproject

# Rope project settings
.ropeproject

# mkdocs documentation
/site

# mypy
.mypy_cache/
.dmypy.json
dmypy.json

# Pyre type checker
.pyre/

# pytype static type analyzer
.pytype/

# Cython debug symbols
cython_debug/

# ============================================================================
# THREATOPS SIEM SPECIFIC
# ============================================================================

# Logs
logs/
*.log
*.log.*
*.gz

# Data files
data/sim_attacks.log
data/alerts/*.json
data/threat_intel.db
data/*.csv
data/*.json

# ML Models
models/*.joblib
models/*.pkl
models/*.h5
models/*.pt

# Reports
reports/*.html
reports/*.pdf
reports/*.json

# Temporary files
tmp/
temp/
*.tmp

# Database files
*.db
*.sqlite
*.sqlite3

# Backups
*.bak
*.backup
*.old

# ============================================================================
# IDE / EDITOR
# ============================================================================

# VSCode
.vscode/
*.code-workspace

# PyCharm
.idea/
*.iml
*.iws
*.ipr

# Sublime Text
*.sublime-project
*.sublime-workspace

# Vim
*.swp
*.swo
*~
.vim/

# Emacs
*~
\#*\#
.\#*

# ============================================================================
# OPERATING SYSTEM
# ============================================================================

# macOS
.DS_Store
.AppleDouble
.LSOverride
._*
.Spotlight-V100
.Trashes

# Windows
Thumbs.db
Thumbs.db:encryptable
ehthumbs.db
ehthumbs_vista.db
*.stackdump
[Dd]esktop.ini
$RECYCLE.BIN/
*.cab
*.msi
*.msix
*.msm
*.msp
*.lnk

# Linux
.directory
.Trash-*
.nfs*

# ============================================================================
# SECURITY - NEVER COMMIT THESE!
# ============================================================================

# API Keys and Secrets
.env
.env.local
.env.*.local
secrets.yml
secrets.yaml
config/secrets/*
*.key
*.pem
*.cert
*.crt
*.p12
*.pfx

# SSH Keys
id_rsa
id_dsa
*.ppk

# AWS Credentials
.aws/credentials
.aws/config

# GCP Credentials
gcloud-credentials.json
service-account.json

# Azure Credentials
azureProfile.json

# ============================================================================
# EXTERNAL SERVICES (DO NOT TRACK)
# ============================================================================

# OpenSearch data
opensearch-*/data/
opensearch-*/logs/

# Filebeat data
filebeat-*/data/
filebeat-*/logs/

# OpenSearch Dashboards
opensearch-dashboards-*/data/

# ============================================================================
# BUILD ARTIFACTS
# ============================================================================

# Compiled files
*.com
*.class
*.dll
*.exe
*.o
*.so

# Packages
*.7z
*.dmg
*.gz
*.iso
*.jar
*.rar
*.tar
*.zip

# ============================================================================
# KEEP DIRECTORY STRUCTURE
# ============================================================================

# Don't ignore .gitkeep files
!.gitkeep
!**/.gitkeep

# Keep example configs
!config/example.env
!config/*.example
```

#### Step 2: Remove already-tracked sensitive files

```bash
# Check what's currently tracked
git ls-files | grep -E '\.(env|log|db|key|pem)$'

# Remove sensitive files from git history
git rm --cached .env
git rm --cached logs/*.log
git rm --cached data/threat_intel.db
git rm --cached **/*.key

# Commit the removal
git add .gitignore
git commit -m "Remove sensitive files and add comprehensive .gitignore"

# Push changes
git push

# CRITICAL: If .env with API keys was already pushed:
# 1. Rotate ALL API keys immediately
# 2. Consider using git-filter-branch or BFG Repo-Cleaner
#    to remove from history completely
```

#### Step 3: Clean repository of ignored files

```bash
# See what will be removed (dry run)
git clean -fdxn

# Actually remove untracked files
git clean -fdx

# This removes:
# - All files in .gitignore
# - All untracked files
# - All empty directories

# CAUTION: This is destructive!
# Make a backup first if unsure
```

#### Step 4: Create .gitattributes for line endings

Create `.gitattributes`:

```bash
# Auto detect text files and normalize line endings
* text=auto

# Python files
*.py text eol=lf
*.pyi text eol=lf

# Scripts
*.sh text eol=lf
*.bash text eol=lf

# Configuration files
*.yml text eol=lf
*.yaml text eol=lf
*.json text eol=lf
*.toml text eol=lf
*.ini text eol=lf
*.cfg text eol=lf
.env* text eol=lf

# Documentation
*.md text eol=lf
*.txt text eol=lf
LICENSE text eol=lf
README text eol=lf

# Windows files
*.bat text eol=crlf
*.cmd text eol=crlf
*.ps1 text eol=crlf

# Binary files
*.png binary
*.jpg binary
*.jpeg binary
*.gif binary
*.ico binary
*.pdf binary
*.zip binary
*.gz binary
*.tar binary
*.joblib binary
*.pkl binary
*.db binary
*.sqlite binary
*.sqlite3 binary
```

#### Step 5: Create .gitkeep files for empty directories

```bash
# Create directory structure placeholders
touch data/.gitkeep
touch logs/.gitkeep
touch models/.gitkeep
touch reports/.gitkeep
touch tmp/.gitkeep

# Add them to git
git add data/.gitkeep logs/.gitkeep models/.gitkeep reports/.gitkeep tmp/.gitkeep
git commit -m "Add .gitkeep files to preserve directory structure"
```

#### Step 6: Create example environment file

Create `.env.example` (safe to commit):

```bash
# ============================================================================
# ThreatOps SIEM - Environment Configuration Template
# ============================================================================
# 
# INSTRUCTIONS:
# 1. Copy this file to .env: cp .env.example .env
# 2. Fill in your actual values
# 3. NEVER commit .env file to git!
# 
# ============================================================================

# ============================================================================
# EXTERNAL SERVICE PATHS
# ============================================================================

# OpenSearch
OPENSEARCH_HOME=/path/to/opensearch-3.3.1
OPENSEARCH_HOST=localhost
OPENSEARCH_PORT=9200

# Filebeat
FILEBEAT_HOME=/path/to/filebeat-9.2.0
FILEBEAT_CONFIG=/path/to/filebeat.yml

# OpenSearch Dashboards
DASHBOARDS_HOME=/path/to/opensearch-dashboards-3.3.0

# ============================================================================
# API KEYS (Get from respective providers)
# ============================================================================

# VirusTotal - https://www.virustotal.com/gui/join-us
VIRUSTOTAL_API_KEY=your_key_here

# AbuseIPDB - https://www.abuseipdb.com/register
ABUSEIPDB_API_KEY=your_key_here

# AlienVault OTX - https://otx.alienvault.com/api
OTX_API_KEY=your_key_here

# ============================================================================
# NOTIFICATION SETTINGS
# ============================================================================

# Email
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your_email@gmail.com
SMTP_PASSWORD=your_app_password
EMAIL_FROM=threatops@yourcompany.com
EMAIL_TO=security-team@yourcompany.com

# Slack
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL

# ============================================================================
# APPLICATION SETTINGS
# ============================================================================

LOG_LEVEL=INFO
DETECTION_INTERVAL=60
CONTINUOUS_MODE=false

# ============================================================================
# SECURITY
# ============================================================================

# Change these in production!
JWT_SECRET=change_this_secret_key
API_TOKEN=change_this_api_token
```

Add to git:

```bash
git add .env.example
git commit -m "Add example environment configuration"
```

#### Step 7: Add pre-commit hooks to prevent committing secrets

Create `.git/hooks/pre-commit`:

```bash
#!/bin/bash
#
# Pre-commit hook to prevent committing sensitive files
#

# Colors for output
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check for .env file
if git diff --cached --name-only | grep -q "^\.env$"; then
    echo -e "${RED}ERROR: Attempting to commit .env file!${NC}"
    echo "This file contains sensitive API keys and should NEVER be committed."
    echo "Remove it from staging: git reset HEAD .env"
    exit 1
fi

# Check for API keys in staged files
if git diff --cached | grep -iE '(api[_-]?key|secret|password|token|private[_-]?key).*=.*[a-zA-Z0-9]{20,}'; then
    echo -e "${YELLOW}WARNING: Possible API key or secret detected in staged changes!${NC}"
    echo "Please review your changes carefully."
    echo ""
    read -p "Do you want to continue with commit? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Commit aborted."
        exit 1
    fi
fi

# Check for large files (> 10MB)
while read -r file; do
    file_size=$(du -m "$file" | cut -f1)
    if [ "$file_size" -gt 10 ]; then
        echo -e "${RED}ERROR: Large file detected: $file (${file_size}MB)${NC}"
        echo "Large files should not be committed to git."
        echo "Consider using Git LFS or excluding the file."
        exit 1
    fi
done < <(git diff --cached --name-only)

exit 0
```

Make it executable:

```bash
chmod +x .git/hooks/pre-commit
```

### ✅ Verification

```bash
# Check git status
git status

# Should NOT show:
# - .env
# - logs/*.log
# - data/*.db
# - models/*.joblib

# Test pre-commit hook by trying to add .env
echo "TEST_KEY=12345" > .env
git add .env
git commit -m "test"

# Should be blocked by pre-commit hook

# Clean up
git reset HEAD .env
rm .env

# Check repository size
du -sh .git
# Should be reasonable (< 50MB for code only)

# List all tracked files
git ls-files | wc -l
# Should be reasonable number (code files only, no data/logs)
```

---

## 30. Dependencies Version Conflicts

### ❌ Problem (PACKAGE HELL)

**Symptom:**
```bash
$ pip install -r requirements.txt
ERROR: Cannot install package-a and package-b because...
ERROR: Incompatible versions
ModuleNotFoundError after pip install
```

**Causes:**
1. Conflicting package versions
2. Missing version pins in requirements.txt
3. Python version incompatibility
4. OS-specific packages
5. Outdated packages

**Impact:**
- ❌ Can't install application
- ❌ Different behavior on different machines
- ❌ Security vulnerabilities in old packages
- ❌ "Works on my machine" syndrome

### ✅ Solution - DETAILED FIX

#### Step 1: Create pinned requirements.txt

Create or update `requirements.txt` with specific versions:

```txt
# ============================================================================
# ThreatOps SIEM - Python Dependencies
# ============================================================================
# 
# Tested with Python 3.10.x and 3.11.x
# Last updated: 2024-11-06
#
# Install: pip install -r requirements.txt
#
# ============================================================================

# ============================================================================
# CORE DEPENDENCIES
# ============================================================================

# OpenSearch/Elasticsearch client
opensearch-py==2.3.1
elastic-transport==8.4.0

# HTTP requests
requests==2.31.0
urllib3==2.0.7
certifi==2023.7.22
charset-normalizer==3.3.2
idna==3.4

# Data handling
python-dateutil==2.8.2
pytz==2023.3.post1
six==1.16.0

# Configuration
python-dotenv==1.0.0
pydantic==2.4.2
pydantic-core==2.10.1
annotated-types==0.6.0

# Logging
colorlog==6.7.0

# ============================================================================
# MACHINE LEARNING
# ============================================================================

scikit-learn==1.3.2
numpy==1.26.1
scipy==1.11.3
joblib==1.3.2
threadpoolctl==3.2.0

# ============================================================================
# WEB DASHBOARD
# ============================================================================

streamlit==1.28.1
altair==5.1.2
blinker==1.7.0
cachetools==5.3.2
click==8.1.7
gitpython==3.1.40
importlib-metadata==6.8.0
jinja2==3.1.2
jsonschema==4.19.2
markdown-it-py==3.0.0
mdurl==0.1.2
packaging==23.2
pandas==2.1.2
pillow==10.1.0
protobuf==4.25.0
pyarrow==14.0.1
pydeck==0.8.1b0
pygments==2.16.1
pympler==1.0.1
rich==13.6.0
tenacity==8.2.3
toml==0.10.2
toolz==0.12.0
tornado==6.3.3
typing-extensions==4.8.0
tzdata==2023.3
tzlocal==5.2
validators==0.22.0
watchdog==3.0.0
zipp==3.17.0

# ============================================================================
# DATA VISUALIZATION
# ============================================================================

plotly==5.17.0
matplotlib==3.8.1
seaborn==0.13.0
contourpy==1.2.0
cycler==0.12.1
fonttools==4.44.0
kiwisolver==1.4.5
pyparsing==3.1.1

# ============================================================================
# REPORTING
# ============================================================================

# PDF generation
reportlab==4.0.7
pypdf==3.17.0

# HTML/CSS
beautifulsoup4==4.12.2
soupsieve==2.5
lxml==4.9.3

# Email
secure-smtplib==0.1.1

# ============================================================================
# TESTING
# ============================================================================

pytest==7.4.3
pytest-asyncio==0.21.1
pytest-cov==4.1.0
pytest-mock==3.12.0
coverage==7.3.2
exceptiongroup==1.1.3
iniconfig==2.0.0
pluggy==1.3.0
tomli==2.0.1

# ============================================================================
# CODE QUALITY
# ============================================================================

# Linting
pylint==3.0.2
flake8==6.1.0
black==23.11.0
isort==5.12.0

# Type checking
mypy==1.7.0
types-requests==2.31.0.10
types-python-dateutil==2.8.19.14

# Security scanning
bandit==1.7.5
safety==2.3.5

# ============================================================================
# UTILITIES
# ============================================================================

# System utilities
psutil==5.9.6

# Progress bars
tqdm==4.66.1

# YAML parsing
pyyaml==6.0.1

# JSON parsing
orjson==3.9.10

# Command-line interface
argparse==1.4.0
tabulate==0.9.0
```

#### Step 2: Create requirements-dev.txt for development

```txt
# ============================================================================
# Development Dependencies (not needed in production)
# ============================================================================

# Install with: pip install -r requirements-dev.txt

# Include production requirements
-r requirements.txt

# Development tools
ipython==8.17.2
ipdb==0.13.13
jupyter==1.0.0
notebook==7.0.6

# Documentation
sphinx==7.2.6
sphinx-rtd-theme==1.3.0

# Profiling
line-profiler==4.1.1
memory-profiler==0.61.0

# Debugging
pdbpp==0.10.3
```

#### Step 3: Create dependency management script

Create `check_dependencies.py`:

```python
#!/usr/bin/env python3
"""
Check if all required dependencies are installed
"""
import sys
import importlib.util
from typing import Dict, List, Tuple

# Required modules and their package names (if different)
REQUIRED_MODULES: Dict[str, str] = {
    # Core
    'opensearchpy': 'opensearch-py',
    'requests': 'requests',
    'dotenv': 'python-dotenv',
    'pydantic': 'pydantic',
    
    # ML
    'sklearn': 'scikit-learn',
    'numpy': 'numpy',
    'joblib': 'joblib',
    
    # Dashboard
    'streamlit': 'streamlit',
    'plotly': 'plotly',
    'pandas': 'pandas',
    
    # Reporting
    'reportlab': 'reportlab',
    
    # Testing
    'pytest': 'pytest',
    
    # Utilities
    'psutil': 'psutil',
    'yaml': 'pyyaml'
}

def check_module(module_name: str) -> Tuple[bool, str]:
    """Check if a module is installed"""
    try:
        spec = importlib.util.find_spec(module_name)
        if spec is None:
            return False, "Not found"
        
        # Try to import and get version
        mod = importlib.import_module(module_name)
        version = getattr(mod, '__version__', 'unknown')
        return True, version
    except ImportError as e:
        return False, str(e)

def main():
    """Check all dependencies"""
    print("\n" + "="*70)
    print("DEPENDENCY CHECK")
    print("="*70 + "\n")
    
    print(f"{'Module':<20} {'Package':<25} {'Status':<10} {'Version':<15}")
    print(f"{'-'*20} {'-'*25} {'-'*10} {'-'*15}")
    
    missing: List[str] = []
    
    for module_name, package_name in REQUIRED_MODULES.items():
        installed, info = check_module(module_name)
        
        if installed:
            print(f"{module_name:<20} {package_name:<25} ✓ OK      {info:<15}")
        else:
            print(f"{module_name:<20} {package_name:<25} ✗ MISSING")
            missing.append(package_name)
    
    print(f"{'-'*70}\n")
    
    if missing:
        print(f"❌ {len(missing)} package(s) missing:\n")
        for pkg in missing:
            print(f"   - {pkg}")
        
        print("\nInstall missing packages:")
        print(f"   pip install {' '.join(missing)}")
        print("\nOr install all requirements:")
        print("   pip install -r requirements.txt")
        
        return 1
    else:
        print("✓ All required dependencies are installed!\n")
        return 0

if __name__ == "__main__":
    sys.exit(main())
```

Make it executable:

```bash
chmod +x check_dependencies.py

# Run check
python check_dependencies.py
```

#### Step 4: Create virtual environment setup script

Create `setup_venv.sh` (Mac/Linux) or `setup_venv.bat` (Windows):

**Mac/Linux - `setup_venv.sh`:**

```bash
#!/bin/bash
#
# Setup Python virtual environment for ThreatOps SIEM
#

set -e  # Exit on error

echo "=================================="
echo "ThreatOps SIEM - Environment Setup"
echo "=================================="
echo ""

# Check Python version
PYTHON_CMD="python3"
if ! command -v $PYTHON_CMD &> /dev/null; then
    PYTHON_CMD="python"
fi

PYTHON_VERSION=$($PYTHON_CMD --version 2>&1 | cut -d' ' -f2)
echo "Python version: $PYTHON_VERSION"

# Check if version is 3.10 or higher
MAJOR=$(echo $PYTHON_VERSION | cut -d'.' -f1)
MINOR=$(echo $PYTHON_VERSION | cut -d'.' -f2)

if [ "$MAJOR" -lt 3 ] || ([ "$MAJOR" -eq 3 ] && [ "$MINOR" -lt 10 ]); then
    echo "❌ Error: Python 3.10 or higher required"
    echo "   Current version: $PYTHON_VERSION"
    exit 1
fi

echo "✓ Python version OK"
echo ""

# Create virtual environment
VENV_DIR=".venv"

if [ -d "$VENV_DIR" ]; then
    echo "⚠️  Virtual environment already exists: $VENV_DIR"
    read -p "   Delete and recreate? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf "$VENV_DIR"
    else
        echo "Using existing virtual environment"
    fi
fi

if [ ! -d "$VENV_DIR" ]; then
    echo "Creating virtual environment..."
    $PYTHON_CMD -m venv "$VENV_DIR"
    echo "✓ Virtual environment created"
fi

# Activate virtual environment
echo ""
echo "Activating virtual environment..."
source "$VENV_DIR/bin/activate"

# Upgrade pip
echo ""
echo "Upgrading pip..."
pip install --upgrade pip setuptools wheel

# Install requirements
echo ""
echo "Installing requirements..."
pip install -r requirements.txt

# Run dependency check
echo ""
python check_dependencies.py

# Success
echo ""
echo "=================================="
echo "✓ Setup complete!"
echo "=================================="
echo ""
echo "To activate the environment:"
echo "   source $VENV_DIR/bin/activate"
echo ""
echo "To deactivate:"
echo "   deactivate"
echo ""
```

**Windows - `setup_venv.bat`:**

```batch
@echo off
REM
REM Setup Python virtual environment for ThreatOps SIEM
REM

echo ==================================
echo ThreatOps SIEM - Environment Setup
echo ==================================
echo.

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python not found
    echo Please install Python 3.10 or higher
    exit /b 1
)

for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
echo Python version: %PYTHON_VERSION%

REM Create virtual environment
set VENV_DIR=.venv

if exist "%VENV_DIR%" (
    echo Warning: Virtual environment already exists: %VENV_DIR%
    set /p RECREATE="Delete and recreate? (y/N): "
    if /i "%RECREATE%"=="y" (
        rmdir /s /q "%VENV_DIR%"
    )
)

if not exist "%VENV_DIR%" (
    echo Creating virtual environment...
    python -m venv "%VENV_DIR%"
    echo Virtual environment created
)

REM Activate virtual environment
echo.
echo Activating virtual environment...
call "%VENV_DIR%\Scripts\activate.bat"

REM Upgrade pip
echo.
echo Upgrading pip...
python -m pip install --upgrade pip setuptools wheel

REM Install requirements
echo.
echo Installing requirements...
pip install -r requirements.txt

REM Run dependency check
echo.
python check_dependencies.py

REM Success
echo.
echo ==================================
echo Setup complete!
echo ==================================
echo.
echo To activate the environment:
echo    %VENV_DIR%\Scripts\activate.bat
echo.
echo To deactivate:
echo    deactivate
echo.

pause
```

Make executable and run:

```bash
# Mac/Linux
chmod +x setup_venv.sh
./setup_venv.sh

# Windows
setup_venv.bat
```

#### Step 5: Freeze exact versions

```bash
# Activate virtual environment
source .venv/bin/activate  # Mac/Linux
.venv\Scripts\activate.bat  # Windows

# Install all packages
pip install -r requirements.txt

# Freeze exact versions (including all sub-dependencies)
pip freeze > requirements.lock

# Now requirements.lock has EXACT versions of everything
# Use this for production deployments
```

#### Step 6: Add compatibility checks to run.py

```python
# Add to beginning of run.py

import sys

# Check Python version
MIN_PYTHON = (3, 10)
if sys.version_info < MIN_PYTHON:
    sys.exit(f"Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]} or later is required")

# Check critical dependencies
def check_critical_dependencies():
    """Check that critical packages are installed"""
    critical_packages = [
        'opensearchpy',
        'sklearn',
        'streamlit',
        'requests'
    ]
    
    missing = []
    for package in critical_packages:
        try:
            __import__(package)
        except ImportError:
            missing.append(package)
    
    if missing:
        print(f"❌ Critical packages missing: {', '.join(missing)}")
        print("\nInstall with: pip install -r requirements.txt")
        sys.exit(1)

# Run check at startup
check_critical_dependencies()
```

### ✅ Verification

```bash
# Create fresh virtual environment
python -m venv .venv_test
source .venv_test/bin/activate  # Mac/Linux

# Install from requirements.txt
pip install -r requirements.txt

# Check dependencies
python check_dependencies.py

# Should show all ✓ OK

# Run application
python run.py --help

# Should work without errors

# Check for outdated packages
pip list --outdated

# Update if needed (carefully!)
pip install --upgrade package-name

# Re-freeze
pip freeze > requirements.lock

# Clean up test environment
deactivate
rm -rf .venv_test
```

---

## 🎯 FINAL CHECKLIST

Before running ThreatOps SIEM, verify:

### Environment Setup
- [ ] `.env` file exists with all paths set
- [ ] Filebeat test: `filebeat test output -c filebeat.yml`

### Directory Structure
- [ ] All directories exist: `python validate_structure.py`
- [ ] models/ directory created
- [ ] Permissions correct: `chmod -R 755 data logs models reports`

### Initial Setup
- [ ] OpenSearch templates: `python run.py --setup`
- [ ] ML model trained: `python run.py --train`
- [ ] Threat intel updated: `python run.py --update-intel`

### Testing
- [ ] Generate test data: `python run.py --simulate`
- [ ] Run detection: `python run.py --detect`
- [ ] Check alerts: `curl "localhost:9200/security-alerts/_count"`
- [ ] Run tests: `pytest tests/ -v`

### Final Verification
- [ ] `python run.py --help` works without errors
- [ ] `python run.py --all` starts all services
- [ ] Dashboard loads: http://localhost:8501
- [ ] OpenSearch Dashboards: http://localhost:5601
- [ ] No errors in `logs/threat_ops.log`

---

## 🆘 EMERGENCY TROUBLESHOOTING

### If Nothing Works:

```bash
# 1. Stop everything
pkill -f opensearch
pkill -f filebeat
pkill -f streamlit
pkill -f python

# 2. Clean start
cd "/Users/kaushalyadav/Desktop/Cusor AI/threat_ops"

# 3. Verify environment
python check_dependencies.py
python validate_structure.py

# 4. Start fresh
python run.py --setup
python run.py --train
python run.py --all

# 5. Check logs
tail -f logs/threat_ops.log
```

### Common Error Messages:

| Error | Solution |
|-------|----------|
| `ModuleNotFoundError` | `pip install -r requirements.txt` |
| `Connection refused` | Start OpenSearch |
| `[401] Unauthorized` | Disable security in opensearch.yml |
| `FileNotFoundError` | Run `python validate_structure.py` |
| `No module named 'pytest'` | `pip install pytest pytest-cov` |

---

## 📞 SUPPORT

### Getting Help:

1. **Check logs first:** `logs/threat_ops.log`
2. **Run diagnostics:** `python check_dependencies.py && python validate_structure.py`
3. **Search this guide:** Use Ctrl+F to find your error message
4. **Test components individually:**
   ```bash
   python run.py --simulate  # Test simulation
   python run.py --detect    # Test detection
   python run.py --dashboard # Test dashboard only
   ```

### Reporting Issues:

Include:
- Python version: `python --version`
- OS: `uname -a` (Mac/Linux) or `ver` (Windows)
- Error message (full traceback)
- Last 50 lines of logs: `tail -50 logs/threat_ops.log`
- OpenSearch status: `curl http://localhost:9200`

---

## ✅ SUCCESS INDICATORS

Your system is working correctly when:

1. ✅ All services start without errors
2. ✅ Dashboards accessible at http://localhost:8501 and :5601
3. ✅ Logs flowing: `curl "localhost:9200/filebeat-*/_count"` shows increasing count
4. ✅ Alerts generated: `curl "localhost:9200/security-alerts/_count"` > 0
5. ✅ No ERROR in logs: `grep ERROR logs/threat_ops.log | wc -l` shows 0
6. ✅ All tests pass: `pytest tests/ -v` shows all green

---

## 📚 ADDITIONAL RESOURCES

- **OpenSearch Documentation:** https://opensearch.org/docs/
- **Filebeat Reference:** https://www.elastic.co/guide/en/beats/filebeat/current/index.html
- **Streamlit Docs:** https://docs.streamlit.io/
- **MITRE ATT&CK:** https://attack.mitre.org/

---

**END OF TROUBLESHOOTING GUIDE**

**Total Issues Covered:** 30  
**Lines of Documentation:** 2,400+  
**Last Updated:** November 6, 2025

This guide covers EVERY issue found through deep code analysis of the ThreatOps SIEM project, external services (OpenSearch, Filebeat, Dashboards), and provides production-ready solutions.