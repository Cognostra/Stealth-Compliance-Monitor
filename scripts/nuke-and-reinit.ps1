# ==============================================================================
# NUCLEAR CLEANUP SCRIPT - Stealth Compliance Monitor
# ==============================================================================
# PURPOSE: Scrub all sensitive data and git history for fresh public release
# WARNING: This is DESTRUCTIVE and IRREVERSIBLE. Back up any needed data first!
# ==============================================================================

param(
    [switch]$Force,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot

Write-Host ""
Write-Host "================================================================================" -ForegroundColor Red
Write-Host "                    WARNING: NUCLEAR CLEANUP - DESTRUCTIVE                      " -ForegroundColor Red
Write-Host "================================================================================" -ForegroundColor Red
Write-Host "  This script will:                                                            " -ForegroundColor Yellow
Write-Host "    1. DELETE all reports, logs, and screenshots                               " -ForegroundColor Yellow
Write-Host "    2. DELETE node_modules and dist folders                                    " -ForegroundColor Yellow
Write-Host "    3. DELETE .git folder (ALL COMMIT HISTORY GONE!)                           " -ForegroundColor Yellow
Write-Host "    4. Re-initialize git repository                                            " -ForegroundColor Yellow
Write-Host "    5. Run npm install                                                         " -ForegroundColor Yellow
Write-Host "    6. Create fresh initial commit                                             " -ForegroundColor Yellow
Write-Host "================================================================================" -ForegroundColor Red
Write-Host ""

if ($DryRun) {
    Write-Host "[DRY RUN MODE] No changes will be made." -ForegroundColor Cyan
    Write-Host ""
}

# Confirm unless -Force is passed
if (-not $Force -and -not $DryRun) {
    $confirm = Read-Host "Type 'NUKE' to confirm you want to proceed"
    if ($confirm -ne "NUKE") {
        Write-Host "Aborted. No changes made." -ForegroundColor Green
        exit 0
    }
}

Set-Location $ProjectRoot
Write-Host "Working directory: $ProjectRoot" -ForegroundColor Gray
Write-Host ""

# ------------------------------------------------------------------------------
# STEP 1: Delete sensitive data directories
# ------------------------------------------------------------------------------
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "STEP 1: Deleting sensitive data directories..." -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan

$dataFolders = @(
    "reports",
    "logs", 
    "screenshots",
    "snapshots"
)

foreach ($folder in $dataFolders) {
    $path = Join-Path $ProjectRoot $folder
    if (Test-Path $path) {
        if ($DryRun) {
            Write-Host "  [DRY RUN] Would delete: $folder/" -ForegroundColor Yellow
        } else {
            Remove-Item -Recurse -Force $path
            Write-Host "  [OK] Deleted: $folder/" -ForegroundColor Green
        }
    } else {
        Write-Host "  [SKIP] Not found: $folder/" -ForegroundColor Gray
    }
}

# Delete specific sensitive files
$sensitiveFiles = @(
    ".env",
    ".env.local",
    ".env.production",
    "targets.json",
    "audit_report.json",
    "AUDIT_SUMMARY.md"
)

foreach ($file in $sensitiveFiles) {
    $path = Join-Path $ProjectRoot $file
    if (Test-Path $path) {
        if ($DryRun) {
            Write-Host "  [DRY RUN] Would delete: $file" -ForegroundColor Yellow
        } else {
            Remove-Item -Force $path
            Write-Host "  [OK] Deleted: $file" -ForegroundColor Green
        }
    }
}

Write-Host ""

# ------------------------------------------------------------------------------
# STEP 2: Delete caches and build artifacts
# ------------------------------------------------------------------------------
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "STEP 2: Deleting caches and build artifacts..." -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan

$cacheFolders = @(
    "node_modules",
    "dist",
    "build",
    "out",
    "coverage",
    ".cache",
    "test-results",
    "playwright-report",
    "blob-report",
    ".playwright",
    "zap"
)

foreach ($folder in $cacheFolders) {
    $path = Join-Path $ProjectRoot $folder
    if (Test-Path $path) {
        if ($DryRun) {
            Write-Host "  [DRY RUN] Would delete: $folder/" -ForegroundColor Yellow
        } else {
            Remove-Item -Recurse -Force $path
            Write-Host "  [OK] Deleted: $folder/" -ForegroundColor Green
        }
    } else {
        Write-Host "  [SKIP] Not found: $folder/" -ForegroundColor Gray
    }
}

# Delete log files
if (-not $DryRun) {
    Get-ChildItem -Path $ProjectRoot -Filter "*.log" -Recurse -ErrorAction SilentlyContinue | Remove-Item -Force
    Get-ChildItem -Path $ProjectRoot -Filter "*.jsonl" -Recurse -ErrorAction SilentlyContinue | Remove-Item -Force
    Write-Host "  [OK] Deleted: *.log and *.jsonl files" -ForegroundColor Green
} else {
    Write-Host "  [DRY RUN] Would delete: *.log and *.jsonl files" -ForegroundColor Yellow
}

Write-Host ""

# ------------------------------------------------------------------------------
# STEP 3: Nuke git history
# ------------------------------------------------------------------------------
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "STEP 3: Nuking git history..." -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan

$gitPath = Join-Path $ProjectRoot ".git"
if (Test-Path $gitPath) {
    if ($DryRun) {
        Write-Host "  [DRY RUN] Would delete: .git/" -ForegroundColor Yellow
    } else {
        Remove-Item -Recurse -Force $gitPath
        Write-Host "  [OK] Deleted: .git/ (all history removed)" -ForegroundColor Green
    }
} else {
    Write-Host "  [SKIP] Not found: .git/" -ForegroundColor Gray
}

Write-Host ""

# ------------------------------------------------------------------------------
# STEP 4: Re-initialize git
# ------------------------------------------------------------------------------
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "STEP 4: Re-initializing git repository..." -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan

if ($DryRun) {
    Write-Host "  [DRY RUN] Would run: git init" -ForegroundColor Yellow
    Write-Host "  [DRY RUN] Would run: git branch -M main" -ForegroundColor Yellow
} else {
    git init
    git branch -M main
    Write-Host "  [OK] Initialized fresh git repository on 'main' branch" -ForegroundColor Green
}

Write-Host ""

# ------------------------------------------------------------------------------
# STEP 5: Re-install dependencies
# ------------------------------------------------------------------------------
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "STEP 5: Re-installing dependencies..." -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan

if ($DryRun) {
    Write-Host "  [DRY RUN] Would run: npm install" -ForegroundColor Yellow
} else {
    npm install
    Write-Host "  [OK] Dependencies installed" -ForegroundColor Green
}

Write-Host ""

# ------------------------------------------------------------------------------
# STEP 6: Create initial commit
# ------------------------------------------------------------------------------
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "STEP 6: Creating initial commit..." -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan

if ($DryRun) {
    Write-Host "  [DRY RUN] Would run: git add ." -ForegroundColor Yellow
    Write-Host "  [DRY RUN] Would run: git commit -m 'Initial commit'" -ForegroundColor Yellow
} else {
    git add .
    git commit -m "Initial commit - Stealth Compliance Monitor"
    Write-Host "  [OK] Initial commit created" -ForegroundColor Green
}

Write-Host ""

# ------------------------------------------------------------------------------
# COMPLETE
# ------------------------------------------------------------------------------
Write-Host "================================================================================" -ForegroundColor Green
Write-Host "CLEANUP COMPLETE!" -ForegroundColor Green
Write-Host "================================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Create a new GitHub repository" -ForegroundColor White
Write-Host "  2. Add remote: git remote add origin https://github.com/YOUR_ORG/repo.git" -ForegroundColor White
Write-Host "  3. Push: git push -u origin main" -ForegroundColor White
Write-Host ""
Write-Host "IMPORTANT - Don't forget to:" -ForegroundColor Yellow
Write-Host "  - Create a fresh .env file from .env.example" -ForegroundColor Yellow
Write-Host "  - Rotate any API keys that may have been in the old history" -ForegroundColor Yellow
Write-Host ""
