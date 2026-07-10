# Loom skill installer (Windows / PowerShell)
# Installs the /loom skill for Claude Code and Codex, stamping this repo's path into the
# installed copies. Idempotent: re-run after moving the repo or updating Loom.

$ErrorActionPreference = 'Stop'

$LoomRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$LoomRootFwd = $LoomRoot -replace '\\', '/'

$SkillSrc  = Join-Path $LoomRoot 'skill\loom\SKILL.md'
$PromptSrc = Join-Path $LoomRoot 'skill\codex-prompt\loom.md'
if (-not (Test-Path $SkillSrc)) { throw "Not a Loom repo (missing $SkillSrc)" }

$Targets = @(
    @{ Dir = Join-Path $HOME '.claude\skills\loom'; File = 'SKILL.md'; Src = $SkillSrc;  What = 'Claude Code skill' },
    @{ Dir = Join-Path $HOME '.codex\skills\loom';  File = 'SKILL.md'; Src = $SkillSrc;  What = 'Codex skill' },
    @{ Dir = Join-Path $HOME '.codex\prompts';      File = 'loom.md';  Src = $PromptSrc; What = 'Codex /loom prompt (legacy explicit invocation)' }
)

foreach ($t in $Targets) {
    New-Item -ItemType Directory -Force -Path $t.Dir | Out-Null
    $content = Get-Content -Raw -Encoding UTF8 $t.Src
    $content = $content -replace '\{\{LOOM_PATH\}\}', $LoomRootFwd
    $dest = Join-Path $t.Dir $t.File
    Set-Content -Path $dest -Value $content -Encoding UTF8 -NoNewline
    Write-Host "Installed: $($t.What) -> $dest"
}

Write-Host ""
Write-Host "Loom repo path stamped: $LoomRootFwd"
Write-Host "Claude Code: type /loom  |  Codex: /loom (prompt) or describe a planning task (skill auto-triggers)"
Write-Host "Restart the CLI/session if the command does not appear."
