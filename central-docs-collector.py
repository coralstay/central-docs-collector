#!/usr/bin/env python3
# ---
# title: central-docs-collector.py
# description: 워크스페이스·글로벌 AI 설정의 설계·운영·보안 문서와 프롬프트 기록을 중앙 폴더에 평탄하게 수집하고 인덱스를 만든다
# authors: [coralstay]
# license: AGPL-3.0-only
# status: draft
# created_date: '2026-11-06'
# updated_date: '2026-11-06'
# ---
# [설계 메모]
# 기존 배너 정보: File Name = central-docs-collector.py, Author = coralstay, Updated At = 2026-10-29.
# (title·authors로 옮겼고 updated_date는 새 이력 기준 날짜로 둔다.) 아래는 기존 Description과 가이드 원문이다.
# Description :
#   소프트웨어 구현·설계·운영·보안 관점의 모든 결정사항(MD 및 비-MD 설정 파일)과
#   AI 에이전트(Claude, Antigravity, Gemini)의 지침·스킬·커맨드·훅·프롬프트 기록을
#   중앙 폴더(~/central-docs)에 평탄(flat)하게 수집하고 통합 인덱스를 생성합니다.
#
# ==============================================================================
# [1. 사용법 가이드 (CLI USAGE & CUSTOMIZATION GUIDE)]
# ==============================================================================
#
# ■ 기본 실행 (사전 단위 테스트 자동 수행 후 전체 수집 실행)
#   $ ~/githubs/dev-tools/central-docs-collector/central-docs-collector.py
#   또는
#   $ python3 ~/githubs/dev-tools/central-docs-collector/central-docs-collector.py
#
# ■ 주요 CLI 옵션별 실행 예시
#   1) 키워드 검색 (수집된 파일명·원본 경로 + 과거 프롬프트 본문 동시 검색)
#      $ ~/githubs/dev-tools/central-docs-collector/central-docs-collector.py -f "PostgreSQL"
#      $ ~/githubs/dev-tools/central-docs-collector/central-docs-collector.py --find "eBPF"
#
#   2) 단위·통합 테스트만 단독 실행 (파일 수집 없이 검증 테스트만 수행)
#      $ ~/githubs/dev-tools/central-docs-collector/central-docs-collector.py --test
#
#   3) 사전 테스트 생략하고 즉시 수집 (빠른 실행)
#      $ ~/githubs/dev-tools/central-docs-collector/central-docs-collector.py --skip-test
#
#   4) 글로벌 AI 경로(~/.claude, ~/.gemini) 제외하고 ~/githubs 워크스페이스만 수집
#      $ ~/githubs/dev-tools/central-docs-collector/central-docs-collector.py --no-global
#
#   5) backlog/tasks/*.md 태스크 카드 제외하고 수집 (기본값은 tasks 포함 전수 수집)
#      $ ~/githubs/dev-tools/central-docs-collector/central-docs-collector.py --no-tasks
#
#   6) 중앙 폴더(~/central-docs)의 기존 파일을 모두 비우고 처음부터 클린 수집
#      $ ~/githubs/dev-tools/central-docs-collector/central-docs-collector.py --clean-all
#
#   7) 스캔할 워크스페이스(-w) 또는 저장할 타겟 폴더(-t) 직접 지정
#      $ ~/githubs/dev-tools/central-docs-collector/central-docs-collector.py -w ~/githubs -t ~/central-docs
#
# ■ 수동 커스터마이징 방법 (파일 추가/제외하고 싶을 때)
#   - 아래 [섹션 1] 사용자 설정(USER CONFIGURATION)의 상수 집합(set)에
#     파일명이나 폴더명을 추가/삭제한 뒤 실행하면 즉시 반영 및 테스트 검증됩니다.
#     • 수집할 프롬프트 문서 추가 : PROMPT_EXACT_NAMES
#     • 수집할 에이전트 문서 추가 : AGENT_EXACT_NAMES
#     • 수집할 설계/구현 문서 추가: DESIGN_DOC_NAMES, DESIGN_CONFIG_NAMES
#     • 수집할 운영/보안 설정 추가: OPS_SEC_EXACT_NAMES, SECURITY_POLICY_NAMES
#     • 스캔 제외할 디렉터리 추가 : EXCLUDED_DIR_NAMES, EXTERNAL_NOISE_DIRS
#     • 절대 수집 금지할 시크릿   : SECRET_FILE_NAMES, SECRET_SUFFIXES
#
# ==============================================================================
# [2. 프로그램 실행 흐름도 (PROGRAM EXECUTION FLOWCHART)]
# ==============================================================================
#
#   [터미널 실행: central-docs-collector.py]
#                      │
#                      ▼
#        ┌───────────────────────────┐
#        │  build_arg_parser()       │ ── CLI 인자 파싱 (-w, -t, -f, --test 등)
#        └─────────────┬─────────────┘
#                      │
#         ┌────────────┴────────────┐
#         ▼ (--test 옵션)           ▼ (-f / --find 옵션)
#   ┌───────────────────┐     ┌─────────────────────────┐
#   │ run_self_tests(v) │     │ run_keyword_search()    │
#   │ • unittest 실행   │     │ • _nfc() 정규화 검색    │
#   │ • 결과 출력 후 종료│     │ • MANIFEST + PROMPTS    │
#   └───────────────────┘     └─────────────────────────┘
#                      │ (기본 수집 모드)
#                      ▼
#        ┌───────────────────────────┐
#        │  run_self_tests(False)    │ ── 수집 전 자동 사전 검증 (실패 시 즉시 중단)
#        └─────────────┬─────────────┘
#                      ▼
#        ┌───────────────────────────────────────────────────────────────┐
#        │  collect_all(workspace_root, target_dir, ...)                 │
#        ├───────────────────────────────────────────────────────────────┤
#        │  Step 0. _validate_target_dir()                               │
#        │          • 타겟 폴더가 워크스페이스 내부/상위/홈인지 안전 검증│
#        │                                                               │
#        │  Step 1. _clean_previous_managed_files()                      │
#        │          • 이전 MANIFEST.json 기록 파일 또는 고아 파일 정리   │
#        │                                                               │
#        │  Step 2. 수집 대상 후보 스캔 (os.walk 단계에서 노이즈 폴더 프루닝)│
#        │          ├── scan_workspace()                                 │
#        │          │     └── classify_workspace_file() (6대 관점 분류)  │
#        │          └── scan_global_ai_dirs()  (--no-global 아닐 때)     │
#        │                ├── _scan_claude_global()      (~/.claude)     │
#        │                └── _scan_antigravity_global() (~/.gemini)     │
#        │                                                               │
#        │  Step 3. 평탄화(Flat) 파일명 생성 및 복사                     │
#        │          ├── build_flat_filename()                            │
#        │          │     • _nfc() 유니코드 정규화 + `{category}__{경로}`│
#        │          │     • 36자/73자 UUID 디렉터리 앞 8자리 축약        │
#        │          │     • MAX_FLAT_FILENAME_BYTES(240B) UTF-8 절단     │
#        │          └── shutil.copy2() -> ~/central-docs/                │
#        │                                                               │
#        │  Step 4. 글로벌 AI 프롬프트 전수 추출 및 정제                 │
#        │          ├── extract_all_prompt_records()                     │
#        │          │     • Claude projects / hooks / history.jsonl      │
#        │          │     • Antigravity brain transcripts / history.jsonl│
#        │          │     • 서브에이전트·UDS·bash출력·제어명령·중복 제거 │
#        │          └── write_extracted_prompt_archives()                │
#        │                • _wrap_markdown_code_block() 동적 펜스 적용   │
#        │                • 3종 MD 아카이브 + 1종 JSONL 데이터셋 기록    │
#        │                                                               │
#        │  Step 5. 통합 목차 및 매니페스트 생성                         │
#        │          ├── generate_index_markdown() -> INDEX.md            │
#        │          │     • _to_file_uri() / _escape_md_table() 적용     │
#        │          └── JSON 직렬화               -> MANIFEST.json       │
#        └───────────────────────────────────────────────────────────────┘
#                      │
#                      ▼
#        [관점별 수집 통계 및 프롬프트 추출 요약 터미널 출력 후 종료]
#
# ==============================================================================
# [3. 전역 상수·변수 및 데이터 모델 명세 (VARIABLE SPECIFICATIONS)]
# ==============================================================================
#
# ┌──────────────────────────────┬─────────────────────────┬────────────────────────────────────────────────┐
# │ 변수 / 상수 / 모델명         │ 타입                    │ 설명 및 역할                                   │
# ├──────────────────────────────┼─────────────────────────┼────────────────────────────────────────────────┤
# │ DEFAULT_WORKSPACE_DIR        │ Path                    │ 기본 스캔 워크스페이스 경로 (~/githubs)        │
# │ DEFAULT_TARGET_DIR           │ Path                    │ 기본 중앙 수집 폴더 경로 (~/central-docs)      │
# │ CLAUDE_HOME                  │ Path                    │ 글로벌 Claude 설정/로그 루트 (~/.claude)       │
# │ GEMINI_HOME                  │ Path                    │ 글로벌 Gemini/Antigravity 루트 (~/.gemini)     │
# │ MAX_FLAT_FILENAME_BYTES      │ int                     │ 평탄화 파일명 최대 UTF-8 바이트 수 (240)       │
# │ CATEGORY_META                │ dict[str, tuple]        │ 6대 수집 관점 코드 -> (표시 제목, 상세 설명)   │
# │ PROMPT_EXACT_NAMES           │ set[str]                │ 프롬프트 명세서로 즉시 분류할 파일명 집합      │
# │ AGENT_EXACT_NAMES            │ set[str]                │ AI 에이전트 지침/설정으로 분류할 파일명 집합   │
# │ DESIGN_DOC_NAMES             │ set[str]                │ 아키텍처·설계 문서로 분류할 마크다운 파일명    │
# │ DESIGN_CONFIG_NAMES          │ set[str]                │ 구현 컨벤션·린트·포매터 설정 파일명 집합       │
# │ OPS_SEC_EXACT_NAMES          │ set[str]                │ 운영·보안·인프라·CI/CD 설정 파일명 집합        │
# │ SECURITY_POLICY_NAMES        │ set[str]                │ OPS_SEC 중 'security-policy'로 세분화할 파일명 │
# │ ALLOWED_SKILL_HOOK_EXTS      │ set[str]                │ 스킬·커맨드·훅 폴더에서 수집 허용할 확장자     │
# │ EXCLUDED_DIR_NAMES           │ set[str]                │ 탐색에서 제외할 빌드/캐시/시스템 폴더명 집합   │
# │ EXTERNAL_NOISE_DIRS          │ set[str]                │ 외부 서적 예제·오픈소스 클론 등 노이즈 폴더명  │
# │ SECRET_FILE_NAMES            │ set[str]                │ 수집을 엄격히 차단할 시크릿/토큰 파일명 집합   │
# │ SECRET_SUFFIXES              │ tuple[str, ...]         │ 수집을 차단할 인증서·키·DB 캐시 확장자 튜플    │
# │ USER_REQUEST_RE              │ re.Pattern[str]         │ Antigravity 로그의 <USER_REQUEST> 본문 정규식  │
# │ UUID_DIR_RE                  │ re.Pattern[str]         │ 36자 표준 UUID 디렉터리명 식별 정규식          │
# │ BACKTICK_RUN_RE              │ re.Pattern[str]         │ 마크다운 펜스 충돌 방지용 연속 백틱 탐색 정규식│
# │ PURE_PASTED_PLACEHOLDER_RE   │ re.Pattern[str]         │ 본문 없이 [Pasted text #N +M lines]만 있는 패턴│
# │ TRIVIAL_CLI_COMMANDS         │ set[str]                │ 프롬프트 추출 시 제외할 단순 CLI 명령어 집합   │
# │ SYSTEM_INTERRUPT_MARKERS     │ set[str]                │ 사용자 중단([Request interrupted...]) 마커 집합│
# │ INTERNAL_MESSAGE_PREFIXES    │ tuple[str, ...]         │ 서브에이전트/UDS/bash출력 내부 메시지 접두사   │
# │ CollectedItem                │ @dataclass              │ 수집된 개별 파일의 메타데이터 및 원본 매핑 모델│
# │ PromptRecord                 │ @dataclass              │ 추출된 단일 사용자 프롬프트의 시계열·출처 모델 │
# └──────────────────────────────┴─────────────────────────┴────────────────────────────────────────────────┘
#
# ==============================================================================
# [4. 함수 명세 요약표 (FUNCTION SPECIFICATIONS)]
# ==============================================================================
#
# ┌─────────────────────────────────────────────┬───────────────────────────────────────────────────────────┐
# │ 함수 시그니처                               │ 핵심 역할 요약                                            │
# ├─────────────────────────────────────────────┼───────────────────────────────────────────────────────────┤
# │ _nfc(text) -> str                           │ macOS NFD/NFC 유니코드 차이를 NFC(완성형)로 일관 정규화   │
# │ is_secret_or_blocked(path) -> bool          │ 시크릿(.env, 토큰, 인증서) 및 캐시/백업 파일 여부 판별    │
# │ should_skip_path(path, root) -> bool        │ 제외 대상 디렉터리(EXCLUDED_DIR_NAMES) 하위 경로인지 판별 │
# │ detect_project_name(path, root) -> str      │ 워크스페이스 파일의 소속 프로젝트명(예: freeride/...) 추론│
# │ build_flat_filename(...) -> str             │ 출처가 드러나는 240B 이하 평탄화 파일명 생성 및 UUID 축약 │
# │ classify_workspace_file(...) -> tuple|None  │ 워크스페이스 파일을 6대 관점(category, subcategory) 분류  │
# │ scan_workspace(...) -> list                 │ 워크스페이스 전체 순회(노이즈 폴더 프루닝) 및 후보 반환   │
# │ _scan_claude_global() -> list               │ ~/.claude 내 글로벌 지침·스탠드업·플랜·스킬·훅 스캔       │
# │ _scan_antigravity_global() -> list          │ ~/.gemini 내 Antigravity 설정·히스토리·브레인 아티팩트 스캔│
# │ scan_global_ai_dirs() -> list               │ _scan_claude_global() + _scan_antigravity_global() 통합   │
# │ _parse_timestamp(raw_ts, mtime) -> tuple    │ ms/sec/ISO 타임스탬프를 ('YYYY-MM-DD HH:MM:SS', float)변환│
# │ _normalize_project_label(raw_proj) -> str   │ 절대 경로의 홈 디렉터리(/Users/...)를 ~/ 로 축약          │
# │ _extract_user_text_from_claude_message()    │ Claude user 이벤트에서 tool_result 제외한 순수 텍스트 추출│
# │ extract_all_prompt_records() -> list        │ 모든 AI 채널에서 사용자 프롬프트 전수 추출·정제·중복 제거 │
# │ compute_sha256(path) -> str                 │ 파일 내용의 SHA-256 해시 앞 16자리 계산                   │
# │ format_size(num_bytes) -> str               │ 바이트 크기를 B / KB / MB 단위 문자열로 변환              │
# │ _to_file_uri(path_or_str) -> str            │ 공백 등이 포함된 경로를 안전한 CommonMark file:// URI 변환│
# │ _escape_md_table(text) -> str               │ 마크다운 테이블 셀 내부의 파이프(|) 및 개행 문자 이스케이프│
# │ _wrap_markdown_code_block(text, lang)->list │ 본문 내 백틱 개수에 맞춰 외곽 코드블록 펜스 길이 동적 결정│
# │ write_extracted_prompt_archives() -> list   │ 추출된 프롬프트로 3종 마크다운 아카이브 + 1종 JSONL 생성  │
# │ generate_index_markdown(...) -> Path        │ 카테고리/프로젝트 통계 및 원본 링크가 담긴 INDEX.md 생성  │
# │ _validate_target_dir(ws_root, target_dir)   │ 타겟 폴더가 워크스페이스 내부/상위/홈인지 안전 검증       │
# │ _clean_previous_managed_files(...)          │ 재수집 전 이전 MANIFEST 기준 파일 또는 고아 파일 정리     │
# │ collect_all(...) -> tuple                   │ 스캔·복사·프롬프트 추출·인덱스 생성을 총괄하는 파이프라인 │
# │ run_keyword_search(target_dir, keyword)     │ MANIFEST.json 및 프롬프트 데이터셋에서 키워드 검색 출력   │
# │ run_self_tests(verbose) -> None             │ test_central_docs_collector.py 단위/통합 테스트 실행      │
# │ build_arg_parser() -> ArgumentParser        │ CLI 옵션 파서 구성 및 반환                                │
# │ main() -> None                              │ 프로그램 진입점 (인자 해석 -> 테스트/검색/수집 실행)      │
# └─────────────────────────────────────────────┴───────────────────────────────────────────────────────────┘
# ==============================================================================
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import unicodedata
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path


# ==============================================================================
# [섹션 1] 사용자 설정 (USER CONFIGURATION)
#   - 수집 대상 파일을 추가/제외하고 싶을 때 이 섹션의 상수만 수정하면 됩니다.
# ==============================================================================

# 1-1. 기본 디렉터리 경로 및 파일명 바이트 상한
DEFAULT_WORKSPACE_DIR: Path = Path.home() / "githubs"                  # 스캔할 기본 워크스페이스 (~/githubs)
DEFAULT_TARGET_DIR: Path = DEFAULT_WORKSPACE_DIR.parent / "central-docs"  # 평탄 수집 대상 폴더 (~/central-docs)
CLAUDE_HOME: Path = Path.home() / ".claude"                            # Claude Code 글로벌 홈 경로
GEMINI_HOME: Path = Path.home() / ".gemini"                            # Gemini / Antigravity 글로벌 홈 경로
MAX_FLAT_FILENAME_BYTES: int = 240                                     # macOS APFS 255B 제한 대응 안전 상한

# 1-2. 6대 수집 관점(Category) 정의
#   - Key  : 평탄화 파일명 접두사(`{category}__...`)로 사용되는 관점 코드
#   - Value: (INDEX.md 및 터미널에 표시할 관점 제목, 관점 상세 설명)
CATEGORY_META: dict[str, tuple[str, str]] = {
    "decision": (
        "🧭 의사결정 (Decisions & ADR)",
        "프로젝트 진행 중 확정된 아키텍처·기술·정책 의사결정 및 시행착오(Dead-end) 기록",
    ),
    "prompt": (
        "💬 프롬프트 & 대화 기록 (Prompts)",
        "Claude, Antigravity, Gemini 등에 입력한 모든 프롬프트 히스토리·명세·스탠드업 및 추출 아카이브",
    ),
    "agent": (
        "🤖 AI 에이전트 & Antigravity",
        "Claude, Antigravity, Gemini, Agents 지침·플랜·브레인 산출물 및 규칙 설정",
    ),
    "skill": (
        "🧩 Skill · Command · Hook",
        "에이전트 스킬, 슬래시 커맨드, Git/에이전트 훅 스크립트 및 정책 계약",
    ),
    "design": (
        "📐 설계 & 구현 (Design & Impl)",
        "소프트웨어 요구사항·아키텍처 설계서·구조 문서·다이어그램 및 구현 컨벤션 설정",
    ),
    "ops-sec": (
        "🛡️ 운영 & 보안 (Ops & Security)",
        "보안 스캔·시크릿 가드레일·인프라·컨테이너·CI/CD·품질 게이트 정책 및 설정",
    ),
}

# 1-3. 관점별 수집 대상 파일명 규칙
# (1) 프롬프트 명세서로 분류할 파일명
PROMPT_EXACT_NAMES: set[str] = {
    "PROMPT_SPEC.md",
    "PROMPTS.md",
    "refined_prompt_spec.md",
}

# (2) AI 에이전트 지침 및 에이전트 훅 설정 파일명
AGENT_EXACT_NAMES: set[str] = {
    "CLAUDE.md",
    "GEMINI.md",
    "AGENTS.md",
    "AI_AGENT_INTERFACE.md",
    "copilot-instructions.md",
    ".cursorrules",
    ".windsurfrules",
    ".clinerules",
    ".claude-code-agile-hooks.json",
    ".claude-code-agile-hooks.json.example",
    ".claude-rails.json",
    "settings.hooks.json",
}

# (3) 아키텍처·설계·구현 가이드 마크다운 문서명
DESIGN_DOC_NAMES: set[str] = {
    "PROJECT_STRUCTURE.md",
    "ARCHITECTURE.md",
    "DATABASE_SYSTEMS.md",
    "EXTERNAL_LIBRARIES.md",
    "CHEATSHEET.md",
    "PRACTICE_GUIDE.md",
    "PRACTICAL_VIM_MAP.md",
    "JETBRAINS_VIM_KEYMAP_PRACTICE.md",
    "ADVANCED.md",
    "BUILD.md",
}

# (4) 코드 구현 컨벤션·린터·포매터·다이어그램 테마 설정 파일명 (비-MD 포함)
DESIGN_CONFIG_NAMES: set[str] = {
    ".editorconfig",
    ".rubocop.yml",
    ".shellspec",
    "pyproject.toml",
    "ruff.toml",
    "mermaid-theme.json",
}

# (5) 운영·보안·인프라·컨테이너·릴리즈·품질 게이트 설정 파일명 (비-MD 포함)
OPS_SEC_EXACT_NAMES: set[str] = {
    # 보안 정책 및 취약점/시크릿 스캐너 설정
    "SECURITY.md",
    ".gitleaks.toml",
    ".trivy.yaml",
    ".trivy.yml",
    ".checkov.yaml",
    ".checkov.yml",
    # 인프라 / 컨테이너 / 품질 게이트 / 릴리즈 설정
    "RELEASE.md",
    ".pre-commit-config.yaml",
    ".pre-commit-config.yml",
    ".tflint.hcl",
    ".terraform-docs.yml",
    "infracost.yml",
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yaml",
    "compose.yml",
    "Dockerfile",
    ".goreleaser.yml",
    ".goreleaser.yaml",
    ".tool-versions",
    "layout.yaml",
    "dependabot.yml",
    "dependabot.yaml",
    "labeler.yml",
    "Makefile",
    ".env.example",
}

# (6) OPS_SEC_EXACT_NAMES 중 세부 분류를 'security-policy'로 지정할 보안 파일명
SECURITY_POLICY_NAMES: set[str] = {
    "SECURITY.md",
    ".gitleaks.toml",
    ".trivy.yaml",
    ".trivy.yml",
    ".checkov.yaml",
    ".checkov.yml",
}

# (7) 스킬(skills)·커맨드(commands)·훅(hooks) 디렉터리 내부에서 수집 허용할 확장자
ALLOWED_SKILL_HOOK_EXTS: set[str] = {
    ".md", ".json", ".yaml", ".yml", ".toml",
    ".py", ".sh", ".zsh", ".bash", ".js", ".ts",
}

# 1-4. 스캔 제외 폴더 (빌드 산출물, 가상환경, 캐시, 내부 런타임 폴더 등)
EXCLUDED_DIR_NAMES: set[str] = {
    ".git", "node_modules", ".venv", "venv", "dist", "build", ".next",
    ".ruff_cache", ".pytest_cache", "__pycache__", ".idea", ".vscode",
    ".locks", ".tla-tools", "central-docs", ".system_generated",
    ".user_uploaded", "scratch", "backups", "cache", "file-history",
    "hooks-logs", "paste-cache", "session-env", "sessions",
    "shell-snapshots", "conversations", "annotations", "implicit",
    "presence", "crashes", "log", "updater", "builtin", "lib", "bin",
}

# 외부 서적 샘플 코드·외부 오픈소스 클론(fzf)·벤더 레퍼런스 등 엔지니어링 의사결정과 무관한 폴더명
EXTERNAL_NOISE_DIRS: set[str] = {
    "references", "practice", "tlpi-dist", "official_sources", "contents", "fzf", "opensource",
}

# 1-5. 보안 차단 규칙 (절대 수집하지 않는 실제 환경변수·토큰·인증서·DB 캐시)
SECRET_FILE_NAMES: set[str] = {  # ---- 1
    ".env", ".env.local", ".env.development", ".env.production",
    "credentials.json", "token.json", ".claude.json",
    "antigravity-oauth-token", "jetski-standalone-oauth-token",
    "stats-cache.json",
}

SECRET_SUFFIXES: tuple[str, ...] = (
    ".pem", ".key", ".p12", ".pfx", ".bak", ".coverage",
    ".db", ".db-shm", ".db-wal", ".pb", ".pbtxt", ".lock",
)

# 1-6. 프롬프트 추출·경로 정규화·마크다운 렌더링용 패턴/필터 상수
USER_REQUEST_RE: re.Pattern[str] = re.compile(r"<USER_REQUEST>\s*(.*?)\s*</USER_REQUEST>", re.DOTALL)
UUID_DIR_RE: re.Pattern[str] = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
BACKTICK_RUN_RE: re.Pattern[str] = re.compile(r"`+")
PURE_PASTED_PLACEHOLDER_RE: re.Pattern[str] = re.compile(r"^\[Pasted text #\d+ \+\d+ lines\]$")

# 프롬프트 아카이브에서 제외할 단순 CLI 상태조회/세션제어 명령어
TRIVIAL_CLI_COMMANDS: set[str] = {
    "/exit", "/quit", "exit", "quit",
    "/usage", "/model", "/clear", "/help", "/status",
    "/login", "/logout", "/compact", "/config", "/cost",
    "/effort", "/permissions", "/quota", "/rate-limit-options",
    "/resume", "/rewind", "/statusline", "/terminal-setup",
    "/upgrade", "/agents", "/list-agents", "/auto-mode-setup",
    "/feedback", "/routines",
}

# 사용자 중단(Esc/Ctrl+C) 시 자동 기록되는 시스템 마커
SYSTEM_INTERRUPT_MARKERS: set[str] = {
    "[Request interrupted by user]",
    "[Request interrupted by user for tool use]",
}

# 서브에이전트 핸드백·UDS 소켓 통신·Bash 표준출력 등 내부 메시지 접두사 (인간 프롬프트에서 제외)
INTERNAL_MESSAGE_PREFIXES: tuple[str, ...] = (
    "<local-command",
    "<command-name>",
    "<agent-message",
    "<task-notification",
    "<system-reminder",
    "<SYSTEM_MESSAGE>",
    "<cross-session-message",
    "<bash-stdout>",
    "<bash-stderr>",
)


# ==============================================================================
# [섹션 2] 데이터 모델 (DATA MODELS)
# ==============================================================================

@dataclass
class CollectedItem:
    """
    중앙 저장소(~/central-docs)에 수집된 개별 파일 1건의 메타데이터 및 출처 매핑 모델.

    Attributes:
        category (str)        : 6대 관점 코드 ('decision' | 'prompt' | 'agent' | 'skill' | 'design' | 'ops-sec')
        subcategory (str)     : 세부 분류 코드 (예: 'backlog-decision', 'claude-skill', 'security-policy')
        project (str)         : 소속 프로젝트 식별자 (예: 'coralstay-software-factory', 'global-claude')
        origin_scope (str)    : 수집 출처 영역 ('workspace' | 'global-claude' | 'global-antigravity' | 'extracted-prompts')
        source_path (str)     : 추출된 원본 파일의 절대 경로
        display_rel_path (str): INDEX.md 표에 표시할 상대 경로 또는 `~/` 축약 경로
        flat_filename (str)   : ~/central-docs 내에 저장된 평탄화 파일명 (`{category}__{origin_slug}`)
        extension (str)       : 소문자 파일 확장자 (예: '.md', '.yaml', '.py', 확장자 없으면 '')
        size_bytes (int)      : 파일 크기 (바이트 단위)
        modified_at (str)     : 원본 파일 최종 수정 시각 ('YYYY-MM-DD HH:MM')
        sha256 (str)          : 원본 파일 내용의 SHA-256 해시 앞 16자리
    """
    category: str
    subcategory: str
    project: str
    origin_scope: str
    source_path: str
    display_rel_path: str
    flat_filename: str
    extension: str
    size_bytes: int
    modified_at: str
    sha256: str


@dataclass
class PromptRecord:
    """
    AI 도구(Claude Code, Antigravity CLI, Antigravity IDE)에서 추출한 단일 사용자 프롬프트 모델.

    Attributes:
        timestamp_iso (str): 사람이 읽기 쉬운 로컬 시각 문자열 ('YYYY-MM-DD HH:MM:SS' 또는 'unknown')
        sort_ts (float)    : 시계열 정렬 및 시간차 중복 제거에 사용되는 Unix 타임스탬프(초)
        tool (str)         : 입력 도구 명칭 ('Claude Code' | 'Antigravity CLI' | 'Antigravity IDE')
        channel (str)      : 추출된 로그 채널 ('project-transcript' | 'hook-session' | 'brain-transcript' | 'history.jsonl')
        project (str)      : 프롬프트가 입력된 작업 디렉터리/프로젝트 (`~/` 축약 경로)
        session_id (str)   : 대화/세션 ID (없으면 '-')
        source_path (str)  : 해당 프롬프트가 추출된 원본 JSONL 파일의 절대 경로
        prompt_text (str)  : 정제된 사용자 입력 프롬프트 본문 텍스트
    """
    timestamp_iso: str
    sort_ts: float
    tool: str
    channel: str
    project: str
    session_id: str
    source_path: str
    prompt_text: str


# ==============================================================================
# [섹션 3] 보안 및 경로 필터 유틸리티 (SECURITY & PATH FILTERS)
# ==============================================================================

def _nfc(text: str) -> str:
    """
    역할:
        macOS 파일시스템(NFD 조합형 한글)과 파이썬 문자열(NFC 완성형 한글) 간의
        유니코드 정규화 불일치를 방지하기 위해 문자열을 NFC로 변환합니다.
    매개변수:
        text (str): 정규화할 입력 문자열
    반환값:
        str: NFC 정규화된 문자열
    """
    return unicodedata.normalize("NFC", text)


def is_secret_or_blocked(path: Path) -> bool:
    """
    역할:
        주어진 파일이 시크릿/인증 토큰이거나 백업·바이너리 캐시 파일인지 검사하여 수집을 차단합니다.
    매개변수:
        path (Path): 검사할 대상 파일 경로
    반환값:
        bool: 차단 대상(시크릿/캐시)이면 True, 안전한 파일이면 False
    """
    name = _nfc(path.name)
    lower_name = name.lower()

    if name in SECRET_FILE_NAMES or lower_name in SECRET_FILE_NAMES:
        return True
    if any(lower_name.endswith(sfx) for sfx in SECRET_SUFFIXES):
        return True
    if ".bak." in lower_name or "oauth-token" in lower_name:
        return True
    if lower_name.startswith(".env.") and lower_name != ".env.example":
        return True
    if name.startswith(".DS_Store") or name.startswith("._"):
        return True
    return False


def should_skip_path(path: Path, root: Path) -> bool:
    """
    역할:
        파일 경로의 상위 디렉터리 중 EXCLUDED_DIR_NAMES 또는 빌드 폴더(cmake-build-*)가 포함되어 있는지 확인합니다.
    매개변수:
        path (Path): 검사할 파일의 경로
        root (Path): 스캔 기준 루트 디렉터리 경로
    반환값:
        bool: 스캔 제외 대상 디렉터리 하위에 있으면 True, 아니면 False
    """
    try:
        rel_parts = path.relative_to(root).parts
    except ValueError:
        rel_parts = path.parts

    for part in rel_parts[:-1]:
        if part in EXCLUDED_DIR_NAMES or part.startswith("cmake-build-"):
            return True
    return False


def detect_project_name(path: Path, workspace_root: Path) -> str:
    """
    역할:
        워크스페이스 내 파일의 상대 경로 구조를 분석하여 소속 프로젝트명을 추론합니다.
        - `freeride/<subproject>/...` 또는 `toy-project/<subproject>/...`는 2단계까지 프로젝트명으로 묶습니다.
        - `coralstay-software-factory/components/<comp>/...`는 컴포넌트명을 포함해 구분합니다.
    매개변수:
        path (Path)          : 대상 파일의 절대 경로
        workspace_root (Path): 워크스페이스 루트 경로 (예: ~/githubs)
    반환값:
        str: 추론된 프로젝트 이름 문자열 (NFC 정규화 적용)
    """
    try:
        rel = path.relative_to(workspace_root)
    except ValueError:
        return _nfc(path.parent.name or "root")

    parts = [_nfc(p) for p in rel.parts]
    if len(parts) <= 1:
        return _nfc(workspace_root.name)

    top = parts[0]
    if top in {"freeride", "toy-project", "dev-tools"} and len(parts) >= 3:
        return f"{top}/{parts[1]}"
    if top == "coralstay-software-factory" and len(parts) >= 4 and parts[1] == "components":
        return f"{top}/{parts[2]}"
    return top


def build_flat_filename(
    category: str,
    origin_scope: str,
    display_rel_path: str,
    max_bytes: int = MAX_FLAT_FILENAME_BYTES,
) -> str:
    """
    역할:
        단일 폴더(~/central-docs)에 평탄(flat)하게 저장하면서도 어디서 추출되었는지 즉시 알 수 있도록
        `{관점코드}__{출처경로_슬러그}` 형태의 안전한 파일명을 생성합니다.
    매개변수:
        category (str)        : 6대 관점 코드 ('decision', 'prompt', 'agent', 'skill', 'design', 'ops-sec')
        origin_scope (str)    : 출처 영역 식별자 ('workspace', 'global-claude', 'global-antigravity' 등)
        display_rel_path (str): 워크스페이스 상대 경로 또는 `~/` 시작 경로
        max_bytes (int)       : UTF-8 인코딩 기준 최대 허용 바이트 수 (기본값 MAX_FLAT_FILENAME_BYTES=240)
    반환값:
        str: 평탄화된 안전한 파일명 문자열 (240B 초과 시 `~{8자리해시}{확장자}` 자동 부여)
    """
    clean_rel = _nfc(display_rel_path).removeprefix("~/").lstrip("/")
    clean_rel = clean_rel.replace(".claude/", "claude/").replace(".gemini/", "gemini/")
    if origin_scope.startswith("global-") and not display_rel_path.startswith("~/"):
        clean_rel = f"{origin_scope}/{clean_rel}"
    raw_parts = [part for part in clean_rel.split("/") if part]

    normalized_parts: list[str] = []
    for idx, raw_part in enumerate(raw_parts):
        is_dir_part = idx < len(raw_parts) - 1
        # 디렉터리명이 73자 synced 버킷이거나 36자 표준 UUID인 경우 앞 8자리로 축약해 가독성 향상
        if is_dir_part and (
            (len(raw_part) == 73 and raw_part.count("-") == 8 and "_" in raw_part)
            or UUID_DIR_RE.match(raw_part)
        ):
            normalized_parts.append(raw_part[:8])
        else:
            normalized_parts.append(raw_part.replace(" ", "_"))

    candidate = f"{category}__{'__'.join(normalized_parts)}"
    if len(candidate.encode("utf-8")) <= max_bytes:
        return candidate

    ext = Path(candidate).suffix
    stem = candidate[: len(candidate) - len(ext)] if ext else candidate
    short_hash = hashlib.sha1(f"{origin_scope}:{_nfc(display_rel_path)}".encode("utf-8")).hexdigest()[:8]  # ---- 2
    suffix = f"~{short_hash}{ext}"
    target_stem_bytes = max_bytes - len(suffix.encode("utf-8"))

    safe_stem = stem.encode("utf-8")[:target_stem_bytes].decode("utf-8", errors="ignore").rstrip("_- ")
    return f"{safe_stem}{suffix}"


# ==============================================================================
# [섹션 4] 파일 분류 및 스캔 (CLASSIFIER & SCANNERS)
# ==============================================================================

def classify_workspace_file(
    path: Path,
    workspace_root: Path,
    include_tasks: bool = True,
) -> tuple[str, str] | None:
    """
    역할:
        워크스페이스 내 개별 파일의 경로와 이름을 분석하여 6대 엔지니어링·AI 관점의
        `(category, subcategory)` 튜플로 분류합니다. 수집 대상이 아니면 `None`을 반환합니다.
    매개변수:
        path (Path)          : 분류할 파일의 경로
        workspace_root (Path): 워크스페이스 루트 경로
        include_tasks (bool) : True(기본값)이면 `backlog/tasks/*.md` 및 완료 태스크도 의사결정 카테고리로 함께 수집
    반환값:
        tuple[str, str] | None: 수집 대상이면 `(관점코드, 세부분류코드)`, 제외 대상이면 `None`
    """
    if not path.is_file() or is_secret_or_blocked(path):
        return None

    try:
        rel = path.relative_to(workspace_root)
    except ValueError:
        return None

    parts = [_nfc(p) for p in rel.parts]
    name = _nfc(path.name)
    lower_name = name.lower()
    ext = path.suffix.lower()

    if any(p in EXTERNAL_NOISE_DIRS for p in parts):  # ---- 3
        return None
    if "worktrees" in parts or any(p.endswith("-wt") for p in parts):
        return None
    if "content_data" in parts or ("sample" in parts and "pages" in parts):
        return None

    # 0. 수집기 스크립트 자신 및 테스트 코드 보존
    if path.resolve() == Path(__file__).resolve() or name == "test_central_docs_collector.py":
        return ("ops-sec", "collector-script")

    # 1. 프롬프트 명세 문서
    if name in PROMPT_EXACT_NAMES or ("prompt" in lower_name and ext == ".md"):
        return ("prompt", "prompt-spec")

    # 2. 의사결정 (Backlog Decisions / Docs / Drafts / Milestones / Tasks / ADR / 아키텍처 설계 결정)
    if "backlog" in parts:
        if "decisions" in parts and ext == ".md":
            return ("decision", "decision-index" if lower_name == "readme.md" else "backlog-decision")
        if name in {"config.yml", "config.yaml"}:
            return ("decision", "backlog-config")
        if "docs" in parts and ext == ".md":
            if "결정" in name or "decision" in lower_name:
                return ("decision", "architecture-decision")
            return ("design", "backlog-doc")
        if "drafts" in parts and ext == ".md":
            return ("decision", "backlog-draft")
        if "milestones" in parts and ext == ".md":
            return ("decision", "backlog-milestone")
        if ("tasks" in parts or "completed" in parts) and ext == ".md":
            return ("decision", "backlog-task") if include_tasks else None
        if ext == ".md":
            return ("decision", "backlog-index")
        return None

    if ("decisions" in parts or "adr" in parts or "adrs" in parts) and ext in {".md", ".yaml", ".yml", ".json"}:
        return ("decision", "adr")

    if "설계-결정" in name or ("decision" in lower_name and ext == ".md"):
        return ("decision", "architecture-decision")

    if lower_name == "lesson-and-learn.md":
        return ("decision", "lesson-learned")

    # 3. AI 에이전트 지침 및 설정
    if name in AGENT_EXACT_NAMES:
        return ("agent", "agent-doc" if ext == ".md" else "agent-config")

    if ".claude" in parts:
        if "commands" in parts and ext in ALLOWED_SKILL_HOOK_EXTS:
            return ("skill", "claude-command")
        if "skills" in parts and ext in ALLOWED_SKILL_HOOK_EXTS:
            return ("skill", "claude-skill")
        if name in {"settings.json", "settings.local.json", "CLAUDE.md"}:
            return ("agent", "claude-setting")
        return None

    if any(p in {".agent", ".agents", ".gemini", ".cursor"} for p in parts):
        if "skills" in parts and ext in ALLOWED_SKILL_HOOK_EXTS:
            return ("skill", "agent-skill")
        if "rules" in parts and ext in ALLOWED_SKILL_HOOK_EXTS:
            return ("agent", "agent-rule")
        if ext in ALLOWED_SKILL_HOOK_EXTS:
            return ("agent", "agent-customization")

    # 4. 프로젝트 내 에이전트/Git 훅 스크립트 (프론트엔드 React UI hooks 및 테스트 제외)
    if "hooks" in parts:
        if "src" in parts or "frontend" in parts or name.startswith("test_"):
            return None
        if ext in ALLOWED_SKILL_HOOK_EXTS or path.suffix == "":
            return ("skill", "project-hook")

    # 5. 설계 & 구현 문서/설정 (design, diagrams, TLA+ 정형 명세, 메타데이터/팁 레지스트리 포함)
    if "design" in parts or "diagrams" in parts:
        if ext in {".md", ".dot", ".mmd", ".gv", ".puml", ".json"}:
            return ("design", "design-doc" if ext == ".md" else "design-diagram-spec")
        return None

    if "specs" in parts and ext in {".tla", ".cfg"}:
        return ("design", "formal-spec")

    if name in DESIGN_DOC_NAMES:
        return ("design", "architecture-doc")

    if name in DESIGN_CONFIG_NAMES:
        return ("design", "impl-convention")

    if name == "snippets_registry.json" and "tips" in parts:
        return ("design", "engineering-tip")

    if "docs" in parts and ext == ".json":
        return ("design", "design-doc")

    if "config" in parts and ext in {".yaml", ".yml"} and "doctree" in parts:
        return ("design", "impl-convention")

    # 6. 운영 & 보안 정책/설정 (.github 하위 규칙을 먼저 판별하여 세부 분류 정확도 보장)
    if ".github" in parts:
        if "workflows" in parts and ext in {".yml", ".yaml"}:
            return ("ops-sec", "ci-workflow")
        if name in {"PULL_REQUEST_TEMPLATE.md", "dependabot.yml", "dependabot.yaml", "labeler.yml"}:
            return ("ops-sec", "repo-governance")
        return None

    if "policy" in parts and ext == ".rego":
        return ("ops-sec", "security-policy")

    if name in OPS_SEC_EXACT_NAMES:
        sub = "security-policy" if name in SECURITY_POLICY_NAMES else "ops-config"
        return ("ops-sec", sub)

    if (
        (lower_name.startswith("docker-compose.") and ext in {".yml", ".yaml"})
        or (lower_name.startswith("infracost") and ext in {".yml", ".yaml"})
        or ("deploy" in parts and "k8s" in parts and ext in {".yml", ".yaml"})
    ):
        return ("ops-sec", "ops-config")

    if lower_name == "slo.md":
        return ("ops-sec", "slo-spec")

    # 7. 프로젝트/모듈 README, 엔지니어링 팁(tips), docs/context/SQL-docs 및 기타 사용자 마크다운 문서 전수 수집
    if ext == ".md":
        if lower_name == "readme.md":
            return ("design", "project-readme")
        if "tips" in parts:
            return ("design", "engineering-tip")
        if any(p in {"docs", "context", "SQL-docs", "diagrams", "specs", "policy"} for p in parts):
            return ("design", "design-doc")
        return ("design", "workspace-doc")

    return None


def scan_workspace(workspace_root: Path, include_tasks: bool = True) -> list[tuple[Path, str, str, str, str, str]]:
    """
    역할:
        워크스페이스 루트 디렉터리를 재귀 순회하며 수집 대상 파일 목록을 추출합니다.
        `os.walk` 단계에서 제외/노이즈/worktree 디렉터리를 즉시 가지치기(pruning)하여 탐색 성능을 극대화합니다.
        기본 워크스페이스(`~/githubs`)를 스캔할 때는 형제 워크스페이스(`~/github-gardenning`)도 함께 스캔합니다.
    매개변수:
        workspace_root (Path): 스캔할 워크스페이스 루트 경로 (예: ~/githubs)
        include_tasks (bool) : backlog/tasks 카드 포함 여부 (기본값 True)
    반환값:
        list[tuple[Path, str, str, str, str, str]]:
            `(원본Path, category, subcategory, project, origin_scope, display_rel_path)` 튜플 리스트
    """
    results: list[tuple[Path, str, str, str, str, str]] = []

    roots_to_scan: list[tuple[Path, str | None]] = [(workspace_root, None)]
    if workspace_root.resolve() == DEFAULT_WORKSPACE_DIR.resolve():
        sibling_ws = workspace_root.parent / "github-gardenning"  # ---- 4
        if sibling_ws.is_dir():
            roots_to_scan.append((sibling_ws, "github-gardenning"))

    for scan_root, prefix_override in roots_to_scan:
        for root_dir, dirnames, filenames in os.walk(scan_root):
            root_path = Path(root_dir)
            dirnames[:] = [  # ---- 5
                d for d in dirnames
                if d not in EXCLUDED_DIR_NAMES
                and d not in EXTERNAL_NOISE_DIRS
                and d != "worktrees"
                and not d.endswith("-wt")
                and not d.startswith("cmake-build-")
            ]

            for fname in filenames:
                fpath = root_path / fname
                classified = classify_workspace_file(fpath, scan_root, include_tasks=include_tasks)
                if classified is None:
                    continue

                category, subcategory = classified
                rel_str = _nfc(fpath.relative_to(scan_root).as_posix())
                if prefix_override:
                    project = prefix_override
                    rel_str = f"{prefix_override}/{rel_str}"
                else:
                    project = detect_project_name(fpath, scan_root)
                results.append((fpath, category, subcategory, project, "workspace", rel_str))

    return results


def _scan_claude_global() -> list[tuple[Path, str, str, str, str, str]]:
    """
    역할:
        `~/.claude` 경로에서 글로벌 지침, 프롬프트 히스토리, 데드엔드/바운티 의사결정 로그,
        일별 스탠드업, 플랜, 프로젝트별 메모리(`projects/*/memory/*.md`), 스킬, 훅 파일들을 스캔합니다.
    매개변수:
        없음 (`CLAUDE_HOME` 전역 경로 상수 참조)
    반환값:
        list[tuple[Path, str, str, str, str, str]]: 스캔된 글로벌 Claude 자산 튜플 리스트
    """
    results: list[tuple[Path, str, str, str, str, str]] = []
    if not CLAUDE_HOME.exists():
        return results

    # 1) 기본 설정 및 히스토리/레지스트리 파일
    direct_targets = [
        (CLAUDE_HOME / "CLAUDE.md", "agent", "global-claude-doc", "~/.claude/CLAUDE.md"),
        (CLAUDE_HOME / "settings.json", "agent", "global-claude-config", "~/.claude/settings.json"),
        (CLAUDE_HOME / "history.jsonl", "prompt", "claude-prompt-history", "~/.claude/history.jsonl"),
        (CLAUDE_HOME / "hooks-logs" / "dead-end-registry.jsonl", "decision", "dead-end-registry", "~/.claude/hooks-logs/dead-end-registry.jsonl"),
        (CLAUDE_HOME / "hooks-logs" / "bounty-board.json", "decision", "bounty-board", "~/.claude/hooks-logs/bounty-board.json"),
        (CLAUDE_HOME / "hooks-logs" / "recap-archive.jsonl", "prompt", "session-recap-archive", "~/.claude/hooks-logs/recap-archive.jsonl"),
        (CLAUDE_HOME / "hooks-logs" / "config-watch.jsonl", "ops-sec", "hook-config-watch", "~/.claude/hooks-logs/config-watch.jsonl"),
        (CLAUDE_HOME / "hooks-logs" / "nerf-receipts.jsonl", "decision", "hook-nerf-receipts", "~/.claude/hooks-logs/nerf-receipts.jsonl"),
        (CLAUDE_HOME / "hooks-logs" / "dead-rules-audit.jsonl", "decision", "dead-rules-audit", "~/.claude/hooks-logs/dead-rules-audit.jsonl"),
        (CLAUDE_HOME / "hooks-logs" / "context-hogs.jsonl", "ops-sec", "context-hogs-log", "~/.claude/hooks-logs/context-hogs.jsonl"),
    ]
    for path, cat, sub, disp in direct_targets:
        if path.is_file() and not is_secret_or_blocked(path):
            results.append((path, cat, sub, "global-claude", "global-claude", disp))

    # 2) 일별 스탠드업 로그 (~/.claude/hooks-logs/standup/*.md) 및 파이프라인 로그
    standup_dir = CLAUDE_HOME / "hooks-logs" / "standup"
    if standup_dir.is_dir():
        for p in sorted(standup_dir.glob("*.md")):
            if p.is_file():
                results.append((p, "prompt", "daily-standup-log", "global-claude", "global-claude", f"~/.claude/hooks-logs/standup/{p.name}"))

    pipeline_dir = CLAUDE_HOME / "hooks-logs" / "pipeline"
    if pipeline_dir.is_dir():
        for p in sorted(pipeline_dir.glob("*.json")):
            if p.is_file() and not is_secret_or_blocked(p):
                results.append((p, "ops-sec", "hook-pipeline-log", "global-claude", "global-claude", f"~/.claude/hooks-logs/pipeline/{p.name}"))

    # 3) 플랜 문서 (~/.claude/plans/*.md)
    plans_dir = CLAUDE_HOME / "plans"
    if plans_dir.is_dir():
        for p in sorted(plans_dir.glob("*.md")):
            if p.is_file() and not is_secret_or_blocked(p):
                results.append((p, "agent", "claude-plan", "global-claude", "global-claude", f"~/.claude/plans/{p.name}"))

    # 3-b) 프로젝트별 Claude 메모리·피드백·결정 문서 (~/.claude/projects/*/memory/*.md)
    projects_dir = CLAUDE_HOME / "projects"
    if projects_dir.is_dir():
        for p in sorted(projects_dir.glob("*/memory/*.md")):
            if p.is_file() and not is_secret_or_blocked(p) and p.stat().st_size > 0:
                rel = _nfc(p.relative_to(CLAUDE_HOME).as_posix())
                cat = "decision" if "decision" in p.name.lower() else "agent"
                results.append((p, cat, "claude-project-memory", "global-claude", "global-claude", f"~/.claude/{rel}"))

    # 3-c) Context Hub 레퍼런스 문서 (~/.claude/chub-content/**/*.md)
    chub_dir = CLAUDE_HOME / "chub-content"
    if chub_dir.is_dir():
        for p in sorted(chub_dir.rglob("*.md")):
            if p.is_file() and not is_secret_or_blocked(p) and p.stat().st_size > 0:
                rel = _nfc(p.relative_to(CLAUDE_HOME).as_posix())
                results.append((p, "agent", "claude-chub-doc", "global-claude", "global-claude", f"~/.claude/{rel}"))

    # 4) 과거 아카이브된 프로젝트별 CLAUDE.md (~/.claude/central-docs/project-*.md)
    legacy_dir = CLAUDE_HOME / "central-docs"
    if legacy_dir.is_dir():
        for p in sorted(legacy_dir.glob("project-*.md")):
            if p.is_file() and not is_secret_or_blocked(p) and p.stat().st_size > 0:
                results.append((p, "agent", "legacy-project-claude-doc", "global-claude", "global-claude", f"~/.claude/central-docs/{p.name}"))

    # 5) 글로벌 스킬 (~/.claude/skills/**)
    skills_dir = CLAUDE_HOME / "skills"
    if skills_dir.is_dir():
        for p in sorted(skills_dir.rglob("*")):
            if not p.is_file() or is_secret_or_blocked(p) or should_skip_path(p, skills_dir):
                continue
            rel_parts = p.relative_to(skills_dir).parts
            if "synced" in rel_parts and "scripts" in rel_parts:
                continue
            if p.suffix.lower() in ALLOWED_SKILL_HOOK_EXTS:
                rel = _nfc(p.relative_to(CLAUDE_HOME).as_posix())
                results.append((p, "skill", "global-claude-skill", "global-claude", "global-claude", f"~/.claude/{rel}"))

    # 6) 글로벌 훅 (~/.claude/hooks/**)
    hooks_dir = CLAUDE_HOME / "hooks"
    if hooks_dir.is_dir():
        for p in sorted(hooks_dir.rglob("*")):
            if not p.is_file() or is_secret_or_blocked(p) or should_skip_path(p, hooks_dir):
                continue
            if p.name.startswith("test_"):
                continue
            if p.suffix.lower() in ALLOWED_SKILL_HOOK_EXTS or p.suffix == "":
                rel = _nfc(p.relative_to(CLAUDE_HOME).as_posix())
                results.append((p, "skill", "global-claude-hook", "global-claude", "global-claude", f"~/.claude/{rel}"))

    return results


def _scan_antigravity_global() -> list[tuple[Path, str, str, str, str, str]]:
    """
    역할:
        `~/.gemini` 경로에서 Antigravity / Gemini 설정, 프롬프트 히스토리, 브레인 아티팩트(플랜·워크스루·태스크·스크래치),
        커스텀 스킬 파일들을 스캔합니다.
    매개변수:
        없음 (`GEMINI_HOME` 전역 경로 상수 참조)
    반환값:
        list[tuple[Path, str, str, str, str, str]]: 스캔된 글로벌 Antigravity 자산 튜플 리스트
    """
    results: list[tuple[Path, str, str, str, str, str]] = []
    if not GEMINI_HOME.exists():
        return results

    cfg_dir = GEMINI_HOME / "config"
    if cfg_dir.is_dir():
        for p in sorted(cfg_dir.glob("*.json")):
            if p.is_file() and not is_secret_or_blocked(p) and p.stat().st_size > 0:
                rel = _nfc(p.relative_to(GEMINI_HOME).as_posix())
                results.append((p, "agent", "antigravity-config", "global-antigravity", "global-antigravity", f"~/.gemini/{rel}"))

    for agy_name in ("antigravity", "antigravity-cli"):
        agy_dir = GEMINI_HOME / agy_name
        if not agy_dir.is_dir():
            continue

        proj_label = f"global-{agy_name}"

        # 히스토리 및 설정 파일
        hist_p = agy_dir / "history.jsonl"
        if hist_p.is_file():
            results.append((hist_p, "prompt", "antigravity-prompt-history", proj_label, "global-antigravity", f"~/.gemini/{agy_name}/history.jsonl"))

        settings_p = agy_dir / "settings.json"
        if settings_p.is_file() and not is_secret_or_blocked(settings_p):
            results.append((settings_p, "agent", "antigravity-settings", proj_label, "global-antigravity", f"~/.gemini/{agy_name}/settings.json"))

        # 브레인 아티팩트 (brain/<conv-id>/*.md 및 brain/<conv-id>/scratch/*.md)
        brain_dir = agy_dir / "brain"
        if brain_dir.is_dir():
            for conv_dir in sorted(brain_dir.iterdir()):
                if not conv_dir.is_dir() or conv_dir.name.startswith("."):
                    continue
                candidate_files = list(sorted(conv_dir.iterdir()))
                scratch_dir = conv_dir / "scratch"
                if scratch_dir.is_dir():
                    candidate_files.extend(sorted(scratch_dir.rglob("*")))
                for p in candidate_files:
                    if not p.is_file() or is_secret_or_blocked(p) or p.suffix.lower() not in {".md", ".json"}:
                        continue
                    rel = _nfc(p.relative_to(GEMINI_HOME).as_posix())
                    is_prompt_doc = p.name in PROMPT_EXACT_NAMES or "prompt" in p.name.lower()
                    cat = "prompt" if is_prompt_doc else "agent"
                    if is_prompt_doc:
                        sub = "antigravity-prompt-spec" if p.suffix.lower() == ".md" else "antigravity-prompt-meta"
                    else:
                        sub = "antigravity-brain-artifact" if p.suffix.lower() == ".md" else "antigravity-brain-meta"
                    results.append((p, cat, sub, proj_label, "global-antigravity", f"~/.gemini/{rel}"))

        # 커스텀 스킬
        custom_skills_dir = agy_dir / "skills"
        if custom_skills_dir.is_dir():
            for p in sorted(custom_skills_dir.rglob("*")):
                if p.is_file() and not is_secret_or_blocked(p) and p.suffix.lower() in ALLOWED_SKILL_HOOK_EXTS:
                    rel = _nfc(p.relative_to(GEMINI_HOME).as_posix())
                    results.append((p, "skill", "antigravity-skill", proj_label, "global-antigravity", f"~/.gemini/{rel}"))

    return results


def scan_global_ai_dirs() -> list[tuple[Path, str, str, str, str, str]]:
    """
    역할:
        글로벌 AI 디렉터리(`~/.claude` 및 `~/.gemini`) 전체를 통합 스캔합니다.
    반환값:
        list[tuple[Path, str, str, str, str, str]]: 글로벌 AI 수집 후보 리스트
    """
    return _scan_claude_global() + _scan_antigravity_global()


# ==============================================================================
# [섹션 5] 프롬프트 전수 추출기 (PROMPT EXTRACTOR)
# ==============================================================================

def _parse_timestamp(raw_ts: object, fallback_mtime: float = 0.0) -> tuple[str, float]:
    """
    역할:
        정수(밀리초/초), 실수(초), ISO-8601 문자열 형태의 타임스탬프를
        로컬 시각 문자열(`YYYY-MM-DD HH:MM:SS`)과 정렬용 Unix 타임스탬프(`float`)로 변환합니다.
    매개변수:
        raw_ts (object)       : JSONL에서 읽은 원본 타임스탬프 값 (int, float, str, None 등)
        fallback_mtime (float): 타임스탬프 파싱 실패 시 사용할 파일 수정 시각(mtime)
    반환값:
        tuple[str, float]: `(포맷팅된_시각_문자열, unix_timestamp_초)`
    """
    if isinstance(raw_ts, (int, float)):
        ts_val = float(raw_ts)
        if ts_val > 1e11:
            ts_val /= 1000.0
        try:
            return datetime.fromtimestamp(ts_val).strftime("%Y-%m-%d %H:%M:%S"), ts_val
        except Exception:
            pass
    elif isinstance(raw_ts, str) and raw_ts.strip():
        s = raw_ts.strip()
        try:
            if s.endswith("Z"):
                s = s[:-1] + "+00:00"
            dt = datetime.fromisoformat(s)
            if dt.tzinfo is not None:
                dt = dt.astimezone()
            return dt.strftime("%Y-%m-%d %H:%M:%S"), dt.timestamp()
        except Exception:
            pass

    if fallback_mtime > 0:
        return datetime.fromtimestamp(fallback_mtime).strftime("%Y-%m-%d %H:%M:%S"), fallback_mtime
    return "unknown", 0.0


def _normalize_project_label(raw_proj: str) -> str:
    """
    역할:
        절대 경로에 포함된 사용자 홈 디렉터리 접두사(`/Users/...`)를 `~/`로 축약하고 NFC로 정규화합니다.
    매개변수:
        raw_proj (str): 원본 프로젝트 경로 문자열
    반환값:
        str: `~/`로 축약된 프로젝트 경로 문자열
    """
    if not raw_proj:
        return "unknown"
    norm_proj = _nfc(raw_proj)
    home_str = _nfc(str(Path.home()))
    if norm_proj.startswith(home_str):
        rel = norm_proj[len(home_str):].lstrip("/")
        return f"~/{rel}" if rel else "~"
    return norm_proj


def _extract_user_text_from_claude_message(msg: object) -> str:
    """
    역할:
        Claude 프로젝트 트랜스크립트의 `message` 필드에서 도구 실행 결과(`tool_result`)를 제외하고
        실제 사용자가 입력한 텍스트(`type == "text"` 또는 문자열)만 추출합니다.
    매개변수:
        msg (object): JSONL 레코드의 `message` 객체
    반환값:
        str: 추출된 순수 사용자 프롬프트 문자열 (없으면 빈 문자열 `""`)
    """
    if not isinstance(msg, dict):
        return ""
    content = msg.get("content", "")
    if isinstance(content, str):
        return content.strip()
    if isinstance(content, list):
        texts = [
            str(block.get("text", ""))
            for block in content
            if isinstance(block, dict) and block.get("type") == "text"
        ]
        return "\n".join(t for t in texts if t).strip()
    return ""


def extract_all_prompt_records() -> list[PromptRecord]:
    """
    역할:
        Claude Code, Antigravity CLI, Antigravity IDE의 모든 히스토리 및 세션 트랜스크립트에서
        사용자가 입력한 프롬프트 기록들을 전수 추출하고 노이즈 및 채널 간 중복을 제거합니다.
    동작 흐름:
        1) 원본 전문이 보존된 트랜스크립트(`~/.claude/projects`, `~/.gemini/*/brain`)를 먼저 스캔하고,
           `history.jsonl`을 보조로 병합하여 `[Pasted text #1 +N lines]` 축약본 대신 전문이 보존되도록 합니다.
        2) 서브에이전트 위임 로그(`subagents/agent-*.jsonl`), 내부 핸드백/UDS/bash출력(`INTERNAL_MESSAGE_PREFIXES`),
           중단 마커(`SYSTEM_INTERRUPT_MARKERS`), 단순 제어 명령(`TRIVIAL_CLI_COMMANDS`), 임시 테스트 폴더(`/private/tmp`)를 필터링합니다.
        3) 서로 다른 채널 간(`transcript` vs `history.jsonl`/`hook-session`)에는 5분(300초) 이내 동일 프롬프트를
           중복 제거하고, 동일 채널 내에서는 1초 이내 중복 이벤트만 제거하여 실제 사용자의 반복 지시 턴을 보존합니다.
    반환값:
        list[PromptRecord]: 시간순 정렬된 고유 사용자 프롬프트 레코드 리스트
    """
    records: list[PromptRecord] = []
    seen_entries: dict[tuple[str, str], list[tuple[float, str]]] = {}
    session_timestamps: dict[tuple[str, str], list[float]] = {}

    def add_record(
        ts_iso: str,
        sort_ts: float,
        tool: str,
        channel: str,
        project: str,
        session_id: str,
        source_path: str,
        prompt_text: str,
    ) -> None:
        cleaned = _nfc(prompt_text.strip())
        if not cleaned or cleaned.startswith(INTERNAL_MESSAGE_PREFIXES):
            return
        if cleaned in SYSTEM_INTERRUPT_MARKERS:
            return
        if cleaned.lower() in TRIVIAL_CLI_COMMANDS:
            return
        if PURE_PASTED_PLACEHOLDER_RE.match(cleaned):
            return
        if project.startswith("/private/tmp/") or project.startswith("/tmp/"):
            return

        sid = session_id or "-"
        norm_text = " ".join(cleaned.split())

        if channel == "history.jsonl" and "[Pasted text #" in cleaned and sid != "-":  # ---- 6
            existing_ts_list = session_timestamps.get((tool, sid), [])
            if any(abs(sort_ts - ets) <= 120 for ets in existing_ts_list):
                return

        text_key = (tool, norm_text)
        prev_list = seen_entries.setdefault(text_key, [])
        for prev_ts, prev_channel in prev_list:
            if prev_channel == channel and abs(sort_ts - prev_ts) <= 1.0:  # ---- 7
                return
            if prev_channel != channel and abs(sort_ts - prev_ts) <= 300.0:
                return
        prev_list.append((sort_ts, channel))

        if sid != "-":
            session_timestamps.setdefault((tool, sid), []).append(sort_ts)

        records.append(
            PromptRecord(
                timestamp_iso=ts_iso,
                sort_ts=sort_ts,
                tool=tool,
                channel=channel,
                project=_normalize_project_label(project),
                session_id=sid,
                source_path=source_path,
                prompt_text=cleaned,
            )
        )

    # 1) Claude 프로젝트별 세션 트랜스크립트 (~/.claude/projects/**/*.jsonl 및 transcript_backups) — 전문 우선 확보 (서브에이전트 제외)
    claude_transcript_files: list[Path] = []
    claude_projects_dir = CLAUDE_HOME / "projects"  # ---- 8
    if claude_projects_dir.is_dir():
        claude_transcript_files.extend(sorted(claude_projects_dir.rglob("*.jsonl")))
    transcript_backups_dir = CLAUDE_HOME / "hooks-logs" / "transcript_backups"
    if transcript_backups_dir.is_dir():
        claude_transcript_files.extend(sorted(transcript_backups_dir.glob("*.jsonl")))

    for jf in claude_transcript_files:
        if not jf.is_file() or "subagents" in jf.parts or jf.name.startswith("agent-"):
            continue
        mtime = jf.stat().st_mtime
        last_cwd = "global-claude"
        with jf.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                try:
                    obj = json.loads(line)
                    if obj.get("cwd"):
                        last_cwd = str(obj["cwd"])
                    if obj.get("type") != "user" or obj.get("isMeta"):
                        continue
                    text = _extract_user_text_from_claude_message(obj.get("message"))
                    if not text:
                        continue
                    ts_iso, sort_ts = _parse_timestamp(obj.get("timestamp"), mtime)
                    add_record(
                        ts_iso, sort_ts, "Claude Code", "project-transcript",
                        last_cwd,
                        str(obj.get("sessionId") or jf.stem),
                        str(jf),
                        text,
                    )
                except Exception:
                    continue

    # 2) Claude 훅 세션 로그 (~/.claude/hooks-logs/sessions/*.jsonl)
    hook_sessions_dir = CLAUDE_HOME / "hooks-logs" / "sessions"
    if hook_sessions_dir.is_dir():
        for hf in sorted(hook_sessions_dir.glob("*.jsonl")):
            if not hf.is_file():
                continue
            mtime = hf.stat().st_mtime
            session_cwd = "global-claude"
            with hf.open("r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    try:
                        obj = json.loads(line)
                        if obj.get("event") == "session_start" and obj.get("cwd"):
                            session_cwd = str(obj["cwd"])
                        elif obj.get("event") == "prompt":
                            if obj.get("cwd"):
                                session_cwd = str(obj["cwd"])
                            ts_iso, sort_ts = _parse_timestamp(obj.get("timestamp"), mtime)
                            add_record(
                                ts_iso, sort_ts, "Claude Code", "hook-session",
                                session_cwd, hf.stem, str(hf), str(obj.get("prompt") or ""),
                            )
                    except Exception:
                        continue

    # 3) Claude 전역 history.jsonl (트랜스크립트에 없는 세션 보완)
    claude_hist = CLAUDE_HOME / "history.jsonl"
    if claude_hist.is_file():
        mtime = claude_hist.stat().st_mtime
        with claude_hist.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                try:
                    obj = json.loads(line)
                    ts_iso, sort_ts = _parse_timestamp(obj.get("timestamp"), mtime)
                    add_record(
                        ts_iso, sort_ts, "Claude Code", "history.jsonl",
                        str(obj.get("project") or "global-claude"),
                        str(obj.get("sessionId") or "-"),
                        str(claude_hist),
                        str(obj.get("display") or ""),
                    )
                except Exception:
                    continue

    # 4) Antigravity CLI & IDE (brain/**/transcript*.jsonl 우선 스캔 후 history.jsonl 보완)
    if GEMINI_HOME.exists():
        ws_re = re.compile(r"(?:Active Workspaces:\s*\n-\s*|Command Working Directory:\s*)(\S+)")
        for agy_name, tool_label in (("antigravity-cli", "Antigravity CLI"), ("antigravity", "Antigravity IDE")):
            agy_dir = GEMINI_HOME / agy_name
            if not agy_dir.is_dir():
                continue

            # history.jsonl에서 conversationId -> workspace 매핑 선추출
            conv_workspace_map: dict[str, str] = {}
            hist_f = agy_dir / "history.jsonl"
            if hist_f.is_file():
                with hist_f.open("r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        try:
                            obj = json.loads(line)
                            cid = str(obj.get("conversationId") or "")
                            ws_val = str(obj.get("workspace") or "")
                            if cid and ws_val:
                                conv_workspace_map[cid] = ws_val
                        except Exception:
                            continue

            brain_dir = agy_dir / "brain"
            if brain_dir.is_dir():
                for conv_dir in sorted(brain_dir.iterdir()):
                    if not conv_dir.is_dir():
                        continue
                    logs_dir = conv_dir / ".system_generated" / "logs"
                    trans_file = logs_dir / "transcript_full.jsonl"  # ---- 9
                    if not trans_file.is_file():
                        trans_file = logs_dir / "transcript.jsonl"
                    if not trans_file.is_file():
                        continue

                    mtime = trans_file.stat().st_mtime
                    conv_id = conv_dir.name
                    conv_proj = conv_workspace_map.get(conv_id)
                    with trans_file.open("r", encoding="utf-8", errors="replace") as f:
                        for line in f:
                            try:
                                obj = json.loads(line)
                                raw_content = str(obj.get("content") or "")
                                if not conv_proj and ("Active Workspaces:" in raw_content or "Command Working Directory:" in raw_content):
                                    m_ws = ws_re.search(raw_content)
                                    if m_ws:
                                        conv_proj = m_ws.group(1)
                                if obj.get("type") != "USER_INPUT":
                                    continue
                                match = USER_REQUEST_RE.search(raw_content)
                                text = match.group(1).strip() if match else raw_content.strip()
                                ts_iso, sort_ts = _parse_timestamp(obj.get("created_at"), mtime)
                                add_record(
                                    ts_iso, sort_ts, tool_label, "brain-transcript",
                                    conv_proj or f"~/.gemini/{agy_name}/brain/{conv_id[:8]}",
                                    conv_id, str(trans_file), text,
                                )
                            except Exception:
                                continue

            if hist_f.is_file():
                mtime = hist_f.stat().st_mtime
                with hist_f.open("r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        try:
                            obj = json.loads(line)
                            ts_iso, sort_ts = _parse_timestamp(obj.get("timestamp"), mtime)
                            add_record(
                                ts_iso, sort_ts, tool_label, "history.jsonl",
                                str(obj.get("workspace") or f"~/.gemini/{agy_name}"),
                                str(obj.get("conversationId") or "-"),
                                str(hist_f),
                                str(obj.get("display") or ""),
                            )
                        except Exception:
                            continue

    records.sort(key=lambda r: (r.sort_ts, r.tool, r.session_id))
    return records


# ==============================================================================
# [섹션 6] 아카이브 및 통합 인덱스 생성기 (ARCHIVE & INDEX WRITERS)
# ==============================================================================

def compute_sha256(path: Path) -> str:
    """
    역할:
        파일 내용을 64KB 청크 단위로 읽어 SHA-256 해시 앞 16자리를 반환합니다.
    매개변수:
        path (Path): 해시를 계산할 대상 파일 경로
    반환값:
        str: 16자리 16진수 해시 문자열
    """
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()[:16]


def format_size(num_bytes: int) -> str:
    """
    역할:
        바이트 단위 파일 크기를 사람이 읽기 쉬운 `B`, `KB`, `MB` 문자열로 변환합니다.
    매개변수:
        num_bytes (int): 파일 크기(바이트)
    반환값:
        str: 포맷팅된 크기 문자열 (예: `'4.2 KB'`)
    """
    if num_bytes < 1024:
        return f"{num_bytes} B"
    if num_bytes < 1024 * 1024:
        return f"{num_bytes / 1024:.1f} KB"
    return f"{num_bytes / (1024 * 1024):.1f} MB"


def _to_file_uri(path_or_str: Path | str) -> str:
    """
    역할:
        파일 경로 내에 공백이나 괄호가 포함되어 있어도 CommonMark / GFM 마크다운 링크(`[...](file://...)`)가
        깨지지 않도록 공백 등을 퍼센트 인코딩(`%20`)한 `file://` URI를 반환합니다.
    매개변수:
        path_or_str (Path | str): 변환할 절대 경로
    반환값:
        str: `file:///...` 형태의 마크다운 안전 URI 문자열
    """
    raw = _nfc(str(path_or_str)).replace(" ", "%20").replace("(", "%28").replace(")", "%29")
    return f"file://{raw}"


def _escape_md_table(text: str) -> str:
    """
    역할:
        마크다운 테이블 셀 내부에 파이프(`|`)나 줄바꿈이 들어가 표 레이아웃이 깨지는 것을 방지합니다.
    매개변수:
        text (str): 원본 셀 문자열
    반환값:
        str: 파이프와 개행이 이스케이프된 문자열
    """
    return _nfc(text).replace("|", "\\|").replace("\n", " ")


def _wrap_markdown_code_block(text: str, lang: str = "text") -> list[str]:
    """
    역할:
        프롬프트 본문(`text`) 내부에 코드블록(예: ```c ... ```)이 포함되어 있을 때
        외곽 마크다운 코드블록 펜스가 조기 종료되지 않도록 본문 내 최대 연속 백틱 수보다
        1개 더 긴 백틱 펜스(최소 3개)로 안전하게 감쌉니다.
    매개변수:
        text (str): 코드블록으로 감쌀 본문 텍스트
        lang (str): 코드블록 언어 지정자 (기본값: 'text')
    반환값:
        list[str]: `[여는_펜스, 본문, 닫는_펜스]` 문자열 리스트
    """
    max_ticks = max((len(m.group(0)) for m in BACKTICK_RUN_RE.finditer(text)), default=0)
    fence = "`" * max(3, max_ticks + 1)
    return [f"{fence}{lang}", text, fence]


def write_extracted_prompt_archives(target_dir: Path, records: list[PromptRecord]) -> list[CollectedItem]:
    """
    역할:
        추출된 `PromptRecord` 리스트를 바탕으로 중앙 폴더에 3종의 마크다운 아카이브와
        1종의 정규화된 JSONL 데이터셋 파일을 생성하고, 이를 `CollectedItem` 목록으로 반환합니다.
    매개변수:
        target_dir (Path)          : 아카이브 파일을 저장할 중앙 폴더 경로 (~/central-docs)
        records (list[PromptRecord]): 추출 및 정렬된 프롬프트 레코드 리스트
    반환값:
        list[CollectedItem]: 생성된 4종 아카이브 파일의 `CollectedItem` 메타데이터 리스트
    """
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    created_files: list[tuple[Path, str, str]] = []

    claude_records = [r for r in records if r.tool == "Claude Code"]
    agy_records = [r for r in records if r.tool != "Claude Code"]

    # 1) 전체 시계열 통합 마크다운
    timeline_path = target_dir / "prompt__EXTRACTED__ALL_PROMPTS_TIMELINE.md"
    t_lines: list[str] = [
        "# 💬 전체 AI 프롬프트 통합 시계열 아카이브 (Claude · Antigravity · Gemini)",
        "",
        f"- **추출 일시**: `{now_str}`",
        f"- **총 고유 프롬프트 수**: **{len(records):,}건** (Claude Code: {len(claude_records):,}건 / Antigravity & Gemini: {len(agy_records):,}건)",
        "- **추출 출처**: `~/.claude/history.jsonl`, `~/.claude/projects/**/*.jsonl`, `~/.claude/hooks-logs/sessions/*.jsonl`, `~/.gemini/antigravity*/history.jsonl`, `~/.gemini/antigravity*/brain/**/transcript*.jsonl`",
        "",
        "---",
        "",
    ]
    for idx, rec in enumerate(records, start=1):
        t_lines.extend([
            f"### #{idx} · `{rec.timestamp_iso}` · **{rec.tool}** (`{rec.project}`)",
            f"- **세션 ID**: `{rec.session_id}` | **채널**: `{rec.channel}` | **추출 원본**: [`{Path(rec.source_path).name}`]({_to_file_uri(rec.source_path)})",
            "",
            *_wrap_markdown_code_block(rec.prompt_text, "text"),
            "",
        ])
    timeline_path.write_text("\n".join(t_lines), encoding="utf-8")
    created_files.append((timeline_path, "extracted-all-prompts-timeline", "~/.claude + ~/.gemini (전수 추출 시계열 통합본)"))

    # 2) Claude 프로젝트별 프롬프트 마크다운
    claude_md_path = target_dir / "prompt__EXTRACTED__CLAUDE_PROMPTS_BY_PROJECT.md"
    by_proj: dict[str, list[PromptRecord]] = {}
    for r in claude_records:
        by_proj.setdefault(r.project, []).append(r)

    c_lines: list[str] = [
        "# 🤖 Claude Code 프로젝트별 프롬프트 아카이브",
        "",
        f"- **추출 일시**: `{now_str}`",
        f"- **총 프롬프트 수**: **{len(claude_records):,}건**",
        "",
        "## 📦 프로젝트별 요약",
        "",
        "| 프로젝트 경로 | 프롬프트 수 |",
        "| :--- | ---: |",
    ]
    for proj in sorted(by_proj.keys()):
        c_lines.append(f"| `{_escape_md_table(proj)}` | **{len(by_proj[proj]):,}건** |")
    c_lines.extend(["", "---", ""])

    for proj in sorted(by_proj.keys()):
        proj_recs = by_proj[proj]
        c_lines.extend([f"## 📂 `{proj}` ({len(proj_recs):,}건)", ""])
        for i, rec in enumerate(proj_recs, start=1):
            c_lines.extend([
                f"#### [{i}] `{rec.timestamp_iso}` (세션: `{rec.session_id[:12]}` · [원본]({_to_file_uri(rec.source_path)}))",
                "",
                *_wrap_markdown_code_block(rec.prompt_text, "text"),
                "",
            ])
    claude_md_path.write_text("\n".join(c_lines), encoding="utf-8")
    created_files.append((claude_md_path, "extracted-claude-prompts", "~/.claude/history.jsonl + projects/**/*.jsonl"))

    # 3) Antigravity & Gemini 세션별 프롬프트 마크다운
    agy_md_path = target_dir / "prompt__EXTRACTED__ANTIGRAVITY_GEMINI_PROMPTS.md"
    by_sess: dict[str, list[PromptRecord]] = {}
    agy_by_proj: dict[str, list[PromptRecord]] = {}
    for r in agy_records:
        by_sess.setdefault(r.session_id, []).append(r)
        agy_by_proj.setdefault(r.project, []).append(r)

    a_lines: list[str] = [
        "# 🚀 Antigravity & Gemini 프롬프트 아카이브",
        "",
        f"- **추출 일시**: `{now_str}`",
        f"- **총 프롬프트 수**: **{len(agy_records):,}건**",
        "",
        "## 📦 프로젝트별 요약",
        "",
        "| 프로젝트 경로 | 프롬프트 수 |",
        "| :--- | ---: |",
    ]
    for proj in sorted(agy_by_proj.keys()):
        a_lines.append(f"| `{_escape_md_table(proj)}` | **{len(agy_by_proj[proj]):,}건** |")
    a_lines.extend(["", "---", ""])

    for sid, s_recs in sorted(by_sess.items(), key=lambda kv: kv[1][0].sort_ts):
        sess_proj = s_recs[0].project
        a_lines.extend([
            f"## 🧠 대화 세션 `{sid}` · `{sess_proj}` ({len(s_recs)}건 · `{s_recs[0].timestamp_iso}` ~ `{s_recs[-1].timestamp_iso}`)",
            "",
        ])
        for i, rec in enumerate(s_recs, start=1):
            a_lines.extend([
                f"#### [{i}] `{rec.timestamp_iso}` · `{rec.tool}` (`{rec.project}`) · [원본 로그]({_to_file_uri(rec.source_path)})",
                "",
                *_wrap_markdown_code_block(rec.prompt_text, "text"),
                "",
            ])
    agy_md_path.write_text("\n".join(a_lines), encoding="utf-8")
    created_files.append((agy_md_path, "extracted-antigravity-prompts", "~/.gemini/antigravity*/history.jsonl + brain/**/transcript.jsonl"))

    # 4) 정규화된 JSONL 통합 데이터셋
    dataset_path = target_dir / "prompt__EXTRACTED__ALL_PROMPTS_DATASET.jsonl"
    with dataset_path.open("w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(asdict(rec), ensure_ascii=False) + "\n")
    created_files.append((dataset_path, "extracted-prompts-dataset", "~/.claude + ~/.gemini (JSONL 통합 데이터셋)"))

    items: list[CollectedItem] = []
    for fpath, subcat, disp_rel in created_files:
        stat = fpath.stat()
        items.append(
            CollectedItem(
                category="prompt",
                subcategory=subcat,
                project="extracted-prompts",
                origin_scope="extracted-prompts",
                source_path=str(fpath),
                display_rel_path=disp_rel,
                flat_filename=fpath.name,
                extension=fpath.suffix.lower(),
                size_bytes=stat.st_size,
                modified_at=datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M"),
                sha256=compute_sha256(fpath),
            )
        )
    return items


def generate_index_markdown(
    target_dir: Path,
    workspace_root: Path,
    items: list[CollectedItem],
    prompt_count: int = 0,
    include_global: bool = True,
) -> Path:
    """
    역할:
        수집된 모든 파일의 관점별·프로젝트별 분포 표와 클릭 가능한 원본/사본 `file://` 링크를 담은
        통합 목차 파일(`INDEX.md`)을 생성합니다.
    매개변수:
        target_dir (Path)          : 중앙 수집 폴더 경로
        workspace_root (Path)      : 스캔한 워크스페이스 루트 경로
        items (list[CollectedItem]): 수집된 전체 파일 메타데이터 리스트
        prompt_count (int)         : 전수 추출된 고유 프롬프트 건수
        include_global (bool)      : 글로벌 스캔 및 프롬프트 아카이브 생성 여부
    반환값:
        Path: 생성된 `INDEX.md` 파일의 경로
    """
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    index_path = target_dir / "INDEX.md"
    md_total = sum(1 for i in items if i.extension == ".md")
    non_md_total = len(items) - md_total
    global_desc = "`~/.claude`, `~/.gemini/antigravity*`" if include_global else "제외됨 (`--no-global`)"

    lines: list[str] = [
        "# 🗂️ 소프트웨어 엔지니어링 & AI 에이전트 중앙 지식/결정/프롬프트 저장소",
        "",
        f"- **최종 갱신**: `{now_str}`",
        f"- **스캔 워크스페이스**: `{workspace_root}`",
        f"- **글로벌 스캔 경로**: {global_desc}",
        f"- **중앙 수집 폴더**: `{target_dir}`",
        f"- **총 수집 파일 수**: **{len(items):,}개** (마크다운 `{md_total:,}개` / 비-MD 설정·스크립트·로그 `{non_md_total:,}개`)",
        f"- **전수 추출된 고유 프롬프트**: **{prompt_count:,}건**",
        "",
    ]

    if include_global:
        lines.extend([
            "## ⚡ 프롬프트 통합 아카이브 바로가기",
            "",
            f"- 🕒 **[전체 AI 프롬프트 시계열 통합본 열기]({_to_file_uri(target_dir / 'prompt__EXTRACTED__ALL_PROMPTS_TIMELINE.md')})**",
            f"- 🤖 **[Claude Code 프로젝트별 프롬프트 모음 열기]({_to_file_uri(target_dir / 'prompt__EXTRACTED__CLAUDE_PROMPTS_BY_PROJECT.md')})**",
            f"- 🚀 **[Antigravity & Gemini 세션별 프롬프트 모음 열기]({_to_file_uri(target_dir / 'prompt__EXTRACTED__ANTIGRAVITY_GEMINI_PROMPTS.md')})**",
            f"- 🧾 **[프롬프트 정규화 데이터셋 (JSONL)]({_to_file_uri(target_dir / 'prompt__EXTRACTED__ALL_PROMPTS_DATASET.jsonl')})**",
            "",
        ])

    lines.extend([
        "## 📊 1. 관점별(Category) 수집 요약",
        "",
        "| 관점 코드 | 관점 명칭 | 설명 | 파일 수 |",
        "| :--- | :--- | :--- | ---: |",
    ])

    for cat_key, (cat_title, cat_desc) in CATEGORY_META.items():
        count = sum(1 for i in items if i.category == cat_key)
        lines.append(f"| `{cat_key}` | [{cat_title}](#cat-{cat_key}) | {cat_desc} | **{count}개** |")

    # 프로젝트별 분포 표
    lines.extend([
        "",
        "## 📦 2. 프로젝트 / 출처별 분포",
        "",
        "| 프로젝트 / 출처 | 의사결정 (`decision`) | 프롬프트 (`prompt`) | 에이전트 (`agent`) | 스킬/훅 (`skill`) | 설계/구현 (`design`) | 운영/보안 (`ops-sec`) | 합계 |",
        "| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ])

    for proj in sorted({i.project for i in items}):
        p_items = [i for i in items if i.project == proj]
        by_cat = {cat: sum(1 for i in p_items if i.category == cat) for cat in CATEGORY_META}
        lines.append(
            f"| **{_escape_md_table(proj)}** | {by_cat['decision']} | {by_cat['prompt']} | {by_cat['agent']} "
            f"| {by_cat['skill']} | {by_cat['design']} | {by_cat['ops-sec']} | **{len(p_items)}** |"
        )

    # 관점별 상세 파일 테이블
    lines.extend([
        "",
        "---",
        "",
        "## 🔍 3. 관점별 상세 파일 목록 및 추출 원본 위치",
        "",
        "> **파일명 규칙**: `{관점코드}__{출처_상대경로_슬러그}` 형태로 단일 폴더에 평탄(flat)하게 저장됩니다.",
        "> **추출된 원본 경로**를 클릭하면 실제 프로젝트의 원본 파일이 열리고, **수집된 플랫 파일명**을 클릭하면 중앙 저장소 사본이 열립니다.",
        "",
    ])

    for cat_key, (cat_title, cat_desc) in CATEGORY_META.items():
        cat_items = sorted(
            [i for i in items if i.category == cat_key],
            key=lambda x: (x.project, x.display_rel_path),
        )
        lines.extend([
            f"<a id=\"cat-{cat_key}\"></a>",
            f"### {cat_title} ({len(cat_items)}개)",
            f"_{cat_desc}_",
            "",
        ])
        if not cat_items:
            lines.append("- _수집된 파일이 없습니다._\n")
            continue

        lines.extend([
            "| 프로젝트/출처 | 세부 분류 | 추출된 원본 경로 (Source) | 수집된 플랫 파일명 (Collected) | 형식 | 크기 | 수정일 |",
            "| :--- | :--- | :--- | :--- | :--- | ---: | :--- |",
        ])
        for item in cat_items:
            ext_label = item.extension or "script"
            safe_disp = _escape_md_table(item.display_rel_path)
            safe_flat = _escape_md_table(item.flat_filename)
            lines.append(
                f"| `{_escape_md_table(item.project)}` | `{item.subcategory}` | "
                f"[`{safe_disp}`]({_to_file_uri(item.source_path)}) | "
                f"[`{safe_flat}`]({_to_file_uri(target_dir / item.flat_filename)}) | "
                f"`{ext_label}` | {format_size(item.size_bytes)} | {item.modified_at} |"
            )
        lines.append("")

    index_path.write_text("\n".join(lines), encoding="utf-8")
    return index_path


# ==============================================================================
# [섹션 7] 메인 수집 파이프라인 및 CLI (MAIN PIPELINE & CLI)
# ==============================================================================

def _validate_target_dir(workspace_root: Path, target_dir: Path) -> None:
    """
    역할:
        타겟 디렉터리가 워크스페이스 자체, 워크스페이스 하위 폴더, 또는 워크스페이스의 상위 폴더(홈/루트)로
        잘못 지정되어 원본 파일 삭제 또는 재귀 중복 수집이 발생하는 것을 원천 차단합니다.
    매개변수:
        workspace_root (Path): 스캔 워크스페이스 루트 경로
        target_dir (Path)    : 수집 대상 중앙 폴더 경로
    반환값:
        None (위험한 경로일 경우 `ValueError` 발생)
    """
    ws_res = workspace_root.resolve()
    tg_res = target_dir.resolve()
    home_res = Path.home().resolve()

    if tg_res in {ws_res, home_res, Path("/")}:  # ---- 10
        raise ValueError(f"안전 가드레일: 타겟 폴더('{tg_res}')는 워크스페이스나 홈/루트 디렉터리 자체일 수 없습니다.")
    if ws_res.is_relative_to(tg_res):
        raise ValueError(f"안전 가드레일: 타겟 폴더('{tg_res}')가 워크스페이스('{ws_res}')의 상위 폴더일 수 없습니다.")
    if tg_res.is_relative_to(ws_res):
        raise ValueError(f"안전 가드레일: 타겟 폴더('{tg_res}')는 워크스페이스('{ws_res}') 외부(형제 경로 등)에 위치해야 합니다.")


def _clean_previous_managed_files(target_dir: Path, manifest_path: Path, clean_all: bool) -> None:
    """
    역할:
        새로운 수집을 시작하기 전에 이전 실행에서 생성되었던 관리 대상 파일들을 정리합니다.
        `MANIFEST.json`이 유실된 경우에도 `{category}__*` 패턴의 고아 파일들을 안전하게 정리합니다.
    매개변수:
        target_dir (Path)   : 중앙 수집 폴더 경로
        manifest_path (Path): 이전 `MANIFEST.json` 파일 경로
        clean_all (bool)    : True이면 폴더 내 모든 파일을 삭제하고, False이면 관리 대상 파일만 삭제
    반환값:
        None
    """
    if clean_all:
        for existing in target_dir.iterdir():
            if existing.is_file():
                existing.unlink()
        return

    if manifest_path.is_file():
        try:
            prev_data = json.loads(manifest_path.read_text(encoding="utf-8"))
            for prev_item in prev_data.get("items", []):
                old_file = target_dir / prev_item.get("flat_filename", "")
                if old_file.is_file():
                    old_file.unlink()
            return
        except Exception:
            pass

    prefixes = tuple(f"{cat}__" for cat in CATEGORY_META)  # ---- 11
    for existing in target_dir.iterdir():
        if existing.is_file() and existing.name.startswith(prefixes):
            existing.unlink()


def collect_all(  # ---- 12
    workspace_root: Path,
    target_dir: Path,
    include_global: bool = True,
    include_tasks: bool = True,
    clean_all: bool = False,
) -> tuple[list[CollectedItem], int, Path, Path]:
    """
    역할:
        타겟 경로 안전 검증, 워크스페이스 및 글로벌 AI 경로 스캔, 평탄화 파일 복사,
        프롬프트 전수 추출, `INDEX.md` 및 `MANIFEST.json` 생성을 일괄 수행하는 핵심 파이프라인 함수입니다.
    매개변수:
        workspace_root (Path): 스캔할 워크스페이스 루트 경로 (예: ~/githubs)
        target_dir (Path)    : 수집 파일을 저장할 중앙 폴더 경로 (예: ~/central-docs)
        include_global (bool): 글로벌 경로(`~/.claude`, `~/.gemini`) 스캔 및 프롬프트 추출 포함 여부
        include_tasks (bool) : `backlog/tasks/*.md` 및 완료 태스크 포함 수집 여부 (기본값 True)
        clean_all (bool)     : 수집 전 타겟 폴더 전체 초기화 여부
    반환값:
        tuple[list[CollectedItem], int, Path, Path]:
            `(수집된_아이템_리스트, 추출된_고유_프롬프트_수, INDEX_경로, MANIFEST_경로)`
    """
    _validate_target_dir(workspace_root, target_dir)
    target_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = target_dir / "MANIFEST.json"
    _clean_previous_managed_files(target_dir, manifest_path, clean_all=clean_all)

    raw_candidates = scan_workspace(workspace_root, include_tasks=include_tasks)
    if include_global:
        raw_candidates.extend(scan_global_ai_dirs())

    seen_sources: set[Path] = set()
    used_flat_names: set[str] = set()
    collected_items: list[CollectedItem] = []

    for src_path, category, subcategory, project, origin_scope, display_rel_path in raw_candidates:
        try:
            resolved = src_path.resolve()
            if resolved in seen_sources or not resolved.is_file():
                continue
            stat = resolved.stat()
        except (OSError, RuntimeError):
            continue

        if stat.st_size == 0:
            continue
        seen_sources.add(resolved)

        flat_name = build_flat_filename(category, origin_scope, display_rel_path)
        if flat_name in used_flat_names:
            short_hash = hashlib.sha1(str(resolved).encode("utf-8")).hexdigest()[:6]
            ext = Path(flat_name).suffix
            stem = flat_name[: len(flat_name) - len(ext)] if ext else flat_name
            suffix = f"__{short_hash}{ext}"
            max_stem_bytes = MAX_FLAT_FILENAME_BYTES - len(suffix.encode("utf-8"))
            safe_stem = stem.encode("utf-8")[:max_stem_bytes].decode("utf-8", errors="ignore").rstrip("_- ")
            flat_name = f"{safe_stem}{suffix}"
        used_flat_names.add(flat_name)

        dest_path = target_dir / flat_name
        if resolved != dest_path.resolve():
            shutil.copy2(resolved, dest_path)

        collected_items.append(
            CollectedItem(
                category=category,
                subcategory=subcategory,
                project=project,
                origin_scope=origin_scope,
                source_path=_nfc(str(resolved)),
                display_rel_path=_nfc(display_rel_path),
                flat_filename=flat_name,
                extension=resolved.suffix.lower(),
                size_bytes=stat.st_size,
                modified_at=datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M"),
                sha256=compute_sha256(resolved),
            )
        )

    # 글로벌 프롬프트 전수 추출 및 아카이브 생성
    prompt_records: list[PromptRecord] = []
    if include_global:
        prompt_records = extract_all_prompt_records()
        collected_items.extend(write_extracted_prompt_archives(target_dir, prompt_records))

    # 카테고리 우선순위 -> 프로젝트 -> 상대경로 순 정렬
    cat_order = {k: idx for idx, k in enumerate(CATEGORY_META.keys())}
    collected_items.sort(key=lambda x: (cat_order.get(x.category, 99), x.project, x.display_rel_path))

    # INDEX.md 및 MANIFEST.json 기록
    index_path = generate_index_markdown(
        target_dir,
        workspace_root,
        collected_items,
        prompt_count=len(prompt_records),
        include_global=include_global,
    )
    manifest_data = {
        "generated_at": datetime.now().isoformat(),
        "workspace_root": str(workspace_root),
        "target_dir": str(target_dir),
        "total_count": len(collected_items),
        "extracted_prompt_count": len(prompt_records),
        "counts_by_category": {
            cat: sum(1 for i in collected_items if i.category == cat)
            for cat in CATEGORY_META
        },
        "items": [asdict(i) for i in collected_items],
    }
    manifest_path.write_text(json.dumps(manifest_data, ensure_ascii=False, indent=2), encoding="utf-8")

    return collected_items, len(prompt_records), index_path, manifest_path


def run_keyword_search(target_dir: Path, keyword_raw: str) -> None:
    """
    역할:
        `MANIFEST.json`에 기록된 수집 파일/원본 경로 목록과
        `prompt__EXTRACTED__ALL_PROMPTS_DATASET.jsonl`의 프롬프트 본문에서 키워드를 NFC 정규화 후 대소문자 구분 없이 검색합니다.
    매개변수:
        target_dir (Path): 중앙 수집 폴더 경로 (~/central-docs)
        keyword_raw (str): 검색할 키워드 문자열
    반환값:
        None (검색 결과를 터미널에 출력)
    """
    manifest_file = target_dir / "MANIFEST.json"
    if not manifest_file.is_file():
        print(f"⚠️ '{manifest_file}' 파일이 없습니다. 먼저 수집을 1회 실행해 주세요.")
        return

    data = json.loads(manifest_file.read_text(encoding="utf-8"))
    keyword = _nfc(keyword_raw).lower()
    matches = [
        it for it in data.get("items", [])
        if keyword in _nfc(it["flat_filename"]).lower()
        or keyword in _nfc(it["source_path"]).lower()
        or keyword in _nfc(it["project"]).lower()
        or keyword in _nfc(it["category"]).lower()
    ]

    print(f"🔎 [파일/경로 검색] '{keyword_raw}' 결과: {len(matches)}건")
    for m in matches:
        print(f"  • [{m['category']}/{m['subcategory']}] {m['flat_filename']}")
        print(f"    ↳ 프로젝트 : {m['project']}")
        print(f"    ↳ 원본 경로: {m['source_path']}")

    dataset_file = target_dir / "prompt__EXTRACTED__ALL_PROMPTS_DATASET.jsonl"
    if not dataset_file.is_file():
        return

    prompt_matches = []
    with dataset_file.open("r", encoding="utf-8") as f:
        for line in f:
            try:
                rec = json.loads(line)
                if keyword in _nfc(rec.get("prompt_text", "")).lower() or keyword in _nfc(rec.get("project", "")).lower():
                    prompt_matches.append(rec)
            except Exception:
                continue

    print(f"\n💬 [프롬프트 본문 검색] '{keyword_raw}' 결과: {len(prompt_matches)}건")
    for pm in prompt_matches[:20]:
        preview = pm["prompt_text"].replace("\n", " ")[:120]
        suffix = "..." if len(pm["prompt_text"]) > 120 else ""
        print(f"  • [{pm['timestamp_iso']}] ({pm['tool']} | {pm['project']})")
        print(f"    ↳ 내용: {preview}{suffix}")
        print(f"    ↳ 출처: {pm['source_path']} (session: {pm['session_id']})")
    if len(prompt_matches) > 20:
        print(f"  ... 외 {len(prompt_matches) - 20}건 (전체 내용은 prompt__EXTRACTED__ALL_PROMPTS_TIMELINE.md 참조)")


def run_self_tests(verbose: bool = False) -> None:
    """
    역할:
        동일 디렉터리에 위치한 `test_central_docs_collector.py` 단위/통합 테스트 스위트를 실행합니다.
        코드 수정 후 수동 실행 시 분류기나 보안 필터, 주석 명세표가 깨졌으면 수집 전에 즉시 감지하여 중단합니다.
    매개변수:
        verbose (bool): True이면 상세 테스트 로그를 출력하고 즉시 종료(`--test` 모드),
                        False이면 조용히 실행하고 통과 여부만 확인(기본 사전 검증 모드)
    반환값:
        None (실패 시 비정상 종료 코드로 프로세스 종료)
    """
    test_file = Path(__file__).resolve().parent / "test_central_docs_collector.py"
    if not test_file.is_file():
        return

    cmd = [sys.executable, "-m", "unittest"]
    if verbose:
        cmd.append("-v")
    cmd.append(test_file.name)

    if verbose:
        res = subprocess.run(cmd, cwd=test_file.parent)
        raise SystemExit(res.returncode)

    res = subprocess.run(cmd, cwd=test_file.parent, capture_output=True, text=True)  # ---- 13
    if res.returncode != 0:
        print("❌ 사전 검증 테스트(test_central_docs_collector.py) 실패! 수집을 중단합니다:\n")
        print(res.stderr or res.stdout)
        raise SystemExit(res.returncode)
    print("✅ 사전 검증 테스트(test_central_docs_collector.py) 통과")


def build_arg_parser() -> argparse.ArgumentParser:
    """
    역할:
        명령줄 인자(CLI Arguments) 파서를 생성하고 반환합니다.
    반환값:
        argparse.ArgumentParser: 구성된 CLI 인자 파서 객체
    """
    parser = argparse.ArgumentParser(
        description="소프트웨어 설계·구현·운영·보안 결정사항 및 AI(Claude/Antigravity/Prompt/Skill/Hook) 자산 중앙 수집기"
    )
    parser.add_argument(
        "-w", "--workspace",
        type=Path,
        default=DEFAULT_WORKSPACE_DIR,
        help=f"스캔할 워크스페이스 루트 경로 (기본값: {DEFAULT_WORKSPACE_DIR})",
    )
    parser.add_argument(
        "-t", "--target",
        type=Path,
        default=None,
        help=f"수집된 파일을 저장할 중앙 폴더 (기본값: {DEFAULT_TARGET_DIR})",
    )
    parser.add_argument(
        "-f", "--find",
        type=str,
        default=None,
        help="수집된 파일명·원본 경로 또는 과거 프롬프트 내용에서 키워드를 즉시 검색",
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="단위/통합 테스트(test_central_docs_collector.py)만 단독 실행",
    )
    parser.add_argument(
        "--skip-test",
        action="store_true",
        help="수집 전 자동 사전 검증 테스트 생략",
    )
    parser.add_argument(
        "--no-global",
        action="store_true",
        help="글로벌 경로(~/.claude, ~/.gemini/antigravity*) 스캔 및 프롬프트 추출 제외",
    )
    parser.add_argument(
        "--include-tasks",
        action="store_true",
        default=True,
        help="backlog/decisions 외에 backlog/tasks 카드들도 함께 수집 (기본값: True)",
    )
    parser.add_argument(
        "--no-tasks",
        action="store_true",
        help="backlog/tasks 및 completed 태스크 카드를 수집에서 제외",
    )
    parser.add_argument(
        "--clean-all",
        action="store_true",
        help="중앙 폴더의 모든 기존 파일을 비우고 처음부터 새로 수집",
    )
    return parser


def main() -> None:
    """
    역할:
        프로그램 메인 진입점입니다.
        CLI 옵션을 해석하여 단독 테스트(`--test`), 키워드 검색(`-f`), 또는 전체 수집(`collect_all`)을 수행합니다.
    반환값:
        None
    """
    args = build_arg_parser().parse_args()  # ---- 14

    if args.test:
        run_self_tests(verbose=True)

    workspace_root = args.workspace.expanduser().resolve()
    target_dir = (
        args.target.expanduser().resolve()
        if args.target is not None
        else (workspace_root.parent / "central-docs").resolve()
    )

    if args.find:
        run_keyword_search(target_dir, args.find)
        return

    if not args.skip_test:
        run_self_tests(verbose=False)

    print(f"🔍 스캔 시작 워크스페이스: {workspace_root}")
    if not args.no_global:
        print(f"🌐 글로벌 AI 경로 포함  : {CLAUDE_HOME}, {GEMINI_HOME}/antigravity*")
    print(f"📂 중앙 저장소 대상 경로: {target_dir}\n")

    items, prompt_count, index_path, manifest_path = collect_all(
        workspace_root=workspace_root,
        target_dir=target_dir,
        include_global=not args.no_global,
        include_tasks=not args.no_tasks,
        clean_all=args.clean_all,
    )

    print("📊 [관점별 수집 현황]")
    for cat_key, (cat_title, _) in CATEGORY_META.items():
        cat_items = [i for i in items if i.category == cat_key]
        md_cnt = sum(1 for i in cat_items if i.extension == ".md")
        non_md_cnt = len(cat_items) - md_cnt
        print(f"  - {cat_title:<36}: 총 {len(cat_items):>3}개 (MD {md_cnt:>3}개 / 비-MD {non_md_cnt:>3}개)")

    if not args.no_global:
        print(f"\n💬 [프롬프트 전수 추출 결과]")
        print(f"  - Claude · Antigravity · Gemini 통합 고유 프롬프트: 총 {prompt_count:,}건 추출 완료")
        print(f"  - 전체 시계열 마크다운: {target_dir / 'prompt__EXTRACTED__ALL_PROMPTS_TIMELINE.md'}")
        print(f"  - Claude 프로젝트별  : {target_dir / 'prompt__EXTRACTED__CLAUDE_PROMPTS_BY_PROJECT.md'}")
        print(f"  - Antigravity 세션별 : {target_dir / 'prompt__EXTRACTED__ANTIGRAVITY_GEMINI_PROMPTS.md'}")
        print(f"  - 통합 JSONL 데이터셋 : {target_dir / 'prompt__EXTRACTED__ALL_PROMPTS_DATASET.jsonl'}")

    print(f"\n✨ 완료! 총 {len(items)}개의 파일이 '{target_dir}' 폴더에 평탄(flat)하게 수집되었습니다.")
    print(f"   📑 통합 목차 및 출처 인덱스 : {index_path}")
    print(f"   🧾 원본 경로 매핑 매니페스트: {manifest_path}")


if __name__ == "__main__":  # pragma: no cover
    main()


# ======== 노트 ========
# 1 시크릿 파일명 차단 목록
#   설명: 환경변수·토큰·OAuth 토큰 파일명은 어떤 경로에서도 수집하지 않는다. 이 집합과 SECRET_SUFFIXES,
#   설명: is_secret_or_blocked()가 함께 시크릿 유출을 막는 불변식이며, 스캐너는 분류 전에 항상 이 검사를 거친다.
#   관련: test_central_docs_collector.py (test_blocks_secret_and_sensitive_files)
#   개념: 불변식, 차단 목록(denylist)
# 2 240바이트 초과 시 해시 접미사
#   설명: macOS APFS 파일명 255B 제한 때문에 UTF-8 기준 240B를 넘으면 `~{sha1 앞 8자리}{확장자}`를 붙여 잘라 낸다.
#   설명: 해시 입력에 origin_scope를 넣어 서로 다른 출처의 같은 상대 경로가 같은 이름으로 합쳐지지 않게 한다.
#   개념: 결정적 이름(deterministic naming), UTF-8 바이트 절단
# 3 외부·노이즈 폴더 제외
#   설명: 외부 레퍼런스/서적 예제 폴더, Git worktree 복제본, OCR 페이지 출력 덤프 및 외부 크롤링 데이터는
#   설명: 엔지니어링 의사결정과 무관하므로 분류 단계에서 제외한다(원문 주석: "외부 레퍼런스/서적 예제 폴더, Git worktree
#   설명: 복제본, OCR 페이지 출력 덤프 및 외부 크롤링 데이터 제외").
#   관련: EXTERNAL_NOISE_DIRS, scan_workspace()의 가지치기(노트 5)
# 4 형제 워크스페이스 자동 포함
#   설명: 기본 워크스페이스(~/githubs)를 스캔할 때만 형제 폴더 github-gardenning도 함께 스캔하고, 그 결과의 프로젝트명은
#   설명: 접두사 github-gardenning으로 고정한다. 임의 -w 경로를 줬을 때는 포함하지 않는다.
#   관련: DEFAULT_WORKSPACE_DIR
# 5 os.walk 제자리 가지치기
#   설명: dirnames를 슬라이스 대입으로 제자리 수정해야 os.walk가 제외 폴더로 내려가지 않는다.
#   설명: 새 리스트를 대입하면 가지치기가 적용되지 않는다. 대규모 워크스페이스 순회 성능의 핵심이다.
#   개념: 가지치기(pruning), 제자리 변경
# 6 붙여넣기 축약본 제외
#   설명: history.jsonl의 `[Pasted text #1 +N lines]` 축약본이 트랜스크립트 원문과 같은 시점(120초 이내)에 이미 존재하면
#   설명: 제외한다. 전문이 보존된 쪽만 남기려는 것이다.
#   관련: extract_all_prompt_records() docstring의 동작 흐름 1)
# 7 중복 제거 시간창
#   설명: 동일 채널은 1초 이내, 서로 다른 채널은 300초 이내의 동일 프롬프트만 중복으로 본다. 이렇게 해야 같은 지시를
#   설명: 사용자가 일부러 반복한 턴은 남기면서 트랜스크립트·history·hook 로그가 겹쳐 기록한 사본만 걸러 낸다.
#   개념: 중복 제거(dedup), 시간창(time window)
# 8 Claude 트랜스크립트 소스
#   설명: ~/.claude/projects/**/*.jsonl과 hooks-logs/transcript_backups가 원문이 보존된 1순위 소스다.
#   설명: 서브에이전트 로그(subagents, agent-*)는 사람이 입력한 프롬프트가 아니므로 읽지 않는다.
#   관련: CLAUDE_HOME, INTERNAL_MESSAGE_PREFIXES
# 9 Antigravity 트랜스크립트 소스
#   설명: brain/<대화ID>/.system_generated/logs 아래 transcript_full.jsonl을 우선, 없으면 transcript.jsonl을 읽는다.
#   설명: history.jsonl의 conversationId -> workspace 매핑으로 프로젝트를 정하고, 없으면 본문의 Active Workspaces 등에서 찾는다.
#   관련: GEMINI_HOME
# 10 타겟 폴더 안전 가드레일
#   설명: 타겟 폴더가 워크스페이스·홈·루트 자체이거나 워크스페이스의 상위 또는 하위면 ValueError로 막는다.
#   설명: 수집 전 단계에서 기존 파일을 지우므로(_clean_previous_managed_files), 잘못된 경로면 원본 삭제나 재귀 수집이 일어날 수 있다.
#   개념: 가드레일(guardrail), 불변식
# 11 MANIFEST 유실 시 고아 파일 정리
#   설명: MANIFEST.json이 없거나 손상된 경우 `{category}__*` 접두사를 가진 기존 수집본을 지워 재수집 때 쌓이지 않게 한다.
#   설명: clean_all이 아니면 접두사가 맞는 관리 대상 파일만 지우고 그 밖의 파일은 건드리지 않는다.
# 12 수집 파이프라인 진입 함수
#   설명: 타겟 검증 -> 이전 수집본 정리 -> 스캔 -> 평탄화 복사 -> 프롬프트 추출 -> INDEX.md·MANIFEST.json 순서로 진행한다.
#   관련: 파일 위 [설계 메모]의 실행 흐름도 Step 0~5
# 13 수집 전 사전 테스트 게이트
#   설명: 기본 실행은 수집 전에 test_central_docs_collector.py를 조용히 돌리고, 실패하면 수집을 중단하고 같은 종료 코드로 끝낸다.
#   설명: 분류기나 보안 필터가 깨진 채로 중앙 폴더를 덮어쓰지 않게 하는 안전장치다(--skip-test로 생략 가능).
#   관련: test_central_docs_collector.py
# 14 프로그램 진입점
#   설명: CLI 인자를 해석해 --test(테스트만), -f/--find(키워드 검색), 기본(전체 수집) 중 하나를 수행한다.
#   관련: build_arg_parser(), collect_all()
