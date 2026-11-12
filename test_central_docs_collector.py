# ---
# title: test_central_docs_collector.py
# description: central-docs-collector.py의 시크릿 차단·분류·평탄화·프롬프트 추출 등을 검증하는 단위·통합 테스트 스위트
# authors: [coralstay]
# license: AGPL-3.0-only
# status: draft
# created_date: '2026-11-06'
# updated_date: '2026-11-06'
# ---
# [설계 메모]
# 기존 배너 정보: File Name = test_central_docs_collector.py.
# Description: central-docs-collector.py 에 대한 단위 및 통합 테스트 스위트
from __future__ import annotations

import ast
import importlib.util
import json
import sys
import tempfile
import unicodedata
import unittest
from pathlib import Path
from unittest import mock

# 하이픈이 포함된 central-docs-collector.py 모듈 동적 로드
MODULE_PATH = Path(__file__).resolve().parent / "central-docs-collector.py"
spec = importlib.util.spec_from_file_location("central_docs_collector", MODULE_PATH)
assert spec is not None and spec.loader is not None
collector = importlib.util.module_from_spec(spec)
sys.modules["central_docs_collector"] = collector
spec.loader.exec_module(collector)  # ---- 1


class TestSecurityAndExclusionFilters(unittest.TestCase):
    """시크릿/인증정보 차단 및 제외 디렉터리 필터 테스트"""

    def test_blocks_secret_and_sensitive_files(self) -> None:  # ---- 2
        blocked_samples = [
            Path("/repo/.env"),
            Path("/repo/.env.local"),
            Path("/repo/.env.production"),
            Path("/repo/credentials.json"),
            Path("/repo/token.json"),
            Path("/Users/user/.claude/.claude.json"),
            Path("/Users/user/.gemini/antigravity-oauth-token"),
            Path("/Users/user/.gemini/jetski-standalone-oauth-token"),
            Path("/repo/certs/private.pem"),
            Path("/repo/certs/server.key"),
            Path("/Users/user/.claude/settings.json.bak.1791014467"),
            Path("/Users/user/.gemini/conversation_summaries.db"),
            Path("/Users/user/.gemini/conversation_summaries.db-wal"),
            Path("/repo/.DS_Store"),
        ]
        for p in blocked_samples:
            with self.subTest(path=p):
                self.assertTrue(collector.is_secret_or_blocked(p), f"Should block secret/cache file: {p}")

    def test_allows_safe_policy_and_history_files(self) -> None:
        allowed_samples = [
            Path("/repo/.env.example"),
            Path("/repo/SECURITY.md"),
            Path("/repo/.gitleaks.toml"),
            Path("/repo/CLAUDE.md"),
            Path("/Users/user/.claude/history.jsonl"),
            Path("/Users/user/.claude/settings.json"),
            Path("/repo/backlog/decisions/decision-2 - Drive-인증은-OAuth-테스트-모드-수동-실행.md"),
            Path("/repo/hooks/protect_secrets.py"),
            Path("/repo/docs/oauth-setup.md"),
        ]
        for p in allowed_samples:
            with self.subTest(path=p):
                self.assertFalse(collector.is_secret_or_blocked(p), f"Should allow safe file: {p}")


class TestWorkspaceClassification(unittest.TestCase):
    """6대 엔지니어링·AI 관점별 파일 분류 테스트"""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _touch(self, rel_path: str, content: str = "sample") -> Path:
        p = self.ws / rel_path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return p

    def test_classifies_decisions(self) -> None:
        p1 = self._touch("proj/backlog/decisions/decision-1 - 아키텍처-결정.md")
        p2 = self._touch("proj/backlog/config.yml")
        p3 = self._touch("proj/design/3-아키텍처-설계서/05-설계-결정.md")
        p4 = self._touch("proj/backlog/docs/doc-1 - 검증-로그.md")
        p4_dec = self._touch("proj/backlog/docs/doc-4 - 플랫폼-전환-결정-기록.md")
        p5 = self._touch("proj/backlog/drafts/draft-1 - 초안.md")
        p6 = self._touch("proj/backlog/milestones/m-0 - 마일스톤.md")
        p7 = self._touch("proj/backlog/tasks/task-1 - OAuth-구현.md")
        p7_done = self._touch("proj/backlog/completed/gf-43 - 완료-태스크.md")
        p7_idx = self._touch("proj/backlog/work-order.md")
        p8 = self._touch("proj/modules/vpc/Lesson-and-learn.md")

        self.assertEqual(collector.classify_workspace_file(p1, self.ws), ("decision", "backlog-decision"))
        self.assertEqual(collector.classify_workspace_file(p2, self.ws), ("decision", "backlog-config"))
        self.assertEqual(collector.classify_workspace_file(p3, self.ws), ("decision", "architecture-decision"))
        self.assertEqual(collector.classify_workspace_file(p4, self.ws), ("design", "backlog-doc"))
        self.assertEqual(collector.classify_workspace_file(p4_dec, self.ws), ("decision", "architecture-decision"))
        self.assertEqual(collector.classify_workspace_file(p5, self.ws), ("decision", "backlog-draft"))
        self.assertEqual(collector.classify_workspace_file(p6, self.ws), ("decision", "backlog-milestone"))
        self.assertEqual(collector.classify_workspace_file(p7, self.ws), ("decision", "backlog-task"))
        self.assertEqual(collector.classify_workspace_file(p7_done, self.ws), ("decision", "backlog-task"))
        self.assertEqual(collector.classify_workspace_file(p7_idx, self.ws), ("decision", "backlog-index"))
        self.assertIsNone(collector.classify_workspace_file(p7, self.ws, include_tasks=False))
        self.assertEqual(collector.classify_workspace_file(p8, self.ws), ("decision", "lesson-learned"))

    def test_classifies_prompts(self) -> None:
        p1 = self._touch("tracer/PROMPT_SPEC.md")
        self.assertEqual(collector.classify_workspace_file(p1, self.ws), ("prompt", "prompt-spec"))

    def test_classifies_agents_and_rules(self) -> None:
        p1 = self._touch("proj/CLAUDE.md")
        p2 = self._touch("proj/GEMINI.md")
        p3 = self._touch("proj/AGENTS.md")
        p4 = self._touch("proj/.claude-code-agile-hooks.json")
        p5 = self._touch("proj/context/.cursorrules")
        p6 = self._touch("proj/context/.github/copilot-instructions.md")

        self.assertEqual(collector.classify_workspace_file(p1, self.ws), ("agent", "agent-doc"))
        self.assertEqual(collector.classify_workspace_file(p2, self.ws), ("agent", "agent-doc"))
        self.assertEqual(collector.classify_workspace_file(p3, self.ws), ("agent", "agent-doc"))
        self.assertEqual(collector.classify_workspace_file(p4, self.ws), ("agent", "agent-config"))
        self.assertEqual(collector.classify_workspace_file(p5, self.ws), ("agent", "agent-config"))
        self.assertEqual(collector.classify_workspace_file(p6, self.ws), ("agent", "agent-doc"))

    def test_classifies_skills_commands_and_hooks(self) -> None:
        p_cmd = self._touch("proj/.claude/commands/review-full.md")
        p_skl = self._touch("proj/.agents/skills/fuzzing/SKILL.md")
        p_hok = self._touch("proj/hooks/pre_commit_check.py")
        p_sec_hok = self._touch("proj/hooks/protect_secrets.py")
        p_git_hok = self._touch("proj/template/hooks/prepare-commit-msg")
        # 프론트엔드 UI 훅이나 훅 테스트 파일은 제외되어야 함
        p_ui_hook = self._touch("proj/frontend/src/hooks/useAuth.ts")
        p_test_hook = self._touch("proj/hooks/test_pre_commit.py")

        self.assertEqual(collector.classify_workspace_file(p_cmd, self.ws), ("skill", "claude-command"))
        self.assertEqual(collector.classify_workspace_file(p_skl, self.ws), ("skill", "agent-skill"))
        self.assertEqual(collector.classify_workspace_file(p_hok, self.ws), ("skill", "project-hook"))
        self.assertEqual(collector.classify_workspace_file(p_sec_hok, self.ws), ("skill", "project-hook"))
        self.assertEqual(collector.classify_workspace_file(p_git_hok, self.ws), ("skill", "project-hook"))
        self.assertIsNone(collector.classify_workspace_file(p_ui_hook, self.ws))
        self.assertIsNone(collector.classify_workspace_file(p_test_hook, self.ws))

    def test_classifies_design_and_ops_security(self) -> None:
        p_dsg = self._touch("proj/design/1-제안서/01-배경과-문제.md")
        p_dot = self._touch("proj/design/diagrams/01-arch.dot")
        p_diag_dot = self._touch("proj/diagrams/architecture.dot")
        p_tla = self._touch("proj/specs/modules/vpc/spec.tla")
        p_tla_cfg = self._touch("proj/specs/modules/vpc/spec.cfg")
        p_str = self._touch("proj/PROJECT_STRUCTURE.md")
        p_rdm = self._touch("proj/README.md")
        p_tip = self._touch("proj/tips/snippets.md")
        p_tip_reg = self._touch("proj/tips/snippets_registry.json")
        p_doc = self._touch("proj/docs/architecture.md")
        p_doc_json = self._touch("proj/docs/TREE_METADATA.json")
        p_doctree_cfg = self._touch("freeride/doctree/config/category_tree.yaml")
        p_exp = self._touch("proj/실험방법참고.md")
        p_sec = self._touch("proj/.gitleaks.toml")
        p_trv = self._touch("proj/.trivy.yaml")
        p_rego = self._touch("proj/policy/s3_public_access.rego")
        p_slo = self._touch("proj/live/example-dev/SLO.md")
        p_dc_prod = self._touch("proj/deploy/docker-compose.prod.yml")
        p_k8s = self._touch("proj/deploy/k8s/base/kustomization.yaml")
        p_infracost = self._touch("proj/infracost-usage.yml")
        p_ci = self._touch("proj/.github/workflows/ci.yml")
        p_wf_lbl = self._touch("proj/.github/workflows/labeler.yml")
        p_dep = self._touch("proj/.github/dependabot.yml")

        self.assertEqual(collector.classify_workspace_file(p_dsg, self.ws), ("design", "design-doc"))
        self.assertEqual(collector.classify_workspace_file(p_dot, self.ws), ("design", "design-diagram-spec"))
        self.assertEqual(collector.classify_workspace_file(p_diag_dot, self.ws), ("design", "design-diagram-spec"))
        self.assertEqual(collector.classify_workspace_file(p_tla, self.ws), ("design", "formal-spec"))
        self.assertEqual(collector.classify_workspace_file(p_tla_cfg, self.ws), ("design", "formal-spec"))
        self.assertEqual(collector.classify_workspace_file(p_str, self.ws), ("design", "architecture-doc"))
        self.assertEqual(collector.classify_workspace_file(p_rdm, self.ws), ("design", "project-readme"))
        self.assertEqual(collector.classify_workspace_file(p_tip, self.ws), ("design", "engineering-tip"))
        self.assertEqual(collector.classify_workspace_file(p_tip_reg, self.ws), ("design", "engineering-tip"))
        self.assertEqual(collector.classify_workspace_file(p_doc, self.ws), ("design", "design-doc"))
        self.assertEqual(collector.classify_workspace_file(p_doc_json, self.ws), ("design", "design-doc"))
        self.assertEqual(collector.classify_workspace_file(p_doctree_cfg, self.ws), ("design", "impl-convention"))
        self.assertEqual(collector.classify_workspace_file(p_exp, self.ws), ("design", "workspace-doc"))
        self.assertEqual(collector.classify_workspace_file(p_sec, self.ws), ("ops-sec", "security-policy"))
        self.assertEqual(collector.classify_workspace_file(p_trv, self.ws), ("ops-sec", "security-policy"))
        self.assertEqual(collector.classify_workspace_file(p_rego, self.ws), ("ops-sec", "security-policy"))
        self.assertEqual(collector.classify_workspace_file(p_slo, self.ws), ("ops-sec", "slo-spec"))
        self.assertEqual(collector.classify_workspace_file(p_dc_prod, self.ws), ("ops-sec", "ops-config"))
        self.assertEqual(collector.classify_workspace_file(p_k8s, self.ws), ("ops-sec", "ops-config"))
        self.assertEqual(collector.classify_workspace_file(p_infracost, self.ws), ("ops-sec", "ops-config"))
        self.assertEqual(collector.classify_workspace_file(p_ci, self.ws), ("ops-sec", "ci-workflow"))
        self.assertEqual(collector.classify_workspace_file(p_wf_lbl, self.ws), ("ops-sec", "ci-workflow"))
        self.assertEqual(collector.classify_workspace_file(p_dep, self.ws), ("ops-sec", "repo-governance"))

    def test_excludes_worktrees_and_external_book_samples(self) -> None:
        p_wt = self._touch("factory/components/agent-orchestrator-wt/AO-6/backlog/decisions/decision-1.md")
        p_tlpi = self._touch("cpp/contents/linux/tlpi-dist/Makefile")
        p_ref = self._touch("tracer/references/ebpf-docs-master/hooks/doc.md")
        p_fzf = self._touch("fzf/.github/workflows/linux.yml")
        p_ocr_page = self._touch("freeride/handcrafted-python/sample/round2/pages/p01/vlm_only.md")
        p_scraped = self._touch("freeride/devOps-LifeCycle/content_data/docs-podman/1page.md")

        self.assertIsNone(collector.classify_workspace_file(p_wt, self.ws))
        self.assertIsNone(collector.classify_workspace_file(p_tlpi, self.ws))
        self.assertIsNone(collector.classify_workspace_file(p_ref, self.ws))
        self.assertIsNone(collector.classify_workspace_file(p_fzf, self.ws))
        self.assertIsNone(collector.classify_workspace_file(p_ocr_page, self.ws))
        self.assertIsNone(collector.classify_workspace_file(p_scraped, self.ws))


class TestFlatFilenameGeneration(unittest.TestCase):
    """단일 폴더 평탄화 파일명 규칙 및 macOS 255바이트 안전 축약 테스트"""

    def test_preserves_korean_decision_title_and_extension(self) -> None:
        rel = "coralstay-software-factory/backlog/decisions/decision-1 - Plan-Review-Go의-go는-서명-커밋으로-기록한다.md"
        flat = collector.build_flat_filename("decision", "workspace", rel)
        self.assertTrue(flat.startswith("decision__coralstay-software-factory__backlog__decisions__decision-1_-_"))
        self.assertTrue(flat.endswith(".md"))

    def test_shortens_only_synced_uuid_bucket_directory(self) -> None:
        bucket = "11111111-2222-4333-8444-555555555555_aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
        rel = f"~/.claude/skills/synced/{bucket}/deep-research/SKILL.md"
        flat = collector.build_flat_filename("skill", "global-claude", rel)
        self.assertEqual(flat, "skill__claude__skills__synced__11111111__deep-research__SKILL.md")

    def test_shortens_36char_uuid_brain_directory(self) -> None:
        conv_uuid = "00000000-1111-4222-8333-444444444444"
        rel = f"~/.gemini/antigravity/brain/{conv_uuid}/implementation_plan.md"
        flat = collector.build_flat_filename("agent", "global-antigravity", rel)
        self.assertEqual(flat, "agent__gemini__antigravity__brain__00000000__implementation_plan.md")

    def test_truncates_utf8_bytes_safely_within_limit(self) -> None:
        long_title = "가나다라마바사아자차카타파하" * 10
        rel = f"project/backlog/decisions/decision-99 - {long_title}.md"
        flat = collector.build_flat_filename("decision", "workspace", rel, max_bytes=240)
        encoded = flat.encode("utf-8")
        self.assertLessEqual(len(encoded), 240)
        self.assertTrue(flat.endswith(".md"))
        self.assertIn("~", flat)


class TestPromptExtractionAndEndToEndCollection(unittest.TestCase):
    """Claude/Antigravity 프롬프트 추출 및 전체 수집 파이프라인 통합 테스트"""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.ws = self.root / "githubs"
        self.target = self.root / "central-docs"
        self.mock_claude = self.root / ".claude"
        self.mock_gemini = self.root / ".gemini"

        self.ws.mkdir(parents=True)
        self.mock_claude.mkdir(parents=True)
        self.mock_gemini.mkdir(parents=True)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_extracts_prompts_and_collects_all_into_sibling_target(self) -> None:
        # 1. 워크스페이스 샘플 파일 생성
        dec_file = self.ws / "my-proj" / "backlog" / "decisions" / "decision-1 - DB-선정.md"
        dec_file.parent.mkdir(parents=True)
        dec_file.write_text("# PostgreSQL 채택\n", encoding="utf-8")

        sec_file = self.ws / "my-proj" / ".gitleaks.toml"
        sec_file.write_text("[allowlist]\n", encoding="utf-8")

        secret_env = self.ws / "my-proj" / ".env"
        secret_env.write_text("DB_PASSWORD=supersecret\n", encoding="utf-8")

        # 2. 모의 Claude 히스토리 및 프로젝트 세션 트랜스크립트 생성
        claude_hist = self.mock_claude / "history.jsonl"
        claude_hist.write_text(
            json.dumps({
                "display": "첫 번째 클로드 프롬프트입니다",
                "timestamp": 1790000000000,
                "project": str(self.ws / "my-proj"),
                "sessionId": "sess-111",
            }, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

        proj_trans = self.mock_claude / "projects" / "my-proj" / "sess-222.jsonl"
        proj_trans.parent.mkdir(parents=True)
        proj_trans.write_text(
            "\n".join([
                json.dumps({
                    "type": "user",
                    "timestamp": "2026-10-20T10:00:00Z",
                    "cwd": str(self.ws / "my-proj"),
                    "sessionId": "sess-222",
                    "message": {"role": "user", "content": [{"type": "text", "text": "트랜스크립트 내부 프롬프트"}]},
                }, ensure_ascii=False),
                # tool_result 블록만 있는 이벤트는 프롬프트에서 제외되어야 함
                json.dumps({
                    "type": "user",
                    "timestamp": "2026-10-20T10:01:00Z",
                    "cwd": str(self.ws / "my-proj"),
                    "sessionId": "sess-222",
                    "message": {"role": "user", "content": [{"type": "tool_result", "content": "ok"}]},
                }, ensure_ascii=False),
                # 서브에이전트 hand-back 메시지도 제외되어야 함
                json.dumps({
                    "type": "user",
                    "timestamp": "2026-10-20T10:02:00Z",
                    "cwd": str(self.ws / "my-proj"),
                    "sessionId": "sess-222",
                    "message": {"role": "user", "content": "<agent-message from=\"sub1\">hand-back</agent-message>"},
                }, ensure_ascii=False),
            ]) + "\n",
            encoding="utf-8",
        )
        # 서브에이전트 전용 트랜스크립트 파일(subagents/agent-*.jsonl)도 제외되어야 함
        subagent_trans = self.mock_claude / "projects" / "my-proj" / "sess-222" / "subagents" / "agent-abc.jsonl"
        subagent_trans.parent.mkdir(parents=True)
        subagent_trans.write_text(
            json.dumps({
                "type": "user",
                "timestamp": "2026-10-20T10:03:00Z",
                "cwd": str(self.ws / "my-proj"),
                "sessionId": "sess-222",
                "message": {"role": "user", "content": "You are implementing subagent task"},
            }, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

        # 2-b. 모의 Claude 프로젝트 메모리 및 트랜스크립트 백업 생성
        mem_dir = self.mock_claude / "projects" / "my-proj" / "memory"
        mem_dir.mkdir(parents=True, exist_ok=True)
        (mem_dir / "MEMORY.md").write_text("# 프로젝트 메모리\n", encoding="utf-8")
        (mem_dir / "conflict-decisions.md").write_text("# 충돌 결정\n", encoding="utf-8")

        backup_dir = self.mock_claude / "hooks-logs" / "transcript_backups"
        backup_dir.mkdir(parents=True, exist_ok=True)
        (backup_dir / "backup-1.jsonl").write_text(
            json.dumps({
                "type": "user",
                "timestamp": "2026-10-20T11:00:00Z",
                "cwd": str(self.ws / "my-proj"),
                "sessionId": "sess-backup",
                "message": {"role": "user", "content": "백업 트랜스크립트 프롬프트"},
            }, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

        # 3. 모의 Antigravity 브레인 트랜스크립트, scratch 아티팩트 및 1분 차이 중복 history.jsonl 생성
        agy_conv_dir = self.mock_gemini / "antigravity-cli" / "brain" / "conv-333"
        agy_logs = agy_conv_dir / ".system_generated" / "logs"
        agy_logs.mkdir(parents=True)
        scratch_dir = agy_conv_dir / "scratch"
        scratch_dir.mkdir(parents=True)
        (scratch_dir / "verifier.md").write_text("# 스크래치 검증 보고서\n", encoding="utf-8")

        (agy_logs / "transcript.jsonl").write_text(
            json.dumps({
                "step_index": 0,
                "type": "USER_INPUT",
                "created_at": "2026-10-29T05:01:05Z",
                "content": "<USER_REQUEST>\n안티그래비티 프롬프트 테스트\n</USER_REQUEST>\n<ADDITIONAL_METADATA>meta</ADDITIONAL_METADATA>",
            }, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        # 동일 프롬프트가 history.jsonl에 65초 전 타임스탬프로 기록되고, 단순 /usage 명령어도 섞여 있는 케이스
        agy_hist = self.mock_gemini / "antigravity-cli" / "history.jsonl"
        agy_hist.write_text(
            "\n".join([
                json.dumps({
                    "display": "안티그래비티 프롬프트 테스트",
                    "timestamp": "2026-10-29T05:00:00Z",
                    "workspace": str(self.ws / "my-proj"),
                    "conversationId": "conv-333",
                }, ensure_ascii=False),
                json.dumps({
                    "display": "/usage",
                    "timestamp": "2026-10-29T05:02:00Z",
                    "workspace": str(self.ws / "my-proj"),
                    "conversationId": "conv-333",
                }, ensure_ascii=False),
            ]) + "\n",
            encoding="utf-8",
        )

        with mock.patch.object(collector, "CLAUDE_HOME", self.mock_claude), \
             mock.patch.object(collector, "GEMINI_HOME", self.mock_gemini):  # ---- 3
            items, prompt_count, index_path, manifest_path = collector.collect_all(
                workspace_root=self.ws,
                target_dir=self.target,
                include_global=True,
            )

        # 검증 1: 시크릿(.env)은 수집되지 않아야 함
        flat_names = {i.flat_filename for i in items}
        self.assertFalse(any(".env" in fn for fn in flat_names))

        # 검증 2: 의사결정, 보안 설정, Claude 메모리, Antigravity scratch 아티팩트가 평탄하게 수집되어야 함
        self.assertIn("decision__my-proj__backlog__decisions__decision-1_-_DB-선정.md", flat_names)
        self.assertIn("ops-sec__my-proj__.gitleaks.toml", flat_names)
        self.assertIn("agent__claude__projects__my-proj__memory__MEMORY.md", flat_names)
        self.assertIn("decision__claude__projects__my-proj__memory__conflict-decisions.md", flat_names)
        self.assertIn("agent__gemini__antigravity-cli__brain__conv-333__scratch__verifier.md", flat_names)

        # 검증 3: 4건의 인간 프롬프트(히스토리, 트랜스크립트, 백업 트랜스크립트, 안티그래비티)가 추출되고 프로젝트명이 매핑되어야 함
        self.assertEqual(prompt_count, 4)
        timeline_md = (self.target / "prompt__EXTRACTED__ALL_PROMPTS_TIMELINE.md").read_text(encoding="utf-8")
        self.assertIn("첫 번째 클로드 프롬프트입니다", timeline_md)
        self.assertIn("트랜스크립트 내부 프롬프트", timeline_md)
        self.assertIn("백업 트랜스크립트 프롬프트", timeline_md)
        self.assertIn("안티그래비티 프롬프트 테스트", timeline_md)
        agy_md = (self.target / "prompt__EXTRACTED__ANTIGRAVITY_GEMINI_PROMPTS.md").read_text(encoding="utf-8")
        self.assertIn("my-proj", agy_md)

        # 검증 4: INDEX.md 와 MANIFEST.json 이 생성되고 원본 경로 매핑이 존재해야 함
        self.assertTrue(index_path.is_file())
        self.assertTrue(manifest_path.is_file())
        index_text = index_path.read_text(encoding="utf-8")
        # 공백이 포함된 원본 경로의 file:// 링크가 %20으로 안전하게 인코딩되어야 함
        self.assertIn("decision-1%20-%20DB-선정.md", index_text)
        manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(manifest_data["extracted_prompt_count"], 4)
        self.assertEqual(manifest_data["total_count"], len(items))


class TestMarkdownAndTargetSafety(unittest.TestCase):
    """마크다운 코드블록 동적 펜스 및 타겟 디렉터리 안전 가드레일 테스트"""

    def test_wraps_nested_code_fence_dynamically(self) -> None:
        prompt_with_code = "아래 코드를 봐줘:\n```c\nint main() { return 0; }\n```"
        wrapped = collector._wrap_markdown_code_block(prompt_with_code, "text")
        self.assertEqual(wrapped[0], "````text")
        self.assertEqual(wrapped[2], "````")

    def test_rejects_dangerous_target_directories(self) -> None:  # ---- 4
        ws = Path("/tmp/sample-ws/githubs")
        with self.assertRaises(ValueError):
            collector._validate_target_dir(ws, ws)
        with self.assertRaises(ValueError):
            collector._validate_target_dir(ws, ws.parent)
        with self.assertRaises(ValueError):
            collector._validate_target_dir(ws, ws / "inside-ws-target")
        with self.assertRaises(ValueError):
            collector._validate_target_dir(ws, Path.home())

    def test_normalizes_macos_nfd_hangul_filenames(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            nfd_rel = unicodedata.normalize("NFD", "proj/design/3-아키텍처-설계서/05-설계-결정.md")
            p = ws / nfd_rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("# 결정\n", encoding="utf-8")
            self.assertEqual(collector.classify_workspace_file(p, ws), ("decision", "architecture-decision"))

    def test_documentation_tables_match_code_ast(self) -> None:
        src = MODULE_PATH.read_text(encoding="utf-8")
        header_comments = "\n".join(
            line for line in src.splitlines() if line.startswith("#")
        )
        tree = ast.parse(src)
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                self.assertIn(
                    node.name,
                    header_comments,
                    f"Function/Class '{node.name}' missing from top-level documentation specification table",
                )
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                self.assertIn(
                    node.target.id,
                    header_comments,
                    f"Constant '{node.target.id}' missing from top-level documentation specification table",
                )


class TestFullCoverageEdgeCasesAndCLI(unittest.TestCase):
    """모든 유틸리티, 분기, 글로벌 스캐너, 프롬프트 정제 예외 처리 및 CLI 진입점 100% 커버리지 테스트"""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.ws = self.root / "githubs"
        self.target = self.root / "central-docs"
        self.ws.mkdir(parents=True)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _touch(self, base: Path, rel_path: str, content: str = "sample") -> Path:
        p = base / rel_path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return p

    def test_security_path_project_and_flatname_edge_cases(self) -> None:
        # .env.staging (SECRET_FILE_NAMES에 없지만 .env. 접두사로 차단되는 케이스)
        self.assertTrue(collector.is_secret_or_blocked(Path("/repo/.env.staging")))

        # should_skip_path: root 외부 경로(ValueError) 및 제외 디렉터리 포함 경로
        outside_skip = Path("/tmp/node_modules/pkg/file.md")
        self.assertTrue(collector.should_skip_path(outside_skip, Path("/completely/other/root")))
        self.assertFalse(collector.should_skip_path(Path("/repo/src/main.py"), Path("/repo")))

        # detect_project_name: 외부 경로, 루트 파일, freeride/sub, coralstay-software-factory/components/comp
        self.assertEqual(collector.detect_project_name(Path("/outside/dir/f.md"), self.ws), "dir")
        self.assertEqual(collector.detect_project_name(self.ws / "README.md", self.ws), "githubs")
        self.assertEqual(collector.detect_project_name(self.ws / "freeride/doctree/a/b.md", self.ws), "freeride/doctree")
        self.assertEqual(
            collector.detect_project_name(self.ws / "coralstay-software-factory/components/agent-orchestrator/README.md", self.ws),
            "coralstay-software-factory/agent-orchestrator",
        )

        # build_flat_filename: global-* scope인데 ~/로 시작하지 않는 상대경로
        flat = collector.build_flat_filename("agent", "global-claude", "CLAUDE.md")
        self.assertEqual(flat, "agent__global-claude__CLAUDE.md")

        # format_size: MB 단위
        self.assertEqual(collector.format_size(500), "500 B")
        self.assertEqual(collector.format_size(2048), "2.0 KB")
        self.assertEqual(collector.format_size(3 * 1024 * 1024), "3.0 MB")

    def test_classifier_all_remaining_branches_and_sibling_workspace(self) -> None:
        # 워크스페이스 외부 경로 -> None
        outside_file = self._touch(self.root, "outside.md")
        self.assertIsNone(collector.classify_workspace_file(outside_file, self.ws))

        # 수집기 테스트 스크립트 자신 보존 분류
        test_self = self._touch(self.ws, "proj/test_central_docs_collector.py")
        self.assertEqual(collector.classify_workspace_file(test_self, self.ws), ("ops-sec", "collector-script"))

        # backlog 내 비-MD 비-config 파일 -> None
        b_txt = self._touch(self.ws, "proj/backlog/notes.txt")
        self.assertIsNone(collector.classify_workspace_file(b_txt, self.ws))

        # adr 폴더
        adr_f = self._touch(self.ws, "proj/adr/0001-record.yaml")
        self.assertEqual(collector.classify_workspace_file(adr_f, self.ws), ("decision", "adr"))

        # .claude 하위 skills, settings.json, 기타 제외 파일
        c_skl = self._touch(self.ws, "proj/.claude/skills/s1/SKILL.md")
        c_set = self._touch(self.ws, "proj/.claude/settings.json")
        c_ign = self._touch(self.ws, "proj/.claude/unknown.bin")
        self.assertEqual(collector.classify_workspace_file(c_skl, self.ws), ("skill", "claude-skill"))
        self.assertEqual(collector.classify_workspace_file(c_set, self.ws), ("agent", "claude-setting"))
        self.assertIsNone(collector.classify_workspace_file(c_ign, self.ws))

        # .cursor/rules 및 .gemini 커스터마이징
        a_rul = self._touch(self.ws, "proj/.cursor/rules/r1.md")
        a_cus = self._touch(self.ws, "proj/.gemini/custom.json")
        self.assertEqual(collector.classify_workspace_file(a_rul, self.ws), ("agent", "agent-rule"))
        self.assertEqual(collector.classify_workspace_file(a_cus, self.ws), ("agent", "agent-customization"))

        # design 하위 비허용 확장자(.png), DESIGN_CONFIG_NAMES, .github 하위 기타 파일, 일반 소스코드(.py)
        d_png = self._touch(self.ws, "proj/design/logo.png")
        d_cfg = self._touch(self.ws, "proj/pyproject.toml")
        g_own = self._touch(self.ws, "proj/.github/CODEOWNERS")
        s_py = self._touch(self.ws, "proj/src/app.py")
        self.assertIsNone(collector.classify_workspace_file(d_png, self.ws))
        self.assertEqual(collector.classify_workspace_file(d_cfg, self.ws), ("design", "impl-convention"))
        self.assertIsNone(collector.classify_workspace_file(g_own, self.ws))
        self.assertIsNone(collector.classify_workspace_file(s_py, self.ws))

        # 형제 워크스페이스(github-gardenning) 자동 동반 스캔 검증
        sibling_ws = self.root / "github-gardenning"
        self._touch(sibling_ws, "README.md", "# Gardening")
        with mock.patch.object(collector, "DEFAULT_WORKSPACE_DIR", self.ws):
            scanned = collector.scan_workspace(self.ws)
        projects = {item[3] for item in scanned}
        self.assertIn("github-gardenning", projects)

    def test_global_scanners_all_branches(self) -> None:
        # 존재하지 않는 CLAUDE_HOME / GEMINI_HOME
        with mock.patch.object(collector, "CLAUDE_HOME", self.root / "no-claude"), \
             mock.patch.object(collector, "GEMINI_HOME", self.root / "no-gemini"):
            self.assertEqual(collector.scan_global_ai_dirs(), [])

        mock_claude = self.root / ".claude"
        mock_gemini = self.root / ".gemini"
        self._touch(mock_claude, "hooks-logs/standup/2026-10-29.md")
        self._touch(mock_claude, "hooks-logs/pipeline/p1.json", "{}")
        self._touch(mock_claude, "plans/plan-a.md")
        self._touch(mock_claude, "chub-content/claude-code/DOC.md")
        self._touch(mock_claude, "central-docs/project-old-CLAUDE.md")
        self._touch(mock_claude, "skills/my-skill/SKILL.md")
        self._touch(mock_claude, "skills/synced/bkt/scripts/helper.py")
        self._touch(mock_claude, "skills/.env", "SECRET=1")
        self._touch(mock_claude, "hooks/guard.py")
        self._touch(mock_claude, "hooks/test_guard.py")
        self._touch(mock_claude, "hooks/.env", "SECRET=1")

        self._touch(mock_gemini, "config/config.json", "{}")
        self._touch(mock_gemini, "antigravity-cli/settings.json", "{}")
        self._touch(mock_gemini, "antigravity-cli/brain/.hidden/skip.md")
        self._touch(mock_gemini, "antigravity-cli/brain/conv-1/PROMPT_SPEC.md")
        self._touch(mock_gemini, "antigravity-cli/brain/conv-1/PROMPT_SPEC.json", "{}")
        self._touch(mock_gemini, "antigravity-cli/brain/conv-1/ignore.txt")
        self._touch(mock_gemini, "antigravity-cli/skills/s1/SKILL.md")

        with mock.patch.object(collector, "CLAUDE_HOME", mock_claude), \
             mock.patch.object(collector, "GEMINI_HOME", mock_gemini):
            global_items = collector.scan_global_ai_dirs()

        subcats = {it[2] for it in global_items}
        self.assertIn("daily-standup-log", subcats)
        self.assertIn("hook-pipeline-log", subcats)
        self.assertIn("claude-plan", subcats)
        self.assertIn("claude-chub-doc", subcats)
        self.assertIn("legacy-project-claude-doc", subcats)
        self.assertIn("global-claude-skill", subcats)
        self.assertIn("global-claude-hook", subcats)
        self.assertIn("antigravity-config", subcats)
        self.assertIn("antigravity-settings", subcats)
        self.assertIn("antigravity-prompt-spec", subcats)
        self.assertIn("antigravity-prompt-meta", subcats)
        self.assertIn("antigravity-skill", subcats)

    def test_timestamp_normalizer_and_prompt_extractor_edge_cases(self) -> None:
        # _parse_timestamp 예외 분기
        self.assertEqual(collector._parse_timestamp(1e300, fallback_mtime=0.0), ("unknown", 0.0))
        ts_str, ts_val = collector._parse_timestamp("invalid-iso", fallback_mtime=1700000000.0)
        self.assertEqual(ts_val, 1700000000.0)
        self.assertNotEqual(ts_str, "unknown")

        # _normalize_project_label 분기
        self.assertEqual(collector._normalize_project_label(""), "unknown")
        self.assertEqual(collector._normalize_project_label(str(Path.home())), "~")
        self.assertEqual(collector._normalize_project_label(str(Path.home() / "my-ws")), "~/my-ws")

        # _extract_user_text_from_claude_message 비정상 타입 분기
        self.assertEqual(collector._extract_user_text_from_claude_message(None), "")
        self.assertEqual(collector._extract_user_text_from_claude_message({"content": 12345}), "")

        mock_claude = self.root / ".claude_edge"
        mock_gemini = self.root / ".gemini_edge"

        # 1) Claude projects 트랜스크립트: isMeta, 빈 텍스트, 중단 마커, Pasted placeholder, /tmp 경로, 동일 채널 1초 내 중복, 깨진 JSON
        proj_jf = self._touch(
            mock_claude,
            "projects/p1/s1.jsonl",
            "\n".join([
                "NOT_A_JSON_LINE",
                json.dumps({"type": "user", "isMeta": True, "message": {"content": "meta"}}),
                json.dumps({"type": "user", "message": {"content": "   "}}),
                json.dumps({"type": "user", "message": {"content": "[Request interrupted by user]"}}),
                json.dumps({"type": "user", "message": {"content": "[Pasted text #1 +15 lines]"}}),
                json.dumps({"type": "user", "cwd": "/tmp/ephemeral", "message": {"content": "tmp prompt"}}),
                json.dumps({"type": "user", "timestamp": 1700000100, "cwd": "/Users/test/proj", "sessionId": "s1", "message": {"content": "정상 프롬프트"}}),
                json.dumps({"type": "user", "timestamp": 1700000100.5, "cwd": "/Users/test/proj", "sessionId": "s1", "message": {"content": "정상 프롬프트"}}),
            ]),
        )
        self.assertTrue(proj_jf.is_file())

        # 2) Claude hook-session 로그
        (mock_claude / "hooks-logs/sessions/dir.jsonl").mkdir(parents=True, exist_ok=True)
        self._touch(
            mock_claude,
            "hooks-logs/sessions/hs1.jsonl",
            "\n".join([
                "BROKEN_JSON",
                json.dumps({"event": "session_start", "cwd": "/Users/test/hook-proj"}),
                json.dumps({"event": "prompt", "timestamp": 1700000200, "cwd": "/Users/test/hook-proj", "prompt": "훅 세션 프롬프트"}),
            ]),
        )

        # 3) Claude history.jsonl: 세션 내 [Pasted text #] 축약본 중복 제거 및 깨진 JSON
        self._touch(
            mock_claude,
            "history.jsonl",
            "\n".join([
                "BROKEN_JSON",
                json.dumps({"display": "앞부분 [Pasted text #1 +20 lines]", "timestamp": 1700000110, "project": "/Users/test/proj", "sessionId": "s1"}),
            ]),
        )

        # 4) Antigravity brain: 파일 노이즈, 로그 없는 폴더, Active Workspaces 추출, 비-USER_INPUT, 깨진 JSON
        self._touch(mock_gemini, "antigravity-cli/brain/not_a_dir.txt", "x")
        (mock_gemini / "antigravity-cli/brain/empty-conv").mkdir(parents=True, exist_ok=True)
        self._touch(
            mock_gemini,
            "antigravity-cli/brain/conv-ws/.system_generated/logs/transcript_full.jsonl",
            "\n".join([
                "BROKEN_JSON",
                json.dumps({"type": "SYSTEM", "content": "Active Workspaces:\n- /Users/test/agy-ws\n"}),
                json.dumps({"type": "USER_INPUT", "created_at": "2026-10-29T06:00:00Z", "content": "안티그래비티 워크스페이스 추론 프롬프트"}),
            ]),
        )
        self._touch(
            mock_gemini,
            "antigravity-cli/history.jsonl",
            "\n".join([
                "BROKEN_JSON",
                json.dumps({"display": "히스토리 단독 프롬프트", "timestamp": "2026-10-29T07:00:00Z", "workspace": "/Users/test/agy-ws", "conversationId": "conv-hist"}),
            ]),
        )

        with mock.patch.object(collector, "CLAUDE_HOME", mock_claude), \
             mock.patch.object(collector, "GEMINI_HOME", mock_gemini):
            recs = collector.extract_all_prompt_records()

        texts = [r.prompt_text for r in recs]
        self.assertEqual(texts.count("정상 프롬프트"), 1)
        self.assertIn("훅 세션 프롬프트", texts)
        self.assertIn("안티그래비티 워크스페이스 추론 프롬프트", texts)
        self.assertIn("히스토리 단독 프롬프트", texts)
        ws_rec = next(r for r in recs if r.prompt_text == "안티그래비티 워크스페이스 추론 프롬프트")
        self.assertEqual(ws_rec.project, "/Users/test/agy-ws")

    def test_cleanup_modes_collisions_and_empty_category_index(self) -> None:
        # 빈 파일(0바이트)은 스킵되어야 함
        self._touch(self.ws, "proj/empty.md", "")
        f1 = self._touch(self.ws, "proj/README.md", "# Readme 1")

        # 1) 이전 MANIFEST.json이 정상 존재할 때 정리 동작
        self.target.mkdir(parents=True, exist_ok=True)
        old_managed = self._touch(self.target, "design__old_file.md", "old")
        (self.target / "MANIFEST.json").write_text(
            json.dumps({"items": [{"flat_filename": "design__old_file.md"}]}),
            encoding="utf-8",
        )
        with mock.patch.object(collector, "CLAUDE_HOME", self.root / "none"), \
             mock.patch.object(collector, "GEMINI_HOME", self.root / "none"):
            collector.collect_all(self.ws, self.target, include_global=False, clean_all=False)
        self.assertFalse(old_managed.exists())

        # 2) MANIFEST.json이 손상되었을 때 접두사 기반 정리 동작
        orphan = self._touch(self.target, "decision__orphan.md", "orphan")
        (self.target / "MANIFEST.json").write_text("CORRUPT_JSON", encoding="utf-8")
        with mock.patch.object(collector, "CLAUDE_HOME", self.root / "none"), \
             mock.patch.object(collector, "GEMINI_HOME", self.root / "none"):
            collector.collect_all(self.ws, self.target, include_global=False, clean_all=False)
        self.assertFalse(orphan.exists())

        # 3) clean_all=True 동작 및 중복/깨진 후보·파일명 충돌 처리
        unmanaged = self._touch(self.target, "custom_note.txt", "custom")
        f2 = self._touch(self.ws, "proj/other.md", "# Other")
        missing_path = self.ws / "proj/missing.md"
        loop_a = self.ws / "proj/loop_a.md"
        loop_b = self.ws / "proj/loop_b.md"
        loop_a.symlink_to(loop_b)
        loop_b.symlink_to(loop_a)
        fake_candidates = [
            (f1, "design", "project-readme", "proj", "workspace", "proj/README.md"),
            (f1, "design", "project-readme", "proj", "workspace", "proj/README.md"),  # 동일 resolved 중복 스킵
            (f2, "design", "project-readme", "proj", "workspace", "proj/README.md"),  # 동일 flat_name 해시 충돌 해소
            (missing_path, "design", "project-readme", "proj", "workspace", "proj/missing.md"),
            (loop_a, "design", "project-readme", "proj", "workspace", "proj/loop_a.md"),  # OSError 유발
        ]
        with mock.patch.object(collector, "scan_workspace", return_value=fake_candidates):
            items, _, _, _ = collector.collect_all(self.ws, self.target, include_global=False, clean_all=True)
        self.assertFalse(unmanaged.exists())
        self.assertEqual(len(items), 2)
        self.assertTrue(any("__" in it.flat_filename for it in items))

    def test_keyword_search_self_tests_and_cli_main(self) -> None:
        # 1) MANIFEST.json 없을 때 키워드 검색
        collector.run_keyword_search(self.target, " PostgreSQL ")

        # 2) MANIFEST.json만 있고 프롬프트 데이터셋이 없을 때 검색
        self.target.mkdir(parents=True, exist_ok=True)
        manifest_path = self.target / "MANIFEST.json"
        manifest_path.write_text(
            json.dumps({
                "items": [{
                    "category": "decision",
                    "subcategory": "backlog-decision",
                    "project": "my-proj",
                    "flat_filename": "decision__my-proj__db.md",
                    "source_path": "/repo/my-proj/db.md",
                }]
            }),
            encoding="utf-8",
        )
        collector.run_keyword_search(self.target, "db")

        # 3) 프롬프트 데이터셋(21건 이상 + 깨진 라인 포함)이 있을 때 검색
        dataset_path = self.target / "prompt__EXTRACTED__ALL_PROMPTS_DATASET.jsonl"
        lines = ["BROKEN_LINE"] + [
            json.dumps({
                "timestamp_iso": f"2026-10-29 10:00:{i:02d}",
                "tool": "Claude Code",
                "project": "~/my-proj",
                "session_id": f"sess-{i}",
                "source_path": "/path/hist.jsonl",
                "prompt_text": f"검색키워드 프롬프트 {i} " + ("길고긴텍스트" * 30),
            }, ensure_ascii=False)
            for i in range(22)
        ]
        dataset_path.write_text("\n".join(lines), encoding="utf-8")
        collector.run_keyword_search(self.target, "검색키워드")

        # 4) run_self_tests: verbose=True, verbose=False (성공/실패), 테스트 파일 미존재
        with mock.patch.object(collector.Path, "is_file", return_value=False):
            collector.run_self_tests(verbose=False)

        mock_ok = mock.MagicMock(returncode=0, stdout="OK", stderr="")
        mock_fail = mock.MagicMock(returncode=1, stdout="", stderr="FAIL")
        with mock.patch.object(collector.subprocess, "run", return_value=mock_ok):
            collector.run_self_tests(verbose=False)
            with self.assertRaises(SystemExit) as cm_v:
                collector.run_self_tests(verbose=True)
            self.assertEqual(cm_v.exception.code, 0)

        with mock.patch.object(collector.subprocess, "run", return_value=mock_fail):
            with self.assertRaises(SystemExit) as cm_f:
                collector.run_self_tests(verbose=False)
            self.assertEqual(cm_f.exception.code, 1)

        # 5) main() CLI 진입점: --test, --find, 기본 수집 모드
        self._touch(self.ws, "proj/README.md", "# Hello")
        with mock.patch.object(sys, "argv", ["prog", "--test"]), \
             mock.patch.object(collector, "run_self_tests", side_effect=SystemExit(0)):
            with self.assertRaises(SystemExit):
                collector.main()

        with mock.patch.object(sys, "argv", ["prog", "-w", str(self.ws), "-t", str(self.target), "-f", "db"]):
            collector.main()

        with mock.patch.object(sys, "argv", ["prog", "-w", str(self.ws), "-t", str(self.target)]), \
             mock.patch.object(collector, "run_self_tests"), \
             mock.patch.object(collector, "CLAUDE_HOME", self.root / "no-claude"), \
             mock.patch.object(collector, "GEMINI_HOME", self.root / "no-gemini"):
            collector.main()


if __name__ == "__main__":
    unittest.main()


# ======== 노트 ========
# 1 하이픈 이름 모듈의 동적 로드
#   설명: 대상 파일명이 central-docs-collector.py라 일반 import가 안 된다. importlib으로 경로에서 직접 로드해
#   설명: collector라는 이름으로 쓴다. 테스트가 수집기 안의 상수와 함수를 직접 참조하는 진입점이다.
#   관련: central-docs-collector.py
# 2 시크릿 차단 회귀 테스트
#   설명: .env, 토큰, 인증서, DB 캐시 등 수집하면 안 되는 파일 목록이 계속 차단되는지 확인한다.
#   설명: 수집기의 시크릿 차단 불변식을 지키는 핵심 테스트이므로 목록을 줄이지 않는다.
#   관련: central-docs-collector.py의 is_secret_or_blocked()
#   개념: 불변식, 회귀 테스트
# 3 홈 디렉터리 모의 치환
#   설명: CLAUDE_HOME과 GEMINI_HOME을 임시 폴더로 바꿔 끼워, 실제 ~/.claude와 ~/.gemini를 읽거나 건드리지 않고
#   설명: 전체 수집 파이프라인(collect_all)을 끝까지 검증한다.
#   개념: 모킹(mock.patch.object), 격리
# 4 위험한 타겟 폴더 거부
#   설명: 타겟이 워크스페이스 자체·상위(홈 포함)·하위일 때 ValueError가 나는지 확인한다.
#   설명: 이 가드가 없으면 수집 전 정리 단계가 원본을 지울 수 있다.
#   관련: central-docs-collector.py의 _validate_target_dir()
