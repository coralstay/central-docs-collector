# central-docs-collector

소프트웨어 구현·설계·운영·보안 관점의 모든 결정사항(MD 및 비-MD 설정 파일)과 AI 에이전트(Claude, Antigravity, Gemini)의 지침·스킬·커맨드·훅·프롬프트 기록을 중앙 폴더(`~/central-docs`)에 평탄(flat)하게 수집하고 통합 인덱스(`INDEX.md`, `MANIFEST.json`)를 생성하는 CLI 도구입니다.

## 빠른 실행

```bash
# 전체 수집 실행 (사전 단위 테스트 자동 수행)
python3 ./central-docs-collector.py

# 단위 및 통합 테스트만 단독 실행
python3 ./central-docs-collector.py --test

# 키워드 검색 (수집된 문서 + 프롬프트 본문 통합 검색)
python3 ./central-docs-collector.py -f "eBPF"
```

## 라이선스

[GNU AGPL-3.0-only](./LICENSE)
