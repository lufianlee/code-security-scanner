# Code Security Scanner

코드 보안 취약점을 스캔하고 분석하는 웹 애플리케이션입니다.
간단한 점검 및 AWS Bedrock의 프롬프트 성능 테스트용으로 개발된 어플리케이션이기 때문에,
최소 수준의 기능만 있는 점을 참고하여 사용해주세요.

## 기능

- GitHub / Bitbucket 저장소 클론 후 코드 보안 취약점 스캔 (Private 저장소는 PAT 지원)
- AWS Bedrock의 최신 Claude 모델(`anthropic.claude-sonnet-5`)을 이용한 취약점 분석
- SSE(Server-Sent Events) 기반 실시간 스캔 진행 상황 모니터링

## 아키텍처

- **Backend**: FastAPI (Python 3.11) + Anthropic SDK (Bedrock)
- **Frontend**: Next.js 15 + React 19 + Tailwind CSS

## 시스템 요구사항

- Docker / Docker Compose (권장)
- 또는 로컬 개발 환경: Python 3.11 이상, Node.js 20 이상
- Bedrock 모델 접근이 허용된 AWS 자격 증명

## 설치 방법

1. 저장소 클론
```bash
git clone https://github.com/lufianlee/code-security-scanner.git
cd code-security-scanner
```

2. 환경 변수 설정
```bash
cp backend/.env.example backend/.env
cp frontend/.env.example frontend/.env
# backend/.env 파일에 AWS 리전 및 자격 증명을 입력하세요
```

3. Docker Compose로 실행
```bash
docker compose up -d --build
```

## 개발 환경 설정

### Backend
```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload
```

### Frontend
```bash
cd frontend
npm install
npm run dev
```

## 사용 방법

1. 웹 브라우저에서 `http://localhost:3000` 접속
2. 스캔할 GitHub/Bitbucket 저장소 URL 입력 (Private 저장소는 Personal Access Token 추가 입력)
3. Start Scan 버튼 클릭
4. 파일별 스캔 결과를 실시간으로 확인

## 환경 변수

### Backend (`backend/.env`)

| 변수 | 필수 | 설명 |
| --- | --- | --- |
| `AWS_REGION_NAME` | ✅ | Bedrock을 사용할 AWS 리전 (예: `us-east-1`) |
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` | ❌ | 미설정 시 기본 AWS 자격 증명 체인(IAM 역할 등) 사용 |
| `BEDROCK_MODEL_ID` | ❌ | 기본값 `anthropic.claude-sonnet-5` |
| `ALLOWED_ORIGINS` | ❌ | CORS 허용 오리진 (쉼표 구분, 기본값 `http://localhost:3000`) |
| `MAX_FILE_SIZE_BYTES` | ❌ | 분석 대상 파일 최대 크기 (기본값 200KB) |

### Frontend (`frontend/.env`)

| 변수 | 필수 | 설명 |
| --- | --- | --- |
| `NEXT_PUBLIC_API_URL` | ❌ | 백엔드 API URL (기본값 `http://localhost:8000`) |

## API 문서

서버 실행 후 다음 URL에서 확인할 수 있습니다:
- Swagger UI: `http://localhost:8000/docs`
- 헬스 체크: `http://localhost:8000/health`

## 라이선스

이 프로젝트는 MIT 라이선스 하에 배포됩니다. 자세한 내용은 [LICENSE](LICENSE) 파일을 참조하세요.
