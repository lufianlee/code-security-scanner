# Code Security Scanner

코드 보안 취약점을 스캔하고 분석하는 웹 애플리케이션입니다.
간단한 점검 및 AWS 배드락의 프롬프트 성능 테스트용으로 개발된 어플리케이션이기때문에, 
최소 수준의 기능만 있는 점을 참고하여 사용해주세요.

## 기능

- 코드 보안 취약점 스캔
- 취약점 분석 및 보고서 생성
- 실시간 스캔 결과 모니터링

## 시스템 요구사항

- Docker
- Docker Compose
- Node.js 18 이상 (개발 환경)

## 설치 방법

1. 저장소 클론
```bash
git clone https://github.com/yourusername/code-security-scanner.git
cd code-security-scanner
```

2. 환경 변수 설정
```bash
cp backend/.env.example backend/.env
cp frontend/.env.example frontend/.env
```

3. Docker Compose로 실행
```bash
docker-compose up -d
```

## 개발 환경 설정

### Backend 설정
```bash
cd backend
npm install
npm run dev
```

### Frontend 설정
```bash
cd frontend
npm install
npm run dev
```

## 사용 방법

1. 웹 브라우저에서 `http://localhost:3000` 접속
2. 스캔하고자 하는 코드를 입력하거나 파일을 업로드
3. 스캔 시작 버튼 클릭
4. 스캔 결과 확인 및 분석

## API 문서

API 문서는 서버 실행 후 다음 URL에서 확인할 수 있습니다:
- Swagger UI: `http://localhost:8000/api-docs`

## 라이선스

이 프로젝트는 MIT 라이선스 하에 배포됩니다. 자세한 내용은 [LICENSE](LICENSE) 파일을 참조하세요. 