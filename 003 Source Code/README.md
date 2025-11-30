📝 🔐 Zero Trust 기반 디바이스 인증 시스템
(A Study on the Design & Implementation of Zero Trust Device Authentication)
(산학협력 캡스톤 디자인 프로젝트)
⚠️ 프로젝트 주의사항

본 프로젝트는 산학협력 캡스톤 프로젝트로서 다음의 보안·윤리 요구사항을 준수합니다.

🔒 오픈소스 SW 라이선스 준수

본 프로젝트에 포함된 모든 오픈소스 라이브러리의 라이선스는 하단 Open Source Licenses 섹션에 명시하였습니다.

🛡 기밀 데이터 보호

API Key, 내부 문서, 사용자 정보 등 모든 민감 정보는 저장소에 포함하지 않습니다.

만약 기밀정보가 외부(GitHub 등)에 노출될 경우, 해당 정보를 업로드한 사용자에게 책임이 있음을 인지합니다.

📢 연구 기반 고지

본 구현은 연구 논문
《제로 트러스트 기반 디바이스 인증 체계의 설계 및 구현에 관한 연구》
파일 내용에 기반하여 개발되었습니다.

🛠 설치 및 실행 (Installation & Usage)
1️⃣ 가상환경 생성 및 활성화
python -m venv venv
.\venv\Scripts\Activate.ps1     # Windows PowerShell

2️⃣ 패키지 의존성 설치
pip install -r requirements.txt

3️⃣ 프로그램 실행
cd server
python app.py

📄 Open Source Licenses 
Package	Version Rule	License
fastapi	>=0.110	MIT License
uvicorn[standard]	>=0.29	BSD License
pymongo	>=4.6	Apache License 2.0
dnspython	>=2.6	ISC License
python-dotenv	>=1.0	BSD License
argon2-cffi	>=23.1.0	MIT License
itsdangerous	>=2.1.2	BSD License
email-validator	>=2.2	Apache License 2.0
pyotp	==2.9.0	MIT License
python-multipart	>=0.0.6	Apache License 2.0