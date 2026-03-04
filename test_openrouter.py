import os
import requests
from dotenv import load_dotenv

# .env 로드
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

# .env에서 테스트할 모델 가져오기
MODELS = [m for m in [os.getenv("MODEL_A", ""), os.getenv("MODEL_B", "")] if m]

def test_model(model_name: str):
    print(f"\n🚀 모델 테스트 중: {model_name}")
    
    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json",
    }
    
    payload = {
        "model": model_name,
        "messages": [
            {"role": "user", "content": "안녕? 넌 누구야?"}
        ],
        "max_tokens": 100
    }
    
    try:
        response = requests.post(OPENROUTER_URL, headers=headers, json=payload, timeout=20)
        
        if response.status_code == 200:
            data = response.json()
            content = data["choices"][0]["message"]["content"]
            print(f"✅ 성공! 모델 응답: {content.strip()}")
        else:
            print(f"❌ 실패! 상태 코드: {response.status_code}")
            print(f"에러 내용: {response.text}")
            
    except Exception as e:
        print(f"❌ 예외 발생: {e}")

if __name__ == "__main__":
    if not OPENROUTER_API_KEY:
        print("❌ 오류: .env 파일에 OPENROUTER_API_KEY가 설정되지 않았습니다.")
    else:
        for model in MODELS:
            test_model(model)
