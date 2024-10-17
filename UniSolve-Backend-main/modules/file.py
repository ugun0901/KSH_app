import base64
import requests
from io import BytesIO

from config import IMAGE_SAVER_BASEURL


# 이미지를 받아서 다른 서버로 전송하는 함수
def send_image_to_upload_service(image_file, file_name):
    url = f"{IMAGE_SAVER_BASEURL}/upload"
    files = {"file": (file_name, image_file)}

    try:
        response = requests.post(url, files=files)

        # 서버가 응답했지만 400 이상의 상태 코드를 반환한 경우 처리
        if response.status_code >= 400:
            return {
                "error": "Failed to upload image",
                "status_code": response.status_code,
            }

        return response.json()  # 응답 JSON 데이터 반환
    except requests.RequestException as e:
        return {"error": str(e), "status_code": None}


# Base64 이미지를 디코딩하고 전송하는 함수
def send_base64_image_to_service(base64_data, title):
    try:
        image_data = base64.b64decode(
            base64_data.split(",")[1]
        )  # Base64 데이터에서 헤더 제거
        file_name = f"image_{title}.jpg"
        image_file = BytesIO(image_data)  # 메모리 내에서 이미지 파일 객체 생성
        return send_image_to_upload_service(image_file, file_name)
    except Exception as e:
        return {"error": "Invalid Base64 data", "details": str(e)}
