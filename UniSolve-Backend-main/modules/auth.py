import jwt
from flask import jsonify
from config import SECRET_KEY


# JWT 토큰을 추출하여 
# UserID를 반환하거나 에러를 반환합니다.
# user_id, error_response, status_code 를 받환합니다.
def get_user_id_from_token(request):
    """Authorization 헤더에서 JWT 토큰을 추출하고 디코딩하여 사용자 ID를 반환"""
    try:
        token = request.headers.get("Authorization")
        if not token:
            return None, jsonify({"error": "Authorization token is missing!"}), 401

        if token.startswith("Bearer "):
            token = token.split(" ")[1]

        decoded_token = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        user_id = decoded_token.get("user_id")
        if not user_id:
            return None, jsonify({"error": "User ID not found in the token!"}), 400
        """
        # 사용자 정보 확인 (username이 '탈퇴한 사용자'인 경우 에러 반환)
        with connection.cursor(dictionary=True) as cursor:
            query = "SELECT username FROM users WHERE user_id = %s"
            cursor.execute(query, (user_id,))
            user_data = cursor.fetchone()

        if user_data and user_data["username"] == "탈퇴한 사용자":
            return None, jsonify({"error": "User has been deleted!"}), 403
        """
        return user_id, None, None

    except jwt.ExpiredSignatureError:
        return None, jsonify({"error": "Token has expired!"}), 401
    except jwt.InvalidTokenError:
        return None, jsonify({"error": "Invalid token!"}), 401

