import base64
from io import BytesIO
from flask import Flask, request, jsonify
from flask_cors import CORS
import bcrypt
import jwt
import datetime
import pytz
import mysql.connector
from mysql.connector import Error
from modules.auth import get_user_id_from_token
from config import SECRET_KEY
from functools import wraps
import requests
from modules.file import send_image_to_upload_service, send_base64_image_to_service
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import random


# Flask 애플리케이션 초기화
app = Flask(__name__)
CORS(app)

# MySQL 데이터베이스 설정
db_config = {
    "host": "119.203.117.3",
    "user": "unisolve",
    "password": "1234**",
    "database": "unisolve",
}


# MySQL 연결 함수 (연결을 설정하거나 재연결 시도)
def get_db_connection():
    try:
        # 데이터베이스 연결
        connection = mysql.connector.connect(**db_config)
        if connection.is_connected():
            print("Successfully connected to the database")
        return connection
    except mysql.connector.Error as err:
        print(f"Error: {err}")
        return None


# 각 요청마다 새로운 커넥션을 열고 닫기
def use_db_connection(func):
    @wraps(func)  # 원래의 함수 이름을 사용하여 중복으로 인식안되도록 처리
    def wrapper(*args, **kwargs):
        connection = get_db_connection()  # db 연결

        # 연결이 안될 때
        if connection is None:
            return jsonify({"error": "Database connection error"}), 500

        try:
            # 연결된 connection으로 함수 실행
            result = func(connection, *args, **kwargs)
        finally:
            # 커넥션 닫기
            connection.close()
        return result

    return wrapper


# 로그인 처리 엔드포인트
@app.route("/login", methods=["POST"])
@use_db_connection
def login(connection):
    try:

        # 클라이언트에서 전달받은 JSON 데이터
        data = request.json
        user_id = data.get("user_id")  # 사용자 ID
        password = data.get("password")  # 비밀번호

        # 입력값 유효성 검사
        if not user_id or not password:
            return jsonify(
                {"status": "error", "message": "User ID and password are required!"}
            )

        # 데이터베이스 커서 생성 (딕셔너리 형태로 결과 반환)
        with connection.cursor(dictionary=True) as cursor:
            # 사용자가 입력한 ID로 DB에서 비밀번호 조회
            sql = "SELECT user_pw FROM users WHERE user_id = %s"
            cursor.execute(sql, (user_id,))
            result = cursor.fetchone()

        # 해당 ID가 존재하지 않는 경우
        if not result:
            return jsonify({"status": "error", "message": "User ID not found!"})

        # 데이터베이스에서 가져온 해시된 비밀번호와 입력된 비밀번호 비교
        hashed_pw = result["user_pw"]
        if bcrypt.checkpw(password.encode("utf-8"), hashed_pw.encode("utf-8")):
            # JWT 토큰 생성
            token = jwt.encode(
                {
                    "user_id": user_id,
                    "exp": datetime.datetime.now(pytz.UTC)
                    + datetime.timedelta(hours=24),
                },
                SECRET_KEY,
                algorithm="HS256",
            )
            return jsonify({"message": "Login successful", "token": token}), 200
        else:
            return jsonify({"status": "error", "message": "Incorrect password!"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})


verification_codes = {}


def generate_verification_code():
    return "".join(random.choices("0123456789", k=7))


@app.route("/send-code", methods=["POST"], endpoint="send_code")
def send_code():
    data = request.get_json()
    email = data["email"]
    code = generate_verification_code()

    verification_codes[email] = code

    msg = MIMEText(f"아래의 인증번호를 정확히 입력해주세요.\n {code}")
    msg["Subject"] = "UniSolve 회원가입을 위한 이메일 인증번호입니다."
    msg["From"] = "unisolve7@naver.com"
    msg["To"] = email

    try:
        with smtplib.SMTP_SSL("smtp.naver.com", 465) as server:
            server.login("unisolve7", "UNiSolve11!")
            server.sendmail("unisolve7@naver.com", email, msg.as_string())

        return jsonify({"isSent": True}), 200
    except Exception as e:
        return jsonify({"isSent": False, "error": str(e)}), 500


@app.route("/verify-code", methods=["POST"], endpoint="verify_code")
def verify_code():
    data = request.get_json()
    email = data["email"]
    received_code = data["code"]

    if email in verification_codes and verification_codes[email] == received_code:
        return jsonify({"isVerified": True}), 200
    else:
        return jsonify({"isVerified": False}), 400


# 회원가입 처리 엔드포인트
@app.route("/register", methods=["POST"])
@use_db_connection
def register(connection):
    try:
        # 클라이언트에서 전달받은 JSON 데이터
        data = request.json
        user_id = data.get("user_id")
        username = data.get("username")
        email = data.get("email")
        password = data.get("password")
        user_nickname = data.get("user_nickname", None)
        school = data.get("school")

        # 필수 입력값이 비어 있는지 확인
        if not user_id or not username or not email or not password:
            return jsonify({"status": "error", "message": "All fields are required!"})

        # 데이터베이스 커서 생성
        with connection.cursor(dictionary=True) as cursor:
            # 1. ID 중복 여부 확인
            check_user_sql = "SELECT user_id FROM users WHERE user_id = %s"
            cursor.execute(check_user_sql, (user_id,))
            existing_user = cursor.fetchone()

            # 중복된 user_id가 있을 경우
            if existing_user:
                return jsonify(
                    {"status": "error", "message": "User ID already exists!"}
                )

            # 2. 비밀번호 해싱
            hashed_pw = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

            # 3. 회원 정보 데이터베이스에 삽입
            insert_user_sql = """
            INSERT INTO users (user_id, username, email, user_pw, user_nickname, school)
            VALUES (%s, %s, %s, %s, %s, %s)
            """
            cursor.execute(
                insert_user_sql,
                (
                    user_id,
                    username,
                    email,
                    hashed_pw.decode("utf-8"),
                    user_nickname,
                    school,
                ),
            )

        # 4. 커밋하여 변경 사항 저장
        connection.commit()

        # 성공적으로 등록된 경우
        return jsonify(
            {"status": "success", "message": "User registered successfully!"}
        )

    except Exception as e:
        # 예외 발생 시 에러 메시지 반환
        return jsonify({"status": "error", "message": str(e)}), 500


"""
# 질문 데이터 조회 (전체 또는 특정 사용자)
@app.route("/questions", methods=["GET"])
@use_db_connection
def get_questions(connection):
    user = request.args.get("user")
    conn = connection
    cursor = conn.cursor(dictionary=True)


    # 특정 사용자의 질문 조회 (쿼리 파라미터로 전달된 경우)
    if user:
        cursor.execute("SELECT * FROM problem WHERE created_by = %s", (user,))
    else:
        cursor.execute("SELECT * FROM problem")

    result = cursor.fetchall()
    cursor.close()
    return jsonify(result)
"""


# 질문 데이터 삽입
@app.route("/questions", methods=["POST"])
@use_db_connection
def add_question(connection):
    is_private = request.form.get("is_private")
    title = request.form.get("title")
    content = request.form.get("content")
    created_time = datetime.datetime.now()
    reply = 0

    # =========== 이미지 저장하고 url 받아오기 ===========
    # 이미지 파일 받기
    file = request.files.get("image")  # 앱에서 파일로 받은 이미지
    img_base64 = request.form.get("image")  # 웹에서 Base64로 받은 이미지

    response = None
    if file:
        # 네이티브 앱에서 전송된 파일 처리 (이미지 바로 전송)
        print("File received from native app")
        file_name = file.filename
        response = send_image_to_upload_service(file.stream, file_name)
    elif img_base64:
        # 웹에서 Base64 이미지 처리 (이미지 바로 전송)
        print("Base64 Image received from web")
        response = send_base64_image_to_service(img_base64, title)

    # 이미지 전송 결과 확인 및 URL 저장
    image_url = None
    if response and response.get("error"):
        return (
            jsonify(
                {
                    "error": "Failed to upload image",
                    "details": response.get("error"),
                    "status_code": response.get("status_code"),
                }
            ),
            400,
        )
    elif response and response.get("url"):
        image_url = response.get("url")  # 이미지 URL을 저장
        # 이미지가 성공적으로 업로드되었음을 알림
        print(f"Image uploaded successfully. Response: {response}")

    # =========== 받아온 이미지 url 과 함께 db에 저장하기 ===========
    try:
        # 모듈화된 함수로부터 user_id 추출
        user_id, error_response, status_code = get_user_id_from_token(request)
        if error_response:
            return error_response, status_code

        # 데이터베이스에 질문 삽입
        with connection.cursor() as cursor:
            cursor.execute(
                "INSERT INTO post (is_private, author_id, title, content, created_at, reply, image)"
                "VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (is_private, user_id, title, content, created_time, reply, image_url),
            )

            # 마지막으로 삽입된 ID를 가져옴
            post_id = cursor.lastrowid

        connection.commit()

        return (
            jsonify({"message": "Question added successfully!", "postId": post_id}),
            201,
        )
    except Exception as e:
        return jsonify({"error": "Failed to insert question", "details": str(e)}), 500


"""
# 특정 질문 수정 (공개 여부, 제목, 내용 수정)
@app.route("/questions/<int:id>", methods=["PUT"])
@use_db_connection
def update_question(connection, id):
    update_data = request.json
    is_public = update_data.get("is_public")
    title = update_data.get("title")
    content = update_data.get("content")


    conn = connection
    cursor = connection.cursor()
    cursor.execute(
        "UPDATE problem SET is_public = %s, title = %s, description = %s WHERE problem_id = %s",
        (is_public, title, content, id),
    )
    conn.commit()
    cursor.close()

    return jsonify({"message": "Question updated successfully!"})
"""

"""
# 특정 질문 삭제
@app.route("/questions/<int:id>", methods=["DELETE"])
@use_db_connection
def delete_question(id, connection):

    conn = connection
    cursor = connection.cursor()
    cursor.execute("DELETE FROM problem WHERE problem_id = %s", (id,))
    conn.commit()
    cursor.close()

    return jsonify({"message": "Question deleted successfully!"})
"""

'''
# 질문 기록을 데이터베이스에 추가하는 라우트
@app.route("/add_history", methods=["POST"])
@use_db_connection
def add_history(connection):
    # 요청으로부터 데이터 수신
    histories = request.json  # `histories`는 배열 형태의 데이터가 들어온다고 가정
    conn = connection
    cursor = connection.cursor()


    # 각 데이터를 `problem_history` 테이블에 삽입
    for history in histories:
        id = history.get("id")
        is_private = history.get("private")
        user = history.get("user")
        title = history.get("title")
        description = history.get("description")
        timestamp = (
            datetime.datetime.strptime(history.get("timestamp"), "%Y.%m.%d %H:%M")
            if "timestamp" in history
            else datetime.datetime.now()
        )
        reply_count = history.get("reply", 0)

        cursor.execute(
            """
            INSERT INTO problem_history (history_id, is_private, user_id, title, description, solved_at, reply_count)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
            (id, is_private, user, title, description, timestamp, reply_count),
        )

    conn.commit()
    cursor.close()

    return jsonify({"message": "Histories added successfully!"}), 201
'''


# /history 경로에 GET 요청을 처리하여 데이터 저장
@app.route("/history", methods=["GET"])
@use_db_connection
def get_history(connection):
    try:

        # 모듈화된 함수로부터 user_id 추출
        user_id, error_response, status_code = get_user_id_from_token(request)
        if error_response:
            return error_response, status_code

        # 데이터베이스에 데이터 조회를 위한 커서 생성
        with connection.cursor(dictionary=True) as cursor:
            # SELECT 쿼리: 특정 사용자의 `problem_history` 조회
            query = """
                SELECT *
                FROM post
                WHERE author_id = %s
            """
            cursor.execute(query, (user_id,))
            result = cursor.fetchall()

        if not result:
            return jsonify([])  # 빈 리스트 반환

        # 데이터 형식 맞추기
        response = []
        for row in result:
            response.append(
                {
                    "id": row["post_id"],
                    "user": row["author_id"],
                    "timestamp": row["created_at"].strftime("%Y.%m.%d %H:%M"),
                    "private": True if row["is_private"] == 1 else False,
                    "reply": row["reply"],
                    "description": row["content"],
                    "title": row["title"],
                }
            )

        return (
            jsonify({"message": "Data retrieved successfully", "data": response}),
            200,
        )

    except Error as e:
        print(e)
        return jsonify({"error": str(e)}), 500


# 게시글 목록을 가져오는 API 엔드포인트
@app.route("/community", methods=["GET"])
@use_db_connection
def get_community(connection):
    try:

        with connection.cursor(dictionary=True) as cursor:
            cursor.execute("SELECT * FROM post Where is_private=0")
            rows = cursor.fetchall()

        if not rows:
            return jsonify([])

        response = []
        for row in rows:
            response.append(
                {
                    "id": row["post_id"],
                    "questioner": row["author_id"],
                    "title": row["title"],
                    "description": row["content"],
                    "timestamp": row["created_at"].strftime("%Y.%m.%d %H:%M"),
                    "reply": row["reply_count"] if "reply_count" in row else 0,
                }
            )

        return jsonify(response)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})


'''
# 게시글 작성 API 엔드포인트
@app.route("/add_post", methods=["POST"])
@use_db_connection
def add_post(connection):
    try:
        data = request.json
        title = data.get("title")
        content = data.get("content")
        is_private = data.get("isPrivate")
        image = data.get("image")
        author_id = "닉네임"  # 예시로 작성자를 고정값으로 설정. 실제 작성자 ID를 받아올 수 있도록 수정 가능


        # 데이터베이스 커서 생성
        cursor = connection.cursor()

        # 게시글 삽입 쿼리
        sql = """
        INSERT INTO post (title, content, is_private, image, author_id)
        VALUES (%s, %s, %s, %s, %s)
        """
        cursor.execute(sql, (title, content, is_private, image, author_id))
        connection.commit()

        return jsonify({"status": "success", "message": "Post added successfully!"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})
'''

'''
# 알림 추가 API 엔드포인트
@app.route("/add_notification", methods=["POST"])
@use_db_connection
def add_notification(connection):
    try:
        # 클라이언트에서 전달받은 JSON 데이터
        data = request.json
        user_id = data.get("user_id")  # 사용자 ID
        title = data.get("title")  # 알림 제목
        is_private = data.get("isPrivate", False)  # 공개 여부 (기본값: False)
        description = data.get("description")  # 알림 설명
        is_read = data.get("isRead", False)  # 읽음 여부 (기본값: False)


        # 데이터베이스 커서 생성
        cursor = connection.cursor()

        # 알림 삽입 쿼리
        sql = """
        INSERT INTO notification (user_id, title, is_private, description, is_read)
        VALUES (%s, %s, %s, %s, %s)
        """
        cursor.execute(sql, (user_id, title, is_private, description, is_read))
        connection.commit()

        return jsonify(
            {"status": "success", "message": "Notification added successfully!"}
        )
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})
'''

"""
# 알림 리스트 가져오기 엔드포인트
@app.route("/notification", methods=["GET"])
@use_db_connection
def get_notifications(connection):
    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            "SELECT notification_id AS id, user_id, title, description, created_at AS timestamp, is_read AS `check`, is_private, TIMESTAMPDIFF(MINUTE, created_at, NOW()) AS timebefore FROM notification"
        )
        rows = cursor.fetchall()

        for row in rows:
            row["timebefore"] = f"{row['timebefore']}분 전"  # 시간차이를 표시
            row["timestamp"] = row["timestamp"].strftime("%Y.%m.%d %H:%M")
            row["type"] = 1 if row["is_private"] else 0  # type 변환

        return jsonify(rows)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})
"""


# 특정 게시글 보기 엔드포인트
@app.route("/post/<int:post_id>", methods=["GET"])
@use_db_connection
def get_post(connection, post_id):
    try:
        with connection.cursor(dictionary=True) as cursor:
            # 게시글 정보 가져오기
            cursor.execute(
                """
                SELECT post_id AS id, title, content AS description, author_id, created_at AS timestamp, 
                is_private, image 
                FROM post 
                WHERE post_id = %s
                """,
                (post_id,),
            )
            post = cursor.fetchone()

            # 게시글이 존재하지 않는 경우
            if not post:
                return jsonify({"status": "error", "message": "Post not found"}), 404

            # 비공개 게시글일 경우 작성자인지 확인
            if post["is_private"] == 1:
                author_id = post["author_id"]
                # 모듈화된 함수로부터 user_id 추출
                user_id, error_response, status_code = get_user_id_from_token(request)
                if error_response:
                    return error_response, status_code
                # 작성자가 아닐 경우 접근 금지
                if user_id != author_id:
                    return jsonify({"error": "Access forbidden"}), 403

            # 댓글 및 대댓글 정보 가져오기
            cursor.execute(
                """
                SELECT comment_id, content, author_id, created_at, parent_id
                FROM comment
                WHERE post_id = %s
                ORDER BY created_at ASC
                """,
                (post_id,),
            )
            comments_data = cursor.fetchall()

        # 댓글과 대댓글을 구조화
        comments = []
        comment_map = {}
        comment_count = 0  # 정상적인 댓글 및 대댓글 수

        for comment in comments_data:
            comment["created_at"] = comment["created_at"].strftime("%Y.%m.%d %H:%M")
            comment["replies"] = []

            if comment["parent_id"] is None:
                # 댓글 (대댓글이 아닌 경우)
                comments.append(comment)
                comment_map[comment["comment_id"]] = comment
                comment_count += 1  # 댓글 카운트 증가
            else:
                # 대댓글 처리
                parent_comment = comment_map.get(comment["parent_id"])
                if parent_comment and not comment_map.get(comment["comment_id"]):
                    # 대댓글에 또 다른 대댓글이 없는 경우만 처리
                    parent_comment["replies"].append(comment)
                    comment_count += 1  # 대댓글 카운트 증가

        # 게시글 정보에 댓글 포함 및 댓글 수 추가
        post["timestamp"] = post["timestamp"].strftime("%Y.%m.%d %H:%M")
        post["comments"] = comments
        post["comments_count"] = comment_count  # 정상적인 댓글 및 대댓글 수

        return jsonify(post), 200

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# 개인정보 페이지에서 사용할 유저 정보 가져오기
@app.route("/userinfo", methods=["GET"])
@use_db_connection
def get_userinfo(connection):
    try:
        # 모듈화된 함수로부터 user_id 추출
        user_id, error_response, status_code = get_user_id_from_token(request)
        if error_response:
            return error_response, status_code

        # 데이터베이스에 데이터 조회를 위한 커서 생성
        with connection.cursor(dictionary=True) as cursor:
            # SELECT 쿼리: 특정 사용자의 `problem_history` 조회
            query = """
                SELECT username, email, user_nickname, school, major, profile_picture, role, created_at
                FROM users
                WHERE user_id = %s
            """
            cursor.execute(query, (user_id,))
            result = cursor.fetchall()

        if not result:
            return jsonify([])  # 빈 리스트 반환

        # 데이터 형식 맞추기
        response = []
        for row in result:
            response.append(
                {
                    "username": row["username"],
                    "email": row["email"],
                    "user_nickname": row["user_nickname"],
                    "school": row["school"],
                    "major": row["major"],
                    "profile_picture": row["profile_picture"],
                    "role": row["role"],
                    "created_at": row["created_at"],
                }
            )

        return (
            jsonify({"message": "Data retrieved successfully", "data": response[0]}),
            200,
        )

    except Error as e:
        print(e)
        return jsonify({"error": str(e)}), 500

# 회원 탈퇴(회원 정보 삭제)
@app.route("/delete_user", methods=["DELETE"])
@use_db_connection
def delete_user(connection):
    try:
        # 토큰에서 user_id 추출
        user_id, error_response, status_code = get_user_id_from_token(request)
        if error_response:
            return error_response, status_code

        # 데이터베이스에 사용자 정보 삭제를 위한 커서 생성
        with connection.cursor(dictionary=True) as cursor:
            
            query = "SELECT is_deleted FROM users WHERE user_id = %s"
            cursor.execute(query, (user_id,))
            user = cursor.fetchone()

            if not user:
                return jsonify({"error": "User not found"}), 404

            if user["is_deleted"]:
                return jsonify({"isDeleted": False}), 403
            
            # DELETE 쿼리: 사용자를 삭제
            delete_query = """
                UPDATE users
                SET username = null,
                    email = NULL,
                    user_nickname = NULL,
                    user_pw = null,
                    school = NULL,
                    major = NULL,
                    profile_picture = NULL,
                    role = null,
                    is_deleted = true
                WHERE user_id = %s
            """
            
            post_check_query = """
                update post
                set inactivated = true
                where author_id = %s
            """
            cursor.execute(delete_query, (user_id,))
            cursor.execute(post_check_query, (user_id,))
            connection.commit()
        
        return jsonify({"deleted": True}), 200

    except Error as e:
        print(e)
        return jsonify({"error": str(e)}), 500


# 회원 정보 수정
@app.route("/update_user", methods=["PUT"])
@use_db_connection
def update_user(connection):
    try:
        # 토큰에서 user_id 추출
        user_id, error_response, status_code = get_user_id_from_token(request)
        if error_response:
            return error_response, status_code

        # 요청 본문에서 업데이트할 정보 가져오기
        data = request.get_json()
        new_username = data.get("username")
        new_email = data.get("email")
        new_user_nickname = data.get("user_nickname")
        new_school = data.get("school")
        new_major = data.get("major")
        new_profile_picture = data.get("profile_picture")

        # 데이터베이스에 업데이트를 위한 커서 생성
        with connection.cursor() as cursor:
            # UPDATE 쿼리: 사용자 정보를 업데이트
            update_query = """
                UPDATE users
                SET username = %s, email = %s, user_nickname = %s, school = %s, major = %s, profile_picture = %s
                WHERE user_id = %s
            """
            cursor.execute(
                update_query,
                (new_username, new_email, new_user_nickname, new_school, new_major, new_profile_picture, user_id),
            )
            connection.commit()

        return jsonify({"updated": True}), 200

    except Error as e:
        print(e)
        return jsonify({"error": str(e)}), 500

# universities 테이블에서 대학교 리스트를 GET 방식으로 반환하는 API
@app.route('/universities', methods=['GET'])
def get_universities():
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        # universities 테이블에서 모든 대학교 이름을 조회
        query = "SELECT * FROM universities"
        cursor.execute(query)
        universities = cursor.fetchall()

        # 데이터베이스 연결 및 커서 닫기
        cursor.close()

        # JSON 응답으로 대학교 목록 반환
        return jsonify({"universities": universities}), 200

    except mysql.connector.Error as err:
        print(f"Error: {err}")
        return jsonify({"error": "Database connection error"}), 500

# 인증 및 리다이렉트 처리
"""
@app.route("/auth/<path:url>", methods=["GET"])
@use_db_connection
def auth_redirect(connection, url):
    token = request.headers.get("Authorization")  # 헤더에서 Authorization 토큰 가져오기

    if token:
        try:
            # Bearer token 형식이므로 "Bearer "를 제거한 후 디코딩
            token = token.replace("Bearer ", "")
            decoded_token = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])

            # 토큰 검증이 성공하면 요청된 URL로 리다이렉트
            return redirect(f"/{url}")
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401
    else:
        # 토큰이 없으면 로그인 페이지로 리다이렉트
        return redirect("/login")
"""


# 유저 아이디 있는지 확인
@app.route("/existuser", methods=["POST"])
@use_db_connection
def check_exist_user(connection):
    try:
        # 클라이언트에서 전달받은 JSON 데이터
        data = request.json
        user_id = data.get("user_id")

        # 필수 입력값이 비어 있는지 확인
        if not user_id:
            return jsonify({"status": "error", "message": "user_id is required!"})

        # 데이터베이스 커서 생성
        with connection.cursor(dictionary=True) as cursor:
            # 1. ID 중복 여부 확인
            check_user_sql = "SELECT user_id FROM users WHERE user_id = %s"
            cursor.execute(check_user_sql, (user_id,))
            existing_user = cursor.fetchone()

            # 중복된 user_id가 있을 경우
            if not existing_user:
                return jsonify({"isNotExist": True})
            else:
                return jsonify({"isNotExist": False})

    except Exception as e:
        # 예외 발생 시 에러 메시지 반환
        return jsonify({"status": "error", "message": str(e)}), 500


'''
# 채팅방 정보 조회 API
@app.route("/room/<int:room_id>", methods=["GET"])
@use_db_connection
def get_room_data(connection, room_id):
    with connection.cursor(dictionary=True) as cursor:
        # 채팅방 정보 가져오기
        cursor.execute(
            """
            SELECT room_id, room_name, created_by, created_at
            FROM chatroom
            WHERE room_id = %s
        """,
            (room_id,),
        )
        room_data = cursor.fetchone()

        if not room_data:
            return jsonify({"error": "Room not found"}), 404

        # 메시지 정보 가져오기
        cursor.execute(
            """
            SELECT message_id, sender_id, content, sent_at
            FROM messages
            WHERE room_id = %s
            ORDER BY sent_at ASC
        """,
            (room_id,),
        )
        messages = cursor.fetchall()

    # 방 데이터와 메시지를 반환
    return (
        jsonify(
            {
                "room_id": room_data["room_id"],
                "room_name": room_data["room_name"],
                "created_by": room_data["created_by"],
                "created_at": room_data["created_at"],
                "messages": messages,
            }
        ),
        200,
    )


# 메시지 전송 API
@app.route("/room/<int:room_id>/message", methods=["POST"])
@use_db_connection
def send_message(connection, room_id):
    data = request.get_json()
    sender_id = data.get("sender_id")
    content = data.get("content")

    if not sender_id or not content:
        return jsonify({"error": "Sender ID and content are required"}), 400

    with connection.cursor() as cursor:
        # 메시지 삽입
        cursor.execute(
            """
            INSERT INTO messages (room_id, sender_id, content)
            VALUES (%s, %s, %s)
        """,
            (room_id, sender_id, content),
        )

    connection.commit()

    return jsonify({"success": True, "message": "Message sent"}), 201


# 채팅방 메시지 불러오기 API
@app.route("/get_messages/<int:room_id>", methods=["GET"])
@use_db_connection
def get_messages(connection, room_id):
    with connection.cursor(dictionary=True) as cursor:
        cursor.execute(
            """
            SELECT message_id, room_id, sender_id, receiver_id, content, sent_at
            FROM messages
            WHERE room_id = %s
            ORDER BY sent_at ASC
        """,
            (room_id,),
        )

        messages = cursor.fetchall()

    return jsonify(messages), 200
'''


# 댓글 작성 API
@app.route("/comment", methods=["POST"])
@use_db_connection
def add_comment(connection):
    try:
        # 클라이언트에서 전달받은 JSON 데이터
        data = request.json
        content = data.get("content")  # 댓글의 내용 - 필수
        post_id = data.get("post_id")  # 댓글이 달릴 포스트 ID - 필수
        parent_id = data.get("parent_id")  # 부모 댓글 아이디 (선택적)

        # 모듈화된 함수로부터 user_id 추출
        user_id, error_response, status_code = get_user_id_from_token(request)
        if error_response:
            return error_response, status_code

        # 댓글 내용과 포스트 ID가 없는 경우 에러 반환
        if not content or not post_id:
            return (
                jsonify(
                    {"status": "error", "message": "Content and post_id are required"}
                ),
                400,
            )

        # parent_id가 있을 때, 해당 parent_id가 최상위 댓글인지 확인
        if parent_id is not None:
            with connection.cursor(dictionary=True) as cursor:
                # parent_id가 가리키는 댓글의 parent_id가 NULL인지 확인 (최상위 댓글만 대댓글 허용)
                cursor.execute(
                    "SELECT parent_id FROM comment WHERE comment_id = %s", (parent_id,)
                )
                parent_comment = cursor.fetchone()

                if not parent_comment:
                    # parent_id에 해당하는 댓글이 없는 경우
                    return (
                        jsonify(
                            {"status": "error", "message": "Parent comment not found"}
                        ),
                        400,
                    )

                if parent_comment["parent_id"] is not None:
                    # parent_id가 이미 대댓글인 경우 (즉, 대댓글에 대댓글을 달려는 경우)
                    return (
                        jsonify(
                            {
                                "status": "error",
                                "message": "Cannot reply to a child comment",
                            }
                        ),
                        400,
                    )

        # 댓글 삽입
        with connection.cursor(dictionary=True) as cursor:
            sql = "INSERT INTO comment (post_id, author_id, content, parent_id) VALUES (%s, %s, %s, %s)"
            cursor.execute(sql, (post_id, user_id, content, parent_id))

            # 마지막으로 삽입된 댓글 ID 가져오기
            comment_id = cursor.lastrowid

        connection.commit()

        return (
            jsonify(
                {"message": "Comment added successfully!", "comment_id": comment_id}
            ),
            201,
        )

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5001)
