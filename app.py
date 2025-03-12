from flask import Flask, render_template, jsonify, request, session, redirect, url_for, make_response

app = Flask(__name__)

from pymongo import MongoClient
import certifi

ca=certifi.where()

# JWT 토큰을 만들 때 필요한 비밀문자열입니다. 아무거나 입력해도 괜찮습니다.
# 이 문자열은 서버만 알고있기 때문에, 내 서버에서만 토큰을 인코딩(=만들기)/디코딩(=풀기) 할 수 있습니다.
#8b66bc30c7e44ac19efffa0de7cdb9c1을 시크릿키로 사용 예정
SECRET_KEY = 'SPARTA'     

# JWT 패키지를 사용합니다. (설치해야할 패키지 이름: PyJWT)
import jwt

#jwt 관련된 확장기능을 사용합니다. 예를 들어 jwt 토큰 여부를 확인하는 required 등
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

# 토큰에 만료시간을 줘야하기 때문에, datetime 모듈도 사용합니다.
from datetime import datetime, timedelta, timezone

# 회원가입 시엔, 비밀번호를 암호화하여 DB에 저장해두는 게 좋습니다.
# 그렇지 않으면, 개발자(=나)가 회원들의 비밀번호를 볼 수 있으니까요. 그래서 해싱을 하여 DB에 저장합니다.
import hashlib

from functools import wraps

# 🔹 JWT 검증 실패 시 로그인 페이지로 리다이렉트(이벤트 핸들러로 토큰 없을시 대응)
from flask_jwt_extended.exceptions import NoAuthorizationError
from werkzeug.exceptions import Unauthorized

from flask_jwt_extended import *
from bson import ObjectId
from flask_socketio import SocketIO

socketio = SocketIO(app)
client = MongoClient('localhost',27017)
################################################################################################################################ 배포시 수정할 부분
#client = MongoClient('mongodb://test:test@3.37.36.71',27017) 
db = client.dbjungle

@app.errorhandler(NoAuthorizationError)
@app.errorhandler(Unauthorized)
def handle_auth_error(e):
    return jsonify({"error": "로그인이 필요합니다.", "redirect": "login"}), 401     #로그인 토큰이 없어 에러 메시지 출력 후 로그인 페이지로 리다이렉션


#################################
##  HTML을 주는 부분             ##
#################################
@app.route('/')    # 만약 등록된 사용자라면 닉네임과 함께 index페이지로 넘긴다. 예외사항에는 각각 맞는 경고 메시지가 출력되도록 처리하였다. return render_template("login")로 대체될 수 있다.
def home():
    token_receive = request.cookies.get('mytoken')
    cards = list(db.cards.find({}))
    chats = list(db.chats.find({}))
    for card in cards:
        card['_id'] =str(card['_id'])
    
    # 쿠키가 없는 경우: 로그인 페이지로 리디렉트
    if not token_receive:
        return redirect(url_for("login"))

    try:
        payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])
        user_info = db.user.find_one({"id": payload['id']})
        return render_template('mainpage.html', nickname=user_info["nick"], cards = cards, chats = chats)
    except jwt.ExpiredSignatureError:
        return redirect(url_for("login", msg="로그인 시간이 만료되었습니다."))
    except jwt.exceptions.DecodeError:
        return redirect(url_for("login", msg="로그인 정보가 존재하지 않습니다."))
    
    

@app.route('/login')    # 로그인 버튼 누를시 처리
def login():
    msg = request.args.get("msg")
    return render_template('login.html', msg=msg)


@app.route('/register')  # 회원가입 버튼 누를시 처리
def register():
    return render_template('register.html')


#################################
##  로그인을 위한 API            ##
#################################

### [회원가입 API]
# id, pw, nickname을 받아서, mongoDB에 저장합니다.
# 저장하기 전에, pw를 sha256 방법(=단방향 암호화. 풀어볼 수 없음)으로 암호화해서 저장합니다.
@app.route('/api/register', methods=['POST'])
def api_register():
    id_receive = request.form['id_give']
    pw_receive = request.form['pw_give']
    nickname_receive = request.form['nickname_give']
    
    # 이름 중복 확인
    if db.user.find_one({'nick': nickname_receive}):
        return jsonify({'result': 'fail', 'msg': '존재하는 이름입니다.'})
    
    # 아이디 중복 확인
    if db.user.find_one({'id': id_receive}):
        return jsonify({'result': 'fail', 'msg': '존재하는 아이디입니다.'})
  
  # 중요!!!!아무도(개발자라도) 암호를 해석할 수 없도록 만든다!!! 패스워드를 이런식으로 숨겨서 관리한다. 패스워드 보안에 핵심. 사용자만 패스워드를 안다.
    pw_hash = hashlib.sha256(pw_receive.encode('utf-8')).hexdigest()
  # 입력된 값을 서버에 올릴 준비(함수)
    db.user.insert_one({'id': id_receive, 'pw': pw_hash, 'nick': nickname_receive})

    return jsonify({'result': 'success'})


### [로그인 API]
# id, pw를 받아서 맞춰보고, 토큰을 만들어 발급합니다.
@app.route('/api/login', methods=['POST'])
def api_login():
    id_receive = request.form['id_give']
    pw_receive = request.form['pw_give']

    # 회원가입 때와 같은 방법으로 pw를 암호화합니다. 보안성 강화
    pw_hash = hashlib.sha256(pw_receive.encode('utf-8')).hexdigest()

    # id, 암호화된pw을 가지고 해당 유저를 찾습니다.
    result = db.user.find_one({'id': id_receive, 'pw': pw_hash})

    # 찾으면 JWT 토큰을 만들어 발급합니다.
    if result is not None:
        # JWT 토큰에는, payload와 시크릿키가 필요합니다.
        # 시크릿키가 있어야 토큰을 디코딩(=풀기) 해서 payload 값을 볼 수 있습니다.
        # 아래에선 id와 exp를 담았습니다. 즉, JWT 토큰을 풀면 유저ID 값을 알 수 있습니다.
        # exp에는 만료시간을 넣어줍니다(5초). 만료시간이 지나면, 시크릿키로 토큰을 풀 때 만료되었다고 에러가 납니다.
        payload = {
            'id': id_receive,
            'exp':datetime.now(timezone.utc) + timedelta(days=2)  #####################################################################해당 부분이 토큰 기한 지정
        }
        token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')

        # token을 줍니다.
        return jsonify({'result': 'success', 'token': token})
    # 찾지 못하면
    else:
        return jsonify({'result': 'fail', 'msg': '아이디/비밀번호가 일치하지 않습니다.'})
    
### [로그아웃 API]
@app.route('/logout')
def logout():
    response = make_response(redirect(url_for('login')))  # 로그인 페이지로 리디렉트
    response.set_cookie('mytoken', '', expires=0)  # ✅ 토큰 쿠키 삭제
    return response


# [유저 정보 확인 API]
# 로그인된 유저만 call 할 수 있는 API입니다.
# 유효한 토큰을 줘야 올바른 결과를 얻어갈 수 있습니다.
# (그렇지 않으면 남의 장바구니라든가, 정보를 누구나 볼 수 있겠죠?)
@app.route('/api/nick', methods=['GET'])
def api_valid():
    token_receive = request.cookies.get('mytoken')

    # 쿠키가 없는 경우: 로그인 페이지로 리디렉트
    if not token_receive:
        return redirect(url_for("login"))
    
    # try / catch 문?
    # try 아래를 실행했다가, 에러가 있으면 except 구분으로 가란 얘기입니다.
    try:
        # token을 시크릿키로 디코딩합니다.
        # 보실 수 있도록 payload를 print 해두었습니다. 우리가 로그인 시 넣은 그 payload와 같은 것이 나옵니다.
        payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])
        print(payload)

        # payload 안에 id가 들어있습니다. 이 id로 유저정보를 찾습니다.
        # 여기에선 그 예로 닉네임을 보내주겠습니다.
        userinfo = db.user.find_one({'id': payload['id']}, {'_id': 0})
        return jsonify({'result': 'success', 'nickname': userinfo['nick']})
    except jwt.ExpiredSignatureError:
        # 위를 실행했는데 만료시간이 지났으면 에러가 납니다.
        return jsonify({'result': 'fail', 'msg': '로그인 시간이 만료되었습니다.'})
    except jwt.exceptions.DecodeError:
        return jsonify({'result': 'fail', 'msg': '로그인 정보가 존재하지 않습니다.'})
    
    
#############################################
##############################################

# 구성원 참여
@app.route('/mainpage/join', methods=['POST'])
def Join():
    #cardID를 불러옴
    cardID = request.form.get('')
    #참여를 시작한 userID를 불러옴
    userID = request.form.get('')

@app.route('/postcard')
def Post_page():
    return render_template('new_post.html')

#새카드 포스팅
@app.route('/postcard/post', methods = ['POST'])
def PostCard():
    #토큰 받아오기
    token_receive = request.cookies.get('mytoken')
    # 쿠키가 없는 경우: 로그인 페이지로 리디렉트
    if not token_receive:
        return redirect(url_for("login"))
    try:
        payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])
        user_info = db.user.find_one({"id": payload['id']})
    except jwt.ExpiredSignatureError:
        return redirect(url_for("login", msg="로그인 시간이 만료되었습니다."))
    except jwt.exceptions.DecodeError:
        return redirect(url_for("login", msg="로그인 정보가 존재하지 않습니다."))
    # 프론트에서 새 카드 받아오기 
    card_title = request.form.get('card_title')
    menu_list = request.form.get('menu_list')
    food_type = request.form.get('food_type')
    URL_info = request.form.get('URL_info')
    delivery_fee = request.form.get('delivery_fee')
    end_time = request.form.get('end_time')
    announcement = request.form.get('announcement')
    writer_nickname = user_info["nick"]

    result = db.cards.insert_one({'card_title' : card_title, 'menu_list' : menu_list, 
        'food_type' : food_type, 'URL_info' : URL_info,
        'delivery_fee' : delivery_fee, 'end_time' : end_time, 'announcement' : announcement, 'writer_nickname' : writer_nickname, 'status' : 'before_order'})

    if result.acknowledged:
        return jsonify({'result' : 'success'})
    else:
        return jsonify({'result' : 'failure'})
    
#카드 수정 진입
@app.route('/modifycard')
def modify_card():
    post_id = request.args.get('post_id')
    post = db.cards.find_one({'_id': ObjectId(post_id)})  # MongoDB 사용 시
    return render_template('edit_post.html', post=post)
    

#수정 내용 카드 업데이트 
@app.route('/postcard/update/<post_id>', methods=['POST'])
def update_post(post_id):
    # 프론트에서 수정된 데이터 받아오기
    card_title = request.form.get('card_title')
    menu_list = request.form.get('menu_list')
    food_type = request.form.get('food_type')
    URL_info = request.form.get('URL_info')
    delivery_fee = request.form.get('delivery_fee')
    end_time = request.form.get('end_time')
    announcement = request.form.get('announcement')

    # 기존 데이터가 존재하는지 확인
    existing_post = db.cards.find_one({'_id': ObjectId(post_id)})
    if not existing_post:
        return jsonify({'result': 'failure', 'msg': '해당 게시글을 찾을 수 없습니다.'})

    # 데이터 업데이트
    update_result = db.cards.update_one(
        {'_id': ObjectId(post_id)}, 
        {'$set': {
            'card_title': card_title,
            'menu_list': menu_list,
            'food_type': food_type,
            'URL_info': URL_info,
            'delivery_fee': delivery_fee,
            'end_time': end_time,
            'announcement': announcement
        }}
    )

    return jsonify({'result': 'success'})

    
    
# 게시자 카드 삭제
@app.route('/postcard/delete/<card_id>', methods=['POST'])
def delete_post(card_id):
    # 해당 게시글이 존재하는지 확인
    existing_post = db.cards.find_one({'_id': ObjectId(card_id)})
    if not existing_post:
        return jsonify({'result': 'failure', 'msg': '해당 게시글을 찾을 수 없습니다.'})

    # 게시글 삭제
    delete_result = db.cards.delete_one({'_id': ObjectId(card_id)})

    if delete_result.deleted_count > 0:
        return jsonify({'result': 'success', 'msg': '게시글이 삭제되었습니다.'})
    else:
        return jsonify({'result': 'failure', 'msg': '게시글 삭제에 실패했습니다.'})
    

@app.route('/postchat', methods=["POST"])
def postChat():
    nickname = request.form.get('give_nickname')
    texts = request.form.get('give_texts')

    result = db.chats.insert_one({'nickname' : nickname, "texts" : texts})
    if result.acknowledged:
        print("저장됨")
        return jsonify({'result' : 'success'})
    else:
        return jsonify({'result' : 'failure'})


@app.route("/update_order_status", methods=["POST"])
def updateOrderStatus():
    data = request.json
    print(data['post_id'])
    id = ObjectId(data['post_id'])
    new_status = data['status']
    print(new_status)

    result = db.cards.update_one({'_id' : id}, {'$set': {'status': new_status}})
    if result.modified_count == 1:
        return jsonify({'result': 'success'})
    else:
        return jsonify({'result': 'failure'})

# 실시간 채팅 관련
@socketio.on('message')
def handle_message(data):
    print("Received message : " , data)
    socketio.emit('message', data)
###
if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)