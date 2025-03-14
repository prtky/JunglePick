# JunglePick

## 기획의도

일요일날이나 야식을 먹고 싶을때, 혼자 먹기에는 부담스럽고 본인이 먹고 싶은 음식과 같이 먹고 싶은 교육생분들의 고민을 알게되었다. 이러한 고민을 해결하기 위해 기획하게 되었다.

## 서비스 소개

야식이나 일요일날 배달음식을 같이 먹을 친구가 없을때 같이 먹을 친구를 찾는 서비스이다.

## 장정

배달비를 절약하고 최소주문 컷을 지킬수 있으며 양이 많은 음식의 경우 N 분의 1로 적절한 양으로 먹을 수 있다.

## 아키텍쳐

형상관리: 깃허브, 노션  
프론트엔드: BULMA  
서버 벡엔드: Flask, JWT, Python, jinja  
DB: MongoDB, 3T  
배포: AWS  

## 기술적 챌린지

[벡엔드] JWT로 로그인 시스템 개발, 웹소켓을 통한 실시간 채팅 개발, Jinja2 사용해서 서버사이드 구현,  
MongoDB를 통한 아이디 중복 확인 구현  
[프론트엔드] Bulma를 통한 CSS 구현, 실시간 채팅에서의 프론트엔드 처리  

## 설치 방법

> pip install -r requirements.txt

로 패키지 다운 후

> python3 app.py

로 실행하시면 됩니다.
