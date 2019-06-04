from django.shortcuts import render,redirect
from django.http import HttpResponse, JsonResponse
import json
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.models import User
from django.contrib.auth import login,authenticate
from django.contrib.auth.decorators import login_required
from .token_module import out_token, get_token
from .models import UserToken
from django.conf import settings
import jwt
from datetime import datetime, timedelta


# Create your views here.
@csrf_exempt
def loginView(request):
    if request.method == 'POST':
        username = request.POST.get('username','error')
        password = request.POST.get('password','error')
        print(username,password)
        tips = ''
        if User.objects.filter(username=username):
            # authenticate 判断密码是否正确
            user = authenticate(username=username, password=password)
            if user:
                if user.is_active:
                    # token = get_token(username, settings.TOKEN_EXPIRE_TIME)
                    token = jwt.encode({
                            'exp':datetime.utcnow()+timedelta(seconds=settings.TOKEN_EXPIRE_TIME),
                            'iat':datetime.utcnow(),
                            'data': {
                                'username': username
                            }
                        },settings.SECRET_KEY, algorithm='HS256').decode('utf-8')
                    UserToken.objects.update_or_create(user=user, defaults={"token": token})
                    tips = '登陆成功'
                    # 'sesssionid': request.session.session_key,
                    res = HttpResponse(json.dumps({'tips':tips, 'token': token, 'status':200}))
                    return res
            else:
                tips = ' 密码错误，请重新输入 '
        else:
            tips = ' 用户不存在，请注册 '
        res = HttpResponse(json.dumps({'tips': tips, 'status': 201}))
        return res
    else:
        return HttpResponse('asd')


@csrf_exempt
def register(request):
    if request.method == 'POST':
        username = request.POST.get('username','error')
        password = request.POST.get('password','error')
        print(username,password)
        if User.objects.filter(username=username):
            tips = '用户已存在'
        else:
            user = User.objects.create_user(username=username,password=password)
            user.save()
            tips = ' 注册成功 '
        return HttpResponse(json.dumps({'tips':tips}))
    else:
    	return HttpResponse(json.dumps({'tips':'莫得get界面'}))


def islogin(request):
    try:
        token = request.META.get('HTTP_AUTHORIZATION')
    except:
        return HttpResponse(json.dumps({{"status": 402, "tips": "No authenticate header"}}))
    # try:
    #     if out_token(token_list[1], token_list[0]):
    #         return HttpResponse(json.dumps({'tips':'登录成功,当前用户'+token_list[1]}))
    #     else:
    #         return HttpResponse(json.dumps({'tips': '您未登录', 'status': 401}))
    # except Exception as e:
    #     print(e)
    try:
        dict = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        username = dict.get('data').get('username')
    except jwt.ExpiredSignatureError:
        return JsonResponse({"status": 401, "tips": "Token expired"})
    except jwt.InvalidTokenError:
        return JsonResponse({"status": 401, "tips": "Invalid token"})
    except Exception as e:
        return JsonResponse({"status": 401, "tips": "Can not get user object"})

    try:
        user = User.objects.get(username=username)
        return JsonResponse({"status":200, "tips": "登陆成功，当前用户 "+ username})
    except:
        return JsonResponse({"status_code": 401, "tips": "User Does not exist"})


def indexView(request):
    if request.method == 'GET':
        return HttpResponse(json.dumps({'tips':'这是一个简单的页面信息'}))