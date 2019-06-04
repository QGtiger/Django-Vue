from django.shortcuts import HttpResponse
from .token_module import out_token, get_token
import json


try:
    from django.utils.deprecation import MiddlewareMixin  # Django 1.10.x
except ImportError:
    MiddlewareMixin = object

# 拦截器
class SimpleMiddleware(MiddlewareMixin):
    def process_request(self, request):
        if request.path != '/backend/login' and request.path != '/backend/register':
            try:
                token = request.META.get('HTTP_AUTHORIZATION')
                token_list = token.split('&')
            except:
                return HttpResponse(json.dumps({'tips': '您未登录', 'status':402}))
            try:
                if out_token(token_list[1], token_list[0]):
                    pass
                else:
                    return HttpResponse(json.dumps({'tips': '您未登录,登录信息过期', 'status': 401}))
            except Exception as e:
                print(e)