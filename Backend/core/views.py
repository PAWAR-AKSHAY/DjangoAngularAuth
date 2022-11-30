from rest_framework import exceptions
from rest_framework.authentication import get_authorization_header
from rest_framework.response import Response
from rest_framework.views import APIView

from core import models, serializers
from core.authentication import create_access_token, create_refresh_token, decode_access_token, JWTAuthentication, \
    decode_refresh_token


class RegisterAPIView(APIView):

    def post(self, request):
        data = request.data
        if data["password"] != data["password_confirm"]:
            raise exceptions.APIException("Password do not match!")

        serializer = serializers.UserSerializer(data=data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)


class LoginAPIView(APIView):
    def post(self, request):
        email = request.data["email"]
        password = request.data["password"]

        user = models.User.objects.filter(email=email).first()

        if user is None:
            raise exceptions.AuthenticationFailed("Invalid Credentials")
        if not user.check_password(password):
            raise exceptions.AuthenticationFailed("Invalid Credentials")

        access_token = create_access_token(user.id)
        refresh_token = create_refresh_token(user.id)

        response = Response()
        response.set_cookie(key="refresh_token", value=refresh_token, httponly=True)
        response.data = {
            "token": access_token
        }
        return response


# class UserAPIView(APIView):
#  """ UserAPIView with custom jwt authentication logic in-built in it"""
#     def get(self, request):
#         auth = get_authorization_header(request).split()
#         if auth and len(auth) == 2:
#             token = auth[1].decode("utf-8")
#             id = decode_access_token(token)
#
#             user = models.User.objects.get(pk=id)
#             if user:
#                 serializer = serializers.UserSerializer(user)
#                 return Response(serializer.data)
#         raise exceptions.AuthenticationFailed("unauthenticated")


class UserAPIView(APIView):
    """ UserAPIView with custom jwt authentication class"""
    authentication_classes = [JWTAuthentication, ]

    def get(self, request):
        return Response(serializers.UserSerializer(request.user).data)


class RefreshAPIView(APIView):
    def post(self, request):
        refresh_token = request.COOKIES.get("refresh_token")
        id = decode_refresh_token(refresh_token)

        access_token = create_access_token(id)
        return Response({"token": access_token})


class LogoutAPIView(APIView):
    def post(self, request):
        response = Response()
        response.delete_cookie(key="refresh_token")
        response.data = {
            "message": "success"
        }
        return response
