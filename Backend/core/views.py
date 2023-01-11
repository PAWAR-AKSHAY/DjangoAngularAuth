import datetime
import random
import string
import pyotp

from django.core.mail import send_mail
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
        
        # 1. when user tfa_secret is set we will return user id
        if user.tfa_secret:
            return Response({
                "id": user.id
            })
        
        # 2 when we don't have tfa_secret value, we will generated and return secret
        secret = pyotp.random_base32()
        otpauth_url = pyotp.totp.TOTP(secret).provisioning_uri(issuer_name="Django Angular Authentication")

       
        return Response({
            "id": user.id,
            "secret": secret,
            "otpauth_url": otpauth_url
        })


class TwoFactorAPIView(APIView):
    def post(self, request):
        # 1.1 then send request with id here
        id = request.data["id"]

        user = models.User.objects.filter(pk=id).first()

        if not user:
            raise exceptions.AuthenticationFailed("Invalid Credentials")

        # 1.2 if user tfa_secret is set we get directly from here
        # 2.1 when we don't have secret value then we return like else part
        # therefore secret in these two cases won't empty

        secret = user.tfa_secret if user.tfa_secret !="" else request.data["secret"]

        if not pyotp.TOTP(secret).verify(request.data["code"]):
            raise exceptions.AuthenticationFailed("Invalid Credentials")
        
        # this value will be set when user login first time, second time user login we will only return user id, not a qr code
        if user.tfa_secret == "":
            user.tfa_secret = secret
            user.save()

        access_token = create_access_token(id)
        refresh_token = create_refresh_token(id)

        models.UserToken.objects.create(
            user_id=id,
            token=refresh_token,
            expire_at=datetime.datetime.utcnow() + datetime.timedelta(days=7)
        )
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

        if not models.UserToken.objects.filter(
                user_id=id,
                token=refresh_token,
                expire_at__gt=datetime.datetime.now(tz=datetime.timezone.utc)
        ).exists():
            raise exceptions.AuthenticationFailed("unauthenticated")

        access_token = create_access_token(id)
        return Response({"token": access_token})


class LogoutAPIView(APIView):
    def post(self, request):
        refresh_token = request.COOKIES.get("refresh_token")
        models.UserToken.objects.filter(token=refresh_token).delete()
        response = Response()
        response.delete_cookie(key="refresh_token")
        response.data = {
            "message": "success"
        }
        return response


class ForgotAPIView(APIView):
    def post(self, request):
        email = request.data["email"]
        token = "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(10))

        models.Reset.objects.create(email=email, token=token)
        url = "http://localhost:4200/reset/" + token

        send_mail(
            subject="Reset your password!",
            message=f"Click on link {url} to reset your password!",
            from_email="from@example.com",
            recipient_list=[email]
        )
        return Response({"message": "success"})


class ResetAPIView(APIView):
    def post(self, request):
        data = request.data

        if data["password"] != data["password_confirm"]:
            raise exceptions.APIException("Password do not match!")

        reset_password = models.Reset.objects.filter(token=data["token"]).first()
        if not reset_password:
            raise exceptions.APIException("Invalid link!")
        user = models.User.objects.filter(email=reset_password.email).first()

        if not user:
            raise exceptions.APIException("User not found!")

        user.set_password(data["password"])
        user.save()
        return Response({"message": "success"})
