from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions,authentication
from .serializers import UserSerializer
from .models import UserModel

BAD_REQUEST = status.HTTP_400_BAD_REQUEST
GET_REQUEST = status.HTTP_200_OK

# Create your views here.
class Me(APIView):
    authentication_classes = [authentication.TokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get(self,request,*args,**kwargs):
        try:
            user = UserModel.objects.filter(id=request.auth.user.pk).order_by('id')
            serializer = UserSerializer(instance=user, many=True)
            return Response(serializer.data, status=GET_REQUEST)
        except Exception as e:
            return Response(str(e), status=BAD_REQUEST)