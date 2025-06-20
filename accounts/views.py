import logging
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from django.contrib.auth.models import User

# Logger setup
logger = logging.getLogger(__name__)

# 🚀 REGISTER VIEW
@api_view(['POST'])
def register_user(request):
    full_name = request.data.get('full_name')
    email = request.data.get('email')
    password = request.data.get('password')

    if User.objects.filter(email=email).exists():
        return Response({'error': 'Email already registered'}, status=status.HTTP_400_BAD_REQUEST)

    user = User.objects.create_user(
        username=email,   # ✅ using email as username
        email=email,
        password=password,
        first_name=full_name
    )

    logger.info(f"User registered: {email}")
    return Response({'message': 'User registered successfully'}, status=status.HTTP_201_CREATED)

# 🚀 LOGIN VIEW
@api_view(['POST'])
def login_user(request):
    email = request.data.get('email')
    password = request.data.get('password')

    user = authenticate(request, username=email, password=password)  # ✅ works with custom backend

    if user:
        logger.info(f"User logged in: {user.email}")

        refresh = RefreshToken.for_user(user)
        return Response({
            'token': str(refresh.access_token),
            'refresh': str(refresh),
            'username': user.first_name,
            'email': user.email,
        }, status=status.HTTP_200_OK)
    else:
        logger.warning(f"Failed login attempt with email: {email}")
        return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
