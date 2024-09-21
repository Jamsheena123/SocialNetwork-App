from rest_framework import generics, status, viewsets
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.throttling import UserRateThrottle
from rest_framework.decorators import action
from django.db import transaction
from django.db.models import Q
from django.contrib.auth import get_user_model
from .models import UserProfile, FriendRequest, Friendship, UserActivity, UserBlock
from .serializers import CustomUserSerializer,UserProfileSerializer, FriendshipSerializer ,FriendRequestSerializer,UserActivitySerializer,UserBlockSerializer
from django.contrib.auth import authenticate
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from django.utils import timezone
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.throttling import UserRateThrottle



User = get_user_model()

class SignupView(generics.CreateAPIView):
    serializer_class = CustomUserSerializer
    permission_classes = [AllowAny]

    def create(self, request, *args, **kwargs):
        email = request.data.get("email", "").lower()
        
        if User.objects.filter(email=email).exists():
            return Response({"detail": "User already exists."}, status=status.HTTP_400_BAD_REQUEST)
        
        request.data['email'] = email  
        response = super().create(request, *args, **kwargs)

        # Automatically create UserProfile after user registration
        user = User.objects.get(email=email)
        UserProfile.objects.create(user=user)

        return response



class LoginThrottle(UserRateThrottle):
    rate = '5/minute'



class LoginView(APIView):
    throttle_classes = [LoginThrottle]  # Throttle for rate-limiting
    permission_classes = [IsAuthenticated]

    def post(self, request):
        email = request.data.get("email", "").lower()  # Case-insensitive email
        password = request.data.get("password")

        # Authenticate using email
        user = authenticate(request, email=email, password=password)

        if user is not None:
            # Generate JWT token for authenticated user
            refresh = RefreshToken.for_user(user)
            user_data = CustomUserSerializer(user).data

            # Log user activity
            UserActivity.objects.create(
                user=user,
                action="login",
                timestamp=timezone.now()
            )

            return Response({
                'access_token': str(refresh.access_token),
                'refresh_token': str(refresh),
                'user': user_data
            }, status=status.HTTP_200_OK)
        else:
            return Response({
                'error': 'Invalid credentials'
            }, status=status.HTTP_400_BAD_REQUEST)



class LoginView(APIView):
    throttle_classes = [LoginThrottle]  # Throttle for rate-limiting
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get("email", "").lower()  # Case-insensitive email
        password = request.data.get("password")
        

        # Authenticate using email
        user = authenticate(request, email=email, password=password)

        if user is not None:
            # Generate JWT token for authenticated user
            refresh = RefreshToken.for_user(user)
            user_data = CustomUserSerializer(user).data

            return Response({
                'access_token': str(refresh.access_token),
                'refresh_token': str(refresh),
                'user': user_data
            }, status=status.HTTP_200_OK)
        else:
            return Response({
                'error': 'Invalid credentials'
            }, status=status.HTTP_400_BAD_REQUEST)


class FriendRequestThrottle(UserRateThrottle):
    rate = '3/minute'





class FriendRequestViewSet(viewsets.ModelViewSet):
    queryset = FriendRequest.objects.all()
    serializer_class = FriendRequestSerializer
    permission_classes = [IsAuthenticated]
    throttle_classes = [FriendRequestThrottle]

    def get_queryset(self):
        user = self.request.user
        return FriendRequest.objects.filter(Q(sender=user) | Q(receiver=user))

    def perform_create(self, serializer):
        serializer.save(sender=self.request.user)

    @action(detail=False, methods=['get'])
    def pending(self, request):
        """List all pending friend requests received by the current user"""
        user = request.user
        pending_requests = FriendRequest.objects.filter(receiver=user, accepted=False, rejected=False)
        serializer = self.get_serializer(pending_requests, many=True)
        return Response(serializer.data)

   

    @action(detail=True, methods=['patch'])
    def accept(self, request, pk=None):
        """Accept a friend request"""
        try:
            # Retrieve the friend request for the authenticated user
            friend_request = FriendRequest.objects.get(pk=pk, receiver=request.user, accepted=False, rejected=False)
        except FriendRequest.DoesNotExist:
            return Response({"detail": "Friend request not found or already processed."}, status=status.HTTP_404_NOT_FOUND)

        with transaction.atomic():
            # Mark the friend request as accepted
            friend_request.accepted = True
            friend_request.rejected = False  # Ensure rejected is set to False if you have that field
            friend_request.save()

            # Create a friendship
            Friendship.objects.create(user1=friend_request.sender, user2=friend_request.receiver, accepted=True)

        return Response({"detail": "Friend request accepted and friendship created."}, status=status.HTTP_200_OK)


    

    @action(detail=True, methods=['patch'])
    def reject(self, request, pk=None):
        """Reject a friend request"""
        try:
            friend_request = FriendRequest.objects.get(pk=pk, receiver=request.user, accepted=False, rejected=False)
        except FriendRequest.DoesNotExist:
            return Response({"detail": "Friend request not found or already processed."}, status=status.HTTP_404_NOT_FOUND)

        with transaction.atomic():
            friend_request.rejected = True
            friend_request.save()

        return Response({"detail": "Friend request rejected."}, status=status.HTTP_200_OK)

    @action(detail=True, methods=['post'])
    def block(self, request, pk=None):
        """Block a user from sending further requests"""
        try:
            friend_request = FriendRequest.objects.get(pk=pk, receiver=request.user)
        except FriendRequest.DoesNotExist:
            return Response({"detail": "Friend request not found."}, status=status.HTTP_404_NOT_FOUND)

        # Block user
        UserBlock.objects.create(blocker=request.user, blocked=friend_request.sender)

        return Response({"detail": "User blocked."}, status=status.HTTP_200_OK)

class UserProfileViewSet(viewsets.ModelViewSet):
    queryset = UserProfile.objects.all()
    serializer_class = UserProfileSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return UserProfile.objects.filter(user=self.request.user)

    @action(detail=False, methods=['get'])
    def me(self, request):
        """Get the current user's profile, create if it doesn't exist."""
        profile, created = UserProfile.objects.get_or_create(user=request.user)
        serializer = self.get_serializer(profile)
        return Response(serializer.data)

    def create(self, request, *args, **kwargs):
        """Create or update the user profile."""
        user = request.user
        bio = request.data.get('bio')
        profile_picture = request.FILES.get('profile_picture')

        # Check if the profile already exists
        profile, created = UserProfile.objects.get_or_create(user=user)

        # Update bio and profile picture
        profile.bio = bio if bio else profile.bio
        profile.profile_picture = profile_picture if profile_picture else profile.profile_picture
        profile.save()

        serializer = self.get_serializer(profile)
        return Response(serializer.data)


# --- Friendship Management ---

class FriendshipViewSet(viewsets.ModelViewSet):
    serializer_class = FriendshipSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        return Friendship.objects.filter(
            Q(user1=user) | Q(user2=user),
            accepted=True
        )

    @action(detail=False, methods=['get'])
    def friends(self, request):
        user = request.user
        friendships = self.get_queryset()  # Retrieves accepted friendships

        # Use a list to store serialized friendships
        friends = []
        for friendship in friendships:
            friend = friendship.user2 if friendship.user1 == user else friendship.user1
            friends.append({
                "id": friend.id,
                "username": friend.username,
                "accept": friendship.accepted,
                "created_at": friendship.created_at,  # Include the creation timestamp
            })

        return Response(friends)



# --- User Activity Logging ---

 
class UserActivityViewSet(viewsets.ModelViewSet):
    serializer_class = UserActivitySerializer
    permission_classes = [IsAuthenticated]
    def get_queryset(self):
        # Only return the activities for the authenticated user
        return UserActivity.objects.filter(user=self.request.user).order_by('-timestamp')

    def create(self, request, *args, **kwargs):
        # Automatically associate the activity with the authenticated user
        data = request.data.copy()
        data['user'] = request.user.id
        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    def list(self, request, *args, **kwargs):
        # List all activities for the authenticated user
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

class UserBlockViewSet(viewsets.ModelViewSet):
    queryset = UserBlock.objects.all()
    serializer_class = UserBlockSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # Allow users to see who they have blocked
        return UserBlock.objects.filter(blocker=self.request.user)

    @action(detail=True, methods=['post'])
    def unblock(self, request, pk=None):
        """Unblock a user."""
        try:
            block_entry = UserBlock.objects.get(pk=pk, blocker=request.user)
        except UserBlock.DoesNotExist:
            return Response({"detail": "User block entry not found."}, status=status.HTTP_404_NOT_FOUND)

        block_entry.delete()
        return Response({"detail": "User unblocked."}, status=status.HTTP_200_OK)

    @action(detail=True, methods=['post'])
    def block(self, request, pk=None):
        """Block a user from interacting."""
        try:
            user_to_block = User.objects.get(pk=pk)
        except User.DoesNotExist:
            return Response({"detail": "User not found."}, status=status.HTTP_404_NOT_FOUND)

        # Check if already blocked
        if UserBlock.objects.filter(blocker=request.user, blocked=user_to_block).exists():
            return Response({"detail": "User already blocked."}, status=status.HTTP_400_BAD_REQUEST)

        # Create a block entry
        UserBlock.objects.create(blocker=request.user, blocked=user_to_block)
        return Response({"detail": "User blocked."}, status=status.HTTP_200_OK)
