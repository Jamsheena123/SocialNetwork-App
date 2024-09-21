from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    SignupView,
    LoginView,
    FriendRequestViewSet,
    UserProfileViewSet,
    FriendshipViewSet,
    UserActivityViewSet,
    UserBlockViewSet

)

router = DefaultRouter()
router.register(r'friend-requests', FriendRequestViewSet, basename='friendrequest')
router.register(r'profiles', UserProfileViewSet, basename='userprofile')
router.register(r'friendships', FriendRequestViewSet, basename='friendship')
router.register(r'user-activities', UserActivityViewSet, basename='useractivity')
router.register(r'user-blocks', UserBlockViewSet, basename='userblock')

urlpatterns = [
    path('signup/', SignupView.as_view(), name='signup'),
    path('login/', LoginView.as_view(), name='login'),
    path('', include(router.urls)),  # Include the router's URLs
]