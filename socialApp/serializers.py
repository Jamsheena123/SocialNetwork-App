from rest_framework import serializers
from .models import CustomUser, UserProfile, FriendRequest, Friendship, UserActivity, UserBlock
from django.contrib.auth import get_user_model


class CustomUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['id', 'email', 'username', 'password', 'role']


    def create(self, validated_data):
        password = validated_data.pop('password', None)
        user = super().create(validated_data)
        if password:
            user.set_password(password)
            user.save()
        return user        


class UserProfileSerializer(serializers.ModelSerializer):
    user = CustomUserSerializer(read_only=True)  
    class Meta:
        model = UserProfile
        fields = ['id', 'user', 'bio', 'profile_picture']

User = get_user_model()

class FriendRequestSerializer(serializers.ModelSerializer):
    sender = CustomUserSerializer(read_only=True)  # Sender is read-only, will be set in create method
    receiver = serializers.PrimaryKeyRelatedField(queryset=User.objects.all())  # Receiver can be selected

    class Meta:
        model = FriendRequest
        fields = ['id', 'sender', 'receiver', 'created_at', 'accepted', 'rejected']
        read_only_fields = ['sender', 'created_at']

    def validate(self, data):
        sender = self.context['request'].user
        receiver = data.get('receiver')

        # Check if sender is trying to send a request to themselves
        if sender == receiver:
            raise serializers.ValidationError("You cannot send a friend request to yourself.")

        # Check if a request already exists between the sender and receiver
        if FriendRequest.objects.filter(sender=sender, receiver=receiver).exists():
            raise serializers.ValidationError("Friend request already sent to this user.")

        # Ensure that both 'accepted' and 'rejected' are not True simultaneously
        accepted = data.get('accepted', False)
        rejected = data.get('rejected', False)
        if accepted and rejected:
            raise serializers.ValidationError("A friend request cannot be both accepted and rejected.")

        return data

    def create(self, validated_data):
        # Set the sender as the logged-in user when creating the friend request
        validated_data['sender'] = self.context['request'].user
        return super().create(validated_data)


class FriendshipSerializer(serializers.ModelSerializer):
    user1 = serializers.SerializerMethodField()
    user2 = serializers.SerializerMethodField()

    class Meta:
        model = Friendship
        fields = ['id', 'user1', 'user2', 'accepted', 'created_at']
        read_only_fields = ['created_at']

  
class UserActivitySerializer(serializers.ModelSerializer):
    user = CustomUserSerializer(read_only=True) 

    class Meta:
        model = UserActivity
        fields = ['id', 'user', 'action', 'timestamp', 'details']
        read_only_fields = ['timestamp']

class UserBlockSerializer(serializers.ModelSerializer):
    blocker = CustomUserSerializer(read_only=True)  
    blocked = CustomUserSerializer(read_only=True) 

    class Meta:
        model = UserBlock
        fields = ['id', 'blocker', 'blocked', 'blocked_at']
        read_only_fields = ['blocked_at']
