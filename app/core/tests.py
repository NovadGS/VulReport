from django.test import TestCase
from django.urls import reverse

from .models import FriendRequest, FriendRequestStatus, User, UserRole


class FriendSystemTests(TestCase):
    def setUp(self):
        self.alice = User.objects.create_user(
            username="alice",
            email="alice@example.com",
            password="StrongPass123!",
            role=UserRole.VIEWER,
        )
        self.bob = User.objects.create_user(
            username="bob",
            email="bob@example.com",
            password="StrongPass123!",
            role=UserRole.VIEWER,
        )

    def test_profile_id_is_generated_for_each_user(self):
        self.assertTrue(self.alice.profile_id)
        self.assertTrue(self.bob.profile_id)
        self.assertNotEqual(self.alice.profile_id, self.bob.profile_id)

    def test_can_send_friend_request_by_profile_id(self):
        self.client.force_login(self.alice)

        response = self.client.post(reverse("friends"), {"profile_id": self.bob.profile_id})

        self.assertRedirects(response, reverse("friends"))
        request_obj = FriendRequest.objects.get(from_user=self.alice, to_user=self.bob)
        self.assertEqual(request_obj.status, FriendRequestStatus.PENDING)

    def test_can_accept_friend_request(self):
        request_obj = FriendRequest.objects.create(
            from_user=self.bob,
            to_user=self.alice,
            status=FriendRequestStatus.PENDING,
        )
        self.client.force_login(self.alice)

        response = self.client.post(reverse("friend_request_accept", args=[request_obj.id]))

        self.assertRedirects(response, reverse("friends"))
        request_obj.refresh_from_db()
        self.assertEqual(request_obj.status, FriendRequestStatus.ACCEPTED)
