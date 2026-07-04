from rest_framework.test import APITestCase, APIClient
from rest_framework import status
from django.urls import reverse
from django.contrib.auth import get_user_model

User = get_user_model()


def make_staff(**kwargs):
    defaults = dict(email="staff@example.com", password="StrongPass1!", username="staff", is_staff=True)
    defaults.update(kwargs)
    return User.objects.create_user(**defaults)


def make_user(**kwargs):
    defaults = dict(email="regular@example.com", password="StrongPass1!", username="regular", is_staff=False)
    defaults.update(kwargs)
    return User.objects.create_user(**defaults)


class LoginTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_superuser(
            full_name="admin User",
            username="admin",
            email="admin@anof.com",
            is_active=True,
            is_superuser=True,
            position="Security Engineer",
            password="admin",
        )
        self.url = reverse('login')

    def test_login_with_email_returns_200(self):
        r = self.client.post(self.url, {"email": "admin@anof.com", "password": "admin"}, format='json')
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertIn('access', r.data)

    def test_login_with_wrong_password_returns_401(self):
        r = self.client.post(self.url, {"email": "admin@anof.com", "password": "wrong"}, format='json')
        self.assertEqual(r.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_login_unknown_user_returns_401(self):
        r = self.client.post(self.url, {"email": "nobody@x.com", "password": "x"}, format='json')
        self.assertEqual(r.status_code, status.HTTP_401_UNAUTHORIZED)


class ChangePasswordTests(APITestCase):
    def setUp(self):
        self.user = make_staff(email="cp@example.com", username="cpuser")
        self.client.force_authenticate(user=self.user)
        self.url = reverse('change-password')

    def test_change_password_correct_old(self):
        r = self.client.post(self.url, {"oldpassword": "StrongPass1!", "newpassword": "NewPass99!"}, format='json')
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("NewPass99!"))

    def test_change_password_wrong_old_returns_400(self):
        r = self.client.post(self.url, {"oldpassword": "wrongold", "newpassword": "NewPass99!"}, format='json')
        self.assertEqual(r.status_code, status.HTTP_400_BAD_REQUEST)

    def test_change_password_unauthenticated_returns_401(self):
        self.client.logout()
        r = self.client.post(self.url, {"oldpassword": "x", "newpassword": "y"}, format='json')
        self.assertEqual(r.status_code, status.HTTP_401_UNAUTHORIZED)
