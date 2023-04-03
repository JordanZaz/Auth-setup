from django.contrib.auth import get_user_model
from django.test import TestCase, RequestFactory
from django.urls import reverse
from allauth.account.models import EmailAddress
from .forms import CustomSignupForm
from .models import CustomUser
from ThreeDModeler import settings
from django.core.exceptions import ValidationError
from django.db import IntegrityError
from allauth.socialaccount.models import SocialApp, SocialAccount, SocialLogin
from allauth.socialaccount.providers.oauth2.client import OAuth2Error
from allauth.account.models import EmailConfirmation, EmailConfirmationHMAC
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.core import mail


class SignupTests(TestCase):

    def setUp(self):
        self.signup_url = reverse('account_signup')
        self.user_model = get_user_model()

    def test_signup_page_exists(self):
        response = self.client.get(self.signup_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'account/signup.html')

    def test_signup_success(self):
        data = {
            'email': 'Jordan@example.com',
            'username': 'Jordan',
            'password1': 'gF0@yorotoro',
            'password2': 'gF0@yorotoro'
        }
        form = CustomSignupForm(data=data)
        if form.errors:
            print(form.errors)
        self.assertTrue(form.is_valid())

        request = RequestFactory().post(self.signup_url, data=data)
        request.session = {}
        user = form.save(request=request)

        self.assertEqual(user.email, 'jordan@example.com')
        self.assertEqual(user.username, 'Jordan')
        self.assertTrue(user.check_password('gF0@yorotoro'))
        email_address = EmailAddress.objects.get(user=user)
        self.assertFalse(email_address.verified)
        self.assertEqual(self.user_model.objects.count(), 1)
        print("Number of user objects in the database:",
              self.user_model.objects.count())
        print(self.user_model.objects.first())

    def test_signup_missing_username(self):
        data = {
            'email': 'jordan@example.com',
            'username': '',
            'password1': 'gF0@yorotoro',
            'password2': 'gF0@yorotoro'
        }
        form = CustomSignupForm(data=data)
        self.assertFalse(form.is_valid())
        response = self.client.post(self.signup_url, data)
        self.assertIn('username', form.errors)
        self.assertContains(response, 'This field is required.')

    def test_signup_missing_email(self):
        data = {
            'email': '',
            'username': 'testuser',
            'password1': 'gF0@yorotoro',
            'password2': 'gF0@yorotoro'
        }
        form = CustomSignupForm(data=data)
        self.assertFalse(form.is_valid())
        response = self.client.post(self.signup_url, data)
        self.assertIn('email', form.errors)
        self.assertContains(response, 'This field is required.')

    def test_signup_missing_password(self):
        data = {
            'email': 'jordan@example.com',
            'username': 'testuser',
            'password1': '',
            'password2': ''
        }
        form = CustomSignupForm(data=data)
        self.assertFalse(form.is_valid())
        response = self.client.post(self.signup_url, data)
        self.assertIn('password1', form.errors)
        self.assertContains(response, 'This field is required.')

    def test_signup_password_mismatch(self):
        data = {
            'email': 'test@example.com',
            'username': 'testuser',
            'password1': 'Fa4#asdogtof',
            'password2': 'jJ4^jhutolan'
        }
        response = self.client.post(self.signup_url, data)
        self.assertEqual(response.status_code, 200)
        self.assertContains(
            response, 'You must type the same password each time.')

    def test_signup_existing_email(self):
        user = self.user_model.objects.create_user(
            email='test@example.com',
            username='testuser1',
            password='pAssw0rd123'
        )
        data = {
            'email': 'test@example.com',
            'username': 'newuser',
            'password1': 'pAssw0rd123',
            'password2': 'pAssw0rd123'
        }
        response = self.client.post(self.signup_url, data)
        self.assertEqual(response.status_code, 200)
        self.assertContains(
            response, 'Email is already taken.')

    def test_signup_existing_username(self):
        user = self.user_model.objects.create_user(
            email='test@example.com',
            username='testuser',
            password='pAssw0rd123'
        )
        data = {
            'email': 'test2@example.com',
            'username': 'testuser',
            'password1': 'pAssw0rd123',
            'password2': 'pAssw0rd123'
        }
        response = self.client.post(self.signup_url, data)
        self.assertEqual(response.status_code, 200)
        self.assertContains(
            response, 'Username is already taken.')

    def test_signup_invalid_email(self):
        data = {
            'email': 'invalid-email',
            'username': 'testuser',
            'password1': 'pAssw0rd123',
            'password2': 'pAssw0rd123'
        }
        response = self.client.post(self.signup_url, data)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Enter a valid email address.')

    def test_signup_username_too_long(self):
        data = {
            'email': 'test@example.com',
            # 'username': 'WrjgH1m63FOQ3ETSAM3XpUjV0P2rHaIMqQvVIZzhUJ2hn1FaBSZ',
            'username': 'mbudxmeqdyyfwqxjghxxvvfgaywcaxa',
            'password1': 'pAssw0rd123',
            'password2': 'pAssw0rd123'
        }
        response = self.client.post(self.signup_url, data)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Username is too long.')

    def test_signup_password_too_short(self):
        data = {
            'email': 'test@example.com',
            'username': 'testuser',
            'password1': 'shortpw',
            'password2': 'shortpw'
        }
        response = self.client.post(self.signup_url, data)
        self.assertEqual(response.status_code, 200)
        self.assertContains(
            response, 'Password length should be between 10 and 30 characters.')

    def test_signup_password_missing_criteria(self):
        data = {
            'email': 'test@example.com',
            'username': 'testuser',
            'password1': 'passwordwithoutcriteria',
            'password2': 'passwordwithoutcriteria'
        }
        response = self.client.post(self.signup_url, data)
        self.assertEqual(response.status_code, 200)
        # self.assertContains(
        #     response, 'The password is too similar to the email.')
        self.assertContains(
            response, 'This password must contain at least 1 uppercase letter(s).')
        self.assertContains(
            response, 'This password must contain at least 1 digit(s).')
        self.assertContains(
            response, 'This password must contain at least 1 special character(s).')

    def test_signup_common_password(self):
        data = {
            'email': 'test@example.com',
            'username': 'testuser',
            'password1': 'password12',
            'password2': 'password12'
        }
        response = self.client.post(self.signup_url, data)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'This password is too common.')

    def test_signup_password_too_similar(self):
        data = {
            'email': 'test@example.com',
            'username': 'testuser',
            'password1': 'aaabbbcccddd',
            'password2': 'aaabbbcccddd'
        }
        response = self.client.post(self.signup_url, data)
        self.assertEqual(response.status_code, 200)
        self.assertContains(
            response, 'This password contains too many similar characters.')

    def test_signup_password_too_long(self):
        data = {
            'email': 'test@example.com',
            'username': 'testuser',
            'password1': 'a' * 129,
            'password2': 'a' * 129
        }
        response = self.client.post(self.signup_url, data)
        self.assertEqual(response.status_code, 200)
        self.assertContains(
            response, 'Password length should be between 10 and 30 characters.')

    def test_signup_username_special_chars_or_spaces(self):
        data = {
            'email': 'test@example.com',
            'username': ' Test#^?',
            'password1': ';un#5Lubw8%7',
            'password2': ';un#5Lubw8%7'
        }
        response = self.client.post(self.signup_url, data)
        # print(response.content.decode())
        self.assertEqual(response.status_code, 200)
        self.assertContains(
            response, 'Enter a valid username. This value may contain only letters, numbers, and @/./+/-/_ characters.')

        data = {
            'email': 'test@example.com',
            'username': ' d  testuser',
            'password1': ';un#5Lubw8%7',
            'password2': ';un#5Lubw8%7'
        }
        response = self.client.post(self.signup_url, data)
        # print(response.content.decode())
        user = CustomUser.objects.filter(username='testuser').first()
        if user:
            print("The created username is:", user.username)
        else:
            print("User with the given username was not created.")
        self.assertEqual(response.status_code, 200)
        self.assertContains(
            response, 'Enter a valid username. This value may contain only letters, numbers, and @/./+/-/_ characters.')

    def test_signup_email_already_verified(self):
        user = self.user_model.objects.create_user(
            email='test@example.com',
            username='testuser',
            password='pAssw0rd123@'
        )
        email_address = EmailAddress.objects.create(
            user=user,
            email=user.email,
            verified=True
        )
        data = {
            'email': 'test@example.com',
            'username': 'newuser',
            'password1': 'pAssw0rd123@',
            'password2': 'pAssw0rd123@'
        }
        response = self.client.post(self.signup_url, data)
        self.assertEqual(response.status_code, 200)
        self.assertContains(
            response, 'Email is already taken.')

    def test_signup_email_already_associated_with_existing_account(self):
        user = self.user_model.objects.create_user(
            email='test@example.com',
            username='testuser1',
            password='jJ4^jhutolan'
        )
        email_address = EmailAddress.objects.create(
            user=user,
            email=user.email,
            verified=False
        )
        data = {
            'email': 'test@example.com',
            'username': 'newuser',
            'password1': 'jJ4^jhutolan',
            'password2': 'jJ4^jhutolan'
        }

        response = self.client.post(self.signup_url, data)
        self.assertEqual(response.status_code, 200)
        self.assertContains(
            response, 'Email is already taken.')

    def test_signup_page_redirects_to_correct_page(self):
        data = {
            'email': 'user@example.com',
            'username': 'userBob',
            'password1': 'jJ4^jhutolan',
            'password2': 'jJ4^jhutolan'
        }

        form = CustomSignupForm(data=data)
        self.assertTrue(form.is_valid())

        response = self.client.post(self.signup_url, data=data)
        user = self.user_model.objects.first()

        expected_url = '/accounts/confirm-email/'

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, '/profile/')
        self.assertEqual(user.email, 'user@example.com')
        self.assertEqual(user.username, 'userBob')
        self.assertTrue(user.check_password('jJ4^jhutolan'))
        email_address = EmailAddress.objects.get(user=user)
        self.assertFalse(email_address.verified)
        self.assertEqual(self.user_model.objects.count(), 1)
        print("Number of user objects in the database:",
              self.user_model.objects.count())
        print(self.user_model.objects.first())

    def test_signup_with_uppercase_email(self):
        data = {
            'email': 'User@EXAMPLE.COM',
            'username': 'user',
            'password1': 'jJ4^jhutolan',
            'password2': 'jJ4^jhutolan'
        }
        form = CustomSignupForm(data=data)
        self.assertTrue(form.is_valid())

        response = self.client.post(self.signup_url, data=data)
        user = self.user_model.objects.first()

        expected_url = '/accounts/confirm-email/'

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, '/profile/')
        self.assertEqual(user.email, 'user@example.com')
        self.assertEqual(user.username, 'user')
        self.assertTrue(user.check_password('jJ4^jhutolan'))
        email_address = EmailAddress.objects.get(user=user)
        self.assertFalse(email_address.verified)
        self.assertEqual(self.user_model.objects.count(), 1)
        print("Number of user objects in the database:",
              self.user_model.objects.count())
        print(self.user_model.objects.first())

    def test_signup_username_already_taken_case_insensitive(self):
        user = self.user_model.objects.create_user(
            email='user@example.com',
            username='testuser',
            password='jJ4^jhutolan'
        )
        data = {
            'email': 'test@example.com',
            'username': 'TESTuser',
            'password1': 'jJ4^jhutolan',
            'password2': 'jJ4^jhutolan'
        }
        response = self.client.post(self.signup_url, data)
        self.assertContains(response, 'Username is already taken.')
        self.assertEqual(self.user_model.objects.count(), 1)

    def test_signup_username_already_taken_case_insensitive1(self):
        user = self.user_model.objects.create_user(
            email='user@example.com',
            username='testuser',
            password='jJ4^jhutolan'
        )
        data = {
            'email': 'test@example.com',
            'username': 'TESTuser',
            'password1': 'jJ4^jhutolan',
            'password2': 'jJ4^jhutolan'
        }
        form = CustomSignupForm(data=data)

        # manually call the clean method of a CustomUser instance
        user = CustomUser(username='TESTuser')
        try:
            user.clean()
        except ValidationError as e:
            print(e.message)
        self.assertEqual(self.user_model.objects.count(), 1)

    def test_signup_password_similar_to_email_or_username(self):
        data = {
            'email': 'johndoe@example.com',
            'username': 'johndoe',
            'password1': 'doe1john23S#',
            'password2': 'doe1john23S#'
        }
        response = self.client.post(self.signup_url, data)
        self.assertContains(
            response, 'The password is too similar to the email.')
        self.assertEqual(self.user_model.objects.count(), 0)

    def test_signup_password_contains_username(self):
        data = {
            'email': 'user@example.com',
            'username': 'Jordanz',
            'password1': 'Jordanz#21',
            'password2': 'Jordanz#21'
        }
        response = self.client.post(self.signup_url, data)
        self.assertContains(
            response, 'The password is too similar to the username.')
        self.assertEqual(self.user_model.objects.count(), 0)

    def test_signup_password_validators(self):
        data = {
            'email': 'user@example.com',
            'username': 'user',
            'password1': 'userE!xample99',
            'password2': 'userE!xample99'
        }
        response = self.client.post(self.signup_url, data)
        self.assertEqual(response.status_code, 200)
        self.assertFormError(
            response, 'form', 'password1', 'The password is too similar to the email.')
        self.assertFormError(
            response, 'form', 'password1', 'The password is too similar to the email.')
        self.assertEqual(self.user_model.objects.count(), 0)

    def test_xss_protection(self):
        data = {
            'email': 'xss@example.com',
            'username': '<script>alert("XSS")</script>',
            'password1': 'gF0@yorotoro',
            'password2': 'gF0@yorotoro'
        }
        form = CustomSignupForm(data=data)
        self.assertFalse(form.is_valid())
        self.assertIn('username', form.errors)
        print(form.errors)

    def test_sql_injection_protection(self):
        data = {
            'email': 'sqlinjection@example.com',
            'username': "testuser' OR 1=1;--",
            'password1': 'gF0@yorotoro',
            'password2': 'gF0@yorotoro'
        }
        form = CustomSignupForm(data=data)
        self.assertFalse(form.is_valid())
        self.assertIn('username', form.errors)
        print(form.errors)


class CustomUserModelTests(TestCase):
    def setUp(self):
        # Create a user for testing
        self.user = CustomUser.objects.create_user(
            username='testuser',
            email='testuser@example.com',
            password='jJ4^jordanzhutolan'
        )

    def test_unique_email_constraint(self):
        # Attempt to create another user with the same email
        with self.assertRaises(IntegrityError):
            CustomUser.objects.create_user(
                username='testuser2',
                email='testuser@example.com',
                password='jJ4^jordanzhutolan'
            )

    def test_invalid_email_addresses(self):
        # Test for handling of invalid email addresses
        form = CustomSignupForm(data={
            'username': 'testuser2',
            'email': 'invalid email',
            'password1': 'jJ4^jordanzhutolan',
            'password2': 'jJ4^jordanzhutolan',
        })
        self.assertFalse(form.is_valid())
        self.assertIn('email', form.errors)

        form = CustomSignupForm(data={
            'username': 'testuser3',
            'email': 'testr3@example.',
            'password1': 'jJ4^jhutolan',
            'password2': 'jJ4^jhutolan',
        })
        self.assertFalse(form.is_valid())
        self.assertIn('email', form.errors)

        form = CustomSignupForm(data={
            'username': 'testuser5',
            'email': ' testr3@.ca',
            'password1': 'jJ4^jhutolan',
            'password2': 'jJ4^jhutolan',
        })
        self.assertFalse(form.is_valid())
        self.assertIn('email', form.errors)

    def test_unusual_usernames(self):
        # Test for handling of unusual usernames
        form = CustomSignupForm(data={
            'username': '  testuser',
            'email': 'testuser2@example.com',
            'password1': ';un#5Lubw8%7',
            'password2': ';un#5Lubw8%7',
        })
        # print(form.errors)
        self.assertFalse(form.is_valid())
        self.assertIn('username', form.errors)

        form = CustomSignupForm(data={
            'username': 'testuser\xF1o',
            'email': 'testuser3@example.com',
            'password1': ';un#5Lubw8%7',
            'password2': ';un#5Lubw8%7',
        })
        # print(form.errors)
        self.assertFalse(form.is_valid())
        self.assertIn('username', form.errors)

    def test_clean_method_duplicate_username(self):
        # Test for behavior of the clean method when username is not unique
        form = CustomSignupForm(data={
            'username': 'testuser',
            'email': 'testuser3@example.com',
            'password1': 'jJ4^jordanzhutolan',
            'password2': 'jJ4^jordanzhutolan',
        })
        self.assertFalse(form.is_valid())
        self.assertIn('username', form.errors)


class SignInTests(TestCase):
    def setUp(self):
        # Create a user for testing
        self.user = CustomUser.objects.create_user(
            username='testuser',
            email='testuser@example.com',
            password='jJ4^jordanzhutolan'
        )

    def test_signin_success(self):
        self.user.is_active = True
        self.user.save()

        # Log the user in
        response = self.client.post(
            '/accounts/login/', {'login': 'testuser@example.com', 'password': 'jJ4^jordanzhutolan'})

        # Check if the user is logged in and redirected to the profile page
        self.assertRedirects(response, '/profile/')

    def test_signin_invalid_credentials(self):
        self.user.is_active = True
        self.user.save()

        # Log the user in with incorrect credentials
        response = self.client.post(
            '/accounts/login/', {'login': 'testuser@example.com', 'password': 'WrongPassword'})

        # Check if an error message is displayed
        self.assertContains(
            response, 'The e-mail address and/or password you specified are not correct.')

    def test_signin_unverified_account(self):
        self.user.is_active = False
        self.user.save()

        # Log the user in
        response = self.client.post(
            '/accounts/login/', {'login': 'testuser@example.com', 'password': 'jJ4^jordanzhutolan'})

        # Check if an error message is displayed
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, '/accounts/inactive/')


class PasswordResetTests(TestCase):
    def setUp(self):
        # Create a user for testing
        self.user = CustomUser.objects.create_user(
            username='testuser',
            email='testuser@example.com',
            password='jJ4^jordanzhutolan'
        )

    def test_send_password_reset_email(self):
        response = self.client.post(
            '/accounts/password/reset/', {'email': 'testuser@example.com'})
        self.assertEqual(response.status_code, 302)
        self.assertIn('/accounts/password/reset/done/', response.url)

    # def test_successful_password_reset(self):
    #     # Request password reset
    #     self.client.post('/accounts/password/reset/',
    #                      {'email': 'testuser@example.com'})

    #     # Get reset token
    #     token_generator = PasswordResetTokenGenerator()
    #     reset_token = token_generator.make_token(self.user)

    #     # Reset password with mismatched passwords
    #     response = self.client.post(f'/accounts/password/reset/key/{urlsafe_base64_encode(force_bytes(self.user.pk))}-{reset_token}/', {
    #         'password1': 'jJ4^jordanzhutolann',
    #         'password2': 'jJ4^jordanzhutolann',
    #     }, follow=True)

    #     # self.assertContains(
    #     #     response, 'Password successfully changed.')

    #     # Check if the user's password remains unchanged
    #     self.user.refresh_from_db()
    #     self.user.save()
    #     self.assertTrue(self.user.check_password('jJ4^jordanzhutolann'))

    def test_unsuccessful_password_reset(self):
        # Request password reset
        self.client.post('/accounts/password/reset/',
                         {'email': 'testuser@example.com'})

        # Get reset token
        token_generator = PasswordResetTokenGenerator()
        reset_token = token_generator.make_token(self.user)

        # Reset password with mismatched passwords
        response = self.client.post(f'/accounts/password/reset/key/{urlsafe_base64_encode(force_bytes(self.user.pk))}-{reset_token}/', {
            'password1': 'NewPass123!',
            'password2': 'NewPass321!',
        }, follow=True)

        self.assertContains(
            response, 'The password reset link was invalid, possibly because it has already been used.  Please request a <a href="/accounts/password/reset/">new password reset')

        # Check if the user's password remains unchanged
        # print(response.content)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('jJ4^jordanzhutolan'))


from django.utils import timezone
from allauth.account.models import EmailAddress, EmailConfirmation


class EmailConfirmationTestCase(TestCase):
    def setUp(self):
        self.user = CustomUser.objects.create_user(
            username='testuser',
            email='testuser@example.com',
            password='Thechumby69!'
        )
        self.email_address = EmailAddress.objects.create(
            user=self.user,
            email='testuser@example.com',
            primary=True,
            verified=False
        )
        self.client.force_login(self.user)

    def test_successful_email_confirmation(self):
        # Get confirmation token
        confirmation_token = EmailConfirmation.create(self.email_address)
        confirmation_token.sent = timezone.now()
        confirmation_token.save()

        # Confirm email
        url = reverse('account_confirm_email', args=[confirmation_token.key])
        response = self.client.get(url)

        # Assert
        self.assertEqual(response.status_code, 200)
        self.assertContains(
            response, 'Please confirm that <a href="mailto:testuser@example.com">testuser@example.com</a> is an e-mail address for user testuser.')

    def test_unsuccessful_email_confirmation(self):
        # Get confirmation token
        confirmation_token = EmailConfirmation.create(self.email_address)
        confirmation_token.sent = timezone.now()
        confirmation_token.save()

        # Invalidate the token
        invalid_key = 'invalid-key'

        # Try to confirm email with invalid token
        url = reverse('account_confirm_email', args=[invalid_key])
        response = self.client.get(url)

        # Assert
        print(response.content)
        self.assertEqual(response.status_code, 200)
        self.assertContains(
            response, 'This e-mail confirmation link expired or is invalid. Please <a href="/accounts/email/">issue a new e-mail confirmation request</a>.')


class ProfileDeletionTests(TestCase):
    def setUp(self):
        self.user = CustomUser.objects.create_user(
            username='testuser',
            email='testuser@example.com',
            password='jJ4^jordanzhutolan'
        )
        self.client.force_login(self.user)

    def test_profile_deletion(self):
        response = self.client.post(reverse('delete_account'))
        self.assertEqual(response.status_code, 302)
        self.assertFalse(CustomUser.objects.filter(
            username='testuser').exists())

    def test_deleted_profile_inaccessible(self):
        self.client.post(reverse('delete_account'))
        self.client.logout()

        response = self.client.post(
            '/accounts/login/', {'login': 'testuser@example.com', 'password': 'jJ4^jordanzhutolan'})

        # print(response.content)
        self.assertContains(
            response, 'The e-mail address and/or password you specified are not correct.')


class UsernameChangeTests(TestCase):
    def setUp(self):
        self.user = CustomUser.objects.create_user(
            username='testuser',
            email='testuser@example.com',
            password='jJ4^jordanzhutolan'
        )
        self.client.force_login(self.user)

    def test_username_change(self):
        new_username = 'new_testuser'
        response = self.client.post(reverse('change_username'), {
                                    'username': new_username})

        self.assertEqual(response.status_code, 302)
        self.user.refresh_from_db()
        self.assertEqual(self.user.username, new_username)

    def test_unique_username_validation(self):
        CustomUser.objects.create_user(
            username='existing_user',
            email='existing_user@example.com',
            password='jJ4^jordanzhutolan'
        )

        response = self.client.post(reverse('change_username'), {
                                    'username': 'existing_user'})
        self.assertEqual(response.status_code, 200)
        self.assertContains(
            response, 'Username is already taken.')

    def test_xss_protection(self):
        new_username = '<script>alert("XSS")</script>'
        response = self.client.post(reverse('change_username'), {
                                    'username': new_username})

        self.assertEqual(response.status_code, 200)
        self.assertContains(
            response, 'Enter a valid username. This value may contain only letters, numbers, and @/./+/-/_ characters.')

    def test_sql_injection_protection(self):
        new_username = "testuser' OR 1=1;--"
        response = self.client.post(reverse('change_username'), {
                                    'username': new_username})

        self.assertEqual(response.status_code, 200)
        self.assertContains(
            response, 'Enter a valid username. This value may contain only letters, numbers, and @/./+/-/_ characters.')
