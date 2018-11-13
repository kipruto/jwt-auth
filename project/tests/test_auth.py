import unittest
import time
import json
from project.server import db
from project.server.models import User, BlacklistToken
from project.tests.base import BaseTestCase


def register_user(self, email, password):
        return self.client.post(
            '/auth/register',
            data=json.dumps(dict(
                email=email,
                password=password
            )),
            content_type='application/json',
        )


def user_login(self, email, password):
    return self.client.post(
        '/auth/login',
        data=json.dumps(dict(
            email='joe@gmail.com',
            password='123456'
        )),
        content_type='application/json'
    )


def user_login_status(self, email, password):
    return self.client.get(
        '/auth/status',
        headers=dict(
            Authorization='Bearer ' + json.loads(
                register_user(self, email, password).data.decode()
            )['auth_token']
        )
    )


def user_logout(self, email, password):
    # register_user(self, email, password)
    user_login(self, email, password)
    return self.client.post(
        '/auth/logout',
        headers=dict(
            Authorization='Bearer ' + json.loads(
                user_login(self, email, password).data.decode()
            )['auth_token']
        )
    )


def get_login_user(self, email, password):
    return self.client.get(
        '/auth/status',
        headers=dict(
            Authorization='Bearer' + json.loads(
                register_user(self, email, password).data.decode()
            )['auth_token']
        )
    )


class TestAuthBlueprint(BaseTestCase):
    def test_registration(self):
        """ Test user registration """
        with self.client:
            response = register_user(self, 'joe@gmail.com', '123456')
            data = json.loads(response.data.decode())
            self.assertTrue(data['status'] == 'success')
            self.assertTrue(data['message'] == 'Successfully registered.')
            self.assertTrue(data['auth_token'])
            self.assertTrue(response.content_type == 'application/json')
            self.assertEqual(response.status_code, 201)

    def test_registered_with_already_registered_user(self):
        """ Test registration attempt with an already registered email"""
        user = User(
            email='joe@gmail.com',
            password='test'
        )
        db.session.add(user)
        db.session.commit()
        with self.client:
            response = register_user(self, 'joe@gmail.com', '123456')
            data = json.loads(response.data.decode())
            self.assertTrue(data['status'] == 'fail')
            self.assertTrue(
                data['message'] == 'User already exists. Please Log in.')
            self.assertTrue(response.content_type == 'application/json')
            self.assertEqual(response.status_code, 202)

    def test_registered_user_login(self):
        """ Test registered user login """
        with self.client:
            # user registration
            resp_register = register_user(self, 'joe@gmail.com', '123456')
            data_register = json.loads(resp_register.data.decode())
            self.assertTrue(data_register['status'] == 'success')
            self.assertTrue(
                data_register['message'] == 'Successfully registered.'
            )
            self.assertTrue(data_register['auth_token'])
            self.assertTrue(resp_register.content_type == 'application/json')
            self.assertEqual(resp_register.status_code, 201)
            # registered user login
            response = user_login(self, 'joe@gmail.com', '123456')
            data = json.loads(response.data.decode())
            self.assertTrue(data['status'] == 'success')
            self.assertTrue(data['message'] == 'Successfully logged in.')
            self.assertTrue(data['auth_token'])
            self.assertTrue(response.content_type == 'application/json')
            self.assertEqual(response.status_code, 200)


    def test_non_registered_user_login(self):
        """ Test non-registered user login """
        with self.client:
            response = response = user_login(self, 'joe@gmail.com', '123456')
            data = json.loads(response.data.decode())
            self.assertTrue(data['status'] == 'fail')
            self.assertTrue(data['message'] == 'User does not exist.')
            self.assertTrue(response.content_type == 'application/json')
            self.assertEqual(response.status_code, 404)

    def test_user_status(self):
        """ Test user login status """
        with self.client:
            response = user_login_status(self, 'joe@gmail.com', '123456')
            data = json.loads(response.data.decode())
            self.assertTrue(data['status'] == 'success')
            self.assertTrue(data['data'] is not None)
            self.assertTrue(data['data']['email'] == 'joe@gmail.com')
            self.assertTrue(data['data']['admin'] is 'true' or 'false')
            self.assertEqual(response.status_code, 200)

    def test_valid_logout(self):
        """ Test user logout before token expires """
        with self.client:
            register_user(self, 'joe@gmail.com', '123456')
            response = user_logout(self, 'joe@gmail.com', '123456')
            data = json.loads(response.data.decode())
            self.assertTrue(data['status'] == 'success')
            self.assertTrue(data['message'] == 'Successfully logged out.')
            self.assertEqual(response.status_code, 200)

    def test_invalid_logout(self):
        """ Testing logout after the token expires """
        with self.client:
            register_user(self, 'joe@gmail.com', '123456')
            login = user_login(self, 'joe@gmail.com', '123456')

            # invalid token logout
            time.sleep(6)
            response = self.client.post(
                '/auth/logout',
                headers=dict(
                    Authorization='Bearer ' + json.loads(
                        login.data.decode()
                    )['auth_token']
                )
            )
            data = json.loads(response.data.decode())
            self.assertTrue(data['status'] == 'fail')
            self.assertTrue(
                data['message'] == 'Signature expired. Please log in again.')
            self.assertEqual(response.status_code, 401)

    def test_valid_blacklisted_token_logout(self):
        """ Test for logout after a valid token gets blacklisted """
        with self.client:
            register_user(self, 'joe@gmail.com', '123456')
            blacklist_token = BlacklistToken(
                token=json.loads(user_login(self, 'joe@gmail.com', '123456').data.decode())['auth_token'])
            db.session.add(blacklist_token)
            db.session.commit()
            # blacklisted valid token logout
            response = user_logout(self, 'joe@gmail.com', '123456')
            data = json.loads(response.data.decode())
            self.assertTrue(data['status'] == 'fail')
            self.assertTrue(data['message'] == 'Token blacklisted. Please log in again.')
            self.assertEqual(response.status_code, 401)

    def test_valid_blacklisted_token_user(self):
        """ Test for user status with a blacklisted valid token """
        with self.client:
            user = register_user(self, 'joe@gmail.com', '123456')
            # blacklist a valid token
            blacklist_token = BlacklistToken(
                token=json.loads(user.data.decode())['auth_token'])
            db.session.add(blacklist_token)
            db.session.commit()
            response = self.client.get(
                '/auth/status',
                headers=dict(
                    Authorization='Bearer ' + json.loads(
                        user.data.decode()
                    )['auth_token']
                )
            )
            data = json.loads(response.data.decode())
            self.assertTrue(data['status'] == 'fail')
            self.assertTrue(data['message'] == 'Token blacklisted. Please log in again.')
            self.assertEqual(response.status_code, 401)


    def test_user_status_malformed_bearer_token(self):
        """ Test for user status with invalid bearer token"""
        with self.client:
            # user = register_user(self, 'joe@gmail.com', '123456')
            response = get_login_user(self, 'joe@gmail.com', '123456')
            data = json.loads(response.data.decode())
            self.assertTrue(data['status'] == 'fail')
            self.assertTrue(data['message'] == 'Bearer token malformed.')
            self.assertEqual(response.status_code, 401)



if __name__ == '__main__':
    unittest.main()
