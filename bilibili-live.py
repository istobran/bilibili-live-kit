#!/usr/bin/env python3
import json
import logging
import os
import re
import threading
from base64 import b64encode as base64_encode
from datetime import datetime, timedelta
from time import sleep

import requests
import rsa
from requests.utils import cookiejar_from_dict, dict_from_cookiejar

API_LIVE = 'http://live.bilibili.com'
API_LIVE_ROOM = '%s/%%s' % API_LIVE
API_LIVE_GET_USER_INFO = '%s/User/getUserInfo' % API_LIVE
API_LIVE_USER_ONLINE_HEART = '%s/User/userOnlineHeart' % API_LIVE
API_PASSPORT = 'https://passport.bilibili.com'
API_PASSPORT_GET_RSA_KEY = '%s/login?act=getkey' % API_PASSPORT
API_PASSPORT_MINILOGIN = '%s/ajax/miniLogin' % API_PASSPORT
API_PASSPORT_MINILOGIN_MINILOGIN = '%s/minilogin' % API_PASSPORT_MINILOGIN
API_PASSPORT_MINILOGIN_LOGIN = '%s/login' % API_PASSPORT_MINILOGIN


class BiliBiliPassport:
    def __init__(self, username, password, cookies_path='bilibili.passport'):
        self.session = requests.session()
        self.__cookies_load(username, cookies_path)
        if self.login(username, password):
            self.__cookies_save(username, cookies_path)
        else:
            logging.error('BiliBiliPassport#login faild')
            exit()

    def __handle_login_password(self, password):
        data = self.session.get(API_PASSPORT_GET_RSA_KEY).json()
        pub_key = rsa.PublicKey.load_pkcs1_openssl_pem(data['key'])
        encrypted = rsa.encrypt((data['hash'] + password).encode(), pub_key)
        return base64_encode(encrypted).decode()

    def login(self, username, password):
        if not self.check_login():
            self.session.get(API_PASSPORT_MINILOGIN_MINILOGIN)
            payload = {
                'keep': 1,
                'captcha': '',
                'userid': username,
                'pwd': self.__handle_login_password(password)
            }
            rasp = self.session.post(API_PASSPORT_MINILOGIN_LOGIN, data=payload)
            logging.debug('BiliBiliPassport#login rasponse: %s', rasp.json())
            return rasp.json()['status']
        return True

    def check_login(self):
        rasp = self.session.get(API_LIVE_GET_USER_INFO)
        return rasp.json()['code'] == 'REPONSE_OK'

    def __cookies_load(self, username, path):
        data = {}
        if os.path.exists(path):
            with open(path, 'r') as fp:
                data = json.load(fp)
        if data and username in data:
            self.session.cookies.update(cookiejar_from_dict(data[username]))

    def __cookies_save(self, username, path):
        data = {}
        if os.path.exists(path):
            with open(path, 'r') as fp:
                data = json.load(fp)
        with open(path, 'w') as fp:
            data[username] = dict_from_cookiejar(self.session.cookies)
            json.dump(data, fp)


class BiliBiliLive:
    def __init__(self, passport: BiliBiliPassport):
        self.passport = passport
        self.session = self.passport.session

    def send_heart(self):
        headers = {'Referer': API_LIVE_ROOM % self.get_room_id()}
        rasp = self.session.post(API_LIVE_USER_ONLINE_HEART, headers=headers)
        logging.debug('BiliBiliLive#send_heart rasponse: %s', rasp.json())
        payload = rasp.json()
        if payload['code'] != 0:
            return payload['msg']
        return True

    def get_room_id(self):
        rasponse = self.session.get(API_LIVE)
        matches = re.search(r'data-room-id="(\d+)"', rasponse.text)
        if matches:
            return matches.group(1)

    def get_user_info(self):
        rasp = self.session.get(API_LIVE_GET_USER_INFO)
        payload = rasp.json()
        logging.debug('BiliBiliLive#get_user_info rasponse: %s', payload)
        if payload['code'] == 'REPONSE_OK':
            return payload
        return False

    def print_report(self, user_info, heart_status=None):
        if not user_info:
            return
        data = user_info['data']
        upgrade_requires = data['user_next_intimacy'] - data['user_intimacy']
        upgrade_progress = data['user_intimacy'] / data['user_next_intimacy']
        upgrade_takes_time = timedelta(minutes=(upgrade_requires / 3000) * 5)
        heart_time = datetime.now()
        heart_next_time = heart_time + timedelta(minutes=5)
        items = (
            ('User name', data['uname']),
            ('Live level', data['user_level']),
            ('Upgrade requires', upgrade_requires),
            ('Upgrade takes time', upgrade_takes_time),
            ('Upgrade progress', upgrade_progress),
            ('Level rank', data['user_level_rank']),
            ('Heart status', 'Success' if heart_status else heart_status),
            ('Heart time', heart_time.isoformat()),
            ('Heart next time', heart_next_time.isoformat()),
        )
        report = '\n'.join('%20s: %s' % (name, value) for name, value in items)
        logging.info('\n%s', report)


def main():
    conf = json.load(open('configure.json'))
    logging.basicConfig(**conf['logging'])

    def send_heart(passport):
        live = BiliBiliLive(BiliBiliPassport(**passport))
        heart_status = live.send_heart()
        user_info = live.get_user_info()
        live.print_report(user_info, heart_status)

    def set_interval(func, seconds):
        def func_wrapper():
            set_interval(func, seconds)
            func()

        timer = threading.Timer(seconds, func_wrapper)
        timer.start()
        return timer

    for passport in conf['passports']:
        set_interval(lambda: send_heart(passport), 5 * 60)
        logging.info('start %(username)s', passport)
        sleep(1 * 60)


if __name__ == '__main__':
    main()
