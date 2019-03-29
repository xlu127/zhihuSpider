import requests
import json
from PIL import Image
import base64
import hmac
import time
import execjs
import copy
from fateadm_api import FateadmApi

class ZhihuSpider(object):
    def __init__(self, username, password):

        self.password = str(password)
        self.username = str(username)

        self.timestamp = str(round(time.time(), 3)).replace(".", "")

        self.url = {
            "ordinary": "https://www.zhihu.com",
            "sign_in": "https://www.zhihu.com/api/v3/oauth/sign_in",
            "captcha_url": "https://www.zhihu.com/api/v3/oauth/captcha",
        }
        self.headers = {
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.86 Safari/537.36",
        }
        self.session = requests.session()

    def parse_url(self, url, headers=None, method="get", data=None):
        '''
        :param url:
        :param method: "post", "get", "put"
        :return: None: 请求过程错误， 无返回值
        '''
        if method == "get":
            response = self.session.get(url=url, headers=headers) if headers else self.session.get(url)
        elif method == "put":
            response = self.session.put(url=url, headers=headers) if headers else self.session.get(url)
        elif method == "post":
            response = self.session.post(url=url, headers=headers, data=data)
        else:
            return None
        return response

    def auth_captcha(self, response):
        '''
        验证是否需要验证码
        :param response:
        :return: type: bool
        '''
        show_captcha = json.loads(response.text).get("show_captcha")
        return show_captcha

    def get_captcha(self, response):
        '''
        获取验证码，保存到本地
        :param response:
        :return:
        '''
        img_base64 = json.loads(response.text).get("img_base64")
        # 解码base64编码的图片
        with open("captcha.png", "wb") as f:
            f.write(base64.b64decode(img_base64))

    def auth_captcha_success(self, response):
        '''
        验证验证码是否登入成功
        :param response:
        :return:
        '''
        msg = json.loads(response.text)
        if "success" in msg:
            return True
        print(msg)
        return False

    def sign_decrypt(self):
        '''
        获取signature加密， python的hmac sha1实现
        :return:
        '''
        client_id = "c3cef7c66a1843f8b3a9e6a1e3160e20"
        grantType = "password"
        source = "com.zhihu.web"
        timestamp = self.timestamp

        h = hmac.new(key="d1b964811afb40118a12068ff74a12f4".encode(), digestmod="sha1")
        h.update((grantType + client_id + source + timestamp).encode())
        return h.hexdigest()

    def formdata_encrypt(self, data):
        '''
        加密form表单data数据
        :param data:
        :return:
        '''

        e = "&".join(["{}={}".format(key, value) for key, value in data.items()])

        with open("form_js.js", "r", encoding="utf-8") as f:
            js = f.read()
            com = execjs.compile(js)
            return com.call("Q", e)

    def login(self):
        '''
        登录
        :return:
        '''
        # 设置请求头
        headers = copy.deepcopy(self.headers)
        headers["x-zse-83"] = "3_1.1"
        headers["content-type"] = 'application/x-www-form-urlencoded'

        # 获取signature
        data = dict()

        data["client_id"] = "c3cef7c66a1843f8b3a9e6a1e3160e20"
        data["grant_type"] = "password"
        data["lang"] = "en"
        data["password"] = self.password
        data["refSource"] = "homepage"
        data["signature"] = self.sign_decrypt()
        data["source"] = "com.zhihu.web"
        data["timestamp"] = self.timestamp
        data["username"] = "%2B86" + self.username
        data["utm_source"] = ""

        encrypt = self.formdata_encrypt(data)
        self.parse_url(url=self.url.get("sign_in"), method="post", headers=headers, data=encrypt)

    def varify_login(self):
        '''
        验证登录是否成功
        :return:
        '''
        response = self.parse_url(url=self.url.get("ordinary"), headers=self.headers)
        if response.url == "https://www.zhihu.com":
            print("登入成功")
            print(requests.utils.dict_from_cookiejar(response.cookies))
            return True
        else:
            print("登录失败", response.url)
            return False

    def captcha(self):
        '''
        可改写验证码的获取方式，此处使用打码平台识别验证码
        :return:
        '''
        api = FateadmApi(app_id="", app_key="", pd_id="",
                         pd_key="")
        captcha = api.PredictFromFile("20400", "captcha.png").pred_rsp.value
        return captcha

    def varify_captcha(self):
        '''
        验证验证码
        :return:
        '''
        response = self.parse_url(self.url.get("captcha_url"), headers=self.headers, method="put")
        self.get_captcha(response)

        captcha = self.captcha()

        response = self.parse_url(self.url.get("captcha_url"), headers=self.headers, method="post",
                                  data={"input_text": captcha})
        if not self.auth_captcha_success(response):
            return self.varify_captcha()

    def login_by_cookies(self, cookies):
        '''
        使用cookie登入
        :param cookies:
        :return:
        '''
        response = self.session.get(url=self.url.get("ordinary"), headers=self.headers, cookies=cookies)
        if response.url == "https://www.zhihu.com/":
            print("登陆成功")
            return True
        else:
            print("登录失败",response.url)
            self.run()


    def run(self):
        '''
        直接登录主入口
        '''

        # 验证是否需要验证码
        show_captcha = self.auth_captcha(
            self.parse_url(url=self.url.get("captcha_url"), headers=self.headers, method="get"))
        if not show_captcha:
            self.login()

        elif show_captcha:

            self.varify_captcha()
            # 验证码登入成功
            self.login()

        # 验证登录
        self.varify_login()



if __name__ == '__main__':
    spider = ZhihuSpider("", "")
    # spider.run()
    # spider.login_by_cookies(cookies=cookies)
