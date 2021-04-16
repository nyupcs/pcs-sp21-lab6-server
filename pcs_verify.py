import random
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import string
from time import sleep
from werkzeug.security import generate_password_hash

# Selenium
options = Options()
options.headless = True

# Random String
letters = string.ascii_lowercase


def get_random_string(length):
    return ''.join(random.choice(letters) for i in range(length))


def get_flag():
    with open("flag") as f:
        return f.readline()


def login(browser, users, username):
    password = get_random_string(16)
    users[username]['password'] = generate_password_hash(password)

    browser.get('http://127.0.0.1:4000/login')
    browser.find_element_by_name("username").send_keys(username)
    browser.find_element_by_name("password").send_keys(password)
    browser.find_element_by_tag_name("button").click()


def logout(browser):
    browser.get("http://127.0.0.1:4000/logout")


def visit(browser, url):
    browser.get(url)


def visit_html(browser, html):
    browser.get("data:text/html;charset=utf-8,{}".format(html))


def verify_profile(browser, username, text):
    browser.get("http://127.0.0.1:4000/profile/" + username)
    slogan = browser.find_element_by_class_name("profile-slogan").text

    return text in slogan, slogan


def verify_visibility(browser, username):
    browser.get("http://127.0.0.1:4000/profile/" + username)

    alerts = browser.find_elements_by_class_name('alert-warning')

    if len(alerts) > 0:
        return False, alerts[0].text
    else:
        return True, ''


# Git-CTF
flag = get_flag()


def pcs_verify(users, code1, code2):
    browser = webdriver.Chrome(chrome_options=options)

    login(browser, users, 'joe')

    visit_html(browser, code1)

    sleep(2)

    visit_html(browser, code2)

    sleep(2)

    logout(browser)

    result, msg = verify_visibility(browser, 'joe')

    if not result:
        browser.quit()
        return False, "Joe's profile is not public. Got the error message \"{}\".".format(msg)

    result, slogan = verify_profile(browser, 'joe', "Samy is my hero!")

    if not result:
        browser.quit()
        return False, "Expect \"{}\" in Joe's profile, got \"{}\" instead.".format("Samy is my hero!", slogan)

    browser.quit()
    return True, "Verified! The flag is [{}].".format(flag)
