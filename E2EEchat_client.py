import socket
import ssl
import threading
import tkinter as tk
from tkinter import simpledialog
import os
import json
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization, hashes, padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

PORT = 1234  # 这里替换成服务端实际的端口
HOST = "example.com"  # 这里替换为服务器实际的地址

# 服务器证书内容，嵌入到代码中，全局定义，确保没有缩进
server_cert = """
-----BEGIN CERTIFICATE-----
这里替换为服务器的公钥，可以使用openssl在服务器上生成
-----END CERTIFICATE-----
"""


class SecureChatClient:
    def __init__(self, master):
        self.master = master
        self.master.title("安全聊天客户端")

        self.text_area = tk.Text(master, wrap=tk.WORD, state='disabled', width=50, height=20)
        self.text_area.grid(column=0, row=0, padx=10, pady=10, columnspan=2)

        self.message_entry = tk.Entry(master, width=40, state='disabled')  # 初始时禁用输入框
        self.message_entry.grid(column=0, row=1, padx=10, pady=10)

        self.send_button = tk.Button(master, text="发送", command=self.send_message, state='disabled')  # 初始时禁用发送按钮
        self.send_button.grid(column=1, row=1, padx=10, pady=10)

        self.client_socket = None
        self.session_number = None
        self.running = True  # 用于控制接收线程的循环

        # 加密相关变量
        self.private_key = None
        self.public_key = None
        self.public_key_pem = None
        self.other_public_key = None
        self.aes_key = None
        self.is_initiator = False  # 是否为会话的发起者

        # 绑定 Enter 键事件到消息输入框
        self.message_entry.bind('<Return>', self.send_message_event)

        # 初始化时连接到服务器
        self.connect_to_server()

        # 监听窗口关闭事件
        self.master.protocol("WM_DELETE_WINDOW", self.on_closing)

    def connect_to_server(self):
        """连接服务器"""
        global HOST, PORT
        # 让用户输入会话数字
        self.session_number = simpledialog.askinteger("输入会话数字", "请输入1-9999的会话数字:")

        if self.session_number is None or not (1 <= self.session_number <= 9999):
            self.display_message("无效的会话数字")
            return

        raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # 使用 cadata 参数加载嵌入的证书
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cadata=server_cert)
        context.check_hostname = False

        self.client_socket = context.wrap_socket(raw_socket, server_hostname=HOST)

        try:
            self.client_socket.connect((HOST, PORT))
            # 发送会话数字
            self.client_socket.sendall(str(self.session_number).encode('utf-8'))

            # 生成RSA密钥对
            self.generate_rsa_keys()

            # 启动接收线程并设置为守护线程
            receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
            receive_thread.start()
        except Exception as e:
            self.display_message(f"连接服务器失败: {e}")
            return

    def generate_rsa_keys(self):
        """生成RSA密钥对"""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        self.public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

    def receive_messages(self):
        """接收服务器的消息"""
        while self.running:
            try:
                message = self.client_socket.recv(4096).decode('utf-8')
                if not message:
                    break

                # 尝试解析为JSON格式
                try:
                    message_json = json.loads(message)
                    message_type = message_json.get('type')
                    data = message_json.get('data')

                    if message_type == 'PUBLIC_KEY':
                        # 接收到对方的公钥
                        self.other_public_key_pem = data
                        self.other_public_key = serialization.load_pem_public_key(
                            data.encode('utf-8'),
                            backend=default_backend()
                        )
                        self.display_message("已接收到对方的公钥")

                        # 如果自己是发起者，生成AES密钥并发送给对方
                        if self.is_initiator:
                            self.generate_and_send_aes_key()
                    elif message_type == 'AES_KEY':
                        # 接收到对方发送的AES密钥
                        if self.aes_key is None:
                            encrypted_aes_key = base64.b64decode(data)
                            self.aes_key = self.private_key.decrypt(
                                encrypted_aes_key,
                                asym_padding.OAEP(
                                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                                    algorithm=hashes.SHA256(),
                                    label=None
                                )
                            )
                            self.display_message("已接收到AES密钥")
                        else:
                            self.display_message("已忽略重复的AES密钥")
                    elif message_type == 'MESSAGE':
                        # 接收到加密的聊天消息
                        self.decrypt_and_display_message(data)
                    else:
                        # 未知类型的消息
                        self.display_message(f"未知消息类型: {message}")
                except json.JSONDecodeError:
                    # 非JSON格式的消息，处理服务器发送的控制消息
                    if message == "会话已满，拒绝连接":
                        self.display_message("服务器: 会话已满，拒绝连接")
                        self.client_socket.close()
                        break
                    elif message == "加密通讯还未建立，请等待另一个人加入":
                        self.display_message("服务器: 加密通讯还未建立，请等待另一个人加入")
                        # 禁用输入框和发送按钮
                        self.message_entry.config(state='disabled')
                        self.send_button.config(state='disabled')
                        self.is_initiator = True  # 第一个加入的客户端为发起者
                    elif message == "对方已加入，会话已建立":
                        self.display_message("服务器: 对方已加入，会话已建立")
                        # 启用输入框和发送按钮
                        self.message_entry.config(state='normal')
                        self.send_button.config(state='normal')
                        # 发送自己的公钥
                        self.send_public_key()
                    elif message == "对方已离开，会话断开":
                        self.display_message("服务器: 对方已离开，会话断开")
                        # 禁用输入框和发送按钮
                        self.message_entry.config(state='disabled')
                        self.send_button.config(state='disabled')
                    else:
                        self.display_message(f"服务器: {message}")
            except Exception as e:
                self.display_message(f"接收消息时出错: {e}")
                break

    def send_public_key(self):
        """发送公钥给对方"""
        message = json.dumps({
            "type": "PUBLIC_KEY",
            "data": self.public_key_pem
        })
        self.client_socket.sendall(message.encode('utf-8'))
        self.display_message("已发送公钥给对方")

    def generate_and_send_aes_key(self):
        """生成AES密钥并发送给对方"""
        if self.aes_key is None and self.other_public_key is not None:
            # 生成AES密钥
            self.aes_key = os.urandom(32)
            # 使用对方的公钥加密AES密钥
            encrypted_aes_key = self.other_public_key.encrypt(
                self.aes_key,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            # 发送加密的AES密钥
            message = json.dumps({
                "type": "AES_KEY",
                "data": base64.b64encode(encrypted_aes_key).decode('utf-8')
            })
            self.client_socket.sendall(message.encode('utf-8'))
            self.display_message("已发送AES密钥给对方")

    def decrypt_and_display_message(self, encrypted_data):
        """解密并显示收到的消息"""
        if self.aes_key is None:
            self.display_message("尚未建立AES密钥，无法解密消息")
            return

        encrypted_message = base64.b64decode(encrypted_data)
        iv = encrypted_message[:16]
        ciphertext = encrypted_message[16:]

        cipher = Cipher(
            algorithms.AES(self.aes_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = sym_padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        plaintext = plaintext.decode('utf-8')

        self.display_message(f"对方: {plaintext}")

    def send_message(self):
        """发送消息"""
        message = self.message_entry.get()
        if message:
            if self.aes_key is None:
                self.display_message("尚未建立AES密钥，无法发送消息")
                return
            try:
                # 使用AES加密消息
                padder = sym_padding.PKCS7(128).padder()
                padded_data = padder.update(message.encode('utf-8')) + padder.finalize()

                iv = os.urandom(16)
                cipher = Cipher(
                    algorithms.AES(self.aes_key),
                    modes.CBC(iv),
                    backend=default_backend()
                )
                encryptor = cipher.encryptor()
                ciphertext = encryptor.update(padded_data) + encryptor.finalize()

                encrypted_message = iv + ciphertext
                encoded_message = base64.b64encode(encrypted_message).decode('utf-8')

                # 发送加密的消息
                message_json = json.dumps({
                    "type": "MESSAGE",
                    "data": encoded_message
                })
                self.client_socket.sendall(message_json.encode('utf-8'))
                self.display_message(f"我: {message}")
                self.message_entry.delete(0, tk.END)
            except Exception as e:
                self.display_message(f"发送消息时出错: {e}")

    def send_message_event(self, event):
        """处理按下 Enter 键的事件"""
        self.send_message()

    def display_message(self, message):
        """在聊天区域显示消息"""
        self.text_area.config(state='normal')
        self.text_area.insert(tk.END, message + '\n')
        self.text_area.config(state='disabled')
        self.text_area.yview(tk.END)

    def on_closing(self):
        """窗口关闭时，安全关闭Socket连接并退出程序"""
        self.running = False  # 停止接收消息的循环
        if self.client_socket:
            try:
                self.client_socket.shutdown(socket.SHUT_RDWR)
                self.client_socket.close()
            except Exception as e:
                print(f"关闭socket连接时出错: {e}")
        self.master.quit()  # 退出Tkinter主循环
        self.master.destroy()  # 销毁窗口并退出


if __name__ == "__main__":
    root = tk.Tk()
    root.resizable(False, False)  # 锁定窗口大小
    client = SecureChatClient(root)
    root.mainloop()
