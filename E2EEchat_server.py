import socket
import ssl
import threading

PORT = 1234 # 这里替换为服务器实际的通信端口
# 保存客户端的信息
clients = {}  # {session_number: [client_socket]}

def handle_client(client_socket, session_number):
    try:
        # 将客户端加入当前会话
        if session_number not in clients:
            clients[session_number] = []
        clients[session_number].append(client_socket)

        client_count = len(clients[session_number])
        print(f"有客户端加入会话 {session_number}，当前人数: {client_count}")

        # 通知所有客户端当前的连接状态
        for other_socket in clients[session_number]:
            if other_socket != client_socket:
                other_socket.sendall("对方已加入，会话已建立".encode('utf-8'))
            else:
                if client_count == 1:
                    client_socket.sendall("加密通讯还未建立，请等待另一个人加入".encode('utf-8'))
                elif client_count == 2:
                    client_socket.sendall("对方已加入，会话已建立".encode('utf-8'))

        # 检查会话中的客户端数量
        if client_count > 2:
            # 如果会话中已有两个客户端，拒绝新连接
            client_socket.sendall("会话已满，拒绝连接".encode('utf-8'))
            clients[session_number].remove(client_socket)
            client_socket.close()
            print(f"拒绝客户端加入会话 {session_number}，会话已满")
            return

        while True:
            try:
                message = client_socket.recv(4096)
                if not message:
                    break

                # 只有在会话中有两个客户端时才转发消息
                if len(clients[session_number]) == 2:
                    # 转发消息给另一个客户端
                    for other_socket in clients[session_number]:
                        if other_socket != client_socket:
                            other_socket.sendall(message)
                else:
                    # 如果只有一个客户端，可以选择发送提示消息
                    pass
            except Exception as e:
                print(f"转发消息时出错: {e}")
                break
    except Exception as e:
        print(f"处理客户端时发生异常: {e}")
    finally:
        # 从会话中移除客户端
        if session_number in clients and client_socket in clients[session_number]:
            clients[session_number].remove(client_socket)
            print(f"有客户端退出会话 {session_number}，当前人数: {len(clients[session_number])}")
            # 通知另一客户端连接已断开
            for other_socket in clients[session_number]:
                other_socket.sendall("对方已离开，会话断开".encode('utf-8'))
            if not clients[session_number]:
                del clients[session_number]
                print(f"会话 {session_number} 已结束")
        client_socket.close()

def start_server():
    global PORT
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="server.crt", keyfile="server.key")
    context.verify_mode = ssl.CERT_NONE  # 不要求客户端提供证书

    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_socket.bind(("0.0.0.0", PORT))
    raw_socket.listen(5)
    print("服务器已启动，等待客户端连接...")

    while True:
        try:
            client_socket, addr = raw_socket.accept()
            print(f"接受到来自 {addr} 的连接，准备进行 SSL 握手")
        except Exception as e:
            print(f"接受客户端连接时出错: {e}")
            continue  # 继续等待下一个连接

        try:
            ssl_socket = context.wrap_socket(client_socket, server_side=True)
            print(f"SSL 握手完成，与 {addr} 的安全连接已建立")
        except ssl.SSLError as e:
            print(f"SSL 握手失败，关闭连接：{e}")
            client_socket.close()
            continue  # 继续等待下一个连接
        except Exception as e:
            print(f"在 SSL 握手过程中发生未知错误：{e}")
            client_socket.close()
            continue  # 继续等待下一个连接

        try:
            # 接收会话数字
            session_number_data = ssl_socket.recv(1024).decode('utf-8')
            session_number = int(session_number_data)
            print(f"客户端 {addr} 请求加入会话 {session_number}")

            client_thread = threading.Thread(target=handle_client, args=(ssl_socket, session_number))
            client_thread.start()
        except Exception as e:
            print(f"处理客户端连接时出错：{e}")
            ssl_socket.close()

start_server()
