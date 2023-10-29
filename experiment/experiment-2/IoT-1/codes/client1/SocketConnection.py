import socket

class SocketConnection:
    @staticmethod
    def send_data(host:str, port:int, data:bytes):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((host, port))
            s.sendall(data)
            s.close()
    @staticmethod
    def receive_data(HOST, PORT):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((HOST, PORT))
            s.listen()
            conn, addr = s.accept()
            data = bytes()
            with conn:
                print(f"[Server] Client IP: {addr}")
                while True:
                    temp_data = conn.recv(1024)
                    data += temp_data
                    if not temp_data:
                        break
            print("[Server] Data length: ", len(data))
            s.close()
            return data
