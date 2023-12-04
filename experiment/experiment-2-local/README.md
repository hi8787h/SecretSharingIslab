# experiment-2-local 是什麼?

為了加快開發速度，所以設置了一個本機開發環境。

唯一的限制，就是不能讀取樹梅派的溫度。但不影響加解密通訊與開發。

# 我需要在哪裡編輯我的測試代碼?

請在以下目錄進行測試代碼編輯

```
experiment-2-local
    └──codes
       ├─IoT-Client (發送用的 Client 端)
       │
       └──IoT-Server (發送用的 Server 端)
```

# 如何啟動這個環境

安裝好  Dokcer 後

啟動 Docker Desktop 或者任意 Docker 環境

先cd 到這個目錄

```
cd experiment
cd experiment-2-local
```

然後用以下指令

```
docker-compose up --build -d
```

# 我該如何測試這個環境是否正確。

```
experiment-2-local
    └──codes
       ├─IoT-Client
       |    └ example.main.py (範例檔案) (請先別刪除，可以做為之後的開發參考)
       │
       └──IoT-Server
            └ example.main.py (範例檔案) (請先別刪除，可以做為之後的開發參考)
```

先cd 到這個目錄

```
cd experiment
cd experiment-2-local
```

開啟兩個終端，一個 Server 一個 Client

登入 Server 終端，並且執行 Server

```
docker-compose exec iot-server bash
python example.main.py
```

登入 Client 終端，並且執行 Client

```
docker-compose exec iot-client bash
python example.main.py
```

