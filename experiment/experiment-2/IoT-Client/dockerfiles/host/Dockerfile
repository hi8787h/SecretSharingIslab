FROM python:3.10-bullseye

RUN apt-get update -y 
RUN apt-get install -y iputils-ping net-tools
RUN apt-get install lgpio

RUN pip install pycryptodome
# check temperature of IoT
RUN pip install gpiozero
RUN pip install psutil
RUN pip install RPi.GPIO