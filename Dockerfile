### THIS FILE IS AUTOMATICALLY GENERATED BY COB
### DO NOT EDIT THIS FILE DIRECTLY

FROM ubuntu:latest

ENV PYTHON_VERSION=3.6 PYTHON_EXECUTABLE=python3.6 LC_ALL=C.UTF-8 LANG=C.UTF-8 COB_IN_DOCKER=1

RUN apt-get update
RUN apt-get -y install build-essential rsync software-properties-common libpq-dev nginx curl redis-server gcc sudo libsasl2-dev libldap2-dev wget git


# nginx
RUN add-apt-repository ppa:chris-lea/nginx-devel
RUN apt-get update
RUN apt-get -y install nginx


RUN curl -sL https://deb.nodesource.com/setup_6.x | bash -
RUN apt-get -y install nodejs
RUN npm --version

RUN add-apt-repository ppa:fkrull/deadsnakes
RUN apt-get update
RUN apt-get install -y $PYTHON_EXECUTABLE $PYTHON_EXECUTABLE-dev $PYTHON_EXECUTABLE-gdbm

RUN wget https://bootstrap.pypa.io/get-pip.py -O /tmp/get-pip.py
RUN $PYTHON_EXECUTABLE /tmp/get-pip.py
RUN $PYTHON_EXECUTABLE -m pip install -U virtualenv pip setuptools













ADD . /app













WORKDIR /app


RUN $PYTHON_EXECUTABLE -m pip install cob


RUN cob -vvv bootstrap

## nginx configuration
RUN rm -rf /etc/nginx/conf.d/* /etc/nginx/sites-enabled/*



EXPOSE 80 443