FROM ubuntu:latest
RUN apt-get update && \
  apt-get install -y python && \
  apt-get install -y python-pip python-dev build-essential && \
  pip install requests
EXPOSE 5000
ADD playground.py .
CMD ["/usr/bin/python","./playground.py"]