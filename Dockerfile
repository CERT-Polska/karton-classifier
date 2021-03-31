# We're using alpine because libmagic bundled in Debian is quite old (5.35)
FROM python:3.7-alpine

RUN apk add libmagic

WORKDIR /app/service
COPY ./requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY ./karton ./karton
COPY ./setup.py ./setup.py
RUN pip install .
ENTRYPOINT karton-classifier
