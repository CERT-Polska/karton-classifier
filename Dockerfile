# We're using alpine because libmagic bundled in Debian is quite old (5.35)
FROM python:3.7-alpine

RUN apk add file

WORKDIR /app/service
COPY ./requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY ./README.md ./README.md
COPY ./karton ./karton
COPY ./setup.py ./setup.py
RUN pip install .
ENTRYPOINT karton-classifier
