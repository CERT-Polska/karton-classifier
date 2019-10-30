FROM dr.cert.pl/karton/karton2:latest

COPY requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt
COPY . /app/service

WORKDIR /app/service
CMD python3 classifier.py
