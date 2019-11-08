FROM dr.cert.pl/karton/karton2:23212bf5e6b6c4db1eca0edf7d5baae630d8dfe0

COPY requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt
COPY . /app/service

WORKDIR /app/service
CMD python3 classifier.py
