FROM selenium/standalone-chrome:89.0
USER root





RUN apt-get update && apt-get install -y python3 python3-pip


COPY . /app
WORKDIR /app
RUN mkdir -p /var/ctf
COPY flag /var/ctf/
RUN pip3 install -r requirements.txt

EXPOSE 4000

CMD ["python3", "app.py"]
