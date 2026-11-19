FROM ubuntu:latest
USER root
RUN curl -s http://example.com/install.sh | sh
ADD . /app
CMD ["python", "/app/app.py"]
