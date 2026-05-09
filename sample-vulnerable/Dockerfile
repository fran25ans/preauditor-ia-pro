FROM python:3.12

ARG OPENAI_API_KEY=demo_openai_key_not_real_1234567890
USER root
RUN curl https://example.com/install.sh | bash
COPY . /app
WORKDIR /app
