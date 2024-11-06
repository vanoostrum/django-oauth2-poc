FROM python:3.12

RUN pip install pip-tools

# Copy requirements.txt to the docker image and install packages
COPY requirements.txt /
RUN pip-sync

# Set the WORKDIR to be the folder
COPY . /app

# Expose port 8082
EXPOSE 8082
WORKDIR /app

CMD python manage.py runserver 0.0.0.0:8082