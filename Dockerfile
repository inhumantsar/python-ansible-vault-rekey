FROM inhumantsar/ansible
MAINTAINER Shuan Martin <shaun@samsite.ca>

WORKDIR /workspace
VOLUME /workspace

ADD requirements*.txt /workspace/
RUN pip install -r /workspace/requirements.txt -r /workspace/requirements_dev.txt

CMD python -m pytest tests/*.py
