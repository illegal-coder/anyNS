FROM python:3.12-alpine

WORKDIR /tests
COPY tests/selenium/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY tests/selenium/test_admin_ui.py ./test_admin_ui.py

CMD ["python", "-m", "unittest", "-v", "test_admin_ui.py"]