# pyfuzzer

fuzzer for itmo srw

Перед запуском



pip install poetry

cd pyfuzzer

poetry config virtualenvs.in-project true --local

poetry install

poetry shell

docker compose up -d

для bwapp первый запуск http://localhost:8081/install.php


Словари
# SecLists (~2GB)

git clone https://github.com/danielmiessler/SecLists.git



\# PayloadsAllTheThings (~1GB)

git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git



\# fuzzdb (~500MB)

git clone https://github.com/fuzzdb-project/fuzzdb.git


Запуск проекта
poetry run uvicorn main:app --reload --port 8000



