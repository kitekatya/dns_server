# **_DNS-сервер_**
* Это реализация DNS-сервера на Python, предназначенная для разрешения доменных имен с использованием DNS-запросов.
* Сервер обрабатывает запросы типов A (IPv4) и AAAA (IPv6).
* Cервер слушает на localhost (127.0.0.1) и порту 53
* Ответы разбираются и создаются вручную (используется встроенная библиотека struct)

## Особенности
* Поддержка разрешения доменов для записей типов A (IPv4) и AAAA (IPv6).
* Если в запросе встречается ".multiply.", то отвечать IP 127.0.0.X, где X - произведение чисел до 'multiply' по модулю 256, например
  + ```2.22.multiply.test.com -> 127.0.0.44```
  + ```2.2.100.multiply.test.com -> 127.0.0.144```

## Requirements
* Python последних версий

## Инсталляция
* Клонируйте репозиторий
* Запустите DNS-сервер: ```python main.py```

## Использование
* На Windows
  + ```nslookup example.com 127.0.0.1```
  + ```nslookup -type=AAAA example.com 127.0.0.1```
* На Linux/MacOS
  + ```dig @127.0.0.1 example.com```
  + ```dig @127.0.0.1 example.com AAAA```
