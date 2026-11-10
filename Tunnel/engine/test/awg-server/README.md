# Тестовые серверы AmneziaWG (2026-10-23)

Два сервера AmneziaWG в одном контейнере - чтобы проверить на телефоне AmneziaWG, которого на Passport ещё
не было (PLAN §0, «Что осталось»). Запускается на ПК с Docker Desktop или на NAS.

| Интерфейс | Протокол | Порт | Туннель |
|---|---|---|---|
| `awg0` | AmneziaWG 2.0: S1-S4, H1-H4 диапазонами, I1 | UDP 41820 | 10.77.0.0/24 |
| `awg1` | AmneziaWG 3.1, как его сегодня ставит установщик AmneziaVPN (`amnezia-client`, `awgInstaller.cpp`): защита заголовка, случайные хвосты, таймеры диапазонами, I1 под DNS | UDP 41821 | 10.78.0.0/24 |

Образ - официальный `amneziavpn/amneziawg-go:3.1.20260828`: amneziawg-go и amneziawg-tools тех же версий, с
которыми движок проверен на ПК (`engine/test/interop/run_awg.sh`). Модуля AmneziaWG в ядре нет - `awg-quick`
сам берёт amneziawg-go в пространстве пользователя. Первый запуск (`start.sh`) делает ключи и конфиги в
`config/` (в git не попадает - `.gitignore`): серверные (0600) и четыре для телефона (0644), у каждого
сервера - только адреса туннеля (`phone-awg2.conf`, `phone-awg3.conf`) и весь трафик через сервер
(`*-full.conf`, DNS 1.1.1.1, NAT в контейнере). Следующие запуски берут те же ключи; новые - удалить файлы
из `config/`. `Endpoint` в конфигах телефона - `SERVER_IP`: адрес машины в домашней сети. Порты ниже 49152:
выше Windows резервирует диапазоны под Hyper-V (у Миши 51751-51950 - 51820 там не опубликовать: «bind: An
attempt was made to access a socket in a way forbidden»); свои резервы - `netsh int ipv4 show
excludedportrange protocol=udp`.

Дома это проверяет протокол и путь данных на телефоне. DPI так не проверить - это только с сервера за
границей. Amnezia Free для проверки не годится: его ключ - подписка, конфиг по ней приложение AmneziaVPN
каждый раз получает с серверов Amnezia, и Tunnel такие ключи не берёт (APP §5).

**Проверено без сервера** - `check.sh` (WSL, root): тот же `start.sh` в своём сетевом пространстве, наш демон
как телефон - 28 из 28: оба сервера, четыре конфига импортируются как AmneziaWG, рукопожатие, пинг адреса
сервера в туннеле, полные - и дальше сервера; чистая остановка; второй запуск с теми же ключами; сервер, у
которого iptables не сработал, - поднимается без NAT, разделённые конфиги работают.

## На ПК (Docker Desktop, Windows)

ПК Миши (2026-10-23): Docker Desktop 29.6.1 стоит, адрес в домашней сети - 192.168.1.82 (`Ethernet`, сеть
«Частная»), входящие правила брандмауэра для «Docker Desktop Backend» есть.

1. **Запустить Docker Desktop** (меню Пуск) и дождаться «Engine running».
2. **Поднять** - в Git Bash:
   ```
   cd /e/dev/momentics-projects/Tunnel/engine/test/awg-server
   echo SERVER_IP=192.168.1.82 > .env
   docker compose up -d
   docker compose logs
   ```
   `.env` (в git не попадает) читают все команды compose, не только `up`; без `SERVER_IP` compose откажется
   и скажет почему. В журнале: `first start: new keys and configs in /config`, затем `up: awg0 (AmneziaWG
   2.0) on UDP 41820, awg1 (AmneziaWG 3.1) on UDP 41821`. Docker Desktop пробрасывает UDP 41820-41821 с
   адресов ПК в контейнер. Окно Docker Desktop про интеграцию WSL с Ubuntu - «Skip WSL distro integration»:
   `docker` здесь из Git Bash, а в той же Ubuntu - стенды Tailscale с их сетевыми пространствами.
3. **Конфиги на телефон** - в `config/` той же папки. Отправить себе письмом и открыть вложение «в Tunnel»,
   или по USB в Документы -> Tunnel -> Добавить -> Из файла. В них закрытые ключи - никуда не выкладывать.
4. **Проверка на телефоне** - ниже, «Порядок проверки». Сервер со своей стороны:
   `docker exec tunnel-awg awg show` - `latest handshake` и `transfer` (закрытых ключей команда не показывает).
5. **Нет рукопожатия:** ПК не должен спать; адрес ПК тот же (`ipconfig`; сменился - `docker compose down`,
   удалить файлы из `config/`, поправить `.env`, поднять заново и снова перенести конфиги). Брандмауэр - в Git
   Bash, запущенном от администратора:
   `netsh advfirewall firewall add rule name="Tunnel AWG test" dir=in action=allow protocol=UDP localport=41820,41821 profile=private`
   (убрать потом: `netsh advfirewall firewall delete rule name="Tunnel AWG test"`).
6. **После:** `docker compose down` - интерфейсы и правила NAT уходят чисто. Образ: `docker image rm
   amneziavpn/amneziawg-go:3.1.20260828`.

## На NAS (Synology, DSM 7.2+)

0. **Модель.** Образ есть только для amd64 - нужен NAS на Intel или AMD: Панель управления ->
   Информационный центр -> ЦП.
1. **Container Manager** - из Центра пакетов.
2. **`/dev/net/tun`.** amneziawg-go делает свой интерфейс через tun. По SSH: `ls -l /dev/net/tun`; нет - `sudo
   insmod /lib/modules/tun.ko`. После перезагрузки NAS сам не загрузится: Планировщик задач -> Запускаемая
   задача, событие «Загрузка», root, `/sbin/insmod /lib/modules/tun.ko || true`.
3. **Папка.** File Station -> `docker/tunnel-awg`, в ней пустая `config`; туда `docker-compose.yml` и `start.sh`.
   В `docker-compose.yml` вместо `${SERVER_IP:?...}` вписать адрес NAS (Container Manager переменных окружения
   оболочки не видит).
4. **Проект.** Container Manager -> Проект -> Создать: путь `/docker/tunnel-awg`, источник - существующий
   `docker-compose.yml`. Журнал - как на ПК. Включён брандмауэр DSM - разрешить UDP 41820-41821 из
   192.168.1.0/24. Строка `no NAT: ...` в журнале - iptables NAS не дал NAT: полные конфиги дальше NAS не
   пойдут, разделённые работают.

## Порядок проверки на телефоне

Время каждого шага записать - журнал демона потом читается по root-SSH.

1. `phone-awg2` (только 10.77.0.0/24): «Подключено», на странице профиля - рукопожатие «N с назад».
2. `phone-awg2-full` (весь трафик через сервер; WARP при этом выключить - два «весь трафик» сразу нельзя):
   любой сайт в браузере, на странице профиля растут «Получено / Отправлено».
3. `phone-awg3` и `phone-awg3-full` - то же для 3.1.
