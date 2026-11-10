# Tunnel in BlackBerry World

The listing's texts, ready to paste, and its pictures. Each language has a full description - the store's page - and a
short one, at most 255 characters, the limit of `bar-descriptor.xml`'s `<description>`. Only about what works in the
current version.

Pictures: `BBTunnel/store_icon.png` (480 x 480) and `BBTunnel/store_banner.png` (1920 x 1186, the feature image), not
listed in the bar; the command that makes them is in `docs/APP.md`, section 16. Screenshots: from the phone.

Category: the closest to Utilities in the store's form (the bar's `<category>` is `core.media`).

What the texts keep to:

- Root v4 is in every text: without it the app cannot work, and the service comes up only when root does.
- An AmneziaVPN key means one of your own server: the subscription keys of Amnezia Free are not taken (`docs/APP.md`,
  section 5).
- Getting past a block is not promised: AmneziaWG was checked at home, where there is no DPI (`docs/PLAN.md`, section 0).
- Not made by WireGuard or Tailscale: every full text says so.

## English

Short:

WireGuard, AmneziaWG and Tailscale for BlackBerry 10 on an engine of its own: profiles from a file, a QR code or text, several tunnels at once, always on from boot, DNS through the tunnel. Requires a phone with root v4.

Full:

Tunnel is a VPN client for BlackBerry 10 with its own engine, written for these phones. It connects to your WireGuard
and AmneziaWG servers, over IPv4 and IPv6, and joins your Tailscale network. A phone with root v4 is required: the
tunnels are run by a service that works as root and starts with the phone, when root comes up, up to about 15 minutes
after a boot. Without root it cannot run, and the app says so.

Add a WireGuard or AmneziaWG profile from a .conf file, a QR code or pasted text, or open a .conf "in Tunnel" from a
mail or the file manager; a key of your own AmneziaVPN server works too (vpn://, a .vpn file or its QR codes). With
Tailscale, log in by a link, opened on a computer or another phone from its QR code, or with an auth key, and reach
your devices - a NAS behind any router too - by name or by their 100.x addresses. The traffic goes directly when it
can, otherwise through Tailscale's relays.

Each profile has a switch and its state in words, and several tunnels can be up at once, a split one beside the one
that takes all traffic. A tunnel's DNS serves the whole phone while it is up. One WireGuard or AmneziaWG profile and one
Tailscale profile can be always on: they come up when the phone boots and stay up across network changes. Notifications tell you when the connection is lost, the
Active Frame shows the tunnels that are up, and Diagnostics shares all the logs in one tap. A guide walks you through
the first start. In English, Russian and Polish.

Tunnel is only the client and comes with no VPN service of its own: you need your own server or account. WireGuard is
a registered trademark of Jason A. Donenfeld, Tailscale is a trademark of Tailscale Inc.; Tunnel is not made by them.

## Русский

Short:

WireGuard, AmneziaWG и Tailscale для BlackBerry 10 на собственном движке: профили из файла, QR-кода или текста, несколько туннелей сразу, постоянное подключение с загрузки, DNS через туннель. Нужен телефон с root v4.

Full:

Tunnel - VPN-клиент для BlackBerry 10 с собственным движком, написанным для этих телефонов. Он подключается к вашим
серверам WireGuard и AmneziaWG, по IPv4 и IPv6, и входит в вашу сеть Tailscale. Нужен телефон с root v4: туннелями
управляет служба, которая работает от root и запускается вместе с телефоном, когда появляется root, в течение примерно
15 минут после загрузки. Без root она работать не может, и приложение об этом скажет.

Профиль WireGuard или AmneziaWG добавляется из файла .conf, по QR-коду или вставленным текстом, а .conf можно открыть
«в Tunnel» из почты или менеджера файлов; подходит и ключ вашего собственного сервера AmneziaVPN (vpn://, файл .vpn или
его QR-коды). В Tailscale вход - по ссылке, которую открывают на компьютере или другом телефоне по QR-коду, или по
ключу авторизации, а устройства сети, и NAS за любым роутером, доступны по имени или по адресам 100.x. Трафик идёт
напрямую, когда это возможно, иначе через ретрансляторы Tailscale.

У каждого профиля есть переключатель и состояние словами, а туннелей может быть несколько сразу: раздельный рядом с
тем, что ведёт весь трафик. DNS туннеля работает для всего телефона, пока туннель включён. Один профиль WireGuard или AmneziaWG
и один Tailscale можно сделать «всегда включёнными»: они поднимаются при загрузке телефона и держатся при смене сети. Уведомления скажут о потере связи,
Active Frame показывает включённые туннели, а в Диагностике все журналы отправляются одним касанием. При первом запуске
всё покажет гид. На английском, русском и польском.

Tunnel - только клиент, своего VPN-сервиса в нём нет: нужен ваш сервер или аккаунт. WireGuard - зарегистрированная
торговая марка Jason A. Donenfeld, Tailscale - торговая марка Tailscale Inc.; Tunnel сделан не ими.

## Polski

Short:

WireGuard, AmneziaWG i Tailscale na BlackBerry 10 na własnym silniku: profile z pliku, kodu QR lub tekstu, kilka tuneli naraz, stałe połączenie od startu telefonu, DNS przez tunel. Wymagany telefon z root v4.

Full:

Tunnel to klient VPN dla BlackBerry 10 z własnym silnikiem, napisanym dla tych telefonów. Łączy się z Twoimi serwerami
WireGuard i AmneziaWG, przez IPv4 i IPv6, i dołącza do Twojej sieci Tailscale. Wymagany jest telefon z root v4: tunelami
zarządza usługa działająca jako root, uruchamiana razem z telefonem, gdy pojawi się root, w ciągu około 15 minut od
startu. Bez roota nie może działać i aplikacja o tym powie.

Profil WireGuard lub AmneziaWG dodasz z pliku .conf, z kodu QR lub wklejając tekst, a plik .conf możesz otworzyć
"w Tunnel" z poczty lub menedżera plików; działa też klucz Twojego własnego serwera AmneziaVPN (vpn://, plik .vpn lub
jego kody QR). W Tailscale logujesz się przez link, otwierany na komputerze lub innym telefonie z kodu QR, albo kluczem
uwierzytelniania, a urządzenia sieci - także NAS za dowolnym routerem - są dostępne po nazwie lub pod adresami 100.x.
Ruch idzie bezpośrednio, gdy to możliwe, w przeciwnym razie przez przekaźniki Tailscale.

Każdy profil ma przełącznik i stan opisany słowami, a kilka tuneli może działać naraz: dzielony obok tego, który
prowadzi cały ruch. DNS tunelu działa dla całego telefonu, póki tunel jest włączony. Jeden profil WireGuard lub AmneziaWG
i jeden Tailscale mogą być zawsze włączone: łączą się przy starcie telefonu i trzymają się przy zmianie sieci. Powiadomienia informują o utracie połączenia,
Active Frame pokazuje włączone tunele, a w Diagnostyce wszystkie dzienniki udostępnisz jednym dotknięciem. Przy
pierwszym uruchomieniu poprowadzi Cię przewodnik. Po angielsku, rosyjsku i polsku.

Tunnel jest tylko klientem i nie zawiera własnej usługi VPN: potrzebny jest Twój serwer lub konto. WireGuard jest
zastrzeżonym znakiem towarowym Jasona A. Donenfelda, Tailscale - znakiem towarowym Tailscale Inc.; Tunnel nie jest ich
produktem.
