# SETI Overlay

Учебный прототип защищённой P2P overlay-сети с Kademlia-lite discovery, подписанными адресными записями, TLS 1.3 и двухретрансляторными туннелями.

## Основные требования и профиль

Проект ориентирован на упрощённый уровень ТЗ:

- N = 12..15 логических узлов
- K_BUCKET_SIZE = 3
- ALPHA = 3
- репликация R = 3
- не менее 2 ретрансляторов в туннеле
- TLS 1.3 с взаимной аутентификацией
- текстовые приложения, без продвинутого профиля файлов и AKE
- минимум две bootstrap-схемы: star и ring

Конфигурация по умолчанию хранится в [config/simplified.json](config/simplified.json).

## Требования к среде

- Python 3.11+
- пакет `cryptography`
- Для захвата loopback-трафика в экспериментах: Wireshark с Npcap Loopback Adapter (`dumpcap`)

## Быстрая установка

```powershell
cd c:\seti
python -m pip install --break-system-packages -r requirements.txt
```

## Быстрый прогон тестов

```powershell
cd c:\seti
python -m pytest -q
```

## Основная последовательность запуска

```powershell
cd c:\seti
python -m pip install --break-system-packages -r requirements.txt
python -m pytest -q
python -m overlay.cli experiment --output results/run-001 --nodes 12 --bootstrap star --port 19000
python -m overlay.cli study --output results/study-001 --nodes 12 --runs 5 --port 21000
```

## Что включает проект

- TCP transport и протокольное кадрирование
- идентичность узлов на базе Ed25519
- XOR-метрика и ограниченные k-bucket
- lookup по DHT через промежуточные узлы
- подписанные NodeRecord с TTL и репликацией
- TLS 1.3 mutual-auth соединения
- E2E-шифрование прикладных сообщений
- туннели с ретрансляцией и восстановлением после отказа
- сбор метрик и экспериментов в JSON/CSV/SVG

## Структура каталогов

- [overlay/](overlay/) — ядро протокола и логика узла
- [config/](config/) — профили и конфигурация
- [tests/](tests/) — автоматические проверки
- [results/](results/) — артефакты экспериментальных прогонов

## Примечание по приёмке

Для упрощённого профиля проект должен подтверждать корректность сетевых, криптографических и отказоустойчивых сценариев на локальной машине. Полный сравнительный цикл по TЗ дополнительно требует нескольких независимых прогонов по схемам star и ring с анализом DHT и метрик.
