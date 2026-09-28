# Security Event Analyzer

Security Event Analyzer — mini-SIEM с десктопным клиентом на React и Tauri,
C++ API на Drogon, PostgreSQL, Apache Kafka и отдельным C++ worker.

Пользователь загружает журнал безопасности или сетевой дамп, система разбирает
данные, приводит события к единому виду, ищет признаки подозрительной активности
и формирует отчёт с уровнем риска и рекомендациями.

Подробное описание проекта и инструкции находятся в каталоге
[`docs`](docs/README.md).

## Документация

- [Обзор проекта](docs/overview.md);
- [Архитектура](docs/architecture.md);
- [HTTP API](docs/api.md);
- [База данных](docs/database.md);
- [Десктопный клиент](docs/desktop-client.md);
- [Текущее состояние](docs/progress.md).