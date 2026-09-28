# Десктопное приложение

Десктопный клиент Security Event Analyzer реализован на React и Tauri. React
отвечает за интерфейс и состояние экранов, а Tauri создаёт нативное окно и
собирает macOS-приложение.

Первый экран уже получает через `GET /api/source-types` четыре типа источников
из PostgreSQL. Он показывает состояние API, загрузку, ошибку соединения и
позволяет повторить запрос. Пользователь может выбрать тип, указать файл и
создать задание через `POST /api/uploads`. События, findings и отчёты пока
обозначены как следующие разделы.

Приложение не будет обращаться к PostgreSQL и Kafka напрямую. Оно работает с
Drogon API по HTTP, поэтому запросы вида `GET /api/source-types`,
`POST /api/uploads` и `GET /api/jobs/{id}` остаются частью архитектуры. Сначала
API можно запускать локально вместе с клиентом, а при серверном развёртывании
достаточно будет изменить его адрес.

## Проверка клиента

Установить JavaScript-зависимости и проверить React:

```bash
cd frontend
npm install
npm run lint
npm run build
```

Для нативной сборки нужен Rust. После установки `rustup` приложение можно
собрать командой:

```bash
export PATH="$(brew --prefix rustup)/bin:$PATH"
cd frontend
npm run tauri build -- --debug
```

Готовое приложение появится в
`frontend/src-tauri/target/debug/bundle/macos/Security Event Analyzer.app`.
