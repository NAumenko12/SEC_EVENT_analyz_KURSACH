import { useCallback, useEffect, useState } from 'react'
import type { FormEvent } from 'react'
import './App.css'

type SourceType = {
  code: string
  name: string
  description: string | null
}

type CreatedJob = {
  uploadId: number
  jobId: number
  status: 'queued'
}

const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL ?? 'http://127.0.0.1:8080/api'

const acceptedExtensions: Record<string, string> = {
  auth_log: '.log,.txt',
  nginx_access: '.log,.txt',
  suricata_eve: '.json,.jsonl,.log',
  pcap: '.pcap,.pcapng',
}

function App() {
  const [sourceTypes, setSourceTypes] = useState<SourceType[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [selectedSourceType, setSelectedSourceType] = useState<string | null>(
    null,
  )
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [isUploading, setIsUploading] = useState(false)
  const [uploadError, setUploadError] = useState<string | null>(null)
  const [createdJob, setCreatedJob] = useState<CreatedJob | null>(null)

  const loadSourceTypes = useCallback(async () => {
    setIsLoading(true)
    setError(null)

    try {
      const response = await fetch(`${API_BASE_URL}/source-types`)
      if (!response.ok) {
        throw new Error(`API вернуло статус ${response.status}`)
      }

      const data: SourceType[] = await response.json()
      setSourceTypes(data)
    } catch (requestError) {
      const message =
        requestError instanceof Error
          ? requestError.message
          : 'Неизвестная ошибка'
      setError(message)
      setSourceTypes([])
    } finally {
      setIsLoading(false)
    }
  }, [])

  useEffect(() => {
    // Первый запрос синхронизирует экран с внешним Drogon API.
    // oxlint-disable-next-line react/set-state-in-effect
    void loadSourceTypes()
  }, [loadSourceTypes])

  const handleUpload = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (!selectedSourceType || !selectedFile) {
      setUploadError('Сначала выберите тип источника и файл')
      return
    }

    setIsUploading(true)
    setUploadError(null)
    setCreatedJob(null)

    const formData = new FormData()
    formData.append('source_type', selectedSourceType)
    formData.append('file', selectedFile)

    try {
      const response = await fetch(`${API_BASE_URL}/uploads`, {
        method: 'POST',
        body: formData,
      })
      const body = (await response.json()) as CreatedJob & { message?: string }
      if (!response.ok) {
        throw new Error(body.message ?? `API вернуло статус ${response.status}`)
      }

      setCreatedJob(body)
    } catch (requestError) {
      setUploadError(
        requestError instanceof Error
          ? requestError.message
          : 'Неизвестная ошибка загрузки',
      )
    } finally {
      setIsUploading(false)
    }
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark">S</span>
          <div>
            <strong>Security Event</strong>
            <span>Analyzer</span>
          </div>
        </div>

        <nav aria-label="Основная навигация">
          <button className="nav-item nav-item-active" type="button">
            <span aria-hidden="true">⌂</span>
            Обзор
          </button>
          <button className="nav-item" type="button" disabled>
            <span aria-hidden="true">↑</span>
            Загрузки
          </button>
          <button className="nav-item" type="button" disabled>
            <span aria-hidden="true">◎</span>
            События
          </button>
          <button className="nav-item" type="button" disabled>
            <span aria-hidden="true">!</span>
            Находки
          </button>
          <button className="nav-item" type="button" disabled>
            <span aria-hidden="true">▤</span>
            Отчёты
          </button>
        </nav>

        <div className="sidebar-footer">
          <span className={`status-dot ${error ? 'status-error' : ''}`} />
          {error ? 'API недоступно' : 'API подключено'}
        </div>
      </aside>

      <main className="content">
        <header className="page-header">
          <div>
            <p className="eyebrow">Локальная mini-SIEM</p>
            <h1>Обзор системы</h1>
            <p className="subtitle">
              Выберите источник, чтобы подготовить новый анализ событий.
            </p>
          </div>
          <div className="api-badge">
            <span className={`status-dot ${error ? 'status-error' : ''}`} />
            {error ? 'Нет соединения' : 'Drogon API'}
          </div>
        </header>

        <section className="summary-grid" aria-label="Состояние системы">
          <article className="summary-card">
            <span>Источники</span>
            <strong>{isLoading ? '—' : sourceTypes.length}</strong>
            <small>доступно для анализа</small>
          </article>
          <article className="summary-card">
            <span>Задания</span>
            <strong>{createdJob ? 1 : 0}</strong>
            <small>в очереди Kafka</small>
          </article>
          <article className="summary-card">
            <span>Находки</span>
            <strong>0</strong>
            <small>требуют внимания</small>
          </article>
        </section>

        <section className="sources-section">
          <div className="section-heading">
            <div>
              <h2>Типы источников</h2>
              <p>Данные загружены из PostgreSQL через API.</p>
            </div>
            <button
              className="refresh-button"
              type="button"
              onClick={() => void loadSourceTypes()}
              disabled={isLoading}
            >
              {isLoading ? 'Загрузка…' : 'Обновить'}
            </button>
          </div>

          {error && (
            <div className="error-panel" role="alert">
              <div>
                <strong>Не удалось получить данные</strong>
                <p>{error}. Проверьте, что Drogon API запущено.</p>
              </div>
              <button type="button" onClick={() => void loadSourceTypes()}>
                Повторить
              </button>
            </div>
          )}

          {isLoading && (
            <div className="source-grid" aria-label="Загрузка источников">
              {[0, 1, 2, 3].map((item) => (
                <div className="source-card source-skeleton" key={item} />
              ))}
            </div>
          )}

          {!isLoading && !error && (
            <div className="source-grid">
              {sourceTypes.map((sourceType) => (
                <button
                  className={`source-card ${
                    selectedSourceType === sourceType.code
                      ? 'source-card-selected'
                      : ''
                  }`}
                  key={sourceType.code}
                  type="button"
                  aria-pressed={selectedSourceType === sourceType.code}
                  onClick={() => {
                    setSelectedSourceType(sourceType.code)
                    setSelectedFile(null)
                    setUploadError(null)
                    setCreatedJob(null)
                  }}
                >
                  <div className="source-icon" aria-hidden="true">
                    {sourceType.name.slice(0, 1).toUpperCase()}
                  </div>
                  <div>
                    <h3>{sourceType.name}</h3>
                    <code>{sourceType.code}</code>
                    <p>{sourceType.description ?? 'Описание отсутствует'}</p>
                  </div>
                </button>
              ))}
            </div>
          )}
        </section>

        <section className="upload-section">
          <div className="section-heading">
            <div>
              <h2>Новый анализ</h2>
              <p>Файл будет проверен API и сохранён под случайным именем.</p>
            </div>
          </div>

          <form className="upload-form" onSubmit={handleUpload}>
            <div className="upload-selection">
              <span>1</span>
              <div>
                <strong>Тип источника</strong>
                <p>
                  {selectedSourceType
                    ? sourceTypes.find(
                        (sourceType) =>
                          sourceType.code === selectedSourceType,
                      )?.name
                    : 'Выберите карточку выше'}
                </p>
              </div>
            </div>

            <label
              className={`file-picker ${
                selectedSourceType ? '' : 'file-picker-disabled'
              }`}
            >
              <span>2</span>
              <div>
                <strong>Файл журнала или дампа</strong>
                <p>
                  {selectedFile
                    ? `${selectedFile.name} · ${Math.ceil(
                        selectedFile.size / 1024,
                      )} КБ`
                    : 'Нажмите, чтобы выбрать файл до 20 МБ'}
                </p>
              </div>
              <input
                key={selectedSourceType}
                type="file"
                name="file"
                accept={
                  selectedSourceType
                    ? acceptedExtensions[selectedSourceType]
                    : undefined
                }
                disabled={!selectedSourceType || isUploading}
                onChange={(event) => {
                  const file = event.target.files?.[0] ?? null
                  if (file && file.size > 20 * 1024 * 1024) {
                    setSelectedFile(null)
                    setUploadError('Размер файла превышает 20 МБ')
                    return
                  }
                  setSelectedFile(file)
                  setUploadError(null)
                  setCreatedJob(null)
                }}
              />
            </label>

            <button
              className="upload-button"
              type="submit"
              disabled={!selectedSourceType || !selectedFile || isUploading}
            >
              {isUploading ? 'Создаём задание…' : 'Начать анализ'}
            </button>
          </form>

          {uploadError && (
            <div className="upload-message upload-message-error" role="alert">
              {uploadError}
            </div>
          )}

          {createdJob && (
            <div className="upload-message upload-message-success" role="status">
              Задание №{createdJob.jobId} создано. Файл зарегистрирован как
              загрузка №{createdJob.uploadId}.
            </div>
          )}
        </section>
      </main>
    </div>
  )
}

export default App
