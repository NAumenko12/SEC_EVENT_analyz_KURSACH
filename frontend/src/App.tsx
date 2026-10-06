import { useCallback, useEffect, useState } from 'react'
import type { FormEvent } from 'react'
import { apiRequest } from './api/client'
import { AuthScreen } from './auth/AuthScreen'
import type { AuthSession } from './auth/types'
import './App.css'

type SourceType = {
  code: string
  name: string
  description: string | null
}

type JobStatus = 'queued' | 'processing' | 'completed' | 'failed' | 'cancelled'

type CreatedJob = {
  uploadId: number
  jobId: number
  status: JobStatus
  progress: number
  processedRecords: number
  eventsCreated: number
  findingsCreated: number
  errorMessage: string | null
}

type JobResponse = Omit<CreatedJob, 'jobId'> & { id: number }

const jobStatusLabels: Record<JobStatus, string> = {
  queued: 'Ожидает обработки',
  processing: 'Анализируется',
  completed: 'Завершено',
  failed: 'Ошибка',
  cancelled: 'Отменено',
}

const acceptedExtensions: Record<string, string> = {
  auth_log: '.log,.txt',
  nginx_access: '.log,.txt',
  suricata_eve: '.json,.jsonl,.log',
  pcap: '.pcap,.pcapng',
}

type AnalyzerAppProps = {
  session: AuthSession
  onLogout: () => void
}

function AnalyzerApp({ session, onLogout }: AnalyzerAppProps) {
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
      const data = await apiRequest<SourceType[]>(
        '/source-types',
        {},
        session.token,
      )
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
  }, [session.token])

  useEffect(() => {
    // Первый запрос синхронизирует экран с внешним Drogon API.
    // oxlint-disable-next-line react/set-state-in-effect
    void loadSourceTypes()
  }, [loadSourceTypes])

  useEffect(() => {
    if ( !createdJob || createdJob.status === 'completed' || createdJob.status === 'failed' || createdJob.status === 'cancelled') {
      return
    }

    let cancelled = false
    const timer = window.setTimeout(async () => {
      try {
        const body = await apiRequest<JobResponse>(
          `/jobs/${createdJob.jobId}`,
          {},
          session.token,
        )
        if (!cancelled) {
          setCreatedJob({ ...body, jobId: body.id })
        }
      } catch (requestError) {
        if (!cancelled) {
          setUploadError(
            requestError instanceof Error
              ? requestError.message
              : 'Не удалось получить состояние задания',
          )
        }
      }
    }, 800)

    return () => {
      cancelled = true
      window.clearTimeout(timer)
    }
  }, [createdJob, session.token])

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
      const body = await apiRequest<Pick<
        CreatedJob,
        'uploadId' | 'jobId' | 'status'
      >>('/uploads', { method: 'POST', body: formData }, session.token)

      setCreatedJob({
        ...body,
        progress: 0,
        processedRecords: 0,
        eventsCreated: 0,
        findingsCreated: 0,
        errorMessage: null,
      })
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
          <div className="user-controls">
            <div className="api-badge">
              <span className={`status-dot ${error ? 'status-error' : ''}`} />
              {session.user.username}
            </div>
            <button
              className="logout-button"
              type="button"
              onClick={() => {
                void apiRequest<void>(
                  '/auth/logout',
                  { method: 'POST' },
                  session.token,
                ).finally(onLogout)
              }}
            >
              Выйти
            </button>
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
            <strong>{createdJob?.findingsCreated ?? 0}</strong>
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
            <div
              className={`upload-message ${
                createdJob.status === 'failed'
                  ? 'upload-message-error'
                  : 'upload-message-success'
              }`}
              role="status"
            >
              <strong>
                Задание №{createdJob.jobId}: {jobStatusLabels[createdJob.status]}
              </strong>
              <progress max="100" value={createdJob.progress} />
              <span>
                Прогресс: {createdJob.progress}% · обработано записей:{' '}
                {createdJob.processedRecords} · создано событий:{' '}
                {createdJob.eventsCreated} · находок: {createdJob.findingsCreated}
              </span>
              {createdJob.errorMessage && <span>{createdJob.errorMessage}</span>}
            </div>
          )}
        </section>
      </main>
    </div>
  )
}

function App() {
  const [session, setSession] = useState<AuthSession | null>(null)

  if (session === null) {
    return <AuthScreen onAuthenticated={setSession} />
  }
  return <AnalyzerApp session={session} onLogout={() => setSession(null)} />
}

export default App
