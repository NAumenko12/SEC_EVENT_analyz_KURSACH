import { useState } from 'react'
import type { FormEvent } from 'react'
import { apiRequest } from '../api/client'
import type { AuthSession } from './types'

type AuthScreenProps = {
  onAuthenticated: (session: AuthSession) => void
}

export function AuthScreen({ onAuthenticated }: AuthScreenProps) {
  const [mode, setMode] = useState<'login' | 'register'>('login')
  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [isSubmitting, setIsSubmitting] = useState(false)

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setError(null)
    setIsSubmitting(true)
    try {
      const session = await apiRequest<AuthSession>(
        mode === 'login' ? '/auth/login' : '/auth/register',
        {
          method: 'POST',
          body: JSON.stringify(
            mode === 'login'
              ? { login: username, password }
              : { username, email, password },
          ),
        },
      )
      onAuthenticated(session)
    } catch (requestError) {
      setError(
        requestError instanceof Error
          ? requestError.message
          : 'Не удалось выполнить запрос',
      )
    } finally {
      setIsSubmitting(false)
    }
  }

  const changeMode = (nextMode: 'login' | 'register') => {
    setMode(nextMode)
    setPassword('')
    setError(null)
  }

  return (
    <main className="auth-page">
      <section className="auth-card">
        <div className="auth-brand">
          <span className="brand-mark">S</span>
          <div>
            <strong>Security Event Analyzer</strong>
            <span>Защищённый доступ к анализам</span>
          </div>
        </div>

        <div className="auth-tabs" role="tablist">
          <button
            className={mode === 'login' ? 'auth-tab-active' : ''}
            type="button"
            onClick={() => changeMode('login')}
          >
            Вход
          </button>
          <button
            className={mode === 'register' ? 'auth-tab-active' : ''}
            type="button"
            onClick={() => changeMode('register')}
          >
            Регистрация
          </button>
        </div>

        <form className="auth-form" onSubmit={submit}>
          <label>
            <span>{mode === 'login' ? 'Логин или email' : 'Имя пользователя'}</span>
            <input
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              minLength={mode === 'register' ? 3 : undefined}
              maxLength={mode === 'register' ? 32 : 254}
              autoComplete="username"
              required
            />
          </label>

          {mode === 'register' && (
            <label>
              <span>Email</span>
              <input
                type="email"
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                maxLength={254}
                autoComplete="email"
                required
              />
            </label>
          )}

          <label>
            <span>Пароль</span>
            <input
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              minLength={mode === 'register' ? 15 : undefined}
              maxLength={128}
              autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
              required
            />
            {mode === 'register' && (
              <small>Минимум 15 символов. Можно использовать фразу с пробелами.</small>
            )}
          </label>

          {error && <div className="auth-error" role="alert">{error}</div>}

          <button className="auth-submit" type="submit" disabled={isSubmitting}>
            {isSubmitting
              ? 'Проверяем…'
              : mode === 'login'
                ? 'Войти'
                : 'Создать аккаунт'}
          </button>
        </form>

        <p className="auth-note">
          Пароль передаётся серверу и хранится только в виде Argon2id-хеша.
        </p>
      </section>
    </main>
  )
}
