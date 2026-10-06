export type User = {
  id: number
  username: string
  email: string
  role: 'user' | 'admin'
}

export type AuthSession = {
  token: string
  user: User
}
