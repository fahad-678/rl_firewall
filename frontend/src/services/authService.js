import axios from 'axios'

class AuthService {
  constructor() {
    this.user = null
    this.isAuthenticated = false
  }

  /**
   * Check if the user is currently authenticated
   */
  async checkAuth() {
    try {
      const response = await axios.get('/auth/me')
      if (response.data.user) {
        this.user = response.data.user
        this.isAuthenticated = true
        return true
      } else {
        this.user = null
        this.isAuthenticated = false
        return false
      }
    } catch (error) {
      this.user = null
      this.isAuthenticated = false
      return false
    }
  }

  /**
   * Get the current user (may be null)
   */
  getUser() {
    return this.user
  }

  /**
   * Check if authenticated
   */
  isLoggedIn() {
    return this.isAuthenticated
  }

  /**
   * Logout and clear session
   */
  async logout() {
    try {
      // Ensure CSRF cookie is present before POSTing logout
      await axios.get('/sanctum/csrf-cookie')
      await axios.post('/auth/logout')
      this.user = null
      this.isAuthenticated = false
      return true
    } catch (error) {
      console.error('Logout error:', error)
      // Clear local state even if logout fails
      this.user = null
      this.isAuthenticated = false
      return false
    }
  }
}

export default new AuthService()
