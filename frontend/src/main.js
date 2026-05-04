import { createApp } from 'vue'
import './style.css'
import App from './App.vue'
import router from './router'
import axios from 'axios'

const app = createApp(App)

// Configure axios to send cookies with requests
axios.defaults.withCredentials = true

// Add axios interceptor for 401 responses
axios.interceptors.response.use(
  response => response,
  error => {
    if (error.response?.status === 401) {
      // Redirect to login on 401 unauthorized
      router.push('/login')
    }
    return Promise.reject(error)
  }
)

app.use(router)
app.mount('#app')