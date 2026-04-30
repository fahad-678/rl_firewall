<template>
  <div class="min-h-screen bg-gray-50 flex items-center justify-center px-4 py-12 sm:px-6 lg:px-8">
    <div class="w-full max-w-md">
      <!-- Header -->
      <div class="text-center mb-8">
        <h1 class="text-3xl font-bold tracking-wider text-blue-400 mb-2">RL FIREWALL</h1>
        <p class="text-gray-600">Adaptive Threat Engine</p>
      </div>

      <!-- Login Card -->
      <div class="bg-white rounded-xl shadow-md border border-gray-100 p-8">
        <h2 class="text-xl font-semibold text-gray-900 mb-6">Admin Login</h2>

        <!-- Error Alert -->
        <transition name="fade">
          <div v-if="errorMessage" class="mb-6 p-4 bg-red-50 border border-red-200 rounded-lg">
            <p class="text-sm text-red-700 font-medium">{{ errorMessage }}</p>
          </div>
        </transition>

        <!-- Form -->
        <form @submit.prevent="handleLogin" class="space-y-4">
          <!-- Email Input -->
          <div>
            <label for="email" class="block text-sm font-medium text-gray-700 mb-2">
              Email
            </label>
            <input
              id="email"
              v-model="form.email"
              type="email"
              required
              class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              placeholder="admin@example.com"
              :disabled="isLoading"
            />
          </div>

          <!-- Password Input -->
          <div>
            <label for="password" class="block text-sm font-medium text-gray-700 mb-2">
              Password
            </label>
            <input
              id="password"
              v-model="form.password"
              type="password"
              required
              class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              placeholder="••••••••"
              :disabled="isLoading"
            />
          </div>

          <!-- Submit Button -->
          <button
            type="submit"
            :disabled="isLoading"
            class="w-full px-4 py-2 bg-blue-600 text-white font-medium rounded-lg hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors duration-200 mt-6"
          >
            <span v-if="!isLoading">Sign In</span>
            <span v-else>Loading...</span>
          </button>
        </form>

        <!-- Info Text -->
        <p class="text-center text-xs text-gray-500 mt-6">
          This is the admin dashboard. Use your admin credentials to proceed.
        </p>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import axios from 'axios'

const router = useRouter()
const form = ref({
  email: '',
  password: '',
})
const isLoading = ref(false)
const errorMessage = ref('')

const handleLogin = async () => {
  if (!form.value.email || !form.value.password) {
    errorMessage.value = 'Please fill in all fields'
    return
  }

  isLoading.value = true
  errorMessage.value = ''

  try {
    // Ensure Laravel CSRF cookie is set for the session-based auth
    await axios.get('/sanctum/csrf-cookie')

    const response = await axios.post('/auth/login', {
      email: form.value.email,
      password: form.value.password,
    })

    if (response.data.success) {
      // Redirect to dashboard on successful login
      router.push('/')
    } else {
      errorMessage.value = response.data.message || 'Login failed'
    }
  } catch (error) {
    if (error.response?.status === 401) {
      errorMessage.value = 'Invalid email or password'
    } else {
      errorMessage.value = error.response?.data?.message || 'An error occurred during login'
    }
    console.error('Login error:', error)
  } finally {
    isLoading.value = false
  }
}
</script>

<style scoped>
.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.3s ease;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}
</style>
