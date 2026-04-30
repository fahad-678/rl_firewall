<template>
  <div class="relative flex min-h-screen items-center justify-center overflow-hidden px-4 py-12 sm:px-6 lg:px-8">
    <div class="absolute inset-0 bg-[radial-gradient(circle_at_20%_10%,rgba(63,140,255,0.3),transparent_35%),radial-gradient(circle_at_85%_15%,rgba(46,196,182,0.25),transparent_30%)]"></div>

    <div class="relative z-10 w-full max-w-md">
      <div class="mb-8 text-center">
        <p class="text-xs uppercase tracking-[0.35em] text-cyan-300">Security Operations</p>
        <h1 class="mt-3 text-4xl font-semibold tracking-[0.06em] text-slate-100">RL Firewall</h1>
        <p class="mt-2 text-sm text-slate-400">Adaptive Threat Engine</p>
      </div>

      <div class="soc-panel rounded-2xl p-8">
        <h2 class="mb-6 text-xl font-semibold text-slate-100">Admin Login</h2>

        <transition name="fade">
          <div v-if="errorMessage" class="mb-6 rounded-lg border border-rose-500/30 bg-rose-500/15 p-4">
            <p class="text-sm font-medium text-rose-200">{{ errorMessage }}</p>
          </div>
        </transition>

        <form @submit.prevent="handleLogin" class="space-y-4">
          <div>
            <label for="email" class="mb-2 block text-sm font-medium text-slate-300">
              Email
            </label>
            <input
              id="email"
              v-model="form.email"
              type="email"
              required
              class="w-full rounded-lg border border-[var(--soc-border)] bg-slate-900/70 px-4 py-2 text-slate-100 placeholder:text-slate-500 focus:outline-none"
              placeholder="admin@example.com"
              :disabled="isLoading"
            />
          </div>

          <div>
            <label for="password" class="mb-2 block text-sm font-medium text-slate-300">
              Password
            </label>
            <input
              id="password"
              v-model="form.password"
              type="password"
              required
              class="w-full rounded-lg border border-[var(--soc-border)] bg-slate-900/70 px-4 py-2 text-slate-100 placeholder:text-slate-500 focus:outline-none"
              placeholder="••••••••"
              :disabled="isLoading"
            />
          </div>

          <button
            type="submit"
            :disabled="isLoading"
            class="mt-6 w-full rounded-lg bg-cyan-500 px-4 py-2 font-semibold text-slate-950 transition-colors duration-200 hover:bg-cyan-400 disabled:cursor-not-allowed disabled:bg-slate-500"
          >
            <span v-if="!isLoading">Sign In</span>
            <span v-else>Authenticating...</span>
          </button>
        </form>

        <p class="mt-6 text-center text-xs text-slate-400">
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
  transition: opacity 0.2s ease;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}
</style>
