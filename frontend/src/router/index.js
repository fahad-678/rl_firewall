import { createRouter, createWebHistory } from 'vue-router'
import DashboardLayout from '../layouts/DashboardLayout.vue'
import Dashboard from '../views/Dashboard.vue'
import AiPerformance from '../views/AiPerformance.vue'
import TrainingHistory from '../views/TrainingHistory.vue'
import AuditLogs from '../views/AuditLogs.vue'
import Login from '../views/Login.vue'
import authService from '../services/authService.js'

const routes = [
  {
    path: '/login',
    name: 'Login',
    component: Login,
    meta: { layout: 'blank' }
  },
  {
    path: '/',
    component: DashboardLayout,
    meta: { requiresAuth: true },
    children: [
      { path: '', name: 'Dashboard', component: Dashboard },
      { path: 'performance', name: 'AiPerformance', component: AiPerformance },
      { path: 'training', name: 'TrainingHistory', component: TrainingHistory },
      { path: 'audit', name: 'AuditLogs', component: AuditLogs },
    ]
  }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

// Route guard for authentication
router.beforeEach(async (to, from, next) => {
  // Skip auth check for login page
  if (to.name === 'Login') {
    next()
    return
  }

  const requiresAuth = to.matched.some(record => record.meta.requiresAuth)
  
  if (requiresAuth) {
    const isAuthenticated = await authService.checkAuth()
    
    if (!isAuthenticated) {
      // Redirect to login if not authenticated
      next({ name: 'Login', query: { redirect: to.fullPath } })
    } else {
      next()
    }
  } else {
    next()
  }
})

export default router
