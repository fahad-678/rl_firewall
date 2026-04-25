import { createRouter, createWebHistory } from 'vue-router'
import DashboardLayout from '../layouts/DashboardLayout.vue'
import Dashboard from '../views/Dashboard.vue'
import AiPerformance from '../views/AiPerformance.vue'
import TrainingHistory from '../views/TrainingHistory.vue'
import AuditLogs from '../views/AuditLogs.vue'

const routes = [
  {
    path: '/',
    component: DashboardLayout,
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

export default router