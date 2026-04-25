<template>
  <div class="flex h-screen bg-gray-50 font-sans text-gray-900">
    
    <transition name="fade">
      <div v-if="isMobileMenuOpen" @click="isMobileMenuOpen = false" class="fixed inset-0 bg-gray-900/50 z-40 md:hidden"></div>
    </transition>

    <aside :class="[
        'fixed inset-y-0 left-0 z-50 w-64 bg-gray-900 text-white flex flex-col transition-transform duration-300 ease-in-out md:relative md:translate-x-0',
        isMobileMenuOpen ? 'translate-x-0' : '-translate-x-full'
      ]">
      <div class="p-6 border-b border-gray-800 flex items-center justify-between">
        <div>
          <h1 class="text-xl font-bold tracking-wider text-blue-400">RL FIREWALL</h1>
          <p class="text-xs text-gray-400 mt-1">Adaptive Threat Engine</p>
        </div>
        <button @click="isMobileMenuOpen = false" class="md:hidden text-gray-400 hover:text-white">
          <X class="w-5 h-5" />
        </button>
      </div>

      <nav class="flex-1 p-4 space-y-1 overflow-y-auto">
        <router-link 
          v-for="item in navigation" 
          :key="item.name" 
          :to="item.href" 
          class="flex items-center gap-3 p-3 rounded-lg hover:bg-gray-800 transition-all duration-200 group"
          active-class="bg-blue-600 text-white shadow-md hover:bg-blue-600"
        >
          <component :is="item.icon" class="w-5 h-5 text-gray-400 group-hover:text-white transition-colors" :class="{'text-white': $route.path === item.href}" />
          <span class="font-medium text-sm">{{ item.name }}</span>
        </router-link>
      </nav>

      <!-- <div class="p-4 border-t border-gray-800">
        <div class="flex items-center gap-3 cursor-pointer hover:bg-gray-800 p-2 rounded-lg transition-colors">
          <div class="w-8 h-8 rounded-full bg-blue-500 flex items-center justify-center font-bold text-sm">
            Admin
          </div>
          <div class="flex-1 min-w-0">
            <p class="text-sm font-medium text-white truncate">System Admin</p>
            <p class="text-xs text-gray-400 truncate">admin@structinsight.ai</p>
          </div>
        </div>
      </div> -->
    </aside>

    <main class="flex-1 flex flex-col min-w-0 overflow-hidden">
      
      <header class="bg-white border-b border-gray-200 h-16 flex items-center justify-between px-4 sm:px-6 lg:px-8 shrink-0">
        <div class="flex items-center gap-4">
          <button @click="isMobileMenuOpen = true" class="md:hidden text-gray-500 hover:text-gray-700">
            <Menu class="w-6 h-6" />
          </button>
          <h2 class="text-xl font-semibold text-gray-800 capitalize">{{ $route.name || 'Dashboard' }}</h2>
        </div>

        <div class="flex items-center gap-4">
          <button class="relative p-2 text-gray-400 hover:text-gray-500 transition-colors">
            <span class="absolute top-1.5 right-1.5 w-2 h-2 bg-red-500 rounded-full ring-2 ring-white"></span>
            <Bell class="w-5 h-5" />
          </button>
        </div>
      </header>

      <div class="flex-1 overflow-y-auto bg-gray-50 p-4 sm:p-6 lg:p-8 relative">
        <router-view v-slot="{ Component }">
          <transition name="page" mode="out-in">
            <component :is="Component" />
          </transition>
        </router-view>
      </div>
    </main>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { 
  LayoutDashboard, 
  Activity, 
  BrainCircuit, 
  ClipboardList,
  Menu,
  X,
  Bell
} from 'lucide-vue-next'

// Mobile menu state
const isMobileMenuOpen = ref(false)

// Data-Driven Navigation
const navigation = [
  { name: 'Live Dashboard', href: '/', icon: LayoutDashboard },
  { name: 'AI Performance', href: '/performance', icon: Activity },
  { name: 'Training History', href: '/training', icon: BrainCircuit },
  { name: 'Audit Logs', href: '/audit', icon: ClipboardList },
]
</script>

<style scoped>
/* Smooth page transitions */
.page-enter-active,
.page-leave-active {
  transition: opacity 0.2s ease, transform 0.2s ease;
}

.page-enter-from {
  opacity: 0;
  transform: translateY(10px);
}

.page-leave-to {
  opacity: 0;
  transform: translateY(-10px);
}

/* Mobile overlay transition */
.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.3s ease;
}
.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}
</style>