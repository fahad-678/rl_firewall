<template>
  <div class="flex h-screen bg-gray-100">
    <aside class="w-64 bg-gray-900 text-white flex flex-col">
      <div class="p-6 border-b border-gray-800">
        <h1 class="text-xl font-bold tracking-wider text-blue-400">RL FIREWALL</h1>
        <p class="text-xs text-gray-400 mt-1">Adaptive Threat Engine</p>
      </div>
      <nav class="flex-1 p-4 space-y-2">
        <router-link to="/" class="flex items-center gap-3 p-3 rounded-lg hover:bg-gray-800 transition-colors" active-class="bg-blue-600 hover:bg-blue-600">
          <LayoutDashboard class="w-5 h-5" /> Live Dashboard
        </router-link>
        <router-link to="/performance" class="flex items-center gap-3 p-3 rounded-lg hover:bg-gray-800 transition-colors" active-class="bg-blue-600 hover:bg-blue-600">
          <Activity class="w-5 h-5" /> AI Performance
        </router-link>
        <router-link to="/training" class="flex items-center gap-3 p-3 rounded-lg hover:bg-gray-800 transition-colors" active-class="bg-blue-600 hover:bg-blue-600">
          <BrainCircuit class="w-5 h-5" /> Training History
        </router-link>
        <router-link to="/audit" class="flex items-center gap-3 p-3 rounded-lg hover:bg-gray-800 transition-colors" active-class="bg-blue-600 hover:bg-blue-600">
          <ClipboardList class="w-5 h-5" /> Audit Logs
        </router-link>
      </nav>
    </aside>

    <main class="flex-1 overflow-y-auto">
      <header class="bg-white shadow-sm h-16 flex items-center px-8">
        <h2 class="text-xl font-semibold text-gray-800">{{ $route.name }}</h2>
      </header>
      <div class="p-8">
        <router-view />
      </div>
    </main>
  </div>
</template>

<script setup>
import { LayoutDashboard, Activity, BrainCircuit, ClipboardList } from 'lucide-vue-next'
</script>