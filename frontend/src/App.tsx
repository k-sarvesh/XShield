import { Routes, Route, Navigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { api } from './api/client'
import Layout from './components/Layout'
import LiveMonitor from './pages/LiveMonitor'
import Incidents from './pages/Incidents'
import NetworkResponse from './pages/NetworkResponse'
import HistoricalAnalysis from './pages/HistoricalAnalysis'
import SystemHealth from './pages/SystemHealth'

export default function App() {
  const healthQuery = useQuery({
    queryKey: ['health'],
    queryFn: api.health,
    refetchInterval: 5000,
    retry: 2,
  })

  return (
    <Layout health={healthQuery.data} isConnected={healthQuery.isSuccess} isLoading={healthQuery.isLoading}>
      <Routes>
        <Route path="/" element={<Navigate to="/monitor" replace />} />
        <Route path="/monitor" element={<LiveMonitor />} />
        <Route path="/incidents" element={<Incidents />} />
        <Route path="/response" element={<NetworkResponse />} />
        <Route path="/history" element={<HistoricalAnalysis />} />
        <Route path="/health" element={<SystemHealth />} />
      </Routes>
    </Layout>
  )
}
