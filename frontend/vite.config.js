/* eslint-env node */
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { spawn } from 'node:child_process'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

function startBackendServerPlugin() {
  let backendProcess

  return {
    name: 'start-backend-server',
    apply: 'serve',
    configureServer(server) {
      const backendCwd = path.resolve(__dirname, '..', 'backend')
      const backendEntry = path.join(backendCwd, 'server.js')

      backendProcess = spawn('node', [backendEntry], {
        cwd: backendCwd,
        stdio: ['ignore', 'pipe', 'pipe'],
      })

      // backendProcess = spawn(process.execPath, ['--watch', backendEntry], {
      //   cwd: backendCwd,
      //   stdio: ['ignore', 'pipe', 'pipe'],
      // })

      backendProcess.stdout.on('data', (chunk) => {
        process.stdout.write(`[backend] ${chunk}`)
      })
      backendProcess.stderr.on('data', (chunk) => {
        process.stderr.write(`[backend] ${chunk}`)
      })

      const stopBackend = () => {
        if (!backendProcess) return
        if (backendProcess.killed) return
        if (process.platform === 'win32') backendProcess.kill()
        else backendProcess.kill('SIGINT')
        backendProcess = undefined
      }

      server.httpServer?.once('close', stopBackend)
      process.once('exit', stopBackend)
    },
  }
}

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), startBackendServerPlugin()],
  server: {
    proxy: {
      '/api': {
        target: 'http://localhost:3001',
        changeOrigin: true,
      },
      '/ws': {
        target: 'ws://localhost:3001',
        ws: true,
      },
    },
  },
})
