import { createRoot } from 'react-dom/client'

const root = document.getElementById('root')
if (root === null) throw new Error('#root is missing')
createRoot(root).render(<p>barbican</p>)
