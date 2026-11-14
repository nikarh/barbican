import { createTheme, type MantineColorsTuple } from '@mantine/core'

// Brass: the one accent, for what's actionable and for the agent's own marks (bans).
const brass: MantineColorsTuple = [
  '#fff6e6',
  '#fde9c7',
  '#f9d391',
  '#f5bc58',
  '#f0a640',
  '#e0912a',
  '#c27a1e',
  '#9a6017',
  '#734711',
  '#4d2f0b',
]

// Stone: warm near-blacks for the dark scheme (Mantine reads text from [0], surfaces from [6]..[8]).
const dark: MantineColorsTuple = [
  '#ece9e4',
  '#c7c2ba',
  '#948e85',
  '#67625b',
  '#45413c',
  '#312e2a',
  '#221f1c',
  '#191715',
  '#121110',
  '#0b0a09',
]

export const theme = createTheme({
  primaryColor: 'brass',
  primaryShade: { light: 6, dark: 4 },
  colors: { brass, dark },
  autoContrast: true,
  luminanceThreshold: 0.35,
  fontFamily: "'IBM Plex Sans Variable', ui-sans-serif, system-ui, sans-serif",
  fontFamilyMonospace: "'JetBrains Mono Variable', ui-monospace, monospace",
  headings: {
    fontFamily: "'IBM Plex Sans Variable', ui-sans-serif, system-ui, sans-serif",
    fontWeight: '620',
  },
  defaultRadius: 'sm',
  radius: { xs: '3px', sm: '5px', md: '8px', lg: '12px', xl: '18px' },
  cursorType: 'pointer',
  focusRing: 'auto',
  components: {
    Button: { defaultProps: { fw: 600, autoContrast: true } },
    ActionIcon: { defaultProps: { variant: 'subtle', color: 'gray' } },
    Badge: { defaultProps: { radius: 'xs', variant: 'light' } },
    Modal: {
      defaultProps: { removeScrollProps: { removeScrollBar: false }, radius: 'md', centered: true },
    },
    Drawer: { defaultProps: { removeScrollProps: { removeScrollBar: false } } },
    // Dropdowns of selects are placed against the viewport instead of the page. Placed on the page, one that opens
    // for a field in a modal (fixed, not on the page) makes the browser scroll the page under the modal; in Firefox for
    // Android that slides its toolbar in or out, the viewport the modal is centered in changes size, the dropdown is
    // placed again, and the page scrolls again, up and down without end.
    Combobox: { defaultProps: { floatingStrategy: 'fixed' } },
    Notification: { defaultProps: { radius: 'md' }, classNames: { root: 'app-notification' } },
  },
})
