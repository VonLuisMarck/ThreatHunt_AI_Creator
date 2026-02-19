# .streamlit/static/

Carpeta para assets estáticos servidos por Streamlit.

Coloca aquí archivos que quieras servir directamente via URL:
  http://localhost:8501/app/static/<filename>

Para activar el serving de estáticos, asegúrate de que en config.toml:
  [server]
  enableStaticServing = true

Ejemplos de uso:
  - Logos / imágenes personalizadas
  - CSS adicional
  - Fuentes custom
