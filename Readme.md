# MSTIC 2016
## rsh.py

Es un ejemplo de un programa que establece una conexion remota TCP (IP:Port) con un gestor y queda a al esperar de recibir ordenes o indicaciones.

## rsh_handler.py

Esqueleto de aplicación que gestiona una conexión entrante TCP (IP:Port). Queda a la espera de recibir una conexión y una vez establecida ésta envia comandos al agente remoto.

## conf_nob64.ini

Es un ejemplo de la configuración del fichero JSON que espera la aplicación, pero éste no esta codificado. La aplicación rsh.py espera un fichero de texto codificado en Base 64 con una configuración JSON.

### Caracteristicas a implementar

  - Comunicación codificada en Base 64
  - Configuración mediante un fichero de texto BASE64_JSON
  - Ejecución de Comandos del Sistema
  - Inyección de Shell Remota
  - Upload / Download files

# Credits
This is a python code example for M4: Hacking & Pentesting Class
MSTIC 2016 (4 Ed)
GEO SYSTEM SOFTWARE / ST2Labs
