# Backward-compat shim: TLS functions moved to communication.security
from communication.security import certs_exist, server_ssl_context, client_ssl_context  # noqa: F401
