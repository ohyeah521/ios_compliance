import os

class Config:
    DEBUG = False
    FRIDA_TIMEOUT = 10 
    SERVER_PORT = 8080
    
    # SSH 配置 (默认 alpine)
    SSH_USER = 'root'
    SSH_PASS = 'alpine' 
    SSH_PORT = 22

    APP_PATH_PREFIXES = [
        #"/var/containers/Bundle/Application",         
        "/private/var/containers/Bundle/Application", 
    ]