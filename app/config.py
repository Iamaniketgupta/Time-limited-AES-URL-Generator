import os

class Config:
     SECRET_KEY = os.environ.get('SECRET_KEY')  
     AES_KEY = os.environ.get('AES_KEY')

     LINK_EXPIRATION_SECONDS = 300  

     DEBUG = True
