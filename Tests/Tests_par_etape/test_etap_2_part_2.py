from aegis.config.manager import Config
from aegis.logger.logger import setup_logger
from aegis.scanner.walker import FileWalker

config = Config.from_yaml("config.yaml")
setup_logger(config)

walker = FileWalker(config)

fichiers = list(walker.walk(""))
i = 0
for f in fichiers:
    i = i+1
    print("\n",i, "  ",f,"\n")