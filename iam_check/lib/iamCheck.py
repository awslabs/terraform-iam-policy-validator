import abc
import logging

logger = logging.getLogger(__name__)

class IamCheck(abc.ABC):
    def __init__(self, *args, **kwargs):
        name = type(self).__name__
        logger.debug(f'Initializing check: {name}')

        self.exceptions = kwargs.get('exceptions', [])
    
    @abc.abstractclassmethod
    def run(self, policy, **kwargs): pass
