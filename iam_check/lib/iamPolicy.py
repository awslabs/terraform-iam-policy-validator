import json
import logging
from typing import Optional, Union

LOGGER = logging.getLogger('iam-policy-validator-for-terraform')

class Policy:
    def __init__(self, **kwargs):
        self._version = ""
        self._id = ""
        self._statement = []

        accepted =['Version', 'Id', 'Statement', 'file', 'json']

        for key, value in kwargs.items():
            if key == 'Version':
                self.setVersion(value)
            elif key == 'Id':
                self.setId(value)
            elif key =='Statement':
                if isinstance(value, Statement):
                    self.addStatement(value)
                elif isinstance(value, dict):
                    self.addStatement(Statement(**value))
                elif isinstance(value, list):
                    for statement in value:
                        if isinstance(value, Statement):
                            self.addStatement(statement)
                        else:
                            self.addStatement(Statement(**statement))
                else:
                    raise ValueError(f'Statements expects list or dictionary')

            elif key == 'file':
                if len(kwargs) != 1:
                    raise ValueError('Invalid parameter: file can not be used with other arguments')
                with open(value, 'r') as fh:
                    data = json.load(fh)
                self.__init__(**data)

            elif key == 'json':
                if len(kwargs) != 1:
                    raise ValueError('Invalid parameter: file can not be used with other arguments')
                data = json.loads(value)
                self.__init__(**data)

            else:
                raise ValueError(f'Invalid parameter: {key} not a valid parameter')

    def __eq__(self, o) -> bool:
        """Overload = operator to test if two policies are the same"""
        if self._version != o._version:
            return False
        if self._id != o._id:
            return False
        if len(self._statement) != len(o._statement):
            return False
        for s in self._statement:
            if s not in o._statement:
                return False
        return True

    def __str__(self) -> str:
        """return a JSON representative of the iam policy"""
        obj = {}
        if self._version != "":
            obj['Version'] = self._version
        
        if self._id != "":
            obj['Id'] = self._id

        if len(self._statement) == 1:
            t = json.loads(str(self._statement[0]))
            obj['Statement'] = t
        else:
            obj['Statement'] = []
            for statement in self._statement:
                t = json.loads(str(statement))
                obj['Statement'].append(t)
        return json.dumps(obj, indent=4)

    def setId(self, id: str) -> None:
        self._id = id

    def setVersion(self, version: str) -> None:
        valid = ["2012-10-17", "2008-10-17"]

        if version not in valid:
            raise ValueError(f'Invalid IAM policy version: {version}')

        self._version = version

    def addStatement(self, statement) -> None:
        if statement not in self._statement:
            self._statement.append(statement)

    def deleteStatement(self, statement) -> None:
        self._statement = [s for s in self._statement if s != statement]

    def getId(self) -> str:
        return self._id

    def getVersion(self) -> str:
        return self._version

    def getStatement(self) -> str:
        return self._statement

class Statement:
    def __init__(self, json: str= None, **kwargs):
        self._sid = None
        self._principal = None
        self._effect = ""
        self._action = []
        self._resource = []
        self._condition = None

        self._notAction = False
        self._notPrincipal = False
        self._notResource = False

        if json is not None:
            data = json.loads(json)
            self.__init__(**data)
            return

        if 'Action' in kwargs and 'NotAction' in kwargs:
            raise ValueError('Parameter: Can not use Action with NotAction')
        if 'Principal' in kwargs and 'NotPrincipal' in kwargs:
            raise ValueError('Parameter: Can not use Action with NotPrincipal')
        if 'Resource' in kwargs and 'NotResource' in kwargs:
            raise ValueError('Parameter: Can not use Action with NotResource')

        for arg, value in kwargs.items():
            if arg == 'Sid':
                self.setSid(value)
            elif arg == 'Effect':
                self.setEffect(value)
            elif arg == 'Action' or arg == 'NotAction':
                if isinstance(value, list):
                    for action in value:
                        self.addAction(action, arg == 'NotAction')
                else:
                    self.addAction(value, arg == 'NotAction')
            elif arg == 'Principal' or arg == 'NotPrincipal' :
                self.setPrincipal(value, arg == 'NotPrincipal')
            elif arg == 'Resource' or arg == 'NotResource':
                if isinstance(value, list):
                    for resource in value:
                        self.addResource(resource, arg == 'NotResource')
                else:
                    self.addResource(value, arg == 'NotResource')
            elif arg == 'Condition':
                self._condition = value
            else:
                raise ValueError(f'Invalid parameter: {arg} not a valid parameter')
            
    def __eq__(self, o) -> bool:
        if self._notAction != o._notAction:
            return False
        if self._notPrincipal != o._notPrincipal:
            return False
        if self._notResource != o._notResource:
            return False
        if self._sid != o._sid:
            return False
        if self._effect != o._effect:
            return False
        if len(self._action) != len(o._action):
            return False
        if len(self._resource) != len(o._resource):
            return False
        
        me = sorted(self._resource)
        you = sorted(o._resource)
        if me != you:
            return False
        
        me = sorted(self._action)
        you = sorted(o._action)
        if me != you:
            return False      

        me = json.dumps(self._principal, sort_keys = True)
        me = json.dumps(o._principal, sort_keys = True)
        if me != you:
            return False      

        me = json.dumps(self._condition, sort_keys = True)
        me = json.dumps(o._condition, sort_keys = True)
        if me != you:
            return False      

        return True

    def __str__(self) -> str:
        obj = {}
        if self._sid is not None:
            obj['Sid'] = self._sid
        if self._principal is not None:
            key = 'NotPrincipal' if self._notPrincipal else 'Principal'
            obj[key] = self._principal
        if self._effect != "":
            obj['Effect'] = self._effect
        if self._condition is not None:
            obj['Condition'] = self._condition
        
        key = 'NotAction' if self._notAction else 'Action'
        if len(self._action) == 1:
            obj[key] = self._action[0]
        else:
            obj[key] = self._action

        key = 'NotResource' if self._notResource else 'Resource'
        if len(self._resource) == 1:
            obj[key] = self._resource[0]
        else:
            obj[key] = self._resource
        
        return json.dumps(obj, indent=4, default=str)


    def setSid(self, sid: Optional[str] = None):
        self._sid = sid

    def setEffect(self, effect: Optional[str] = None):
        valid = [None, "Allow", "Deny"]
        if effect not in valid:
            raise ValueError(f'Invalid effect: {effect}')
        self._effect = effect
    
    def setPrincipal(self, principal: Union[str, dict, None]= None, NotPrincipal = False):
        if self._principal is not None and self.NotPrincipal != NotPrincipal:
            raise ValueError(f'Can not use Principal with NotPrincipal')
        self._notPrincipal = NotPrincipal
        self._principal = principal

    def addAction(self, action: str, notAction = False):
        if len(self._action) > 0 and self._notAction != notAction:
            raise ValueError(f'Can not use Action with NotAction')
        self._notAction = notAction
        self._action.append(action)

    def addResource(self, resource: str, notResource = False):
        if len(self._resource) > 0 and self._notResource != notResource:
            raise ValueError(f'Can not use Resource with NotResource')
        self._notResource = notResource
        if resource not in self._resource:
            self._resource.append(resource)

    def deleteAction(self, action: str):
        self._action = [a for a in self._action if a != action]

    def deleteResource(self, resource: str):
        self._resource = [r for r in self._resource if r != resource]
    
    def getSid(self):
        return self._sid
    
    def getEffect(self):
        return self._effect

    def getAction(self):
        if self._notAction:
            return None
        return self._action
    
    def getNotAction(self):
        if self._notAction:
            return self._action
        return None

    def getPrincipal(self):
        if self._notPrincipal:
            return None
        return self._principal

    def listPrincipal(self, notPrincipal = False):
        if notPrincipal != self._notPrincipal:
            return [None]
        principal = self._principal

        if principal is None:
            return [None]

        if principal == "*":
            return ["*"]

        principals = []
        for svc,ids in principal.items():
            if isinstance(ids,str):
                principals.append(f'{svc}:{ids}')
                continue
            for id in ids:
                principals.append(f'{svc}:{ids}')
        return principals

    def getNotPrincipal(self):
        if self._notPrincipal:
            return self._principal
        return None
    
    def getResource(self):
        if self._notResource:
            return None
        return self._resource 

    def getNotResource(self):
        if self._notResource:
            return self._resource 
        return None

    def getCondition(self):
        if self._condition:
            return self._condition
        return None