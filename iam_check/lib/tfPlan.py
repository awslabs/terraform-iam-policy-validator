#from ..config import iamPolicyAttributes, arnServiceMap, awsAccount
import iam_check.config as config
import enum
import logging
import json
import re


LOGGER = logging.getLogger('iam-policy-validator-for-terraform')

class TerraformState:
    def __init__(self, **kwargs) -> None:
        """Not implemented since it only supports planned changes"""
        self.format_version = None
        self.terraform_version = None
        self.values = None 

        for arg, value in kwargs.items():
            if arg == 'format_version':
                self.format_version = value
            elif arg == 'terraform_version':
                self.terraform_version = value
            else:
                setattr(self, arg, value)
    def __str__(self):
        return json.dumps(vars(self), indent=4)

    def getValue (self, key):
        raise NotImplementedError('Not implemented as we only support planned changes')

class TerraformPlan:
    def __init__(self, **kwargs) -> None:
        self.format_version = None
        self.prior_state = None
        self.configuration = None
        self.planned_values = None
        self.proposed_unknown = None
        self.variables = {}
        self.resource_changes = []
        self.output_changes = []
        self.ref_map = {}

        for arg, value in kwargs.items():
            if arg == 'format_version':
                self.format_version = value
            elif arg == 'prior_state':
                self.prior_state = TerraformState(**value)
            elif arg == 'configuration':
                self.configuration = TerraformConfig(**value)
            elif arg == 'planned_values':
                if isinstance(value, TerraformValues):
                    self.planned_values = value
                else:
                    self.planned_values = TerraformValues(**value)
            elif arg == 'proposed_unknown':
                self.proposed_unknown = TerraformValues(**value)
            elif arg == 'variables':
                self.variables = value
            elif arg == 'resource_changes':
                self.resource_changes = [TerraformResourceChange(**r) for r in value]
            elif arg == 'output_changes':
                self.output_changes = value
    
    def __str__(self) -> str:
        obj = {}
        obj['format_version'] = self.format_version
        obj['variables'] = self.variables
        obj['resource_changes'] = [json.loads(str(r)) for r in self.resource_changes]
        obj['output_changes'] = self.output_changes
        
        if self.prior_state is not None:
            obj['prior_state'] = json.loads(str(self.prior_state))
        if self.configuration is not None:
            obj['configuration'] = json.loads(str(self.configuration))
        if self.planned_values is not None:
            obj['planned_values'] = json.loads(str(self.planned_values))
        if self.proposed_unknown is not None:
            obj['proposed_unknown'] = json.loads(str(self.proposed_unknown))
        return json.dumps(obj, indent=4)

    def findPolicies(self):
        logging.debug('generating a list of policies in plan')
        policies = {}
        resources = self.listResources()
        for r in resources:
            resourceType = r.split('.')[-2]
            if resourceType not in config.iamPolicyAttributes:
                continue
            
            attributes = config.iamPolicyAttributes[resourceType]
            if isinstance(attributes, str):
                attributes = [attributes]
            for attribute in attributes:
                # check if attribute is a base one or inside a block
                if '.' not in attribute:
                    ref = f'{r}.{attribute}'
                    try:
                        policy = self.getValue(ref)
                        if policy is None or policy == "":
                            LOGGER.info(f'No policy found at: {ref}')
                        else:
                            policies[ref] = policy
                    except KeyError as e:
                        LOGGER.info(f'No policy found at: {ref}')
                        continue
                else:
                    block, key = attribute.split('.')
                    block_ref = f'{r}.{block}'
                    try:
                        data = self.getValue(block_ref)
                    except KeyError as e:
                        LOGGER.info(f'No policy found at: {ref}')
                        continue
                    
                    if not isinstance (data, list):
                        ref = f'{block_ref}.key'
                        policy = data[key]
                        if policy is None or policy == "":
                            LOGGER.info(f'No policy found at: {ref}')
                        else:
                            policies[ref] = policy
                    else:
                        for index, block in enumerate(data):
                            ref = f'{block_ref}.{index}.{key}'
                            self.ref_map[f'{block_ref}.{index}'] = r
                            if "policy" in block: 
                                policy = block[key]
                                if policy is None or policy == "":
                                    LOGGER.info(f'No policy found at: {ref}')
                                else:
                                    policies[ref] = policy
                            else:
                                LOGGER.info(f'No policy found at: {ref}')
        for ref in policies.keys():
            LOGGER.debug(f'found policy at {ref}')
        
        return policies
    def getResourceName(self, ref):
        if isinstance(ref, TerraformResource):
            resource =  ref
            ref = resource.address
        else:
            mapped_ref = self.ref_map.get(ref)
            if mapped_ref is not None:
                resource = self.getValue(mapped_ref)
            else:
                resource = self.getValue(ref)

        if resource.type not in config.arnServiceMap:
            raise TypeError(f'Add resource type {resource.type} in the configuration arnServiceMap')
        key = config.arnServiceMap[resource.type]
        terraformKey = key
        default = None
        if '?' in key:
            terraformKey, default = key.split('?')
        try:
            name = self.getValue(f'{ref}.{terraformKey}')
        except KeyError as e:
            if default is None:
                raise e
            name = default
        return name

    def getFakeArn(self, ref):
        if isinstance(ref, TerraformResource):
            resource =  ref
            ref = resource.address
        else:
            resource = self.getValue(ref)

        if resource.type not in config.arnServiceMap:
            raise TypeError(f'Add resource type {resource.type} in the configuration arnServiceMap')
        arn_pattern = config.arnServiceMap[resource.type]
        arnComponents = arn_pattern.split(':')
        arnComponents[4] = config.awsAccount
        arn_pattern = ':'.join(arnComponents)
        arn_keys = re.findall('{([^}]+)}', arn_pattern)
        print(arn_keys)
        arn_dict = {}
        for key in arn_keys:
            terraformKey = key
            default = None
            if '?' in key:
                terraformKey, default = key.split('?')
            try:
                arn_dict[key] = self.getValue(f'{ref}.{terraformKey}')
                print(terraformKey)
            except KeyError as e:
                if default is None:
                    raise e
                arn_dict[key] = default
            print(arn_dict[key])
        return arn_pattern.format(**arn_dict)

    def getValue(self, ref):
        """ interpolate a given resource address and attribute based on computed values and return the results 
        """
        found = False
        result = None
        # first get the original values
        try: 
            result = self.prior_state.getValue(ref)
            found = True
        except: pass

        # then get the planned value
        try: 
            result = self.planned_values.getValue(ref)
            found = True
        except: pass

        if found is False:
            raise KeyError(f'Invalid Key: {ref}')

        if isinstance(result, str):
            return self.parserHclString(result)
        return result

    def listResources(self):
        "created or updated resources in plan"
        return self.planned_values.listResources()
    
    def parserHclString(self, input):
        "This function will only attempt direct lookups"
        interpolation = '${}'
        directive = '${}'
        result = ""

        class strFsm(enum.Enum):
            parseString = enum.auto()
            startInterpolation = enum.auto()
            startDirective = enum.auto()
            parseInterpolation = enum.auto()
            parseDirective = enum.auto()
            
        state = strFsm.parseString

        for char in input:
            if state is strFsm.parseString:
                if char == interpolation[0]:
                    state = strFsm.startInterpolation
                elif char == directive[0]:
                    state = strFsm.startDirective
                else:
                    result +=char
            elif state is strFsm.startInterpolation: 
                if char == interpolation[0]:
                    state = strFsm.parseString
                    result +=char
                elif char == interpolation[1]:
                    state = strFsm.parseInterpolation
                    expression = ""
                else:
                    state = strFsm.parseString
                    result += interpolation[0] + char

            elif state is strFsm.startDirective:
                if char == directive[0]:
                    state = strFsm.parseString
                    result +=char
                elif char == directive[1]:
                    state = strFsm.parseDirective
                    expression = ""
                else:
                    state = strFsm.parseString
                    result += directive[0] + char

            elif state is strFsm.parseInterpolation:
                if char == interpolation[2]:
                    state = strFsm.parseString
                    try:
                        result += self.getValue(expression)
                    except:
                        LOGGER.warning(f'string interpolation not available: {expression}')
                        expression = '${' + expression + '}'
                        result += expression
                else:
                    expression += char
            elif state is strFsm.parseDirective:
                if char == directive[2]:
                    state = strFsm.parseString         
                    expression = '${' + expression + '}'
                    result += expression
                    LOGGER.warning(f'Cannot process string directive: {directive}')
                else:
                    expression += char
            else:
                raise RuntimeError(f'FSM for parsing HCL string reached an unknown state: {state}')
        return result


class TerraformValues:
    def __init__(self, **kwargs) -> None:
        self.outputs = None
        self.root_module = None

        for arg, value in kwargs.items():
            if arg == 'outputs':
                self.outputs = value
            elif arg == 'root_module':
                if isinstance(value, TerraformModule):
                    self.root_module = value
                else:
                    self.root_module = TerraformModule(**value)
            else:
                raise ValueError(f'TerraformVaules: Unknown parameter: {arg}')
    def __eq__(self, o: object) -> bool:
        return vars(self) == vars(o)
    
    def __str__(self):
        obj = {k: json.loads(str(v)) for k,v in vars(self).items() if v is not None}
        return json.dumps(obj, indent=4)
    
    def getValue(self, key):
        return self.root_module.getValue(key)
    
    def addResource(self, r):
        self.root_module.addResource(r)

    def addChildModule(self, m):
        self.root_module.addChildModule(m)

    def listResources(self):
        return self.root_module.listResources()

class TerraformModule:
    def __init__(self, **kwargs) -> None:
        self.address = None
        self.resources = []
        self.child_modules = []

        for arg, value in kwargs.items():
            if arg == "address":
                self.address = value
            elif arg == "resources":
                for resource in value:
                    if isinstance(resource, TerraformResource):
                        self.resources.append(resource)
                    else:
                        self.resources.append( TerraformResource(**resource) )
            elif arg == "child_modules":
                for child in value:
                    self.child_modules.append(TerraformModule(**child))
            else:
                raise ValueError(f'Unknown parameter: {arg}')
            
    def __eq__(self, o: object) -> bool:
        if self.address != o.address:
            return False
        if self.resources != o.resources:
            return False
        if self.child_modules != o.child_modules:
            return False
        return True
    
    def __str__(self):
        obj = {}

        if self.address is not None:
            obj['address'] = self.address

        obj['resources'] = []
        for r in self.resources:
            data = json.loads(str(r))
            obj['resources'].append(data)
        
        obj['child_modules'] = []
        for m in self.child_modules:
            data = json.loads(str(m))
            obj['child_modules'].append(data)
        return json.dumps(obj, indent=4)

    def addResource(self, r):
        if not isinstance(r, TerraformResource):
            raise ValueError('Must be a TerraformResource')
        self.resources.append(r)
    
    def addChildModule(self, m):
        if not isinstance(m, TerraformModule):
            raise ValueError('Must be a TerraformModule')
        self.child_modules.append(m)

    def getValue(self, key):
        if key == self.address:
            return self
        
        for r in self.resources:
            if r.address == key:
                return r
            if key.startswith(f'{r.address}.'):
                return r.getValue(key)
            
        for m in self.child_modules:
            if m.address == key:
                return key
            if key.startswith(f'{m.address}.'):
                return m.getValue(key)
        raise KeyError(f'Invalid terraform address: {key}')

    def listResources(self):
        result = [r.address for r in self.resources]
        for m in self.child_modules:
            result = result + m.listResources()
        return result

class TerraformResource:
    def __init__(self, **kwargs) -> None:
        self.address = None
        self.mode = None        
        self.type = None
        self.name = None
        self.index = None
        self.change = None
        self.provider_name = None
        self.schema_version = None
        self.values = {}
        self.sensitive_values = {}

        for arg, value in kwargs.items():
            if arg == 'address':
                self.address = value
            elif arg == 'mode':
                if value not in ['managed', 'data']:
                    raise ValueError(f'TerraformResource: Invalid mode: {value}')
                self.mode = value
            elif arg == 'type':
                self.type = value
            elif arg == 'name':
                self.name = value
            elif arg == 'index':
                self.index = value
            elif arg == 'change':
                self.change = TerraformChange(**value)
            elif arg == 'provider_name':
                self.provider_name = value
            elif arg == 'schema_version':
                self.schema_version = value
            elif arg == 'values':
                self.values = value
            elif arg == 'sensitive_values':
                self.sensitive_values = value
            else:
                raise ValueError(f'TerraformResource: Invalid parameter: {arg}')

    def __eq__(self, o: object) -> bool:
        return vars(self) == vars(o)

    def __str__(self):
        obj = {k:v for k,v in vars(self).items() if v is not None}
        if self.change is not None:
            obj['change'] = json.loads(str(self.change))
        return json.dumps(obj, indent=4)

    def getValue(self, key):
        if key.startswith(self.address):
            key = key[len(self.address)+1:]

        if key in self.values:
            return self.values[key]

        if key in self.sensitive_values:
            return self.sensitive_values[key]
        raise KeyError(f'TerraformResources: {self.address}.{key}')
    
    def setValue(self, key, value, sensitive = False):
        if sensitive:
            self.sensitive_values[key] = value
        else:
            self.values[key] = value

class TerraformChange:
    def __init__(self, **kwargs) -> None:
        """Not implemented since it is not needed to find policy strings"""
        pass

    def __str__(self):
        obj = vars(self)
        return json.dumps(obj, indent=4)

class TerraformResourceChange:
    def __init__(self, **kwargs) -> None:
        """Not implemented since it is not needed to find policy strings"""
        pass

    def __str__(self):
        obj = {k: json.loads(str(v)) for k,v in vars(self).items() if v is not None}
        return json.dumps(obj, indent=4)
        
class TerraformConfig:
    def __init__(self, **kwargs) -> None:
        """Not implemented since it is not needed to find policy strings"""
        self.provider_configs = None
        self.root_module = None

    def __str__(self):
        obj = {k: json.loads(str(v)) for k,v in vars(self).items() if v is not None}
        return json.dumps(obj, indent=4)

def plan_from_stdout(input):
    """attempt to convert output from `terraform show` into a data structure. Only compatiable with 0.11 and earlier versions"""
    data = {}
    resource = None
    operation = None
    operators = ['+', '-', '~', '+/-']

    for line in input.split('\n'):
        # remove color encoding
        line = re.sub(r'\033\[[0-9;]*m', '', line)
        line = line.strip()

        #blank lines indicate done processing previous resource
        if len(line) == 0:
            resource = None
            operation = None
            continue

        # determine the operation on the given resource
        key, value = line.split(' ', 1)
        if operation is None:
            if key not in operators:
                raise ValueError('Unkown operations: {line}')
            operation = key
            resource = value
            if operation != '-':
                data[resource] = {}
            continue
        elif operation == '-':
            continue

        
        key = key.strip()
        key = key.rstrip(':')
        value = value.strip()

        if operation in ['+/-', '~']:
            value = value.split(' => ')[1]
        
        # if it is a string it needs to be decoded
        if value[0] == '"':
            value = value.strip('"')
            value = value.encode('utf-8').decode('unicode_escape')

        data[resource][key] = value

    root_module = TerraformModule()

    for resource, attributes in data.items():
        r = TerraformResource()
        r.address = resource
        r.type = resource.split('.')[-2]
        r.name = resource.split('.')[-1]

        for k, v in attributes.items():
            if v == "<computed>":
                continue
            r.values[k] = v

        root_module.addResource(r)

    values = TerraformValues(root_module = root_module)
    plan = TerraformPlan(planned_values = values)

    return plan
