import logging
import yaml
import sys

# logging configuration
LOGGER = logging.getLogger('iam-policy-validator-for-terraform')

# AWS Account ID to use when unknown
awsAccount = '123456789012'

#IAM Policy checks to run
# The default is to run all checks if thhe list is empty
# iamChecks = []

#IAM policy resources
iamPolicyAttributes = {}

#Generate fake ARN
# default substitube is {<key>?<default>}
arnServiceMap = {}

validatePolicyResourceType = {}

def configure_logging(enable_logging):
    console_handler = logging.StreamHandler(sys.stdout)
    #console_handler.setLevel(logging.DEBUG)

    LOGGER.setLevel(logging.INFO)

    # log_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(log_formatter)
    LOGGER.propagate = False
    # for handler in LOGGER.handlers:
    #     LOGGER.removeHandler(handler)
    LOGGER.addHandler(console_handler)
    if not enable_logging:
        LOGGER.disabled = True
def load_config_yaml(file, exclude_resource_type = []):
    global arnServiceMap
    global iamPolicyAttributes
    global validatePolicyResourceType
    
    with open(file, 'r') as fh:
        data = yaml.safe_load(fh)

    arnServiceMap = data.get('arnServiceMap', arnServiceMap)
    if 'arnServiceMap' in data:
        arnServiceMap = data['arnServiceMap'] 
        
    if 'iamPolicyAttributes' in data:
        iamPolicyAttributes = data['iamPolicyAttributes']
        for exclude_type in exclude_resource_type:
            del iamPolicyAttributes[exclude_type]
        
    if 'validatePolicyResourceType' in data:
        validatePolicyResourceType = data['validatePolicyResourceType']
    
