"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
class ApplicationError(Exception):
    pass


class SchemaValidationError(ApplicationError):
    pass