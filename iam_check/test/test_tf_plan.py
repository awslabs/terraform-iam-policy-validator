import config
import json
import pytest
import lib.tfPlan as tfPlan


class TestTerraformResource:
    def test_core_function(self):
        err = []
        data = {
            "address": "foo.bar",
            "name": "bar",
            "values": {"baz": "Hello!"},
            "sensitive_values": {"tags_all": {}},
        }
        match = '{\n    "address": "foo.bar",\n    "name": "bar",\n    "values": {\n        "baz": "Hello!"\n    },\n    "sensitive_values": {\n        "tags_all": {}\n    }\n}'
        x = tfPlan.TerraformResource(**data)
        if str(x) != match:
            err.append("Invalid JSON representation")

        if x.getValue("baz") != "Hello!":
            err.append("Can not get value of baz")

        if x.getValue("tags_all") != {}:
            err.append("Can not get value of tags_all")

        x.setValue("big", "shot")
        if x.getValue("big") != "shot":
            err.append("Failed setting a value with setqVaule()")
        assert err == []

    def test_ignores_unknown_fields(self):
        err = []
        data = {
            "address": "foo.bar",
            "type": "aws_iam_role_policy",
            "name": "bar",
            "identity_schema_version": 0,
            "values": {"baz": "Hello!"},
        }
        x = tfPlan.TerraformResource(**data)
        if x.type != "aws_iam_role_policy":
            err.append("Known field 'type' was not set")
        if x.getValue("baz") != "Hello!":
            err.append("Known field 'values' was not set")
        if hasattr(x, "identity_schema_version"):
            err.append("Unknown field should not be set as an attribute")
        assert err == []

    def test_invalid_mode_still_raises(self):
        with pytest.raises(ValueError):
            tfPlan.TerraformResource(address="foo.bar", mode="bogus", values={})
