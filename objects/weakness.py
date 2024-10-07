from stix2.properties import (
    ExtensionsProperty,
    ReferenceProperty,
    IDProperty,
    ListProperty,
    StringProperty,
    TimestampProperty,
    TypeProperty,
)

from stix2 import CustomObject, ExternalReference
from stix2.utils import NOW


@CustomObject(
    "weakness",
    [
        ("type", TypeProperty("weakness", spec_version="2.1")),
        ("spec_version", StringProperty(fixed="2.1")),
        ("id", IDProperty("weakness", spec_version="2.1")),
        (
            "created_by_ref",
            ReferenceProperty(valid_types="identity", spec_version="2.1"),
        ),
        (
            "created",
            TimestampProperty(
                default=lambda: NOW, precision="millisecond", precision_constraint="min"
            ),
        ),
        (
            "modified",
            TimestampProperty(
                default=lambda: NOW, precision="millisecond", precision_constraint="min"
            ),
        ),
        ("name", StringProperty(required=True)),
        ("description", StringProperty()),
        ("modes_of_introduction", ListProperty(StringProperty)),
        ("common_consequences", ListProperty(StringProperty)),
        ("detection_methods", ListProperty(StringProperty)),
        ("likelihood_of_exploit", ListProperty(StringProperty)),
        ("external_references", ListProperty(ExternalReference)),
        (
            "object_marking_refs",
            ListProperty(
                ReferenceProperty(valid_types="marking-definition", spec_version="2.1")
            ),
        ),
        ("extensions", ExtensionsProperty(spec_version="2.1")),
    ],
)
class Weakness(object):
    def __init__(self, **kwargs):
        pass
