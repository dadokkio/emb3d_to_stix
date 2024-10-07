import json
from utils import clean, create_or_update_stix_obj, create_relationship
from stix2 import CustomObject, Vulnerability
from stix2.properties import (
    ExtensionsProperty,
    ReferenceProperty,
    IDProperty,
    StringProperty,
    TimestampProperty,
    TypeProperty,
)
from stix2.utils import NOW


@CustomObject(
    "property",
    [
        ("type", TypeProperty("property", spec_version="2.1")),
        ("spec_version", StringProperty(fixed="2.1")),
        ("id", IDProperty("property", spec_version="2.1")),
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
        ("x_category", StringProperty()),
        ("text", StringProperty()),
        ("description", StringProperty()),
        ("extensions", ExtensionsProperty(spec_version="2.1")),
    ],
)
class Property(object):
    def __init__(self, **kwargs):
        pass


def process_props(data, filename, identity, keys_to_exclude=None):
    """Processes property data from a JSON file.

    This function reads a JSON file containing property data, creates or
    updates property and vulnerability objects, and establishes relationships
    between them. It also allows for the exclusion of specified keys during
    the processing of the data.

    Args:
        data (dict): A dictionary that holds existing properties, threats,
                     and relationships.
        filename (str): The path to the JSON file containing property data.
        keys_to_exclude (set, optional): A set of keys to exclude from the
                                           processing. Defaults to None.

    Returns:
        None: This function updates the provided data dictionary in place
              but does not return any value.

    Raises:
        FileNotFoundError: If the specified JSON file does not exist.
        json.JSONDecodeError: If the file content is not valid JSON.

    Examples:
        process_props(data_dict, "path/to/file.json")
    """
    if keys_to_exclude is None:
        keys_to_exclude = set()

    with open(filename) as f:
        json_obj = json.loads(f.read())["properties"]

        for obj in json_obj:
            # create main object
            stix_obj = create_or_update_stix_obj(
                obj,
                Property,
                data["properties"],
                identity,
                keys_to_exclude,
                **clean(obj, identity, keys_to_exclude)
            )
            data["properties"][stix_obj["name"]] = stix_obj

            # manage related items
            for rel_obj in obj.get("threats", []):
                stix_rel_obj = create_or_update_stix_obj(
                    rel_obj,
                    Vulnerability,
                    data["threats"],
                    identity,
                    keys_to_exclude,
                    **clean(rel_obj, identity, keys_to_exclude)
                )
                data["relationships"].append(
                    create_relationship(stix_obj.id, stix_rel_obj.id, "indicates")
                )

            for rel_obj in obj.get("subProps", []):
                stix_rel_obj = create_or_update_stix_obj(
                    {"id": rel_obj},
                    Property,
                    data["properties"],
                    identity,
                    keys_to_exclude,
                )
                data["relationships"].append(
                    create_relationship(stix_rel_obj.id, stix_obj.id, "is-subs-of")
                )
