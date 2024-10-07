import re
import uuid
from stix2 import Relationship


def clean(obj, keys_to_exclude=None):
    """Cleans the input dictionary by excluding specified keys.

    This function creates a new dictionary that contains only the keys from the input
    dictionary that are not in the `keys_to_exclude` list. Additionally, it prefixes
    the keys "category" and "level" with "x_" in the resulting dictionary.

    Args:
        obj (dict): The input dictionary to be cleaned.
        keys_to_exclude (list, optional): A list of keys to exclude from the output dictionary. Defaults to an empty list.

    Returns:
        dict: A new dictionary containing the cleaned key-value pairs.
    """
    if keys_to_exclude is None:
        keys_to_exclude = []
    tmp = {}
    for k, v in obj.items():
        if k not in keys_to_exclude:
            if k == "level":
                tmp[f"x_{k}"] = v
            elif k == "category":
                tmp["x_category"] = (
                    re.sub(r"(?<!^)(?=[A-Z])", "-", v).replace(" ", "").lower()
                )
            else:
                tmp[k] = v
    return tmp


def create_or_update_stix_obj(obj, obj_type, existing_objs, keys_to_exclude, **kwargs):
    """Creates a new STIX object or updates an existing one.

    This function checks if a STIX object already exists in the provided
    collection. If it does, it updates the object with new data; if not,
    it creates a new STIX object using the provided parameters and adds it
    to the collection.

    Args:
        obj (dict): The source dictionary containing data for the STIX object.
        obj_type (type): The class type of the STIX object to be created or updated.
        existing_objs (dict): A dictionary of existing STIX objects indexed by their names.
        keys_to_exclude (set): A set of keys to exclude from the source dictionary during processing.
        **kwargs: Additional keyword arguments to pass when creating or updating the STIX object.

    Returns:
        dict: The created or updated STIX object.

    Examples:
        create_or_update_stix_obj(data, CourseOfAction, existing_coas, exclude_keys)
    """
    name = obj["id"]
    try:
        stix_obj = existing_objs[name]
        stix_obj = stix_obj.new_version(**kwargs)
    except KeyError:
        tmp = clean(obj, keys_to_exclude)
        prefix = re.sub(r"(?<!^)(?=[A-Z])", "-", obj_type.__name__).lower()
        stix_obj = obj_type(
            id=f"{prefix}--{uuid.uuid4()}",
            allow_custom=True,
            name=name,
            description=obj.get("description", obj.get("text", "")),
            **tmp,
        )
        existing_objs[stix_obj["name"]] = stix_obj
    return stix_obj


def create_relationship(from_id, to_id, relationship_type):
    """Creates a relationship between two entities.

    This function constructs a relationship object that links two entities
    identified by their IDs. The relationship type defines the nature of the
    connection between the two entities.

    Args:
        from_id (str): The ID of the source entity in the relationship.
        to_id (str): The ID of the target entity in the relationship.
        relationship_type (str): The type of relationship being established.

    Returns:
        Relationship: A relationship object representing the connection
                       between the two entities.

    Examples:
        create_relationship("entity1", "entity2", "related-to")
    """
    return Relationship(
        source_ref=from_id,
        target_ref=to_id,
        relationship_type=relationship_type,
    )
