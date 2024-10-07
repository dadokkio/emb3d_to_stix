import re
import uuid
from stix2 import Relationship
from stix2.exceptions import UnmodifiablePropertyError


def clean(obj, identity=None, keys_to_exclude=None):
    """
    Cleans the input dictionary by excluding specified keys and modifying certain fields.

    This function processes a dictionary, allowing for the exclusion of specific keys and
    transforming the values of the "level" and "category" keys. It also adds a reference to
    the creator if provided.

    Args:
        obj (dict): The input dictionary to be cleaned.
        identity (str, optional): An identifier for the creator to be added to the output. Defaults to None.
        keys_to_exclude (list, optional): A list of keys to exclude from the output dictionary. Defaults to None.

    Returns:
        dict: A new dictionary containing the cleaned data.
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
    if identity:
        tmp["created_by_ref"] = identity
    return tmp


def create_or_update_stix_obj(
    obj, obj_type, existing_objs, identity, keys_to_exclude, **kwargs
):
    """
    Create a new STIX object or update an existing one based on the provided parameters.
    This function manages the lifecycle of STIX objects by either creating a new version or initializing a new object.

    Args:
        obj (dict): The object data containing the necessary attributes for STIX object creation.
        obj_type (type): The type of the STIX object to create or update.
        existing_objs (dict): A dictionary of existing STIX objects indexed by their names.
        identity (str): The identity to associate with the STIX object.
        keys_to_exclude (list): A list of keys to exclude from the object data.
        **kwargs: Additional keyword arguments for STIX object creation.

    Returns:
        dict: The created or updated STIX object.

    Raises:
        KeyError: If the object ID is not found in existing objects during an update.
    """
    name = obj["id"]
    try:
        stix_obj = existing_objs[name]
        stix_obj = stix_obj.new_version(**kwargs)
    except (KeyError, UnmodifiablePropertyError):
        tmp = clean(obj, identity, keys_to_exclude)
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
