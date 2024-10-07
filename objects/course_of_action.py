import json
from utils import clean, create_or_update_stix_obj, create_relationship
from stix2 import CourseOfAction, Vulnerability


def process_coas(data, filename, identity, keys_to_exclude=None):
    """Processes course of action data from a JSON file.

    This function reads a JSON file containing mitigation data, creates or
    updates course of action and vulnerability objects, and establishes
    relationships between them. It allows for the exclusion of specified keys
    during the processing of the data.

    Args:
        data (dict): A dictionary that holds existing mitigations, threats,
                     and relationships.
        filename (str): The path to the JSON file containing mitigation data.
        keys_to_exclude (set, optional): A set of keys to exclude from the
                                           processing. Defaults to None.

    Returns:
        None: This function updates the provided data dictionary in place
              but does not return any value.

    Raises:
        FileNotFoundError: If the specified JSON file does not exist.
        json.JSONDecodeError: If the file content is not valid JSON.

    Examples:
        process_coas(data_dict, "path/to/file.json")
    """
    if keys_to_exclude is None:
        keys_to_exclude = set()

    with open(filename) as f:
        json_obj = json.loads(f.read())["mitigations"]

        for obj in json_obj:
            # create main object
            stix_obj = create_or_update_stix_obj(
                obj,
                CourseOfAction,
                data["mitigations"],
                identity,
                keys_to_exclude,
                **clean(obj, identity, keys_to_exclude)
            )
            data["mitigations"][stix_obj["name"]] = stix_obj

            # manage related items
            for rel_obj in obj.get("threats", []):
                name = rel_obj["id"]
                try:
                    stix_rel_obj = data["threats"][name]
                    stix_rel_obj = stix_rel_obj.new_version(
                        **clean(rel_obj, None, keys_to_exclude)
                    )
                except KeyError:
                    stix_rel_obj = create_or_update_stix_obj(
                        rel_obj,
                        Vulnerability,
                        data["threats"],
                        identity,
                        keys_to_exclude,
                        **clean(rel_obj, identity, keys_to_exclude)
                    )
                    data["threats"][stix_rel_obj["name"]] = stix_rel_obj

                # relation could be reversed
                from_id, to_id = stix_obj.id, stix_rel_obj.id

                # create relationship
                data["relationships"].append(
                    create_relationship(from_id, to_id, "mitigates")
                )
