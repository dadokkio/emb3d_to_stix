from itertools import combinations
import json
import uuid
from pathlib import Path
from bs4 import BeautifulSoup
from stix2 import (
    CustomObject,
    Vulnerability,
    CourseOfAction,
    Relationship,
    Bundle,
    ExternalReference,
)


from stix2.properties import (
    ExtensionsProperty,
    ReferenceProperty,
    IDProperty,
    ListProperty,
    StringProperty,
    TimestampProperty,
    TypeProperty,
)
from stix2.v21.common import (
    ExternalReference,
)
from stix2.utils import NOW
import re


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
        ("description", StringProperty()),
        ("extensions", ExtensionsProperty(spec_version="2.1")),
    ],
)
class Property(object):
    def __init__(self, **kwargs):
        pass


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


objects_info = {
    "threats": {
        "code": "TID",
        "key": "threattitle",
        "class": Vulnerability,
        "uid_prefix": "vulnerability--",
        "name": "title",
        "description": "description",
        "query": "article div > *:not(div, h1, h2)",
    },
    "mitigations": {
        "code": "MID",
        "key": "mitigationTitle",
        "class": CourseOfAction,
        "uid_prefix": "course-of-action--",
        "name": "id",
        "description": "description",
        "query": "article > *:not(div, h1, h2)",
    },
    "properties": {
        "class": Property,
        "uid_prefix": "property--",
        "name": "id",
        "description": "text",
    },
    "weaknesses": {
        "class": Weakness,
        "uid_prefix": "weakness--",
        "name": "title",
        "description": "description",
    },
}

data = {
    "mitigations": {},
    "threats": {},
    "properties": {},
    "relationships": {},
    "weaknesses": {},
}

inner_th_rels = {}


def clean(obj, keys_to_exclude=[]):
    tmp = {}
    for k, v in obj.items():
        if k not in keys_to_exclude:
            if k in ["category", "level"]:
                tmp[f"x_{k}"] = v
            else:
                tmp[k] = v
    return tmp


def process_mappings(filename, obj_type, rel_types=[], keys_to_exclude=set()):
    """
    Processes mappings from a JSON file and updates the data dictionary.

    Args:
        filename (str): Path to the JSON file.
        obj_type (str): Key for the primary object type (e.g., "mitigations").
        rel_types (list): List of tuples defining relationship types:
                           [(related_object_key, action, reverse)]
                           e.g., [("threats", "mitigates", False)]
        keys_to_exclude (set): Keys to exclude when updating the primary object.
    """
    with open(filename) as f:
        json_obj = json.loads(f.read())

        for obj in json_obj[obj_type]:
            tmp = clean(obj, keys_to_exclude)

            # create main object
            stix_obj = objects_info[obj_type]["class"](
                id=f"{objects_info[obj_type]['uid_prefix']}{uuid.uuid4()}",
                name=obj.get(objects_info[obj_type]["name"], ""),
                description=obj.get(objects_info[obj_type]["description"], ""),
                allow_custom=True,
                **tmp,
            )
            data[obj_type][stix_obj["name"]] = stix_obj

            # manage related items
            for rel_type, rel_name, reverse, rel_key in rel_types:
                for rel_obj in obj.get(rel_key, []):
                    # dict could have info.. pick existing and update or create
                    if isinstance(rel_obj, dict):

                        name = rel_obj.get(objects_info[obj_type]["name"], "")
                        try:
                            stix_rel_obj = data[rel_type][name]
                            stix_rel_obj = stix_rel_obj.new_version(**tmp)
                        except KeyError:
                            tmp = clean(rel_obj, keys_to_exclude)
                            stix_rel_obj = objects_info[rel_type].get("class")(
                                id=f"{objects_info[rel_type]['uid_prefix']}{uuid.uuid4()}",
                                allow_custom=True,
                                name=name,
                                description=rel_obj.get(
                                    objects_info[obj_type]["description"], ""
                                ),
                                **tmp,
                            )
                            data[rel_type][stix_rel_obj["name"]] = stix_rel_obj

                        # relation could be reversed
                        from_id, to_id = (
                            (stix_obj.id, stix_rel_obj.id)
                            if not reverse
                            else (stix_rel_obj.id, stix_obj.id)
                        )
                    # list of item id
                    else:

                        # get item by name or create new
                        try:
                            rel_obj = data[rel_type][rel_obj]
                        except KeyError:
                            rel_obj = objects_info[rel_type].get("class")(
                                id=f"{objects_info[rel_type]['uid_prefix']}{uuid.uuid4()}",
                                allow_custom=True,
                                name=rel_obj,
                            )
                            data[rel_type][stix_rel_obj["name"]] = rel_obj

                        from_id, to_id = (
                            (stix_obj.id, rel_obj.id)
                            if not reverse
                            else (rel_obj.id, stix_obj.id)
                        )
                    # create relationship
                    relationship = Relationship(
                        source_ref=from_id,
                        target_ref=to_id,
                        relationship_type=rel_name,
                    )
                    data["relationships"].setdefault(f"{from_id}_{to_id}", relationship)


def extract_html_data(item, obj_type):
    """
    Extracts data from HTML files and updates the data dictionary.

    Args:
        item (Path): Path to the HTML file.
        obj_type (str): Type of object ("mitigations" or "threats").
    """
    with open(item, "r") as f:
        soup = BeautifulSoup(f.read(), "html.parser")
        article = soup.find("article")
        title = " ".join(article.find("h1").text.split())
        obj = {"title": title}
        obj_tag = soup.find("div", {"id": objects_info[obj_type]["key"]}).text
        obj_query = objects_info[obj_type]["query"]

        for tag in article.select(obj_query):
            prev_h2 = tag.find_previous("h2")
            title = prev_h2.text.lower() if prev_h2 else ""
            text = tag.get_text(strip=True, separator="\n")
            obj.setdefault(title, []).append(" ".join(text.split()))

        for key, value in obj.items():
            if key == "title":
                data[obj_type][obj_tag] = data[obj_type][obj_tag].new_version(
                    name=value
                )
            elif key == "description":
                data[obj_type][obj_tag] = data[obj_type][obj_tag].new_version(
                    description="".join(obj["description"])
                )
            elif key == "threat description":
                data[obj_type][obj_tag] = data[obj_type][obj_tag].new_version(
                    description="".join(obj["threat description"])
                )
            elif key == "iec 62443 4-2 mappings":
                # TODO
                continue
            elif key == "threat maturity and evidence":
                data[obj_type][obj_tag] = data[obj_type][obj_tag].new_version(
                    x_maturity=value
                )
            elif key == "references":
                refs = []
                for ref in value:
                    if url := re.search(r"(?P<url>https?://[^\s]+)", ref):
                        url = url.group("url")
                    else:
                        url = None
                    obj_ref = ExternalReference(
                        source_name="mitre", description=ref, url=url
                    )
                    refs.append(obj_ref)
                data[obj_type][obj_tag] = data[obj_type][obj_tag].new_version(
                    external_references=refs
                )
            elif key == "cwe":
                for cwe in value:
                    name, *description = cwe.split(":")
                    # create or relate cwe
                    try:
                        from_id = data["weaknesses"][name].id
                    except KeyError:
                        description = " ".join(description).strip()
                        from_id = (
                            f"{objects_info['weaknesses']['uid_prefix']}{uuid.uuid4()}"
                        )
                        data["weaknesses"][name] = Weakness(
                            id=from_id,
                            name=name,
                            description=description,
                        )
                    relationship = Relationship(
                        source_ref=from_id,
                        target_ref=data[obj_type][obj_tag].id,
                        relationship_type="related-to",
                    )
                    data["relationships"].setdefault(
                        f"{from_id}_{data[obj_type][obj_tag].id}", relationship
                    )
            elif key == "cve":
                for cve in value:
                    # get code from cve if in text, else not sure
                    try:
                        name = [x for x in cve.split() if x.startswith("CVE-")][0]
                    except:
                        # TODO
                        continue

                    # create or relate vulnerability
                    try:
                        from_id = data["threats"][name].id
                    except KeyError:
                        from_id = (
                            f"{objects_info['threats']['uid_prefix']}{uuid.uuid4()}"
                        )
                        data["threats"][name] = Vulnerability(
                            id=from_id,
                            name=name,
                            description=cve,
                        )
                    relationship = Relationship(
                        source_ref=from_id,
                        target_ref=data[obj_type][obj_tag].id,
                        relationship_type="related-to",
                    )
                    data["relationships"].setdefault(
                        f"{from_id}_{data[obj_type][obj_tag].id}", relationship
                    )
            else:
                # update other fields
                data[obj_type][obj_tag] = data[obj_type][obj_tag].new_version(
                    **{key: value}
                )


def inner_relationships(filepath):
    with open(filepath, "r") as f:
        json_data = json.loads(f.read())
    rels = [
        u
        for u in [
            [k["id"] for k in x.get("threats", [])] for x in json_data["properties"]
        ]
        if len(u) > 1
    ]
    for rel in rels:
        pairs = list(combinations(rel, 2))
        for start, end in pairs:
            start_obj = data["threats"][start].id
            end_obj = data["threats"][end].id
            relationship = Relationship(
                source_ref=start_obj,
                target_ref=end_obj,
                relationship_type="similar-to",
            )
            data["relationships"].setdefault(f"{start_obj}_{end_obj}", relationship)


if __name__ == "__main__":
    process_mappings(
        "emb3d/_data/mitigations_threat_mappings.json",
        "mitigations",
        [("threats", "mitigates", False, "threats")],
        {"threats", "id", "name"},
    )
    process_mappings(
        "emb3d/_data/properties_threat_mappings.json",
        "properties",
        [
            ("threats", "has", True, "threats"),
            ("properties", "is-subs-of", True, "subProps"),
        ],
        {"threats", "id", "subProps", "isparentProp", "parentProp", "name"},
    )
    process_mappings(
        "emb3d/_data/threats_properties_mitigations_mappings.json",
        "threats",
        [
            ("properties", "has", False, "properties"),
            ("mitigations", "mitigates", True, "mitigations"),
        ],
        {"properties", "id", "mitigations", "name"},
    )

    # grab descriptions and other info from html files
    for item in Path(".").glob("emb3d/**/*.html"):
        if (
            item.parent.stem in objects_info
            and item.stem[:3] == objects_info[item.parent.stem]["code"]
        ):
            extract_html_data(item, item.parent.stem)

    inner_relationships("emb3d/_data/properties_threat_mappings.json")

    # generate list of items
    stix_objects = []
    for obj_type in data:
        stix_objects.extend(data[obj_type].values())

    # remove text field
    stix_objects = [item.new_version(text=None) for item in stix_objects]

    # create bundle
    bundle = Bundle(stix_objects, allow_custom=True)

    with open("OUT/out_stix.json", "w") as g:
        g.write(bundle.serialize(indent=4))
