import re
import uuid
from bs4 import BeautifulSoup
from objects.identity import make_emb3d_identity
from objects.matrix import make_emb3d_matrix
from objects.category import make_emb3d_categories
from objects.property import process_props
from objects.weakness import Weakness
from objects.course_of_action import process_coas
from objects.vulnerability import inner_relationships, process_threats
from pathlib import Path
from utils import create_relationship
from stix2 import (
    Vulnerability,
    Bundle,
    ExternalReference,
)
from stix2.v21.common import ExternalReference


objects_info = {
    "threats": {
        "code": "TID",
        "key": "threattitle",
        "query": "article div > *:not(div, h1, h2)",
    },
    "mitigations": {
        "code": "MID",
        "key": "mitigationTitle",
        "query": "article > *:not(div, h1, h2)",
    },
}

data = {
    "identities": [],
    "matrices": [],
    "categories": [],
    "mitigations": {},
    "threats": {},
    "properties": {},
    "relationships": [],
    "weaknesses": {},
}


def extract_html_data(item, obj_type):
    """
    Extracts data from an HTML file and updates a data structure.

        This function reads an HTML file, parses it to extract relevant information,
        and updates a global data structure with the extracted data. It processes
        various sections of the HTML document, including titles, descriptions,
        references, and relationships, based on the specified object type.

        Args:
            item (str): The path to the HTML file to be processed.
            obj_type (str): The type of object being processed, which determines
                            how the extracted data is structured and stored.

        Returns:
            None: This function updates a global data structure but does not return
                any value.

        Raises:
            FileNotFoundError: If the specified HTML file does not exist.
            ValueError: If the HTML structure does not match expected formats.

        Examples:
            extract_html_data("path/to/file.html", "some_object_type")
    """

    def update_data(obj_tag, key, value):
        match key:
            case "title":
                return data[obj_type][obj_tag].new_version(name=value)
            case "description" | "threat description":
                return data[obj_type][obj_tag].new_version(description="".join(value))
            case "iec 62443 4-2 mappings":
                return data[obj_type][obj_tag].new_version(x_iec_62443=value)
            case "threat maturity and evidence":
                return data[obj_type][obj_tag].new_version(x_maturity=value)
            case "references":
                refs = [
                    ExternalReference(
                        source_name="mitre", description=ref, url=url["url"]
                    )
                    for ref in value
                    if (url := re.search(r"(?P<url>https?://[^\s]+)", ref))
                ]
                return data[obj_type][obj_tag].new_version(external_references=refs)
            case _:
                return data[obj_type][obj_tag].new_version(**{key: value})

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
            if key in ["cwe", "cve"]:
                for item in value:
                    if key == "cwe":
                        name, *description = item.split(":")
                        try:
                            from_id = data["weaknesses"][name].id
                        except KeyError:
                            description = " ".join(description).strip()
                            from_id = f"weakness--{uuid.uuid4()}"
                            data["weaknesses"][name] = Weakness(
                                id=from_id,
                                name=name,
                                description=description,
                            )
                    elif key == "cve":
                        try:
                            name = [x for x in item.split() if x.startswith("CVE-")][0]
                        except Exception:
                            continue
                        try:
                            from_id = data["threats"][name].id
                        except KeyError:
                            from_id = f"vulnerability--{uuid.uuid4()}"
                            data["threats"][name] = Vulnerability(
                                id=from_id,
                                name=name,
                                description=item,
                            )
                    data["relationships"].append(
                        create_relationship(
                            from_id,
                            data[obj_type][obj_tag].id,
                            "related-to",
                        )
                    )
            else:
                data[obj_type][obj_tag] = update_data(obj_tag, key, value)


# sourcery skip: collection-builtin-to-comprehension, comprehension-to-generator
if __name__ == "__main__":

    data["identities"] = make_emb3d_identity()
    identity = data["identities"][0]["id"]

    process_coas(
        data,
        "emb3d/_data/mitigations_threat_mappings.json",
        identity,
        {"threats", "id", "name"},
    )
    process_props(
        data,
        "emb3d/_data/properties_threat_mappings.json",
        identity,
        {"threats", "id", "subProps", "isparentProp", "parentProp", "name", "text"},
    )
    process_threats(
        data,
        "emb3d/_data/threats_properties_mitigations_mappings.json",
        identity,
        {"properties", "id", "mitigations", "name"},
    )

    data["categories"] = make_emb3d_categories(
        identity,
        list(set([x["x_category"] for x in data["threats"].values()])),
    )
    data["matrices"] = make_emb3d_matrix([x["id"] for x in data["categories"]])

    # grab descriptions and other info from html files
    for item in Path(".").glob("emb3d/**/*.html"):
        if (
            item.parent.stem in objects_info
            and item.stem[:3] == objects_info[item.parent.stem]["code"]
        ):
            extract_html_data(item, item.parent.stem)

    # add internal similarity relationship for vulnerability
    inner_relationships(data, "emb3d/_data/properties_threat_mappings.json")

    # generate list of items
    stix_objects = []
    for obj_type in data:
        try:
            stix_objects.extend(data[obj_type].values())
        except AttributeError:
            stix_objects.extend(data[obj_type])

    # remove text field
    stix_objects = [item.new_version(text=None) for item in stix_objects]

    # create bundle
    bundle = Bundle(stix_objects, allow_custom=True)

    with open("OUT/out_stix.json", "w") as g:
        g.write(bundle.serialize(indent=4))
