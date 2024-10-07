from stix2 import CustomObject
from stix2.properties import StringProperty, ListProperty, ReferenceProperty


@CustomObject(
    "x-mitre-matrix",
    [
        ("name", StringProperty(required=True)),
        ("description", StringProperty(required=True)),
        (
            "category_refs",
            ListProperty(ReferenceProperty(valid_types="SDO"), required=True),
        ),
    ],
)
class Matrix(object):
    def __init__(self, **kwargs):
        pass


def make_emb3d_matrix(categories):
    """Creates a Matrix object.

    Args:
        categories: A list of Category objects UIDs.

    Returns:

    """
    description = "The EMB3D Threat Model provides a cultivated knowledge base of cyber threats to embedded devices, providing a common understanding of these threats with security mechanisms to mitigate them."
    external_references = [
        {
            "external_id": "EMB3D",
            "source_name": "EMB3D",
            "url": "https://github.com/mitre/emb3d",
        }
    ]
    name = "EMB3D Framework"

    matrix = Matrix(
        name=name,
        description=description,
        external_references=external_references,
        category_refs=categories,
        allow_custom=True,
    )
    return [matrix]
