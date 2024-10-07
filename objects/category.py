from stix2 import CustomObject, properties, ExternalReference


@CustomObject(
    "x-mitre-category",
    [
        ("name", properties.StringProperty(required=True)),
        ("description", properties.StringProperty(required=True)),
        ("x_mitre_shortname", properties.StringProperty(required=True)),
        ("external_references", properties.ListProperty(ExternalReference)),
    ],
)
class Category(object):
    def __init__(self, **kwargs):
        pass


def make_emb3d_categories(identity_id, tactics):
    """Create all EMB3D category objects.

    Args:
        data: The category names list.

    Returns:
        A list of Category.

    """
    return [
        Category(
            name=t,
            description=t.capitalize(),
            x_mitre_shortname=t.lower().replace(" ", "-"),
            external_references=[
                {
                    "external_id": t,
                    "source_name": "EMB3D",
                    "url": f"https://emb3d.mitre.org/threats/{t}.html",
                }
            ],
            created_by_ref=identity_id,
        )
        for t in tactics
    ]
